#include "post.h"

#include <chainparams.h>
#include <chiapos/block_fields.h>
#include <chiapos/kernel/bls_key.h>
#include <chiapos/timelord_cli/timelord_client.h>

#include <consensus/validation.h>
#include <logging.h>
#include <net.h>
#include <net_processing.h>
#include <netmessagemaker.h>
#include <rpc/util.h>
#include <uint256.h>
#include <univalue.h>
#include <util/system.h>
#include <validation.h>
#include <vdf_computer.h>

#include <atomic>
#include <cstdint>
#include <memory>

namespace chiapos {

uint256 MakeChallenge(CBlockIndex const* pindex, Consensus::Params const& params) {
    assert(pindex);
    int nTargetHeight = pindex->nHeight + 1;
    if (nTargetHeight == params.BHDIP009Height) {
        Bytes initialVdfProof(100, 0);
        return MakeChallenge(pindex->GetBlockHash(), initialVdfProof);
    } else {
        // We need to read the challenge from last block
        return MakeChallenge(pindex->GetBlockHash(), pindex->chiaposFields.vdfProof.vchProof);
    }
}

bool CheckPosProof(CPosProof const& proof, CValidationState& state, Consensus::Params const& params, int nTargetHeight) {
    static char const* SZ_BAD_WHAT = "bad-chia-pos";

    if (proof.challenge.IsNull()) {
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                             "zero challenge");
    }

    if (proof.nPlotType == static_cast<uint8_t>(PlotPubKeyType::OGPlots)) {
        if (proof.vchPoolPkOrHash.size() != PK_LEN) {
            return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                                 "invalid size of pool public-key");
        }
    } else if (proof.nPlotType == static_cast<uint8_t>(PlotPubKeyType::PooledPlots)) {
        if (proof.vchPoolPkOrHash.size() != ADDR_LEN) {
            return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                                 "invalid size of pool hash");
        }
    } else {
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                             "invalid type of pool");
    }

    if (proof.vchLocalPk.size() != PK_LEN) {
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                             "invalid local public-key");
    }

    if (proof.vchFarmerPk.size() != PK_LEN) {
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                             "invalid farmer public-key");
    }

    if (proof.nPlotK < params.BHDIP009PlotSizeMin || proof.nPlotK > params.BHDIP009PlotSizeMax) {
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                             "invalid k");
    }

    if (proof.vchProof.empty()) {
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                             "empty proof");
    }

    if (proof.vchProof.size() != static_cast<uint32_t>(proof.nPlotK) * 8) {
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                             "the size of proof is invalid (require k * 8)");
    }

    LogPrint(BCLog::POC,
             "%s: before verify PoS, challenge=%s, local-pk=%s, farmer-pk=%s, pool-pk-hash=%s, k=%d, proof=%s\n",
             __func__, proof.challenge.GetHex(), BytesToHex(proof.vchLocalPk), BytesToHex(proof.vchFarmerPk),
             BytesToHex(proof.vchPoolPkOrHash), proof.nPlotK, BytesToHex(proof.vchProof));

    int nBitsOfFilter = nTargetHeight < params.BHDIP009PlotIdBitsOfFilterEnableOnHeight ? 0 : params.BHDIP009PlotIdBitsOfFilter;
    bool verified =
            VerifyPos(proof.challenge, MakeArray<PK_LEN>(proof.vchLocalPk), MakeArray<PK_LEN>(proof.vchFarmerPk),
                      MakePubKeyOrHash(static_cast<PlotPubKeyType>(proof.nPlotType), proof.vchPoolPkOrHash),
                      proof.nPlotK, proof.vchProof, nullptr, nBitsOfFilter);
    if (!verified) {
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                             "cannot verify proof");
    }
    return true;
}

bool CheckVdfProof(CVdfProof const& proof, CValidationState& state) {
    static char const* SZ_BAD_WHAT = "bad-chia-vdf";

    if (proof.challenge.IsNull()) {
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                             "zero challenge");
    }

    if (proof.vchY.size() != VDF_FORM_SIZE) {
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                             "invalid vdf.y");
    }

    if (proof.vchProof.empty()) {
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                             "vdf.proof is empty");
    }

    if (proof.nVdfIters == 0) {
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                             "zero iters");
    }

    if (proof.nVdfDuration == 0) {
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                             "zero duration");
    }

    return VerifyVdf(proof.challenge, MakeZeroForm(), proof.nVdfIters, MakeVDFForm(proof.vchY), proof.vchProof,
                     proof.nWitnessType);
}

bool CheckBlockFields(CBlockFields const& fields, uint64_t nTimeOfTheBlock, CBlockIndex const* pindexPrev,
                      CValidationState& state, Consensus::Params const& params) {
    static char const* SZ_BAD_WHAT = "bad-chia-fields";
    // Initial challenge should be calculated from previous block
    int nTargetHeight = pindexPrev->nHeight + 1;
    if (nTargetHeight < params.BHDIP009Height) {
        return false;
    }
    // Version
    if (fields.nVersion != CHIAHEADER_VERSION) {
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                             tinyformat::format("invalid-chia-header-version, block %x, req %x", fields.nVersion,
                                                CHIAHEADER_VERSION));
    }
    uint256 initialChallenge;
    if (nTargetHeight == params.BHDIP009Height) {
        Bytes emptyProof(100, 0);
        initialChallenge = MakeChallenge(pindexPrev->GetBlockHash(), emptyProof);
    } else {
        // Check duration
        if (pindexPrev->chiaposFields.vdfProof.nVdfDuration == 0) {
            return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                                 "zero vdf-duration");
        }
        if (pindexPrev->chiaposFields.vdfProof.vchProof.empty()) {
            return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                                 "length of vdfProof is zero");
        }
        initialChallenge = MakeChallenge(pindexPrev->GetBlockHash(), pindexPrev->chiaposFields.vdfProof.vchProof);
    }

    if (fields.vdfProof.nVdfDuration == 0) {
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                             "zero vdf-duration");
    }

    int64_t nDuration = nTimeOfTheBlock - pindexPrev->GetBlockTime();
    int64_t nDurationVDF = fields.GetTotalDuration();
    int64_t nAbsDuration = nDuration - nDurationVDF;
    if (nAbsDuration > 30) {
        // should we mark this issue as a failure?
        LogPrintf("%s (warning): duration mismatch block duration: %ld secs, vdf duration %ld secs, distance=%ld secs\n", __func__,
                  nDuration, nDurationVDF, nAbsDuration);
    }

    // Difficulty is important
    LogPrint(BCLog::POC, "%s: checking difficulty\n", __func__);
    uint64_t nDifficultyPrev = GetDifficultyForNextIterations(pindexPrev, params);
    if (nDifficultyPrev == 0) {
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                             "the value of previous difficulty is zero");
    }
    uint64_t nDifficulty = AdjustDifficulty(nDifficultyPrev, fields.GetTotalDuration(), params.BHDIP008TargetSpacing,
                                            params.BHDIP009DifficultyChangeMaxFactor, params.BHDIP009StartDifficulty);
    if (nDifficulty == 0) {
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                             "the value of current difficulty is zero");
    }
    if (nDifficulty != fields.nDifficulty) {
        LogPrintf("%s: incorrect difficulty, expect: %s, actual: %s, difficulty-prev: %s, duration: %lld\n", __func__,
                chiapos::FormatNumberStr(std::to_string(nDifficulty)), chiapos::FormatNumberStr(std::to_string(fields.nDifficulty)),
                chiapos::FormatNumberStr(std::to_string(nDifficultyPrev)), fields.GetTotalDuration());
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                             "incorrect difficulty");
    }

    if (fields.vdfProof.challenge != initialChallenge) {
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                             "invalid vdf challenge");
    }

    // Checking pos challenge
    LogPrint(BCLog::POC, "%s: checking PoS\n", __func__);
    if (fields.posProof.challenge != initialChallenge) {
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                             "invalid pos challenge");
    }
    if (!CheckPosProof(fields.posProof, state, params, nTargetHeight)) {
        return false;
    }

    // Check vdf-iters
    LogPrint(BCLog::POC, "%s: checking iters related with quality, plot-type: %d, plot-k: %d\n", __func__,
             fields.posProof.nPlotType, fields.posProof.nPlotK);
    PubKeyOrHash poolPkOrHash = chiapos::MakePubKeyOrHash(static_cast<PlotPubKeyType>(fields.posProof.nPlotType),
                                                          fields.posProof.vchPoolPkOrHash);
    uint256 mixed_quality_string = MakeMixedQualityString(
            MakeArray<PK_LEN>(fields.posProof.vchLocalPk), MakeArray<PK_LEN>(fields.posProof.vchFarmerPk), poolPkOrHash,
            fields.posProof.nPlotK, fields.posProof.challenge, fields.posProof.vchProof);
    if (mixed_quality_string.IsNull()) {
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                             "mixed quality-string is null(wrong PoS)\n");
    }
    uint64_t nBaseIters = params.BHDIP009BaseIters;
    int nBitsFilter =
            nTargetHeight < params.BHDIP009PlotIdBitsOfFilterEnableOnHeight ? 0 : params.BHDIP009PlotIdBitsOfFilter;
    uint64_t nItersRequired = CalculateIterationsQuality(
            mixed_quality_string, GetDifficultyForNextIterations(pindexPrev, params), nBitsFilter,
            params.BHDIP009DifficultyConstantFactorBits, fields.posProof.nPlotK, nBaseIters);
    LogPrint(BCLog::POC, "%s: required iters: %ld, actual: %ld\n", __func__, nItersRequired, fields.vdfProof.nVdfIters);
    if (fields.vdfProof.nVdfIters < nItersRequired) {
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                             "vdf-iters are not enough");
    }

    // Check vdf-proof
    LogPrint(BCLog::POC, "%s: checking VDF proof\n", __func__);
    if (!CheckVdfProof(fields.vdfProof, state)) {
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                             "vdf proof cannot be verified");
    }

    return true;
}

bool ReleaseBlock(std::shared_ptr<CBlock> pblock, CChainParams const& params) {
    if (!ProcessNewBlock(params, pblock, true, nullptr)) {
        LogPrintf("cannot process the new block: %s\n", pblock->ToString());
        return false;
    }
    return true;
}

bool IsTheChainReadyForChiapos(CBlockIndex const* pindexPrev, Consensus::Params const& params) {
    int nTargetHeight = pindexPrev->nHeight + 1;
    bool fInitialBlockDownload{false};
    if (!gArgs.GetBoolArg("-skip-ibd", false)) {
        fInitialBlockDownload = ChainstateActive().IsInitialBlockDownload();
    }

    if (nTargetHeight < params.BHDIP009Height) {
        return false;
    }

    if (nTargetHeight == params.BHDIP009Height) {
        // Genesis block for chiapos, we do not check the status of the chain
        return true;
    }

    return !fInitialBlockDownload;
}

uint64_t GetChiaBlockDifficulty(CBlockIndex const* pindex, Consensus::Params const& params) {
    assert(pindex != nullptr);
    int nNextHeight = pindex->nHeight + 1;
    if (nNextHeight < params.BHDIP009Height) {
        return 0;
    } else if (nNextHeight == params.BHDIP009Height) {
        return params.BHDIP009StartDifficulty;
    } else {
        return pindex->chiaposFields.nDifficulty;
    }
}

uint64_t GetDifficultyForNextIterations(CBlockIndex const* pindex, Consensus::Params const& params) {
    int nTargetHeight = pindex->nHeight + 1;
    if (nTargetHeight == params.BHDIP009Height) {
        return params.BHDIP009StartDifficulty;
    }
    arith_uint256 totalDifficulty{0};
    int nCount = params.BHDIP009DifficultyEvalWindow;
    while (nCount > 0 && pindex != nullptr && pindex->nHeight >= params.BHDIP009Height) {
        totalDifficulty += GetChiaBlockDifficulty(pindex, params);
        // next
        --nCount;
        pindex = pindex->pprev;
    }
    int nBlocksCalc = params.BHDIP009DifficultyEvalWindow - nCount;
    if (nBlocksCalc == 0) {
        return params.BHDIP009StartDifficulty;
    }
    return (totalDifficulty / nBlocksCalc).GetLow64();
}

}  // namespace chiapos
