#include "post.h"

#include <chainparams.h>
#include <chiapos/block_fields.h>
#include <chiapos/kernel/bls_key.h>
#include <chiapos/timelord.h>
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
#include <boost/asio.hpp>
#include <cstdint>
#include <memory>

namespace net = boost::asio;

namespace chiapos {

uint256 MakeChallenge(CBlockIndex* pindex, Consensus::Params const& params) {
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

bool CheckPosProof(CPosProof const& proof, CValidationState& state, Consensus::Params const& params) {
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

    bool verified =
            VerifyPos(proof.challenge, MakeArray<PK_LEN>(proof.vchLocalPk), MakeArray<PK_LEN>(proof.vchFarmerPk),
                      MakePubKeyOrHash(static_cast<PlotPubKeyType>(proof.nPlotType), proof.vchPoolPkOrHash),
                      proof.nPlotK, proof.vchProof, nullptr, params.BHDIP009PlotIdBitsOfFilter);
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
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT, "invalid-version");
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
    if (nDurationVDF > nDuration) {
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                             "duration between blocks is too short");
    }
    int64_t nAbsDuration = nDuration - nDurationVDF;
    if (nAbsDuration > 30) {
        // should we mark this issue as a failure?
        LogPrintf("%s (warning): duration mismatch block duration: %ld, vdf duration %ld, abs=%ld\n", __func__,
                  nDuration, nDurationVDF, nAbsDuration);
    }

    // Mix out the actual challenge
    uint64_t nItersVoidBlock;
    if (nTargetHeight == params.BHDIP009Height) {
        nItersVoidBlock = 0;
    } else {
        nItersVoidBlock = pindexPrev->chiaposFields.vdfProof.nVdfIters /
                          pindexPrev->chiaposFields.vdfProof.nVdfDuration * params.BHDIP008TargetSpacing;
    }
    uint256 currentChallenge = initialChallenge;
    for (CVdfProof const& vdf : fields.vVoidBlockVdf) {
        // Check the challenge of the vdf proof
        if (currentChallenge != vdf.challenge) {
            return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                                 "invalid vdf.voidBlock.challenge");
        }
        if (vdf.nVdfIters < nItersVoidBlock) {
            // The duration of the VDF is too short
            return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                                 "vdf-iters of void-block is invalid");
        }
        if (!CheckVdfProof(vdf, state)) {
            return false;
        }
        // Mix currentChallenge
        currentChallenge = MakeChallenge(currentChallenge, vdf.vchProof);
    }

    // Difficulty is important
    LogPrint(BCLog::POC, "%s: checking difficulty\n", __func__);
    uint64_t nDifficultyPrev;
    if (nTargetHeight == params.BHDIP009Height) {
        nDifficultyPrev = params.BHDIP009StartDifficulty;
    } else {
        nDifficultyPrev = pindexPrev->chiaposFields.nDifficulty;
    }
    if (nDifficultyPrev == 0) {
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                             "the value of previous difficulty is zero");
    }
    uint64_t nDifficulty = AdjustDifficulty(nDifficultyPrev, fields.GetTotalDuration(), params.BHDIP008TargetSpacing);
    if (nDifficulty == 0) {
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                             "the value of current difficulty is zero");
    }
    if (nDifficulty != fields.nDifficulty) {
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                             "incorrect difficulty");
    }

    if (fields.vdfProof.challenge != currentChallenge) {
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                             "invalid vdf challenge");
    }

    // Checking pos challenge
    LogPrint(BCLog::POC, "%s: checking PoS\n", __func__);
    if (fields.posProof.challenge != currentChallenge) {
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                             "invalid pos challenge");
    }
    if (!CheckPosProof(fields.posProof, state, params)) {
        return false;
    }

    // Check quality
    uint64_t nQuality = CalculateQuality(fields.posProof);
    if (nQuality != fields.nQuality) {
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT,
                             "incorrect quality");
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
    uint64_t nItersRequired = CalculateIterationsQuality(mixed_quality_string, fields.posProof.nPlotK, nDifficultyPrev,
                                                         params.BHDIP009DifficultyConstantFactorBits);
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

static std::map<uint256, CVdfProof> g_mapVdf;

bool SubmitVdfProofPacket(CVdfProof const& vdf) {
    auto i = g_mapVdf.find(vdf.challenge);
    if (i != std::end(g_mapVdf)) {
        if (vdf.nVdfIters == i->second.nVdfIters) {
            // The proof does already exist
            return false;
        }
    }
    // Verify the proof before store it to local memory
    if (vdf.vchY.size() != VDF_FORM_SIZE) {
        LogPrintf("%s: invalid length of vdf.y\n", __func__);
        return false;
    }
    if (vdf.vchProof.empty()) {
        LogPrintf("%s: vdf.proof is empty\n", __func__);
        return false;
    }
    if (!VerifyVdf(vdf.challenge, MakeZeroForm(), vdf.nVdfIters, MakeVDFForm(vdf.vchY), vdf.vchProof,
                   vdf.nWitnessType)) {
        LogPrintf("%s: VDF proof is invalid `%s`\n", __func__, vdf.challenge.GetHex());
        // The vdf received from P2P network is invalid
        return false;
    }
    if (i == std::end(g_mapVdf)) {
        g_mapVdf.insert(std::make_pair(vdf.challenge, vdf));
    } else {
        i->second = vdf;
    }
    LogPrintf("%s: VDF proof `%s`, iters=%ld (%s) is saved\n", __func__, vdf.challenge.GetHex(),
              vdf.nVdfIters, chiapos::FormatNumberStr(std::to_string(vdf.nVdfIters)));
    return true;
}

optional<CVdfProof> QueryReceivedVdfProofPacket(uint256 const& challenge) {
    auto i = g_mapVdf.find(challenge);
    if (i == std::end(g_mapVdf)) {
        return {};
    }
    return i->second;
}

void SendVdfProofOverP2PNetwork(CConnman* connman, CVdfProof const& vdf, CNode* pfrom, NodeChecker checker) {
    // Dispatching the message
    connman->ForEachNode([connman, &vdf, pfrom, checker](CNode* pnode) {
        if (pfrom && pfrom->GetId() == pnode->GetId()) {
            // Same node, exit
            return;
        }
        if (!checker(pnode)) {
            return;
        }
        connman->PushMessage(pnode, CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::VDF, vdf));
    });
}

void SendRequireVdfOverP2PNetwork(CConnman* connman, uint256 const& challenge, uint64_t nIters, CNode* pfrom,
                                  NodeChecker checker, SentHandler sentHandler) {
    connman->ForEachNode([connman, &challenge, nIters, pfrom, checker, sentHandler](CNode* pnode) {
        if (pfrom && pfrom->GetId() == pnode->GetId()) {
            // Same node, exit
            return;
        }
        if (!checker(pnode)) {
            return;
        }
        connman->PushMessage(pnode, CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REQVDF, challenge, nIters));
        sentHandler(pnode);
    });
}

static std::thread g_timelordThread;
static std::unique_ptr<CTimeLord> g_timelord;
static std::mutex g_mtxCalcIters;
static std::atomic_int g_nProofCallbackIdx{0};
static std::map<int, TimelordProofCallback> g_vProofCallback;

int RegisterTimelordProofHandler(TimelordProofCallback callback) {
    g_vProofCallback.insert(std::make_pair(++g_nProofCallbackIdx, std::move(callback)));
    return g_nProofCallbackIdx;
}

void UnregisterTimelordProofHandler(int nIndex) {
    auto i = g_vProofCallback.find(nIndex);
    if (i != std::end(g_vProofCallback)) {
        g_vProofCallback.erase(i);
    }
}

bool IsTimelordRunning() { return g_timelord != nullptr; }

void HandleProofProc(Proof const& proof, uint64_t iters, uint64_t d, uint256 challenge) {
    if (g_vProofCallback.empty()) {
        return;
    }
    CVdfProof vdfProof;
    vdfProof.vchY = proof.y;
    vdfProof.vchProof = proof.proof;
    vdfProof.nWitnessType = proof.witness_type;
    vdfProof.nVdfIters = std::max<uint64_t>(1, iters);
    vdfProof.nVdfDuration = std::max<uint64_t>(1, d);
    vdfProof.challenge = challenge;
    for (auto const& p : g_vProofCallback) {
        p.second(vdfProof);
    }
}

bool StartTimelord() {
    if (g_timelord) {
        LogPrintf("%s: timelord is already running", __func__);
        return false;
    }

    std::string strVdfClientPath = gArgs.GetArg("-timelord-vdf_client", "");
    std::string strBindAddress = gArgs.GetArg("-timelord-bind", "127.0.0.1");
    uint16_t port = gArgs.GetArg("-timelord-port", 9999);

    if (!fs::exists(strVdfClientPath) || !fs::is_regular_file(strVdfClientPath)) {
        LogPrintf("%s: cannot find a valid path for `vdf_client`, provided path %s\n", __func__, strVdfClientPath);
        return false;
    }

    LogPrintf("%s: start timelord on %s:%d, vdf_client=%s\n", __func__, strBindAddress, port, strVdfClientPath);
    g_timelordThread = std::thread([strVdfClientPath, strBindAddress, port]() {
        net::io_context ioc;
        g_timelord = std::unique_ptr<CTimeLord>(new CTimeLord(ioc, strVdfClientPath, strBindAddress, port));
        g_timelord->Start(HandleProofProc);
        ioc.run();
    });

    return true;
}

bool StopTimelord() {
    if (g_timelord == nullptr) {
        return false;
    }
    g_timelord->Stop();
    return true;
}

void WaitTimelord() {
    if (g_timelord == nullptr) {
        return;
    }
    g_timelord->Wait();
}

void UpdateChallengeToTimelord(uint256 challenge, uint64_t iters) {
    // first we query the proof from cache
    CTimeLord::ProofRecord proof_record;
    bool found = g_timelord->QueryIters(challenge, iters, proof_record);
    if (found) {
        LogPrintf("%s: got a proof from cache, challenge: %s, iters=%s\n", __func__, challenge.GetHex(), chiapos::FormatNumberStr(std::to_string(iters)));
        // Handle it here and exit
        HandleProofProc(proof_record.proof, proof_record.iters, proof_record.duration, proof_record.challenge);
        return;
    }
    // trying to invoke method from the timelord
    if (g_timelord->GetCurrentChallenge() != challenge) {
        LogPrintf("%s: start a new timelord calculation for challenge=%s, iters=%s\n", __func__, challenge.GetHex(),
                  chiapos::FormatNumberStr(std::to_string(iters)));
        // We should start a new challenge instead of current one
        g_timelord->GoChallenge(std::move(challenge), TimeType::N, [iters](CTimeSessionPtr psession) {
            std::lock_guard<std::mutex> lg(g_mtxCalcIters);
            psession->CalcIters(iters);
        });
    } else {
        LogPrintf("%s: timelord for challenge %s is already running, send request of iters=%s\n", __func__, challenge.GetHex(),
                  chiapos::FormatNumberStr(std::to_string(iters)));
        // The challenge is good
        std::lock_guard<std::mutex> lg(g_mtxCalcIters);
        g_timelord->CalcIters(challenge, iters);
    }
}

}  // namespace chiapos
