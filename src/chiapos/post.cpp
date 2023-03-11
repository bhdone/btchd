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
#include <boost/asio.hpp>
#include <cstdint>
#include <memory>

#include "newblock_watcher.hpp"

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

    int nVdfPerSec = fields.GetTotalIters() / fields.GetTotalDuration();
    if (nVdfPerSec < params.BHDIP009VdfMinPerSec) {
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, SZ_BAD_WHAT, "vdf speed is too low");
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
        LogPrintf("%s: incorrect difficulty, expect: %s, actual: %s, difficulty-prev: %s, duration: %lld\n", __func__,
                chiapos::FormatNumberStr(std::to_string(nDifficulty)), chiapos::FormatNumberStr(std::to_string(fields.nDifficulty)),
                chiapos::FormatNumberStr(std::to_string(nDifficultyPrev)), fields.GetTotalDuration());
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
    if (!CheckPosProof(fields.posProof, state, params, nTargetHeight)) {
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
    uint64_t nItersRequired = CalculateIterationsQuality(mixed_quality_string, nDifficultyPrev, params.BHDIP009DifficultyConstantFactorBits);
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
    LogPrint(BCLog::NET, "%s: VDF proof `%s`, iters=%ld (%s) is saved\n", __func__, vdf.challenge.GetHex(),
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

static MinerGroups g_minergroups;
std::mutex g_mtx_minergroups;

void UpdateMinerGroup(Bytes const& farmerPk, uint256 const& groupHash, uint64_t size)
{
    std::lock_guard<std::mutex> lg(g_mtx_minergroups);
    MinerGroups::iterator it;
    bool inserted;
    std::tie(it, inserted) = g_minergroups.insert(std::make_pair(farmerPk, std::map<uint256, uint64_t> { { groupHash, size } }));
    if (!inserted) {
        std::map<uint256, uint64_t>::iterator it2;
        std::tie(it2, inserted) = it->second.insert(std::make_pair(groupHash, size));
        if (!inserted) {
            it2->second = size;
        }
    }
}

MinerGroups const& QueryAllMinerGroups()
{
    return g_minergroups;
}

void ClearAllMinerGroups()
{
    std::lock_guard<std::mutex> lg(g_mtx_minergroups);
    g_minergroups.clear();
}

struct PosQuality {
    CPosProof pos;
    uint64_t quality;
};
static std::map<uint256, std::vector<PosQuality>> g_posquality;

bool IsTheBestPos(CPosProof const& pos, uint64_t quality)
{
    auto it = g_posquality.find(pos.challenge);
    if (it == std::end(g_posquality)) {
        return true;
    }
    if (quality == 0) {
        quality = CalculateQuality(pos);
    }
    for (auto const& pq : it->second) {
        if (pq.quality > quality) {
            return false;
        }
    }
    return true;
}

void SavePosQuality(CPosProof const& pos, uint256 const& groupHash, uint64_t nTotalSize, uint64_t quality)
{
    UpdateMinerGroup(pos.vchFarmerPk, groupHash, nTotalSize);

    // Calculate the quality
    if (quality == 0) {
        quality = CalculateQuality(pos);
    }
    auto it = g_posquality.find(pos.challenge);
    if (it == std::end(g_posquality)) {
        g_posquality.insert(std::make_pair(pos.challenge, std::vector<PosQuality> { { pos, quality } }));
    } else {
        it->second.push_back({ pos, quality });
    }
}

void SendPosPreviewOverP2PNetwork(CConnman* connman, CPosProof const& pos, uint256 const& groupHash, uint64_t nTotalSize, CNode* pfrom, NodeChecker checker) {
    connman->ForEachNode([connman, &pos, pfrom, &checker, &groupHash, nTotalSize](CNode* pnode) {
        if (pfrom && pfrom->GetId() == pnode->GetId()) {
            // Same node, exit
            return;
        }
        if (!checker(pnode)) {
            return;
        }
        connman->PushMessage(pnode, CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::POSPREVIEW, pos, groupHash, nTotalSize));
    });
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

static asio::io_context g_iocTimelord;

static std::unique_ptr<std::thread> g_pTimelordThread;
static std::vector<std::shared_ptr<TimelordClient>> g_timelordVec;

static std::atomic_int g_nProofCallbackIdx{0};
static std::map<int, TimelordProofCallback> g_vProofCallback;

int RegisterTimelordProofHandler(TimelordProofCallback callback) {
	++g_nProofCallbackIdx;
	int idx = g_nProofCallbackIdx;
	asio::post(g_iocTimelord, [idx, callback]() {
		g_vProofCallback.insert(std::make_pair(idx, std::move(callback)));
	});
    return idx;
}

void UnregisterTimelordProofHandler(int nIndex) {
	asio::post(g_iocTimelord, [nIndex]() {
		auto i = g_vProofCallback.find(nIndex);
		if (i != std::end(g_vProofCallback)) {
			g_vProofCallback.erase(i);
		}
	});
}

bool IsTimelordRunning() { return g_pTimelordThread != nullptr; }

bool StartTimelord(std::string const& hosts_str) {
	if (g_pTimelordThread != nullptr) {
		// the core thread is already running
		return false;
	}
	auto hosts = ParseHostsStr(hosts_str, 19191);
	if (hosts.empty()) {
		// there is no host can be parsed from the string
		return false;
	}
	// query the address for each hostname
	for (auto const& host_entry : hosts) {
		auto pTimelordClient = std::make_shared<TimelordClient>(g_iocTimelord);
		asio::post(g_iocTimelord, [pTimelordClient]() {
			g_timelordVec.push_back(pTimelordClient);
		});
		auto pweak = std::weak_ptr<TimelordClient>(pTimelordClient);
		pTimelordClient->SetErrorHandler([pweak](FrontEndClient::ErrorType type, std::string const& errs) {
			// the timelord client should be released
			auto pTimelordClient = pweak.lock();
			auto it = std::remove(std::begin(g_timelordVec), std::end(g_timelordVec), pTimelordClient);
			g_timelordVec.erase(it, std::end(g_timelordVec));
		});
		pTimelordClient->SetProofReceiver([](uint256 const& challenge, ProofDetail const& detail) {
			if (g_vProofCallback.empty()) {
				return;
			}
			CVdfProof vdfProof;
			vdfProof.vchY = detail.y;
			vdfProof.vchProof = detail.proof;
			vdfProof.nWitnessType = detail.witness_type;
			vdfProof.nVdfIters = std::max<uint64_t>(1, detail.iters);
			vdfProof.nVdfDuration = std::max<uint64_t>(1, detail.duration);
			vdfProof.challenge = challenge;
			for (auto const& p : g_vProofCallback) {
				p.second(vdfProof);
			}
		});
	}
	g_pTimelordThread.reset(new std::thread([]() {
		g_iocTimelord.run();
	}));

    return true;
}

bool StopTimelord() {
	if (g_pTimelordThread == nullptr) {
		return false;
	}
	asio::post(g_iocTimelord, []() {
		for (auto pTimelordClient : g_timelordVec) {
			pTimelordClient->Exit();
		}
		g_timelordVec.clear();
	});
	if (g_pTimelordThread->joinable()) {
		g_pTimelordThread->join();
		g_pTimelordThread.reset();
	}
	return true;
}

using ChallengePair = std::pair<uint256, uint64_t>;
std::set<ChallengePair> g_queried_challenges;

void UpdateChallengeToTimelord(uint256 challenge, uint64_t iters) {
    if (g_queried_challenges.find(std::make_pair(challenge, iters)) != std::end(g_queried_challenges)) {
        return;
    }
    asio::post(g_iocTimelord, [challenge, iters]() {
        // deliver the iters to every timelord clients
        for (auto pTimelordClient : g_timelordVec) {
            pTimelordClient->Calc(challenge, iters);
        }
    });
}

static NewBlockWatcher g_watcher;

bool IsBlockWatcherRunning() {
    return g_watcher.IsRunning();
}

void StartBlockWatcher() {
    g_watcher.Start();
}

NewBlockWatcher& GetBlockWatcher() {
    return g_watcher;
}

void StopBlockWatcher() {
    g_watcher.Exit();
}

}  // namespace chiapos
