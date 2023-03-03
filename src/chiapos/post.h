#ifndef BTCHD_CHIAPOS_POST_H
#define BTCHD_CHIAPOS_POST_H

#include <chain.h>
#include <chiapos/kernel/calc_diff.h>
#include <chiapos/kernel/chiapos_types.h>
#include <chiapos/kernel/pos.h>
#include <chiapos/kernel/utils.h>
#include <chiapos/kernel/vdf.h>
#include <consensus/validation.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <tuple>
#include <vector>

class CChainParams;
class CConnman;
class CNode;
struct CBlockTemplate;

namespace chiapos {

class NewBlockWatcher;

uint256 MakeChallenge(CBlockIndex* pindex, Consensus::Params const& params);

bool CheckPosProof(CPosProof const& proof, CValidationState& state, Consensus::Params const& params, int nTargetHeight);

bool CheckVdfProof(CVdfProof const& proof, CValidationState& state);

bool CheckBlockFields(CBlockFields const& fields, uint64_t nTimeOfTheBlock, CBlockIndex const* pindexPrev,
                      CValidationState& state, Consensus::Params const& params);

bool ReleaseBlock(std::shared_ptr<CBlock> pblock, CChainParams const& params);

bool IsTheChainReadyForChiapos(CBlockIndex const* pindex, Consensus::Params const& params);

bool SubmitVdfProofPacket(CVdfProof const& vdf);

optional<CVdfProof> QueryReceivedVdfProofPacket(uint256 const& challenge);

using NodeChecker = std::function<bool(CNode* pnode)>;
struct NodeIsAlwaysGood {
    bool operator()(CNode*) const { return true; }
};

using SentHandler = std::function<void(CNode* pnode)>;

void SendPosPreviewOverP2PNetwork(CConnman* connman, CPosProof const& pos, CNode* pfrom = nullptr, NodeChecker checker = NodeIsAlwaysGood());

bool IsTheBestPos(CPosProof const& pos, uint64_t quality = 0);

void SavePosQuality(CPosProof const& pos, uint64_t quality = 0);

void SendVdfProofOverP2PNetwork(CConnman* connman, CVdfProof const& vdf, CNode* pfrom = nullptr,
                                NodeChecker checker = NodeIsAlwaysGood());

void SendRequireVdfOverP2PNetwork(CConnman* connman, uint256 const& challenge, uint64_t nIters, CNode* pfrom = nullptr,
                                  NodeChecker checker = NodeIsAlwaysGood(), SentHandler sentHandler = [](CNode*){});

using TimelordProofCallback = std::function<void(CVdfProof const&)>;

int RegisterTimelordProofHandler(TimelordProofCallback callback);

void UnregisterTimelordProofHandler(int nIndex);

bool IsTimelordRunning();

bool StartTimelord();

bool StopTimelord();

void WaitTimelord();

void UpdateChallengeToTimelord(uint256 challenge, uint64_t iters);

bool IsBlockWatcherRunning();

void StartBlockWatcher();

NewBlockWatcher& GetBlockWatcher();

void StopBlockWatcher();

}  // namespace chiapos

#endif
