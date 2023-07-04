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

uint256 MakeChallenge(CBlockIndex const* pindex, Consensus::Params const& params);

bool CheckPosProof(CPosProof const& proof, CValidationState& state, Consensus::Params const& params, int nTargetHeight);

bool CheckVdfProof(CVdfProof const& proof, CValidationState& state);

bool CheckBlockFields(CBlockFields const& fields, uint64_t nTimeOfTheBlock, CBlockIndex const* pindexPrev,
                      CValidationState& state, Consensus::Params const& params);

bool ReleaseBlock(std::shared_ptr<CBlock> pblock, CChainParams const& params);

bool IsTheChainReadyForChiapos(CBlockIndex const* pindex, Consensus::Params const& params);

uint64_t GetChiaBlockDifficulty(CBlockIndex const* pindex, Consensus::Params const& params);

uint64_t GetDifficultyForNextIterations(CBlockIndex const* pindex, Consensus::Params const& params);

int GetBaseIters(int nTargetHeight, Consensus::Params const& params);

}  // namespace chiapos

#endif
