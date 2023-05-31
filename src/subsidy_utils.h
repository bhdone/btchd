#ifndef SUBSIDY_UTILS_H
#define SUBSIDY_UTILS_H

#include <amount.h>
#include <sync.h>
#include <threadsafety.h>
#include <consensus/params.h>

extern CCriticalSection cs_main;

/** Get block subsidy */
CAmount GetBlockSubsidy(int nHeight, const Consensus::Params& consensusParams) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

CAmount GetTotalSupplyBeforeHeight(int nHeight, Consensus::Params const& params) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

CAmount GetTotalSupplyBeforeBHDIP009(Consensus::Params const& params) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

int GetHeightForCalculatingTotalSupply(int nCurrHeight, Consensus::Params const& params);

#endif
