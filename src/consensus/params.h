// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include <amount.h>
#include <uint256.h>
#include <limits>
#include <map>
#include <array>
#include <set>
#include <string>

#include <chiapos/kernel/chiapos_types.h>

#include "pledge_term.h"

namespace Consensus {

enum DeploymentPos
{
    DEPLOYMENT_TESTDUMMY,
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in versionbits.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit;
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime;
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout;

    /** Constant for nTimeout very far in the future. */
    static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();

    /** Special value for nStartTime indicating that the deployment is always active.
     *  This is useful for testing, as it means tests don't need to deal with the activation
     *  process (which takes at least 3 BIP9 intervals). Only tests that specifically test the
     *  behaviour during activation cannot use this. */
    static constexpr int64_t ALWAYS_ACTIVE = -1;
};

struct BHDIP009PledgeRewardPercentForLockPeriod {
    uint64_t nNumOfBlocks;
    double percent;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    /** BitcoinHD1 Fund address */
    std::string BHDFundAddress;
    std::set<std::string> BHDFundAddressPool;

    uint256 hashGenesisBlock;
    /** Subsidy halving interval blocks base on 600 seconds */
    int nSubsidyHalvingInterval;
    int nCapacityEvalWindow;

    /** BHDIP = BitcoinHD1 Improvement Proposals, like BIP */
    /** BitcoinHD1 target spacing */
    int BHDIP001TargetSpacing;
    /** BitcoinHD1 fund pre-mining height */
    int BHDIP001PreMiningEndHeight;
    /** BitcoinHD1 fund zero height */
    int BHDIP001FundZeroLastHeight;
    /** BitcoinHD1 fund royalty for full pledge. 1000% */
    int BHDIP001FundRoyaltyForFullMortgage;
    /** BitcoinHD1 fund royalty for low pledge. 1000% */
    int BHDIP001FundRoyaltyForLowMortgage;
    /** BitcoinHD1 miner mining ratio per TB */
    CAmount BHDIP001MiningRatio;

    /** View all BHDIP document on https://bhd.one/wiki/BHDIP */
    /** Block height at which BHDIP004 becomes active */
    int BHDIP004Height;
    /** Block height at which BHDIP004 becomes inactive */
    int BHDIP004AbandonHeight;

    /** Block height at which BHDIP006 becomes active */
    int BHDIP006Height;
    /** Block height at which BHDIP006 bind plotter becomes active */
    int BHDIP006BindPlotterActiveHeight;
    int BHDIP006CheckRelayHeight;
    int BHDIP006LimitBindPlotterHeight;

    /** Block height at which BHDIP007 becomes active */
    int BHDIP007Height;
    int BHDIP007SmoothEndHeight;
    int64_t BHDIP007MiningRatioStage;

    /** Block height at which BHDIP008 becomes active */
    int BHDIP008Height;
    int BHDIP008TargetSpacing;
    int BHDIP008FundRoyaltyForLowMortgage;
    int BHDIP008FundRoyaltyDecreaseForLowMortgage;
    int BHDIP008FundRoyaltyDecreasePeriodForLowMortgage;

    /** Block height at which BHDIP009 (chiapos) becomes active */
    bool BHDIP009SkipTestChainChecks; // flag set to True only when building a test chain (skip the check procedure for burst blocks)
    int BHDIP009Height;
    int BHDIP009StartVerifyingVdfDurationHeight;
    int BHDIP009OldPledgesDisableOnHeight;
    std::vector<std::string> BHDIP009FundAddresses;
    int BHDIP009FundRoyaltyForLowMortgage;
    uint64_t BHDIP009StartDifficulty;
    uint64_t BHDIP009StartBlockIters;
    int BHDIP009DifficultyEvalWindow;
    int BHDIP009DifficultyConstantFactorBits;
    int BHDIP009PlotIdBitsOfFilter;
    int BHDIP009PlotIdBitsOfFilterEnableOnHeight;
    int BHDIP009PlotSizeMin;
    int BHDIP009PlotSizeMax;
    int BHDIP009BaseIters;
    std::vector<std::pair<int, int>> BHDIP009BaseItersVec;
    int BHDIP009TotalAmountUpgradeMultiply;
    int BHDIP009CalculateDistributedAmountEveryHeights;
    int BHDIP009PledgeRetargetMinHeights;
    double BHDIP009DifficultyChangeMaxFactor;

    std::array<PledgeTerm, 4> BHDIP009PledgeTerms;

    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nPocTargetTimespan / BHDIP001TargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    int nRuleChangeActivationThreshold;
    int nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];

    /** Proof of Capacity parameters */
    bool fAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    uint256 nMinimumChainWork;
    uint256 defaultAssumeValid;

    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    /** Block height at which BIP65 becomes active */
    int BIP65Height;
    /** Block height at which BIP66 becomes active */
    int BIP66Height;
    /** Block height at which CSV (BIP68, BIP112 and BIP113) becomes active */
    int CSVHeight;
    /** Block height at which Segwit (BIP141, BIP143 and BIP147) becomes active.
     * Note that segwit v0 script rules are enforced on all blocks except the
     * BIP 16 exception blocks. */
    int SegwitHeight;
};

// Get target time space
inline int GetTargetSpacing(int nHeight, const Params& params) {
    return nHeight >= params.BHDIP008Height ? params.BHDIP008TargetSpacing : params.BHDIP001TargetSpacing;
}

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
