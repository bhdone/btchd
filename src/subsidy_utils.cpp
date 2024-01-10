#include "subsidy_utils.h"

/**
 * Mutex to guard access to validation specific variables, such as reading
 * or changing the chainstate.
 *
 * This may also need to be locked when updating the transaction pool, e.g. on
 * AcceptToMemoryPool. See CTxMemPool::cs comment for details.
 *
 * The transaction pool has a separate lock to allow reading from it and the
 * chainstate at the same time.
 */
RecursiveMutex cs_main;

CAmount GetBlockSubsidy(int nHeight, Consensus::Params const& consensusParams) {
    CAmount nSubsidy;

    int halvings;
    if (nHeight < consensusParams.BHDIP008Height) {
        halvings = nHeight / (consensusParams.nSubsidyHalvingInterval * 600 / consensusParams.BHDIP001TargetSpacing);
    } else {
        // 197568*5/3=329280, First halving height is 568288 (=197568+(700000-329280))
        // 106848*5/3=178080, First halving height is 628768 (=106848+(700000-178080))
        // 720*5/3=1200, First halving height is 520 (=720+(1000-1200))
        int nEqualHeight = consensusParams.BHDIP008Height * consensusParams.BHDIP001TargetSpacing /
                           consensusParams.BHDIP008TargetSpacing;
        halvings = (nHeight - consensusParams.BHDIP008Height + nEqualHeight) /
                   (consensusParams.nSubsidyHalvingInterval * 600 / consensusParams.BHDIP008TargetSpacing);
    }
    if (halvings >= 64) {
        // Force block reward to zero when right shift is undefined.
        nSubsidy = 0;
    } else {
        nSubsidy = 50 * COIN * Consensus::GetTargetSpacing(nHeight, consensusParams) / 600;
        // Subsidy is cut in half every 210,000 blocks / 10minutes which will occur approximately every 4 years.
        nSubsidy >>= halvings;
    }

    // Force to double the outcome on BHDIP009
    if (nHeight >= consensusParams.BHDIP009Height) {
        return nSubsidy * consensusParams.BHDIP009TotalAmountUpgradeMultiply;
    }

    // TODO: after BHDIP010 the total subsidy of the block should be increased

    return nSubsidy;
}

CAmount GetTotalSupplyBeforeHeight(int nHeight, Consensus::Params const& params) {
    CAmount totalReward{0};
    for (int i = 0; i < nHeight; ++i) {
        CAmount blockReward = GetBlockSubsidy(i, params);
        totalReward += blockReward;
    }
    return totalReward;
}

CAmount GetTotalSupplyBeforeBHDIP009(Consensus::Params const& params) {
    return GetTotalSupplyBeforeHeight(params.BHDIP009Height, params);
}

int GetHeightForCalculatingTotalSupply(int nCurrHeight, Consensus::Params const& params) {
    int nHeight = (nCurrHeight - params.BHDIP009Height) / params.BHDIP009CalculateDistributedAmountEveryHeights *
                          params.BHDIP009CalculateDistributedAmountEveryHeights +
                  params.BHDIP009Height;
    return nHeight;
}
