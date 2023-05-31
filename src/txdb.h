// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXDB_H
#define BITCOIN_TXDB_H

#include <coins.h>
#include <dbwrapper.h>
#include <chain.h>
#include <primitives/block.h>

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

class CBlockIndex;
class uint256;

//! No need to periodic flush if at least this much space still available.
static constexpr int MAX_BLOCK_COINSDB_USAGE = 10;
//! -dbcache default (MiB)
static const int64_t nDefaultDbCache = 450;
//! -dbbatchsize default (bytes)
static const int64_t nDefaultDbBatchSize = 16 << 20;
//! max. -dbcache (MiB)
static const int64_t nMaxDbCache = sizeof(void*) > 4 ? 16384 : 1024;
//! min. -dbcache (MiB)
static const int64_t nMinDbCache = 4;
//! Max memory allocated to block tree DB specific cache, if no -txindex (MiB)
static const int64_t nMaxBlockDBCache = 2;
//! Max memory allocated to block tree DB specific cache, if -txindex (MiB)
// Unlike for the UTXO database, for the txindex scenario the leveldb cache make
// a meaningful difference: https://github.com/bitcoin/bitcoin/pull/8273#issuecomment-229601991
static const int64_t nMaxTxIndexCache = 1024;
//! Max memory allocated to all block filter index caches combined in MiB.
static const int64_t max_filter_index_cache = 1024;
//! Max memory allocated to coin DB specific cache (MiB)
static const int64_t nMaxCoinsDBCache = 8;

/** CCoinsView backed by the coin database (chainstate/) */
class CCoinsViewDB final : public CCoinsView
{
protected:
    mutable CDBWrapper db;
public:
    /**
     * @param[in] ldb_path    Location in the filesystem where leveldb data will be stored.
     */
    explicit CCoinsViewDB(fs::path ldb_path, size_t nCacheSize, bool fMemory, bool fWipe);

    bool GetCoin(const COutPoint &outpoint, Coin &coin) const override;
    bool HaveCoin(const COutPoint &outpoint) const override;
    uint256 GetBestBlock() const override;
    std::vector<uint256> GetHeadBlocks() const override;
    bool BatchWrite(CCoinsMap &mapCoins, const uint256 &hashBlock) override;
    CCoinsViewCursorRef Cursor() const override;
    CCoinsViewCursorRef Cursor(const CAccountID &accountID) const override;
    CCoinsViewCursorRef PointSendCursor(const CAccountID &accountID, PointType pt) const override;
    CCoinsViewCursorRef PointReceiveCursor(const CAccountID &accountID, PointType pt) const override;

    //! Attempt to update from an older database format. Returns whether an error occurred.
    bool Upgrade(bool &fUpgraded);
    size_t EstimateSize() const override;

    /**
    * @brief Calculate balance for an account
    *
    * @param accountID The account
    * @param mapChildCoins The cached coins
    * @param balanceBindPlotter Get balance for binding plotters
    * @param balancePointSend Get balance for the amount which was sent from this account
    * @param balancePointReceive Get balance for the amount which has received to this account
    * @param terms The term from consensus, chia consensus calculation will be applied only when this parameter isn't null
    * @param nHeight The height for calculating balance with chia consensus
    *
    * @return The coin balance of account, other balances will be returned by parameters `balance*'.
    */
    CAmount GetBalance(const CAccountID &accountID, const CCoinsMap &mapChildCoins, CAmount *balanceBindPlotter, CAmount *balancePointSend, CAmount *balancePointReceive, PledgeTerms const* terms, int nHeight) const override;

    CBindPlotterCoinsMap GetAccountBindPlotterEntries(const CAccountID &accountID, const CPlotterBindData &bindData = {}) const override;
    CBindPlotterCoinsMap GetBindPlotterEntries(const CPlotterBindData &bindData) const override;

private:
    CAmount GetBalanceBind(CPlotterBindData::Type type, CAccountID const& accountID, CCoinsMap const& mapChildCoins) const;

    CAmount GetCoinBalance(const CAccountID &accountID, const CCoinsMap &mapChildCoins, int nHeight) const;

    CAmount GetBalancePointSend(DatacarrierType type, CAccountID const& accountID, CCoinsMap const& mapChildCoins) const;

    CAmount CalculateTermAmount(CAmount coinAmount, PledgeTerm const& term, PledgeTerm const& fallbackTerm, int nPointHeight, int nHeight) const;

    CAmount GetBalancePointReceive(DatacarrierType type, CAccountID const& accountID, CCoinsMap const& mapChildCoins, PledgeTerms const* terms, int nHeight) const;

    CAmount CalculatePledgeAmountFromRetargetCoin(CAmount pointAmount, DatacarrierType pointType, int nPointHeight, PledgeTerms const& terms, int nHeight) const;

    CAmount GetBalancePointRetargetSend(CAccountID const& accountID, CCoinsMap const& mapChildCoins, PledgeTerms const* terms, int nHeight) const;

    CAmount GetBalancePointRetargetReceive(CAccountID const& accountID, CCoinsMap const& mapChildCoins, PledgeTerms const* terms, int nHeight) const;
};

/** Access to the block database (blocks/index/) */
class CBlockTreeDB : public CDBWrapper
{
public:
    explicit CBlockTreeDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

    bool WriteBatchSync(const std::vector<std::pair<int, const CBlockFileInfo*> >& fileInfo, int nLastFile, const std::vector<const CBlockIndex*>& blockinfo, const Consensus::Params &consensusParams);
    bool ReadBlockFileInfo(int nFile, CBlockFileInfo &info);
    bool ReadLastBlockFile(int &nFile);
    bool WriteReindexing(bool fReindexing);
    void ReadReindexing(bool &fReindexing);
    bool WriteFlag(const std::string &name, bool fValue);
    bool ReadFlag(const std::string &name, bool &fValue);
    bool LoadBlockIndexGuts(const Consensus::Params& consensusParams, std::function<CBlockIndex*(const uint256&)> insertBlockIndex);
};

#endif // BITCOIN_TXDB_H
