// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txdb.h>

#include <chainparams.h>
#include <hash.h>
#include <random.h>
#include <shutdown.h>
#include <ui_interface.h>
#include <uint256.h>
#include <util/system.h>
#include <util/translation.h>
#include <validation.h>

#include <exception>
#include <map>
#include <set>
#include <stdexcept>
#include <unordered_map>

#include <stdint.h>
#include <inttypes.h>
#include <optional.h>

#include <boost/thread.hpp>
#include "coins.h"
#include "logging.h"
#include "script/standard.h"
#include "tinyformat.h"

/** UTXO version flag */
static const char DB_COIN_VERSION = 'V';
static const uint32_t DB_VERSION = 0x11;

static const char DB_COIN = 'C';
static const char DB_BLOCK_FILES = 'f';
static const char DB_BLOCK_INDEX = 'b';
static const char DB_BLOCK_GENERATOR_INDEX = 'g';

static const char DB_BEST_BLOCK = 'B';
static const char DB_HEAD_BLOCKS = 'H';
static const char DB_FLAG = 'F';
static const char DB_REINDEX_FLAG = 'R';
static const char DB_LAST_BLOCK = 'l';

static const char DB_COIN_INDEX = 'T';
static const char DB_COIN_BINDPLOTTER = 'P';
static const char DB_COIN_BINDCHIAFARMER = 'm';
static const char DB_COIN_POINT_SEND = 'E';
static const char DB_COIN_POINT_RECEIVE = 'e'; //! DEPRECTED
static const char DB_COIN_POINT_CHIA_SEND = 'A';
static const char DB_COIN_POINT_CHIA_SEND_TERM_1 = '1';
static const char DB_COIN_POINT_CHIA_SEND_TERM_2 = '2';
static const char DB_COIN_POINT_CHIA_SEND_TERM_3 = '3';
static const char DB_COIN_POINT_CHIA_POINT_RETARGET = 'r';

namespace {

struct CoinEntry {
    COutPoint* outpoint;
    char key;
    explicit CoinEntry(const COutPoint* outputIn) : outpoint(const_cast<COutPoint*>(outputIn)), key(DB_COIN) {}

    template<typename Stream>
    void Serialize(Stream &s) const {
        s << key;
        s << outpoint->hash;
        s << VARINT(outpoint->n);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        s >> key;
        s >> outpoint->hash;
        s >> VARINT(outpoint->n);
    }
};

struct CoinIndexEntry {
    COutPoint* outpoint;
    CAccountID* accountID;
    char key;
    CoinIndexEntry(const COutPoint* outputIn, const CAccountID* accountIDIn) :
        outpoint(const_cast<COutPoint*>(outputIn)),
        accountID(const_cast<CAccountID*>(accountIDIn)),
        key(DB_COIN_INDEX) {}

    template<typename Stream>
    void Serialize(Stream &s) const {
        s << key;
        s << *accountID;
        s << outpoint->hash;
        s << VARINT(outpoint->n);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        s >> key;
        s >> *accountID;
        s >> outpoint->hash;
        s >> VARINT(outpoint->n);
    }
};

struct BindPlotterEntry {
    COutPoint* outpoint;
    CAccountID* accountID;
    char key;
    explicit BindPlotterEntry(const COutPoint* outpointIn, const CAccountID* accountIDIn, char inKey) :
        outpoint(const_cast<COutPoint*>(outpointIn)),
        accountID(const_cast<CAccountID*>(accountIDIn)),
        key(inKey) {}

    template<typename Stream>
    void Serialize(Stream &s) const {
        s << key;
        s << *accountID;
        s << outpoint->hash;
        s << VARINT(outpoint->n);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        s >> key;
        s >> *accountID;
        s >> outpoint->hash;
        s >> VARINT(outpoint->n);
    }
};

inline char GetBindKeyFromPlotterIdType(CPlotterBindData::Type type)
{
    if (type == CPlotterBindData::Type::BURST) {
        return DB_COIN_BINDPLOTTER;
    } else if (type == CPlotterBindData::Type::CHIA) {
        return DB_COIN_BINDCHIAFARMER;
    }
    throw std::runtime_error("cannot retrieve key value from an unknown plotter-id");
}

struct BindPlotterValue {
    CPlotterBindData* pbindData;
    uint32_t* nHeight;
    bool *valid;
    BindPlotterValue(const CPlotterBindData* pbindDataIn, const uint32_t* nHeightIn, const bool* validIn) :
        pbindData(const_cast<CPlotterBindData*>(pbindDataIn)),
        nHeight(const_cast<uint32_t*>(nHeightIn)),
        valid(const_cast<bool*>(validIn)) {}

    template<typename Stream>
    void Serialize(Stream &s) const {
        s << *pbindData;
        s << VARINT(*nHeight);
        s << *valid;
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        s >> *pbindData;
        s >> VARINT(*nHeight);
        s >> *valid;
    }
};

struct PointEntry {
    COutPoint* outpoint;
    CAccountID* accountID; // This is the accountID for sender
    char key;
    PointEntry(const COutPoint* outpointIn, const CAccountID* accountIDIn, char keyIn) :
        outpoint(const_cast<COutPoint*>(outpointIn)),
        accountID(const_cast<CAccountID*>(accountIDIn)),
        key(keyIn) {}

    template<typename Stream>
    void Serialize(Stream &s) const {
        s << key;
        s << *accountID;
        s << outpoint->hash;
        s << VARINT(outpoint->n);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        s >> key;
        s >> *accountID;
        s >> outpoint->hash;
        s >> VARINT(outpoint->n);
    }
};

struct PointRetargetEntry {
    COutPoint* outpoint;
    CAccountID* accountID;
    char key;
    PointRetargetEntry(const COutPoint* outpointIn, const CAccountID* accountIDIn) :
        outpoint(const_cast<COutPoint*>(outpointIn)),
        accountID(const_cast<CAccountID*>(accountIDIn)),
        key(DB_COIN_POINT_CHIA_POINT_RETARGET) {}

    template<typename Stream>
    void Serialize(Stream &s) const {
        s << key;
        s << *accountID;
        s << outpoint->hash;
        s << VARINT(outpoint->n);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        s >> key;
        s >> *accountID;
        s >> outpoint->hash;
        s >> VARINT(outpoint->n);
    }
};

struct PointRetargetValue {
    CAccountID* pReceiverID;
    DatacarrierType* pPointType;
    int* pPointHeight;

    PointRetargetValue(CAccountID* pReceiverIDIn, DatacarrierType* pPointTypeIn, int* pPointHeightIn)
        : pReceiverID(pReceiverIDIn), pPointType(pPointTypeIn), pPointHeight(pPointHeightIn) {}

    template <typename Stream>
    void Serialize(Stream& s) const {
        s << *pReceiverID;
        s << static_cast<uint32_t>(*pPointType);
        s << *pPointHeight;
    }

    template <typename Stream>
    void Unserialize(Stream& s) {
        uint32_t nPointType;
        s >> *pReceiverID;
        s >> nPointType;
        *pPointType = static_cast<DatacarrierType>(nPointType);
        s >> *pPointHeight;
    }
};

Optional<char> KeyFromDatacarrierType(DatacarrierType type) noexcept {
    if (type == DATACARRIER_TYPE_BINDPLOTTER) {
        return DB_COIN_BINDPLOTTER;
    } else if (type == DATACARRIER_TYPE_BINDCHIAFARMER) {
        return DB_COIN_BINDCHIAFARMER;
    } else if (type == DATACARRIER_TYPE_POINT) {
        return DB_COIN_POINT_SEND;
    } else if (type == DATACARRIER_TYPE_CHIA_POINT) {
        return DB_COIN_POINT_CHIA_SEND;
    } else if (type == DATACARRIER_TYPE_CHIA_POINT_TERM_1) {
        return DB_COIN_POINT_CHIA_SEND_TERM_1;
    } else if (type == DATACARRIER_TYPE_CHIA_POINT_TERM_2) {
        return DB_COIN_POINT_CHIA_SEND_TERM_2;
    } else if (type == DATACARRIER_TYPE_CHIA_POINT_TERM_3) {
        return DB_COIN_POINT_CHIA_SEND_TERM_3;
    } else if (type == DATACARRIER_TYPE_CHIA_POINT_RETARGET) {
        return DB_COIN_POINT_CHIA_POINT_RETARGET;
    } else {
        LogPrintf("%s: cannot convert datacarrierType: %s to key\n", __func__, DatacarrierTypeToString(type));
        return {};
    }
}

char KeyFromPointType(PointType type) {
    switch (type) {
    case PointType::Burst:
        return DB_COIN_POINT_SEND;
    case PointType::Chia:
        return DB_COIN_POINT_CHIA_SEND;
    case PointType::ChiaT1:
        return DB_COIN_POINT_CHIA_SEND_TERM_1;
    case PointType::ChiaT2:
        return DB_COIN_POINT_CHIA_SEND_TERM_2;
    case PointType::ChiaT3:
        return DB_COIN_POINT_CHIA_SEND_TERM_3;
    case PointType::ChiaRT:
        return DB_COIN_POINT_CHIA_POINT_RETARGET;
    }
    throw std::runtime_error("invalid point-type");
}

bool GetTerm(PledgeTerms const& terms, DatacarrierType type, PledgeTerm& outTerm, PledgeTerm& outFallbackTerm)
{
    int nTermIndex = type - DATACARRIER_TYPE_CHIA_POINT;
    assert(nTermIndex >= 0 && nTermIndex <= 3);
    outTerm = terms[nTermIndex];
    outFallbackTerm = terms[nTermIndex];
    return true;
}

DatacarrierType GetChiaPointType(Coin const& pointCoin) {
    if (!DatacarrierTypeIsChiaPoint(pointCoin.GetExtraDataType())) {
        throw std::runtime_error("invalid coin type, chia point is required!");
    }
    return pointCoin.GetExtraDataType();
}

} // namespace

CCoinsViewDB::CCoinsViewDB(fs::path ldb_path, size_t nCacheSize, bool fMemory, bool fWipe) : db(ldb_path, nCacheSize, fMemory, fWipe, true)
{
}

bool CCoinsViewDB::GetCoin(const COutPoint &outpoint, Coin &coin) const {
    return db.Read(CoinEntry(&outpoint), coin);
}

bool CCoinsViewDB::HaveCoin(const COutPoint &outpoint) const {
    return db.Exists(CoinEntry(&outpoint));
}

uint256 CCoinsViewDB::GetBestBlock() const {
    uint256 hashBestChain;
    if (!db.Read(DB_BEST_BLOCK, hashBestChain))
        return uint256();
    return hashBestChain;
}

std::vector<uint256> CCoinsViewDB::GetHeadBlocks() const {
    std::vector<uint256> vhashHeadBlocks;
    if (!db.Read(DB_HEAD_BLOCKS, vhashHeadBlocks)) {
        return std::vector<uint256>();
    }
    return vhashHeadBlocks;
}

bool CCoinsViewDB::BatchWrite(CCoinsMap &mapCoins, const uint256 &hashBlock) {
    CDBBatch batch(db);
    size_t count = 0;
    size_t changed = 0;
    size_t batch_size = (size_t)gArgs.GetArg("-dbbatchsize", nDefaultDbBatchSize);
    int crash_simulate = gArgs.GetArg("-dbcrashratio", 0);
    assert(!hashBlock.IsNull());

    uint256 old_tip = GetBestBlock();
    if (old_tip.IsNull()) {
        // We may be in the middle of replaying.
        std::vector<uint256> old_heads = GetHeadBlocks();
        if (old_heads.size() == 2) {
            assert(old_heads[0] == hashBlock);
            old_tip = old_heads[1];
        }
    }

    // In the first batch, mark the database as being in the middle of a
    // transition from old_tip to hashBlock.
    // A vector is used for future extensibility, as we may want to support
    // interrupting after partial writes from multiple independent reorgs.
    batch.Erase(DB_BEST_BLOCK);
    batch.Write(DB_HEAD_BLOCKS, std::vector<uint256>{hashBlock, old_tip});

    for (CCoinsMap::iterator it = mapCoins.begin(); it != mapCoins.end();) {
        if (it->second.flags & CCoinsCacheEntry::DIRTY) {
            if (it->second.coin.IsSpent()) {
                batch.Erase(CoinEntry(&it->first));
                if (!it->second.coin.refOutAccountID.IsNull())
                    batch.Erase(CoinIndexEntry(&it->first, &it->second.coin.refOutAccountID));
            } else {
                batch.Write(CoinEntry(&it->first), it->second.coin);
                if (!it->second.coin.refOutAccountID.IsNull())
                    batch.Write(CoinIndexEntry(&it->first, &it->second.coin.refOutAccountID), VARINT(it->second.coin.out.nValue, VarIntMode::NONNEGATIVE_SIGNED));
            }
            changed++;

            // Extra indexes. ONLY FOR vout[0]
            if (it->first.n == 0 && !it->second.coin.refOutAccountID.IsNull()) {
                std::set<DatacarrierType> tryEraseTypes { DATACARRIER_TYPE_BINDPLOTTER, DATACARRIER_TYPE_BINDCHIAFARMER, DATACARRIER_TYPE_POINT, DATACARRIER_TYPE_CHIA_POINT, DATACARRIER_TYPE_CHIA_POINT_TERM_1, DATACARRIER_TYPE_CHIA_POINT_TERM_2, DATACARRIER_TYPE_CHIA_POINT_TERM_3, DATACARRIER_TYPE_CHIA_POINT_RETARGET };
                if (it->second.coin.IsSpent()) {
                    // The coin is spent
                    if (it->second.coin.IsBindPlotter() && (it->second.flags & CCoinsCacheEntry::UNBIND)) {
                        // It's a bind-plotter tx, also it hasn't been unbind
                        tryEraseTypes.erase(it->second.coin.GetExtraDataType());
                        const CPlotterBindData &bindData = BindPlotterPayload::As(it->second.coin.extraData)->GetId();
                        uint32_t nHeight = it->second.coin.nHeight;
                        bool valid = false;
                        batch.Write(BindPlotterEntry(&it->first, &it->second.coin.refOutAccountID, GetBindKeyFromPlotterIdType(bindData.GetType())), BindPlotterValue(&bindData, &nHeight, &valid));
                    }
                } else {
                    // The coin is still available
                    if (it->second.coin.IsBindPlotter()) {
                        tryEraseTypes.erase(it->second.coin.GetExtraDataType());
                        const CPlotterBindData &bindData = BindPlotterPayload::As(it->second.coin.extraData)->GetId();
                        uint32_t nHeight = it->second.coin.nHeight;
                        bool valid = true;
                        batch.Write(BindPlotterEntry(&it->first, &it->second.coin.refOutAccountID, GetBindKeyFromPlotterIdType(bindData.GetType())), BindPlotterValue(&bindData, &nHeight, &valid));
                    }
                    else if (it->second.coin.IsPoint()) {
                        tryEraseTypes.erase(it->second.coin.GetExtraDataType());
                        DatacarrierType datacarrierType = it->second.coin.GetExtraDataType();
                        auto dbKey = KeyFromDatacarrierType(datacarrierType);
                        if (!dbKey.has_value()) {
                            throw std::runtime_error(strprintf("%s(%s:%d): cannot parse key from datacarrierType", __func__, __FILE__, __LINE__));
                        }
                        batch.Write(PointEntry(&it->first, &it->second.coin.refOutAccountID, *dbKey), PointPayload::As(it->second.coin.extraData)->GetReceiverID());
                    }
                    else if (it->second.coin.IsPointRetarget()) {
                        tryEraseTypes.erase(it->second.coin.GetExtraDataType());
                        auto payload = PointRetargetPayload::As(it->second.coin.extraData);
                        CAccountID receiverID = payload->GetReceiverID();
                        DatacarrierType pointType = payload->GetPointType();
                        int nPointHeight = payload->GetPointHeight();
                        PointRetargetValue value(&receiverID, &pointType, &nPointHeight);
                        batch.Write(PointRetargetEntry(&it->first, &it->second.coin.refOutAccountID), value);
                    }
                }

                for (auto const& type : tryEraseTypes) {
                    if (type == DATACARRIER_TYPE_BINDPLOTTER) {
                        batch.Erase(BindPlotterEntry(&it->first, &it->second.coin.refOutAccountID, DB_COIN_BINDPLOTTER));
                    } else if (type == DATACARRIER_TYPE_BINDCHIAFARMER) {
                        batch.Erase(BindPlotterEntry(&it->first, &it->second.coin.refOutAccountID, DB_COIN_BINDCHIAFARMER));
                    } else if (type == DATACARRIER_TYPE_POINT) {
                        batch.Erase(PointEntry(&it->first, &it->second.coin.refOutAccountID, DB_COIN_POINT_SEND));
                    } else if (type == DATACARRIER_TYPE_CHIA_POINT) {
                        batch.Erase(PointEntry(&it->first, &it->second.coin.refOutAccountID, DB_COIN_POINT_CHIA_SEND));
                    } else if (type == DATACARRIER_TYPE_CHIA_POINT_TERM_1) {
                        batch.Erase(PointEntry(&it->first, &it->second.coin.refOutAccountID, DB_COIN_POINT_CHIA_SEND_TERM_1));
                    } else if (type == DATACARRIER_TYPE_CHIA_POINT_TERM_2) {
                        batch.Erase(PointEntry(&it->first, &it->second.coin.refOutAccountID, DB_COIN_POINT_CHIA_SEND_TERM_2));
                    } else if (type == DATACARRIER_TYPE_CHIA_POINT_TERM_3) {
                        batch.Erase(PointEntry(&it->first, &it->second.coin.refOutAccountID, DB_COIN_POINT_CHIA_SEND_TERM_3));
                    } else if (type == DATACARRIER_TYPE_CHIA_POINT_RETARGET) {
                        batch.Erase(PointRetargetEntry(&it->first, &it->second.coin.refOutAccountID));
                    }
                }
            }
        }

        count++;
        CCoinsMap::iterator itOld = it++;
        mapCoins.erase(itOld);
        if (batch.SizeEstimate() > batch_size) {
            LogPrint(BCLog::COINDB, "Writing partial batch of %.2f MiB\n", batch.SizeEstimate() * (1.0 / 1048576.0));
            db.WriteBatch(batch);
            batch.Clear();
            if (crash_simulate) {
                static FastRandomContext rng;
                if (rng.randrange(crash_simulate) == 0) {
                    LogPrintf("Simulating a crash. Goodbye.\n");
                    _Exit(0);
                }
            }
        }
    }

    // In the last batch, mark the database as consistent with hashBlock again.
    batch.Erase(DB_HEAD_BLOCKS);
    batch.Write(DB_BEST_BLOCK, hashBlock);

    LogPrint(BCLog::COINDB, "Writing final batch of %.2f MiB\n", batch.SizeEstimate() * (1.0 / 1048576.0));
    bool ret = db.WriteBatch(batch);
    LogPrint(BCLog::COINDB, "Committed %u changed transaction outputs (out of %u) to coin database...\n", (unsigned int)changed, (unsigned int)count);
    return ret;
}

CCoinsViewCursorRef CCoinsViewDB::Cursor() const {
    /** Specialization of CCoinsViewCursor to iterate over a CCoinsViewDB */
    class CCoinsViewDBCursor : public CCoinsViewCursor
    {
    public:
        CCoinsViewDBCursor(CDBIterator* pcursorIn, const uint256 &hashBlockIn) : CCoinsViewCursor(hashBlockIn), pcursor(pcursorIn) {
            /* It seems that there are no "const iterators" for LevelDB.  Since we
               only need read operations on it, use a const-cast to get around
               that restriction.  */
            pcursor->Seek(DB_COIN);
            // Cache key of first record
            if (pcursor->Valid()) {
                CoinEntry entry(&keyTmp.second);
                pcursor->GetKey(entry);
                keyTmp.first = entry.key;
            }
            else {
                keyTmp.first = 0; // Make sure Valid() and GetKey() return false
            }
        }

        bool GetKey(COutPoint &key) const override {
            // Return cached key
            if (keyTmp.first == DB_COIN) {
                key = keyTmp.second;
                return true;
            }
            return false;
        }

        bool GetValue(Coin &coin) const override { return pcursor->GetValue(coin); }
        unsigned int GetValueSize() const override { return pcursor->GetValueSize(); }

        bool Valid() const override { return keyTmp.first == DB_COIN; }
        void Next() override {
            pcursor->Next();
            CoinEntry entry(&keyTmp.second);
            if (!pcursor->Valid() || !pcursor->GetKey(entry)) {
                keyTmp.first = 0; // Invalidate cached key after last record so that Valid() and GetKey() return false
            }
            else {
                keyTmp.first = entry.key;
            }
        }

    private:
        std::unique_ptr<CDBIterator> pcursor;
        std::pair<char, COutPoint> keyTmp;
    };

    return std::make_shared<CCoinsViewDBCursor>(db.NewIterator(), GetBestBlock());
}

CCoinsViewCursorRef CCoinsViewDB::Cursor(const CAccountID &accountID) const {
    class CCoinsViewDBCursor : public CCoinsViewCursor
    {
    public:
        CCoinsViewDBCursor(const CAccountID& accountIDIn, const CCoinsViewDB* pcoinviewdbIn, CDBIterator* pcursorIn, const uint256& hashBlockIn)
                : CCoinsViewCursor(hashBlockIn), accountID(accountIDIn), pcoinviewdb(pcoinviewdbIn), pcursor(pcursorIn), outpoint(uint256(), 0) {
            // Seek cursor
            pcursor->Seek(CoinIndexEntry(&outpoint, &accountID));
            TestKey();
        }

        bool GetKey(COutPoint &key) const override {
            // Return cached key
            if (!outpoint.IsNull()) {
                key = outpoint;
                return true;
            }
            return false;
        }

        bool GetValue(Coin &coin) const override { return pcoinviewdb->GetCoin(outpoint, coin); }
        unsigned int GetValueSize() const override { return pcursor->GetValueSize(); }

        bool Valid() const override { return !outpoint.IsNull(); }
        void Next() override {
            pcursor->Next();
            TestKey();
        }

    private:
        void TestKey() {
            CAccountID tempAccountID;
            CoinIndexEntry entry(&outpoint, &tempAccountID);
            if (!pcursor->Valid() || !pcursor->GetKey(entry) || entry.key != DB_COIN_INDEX || tempAccountID != accountID) {
                outpoint.SetNull();
            }
        }

        const CAccountID accountID;
        const CCoinsViewDB* pcoinviewdb;
        std::unique_ptr<CDBIterator> pcursor;
        COutPoint outpoint;
    };

    return std::make_shared<CCoinsViewDBCursor>(accountID, this, db.NewIterator(), GetBestBlock());
}

CCoinsViewCursorRef CCoinsViewDB::PointSendCursor(const CAccountID &accountID, PointType pt) const {
    class CCoinsViewDBPointSendCursor : public CCoinsViewCursor
    {
    public:
        CCoinsViewDBPointSendCursor(const CAccountID& accountIDIn, const CCoinsViewDB* pcoinviewdbIn, CDBIterator* pcursorIn, const uint256& hashBlockIn, char keyIn)
                : CCoinsViewCursor(hashBlockIn), senderAccountID(accountIDIn), pcoinviewdb(pcoinviewdbIn), pcursor(pcursorIn), outpoint(uint256(), 0) {
            // Seek cursor
            pcursor->Seek(PointEntry(&outpoint, &senderAccountID, key));
            TestKey();
        }

        bool GetKey(COutPoint &key) const override {
            // Return cached key
            if (!outpoint.IsNull()) {
                key = outpoint;
                return true;
            }
            return false;
        }

        bool GetValue(Coin &coin) const override { return pcoinviewdb->GetCoin(outpoint, coin); }
        unsigned int GetValueSize() const override { return pcursor->GetValueSize(); }

        bool Valid() const override { return !outpoint.IsNull(); }
        void Next() override {
            pcursor->Next();
            TestKey();
        }

    private:
        void TestKey() {
            CAccountID tempSenderAccountID;
            PointEntry entry(&outpoint, &tempSenderAccountID, key);
            if (!pcursor->Valid() || !pcursor->GetKey(entry) || entry.key != key || tempSenderAccountID != senderAccountID) {
                outpoint.SetNull();
            }
        }

        const CAccountID senderAccountID;
        const CCoinsViewDB* pcoinviewdb;
        std::unique_ptr<CDBIterator> pcursor;
        COutPoint outpoint;
        char key;
    };

    return std::make_shared<CCoinsViewDBPointSendCursor>(accountID, this, db.NewIterator(), GetBestBlock(), KeyFromPointType(pt));
}

CCoinsViewCursorRef CCoinsViewDB::PointReceiveCursor(const CAccountID &accountID, PointType pt) const {
    class CCoinsViewDBPointReceiveCursor : public CCoinsViewCursor
    {
    public:
        CCoinsViewDBPointReceiveCursor(const CAccountID& accountIDIn, const CCoinsViewDB* pcoinviewdbIn, CDBIterator* pcursorIn, const uint256& hashBlockIn, char keyIn)
                : CCoinsViewCursor(hashBlockIn), receiverAccountID(accountIDIn), pcoinviewdb(pcoinviewdbIn), pcursor(pcursorIn), outpoint(uint256(), 0), senderAccountID(), key(keyIn) {
            // Seek cursor to first point coin
            pcursor->Seek(keyIn);
            GotoValidEntry();
        }

        bool GetKey(COutPoint &key) const override {
            // Return cached key
            if (!outpoint.IsNull()) {
                key = outpoint;
                return true;
            }
            return false;
        }

        bool GetValue(Coin &coin) const override { return pcoinviewdb->GetCoin(outpoint, coin); }
        unsigned int GetValueSize() const override { return pcursor->GetValueSize(); }

        bool Valid() const override { return !outpoint.IsNull(); }
        void Next() override {
            pcursor->Next();
            GotoValidEntry();
        }

    private:
        void GotoValidEntry() {
            CAccountID tempReceiverAccountID;
            PointEntry entry(&outpoint, &senderAccountID, key);
            while (true) {
                if (!pcursor->Valid() || !pcursor->GetKey(entry) || entry.key != key || !pcursor->GetValue(tempReceiverAccountID)) {
                    outpoint.SetNull();
                    break;
                }
                if (tempReceiverAccountID == receiverAccountID)
                    break;
                pcursor->Next();
            }
        }

        const CAccountID receiverAccountID;
        const CCoinsViewDB* pcoinviewdb;
        std::unique_ptr<CDBIterator> pcursor;
        COutPoint outpoint;
        CAccountID senderAccountID;
        char key;
    };

    return std::make_shared<CCoinsViewDBPointReceiveCursor>(accountID, this, db.NewIterator(), GetBestBlock(), KeyFromPointType(pt));
}

size_t CCoinsViewDB::EstimateSize() const
{
    return db.EstimateSize(DB_COIN, (char)(DB_COIN+1));
}

CAmount CCoinsViewDB::GetBalance(const CAccountID &accountID, const CCoinsMap &mapChildCoins, CAmount *balanceBindPlotter, CAmount *balancePointSend, CAmount *balancePointReceive, PledgeTerms const* terms, int nHeight, bool includeBurst) const
{
    if (balanceBindPlotter != nullptr) {
        if (includeBurst) {
            *balanceBindPlotter = GetBalanceBind(CPlotterBindData::Type::BURST, accountID, mapChildCoins);
        } else {
            *balanceBindPlotter = 0;
        }
        *balanceBindPlotter += GetBalanceBind(CPlotterBindData::Type::CHIA, accountID, mapChildCoins);

        assert(*balanceBindPlotter >= 0);
    }

    if (balancePointSend != nullptr) {
        if (includeBurst) {
            *balancePointSend = GetBalancePointSend(DATACARRIER_TYPE_POINT, accountID, mapChildCoins);
        } else {
            *balancePointSend = 0;
        }
        if (terms) {
            *balancePointSend += GetBalancePointSend(DATACARRIER_TYPE_CHIA_POINT, accountID, mapChildCoins);
            *balancePointSend += GetBalancePointSend(DATACARRIER_TYPE_CHIA_POINT_TERM_1, accountID, mapChildCoins);
            *balancePointSend += GetBalancePointSend(DATACARRIER_TYPE_CHIA_POINT_TERM_2, accountID, mapChildCoins);
            *balancePointSend += GetBalancePointSend(DATACARRIER_TYPE_CHIA_POINT_TERM_3, accountID, mapChildCoins);
            *balancePointSend += GetBalancePointRetargetSend(accountID, mapChildCoins, terms, nHeight);
        }
    }

    if (balancePointReceive != nullptr) {
        if (includeBurst) {
            *balancePointReceive = GetBalancePointReceive(DATACARRIER_TYPE_POINT, accountID, mapChildCoins, nullptr, 0);
        } else {
            *balancePointReceive = 0;
        }
        if (terms) {
            *balancePointReceive += GetBalancePointReceive(DATACARRIER_TYPE_CHIA_POINT, accountID, mapChildCoins, terms, nHeight);
            *balancePointReceive += GetBalancePointReceive(DATACARRIER_TYPE_CHIA_POINT_TERM_1, accountID, mapChildCoins, terms, nHeight);
            *balancePointReceive += GetBalancePointReceive(DATACARRIER_TYPE_CHIA_POINT_TERM_2, accountID, mapChildCoins, terms, nHeight);
            *balancePointReceive += GetBalancePointReceive(DATACARRIER_TYPE_CHIA_POINT_TERM_3, accountID, mapChildCoins, terms, nHeight);
            *balancePointReceive += GetBalancePointRetargetReceive(accountID, mapChildCoins, terms, nHeight);
        }
    }

    return GetCoinBalance(accountID, mapChildCoins, nHeight);
}

CBindPlotterCoinsMap ReadAccountBindPlotterEntriesFromDB(CDBWrapper& db, CAccountID const& accountID, CPlotterBindData::Type type, CPlotterBindData const& bindData) {
    CBindPlotterCoinsMap outpoints;
    std::unique_ptr<CDBIterator> pcursor(db.NewIterator());
    COutPoint tempOutpoint(uint256(), 0);
    CAccountID tempAccountID = accountID;
    CPlotterBindData tempPlotterId;
    bool tempValid = false;
    uint32_t tempHeight = 0;
    BindPlotterEntry entry(&tempOutpoint, &tempAccountID, GetBindKeyFromPlotterIdType(type));
    BindPlotterValue value(&tempPlotterId, &tempHeight, &tempValid);
    pcursor->Seek(entry);
    while (pcursor->Valid()) {
        if (pcursor->GetKey(entry) && (entry.key == DB_COIN_BINDPLOTTER || entry.key == DB_COIN_BINDCHIAFARMER) && *entry.accountID == accountID) {
            if (entry.key == DB_COIN_BINDPLOTTER) {
                tempPlotterId = 0;
            } else if (entry.key == DB_COIN_BINDCHIAFARMER) {
                tempPlotterId = CChiaFarmerPk();
            } else {
                assert(false);
            }
            if (!pcursor->GetValue(value))
                throw std::runtime_error("Database read error");
            if (bindData.IsZero() || *value.pbindData == bindData) {
                CBindPlotterCoinInfo &info = outpoints[*entry.outpoint];
                info.nHeight = static_cast<int>(*value.nHeight);
                info.accountID = *entry.accountID;
                info.bindData = *value.pbindData;
                info.valid = *value.valid;
            }
        } else {
            break;
        }
        pcursor->Next();
    }
    return outpoints;
}

CBindPlotterCoinsMap CCoinsViewDB::GetAccountBindPlotterEntries(const CAccountID &accountID, const CPlotterBindData &bindData) const {
    if (bindData.GetType() != CPlotterBindData::Type::UNKNOWN) {
        return ReadAccountBindPlotterEntriesFromDB(db, accountID, bindData.GetType(), bindData);
    } else {
        // entries of both types are all required
        CBindPlotterCoinsMap outpoints;
        auto entriesOfBurst = ReadAccountBindPlotterEntriesFromDB(db, accountID, CPlotterBindData::Type::BURST, bindData);
        auto entriesOfChia = ReadAccountBindPlotterEntriesFromDB(db, accountID, CPlotterBindData::Type::CHIA, bindData);
        std::copy(std::begin(entriesOfBurst), std::end(entriesOfBurst), std::inserter(outpoints, std::end(outpoints)));
        std::copy(std::begin(entriesOfChia), std::end(entriesOfChia), std::inserter(outpoints, std::end(outpoints)));
        return outpoints;
    }
}

CBindPlotterCoinsMap CCoinsViewDB::GetBindPlotterEntries(const CPlotterBindData &bindData) const {
    CBindPlotterCoinsMap outpoints;

    std::unique_ptr<CDBIterator> pcursor(db.NewIterator());
    COutPoint tempOutpoint(uint256(), 0);
    CAccountID tempAccountID;
    CPlotterBindData tempBindData;
    uint32_t tempHeight = 0;
    bool tempValid = 0;
    BindPlotterEntry entry(&tempOutpoint, &tempAccountID, GetBindKeyFromPlotterIdType(bindData.GetType()));
    BindPlotterValue value(&tempBindData, &tempHeight, &tempValid);
    pcursor->Seek(entry);
    while (pcursor->Valid()) {
        if (pcursor->GetKey(entry) && (entry.key == DB_COIN_BINDPLOTTER || entry.key == DB_COIN_BINDCHIAFARMER)) {
            if (entry.key == DB_COIN_BINDPLOTTER) {
                tempBindData = 0;
            } else if (entry.key == DB_COIN_BINDCHIAFARMER) {
                tempBindData = CChiaFarmerPk();
            } else {
                assert(false);
            }
            if (!pcursor->GetValue(value))
                throw std::runtime_error("Database read error");
            if (*value.pbindData == bindData) {
                CBindPlotterCoinInfo &info = outpoints[*entry.outpoint];
                info.nHeight = static_cast<int>(*value.nHeight);
                info.accountID = *entry.accountID;
                info.bindData = *value.pbindData;
                info.valid = *value.valid;
            }
        } else {
            break;
        }
        pcursor->Next();
    }

    return outpoints;
}

CAmount CCoinsViewDB::GetBalanceBind(CPlotterBindData::Type type, CAccountID const& accountID, CCoinsMap const& mapChildCoins) const {
    std::unique_ptr<CDBIterator> pcursor(db.NewIterator());
    CAmount balanceBindPlotter = 0;

    // Read from database
    std::set<COutPoint> selected;
    CAccountID tempAccountID = accountID;
    COutPoint tempOutpoint(uint256(), 0);
    CPlotterBindData tempBindData;
    uint32_t tempHeight = 0;
    bool tempValid = true;
    char dbKey = GetBindKeyFromPlotterIdType(type);
    BindPlotterEntry entry(&tempOutpoint, &tempAccountID, dbKey);
    BindPlotterValue value(&tempBindData, &tempHeight, &tempValid);
    pcursor->Seek(entry);
    while (pcursor->Valid()) {
        if (pcursor->GetKey(entry) && entry.key == dbKey && *entry.accountID == accountID) {
            if (dbKey == DB_COIN_BINDPLOTTER) {
                tempBindData = 0;
            } else if (dbKey == DB_COIN_BINDCHIAFARMER) {
                tempBindData = CChiaFarmerPk();
            } else {
                assert(false);
            }
            if (!pcursor->GetValue(value))
                throw std::runtime_error("Database read error");
            if (*value.valid) {
                balanceBindPlotter += PROTOCOL_BINDPLOTTER_LOCKAMOUNT;
                selected.insert(*entry.outpoint);
            }
        } else {
            break;
        }
        pcursor->Next();
    }

    // Apply modified coin
    for (CCoinsMap::const_iterator it = mapChildCoins.cbegin(); it != mapChildCoins.cend(); it++) {
        if (!(it->second.flags & CCoinsCacheEntry::DIRTY))
            continue;

        if (selected.count(it->first)) {
            if (it->second.coin.IsSpent()) {
                balanceBindPlotter -= PROTOCOL_BINDPLOTTER_LOCKAMOUNT;
            }
        } else if (it->second.coin.refOutAccountID == accountID && it->second.coin.IsBindPlotter() && !it->second.coin.IsSpent()) {
            balanceBindPlotter += PROTOCOL_BINDPLOTTER_LOCKAMOUNT;
        }
    }

    assert(balanceBindPlotter >= 0);
    return balanceBindPlotter;
}

CAmount CCoinsViewDB::GetCoinBalance(const CAccountID &accountID, const CCoinsMap &mapChildCoins, int nHeight) const {
    std::unique_ptr<CDBIterator> pcursor(db.NewIterator());
    CAmount availableBalance = 0;
    CAmount tempAmount = 0;
    COutPoint tempOutpoint(uint256(), 0);
    CAccountID tempAccountID = accountID;
    CoinIndexEntry entry(&tempOutpoint, &tempAccountID);

    // Read from database
    pcursor->Seek(entry);
    while (pcursor->Valid()) {
        if (pcursor->GetKey(entry) && entry.key == DB_COIN_INDEX && *entry.accountID == accountID) {
            if (!pcursor->GetValue(REF(VARINT(tempAmount, VarIntMode::NONNEGATIVE_SIGNED))))
                throw std::runtime_error("Database read error");
            if (nHeight != 0) {
                // need to find the height of the coin
                Coin coin;
                if (!GetCoin(*entry.outpoint, coin)) {
                    throw std::runtime_error("Read coin error");
                }
                if (coin.nHeight > nHeight) {
                    pcursor->Next();
                    continue;
                }
            }
            availableBalance += tempAmount;
        } else {
            break;
        }
        pcursor->Next();
    }

    // Apply modified coin
    for (CCoinsMap::const_iterator it = mapChildCoins.cbegin(); it != mapChildCoins.cend(); it++) {
        if (!(it->second.flags & CCoinsCacheEntry::DIRTY))
            continue;

        if (it->second.coin.refOutAccountID == accountID) {
            if (nHeight != 0 && it->second.coin.nHeight > nHeight) {
                continue;
            }
            if (it->second.coin.IsSpent()) {
                if (db.Exists(CoinIndexEntry(&it->first, &it->second.coin.refOutAccountID)))
                    availableBalance -= it->second.coin.out.nValue;
            } else {
                if (!db.Exists(CoinIndexEntry(&it->first, &it->second.coin.refOutAccountID)))
                    availableBalance += it->second.coin.out.nValue;
            }
        }
    }
    assert(availableBalance >= 0);
    return availableBalance;
}

CAmount CCoinsViewDB::GetBalancePointSend(DatacarrierType type, CAccountID const& accountID, CCoinsMap const& mapChildCoins) const {
    CAmount balancePointSend{0};
    auto key = KeyFromDatacarrierType(type);
    if (!key.has_value()) {
        throw std::runtime_error("The key cannot be retrieved cause the wrong datacarrier type.");
    }
    std::unique_ptr<CDBIterator> pcursor(db.NewIterator());

    // Read from database
    std::map<COutPoint, CAmount> selected;
    CAccountID tempAccountID = accountID;
    COutPoint tempOutpoint(uint256(), 0);
    Coin coin;
    PointEntry entry(&tempOutpoint, &tempAccountID, *key);
    pcursor->Seek(entry);
    while (pcursor->Valid()) {
        if (pcursor->GetKey(entry) && (entry.key == *key) && *entry.accountID == accountID) {
            if (!db.Read(CoinEntry(entry.outpoint), coin))
                throw std::runtime_error("Database read error");
            balancePointSend += coin.out.nValue;
            selected[*entry.outpoint] = coin.out.nValue;
        } else {
            break;
        }
        pcursor->Next();
    }

    // Apply modified coin
    for (CCoinsMap::const_iterator it = mapChildCoins.cbegin(); it != mapChildCoins.cend(); it++) {
        if (!(it->second.flags & CCoinsCacheEntry::DIRTY))
            continue;
        auto itSelected = selected.find(it->first);
        if (itSelected != selected.cend()) {
            if (it->second.coin.IsSpent()) {
                balancePointSend -= itSelected->second;
            }
        } else if (it->second.coin.GetExtraDataType() == type && it->second.coin.refOutAccountID == accountID && !it->second.coin.IsSpent()) {
            balancePointSend += it->second.coin.out.nValue;
        }
    }

    assert(balancePointSend >= 0);
    return balancePointSend;
}

CAmount CCoinsViewDB::CalculateTermAmount(CAmount coinAmount, PledgeTerm const& term, PledgeTerm const& fallbackTerm, int nPointHeight, int nHeight) const {
    int nLockedHeights = nHeight - nPointHeight;
    if (nLockedHeights < 0) {
        nLockedHeights = 0;
        LogPrintf("%s: (warning) nLockedHeight < 0, nPointHeight=%ld, nHeight=%ld, nLockedHeight is set to 0\n", __func__, nPointHeight, nHeight);
    }
    if (nLockedHeights >= term.nLockHeight) {
        // Fallback with term 0
        return fallbackTerm.nWeightPercent * coinAmount / 100;
    } else {
        return term.nWeightPercent * coinAmount / 100;
    }
}

CAmount CCoinsViewDB::GetBalancePointReceive(DatacarrierType type, CAccountID const& accountID, CCoinsMap const& mapChildCoins, PledgeTerms const* terms, int nHeight) const {
    CAmount balancePointReceive = 0;

    PledgeTerm term, fallbackTerm;
    if (terms) {
        if (!GetTerm(*terms, type, term, fallbackTerm)) {
            throw std::runtime_error("Failed to get term");
        }
    }

    // Prepare for key
    auto key = KeyFromDatacarrierType(type);
    if (!key.has_value()) {
        throw std::runtime_error("The key cannot be retrieved accord the wrong datacarrier type.");
    }

    std::unique_ptr<CDBIterator> pcursor(db.NewIterator());

    // Read from database
    std::map<COutPoint, CAmount> selected;
    CAccountID tempDebitAccountID;
    CAccountID tempAccountID;
    COutPoint tempOutpoint(uint256(), 0);
    Coin pointCoin;

    PointEntry entry(&tempOutpoint, &tempAccountID, *key);
    pcursor->Seek(entry);
    while (pcursor->Valid()) {
        if (pcursor->GetKey(entry) && entry.key == *key) {
            if (!pcursor->GetValue(tempDebitAccountID))
                throw std::runtime_error("Database read error");
            if (tempDebitAccountID == accountID) {
                if (!db.Read(CoinEntry(entry.outpoint), pointCoin)) {
                    throw std::runtime_error("Database read error");
                }
                // Calculate the actual amount of the pledge
                CAmount nActual;
                if (terms) {
                    nActual = CalculateTermAmount(pointCoin.out.nValue, term, fallbackTerm, pointCoin.nHeight, nHeight);
                } else {
                    nActual = pointCoin.out.nValue;
                }
                balancePointReceive += nActual;
                selected[*entry.outpoint] = nActual;
            }
        } else {
            break;
        }
        pcursor->Next();
    }

    // Apply modified coin
    for (CCoinsMap::const_iterator it = mapChildCoins.cbegin(); it != mapChildCoins.cend(); it++) {
        if (!(it->second.flags & CCoinsCacheEntry::DIRTY)) {
            continue;
        }

        auto itSelected = selected.find(it->first);
        if (itSelected != selected.cend()) {
            if (it->second.coin.IsSpent()) {
                balancePointReceive -= itSelected->second; // Reverse the coin value
            }
        } else if (it->second.coin.GetExtraDataType() == type && PointPayload::As(it->second.coin.extraData)->GetReceiverID() == accountID && !it->second.coin.IsSpent()) {
            if (terms) {
                balancePointReceive += CalculateTermAmount(it->second.coin.out.nValue, term, fallbackTerm, it->second.coin.nHeight, nHeight);
            } else {
                balancePointReceive += it->second.coin.out.nValue;
            }
        }
    }

    assert(balancePointReceive >= 0);
    return balancePointReceive;
}

CAmount CCoinsViewDB::CalculatePledgeAmountFromRetargetCoin(CAmount pointAmount, DatacarrierType pointType, int nPointHeight, PledgeTerms const& terms, int nHeight) const
{
    PledgeTerm term, fallbackTerm;
    if (!GetTerm(terms, pointType, term, fallbackTerm)) {
        throw std::runtime_error("failed to get term from chia point-type");
    }
    return CalculateTermAmount(pointAmount, term, fallbackTerm, nPointHeight, nHeight);
}

CAmount CCoinsViewDB::GetBalancePointRetargetSend(CAccountID const& accountID, CCoinsMap const& mapChildCoins, PledgeTerms const* terms, int nHeight) const {
    assert(terms != nullptr);

    CAmount balanceRevoke{0};
    std::unique_ptr<CDBIterator> pcursor(db.NewIterator());
    COutPoint outpoint;
    CAccountID tempAccountID;
    PointRetargetEntry retargetEntry(&outpoint, &tempAccountID);
    pcursor->Seek(retargetEntry);
    while (pcursor->Valid()) {
        if (!pcursor->GetKey(retargetEntry)) {
            throw std::runtime_error("failed to read data from database");
        }
        if (retargetEntry.key != DB_COIN_POINT_CHIA_POINT_RETARGET) {
            break;
        }
        // Because of the RETARGET tx is pointed to a RETARGET or a POINT, but the amount of the pledge should be the same,
        Coin coin;
        if (!GetCoin(outpoint, coin)) {
            throw std::runtime_error("failed to read db");
        }
        CAccountID receiverID;
        DatacarrierType pointType;
        int nPointHeight;
        PointRetargetValue value(&receiverID, &pointType, &nPointHeight);
        if (!pcursor->GetValue(value)) {
            throw std::runtime_error("failed to get coin from database");
        }
        if (tempAccountID == accountID) {
            balanceRevoke += CalculatePledgeAmountFromRetargetCoin(coin.out.nValue, pointType, nPointHeight, *terms, nHeight);
        }
        // Next
        pcursor->Next();
    }
    // Apply cached coins
    for (auto const& entry : mapChildCoins) {
        if ((entry.second.flags & CCoinsCacheEntry::DIRTY) == 0) {
            continue;
        }
        // Just check the entry and find out if it is a RETARGET then check the revokedAccountID
        if (entry.second.coin.IsPointRetarget() && !entry.second.coin.IsSpent() && entry.second.coin.refOutAccountID == accountID) {
            assert(entry.second.coin.extraData != nullptr);
            auto retargetPayload = PointRetargetPayload::As(entry.second.coin.extraData);
            balanceRevoke += CalculatePledgeAmountFromRetargetCoin(entry.second.coin.out.nValue, retargetPayload->GetPointType(), retargetPayload->GetPointHeight(), *terms, nHeight);
        }
    }
    assert(balanceRevoke >= 0);
    return balanceRevoke;
}

CAmount CCoinsViewDB::GetBalancePointRetargetReceive(CAccountID const& accountID, CCoinsMap const& mapChildCoins, PledgeTerms const* terms, int nHeight) const {
    assert(terms != nullptr);

    CAmount balanceReceive{0};
    std::map<COutPoint, CAmount> selected; // Coins are related to the accountID
    std::unique_ptr<CDBIterator> pcursor(db.NewIterator());
    COutPoint outpoint;
    CAccountID tempAccountID;
    PointRetargetEntry retargetEntry(&outpoint, &tempAccountID);
    pcursor->Seek(retargetEntry);
    while (pcursor->Valid()) {
        if (!pcursor->GetKey(retargetEntry)) {
            throw std::runtime_error("failed to read data from database");
        }
        if (retargetEntry.key != DB_COIN_POINT_CHIA_POINT_RETARGET) {
            break;
        }
        CAccountID receiverID;
        DatacarrierType pointType;
        int nPointHeight;
        PointRetargetValue value(&receiverID, &pointType, &nPointHeight);
        if (!pcursor->GetValue(value)) {
            throw std::runtime_error("failed to read receiver-id from database");
        }
        if (receiverID == accountID) {
            Coin coin;
            if (!GetCoin(outpoint, coin)) {
                throw std::runtime_error("failed to read retargetCoin from database");
            }
            CAmount nActual = CalculatePledgeAmountFromRetargetCoin(coin.out.nValue, pointType, nPointHeight, *terms, nHeight);
            balanceReceive += nActual;
            selected[outpoint] = nActual;
        }
        // Next
        pcursor->Next();
    }
    // Apply cached coins
    for (auto const& entry : mapChildCoins) {
        if ((entry.second.flags & CCoinsCacheEntry::DIRTY) == 0) {
            continue;
        }
        auto it = selected.find(entry.first);
        if (it != std::end(selected)) {
            // The coin exists and it has received amount
            if (entry.second.coin.IsSpent()) {
                balanceReceive -= it->second;
            }
        } else {
            // The coin doesn't exist before, we are trying to find out if it is not spent and also the accountID is matched
            if (!entry.second.coin.IsSpent() && entry.second.coin.IsPointRetarget()) {
                auto retargetPayload = PointRetargetPayload::As(entry.second.coin.extraData);
                if (retargetPayload->GetReceiverID() == accountID) {
                    balanceReceive += CalculatePledgeAmountFromRetargetCoin(entry.second.coin.out.nValue, retargetPayload->GetPointType(), retargetPayload->GetPointHeight(), *terms, nHeight);
                }
            }
        }

    }
    assert(balanceReceive >= 0);
    return balanceReceive;
}

CBlockTreeDB::CBlockTreeDB(size_t nCacheSize, bool fMemory, bool fWipe) : CDBWrapper(gArgs.IsArgSet("-blocksdir") ? GetDataDir() / "blocks" / "index" : GetBlocksDir() / "index", nCacheSize, fMemory, fWipe) {
}

bool CBlockTreeDB::ReadBlockFileInfo(int nFile, CBlockFileInfo &info) {
    return Read(std::make_pair(DB_BLOCK_FILES, nFile), info);
}

bool CBlockTreeDB::WriteReindexing(bool fReindexing) {
    if (fReindexing)
        return Write(DB_REINDEX_FLAG, '1');
    else
        return Erase(DB_REINDEX_FLAG);
}

void CBlockTreeDB::ReadReindexing(bool &fReindexing) {
    fReindexing = Exists(DB_REINDEX_FLAG);
}

bool CBlockTreeDB::ReadLastBlockFile(int &nFile) {
    return Read(DB_LAST_BLOCK, nFile);
}

bool CBlockTreeDB::WriteBatchSync(const std::vector<std::pair<int, const CBlockFileInfo*> >& fileInfo, int nLastFile, const std::vector<const CBlockIndex*>& blockinfo, const Consensus::Params &consensusParams) {
    CDBBatch batch(*this);
    for (std::vector<std::pair<int, const CBlockFileInfo*> >::const_iterator it=fileInfo.begin(); it != fileInfo.end(); it++) {
        batch.Write(std::make_pair(DB_BLOCK_FILES, it->first), *it->second);
    }
    LogPrintf("%s: writing indexes total %d entries...\n", __func__, std::distance(std::begin(blockinfo), std::end(blockinfo)));
    batch.Write(DB_LAST_BLOCK, nLastFile);
    for (std::vector<const CBlockIndex*>::const_iterator it=blockinfo.begin(); it != blockinfo.end(); it++) {
        CDiskBlockIndex blockIndex(*it, (*it)->nHeight >= consensusParams.BHDIP009Height);
        batch.Write(std::make_pair(DB_BLOCK_INDEX, (*it)->GetBlockHash()), blockIndex);
        if ((*it)->vchPubKey.empty() && !(*it)->generatorAccountID.IsNull())
            batch.Write(std::make_pair(DB_BLOCK_GENERATOR_INDEX, (*it)->GetBlockHash()), REF((*it)->generatorAccountID));
    }
    return WriteBatch(batch, true);
}

bool CBlockTreeDB::WriteFlag(const std::string &name, bool fValue) {
    return Write(std::make_pair(DB_FLAG, name), fValue ? '1' : '0');
}

bool CBlockTreeDB::ReadFlag(const std::string &name, bool &fValue) {
    char ch;
    if (!Read(std::make_pair(DB_FLAG, name), ch))
        return false;
    fValue = ch == '1';
    return true;
}

bool CBlockTreeDB::LoadBlockIndexGuts(const Consensus::Params& consensusParams, std::function<CBlockIndex*(const uint256&)> insertBlockIndex)
{
    size_t batch_size = (size_t) gArgs.GetArg("-dbbatchsize", nDefaultDbBatchSize);
    CDBBatch batch(*this);

    std::unique_ptr<CDBIterator> pcursor(NewIterator());

    pcursor->Seek(std::make_pair(DB_BLOCK_INDEX, uint256()));

    // Load m_block_index
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        if (ShutdownRequested()) return false;
        std::pair<char, uint256> key;
        if (pcursor->GetKey(key) && key.first == DB_BLOCK_INDEX) {
            CDiskBlockIndex diskindex;
            if (pcursor->GetValue(diskindex)) {
                // Check chiapos related entries
                if (diskindex.nHeight >= consensusParams.BHDIP009Height) {
                    if (diskindex.chiaposFields.IsNull()) {
                        LogPrintf("%s: found null chiaposFields, skip the diskindex, height=%d\n", __func__, diskindex.nHeight);
                        // Fields from chiapos are invalid, ignore this block
                        pcursor->Next();
                        continue;
                    }
                }
                // Construct block index object
                CBlockIndex* pindexNew = insertBlockIndex(diskindex.GetBlockHash());
                pindexNew->pprev              = insertBlockIndex(diskindex.hashPrev);
                pindexNew->nHeight            = diskindex.nHeight;
                pindexNew->nFile              = diskindex.nFile;
                pindexNew->nDataPos           = diskindex.nDataPos;
                pindexNew->nUndoPos           = diskindex.nUndoPos;
                pindexNew->nVersion           = diskindex.nVersion;
                pindexNew->hashMerkleRoot     = diskindex.hashMerkleRoot;
                pindexNew->nTime              = diskindex.nTime;
                pindexNew->nBaseTarget        = diskindex.nBaseTarget;
                pindexNew->nNonce             = diskindex.nNonce;
                pindexNew->nPlotterId         = diskindex.nPlotterId;
                pindexNew->nStatus            = diskindex.nStatus;
                pindexNew->nTx                = diskindex.nTx;
                pindexNew->generatorAccountID = diskindex.generatorAccountID;
                pindexNew->vchPubKey          = diskindex.vchPubKey;
                pindexNew->vchSignature       = diskindex.vchSignature;
                pindexNew->chiaposFields      = diskindex.chiaposFields;

                // Load external generator
                if ((pindexNew->nStatus & BLOCK_HAVE_DATA) && pindexNew->vchPubKey.empty() && pindexNew->nHeight > 0) {
                    bool fRequireStore = false;
                    CAccountID generatorAccountID;
                    if (!Read(std::make_pair(DB_BLOCK_GENERATOR_INDEX, pindexNew->GetBlockHash()), REF(generatorAccountID))) {
                        //! Slowly: Read from full block data
                        CBlock block;
                        if (!ReadBlockFromDisk(block, pindexNew, consensusParams))
                            return error("%s: failed to read block value", __func__);
                        generatorAccountID = ExtractAccountID(block.vtx[0]->vout[0].scriptPubKey);
                        fRequireStore = !generatorAccountID.IsNull();
                    }
                    if (generatorAccountID.GetUint64(0) != pindexNew->generatorAccountID.GetUint64(0))
                        return error("%s: failed to read external generator value", __func__);
                    pindexNew->generatorAccountID = generatorAccountID;

                    if (fRequireStore) {
                        batch.Write(std::make_pair(DB_BLOCK_GENERATOR_INDEX, pindexNew->GetBlockHash()), REF(generatorAccountID));
                        if (batch.SizeEstimate() > batch_size) {
                            WriteBatch(batch);
                            batch.Clear();
                        }
                    }
                }

                pcursor->Next();
            } else {
                return error("%s: failed to read value", __func__);
            }
        } else {
            break;
        }
    }

    return WriteBatch(batch);
}

/** Upgrade the database from older formats */
bool CCoinsViewDB::Upgrade(bool &fUpgraded) {
    fUpgraded = false;
    // Check coin database version
    uint32_t coinDbVersion = 0;
    if (db.Read(DB_COIN_VERSION, REF(VARINT(coinDbVersion))) && coinDbVersion == DB_VERSION)
        return true;
    db.Erase(DB_COIN_VERSION);
    fUpgraded = true;

    // Reindex UTXO for address
    uiInterface.ShowProgress(_("Upgrading UTXO database").translated, 0, true);
    LogPrintf("Upgrading UTXO database to %08x: [0%%]...", DB_VERSION);

    size_t batch_size = (size_t) gArgs.GetArg("-dbbatchsize", nDefaultDbBatchSize);
    int remove = 0, add = 0;
    std::unique_ptr<CDBIterator> pcursor(db.NewIterator());

    // Clear old data
    pcursor->SeekToFirst();
    if (pcursor->Valid()) {
        CDBBatch batch(db);
        for (; pcursor->Valid(); pcursor->Next()) {
            const leveldb::Slice key = pcursor->GetKey();
            if (key.size() > 32 && (key[0] == DB_COIN_INDEX || key[0] == DB_COIN_BINDPLOTTER || key[0] == DB_COIN_BINDCHIAFARMER || key[0] == DB_COIN_POINT_SEND || key[0] == DB_COIN_POINT_RECEIVE)) {
                batch.EraseSlice(key);
                remove++;

                if (batch.SizeEstimate() > batch_size) {
                    db.WriteBatch(batch);
                    batch.Clear();
                }
            }
        }
        db.WriteBatch(batch);
    }

    // Create coin index data
    pcursor->Seek(DB_COIN);
    if (pcursor->Valid()) {
        int utxo_bucket = 173000 / 100;
        int indexProgress = -1;
        CDBBatch batch(db);
        COutPoint outpoint;
        CoinEntry entry(&outpoint);
        for (; pcursor->Valid(); pcursor->Next()) {
            if (pcursor->GetKey(entry) && entry.key == DB_COIN) {
                Coin coin;
                if (!pcursor->GetValue(coin))
                    return error("%s: cannot parse coin record", __func__);

                if (!coin.refOutAccountID.IsNull()) {
                    // Coin index
                    batch.Write(CoinIndexEntry(&outpoint, &coin.refOutAccountID), VARINT(coin.out.nValue, VarIntMode::NONNEGATIVE_SIGNED));
                    add++;

                    // Extra data
                    if (coin.IsBindPlotter()) {
                        const CPlotterBindData &bindData = BindPlotterPayload::As(coin.extraData)->GetId();
                        uint32_t nHeight = coin.nHeight;
                        bool valid = true;
                        batch.Write(BindPlotterEntry(&outpoint, &coin.refOutAccountID, GetBindKeyFromPlotterIdType(bindData.GetType())), BindPlotterValue(&bindData, &nHeight, &valid));
                        add++;
                    }
                    else if (coin.IsPoint()) {
                        auto dbKey = KeyFromDatacarrierType(coin.GetExtraDataType());
                        batch.Write(PointEntry(&outpoint, &coin.refOutAccountID, dbKey.get_value_or(0)), REF(PointPayload::As(coin.extraData)->GetReceiverID()));
                        add++;
                    }

                    if (batch.SizeEstimate() > batch_size) {
                        db.WriteBatch(batch);
                        batch.Clear();
                    }

                    if (add % (utxo_bucket/10) == 0) {
                        int newProgress = std::min(90, add / utxo_bucket);
                        if (newProgress/10 != indexProgress/10) {
                            indexProgress = newProgress;
                            uiInterface.ShowProgress(_("Upgrading UTXO database").translated, indexProgress, true);
                            LogPrintf("[%d%%]...", indexProgress);
                        }
                    }
                }
            } else {
                break;
            }
        }
        db.WriteBatch(batch);
    }

    // Update coin version
    if (!db.Write(DB_COIN_VERSION, VARINT(DB_VERSION)))
        return error("%s: cannot write UTXO version", __func__);

    uiInterface.ShowProgress("", 100, false);
    LogPrintf("[%s]. remove utxo %d, add utxo %d\n", ShutdownRequested() ? "CANCELLED" : "DONE", remove, add);

    return !ShutdownRequested();
}
