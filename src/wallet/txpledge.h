#ifndef BITCOIN_WALLET_TXPLEDGE_H
#define BITCOIN_WALLET_TXPLEDGE_H

#include <uint256.h>

#include <script/standard.h>
#include <wallet/ismine.h>

class CWallet;

struct TxPledge {
    uint256 txid;
    CTxDestination fromDest;
    CTxDestination toDest;
    std::string category;
    DatacarrierType payloadType;
    DatacarrierType pointType;
    int nPointHeight;
    bool fValid;
    bool fFromWatchonly;
    bool fToWatchonly;
    bool fChia;
    bool fRevoked{false};
    int nBlockHeight;
};

using TxPledgeMap = std::multimap<int64_t, TxPledge>;

TxPledgeMap RetrievePledgeMap(CWallet* pwallet, bool fIncludeInvalid, isminefilter filter);

#endif
