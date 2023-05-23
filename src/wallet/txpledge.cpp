#include "txpledge.h"

#include <wallet/wallet.h>

TxPledgeMap RetrievePledgeMap(CWallet* pwallet, bool fIncludeInvalid, isminefilter filter) {
    std::set<uint256> revokedPledgeTxs;
    TxPledgeMap mapTxPledge;
    auto locked_chain = pwallet->chain().lock();
    for (std::pair<const uint256, CWalletTx> const& pairWtx : pwallet->mapWallet) {
        CWalletTx const& wtx = pairWtx.second;
        if (!locked_chain->checkFinalTx(*wtx.tx)) {
            continue;
        }
        auto it = wtx.mapValue.find("type");
        if (it == std::end(wtx.mapValue)) {
            continue;
        }
        std::string type = it->second;
        if (type == "withdrawpledge") {
            // need to find it out and remove the related tx
            revokedPledgeTxs.insert(uint256S(wtx.mapValue.find("relevant_txid")->second));
            continue;
        } else if (type == "pledge" || type == "retarget") {
            // Extract tx
            CDatacarrierPayloadRef payload = ExtractTransactionDatacarrier(
                    *wtx.tx, locked_chain->getBlockHeight(wtx.GetBlockHash()).get_value_or(0),
                    DatacarrierTypes{DATACARRIER_TYPE_POINT, DATACARRIER_TYPE_CHIA_POINT,
                                     DATACARRIER_TYPE_CHIA_POINT_TERM_1, DATACARRIER_TYPE_CHIA_POINT_TERM_2,
                                     DATACARRIER_TYPE_CHIA_POINT_TERM_3, DATACARRIER_TYPE_CHIA_POINT_RETARGET});
            if (!payload) {
                continue;
            }
            assert(payload->type == DATACARRIER_TYPE_POINT || DatacarrierTypeIsChiaPoint(payload->type) ||
                   payload->type == DATACARRIER_TYPE_CHIA_POINT_RETARGET);
            bool fValid = pwallet->chain().haveCoin(COutPoint(wtx.GetHash(), 0));
            if (!fIncludeInvalid && !fValid) {
                continue;
            }
            CTxDestination fromDest = ExtractDestination(wtx.tx->vout[0].scriptPubKey);
            CTxDestination toDest;
            if (payload->type == DATACARRIER_TYPE_CHIA_POINT_RETARGET) {
                toDest = ScriptHash(PointRetargetPayload::As(payload)->GetReceiverID());
            } else {
                toDest = ScriptHash(PointPayload::As(payload)->GetReceiverID());
            }
            isminetype sendIsmine = ::IsMine(*pwallet, fromDest);
            isminetype receiveIsmine = ::IsMine(*pwallet, toDest);
            bool fSendIsmine = (sendIsmine & filter) != 0;
            bool fReceiveIsmine = (receiveIsmine & filter) != 0;
            if (!fSendIsmine && !fReceiveIsmine) {
                continue;
            }
            TxPledge txPledgeRent;
            txPledgeRent.txid = wtx.GetHash();
            txPledgeRent.fromDest = fromDest;
            txPledgeRent.toDest = toDest;
            txPledgeRent.category = (fSendIsmine && fReceiveIsmine) ? "self" : (fSendIsmine ? "loan" : "debit");
            txPledgeRent.payloadType = payload->type;
            if (payload->type == DATACARRIER_TYPE_CHIA_POINT_RETARGET) {
                auto retargetPayload = PointRetargetPayload::As(payload);
                txPledgeRent.pointType = retargetPayload->GetPointType();
                txPledgeRent.nPointHeight = retargetPayload->GetPointHeight();
            }
            txPledgeRent.fValid = fValid;
            txPledgeRent.fFromWatchonly = (sendIsmine & ISMINE_WATCH_ONLY) != 0;
            txPledgeRent.fToWatchonly = (receiveIsmine & ISMINE_WATCH_ONLY) != 0;
            txPledgeRent.fChia = DatacarrierTypeIsChiaPoint(payload->type) ||
                                 payload->type == DATACARRIER_TYPE_CHIA_POINT_RETARGET;
            txPledgeRent.nBlockHeight = locked_chain->getBlockHeight(wtx.GetBlockHash()).get_value_or(0);
            mapTxPledge.insert(std::pair<int64_t, TxPledge>(wtx.nTimeReceived, txPledgeRent));
        }
    }
    // remove revoked txs
    for (auto const& txid : revokedPledgeTxs) {
        auto it = std::find_if(std::begin(mapTxPledge), std::end(mapTxPledge),
                               [&txid](std::pair<int64_t, TxPledge> const& tx) { return tx.second.txid == txid; });
        if (it != std::end(mapTxPledge)) {
            // found
            it->second.fRevoked = true;
        }
    }

    return mapTxPledge;
}
