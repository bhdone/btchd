#include "pointitemmodel.h"

#include <script/standard.h>
#include <wallet/wallet.h>

#include <chainparams.h>

#include <chiapos/kernel/utils.h>

PointItemModel::PointItemModel(CWallet* pwallet) : m_wallet(pwallet) {
    auto pledges = RetrievePledgeMap(pwallet, false, ISMINE_ALL);
    std::transform(std::begin(pledges), std::end(pledges), std::back_inserter(m_pledges),
                   [](std::pair<int64_t, TxPledge> const& pledgePair) { return pledgePair.second; });
}

int PointItemModel::columnCount(QModelIndex const& parent) const { return 5; }

QVariant PointItemModel::data(QModelIndex const& index, int role) const {
    auto params = Params().GetConsensus();
    // retrieve pledge
    auto const& pledge = m_pledges[index.row()];
    auto itTx = m_wallet->mapWallet.find(pledge.txid);
    // term
    auto nTermIdx = pledge.payloadType - DATACARRIER_TYPE_CHIA_POINT;
    auto const& term = params.BHDIP009PledgeTerms[nTermIdx];
    if (role == Qt::DisplayRole) {
        switch (index.column()) {
            case 0:
                return pledge.nBlockHeight;
            case 1:
                return pledge.nBlockHeight + term.nLockHeight;
            case 2:
                return QString::fromStdString(chiapos::MakeNumberStr(itTx->second.tx->vout[0].nValue / COIN));
            case 3:
                return QString::fromStdString(pledge.txid.GetHex());
            case 4:
                return QString::fromStdString(DatacarrierTypeToString(pledge.payloadType));
        }
    }
    return QVariant();
}

QModelIndex PointItemModel::index(int row, int column, QModelIndex const& parent) const {
    return createIndex(row, column);
}

QModelIndex PointItemModel::parent(QModelIndex const& index) const { return QModelIndex(); }

int PointItemModel::rowCount(QModelIndex const& parent) const { return m_pledges.size(); }

QVariant PointItemModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (role == Qt::DisplayRole) {
        switch (section) {
            case 0:
                return tr("Height");
            case 1:
                return tr("Expires");
            case 2:
                return tr("Amount");
            case 3:
                return tr("TxID");
            case 4:
                return tr("Term");
        }
    }
    return QVariant();
}
