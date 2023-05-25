#include "pointitemmodel.h"

#include <QTranslator>

#include <script/standard.h>
#include <wallet/wallet.h>

#include <key_io.h>
#include <chainparams.h>

#include <chiapos/kernel/utils.h>

PointItemModel::PointItemModel(CWallet* pwallet) : m_pwallet(pwallet) {
    reload();
}

int PointItemModel::columnCount(QModelIndex const& parent) const { return 6; }

QVariant PointItemModel::data(QModelIndex const& index, int role) const {
    auto params = Params().GetConsensus();
    // retrieve pledge
    auto const& pledge = m_pledges[index.row()];
    auto itTx = m_pwallet->mapWallet.find(pledge.txid);
    // term
    auto nTermIdx = pledge.payloadType - DATACARRIER_TYPE_CHIA_POINT;
    auto const& term = params.BHDIP009PledgeTerms[nTermIdx];
    if (role == Qt::DisplayRole) {
        switch (index.column()) {
            case 0:
                return pledge.nBlockHeight;
            case 1:
                return QString::fromStdString(EncodeDestination(pledge.toDest));
            case 2:
                return pledge.nBlockHeight + term.nLockHeight;
            case 3:
                return QString::fromStdString(chiapos::MakeNumberStr(itTx->second.tx->vout[0].nValue / COIN));
            case 4:
                return PointTypeToTerm(pledge);
            case 5:
                return QString::fromStdString(pledge.txid.GetHex());
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
                return tr("To");
            case 2:
                return tr("Expires");
            case 3:
                return tr("Amount");
            case 4:
                return tr("Term");
            case 5:
                return tr("TxID");
        }
    }
    return QVariant();
}

void PointItemModel::reload() {
    auto pledges = RetrievePledgeMap(m_pwallet, false, ISMINE_ALL);
    beginResetModel();
    m_pledges.clear();
    std::transform(std::begin(pledges), std::end(pledges), std::back_inserter(m_pledges),
                   [](std::pair<int64_t, TxPledge> const& pledgePair) { return pledgePair.second; });
    endResetModel();
}

TxPledge PointItemModel::pledgeFromIndex(QModelIndex const& index) const {
    return m_pledges[index.row()];
}

static std::string ActualPointTypeToTerm(DatacarrierType type) {
    if (type == DATACARRIER_TYPE_CHIA_POINT) {
        return "No term";
    } else if (type == DATACARRIER_TYPE_CHIA_POINT_TERM_1) {
        return "Term 1";
    } else if (type == DATACARRIER_TYPE_CHIA_POINT_TERM_2) {
        return "Term 2";
    } else if (type == DATACARRIER_TYPE_CHIA_POINT_TERM_3) {
        return "Term 3";
    } else {
        return "Unknown term";
    }
}

QString PointItemModel::PointTypeToTerm(TxPledge const& pledge) const {
    if (DatacarrierTypeIsChiaPoint(pledge.payloadType)) {
        return QString::fromStdString(ActualPointTypeToTerm(pledge.payloadType));
    } else if (pledge.payloadType == DATACARRIER_TYPE_CHIA_POINT_RETARGET) {
        std::string actual = ActualPointTypeToTerm(pledge.pointType);
        return QString::fromStdString(actual + " (R)");
    }
    // wrong type here!!!
    return tr("wrong type!!!");
}
