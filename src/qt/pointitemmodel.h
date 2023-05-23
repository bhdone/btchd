#ifndef BITCOIN_QT_POINTITEMMODEL_H
#define BITCOIN_QT_POINTITEMMODEL_H

#include <QAbstractItemModel>

#include <vector>

#include <wallet/txpledge.h>

class CWallet;

class PointItemModel : public QAbstractItemModel {
public:
    explicit PointItemModel(CWallet* pwallet);

    int columnCount(QModelIndex const& parent = QModelIndex()) const override;

    QVariant data(QModelIndex const& index, int role = Qt::DisplayRole) const override;

    QModelIndex index(int row, int column, QModelIndex const& parent = QModelIndex()) const override;

    QModelIndex parent(QModelIndex const& index) const override;

    int rowCount(QModelIndex const& parent = QModelIndex()) const override;

    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

    void reload();

    TxPledge pledgeFromIndex(QModelIndex const& index) const;

private:
    QString PointTypeToTerm(TxPledge const& pledge) const;

    CWallet* m_pwallet;
    std::vector<TxPledge> m_pledges;
};

#endif
