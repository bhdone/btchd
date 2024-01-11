// Copyright (c) 2017-2020 The DePINC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/uniformer.h>

#include <chainparams.h>
#include <consensus/validation.h>
#include <interfaces/chain.h>
#include <key_io.h>
#include <wallet/coincontrol.h>
#include <wallet/fees.h>
#include <wallet/wallet.h>
#include <txmempool.h>
#include <consensus/tx_verify.h>
#include <util/moneystr.h>
#include <util/rbf.h>
#include <util/system.h>
#include <util/translation.h>
#include <util/validation.h>
#include <net.h>
#include <chiapos/kernel/utils.h>

//! Check whether transaction has descendant in wallet, or has been
//! mined, or conflicts with a mined transaction. Return a uniformer::Result.
static uniformer::Result PreconditionChecks(interfaces::Chain::Lock& locked_chain, CWallet const* wallet, CWalletTx const& wtx, std::vector<std::string>& errors) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet) {
    if (!wtx.tx->IsUniform()) {
        errors.push_back("Transaction version is not `uniform'");
        return uniformer::Result::INVALID_PARAMETER;
    }
    if (wtx.IsUnfrozen(locked_chain)) {
        errors.push_back("Transaction has unfrozen, it is spent!");
        return uniformer::Result::INVALID_PARAMETER;
    }

    if (wtx.GetDepthInMainChain(locked_chain) <= 0) {
        errors.push_back("Transaction not mined, or is conflicted with a mined transaction");
        return uniformer::Result::WALLET_ERROR;
    }

    // check that original tx consists entirely of our inputs
    if (!wallet->IsAllFromMe(*wtx.tx, ISMINE_SPENDABLE)) {
        errors.push_back("Transaction contains inputs that don't belong to this wallet");
        return uniformer::Result::WALLET_ERROR;
    }

    // freeze tx
    auto txAction = wtx.GetTxAction();
    if (txAction != CWalletTx::TX_BINDPLOTTER && txAction != CWalletTx::TX_POINT && txAction != CWalletTx::TX_POINT_RETARGET) {
        errors.push_back(tinyformat::format("Transaction can't unfreeze, txAction = %s", wtx.GetTxActionStr()));
        return uniformer::Result::INVALID_PARAMETER;
    }

    return uniformer::Result::OK;
}

namespace uniformer {

bool CoinCanBeUnfreeze(CWallet const* wallet, COutPoint const& outpoint) {
    if (outpoint.n != 0)
        return false;

    auto locked_chain = wallet->chain().lock();
    LOCK(wallet->cs_wallet);
    CWalletTx const* wtx = wallet->GetWalletTx(outpoint.hash);
    if (wtx == nullptr) return false;

    std::vector<std::string> errors_dummy;
    Result res = PreconditionChecks(*locked_chain, wallet, *wtx, errors_dummy);
    return res == Result::OK;
}

Result CreateBindPlotterTransaction(CWallet* wallet, CTxDestination const& dest, CScript const& bindScriptData,
                                    bool fAllowHighFee, CCoinControl const& coin_control,
                                    std::vector<std::string>& errors, CAmount& txfee, CMutableTransaction& mtx,
                                    bool fChiapos) {
    auto locked_chain = wallet->chain().lock();
    LOCK(wallet->cs_wallet);
    errors.clear();

    CAccountID accountID = ExtractAccountID(dest);
    if (accountID.IsNull()) {
        errors.push_back("Invalid bind destination");
        return Result::INVALID_ADDRESS_OR_KEY;
    }

    CPlotterBindData bindData = GetPlotterBindDataFromScript(bindScriptData);
    if (bindData.IsZero() || bindData.GetType() == CPlotterBindData::Type::UNKNOWN) {
        errors.push_back("Invalid bind data");
        return Result::INVALID_PARAMETER;
    }

    Consensus::Params const& params = Params().GetConsensus();
    int nSpendHeight = locked_chain->getHeight().get_value_or(0) + 1;
    if (nSpendHeight < params.BHDIP006Height) { // Check active status
        errors.push_back(strprintf("The bind plotter inactive (Will active on %d)", params.BHDIP006Height));
        return Result::INVALID_REQUEST;
    }

    // Check already actived bind
    if (wallet->chain().haveActiveBindPlotter(accountID, bindData)) {
        errors.push_back(strprintf("The plotter %s already binded to %s and actived.", bindData.ToString(), EncodeDestination(dest)));
        return Result::INVALID_REQUEST;
    }

    // Create special coin control for bind plotter
    CCoinControl realCoinControl = coin_control;
    realCoinControl.m_signal_bip125_rbf = false;
    realCoinControl.m_coin_pick_policy = CoinPickPolicy::IncludeIfSet;
    realCoinControl.m_pick_dest = dest;
    realCoinControl.destChange = dest;
    if (nSpendHeight >= params.BHDIP006CheckRelayHeight) { // Limit bind plotter minimal fee
        realCoinControl.m_min_txfee = PROTOCOL_BINDPLOTTER_MINFEE;
    }
    // Calculate bind transaction fee
    if (CAmount punishmentReward = wallet->chain().getBindPlotterPunishment(nSpendHeight, bindData).first) { // Calculate bind transaction fee
        realCoinControl.m_min_txfee = std::max(realCoinControl.m_min_txfee, punishmentReward + PROTOCOL_BINDPLOTTER_MINFEE);
        if (!fAllowHighFee) {
            errors.push_back(strprintf("This binding operation triggers a pledge anti-cheating mechanism and therefore requires a large bind plotter fee %s DePC", FormatMoney(realCoinControl.m_min_txfee)));
            return Result::BIND_HIGHFEE_ERROR;
        }
    }

    // Create bind plotter transaction
    std::string strError;
    std::vector<CRecipient> vecSend = { {GetScriptForDestination(dest), PROTOCOL_BINDPLOTTER_LOCKAMOUNT, false}, {bindScriptData, 0, false} };
    int nChangePosRet = 1;
    CTransactionRef tx;
    if (!wallet->CreateTransaction(*locked_chain, vecSend, tx, txfee, nChangePosRet, strError, realCoinControl, false, CTransaction::UNIFORM_VERSION)) {
        errors.push_back(strError);
        return Result::WALLET_ERROR;
    }

    // Check
    bool fReject = false;
    int lastActiveHeight = 0;
    bool fIsBindTx { false };
    DatacarrierType datacarrierType = fChiapos ? DATACARRIER_TYPE_BINDCHIAFARMER : DATACARRIER_TYPE_BINDPLOTTER;
    CDatacarrierPayloadRef payload = ExtractTransactionDatacarrier(*tx, nSpendHeight, DatacarrierTypes{datacarrierType}, fReject, lastActiveHeight, fIsBindTx);
    if (!payload) {
        if (fReject)
            errors.push_back("Not for current address");
        else if (lastActiveHeight != 0 && lastActiveHeight < nSpendHeight)
            errors.push_back(strprintf("Invalid active height. Last active height is %d", lastActiveHeight));
        else
            errors.push_back("Invalid bind hex data");
        return Result::INVALID_PARAMETER;
    }
    assert(payload->type == datacarrierType);

    // return
    mtx = CMutableTransaction(*tx);
    return Result::OK;
}

//! Create point transaction.
Result CreatePointTransaction(CWallet* wallet, CTxDestination const& senderDest, CTxDestination const& receiverDest,
                              CAmount nAmount, bool fSubtractFeeFromAmount, CCoinControl const& coin_control,
                              DatacarrierType type, std::vector<std::string>& errors, CAmount& txfee,
                              CMutableTransaction& mtx) {
    auto locked_chain = wallet->chain().lock();
    LOCK(wallet->cs_wallet);
    errors.clear();

    if (nAmount <= 0) {
        errors.push_back("Invalid amount");
        return Result::INVALID_PARAMETER;
    } if (nAmount < PROTOCOL_POINT_AMOUNT_MIN) {
        errors.push_back(strprintf("Point amount too minimal, require more than %s DePC", FormatMoney(PROTOCOL_POINT_AMOUNT_MIN)));
        return Result::INVALID_PARAMETER;
    }

    // Create special coin control for point
    CCoinControl realCoinControl = coin_control;
    realCoinControl.m_signal_bip125_rbf = false;
    realCoinControl.m_coin_pick_policy = CoinPickPolicy::IncludeIfSet;
    realCoinControl.m_pick_dest = senderDest;
    realCoinControl.destChange = senderDest;

    // Create point transaction
    std::string strError;
    std::vector<CRecipient> vecSend = {
        {GetScriptForDestination(senderDest), nAmount, fSubtractFeeFromAmount},
        {GetPointScriptForDestination(receiverDest, type), 0, false} };
    int nChangePosRet = 1;
    CTransactionRef tx;
    if (!wallet->CreateTransaction(*locked_chain, vecSend, tx, txfee, nChangePosRet, strError, realCoinControl, false, CTransaction::UNIFORM_VERSION)) {
        errors.push_back(strError);
        return Result::WALLET_ERROR;
    }

    // Check
    CDatacarrierPayloadRef payload = ExtractTransactionDatacarrier(*tx, locked_chain->getHeight().get_value_or(0) + 1,
                                                                   DatacarrierTypes{DATACARRIER_TYPE_POINT,
                                                                                    DATACARRIER_TYPE_CHIA_POINT,
                                                                                    DATACARRIER_TYPE_CHIA_POINT_TERM_1,
                                                                                    DATACARRIER_TYPE_CHIA_POINT_TERM_2,
                                                                                    DATACARRIER_TYPE_CHIA_POINT_TERM_3});
    if (!payload) {
        errors.push_back("Error on create point transaction");
        return Result::WALLET_ERROR;
    }
    assert(payload->type == DATACARRIER_TYPE_POINT || DatacarrierTypeIsChiaPoint(payload->type));

    // Return
    mtx = CMutableTransaction(*tx);
    return Result::OK;
}

Result CreatePointRetargetTransaction(CWallet* wallet, COutPoint const& previousOutpoint, CTxDestination const& senderDest, CTxDestination const& receiverDest, DatacarrierType pointType, int nPointHeight, CCoinControl const& coin_control, std::vector<std::string>& errors, CAmount& txfee, CMutableTransaction& mtx) {
    auto locked_chain = wallet->chain().lock();
    LOCK(wallet->cs_wallet);
    auto const& coin = wallet->chain().accessCoin(previousOutpoint);
    errors.clear();

    // Create special coin control for point
    CCoinControl realCoinControl = coin_control;
    realCoinControl.m_signal_bip125_rbf = false;
    realCoinControl.m_coin_pick_policy = CoinPickPolicy::IncludeIfSet;
    realCoinControl.m_pick_dest = senderDest;
    realCoinControl.destChange = senderDest;
    realCoinControl.Select(previousOutpoint);

    // Create point transaction
    std::string strError;
    std::vector<CRecipient> vecSend = {
        {GetScriptForDestination(senderDest), coin.out.nValue, false},
        {GetPointRetargetScriptForDestination(receiverDest, pointType, nPointHeight), 0, false} };
    int nChangePosRet = 1;
    CTransactionRef tx;
    if (!wallet->CreateTransaction(*locked_chain, vecSend, tx, txfee, nChangePosRet, strError, realCoinControl, false, CTransaction::UNIFORM_VERSION)) {
        errors.push_back(strError);
        return Result::WALLET_ERROR;
    }

    // Check
    CDatacarrierPayloadRef payload = ExtractTransactionDatacarrier(*tx, locked_chain->getHeight().get_value_or(0) + 1, DatacarrierTypes{DATACARRIER_TYPE_POINT, DATACARRIER_TYPE_CHIA_POINT, DATACARRIER_TYPE_CHIA_POINT_TERM_1, DATACARRIER_TYPE_CHIA_POINT_TERM_2, DATACARRIER_TYPE_CHIA_POINT_TERM_3, DATACARRIER_TYPE_CHIA_POINT_RETARGET});
    if (!payload) {
        errors.push_back("The payload of the new transaction is null!");
        return Result::WALLET_ERROR;
    }
    assert(payload->type == DATACARRIER_TYPE_CHIA_POINT_RETARGET);

    // Return
    mtx = CMutableTransaction(*tx);
    return Result::OK;
}

Result CreateUnfreezeTransaction(CWallet* wallet, COutPoint const& outpoint, CCoinControl const& coin_control, std::vector<std::string>& errors, CAmount& txfee, CMutableTransaction& mtx)
{
    auto locked_chain = wallet->chain().lock();
    LOCK(wallet->cs_wallet);
    CWalletTx const* wtx = wallet->GetWalletTx(outpoint.hash);
    if (wtx == nullptr || outpoint.n != 0) {
        errors.push_back("Can't unfreeze cause the tx cannot be found or outpoint.n is zero");
        return Result::INVALID_REQUEST;
    }

    if (!wtx->tx->IsUniform()) {
        errors.push_back("Can't unfreeze cause the tx version is not `uniform'.");
        return Result::INVALID_REQUEST;
    }

    Result res = PreconditionChecks(*locked_chain, wallet, *wtx, errors);
    if (res != Result::OK) {
        return res;
    }

    // Check UTXO
    Coin const& coin = wallet->chain().accessCoin(outpoint);
    if (coin.IsSpent()) {
        errors.push_back("Can't unfreeze cause the coin is spent");
    }

    if (coin.GetExtraDataType() == DATACARRIER_TYPE_UNKNOWN) {
        errors.push_back("Can't unfreeze cause the extraData type of the coin is unknown");
        return Result::INVALID_REQUEST;
    }

    int nSpendHeight = locked_chain->getHeight().get_value_or(0);
    // Check unbind limit
    if (coin.IsBindPlotter()) {
        int nUnbindSpendHeight = nSpendHeight + 1;
        int nActiveHeight = wallet->chain().getUnbindPlotterLimitHeight(CBindPlotterInfo(outpoint, coin));
        if (nUnbindSpendHeight < nActiveHeight) {
            errors.push_back(strprintf("Unbind plotter active on %d block height (%d blocks after, about %d minute)",
                    nActiveHeight,
                    nActiveHeight - nUnbindSpendHeight,
                    (nActiveHeight - nUnbindSpendHeight) * Consensus::GetTargetSpacing(nUnbindSpendHeight, Params().GetConsensus()) / 60));
            return Result::WALLET_ERROR;
        }
    }

    CAmount nWithdrawAmount;
    CAmount nBurnAmount;

    // Create transaction
    CMutableTransaction txNew;
    txNew.nLockTime = nSpendHeight;
    txNew.nVersion = CTransaction::UNIFORM_VERSION;
    txNew.vin = { CTxIn(outpoint, CScript(), CTxIn::SEQUENCE_FINAL - 1) };

    auto const& params = Params().GetConsensus();
    auto burnDest = GetBurnToDestination();
    CScript burnScriptPubKey = GetScriptForDestination(burnDest);

    // Is it a POINT related tx?
    PledgeTerm const* pterm{nullptr};
    int nPointHeight;
    if (coin.IsPoint()) {
        // Retrieve the POINT tx(outpoint)
        LogPrintf("%s: withdraw POINT\n", __func__);
        auto pointType = coin.GetExtraDataType();
        nPointHeight = coin.nHeight;
        int nIdx = pointType - DATACARRIER_TYPE_CHIA_POINT;
        pterm = &params.BHDIP009PledgeTerms[nIdx];
    } else if (coin.IsPointRetarget()) {
        // Need to retrieve the POINT coin
        LogPrintf("%s: withdraw RETARGET\n", __func__);
        auto payload = PointRetargetPayload::As(coin.extraData);
        auto pointType = payload->GetPointType();
        nPointHeight = payload->GetPointHeight();
        int nIdx = pointType - DATACARRIER_TYPE_CHIA_POINT;
        pterm = &params.BHDIP009PledgeTerms[nIdx];
    }
    if (pterm) {
        nWithdrawAmount = GetWithdrawAmount(pterm->nLockHeight, nPointHeight, nSpendHeight, coin.out.nValue);
        nBurnAmount = coin.out.nValue - nWithdrawAmount;
    } else {
        // otherwise, current type of tx is bind, we just need to unbind it.
        LogPrintf("%s: unbind\n", __func__);
        nWithdrawAmount = coin.out.nValue;
        nBurnAmount = 0;
    }
    assert(nWithdrawAmount <= coin.out.nValue);
    LogPrintf("%s: pledge %s DePC, withdraw %s DePC, burn %s DePC, point %s DePC, calculated on height: %ld\n", __func__, chiapos::FormatNumberStr(std::to_string(coin.out.nValue / COIN)), chiapos::FormatNumberStr(std::to_string(nWithdrawAmount / COIN)), chiapos::FormatNumberStr(std::to_string(nBurnAmount / COIN)), chiapos::FormatNumberStr(std::to_string(coin.out.nValue)), nSpendHeight);
    txNew.vout = { CTxOut(nWithdrawAmount, coin.out.scriptPubKey) };
    if (nBurnAmount > 0) {
        // We have money needs to be burned
        txNew.vout.push_back(CTxOut(nBurnAmount, burnScriptPubKey));
    }

    int64_t nBytes = CalculateMaximumSignedTxSize(CTransaction(txNew), wallet, coin_control.fAllowWatchOnly);
    if (nBytes < 0) {
        errors.push_back(_("Signing transaction failed").translated);
        return Result::WALLET_ERROR;
    }
    txfee = GetMinimumFee(*wallet, nBytes, coin_control, nullptr);
    if (txNew.vout[0].nValue >= txfee) {
        txNew.vout[0].nValue -= txfee;
    } else {
        errors.push_back("There is not enough amount to pay the tx fee for withdrawal, you might need to wait for a few blocks before trying to withdraw the pledge.");
        return Result::UNBIND_LIMIT_ERROR;
    }

    // Check
    if (txNew.vin.size() != 1 || txNew.vin[0].prevout != outpoint || txNew.vout.size() < 1 || txNew.vout.size() > 2 || txNew.vout[0].scriptPubKey != coin.out.scriptPubKey) {
        errors.push_back("Error on create unfreeze transaction");
        return Result::WALLET_ERROR;
    }

    // return
    mtx = std::move(txNew);
    return Result::OK;
}


bool SignTransaction(CWallet* wallet, CMutableTransaction& mtx) {
    auto locked_chain = wallet->chain().lock();
    LOCK(wallet->cs_wallet);
    return wallet->SignTransaction(mtx);
}

Result CommitTransaction(CWallet* wallet, CMutableTransaction&& mtx, std::map<std::string, std::string>&& mapValue, std::vector<std::string>& errors)
{
    auto locked_chain = wallet->chain().lock();
    LOCK(wallet->cs_wallet);
    if (!errors.empty()) {
        return Result::MISC_ERROR;
    }

    // commit/broadcast the tx
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));
    CValidationState state;
    if (!wallet->CommitTransaction(tx, std::move(mapValue), {} /* orderForm */, state)) {
        // NOTE: CommitTransaction never returns false, so this should never happen.
        errors.push_back(strprintf("The transaction was rejected: %s", FormatStateMessage(state)));
        return Result::WALLET_ERROR;
    }

    if (state.IsInvalid()) {
        // This can happen if the mempool rejected the transaction.  Report
        // what happened in the "errors" response.
        errors.push_back(strprintf("Error: The transaction was rejected: %s", FormatStateMessage(state)));
    }

    return Result::OK;
}

} // namespace feebumper
