// Copyright (c) 2017-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_verify.h>

#include <chain.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <util/moneystr.h>
#include <validation.h>
#include <subsidy_utils.h>
#include <key_io.h>

#include <univalue.h>

void TxToJSON(const CTransaction& tx, const uint256 hashBlock, UniValue& entry);

bool IsFinalTx(CTransaction const& tx, int nBlockHeight, int64_t nBlockTime) {
    if (tx.nLockTime == 0)
        return true;
    if ((int64_t)tx.nLockTime < ((int64_t)tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
        return true;
    for (auto const& txin : tx.vin) {
        if (!(txin.nSequence == CTxIn::SEQUENCE_FINAL))
            return false;
    }
    return true;
}

std::pair<int, int64_t> CalculateSequenceLocks(CTransaction const& tx, int flags, std::vector<int>* prevHeights,
                                               CBlockIndex const& block) {
    assert(prevHeights->size() == tx.vin.size());

    // Will be set to the equivalent height- and time-based nLockTime
    // values that would be necessary to satisfy all relative lock-
    // time constraints given our view of block chain history.
    // The semantics of nLockTime are the last invalid height/time, so
    // use -1 to have the effect of any height or time being valid.
    int nMinHeight = -1;
    int64_t nMinTime = -1;

    // tx.nVersion is signed integer so requires cast to unsigned otherwise
    // we would be doing a signed comparison and half the range of nVersion
    // wouldn't support BIP 68.
    bool fEnforceBIP68 = static_cast<uint32_t>(tx.nVersion) >= 2
                      && flags & LOCKTIME_VERIFY_SEQUENCE;

    // Do not enforce sequence numbers as a relative lock time
    // unless we have been instructed to
    if (!fEnforceBIP68) {
        return std::make_pair(nMinHeight, nMinTime);
    }

    for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
        CTxIn const& txin = tx.vin[txinIndex];

        // Sequence numbers with the most significant bit set are not
        // treated as relative lock-times, nor are they given any
        // consensus-enforced meaning at this point.
        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
            // The height of this input is not relevant for sequence locks
            (*prevHeights)[txinIndex] = 0;
            continue;
        }

        int nCoinHeight = (*prevHeights)[txinIndex];

        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) {
            int64_t nCoinTime = block.GetAncestor(std::max(nCoinHeight-1, 0))->GetMedianTimePast();
            // NOTE: Subtract 1 to maintain nLockTime semantics
            // BIP 68 relative lock times have the semantics of calculating
            // the first block or time at which the transaction would be
            // valid. When calculating the effective block time or height
            // for the entire transaction, we switch to using the
            // semantics of nLockTime which is the last invalid block
            // time or height.  Thus we subtract 1 from the calculated
            // time or height.

            // Time-based relative lock-times are measured from the
            // smallest allowed timestamp of the block containing the
            // txout being spent, which is the median time past of the
            // block prior.
            nMinTime = std::max(nMinTime, nCoinTime + (int64_t)((txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) - 1);
        } else {
            nMinHeight = std::max(nMinHeight, nCoinHeight + (int)(txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) - 1);
        }
    }

    return std::make_pair(nMinHeight, nMinTime);
}

bool EvaluateSequenceLocks(CBlockIndex const& block, std::pair<int, int64_t> lockPair) {
    assert(block.pprev);
    int64_t nBlockTime = block.pprev->GetMedianTimePast();
    if (lockPair.first >= block.nHeight || lockPair.second >= nBlockTime)
        return false;

    return true;
}

bool SequenceLocks(CTransaction const& tx, int flags, std::vector<int>* prevHeights, CBlockIndex const& block) {
    return EvaluateSequenceLocks(block, CalculateSequenceLocks(tx, flags, prevHeights, block));
}

unsigned int GetLegacySigOpCount(CTransaction const& tx) {
    unsigned int nSigOps = 0;
    for (auto const& txin : tx.vin) {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }
    for (auto const& txout : tx.vout) {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}

unsigned int GetP2SHSigOpCount(CTransaction const& tx, CCoinsViewCache const& inputs) {
    if (tx.IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        Coin const& coin = inputs.AccessCoin(tx.vin[i].prevout);
        assert(!coin.IsSpent());
        CTxOut const& prevout = coin.out;
        if (prevout.scriptPubKey.IsPayToScriptHash())
            nSigOps += prevout.scriptPubKey.GetSigOpCount(tx.vin[i].scriptSig);
    }
    return nSigOps;
}

int64_t GetTransactionSigOpCost(CTransaction const& tx, CCoinsViewCache const& inputs, int flags) {
    int64_t nSigOps = GetLegacySigOpCount(tx) * WITNESS_SCALE_FACTOR;

    if (tx.IsCoinBase())
        return nSigOps;

    if (flags & SCRIPT_VERIFY_P2SH) {
        nSigOps += GetP2SHSigOpCount(tx, inputs) * WITNESS_SCALE_FACTOR;
    }

    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        Coin const& coin = inputs.AccessCoin(tx.vin[i].prevout);
        assert(!coin.IsSpent());
        CTxOut const& prevout = coin.out;
        nSigOps += CountWitnessSigOps(tx.vin[i].scriptSig, prevout.scriptPubKey, &tx.vin[i].scriptWitness, flags);
    }
    return nSigOps;
}

bool Consensus::CheckTxInputs(CTransaction const& tx, CValidationState& state, CCoinsViewCache const& inputs, CCoinsViewCache const& prevInputs, int nSpendHeight, CAmount& txfee, CAccountID const& generatorAccountID, CheckTxLevel level, Consensus::Params const& params)
{
    // are the actual inputs available?
    if (!inputs.HaveInputs(tx)) {
        return state.Invalid(ValidationInvalidReason::TX_MISSING_INPUTS, false, REJECT_INVALID, "bad-txns-inputs-missingorspent", strprintf("%s: inputs missing/spent", __func__));
    }

    CAmount nValueIn = 0;
    CAccountID burnAccountID = GetBurnToAccountID();
    for (unsigned int i = 0; i < tx.vin.size(); ++i) {
        COutPoint const& prevout = tx.vin[i].prevout;
        Coin const& previous_coin = inputs.AccessCoin(prevout); // The coin is the previous output
        assert(!previous_coin.IsSpent());

        if (previous_coin.refOutAccountID == burnAccountID) {
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "tx-spend-burn-address", "spend from burn address is not allowed");
        }

        // If prev is coinbase, check that it's matured
        if (previous_coin.IsCoinBase() && nSpendHeight - previous_coin.nHeight < COINBASE_MATURITY) {
            return state.Invalid(ValidationInvalidReason::TX_PREMATURE_SPEND, false, REJECT_INVALID, "bad-txns-premature-spend-of-coinbase", strprintf("tried to spend coinbase at depth %d", nSpendHeight - previous_coin.nHeight));
        }

        // Check for negative or overflow input values
        nValueIn += previous_coin.out.nValue;
        if (!MoneyRange(previous_coin.out.nValue) || !MoneyRange(nValueIn)) {
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-inputvalues-outofrange");
        }
    }

    const CAmount nValueOut = tx.GetValueOut();
    if (nValueIn < nValueOut) {
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-in-belowout", strprintf("value in (%s) < value out (%s)", FormatMoney(nValueIn), FormatMoney(nValueOut)));
    }

    // Tally transaction fees
    CAmount txfee_aux = nValueIn - nValueOut;
    if (!MoneyRange(txfee_aux)) {
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-fee-outofrange");
    }

    // Check uniform transaction. Inputs[i] == Outputs[j]
    if (tx.IsUniform() && nSpendHeight >= params.BHDIP006Height) {
        Coin const& coin = inputs.AccessCoin(tx.vin[0].prevout);
        CScript const& scriptPubKey = coin.out.scriptPubKey;
        // Ensure that all coins are come from 1 address
        for (unsigned int i = 1; i < tx.vin.size(); ++i) {
            Coin const& coin = inputs.AccessCoin(tx.vin[i].prevout);
            if (coin.out.scriptPubKey != scriptPubKey)
                return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-inputdest-invaliduniform");
        }
        // Ensure the `scriptPubkey` is the only script when it is a non-zero outpoint
        // We only verify the first outpoint and ensure the scripPubKey is match with the inputs
        if (tx.vout[0].scriptPubKey != scriptPubKey) {
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-outputdest-invaliduniform");
        }
    }

    // Check for bind plotter fee and unbind plotter limit
    if (level != CheckTxLevel::CheckMempool && tx.IsUniform() && nSpendHeight >= params.BHDIP006CheckRelayHeight) {
        // This is an uniform tx, now we find the previous coin and check it is bind or point
        if (tx.vin.size() == 1 && (tx.vout.size() == 1 || (nSpendHeight >= params.BHDIP009Height && tx.vout.size() <= 2 && tx.vout.size() >= 1))) {
            // Unbind & Withdraw
            Coin const& previous_coin = inputs.AccessCoin(tx.vin[0].prevout);
            if (!previous_coin.extraData && nSpendHeight >= params.BHDIP007Height)
                return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-invaliduniform-unlock");
            if (previous_coin.extraData) {
                if (previous_coin.extraData->type == DATACARRIER_TYPE_BINDPLOTTER ||
                    previous_coin.extraData->type == DATACARRIER_TYPE_BINDCHIAFARMER) {
                    if (level != CheckTxLevel::Consensus && static_cast<int>(previous_coin.nHeight) == nSpendHeight)
                        return state.Invalid(ValidationInvalidReason::TX_INVALID_BIND, false, REJECT_INVALID,
                                             "bad-unbindplotter-strict-limit");
                    int nLimitHeight =
                            GetUnbindPlotterLimitHeight(CBindPlotterInfo(tx.vin[0].prevout, previous_coin), prevInputs, params);
                    if (nSpendHeight < nLimitHeight) {
                        LogPrintf(
                                "%s: assert(nSpendHeight >= nLimitHeight) is failed! nSpendHeight=%d, "
                                "nLimitHeight=%d\n",
                                __func__, nSpendHeight, nLimitHeight);
                        return state.Invalid(ValidationInvalidReason::TX_INVALID_BIND, false, REJECT_INVALID,
                                             "bad-unbindplotter-limit");
                    }
                }
            }
        } else {
            // Bind & Point & Retarget
            bool fReject { false };
            int nLastActiveHeight { 0 };
            CDatacarrierPayloadRef payload = ExtractTransactionDatacarrier(tx, nSpendHeight,
                    DatacarrierTypes{
                        DATACARRIER_TYPE_BINDPLOTTER, DATACARRIER_TYPE_BINDCHIAFARMER, DATACARRIER_TYPE_POINT, DATACARRIER_TYPE_CHIA_POINT,
                        DATACARRIER_TYPE_CHIA_POINT_TERM_1, DATACARRIER_TYPE_CHIA_POINT_TERM_2, DATACARRIER_TYPE_CHIA_POINT_TERM_3,
                        DATACARRIER_TYPE_CHIA_POINT_RETARGET},
                    fReject, nLastActiveHeight);
            if (payload == nullptr) {
                if (nSpendHeight >= params.BHDIP007Height) {
                    LogPrintf("%s: invalid tx found %s, reason - payload is nullptr, nLastActiveHeight=%d, nSpendHeight=%d\n",
                            __func__, tx.GetHash().ToString(), nLastActiveHeight, nSpendHeight);
                    return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-invaliduniform-type");
                }
            } else {
                if ((payload->type == DATACARRIER_TYPE_BINDCHIAFARMER || payload->type == DATACARRIER_TYPE_CHIA_POINT_RETARGET || DatacarrierTypeIsChiaPoint(payload->type)) && nSpendHeight < params.BHDIP009Height) {
                    return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-chia-tx-earlier");
                }

                // Bind plotter
                if ((payload->type == DATACARRIER_TYPE_BINDPLOTTER || payload->type == DATACARRIER_TYPE_BINDCHIAFARMER) && nSpendHeight >= params.BHDIP006LimitBindPlotterHeight) {
                    // Low fee
                    if (txfee_aux < PROTOCOL_BINDPLOTTER_MINFEE)
                        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-bindplotter-lowfee");

                    // Limit bind by last
                    const CBindPlotterInfo lastBindInfo = prevInputs.GetLastBindPlotterInfo(BindPlotterPayload::As(payload)->GetId());
                    if (!lastBindInfo.outpoint.IsNull()) {
                        // Forbidden self-packaging change active bind tx
                        if (lastBindInfo.valid && !generatorAccountID.IsNull() && generatorAccountID == ExtractAccountID(tx.vout[0].scriptPubKey))
                            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-bindplotter-selfpackaging");

                        if (nSpendHeight < GetBindPlotterLimitHeight(nSpendHeight, lastBindInfo, params)) {
                            // Change bind plotter punishment
                            CAmount diffReward = GetBindPlotterPunishmentAmount(nSpendHeight, params);
                            if (txfee_aux < diffReward + PROTOCOL_BINDPLOTTER_MINFEE)
                                return state.Invalid(ValidationInvalidReason::TX_INVALID_BIND, false, REJECT_INVALID, "bad-bindplotter-lowpunishment");

                            // Only pay small transaction fee to miner. Other fee to black hole
                            txfee_aux -= diffReward;
                        }
                    }
                }
            }

        }
    }

    txfee = txfee_aux;
    return true;
}

bool Consensus::CheckTxInputs(CTransaction const& tx, CCoinsViewCache const& inputs, CCoinsViewCache const& prevInputs, int nSpendHeight, CAccountID const& generatorAccountID, CheckTxLevel level, Consensus::Params const& params)
{
    CValidationState state;
    CAmount txfee;
    return Consensus::CheckTxInputs(tx, state, inputs, prevInputs, nSpendHeight, txfee, generatorAccountID, level, params);
}

int Consensus::GetBindPlotterLimitHeight(int nBindHeight, CBindPlotterInfo const& lastBindInfo,
                                         Consensus::Params const& params) {
    assert(!lastBindInfo.outpoint.IsNull() && lastBindInfo.nHeight >= 0);
    assert(nBindHeight > lastBindInfo.nHeight);

    if (nBindHeight < params.BHDIP006LimitBindPlotterHeight)
        return std::max(params.BHDIP006Height, lastBindInfo.nHeight + 1);

    // Checking range [nEvalBeginHeight, nEvalEndHeight]
    int const nEvalBeginHeight =
            std::max(nBindHeight - params.nCapacityEvalWindow, params.BHDIP001PreMiningEndHeight + 1);
    int const nEvalEndHeight = nBindHeight - 1;

    // Mined block in <EvalWindow>, next block unlimit
    for (int nHeight = nEvalBeginHeight; nHeight <= nEvalEndHeight; nHeight++) {
        if (lastBindInfo.bindData.GetType() == CPlotterBindData::Type::BURST) {
            if (::ChainActive()[nHeight]->nPlotterId == lastBindInfo.bindData.GetBurstPlotterId())
                return std::max(nHeight, lastBindInfo.nHeight) + 1;
        } else if (lastBindInfo.bindData.GetType() == CPlotterBindData::Type::CHIA) {
            if (::ChainActive()[nHeight]->chiaposFields.posProof.vchFarmerPk == lastBindInfo.bindData.GetChiaFarmerPk().ToBytes())
                return std::max(nHeight, lastBindInfo.nHeight) + 1;
        }
    }

    // Participator mined after bind require lock <EvalWindow>
    int const nBeginMiningHeight = lastBindInfo.nHeight;
    int const nEndMiningHeight = std::min(lastBindInfo.nHeight + params.nCapacityEvalWindow, nEvalEndHeight);
    for (int nHeight = nBeginMiningHeight; nHeight <= nEndMiningHeight; nHeight++) {
        if (::ChainActive()[nHeight]->generatorAccountID == lastBindInfo.accountID)
            return lastBindInfo.nHeight + params.nCapacityEvalWindow;
    }

    return lastBindInfo.nHeight + 1;
}

int Consensus::GetUnbindPlotterLimitHeight(CBindPlotterInfo const& bindInfo, CCoinsViewCache const& inputs,
                                           Consensus::Params const& params) {
    assert(!bindInfo.outpoint.IsNull() && bindInfo.valid && bindInfo.nHeight >= 0);

    int const nSpendHeight = GetSpendHeight(inputs);
    assert(nSpendHeight >= bindInfo.nHeight);
    if (nSpendHeight < params.BHDIP006CheckRelayHeight)
        return std::max(params.BHDIP006Height, bindInfo.nHeight + 1);

    // Checking range [nEvalBeginHeight, nEvalEndHeight]
    int const nEvalBeginHeight =
            std::max(nSpendHeight - params.nCapacityEvalWindow, params.BHDIP001PreMiningEndHeight + 1);
    int const nEvalEndHeight = nSpendHeight - 1;

    // 2.5%, Large capacity unlimit
    for (int height = nEvalBeginHeight + 1, nMinedBlockCount = 0; height <= nEvalEndHeight; height++) {
        CBlockIndex *pindex = ::ChainActive()[height];
        CPlotterBindData bindData;
        if (pindex->nHeight < params.BHDIP009Height) {
            bindData = pindex->nPlotterId;
        } else {
            bindData = CChiaFarmerPk(pindex->chiaposFields.posProof.vchFarmerPk);
        }
        if (bindData == bindInfo.bindData) {
            if (++nMinedBlockCount > params.nCapacityEvalWindow / 40)
                return std::max(std::min(height, bindInfo.nHeight + params.nCapacityEvalWindow), bindInfo.nHeight);
        }
    }

    if (nSpendHeight < params.BHDIP006LimitBindPlotterHeight) {
        //! Issues: Infinitely +<EvalWindow> when mine to any address
        // Delay unbind EvalWindow blocks when mined block
        for (int nHeight = nEvalEndHeight; nHeight > nEvalBeginHeight; nHeight--) {
            if (bindInfo.bindData == ::ChainActive()[nHeight]->nPlotterId)
                return nHeight + params.nCapacityEvalWindow;
        }
    } else if (nSpendHeight < params.BHDIP007Height) {
        //! Issues: Infinitely +<EvalWindow>
        const CBindPlotterInfo activeBindInfo = inputs.GetChangeBindPlotterInfo(bindInfo, true);
        assert(!activeBindInfo.outpoint.IsNull() && activeBindInfo.valid && activeBindInfo.nHeight >= 0);
        assert(activeBindInfo.nHeight >= bindInfo.nHeight);

        // Checking range [nBeginMiningHeight, nEndMiningHeight]
        int const nBeginMiningHeight = std::max(nEvalBeginHeight, bindInfo.nHeight);
        int const nEndMiningHeight = (bindInfo.outpoint == activeBindInfo.outpoint) ? nEvalEndHeight
                                                                                    : activeBindInfo.nHeight;

        // Last mining in current wallet will lock +<EvalWindow>
        for (int nHeight = nEndMiningHeight; nHeight >= nBeginMiningHeight; nHeight--) {
            CBlockIndex *pindex = ::ChainActive()[nHeight];
            if (pindex->generatorAccountID == bindInfo.accountID && pindex->nPlotterId == bindInfo.bindData.GetBurstPlotterId())
                return nHeight + params.nCapacityEvalWindow;
        }

        // Participate mining lock <EvalWindow>
        for (int nHeight = nEndMiningHeight; nHeight >= nBeginMiningHeight; nHeight--) {
            if (::ChainActive()[nHeight]->generatorAccountID == bindInfo.accountID)
                return bindInfo.nHeight + params.nCapacityEvalWindow;
        }
    } else {
        // Participate mining lock <EvalWindow>
        const CBindPlotterInfo changeBindInfo = inputs.GetChangeBindPlotterInfo(bindInfo, false);
        assert(!changeBindInfo.outpoint.IsNull() && changeBindInfo.nHeight >= 0);
        assert(changeBindInfo.nHeight >= bindInfo.nHeight);
        assert(nSpendHeight >= changeBindInfo.nHeight);

        // Checking range [nBeginMiningHeight, nEndMiningHeight]
        int const nBeginMiningHeight = bindInfo.nHeight;
        int const nEndMiningHeight = (bindInfo.outpoint == changeBindInfo.outpoint) ? nEvalEndHeight
                                                                                    : changeBindInfo.nHeight;
        for (int nHeight = nBeginMiningHeight; nHeight <= nEndMiningHeight; nHeight++) {
            if (::ChainActive()[nHeight]->generatorAccountID == bindInfo.accountID)
                return bindInfo.nHeight + params.nCapacityEvalWindow;
        }
    }

    return bindInfo.nHeight + 1;
}

CAmount Consensus::GetBindPlotterPunishmentAmount(int nBindHeight, Params const& params) {
    AssertLockHeld(cs_main);
    return (GetBlockSubsidy(nBindHeight, params) * (params.BHDIP001FundRoyaltyForLowMortgage - params.BHDIP001FundRoyaltyForFullMortgage)) / 1000;
}
