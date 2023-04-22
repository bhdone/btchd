#include <chainparams.h>
#include <key_io.h>
#include <miner.h>
#include <net.h>
#include <netmessagemaker.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <util/strencodings.h>
#include <validation.h>
#include <subsidy_utils.h>

#include <cstdint>
#include <stdexcept>

#include "chiapos/kernel/bls_key.h"
#include "chiapos/kernel/calc_diff.h"
#include "chiapos/kernel/pos.h"
#include "chiapos/kernel/utils.h"

#include "consensus/params.h"

#include "updatetip_log_helper.hpp"
#include "logging.h"
#include "post.h"

#include "poc/poc.h"

namespace chiapos {
namespace utils {

std::shared_ptr<CBlock> CreateFakeBlock(CTxDestination const& dest) {
    std::unique_ptr<CBlockTemplate> pblocktemplate;
    try {
        pblocktemplate = BlockAssembler(Params()).CreateNewBlock(GetScriptForDestination(dest), 0, 0);
    } catch (std::exception& e) {
        char const* what = e.what();
        LogPrintf("CreateBlock() fail: %s\n", what ? what : "Catch unknown exception");
    }
    if (!pblocktemplate.get()) return nullptr;

    CBlock* pblock = &pblocktemplate->block;
    return std::make_shared<CBlock>(*pblock);
}

}  // namespace utils

static UniValue checkChiapos(JSONRPCRequest const& request) {
    RPCHelpMan("checkchiapos", "Check the chain is ready for chiapos", {},
               RPCResult{"\"ready\" (bool) true if the chain is ready"},
               RPCExamples{HelpExampleCli("checkchiapos", "")})
            .Check(request);

    LOCK(cs_main);

    CBlockIndex const* pindexPrev = ChainActive().Tip();
    Consensus::Params const& params = Params().GetConsensus();

    return IsTheChainReadyForChiapos(pindexPrev, params);
}

static UniValue queryChallenge(JSONRPCRequest const& request) {
    RPCHelpMan("querychallenge", "Query next challenge for PoST", {},
               RPCResult{"\"challenge\" (hex) the challenge in hex string"},
               RPCExamples{HelpExampleCli("querychallenge", "")})
            .Check(request);

    LOCK(cs_main);

    CBlockIndex const* pindexPrev = ChainActive().Tip();
    Consensus::Params const& params = Params().GetConsensus();

    if (!IsTheChainReadyForChiapos(pindexPrev, params)) {
        throw std::runtime_error("chiapos is not ready");
    }

    UniValue res(UniValue::VOBJ);
    int nTargetHeight = pindexPrev->nHeight + 1;
    res.pushKV("difficulty", GetDifficultyForNextIterations(pindexPrev, params));
    if (nTargetHeight == params.BHDIP009Height) {
        Bytes initialVdfProof(100, 0);
        res.pushKV("challenge", MakeChallenge(pindexPrev->GetBlockHash(), initialVdfProof).GetHex());
        res.pushKV("prev_vdf_iters", params.BHDIP009StartBlockIters);
        res.pushKV("prev_vdf_duration", params.BHDIP008TargetSpacing);
    } else {
        // We need to read the challenge from last block
        uint256 challenge = MakeChallenge(pindexPrev->GetBlockHash(), pindexPrev->chiaposFields.vdfProof.vchProof);
        res.pushKV("challenge", challenge.GetHex());
        res.pushKV("prev_vdf_iters", pindexPrev->chiaposFields.vdfProof.nVdfIters);
        res.pushKV("prev_vdf_duration", pindexPrev->chiaposFields.vdfProof.nVdfDuration);
    }
    res.pushKV("prev_block_hash", pindexPrev->GetBlockHash().GetHex());
    res.pushKV("prev_block_height", pindexPrev->nHeight);
    res.pushKV("target_height", nTargetHeight);
    res.pushKV("target_duration", params.BHDIP008TargetSpacing);
    res.pushKV("filter_bits", nTargetHeight < params.BHDIP009PlotIdBitsOfFilterEnableOnHeight ? 0 : params.BHDIP009PlotIdBitsOfFilter);
    res.pushKV("base_iters", params.BHDIP009BaseIters);
    return res;
}

CVdfProof ParseVdfProof(UniValue const& val) {
    CVdfProof proof;
    proof.challenge = ParseHashV(val["challenge"], "challenge");
    proof.vchY = ParseHexV(val["y"], "y");
    proof.vchProof = ParseHexV(val["proof"], "proof");
    proof.nVdfIters = val["iters"].get_int64();
    proof.nWitnessType = val["witness_type"].get_int();
    proof.nVdfDuration = val["duration"].get_int64();
    return proof;
}

void GenerateChiaBlock(uint256 const& hashPrevBlock, int nHeightOfPrevBlock, CTxDestination const& rewardDest,
                       uint256 const& initialChallenge, chiapos::Bytes const& vchFarmerSk,
                       CPosProof const& posProof, CVdfProof const& vdfProof, uint64_t nDifficulty) {
    CKey farmerSk(MakeArray<SK_LEN>(vchFarmerSk));
    auto params = Params();
    std::shared_ptr<CBlock> pblock;
    {
        LOCK(cs_main);

        CBlockIndex const* pindexPrev = LookupBlockIndex(hashPrevBlock);  // The previous block for the new block
        if (pindexPrev == nullptr) {
            throw std::runtime_error("Cannot find the block index");
        }
        if (pindexPrev->nHeight != nHeightOfPrevBlock) {
            throw std::runtime_error("Invalid height number of the previous block");
        }

        if (!IsTheChainReadyForChiapos(pindexPrev, params.GetConsensus())) {
            LogPrintf("%s error: The chain is not ready for chiapos.\n", __func__);
            throw std::runtime_error("chiapos is not ready");
        }

        CBlockIndex* pindexCurr = ::ChainActive().Tip();
        if (pindexPrev->GetBlockHash() != pindexCurr->GetBlockHash()) {
            // The chain has changed during the proofs generation, we need to ensure:
            // 1. The new block is able to connect to the pevious block
            // 2. The difficulty of the new proofs should be larger than the last block's difficulty on the chain

            if (pindexCurr->pprev->GetBlockHash() != pindexPrev->GetBlockHash()) {
                // It seems the new block is not be able to connect to previous block
                LogPrintf("%s(drop proofs): it's not able to find the previous block of the new proofs\n", __func__);
                throw std::runtime_error(
                        "invalid new proofs, the chain has been changed and it is not able to accept it");
            }

            // Quality for the block we are going to generate
            uint256 mixed_quality_string = GenerateMixedQualityString(posProof);
            uint64_t nDuration = vdfProof.nVdfDuration;
            if (nDifficulty < pindexCurr->chiaposFields.nDifficulty) {
                // The quality is too low, and it will not be accepted by the chain
                throw std::runtime_error("the quality is too low, the new block will not be accepted by the chain");
            }

            // We reset the chain states to previous block and try to release the new one after
            {
                CValidationState state;
                LOCK(mempool.cs);
                ::ChainstateActive().DisconnectTip(state, params, nullptr);
            }

            LogPrintf("%s: the chain is reset to previous block in order to release a new block\n", __func__);
        }

        // Trying to release a new block
        PubKeyOrHash poolPkOrHash =
                MakePubKeyOrHash(static_cast<PlotPubKeyType>(posProof.nPlotType), posProof.vchPoolPkOrHash);
        std::unique_ptr<CBlockTemplate> ptemplate = BlockAssembler(params).CreateNewChiaBlock(
                pindexPrev, GetScriptForDestination(rewardDest), farmerSk, posProof, vdfProof);
        if (ptemplate == nullptr) {
            throw std::runtime_error("cannot generate new block, the template object is null");
        }
        pblock.reset(new CBlock(ptemplate->block));
    }

    if (pblock == nullptr) {
        throw std::runtime_error("pblock is null, cannot release new block");
    }
    ReleaseBlock(pblock, params);
}

static UniValue submitProof(JSONRPCRequest const& request) {
    // TODO check the validity of request parameters

    uint256 hashPrevBlock = ParseHashV(request.params[0], "prev_block_hash");
    int nHeightOfPrevBlock = request.params[1].get_int();
    uint256 initialChallenge = ParseHashV(request.params[2], "challenge");
    UniValue posVal = request.params[3];
    if (!posVal.isObject()) {
        throw std::runtime_error("pos is not an object");
    }
    // PoS proof
    CPosProof posProof;
    posProof.challenge = ParseHashV(posVal["challenge"], "challenge");
    posProof.nPlotK = posVal["k"].get_int();
    posProof.vchPoolPkOrHash = ParseHexV(posVal["pool_pk_or_hash"], "pool_pk_or_hash");
    posProof.vchLocalPk = ParseHexV(posVal["local_pk"], "local_pk");
    posProof.nPlotType = posVal["plot_type"].get_int();
    posProof.vchProof = ParseHexV(posVal["proof"], "proof");
    // Farmer secure-key
    Bytes vchFarmerSk = ParseHexV(request.params[4], "farmer_sk");
    // Generate Farmer public-key
    CKey farmerSk(MakeArray<SK_LEN>(vchFarmerSk));
    posProof.vchFarmerPk = MakeBytes(farmerSk.GetPubKey());
    // VDF proof
    CVdfProof vdfProof = ParseVdfProof(request.params[5]);
    uint64_t nTotalDuration = vdfProof.nVdfDuration;
    if (nTotalDuration == 0) {
        throw std::runtime_error("duration is zero from vdf proof");
    }
    // Reward address
    std::string strRewardDest = request.params[6].get_str();
    CTxDestination rewardDest = DecodeDestination(strRewardDest);
    if (!IsValidDestination(rewardDest)) {
        throw std::runtime_error("The reward destination is invalid");
    }

    auto params = Params().GetConsensus();

    uint64_t nDifficulty{1};
    {
        LOCK(cs_main);

        CBlockIndex* pindexPrev = LookupBlockIndex(hashPrevBlock);
        nDifficulty = AdjustDifficulty(GetChiaBlockDifficulty(pindexPrev, params), nTotalDuration,
                                       params.BHDIP008TargetSpacing, params.BHDIP009DifficultyChangeMaxFactor, params.BHDIP009StartDifficulty);
    }

    // We should put it to the chain immediately
    GenerateChiaBlock(hashPrevBlock, nHeightOfPrevBlock, rewardDest, initialChallenge, vchFarmerSk,
                      posProof, vdfProof, nDifficulty);

    return true;
}

static UniValue queryNetspace(JSONRPCRequest const& request) {
    RPCHelpMan("querynetspace", "Query current netspace", {}, RPCResult{"\"result\" (uint64) The netspace in TB"},
               RPCExamples{HelpExampleCli("querynetspace", "")})
            .Check(request);

    LOCK(cs_main);

    auto params = Params().GetConsensus();
    CAmount nTotalSupplied = GetTotalSupplyBeforeBHDIP009(params);

    CBlockIndex* pindex = ::ChainActive().Tip();
    auto netspace = poc::CalculateAverageNetworkSpace(pindex, params);

    UniValue res(UniValue::VOBJ);
    res.pushKV("supplied", nTotalSupplied);
    res.pushKV("supplied(BHD)", MakeNumberStr(nTotalSupplied / COIN));
    res.pushKV("netspace", netspace.GetLow64());
    res.pushKV("netspace(Bytes)", chiapos::FormatNumberStr(std::to_string(netspace.GetLow64())));

    return res;
}

static UniValue queryMiningRequirement(JSONRPCRequest const& request) {
    RPCHelpMan(
        "queryminerpledgeinfo",
        "Query the pledge requirement for the miner",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The miner address"},
            {"farmer-pk", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The farmer public-key"},
        },
        RPCResult("\"{json}\" the requirement for the miner"),
        RPCExamples(HelpExampleCli("queryminerpledgeinfo", "xxxxxx xxxxxx"))
    ).Check(request);

    LOCK(cs_main);
    CBlockIndex* pindex = ::ChainActive().Tip();
    auto params = Params().GetConsensus();
    if (pindex->nHeight < params.BHDIP009Height) {
        throw std::runtime_error("BHDIP009 is required");
    }

    std::string address = request.params[0].get_str();
    Bytes vchFarmerPk = ParseHexV(request.params[1], "farmer-pk");

    CAccountID accountID = ExtractAccountID(DecodeDestination(address));
    CChiaFarmerPk farmerPk(vchFarmerPk);
    CPlotterBindData bindData(farmerPk);

    CCoinsViewCache const& view = ::ChainstateActive().CoinsTip();
    CAmount nBurned = view.GetAccountBalance(GetBurnToAccountID(), nullptr, nullptr, nullptr, &params.BHDIP009PledgeTerms);
    int nMinedCount, nTotalCount, nTargetHeight = pindex->nHeight + 1;
    CAmount nReq = poc::GetMiningRequireBalance(accountID, bindData, nTargetHeight, view, nullptr, nullptr, nBurned, params, &nMinedCount, &nTotalCount);
    CAmount nAccumulate = GetBlockAccumulateSubsidy(pindex, params);
    CAmount nTotalSupplied = GetTotalSupplyBeforeBHDIP009(params);

    UniValue res(UniValue::VOBJ);
    res.pushKV("farmer-pk", chiapos::BytesToHex(vchFarmerPk));
    res.pushKV("require", nReq);
    res.pushKV("mined", nMinedCount);
    res.pushKV("count", nTotalCount);
    res.pushKV("burned", nBurned);
    res.pushKV("accumulate", nAccumulate);
    res.pushKV("supplied", nTotalSupplied);
    res.pushKV("height", nTargetHeight);

    return res;
}

static UniValue queryChainVdfInfo(JSONRPCRequest const& request) {
    RPCHelpMan(
        "querychainvdfinfo",
        "Query vdf speed and etc from current block chain",
        {
            { "height", RPCArg::Type::NUM, RPCArg::Optional::NO, "The summary information will be calculated from this height" }
        },
        RPCResult("\"{json}\" the basic information of the vdf from block chain"),
        RPCExamples(HelpExampleCli("querychainvdfinfo", "200000"))
    ).Check(request);

    LOCK(cs_main);
    auto pindex = ::ChainActive().Tip();

    auto params = Params().GetConsensus();
    int nHeight = atoi(request.params[0].get_str());
    if (nHeight < params.BHDIP009Height) {
        throw std::runtime_error("The height is out of the BHDIP009 range");
    }

    uint64_t vdf_best{0}, vdf_worst{999999}, vdf_total{0}, vdf_count{0};
    while (pindex->nHeight >= nHeight) {
        uint64_t vdf_curr = pindex->chiaposFields.GetTotalIters() / pindex->chiaposFields.GetTotalDuration();
        if (vdf_best < vdf_curr) {
            vdf_best = vdf_curr;
        }
        if (vdf_worst > vdf_curr) {
            vdf_worst = vdf_curr;
        }
        vdf_total += vdf_curr;
        ++vdf_count;
        // next
        pindex = pindex->pprev;
    }

    uint64_t vdf_average = vdf_total / vdf_count;
    UniValue res(UniValue::VOBJ);
    res.pushKV("best", MakeNumberStr(vdf_best));
    res.pushKV("worst", MakeNumberStr(vdf_worst));
    res.pushKV("average", MakeNumberStr(vdf_average));
    res.pushKV("from", nHeight);
    res.pushKV("count", vdf_count);

    return res;
}

static UniValue generateBurstBlocks(JSONRPCRequest const& request) {
    RPCHelpMan("generateburstblocks", "Submit burst blocks to chain",
               {{"count", RPCArg::Type::NUM, RPCArg::Optional::NO, "how many blocks want to generate"}},
               RPCResult{"\"succ\" (bool) True means the block is generated successfully"},
               RPCExamples{HelpExampleCli("generateburstblocks", "")})
            .Check(request);

    int nNumBlocks = request.params[0].get_int();
    if (nNumBlocks <= 0) {
        throw std::runtime_error("invalid number of blocks");
    }

    CChainParams const& params = Params();

    assert(!params.GetConsensus().BHDIP009FundAddresses.empty());
    CTxDestination dest = DecodeDestination(params.GetConsensus().BHDIP009FundAddresses[0]);

    for (int i = 0; i < nNumBlocks; ++i) {
        auto pblock = utils::CreateFakeBlock(dest);
        ReleaseBlock(pblock, params);
    }

    return true;
}

static UniValue queryUpdateTipHistory(JSONRPCRequest const& request) {
    RPCHelpMan("queryupdatetiphistory", "Query update tip logs",
            {
                {"count", RPCArg::Type::NUM, RPCArg::Optional::NO, "how many logs want to be generated"}
            },
            RPCResult{"\"succ\" (result) The update tips history"},
            RPCExamples{HelpExampleCli("queryupdatetiphistory", "")}).Check(request);

    int nCount = atoi(request.params[0].get_str());
    auto params = Params().GetConsensus();

    LOCK(cs_main);
    auto pindex = ::ChainActive().Tip();
    UpdateTipLogHelper helper(pindex, Params());
    UniValue res(UniValue::VARR);

    for (int i = 0; i < nCount; ++i) {
        UniValue entryVal = helper.PrintJson();
        // query the block
        CBlockIndex const* pindex = helper.GetBlockIndex();
        if (IsBlockPruned(pindex)) {
            entryVal.pushKV("error", "block is pruned");
        } else {
            CBlock block;
            if (!ReadBlockFromDisk(block, pindex, params)) {
                entryVal.pushKV("error", "cannot read block from disk");
            } else {
                UniValue txVal(UniValue::VARR);
                for (auto const& tx : block.vtx) {
                    if (tx->IsCoinBase()) {
                        CAccountID generatorAccountID = ExtractAccountID(tx->vout[0].scriptPubKey);
                        UniValue minerVal(UniValue::VOBJ);
                        minerVal.pushKV("address", EncodeDestination(CTxDestination((ScriptHash)generatorAccountID)));
                        minerVal.pushKV("reward", static_cast<double>(tx->vout[0].nValue) / COIN);
                        // accumulate
                        CAmount nAccumulate = GetBlockAccumulateSubsidy(pindex, params);
                        minerVal.pushKV("accumulate", static_cast<double>(nAccumulate) / COIN);
                        // save to entry
                        txVal.push_back(minerVal);
                    } else {
                        auto payload = ExtractTransactionDatacarrier(*tx, pindex->nHeight,
                                {DATACARRIER_TYPE_BINDPLOTTER,
                                 DATACARRIER_TYPE_BINDCHIAFARMER,
                                 DATACARRIER_TYPE_CHIA_POINT,
                                 DATACARRIER_TYPE_CHIA_POINT_TERM_1,
                                 DATACARRIER_TYPE_CHIA_POINT_TERM_2,
                                 DATACARRIER_TYPE_CHIA_POINT_TERM_3,
                                 DATACARRIER_TYPE_CHIA_POINT_RETARGET});
                        if (payload) {
                            UniValue payloadVal(UniValue::VOBJ);
                            if (payload->type == DATACARRIER_TYPE_BINDPLOTTER || payload->type == DATACARRIER_TYPE_BINDCHIAFARMER) {
                                auto p = BindPlotterPayload::As(payload);
                                CAccountID accountID = ExtractAccountID(tx->vout[0].scriptPubKey);
                                std::string strAddress = EncodeDestination(static_cast<ScriptHash>(accountID));
                                payloadVal.pushKV("action", "bind");
                                payloadVal.pushKV("address", strAddress);
                                if (payload->type == DATACARRIER_TYPE_BINDPLOTTER) {
                                    payloadVal.pushKV("plotter", p->GetId().GetBurstPlotterId());
                                } else {
                                    payloadVal.pushKV("farmer", p->GetId().GetChiaFarmerPk().ToString());
                                }
                            } else if (payload->type == DATACARRIER_TYPE_CHIA_POINT ||
                                       payload->type == DATACARRIER_TYPE_CHIA_POINT_TERM_1 ||
                                       payload->type == DATACARRIER_TYPE_CHIA_POINT_TERM_2 ||
                                       payload->type == DATACARRIER_TYPE_CHIA_POINT_TERM_3) {
                                auto p = PointPayload::As(payload);
                                payloadVal.pushKV("action", "point");
                                payloadVal.pushKV("type", DatacarrierTypeToString(payload->type));
                                payloadVal.pushKV("amount", static_cast<double>(tx->vout[0].nValue) / COIN);
                                payloadVal.pushKV("address", EncodeDestination(CTxDestination(static_cast<ScriptHash>(p->GetReceiverID()))));
                            } else if (payload->type == DATACARRIER_TYPE_CHIA_POINT_RETARGET) {
                                auto p = PointRetargetPayload::As(payload);
                                payloadVal.pushKV("action", "retarget");
                                payloadVal.pushKV("amount", static_cast<double>(tx->vout[0].nValue) / COIN);
                                payloadVal.pushKV("address", EncodeDestination(CTxDestination(static_cast<ScriptHash>(p->GetReceiverID()))));
                                payloadVal.pushKV("type", DatacarrierTypeToString(p->GetPointType()));
                                payloadVal.pushKV("height", p->GetPointHeight());
                            }
                            txVal.push_back(payloadVal);
                        }
                    }
                }
                entryVal.pushKV("txs", txVal);
            }
        }
        res.push_back(entryVal);
        // next
        if (!helper.MoveToPrevIndex()) {
            break;
        }
    }

    return res;
}

static CRPCCommand const commands[] = {
        {"chia", "checkchiapos", &checkChiapos, {}},
        {"chia", "querychallenge", &queryChallenge, {}},
        {"chia", "querynetspace", &queryNetspace, {}},
        {"chia", "querychainvdfinfo", &queryChainVdfInfo, {"height"}},
        {"chia", "queryminingrequirement", &queryMiningRequirement, {"address", "farmer-pk"}},
        {"chia", "submitproof", &submitProof, {"challenge", "quality_string", "pos_proof", "k", "pool_pk", "local_pk", "farmer_pk", "farmer_sk", "plot_id", "vdf_proof_vec", "reward_dest"}},
        {"chia", "generateburstblocks", &generateBurstBlocks, {"count"}},
        {"chia", "queryupdatetiphistory", &queryUpdateTipHistory, {"count"}}
};

void RegisterChiaRPCCommands(CRPCTable& t) {
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++) {
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
    }
}

}  // namespace chiapos
