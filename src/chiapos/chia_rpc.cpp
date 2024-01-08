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
#include <core_io.h>

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

extern std::unique_ptr<CConnman> g_connman;

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
    uint256 challenge;
    res.pushKV("difficulty", GetDifficultyForNextIterations(pindexPrev, params));
    if (nTargetHeight == params.BHDIP009Height) {
        Bytes initialVdfProof(100, 0);
        challenge = MakeChallenge(pindexPrev->GetBlockHash(), initialVdfProof);
        res.pushKV("challenge", challenge.GetHex());
        res.pushKV("prev_vdf_iters", params.BHDIP009StartBlockIters);
        res.pushKV("prev_vdf_duration", params.BHDIP008TargetSpacing);
    } else {
        // We need to read the challenge from last block
        challenge = MakeChallenge(pindexPrev->GetBlockHash(), pindexPrev->chiaposFields.vdfProof.vchProof);
        res.pushKV("challenge", challenge.GetHex());
        res.pushKV("prev_vdf_iters", pindexPrev->chiaposFields.vdfProof.nVdfIters);
        res.pushKV("prev_vdf_duration", pindexPrev->chiaposFields.vdfProof.nVdfDuration);
    }
    assert(!challenge.IsNull());
    res.pushKV("prev_block_hash", pindexPrev->GetBlockHash().GetHex());
    res.pushKV("prev_block_height", pindexPrev->nHeight);
    res.pushKV("prev_block_time", pindexPrev->GetBlockTime());
    res.pushKV("target_height", nTargetHeight);
    res.pushKV("target_duration", params.BHDIP008TargetSpacing);
    res.pushKV("filter_bits",
               nTargetHeight < params.BHDIP009PlotIdBitsOfFilterEnableOnHeight ? 0 : params.BHDIP009PlotIdBitsOfFilter);
    int nBaseIters = GetBaseIters(nTargetHeight, params);
    res.pushKV("base_iters", nBaseIters);

    // vdf requests
    UniValue vdf_reqs(UniValue::VARR);
    auto iters_vec = QueryLocalVdfRequests(challenge);
    for (auto iters : iters_vec) {
        if (iters >= nBaseIters) {
            vdf_reqs.push_back(iters);
        }
    }
    res.pushKV("vdf_reqs", vdf_reqs);

    // vdf proofs
    auto vVdfProofs = QueryLocalVdfProof(challenge);
    UniValue vdf_proofs(UniValue::VARR);
    for (auto const& vdfProof : vVdfProofs) {
        UniValue vdf_proof(UniValue::VOBJ);
        vdf_proof.pushKV("challenge", vdfProof.challenge.GetHex());
        vdf_proof.pushKV("y", BytesToHex(vdfProof.vchY));
        vdf_proof.pushKV("proof", BytesToHex(vdfProof.vchProof));
        vdf_proof.pushKV("witness_type", vdfProof.nWitnessType);
        vdf_proof.pushKV("iters", vdfProof.nVdfIters);
        vdf_proof.pushKV("duration", vdfProof.nVdfDuration);
        LogPrint(BCLog::NET, "%s (VDF proof): challenge=%s, iters=%ld, duration=%d (secs)\n", __func__, vdfProof.challenge.GetHex(), vdfProof.nVdfIters, vdfProof.nVdfDuration);
        vdf_proofs.push_back(std::move(vdf_proof));
    }
    res.pushKV("vdf_proofs", vdf_proofs);
    return res;
}

static UniValue submitVdfRequest(JSONRPCRequest const& request) {
    RPCHelpMan("submitvdfrequest", "Submit vdf request to P2P network",
        {
            {"challenge", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The challenge of the request"},
            {"iters", RPCArg::Type::NUM, RPCArg::Optional::NO, "The number of iters of the request"},
        },
        RPCResult{"{boolean} True means the request is submitted successfully, otherwise the request is not accepted"},
        RPCExamples{HelpExampleCli("submitvdfrequest", "xxxxxxxx 10239")}).Check(request);

    uint256 challenge = ParseHashV(request.params[0], "challenge");
    int64_t nIters = request.params[1].get_int64();

    if (nIters < 1) {
        throw std::runtime_error(tinyformat::format("%s: invalid iters=(%d)", __func__, nIters));
    }

    LOCK(cs_main);
    AddLocalVdfRequest(challenge, nIters);

    // send the request to P2P network
    g_connman->ForEachNode(
        [&challenge, nIters](CNode* pnode) {
            if (pnode->nVersion >= VDF_P2P_VERSION) {
                CNetMsgMaker maker(pnode->GetSendVersion());
                g_connman->PushMessage(pnode, maker.Make(NetMsgType::VDFREQ64, challenge, nIters));
            }
        }
    );

    return true;
}

static UniValue submitVdfProof(JSONRPCRequest const& request) {
    RPCHelpMan("submitvdfproof", "Submit vdf proof to P2P network", {
        {"challenge", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The challenge of the vdf proof"},
        {"y", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Y of the proof"},
        {"proof", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Proof of the proof"},
        {"witness_type", RPCArg::Type::NUM, RPCArg::Optional::NO, "Witness type of the proof"},
        {"iters", RPCArg::Type::NUM, RPCArg::Optional::NO, "Iterations of the proof"},
        {"duration", RPCArg::Type::NUM, RPCArg::Optional::NO, "Time consumed to calculate the proof"}
    }, RPCResult{"{boolean} True means the proof is submitted to P2P network, otherwise the proof is not accepted"},
    RPCExamples{
        HelpExampleCli("submitvdfproof", "xxxx xxxx xxxx 0 20000 60")
    }).Check(request);

    CVdfProof vdfProof;
    vdfProof.challenge = ParseHashV(request.params[0], "challenge");
    vdfProof.vchY = ParseHexV(request.params[1], "y");
    vdfProof.vchProof = ParseHexV(request.params[2], "proof");
    vdfProof.nWitnessType = request.params[3].get_int();
    if (vdfProof.nWitnessType < 0 || vdfProof.nWitnessType > 255) {
        throw std::runtime_error("invalid value of witness_type");
    }
    vdfProof.nVdfIters = request.params[4].get_int64();
    vdfProof.nVdfDuration = request.params[5].get_int();

    // verify the proof
    CValidationState state;
    if (!CheckVdfProof(vdfProof, state)) {
        throw std::runtime_error(tinyformat::format("%s: the vdf proof (challenge=%s, proof=%s) is invalid", __func__, vdfProof.challenge.GetHex(), BytesToHex(vdfProof.vchProof)));
    }

    LOCK(cs_main);

    // save the proof
    if (!AddLocalVdfProof(vdfProof)) {
        LogPrint(BCLog::POC, "%s: warning - proof (challenge=%s, iters=%ld) does exist in local\n", __func__, vdfProof.challenge.GetHex(), vdfProof.nVdfIters);
    }

    // dispatch the message to P2P network
    g_connman->ForEachNode([&vdfProof](CNode *pnode) {
        if (pnode->nVersion >= VDF_P2P_VERSION) {
            CNetMsgMaker msgMaker(pnode->GetSendVersion());
            g_connman->PushMessage(pnode, msgMaker.Make(NetMsgType::VDF, vdfProof));
        }
    });

    return true;
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
                       uint256 const& initialChallenge, chiapos::Bytes const& vchFarmerSk, CPosProof const& posProof,
                       CVdfProof const& vdfProof, uint64_t nDifficulty) {
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

        // Check bind
        const CAccountID accountID = ExtractAccountID(rewardDest);
        if (accountID.IsNull()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid BitcoinHD1 address");
        }
        bool fFundAccount { false };
        for (auto const& fundAddr : params.GetConsensus().BHDIP009FundAddresses) {
            auto fundAccountID = ExtractAccountID(DecodeDestination(fundAddr));
            if (fundAccountID == accountID) {
                fFundAccount = true;
                break;
            }
        }
        if (!fFundAccount) {
            auto vchFarmerPk = MakeBytes(farmerSk.GetPubKey());
            if (!::ChainstateActive().CoinsTip().HaveActiveBindPlotter(accountID, CPlotterBindData(CChiaFarmerPk(vchFarmerPk)))) {
                throw JSONRPCError(RPC_INVALID_REQUEST,
                    strprintf("%s with %s not active bind", BytesToHex(vchFarmerPk), EncodeDestination(rewardDest)));
            }
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
        if (pindexPrev == nullptr) {
            LogPrintf("%s: cannot find block by hash: %s, the proof will not be submitted\n", __func__,
                      hashPrevBlock.GetHex());
            return false;
        }
        double targetMulFactor = 1.0;
        int nTargetHeight = pindexPrev->nHeight + 1;
        if (nTargetHeight >= params.BHDIP009TargetSpacingMulFactorEnableAtHeight) {
            targetMulFactor = params.BHDIP009TargetSpacingMulFactor;
        }
        nDifficulty = AdjustDifficulty(GetChiaBlockDifficulty(pindexPrev, params), nTotalDuration,
                                       params.BHDIP008TargetSpacing, QueryDurationFix(nTargetHeight, params.BHDIP009TargetDurationFixes),
                                       GetDifficultyChangeMaxFactor(nTargetHeight, params),
                                       params.BHDIP009StartDifficulty, targetMulFactor);
    }

    // We should put it to the chain immediately
    GenerateChiaBlock(hashPrevBlock, nHeightOfPrevBlock, rewardDest, initialChallenge, vchFarmerSk, posProof, vdfProof,
                      nDifficulty);

    return true;
}

static UniValue queryNetspace(JSONRPCRequest const& request) {
    RPCHelpMan("querynetspace", "Query current netspace", {}, RPCResult{"\"result\" (uint64) The netspace in TB"},
               RPCExamples{HelpExampleCli("querynetspace", "")})
            .Check(request);

    LOCK(cs_main);

    CBlockIndex* pindex = ::ChainActive().Tip();

    auto params = Params().GetConsensus();
    CAmount nTotalSupplied = GetTotalSupplyBeforeBHDIP009(params) * (params.BHDIP009TotalAmountUpgradeMultiply - 1) +
                             GetTotalSupplyBeforeHeight(pindex->nHeight, params);

    auto netspace_avg = poc::CalculateAverageNetworkSpace(pindex, params);

    int nBitsOfFilter = pindex->nHeight >= params.BHDIP009PlotIdBitsOfFilterEnableOnHeight ? params.BHDIP009PlotIdBitsOfFilter : 0;
    auto netspace = chiapos::CalculateNetworkSpace(GetDifficultyForNextIterations(pindex->pprev, params),
                                                   pindex->chiaposFields.GetTotalIters(),
                                                   params.BHDIP009DifficultyConstantFactorBits);

    UniValue res(UniValue::VOBJ);
    res.pushKV("supplied", nTotalSupplied);
    res.pushKV("supplied(Human)", chiapos::FormatNumberStr(std::to_string(nTotalSupplied)));
    res.pushKV("supplied(BHD1)", MakeNumberStr(nTotalSupplied / COIN));
    res.pushKV("netspace_tib", MakeNumberTiB(netspace).GetLow64());
    res.pushKV("netspace_tib(Human)", chiapos::FormatNumberStr(std::to_string(MakeNumberTiB(netspace).GetLow64())));
    res.pushKV("netspace_avg_tib", MakeNumberTiB(netspace_avg).GetLow64());
    res.pushKV("netspace_avg_tib(Human)", chiapos::FormatNumberStr(std::to_string(MakeNumberTiB(netspace_avg).GetLow64())));

    return res;
}

static UniValue queryMiningRequirement(JSONRPCRequest const& request) {
    RPCHelpMan("queryminingrequirement", "Query the pledge requirement for the miner",
               {
                   {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The miner address"},
               },
               RPCResult("\"{json}\" the requirement for the miner"),
               RPCExamples(HelpExampleCli("queryminerpledgeinfo", "xxxxxx xxxxxx")))
            .Check(request);

    LOCK(cs_main);
    CBlockIndex* pindex = ::ChainActive().Tip();
    auto params = Params().GetConsensus();
    if (pindex->nHeight < params.BHDIP009Height) {
        throw std::runtime_error("BHDIP009 is required");
    }

    std::string address = request.params[0].get_str();
    CAccountID accountID = ExtractAccountID(DecodeDestination(address));

    std::vector<uint8_t> vchFarmerPk(chiapos::PK_LEN, '\0');
    CChiaFarmerPk farmerPk(vchFarmerPk);
    CPlotterBindData bindData(farmerPk);

    int nMinedCount, nTotalCount, nTargetHeight = pindex->nHeight + 1;
    int nHeightForCalculatingTotalSupply = GetHeightForCalculatingTotalSupply(nTargetHeight, params);

    CCoinsViewCache const& view = ::ChainstateActive().CoinsTip();
    CAmount nBurned = view.GetAccountBalance(false, GetBurnToAccountID(), nullptr, nullptr, nullptr,
                                             &params.BHDIP009PledgeTerms, nHeightForCalculatingTotalSupply);

    CAmount nReq = poc::GetMiningRequireBalance(accountID, bindData, nTargetHeight, view, nullptr, nullptr, nBurned,
                                                params, &nMinedCount, &nTotalCount, nHeightForCalculatingTotalSupply);
    CAmount nAccumulate = GetBlockAccumulateSubsidy(pindex, params);
    CAmount nTotalSupplied = GetTotalSupplyBeforeHeight(nHeightForCalculatingTotalSupply, params) +
                             GetTotalSupplyBeforeBHDIP009(params) * (params.BHDIP009TotalAmountUpgradeMultiply - 1);

    UniValue summary(UniValue::VOBJ);
    summary.pushKV("address", address);
    summary.pushKV("require", nReq);
    summary.pushKV("mined", nMinedCount);
    summary.pushKV("count", nTotalCount);
    summary.pushKV("burned", nBurned);
    summary.pushKV("accumulate", nAccumulate);
    summary.pushKV("supplied", nTotalSupplied);
    summary.pushKV("height", nTargetHeight);
    summary.pushKV("calc-height", nHeightForCalculatingTotalSupply);

    // Retrieve all public-key which are binding with this account
    UniValue pklist(UniValue::VARR);
    auto fpks = view.GetAccountBindPlotters(accountID, CPlotterBindData::Type::CHIA);
    for (auto const& fpk : fpks) {
        pklist.push_back(fpk.GetChiaFarmerPk().ToString());
    }

    // List mined blocks which are related to this account
    UniValue blks(UniValue::VARR);
    auto pcurrIndex = pindex;
    int count{0}, mined{0};
    while (pcurrIndex && pcurrIndex->nHeight >= params.BHDIP009Height && count < params.nCapacityEvalWindow) {
        // check fpk from the block
        for (auto const& fpk : fpks) {
            if (fpk.GetChiaFarmerPk().ToBytes() == pcurrIndex->chiaposFields.posProof.vchFarmerPk) {
                // Now we export the block to UniValue and push it to array
                UniValue blkVal(UniValue::VOBJ);
                auto dest = CTxDestination(static_cast<ScriptHash>(pcurrIndex->generatorAccountID));
                std::string accountIDStr = EncodeDestination(dest);
                blkVal.pushKV("height", pcurrIndex->nHeight);
                blkVal.pushKV("hash", pcurrIndex->GetBlockHash().GetHex());
                blkVal.pushKV("fpk", chiapos::BytesToHex(pcurrIndex->chiaposFields.posProof.vchFarmerPk));
                blkVal.pushKV("accountID", accountIDStr);
                blks.push_back(blkVal);
                break;
            }
        }
        // next
        pcurrIndex = pcurrIndex->pprev;
        ++count;
    }

    UniValue res(UniValue::VOBJ);
    res.pushKV("summary", summary);
    res.pushKV("fpks", pklist);
    res.pushKV("mined", blks);
    return res;
}

static UniValue queryChainVdfInfo(JSONRPCRequest const& request) {
    RPCHelpMan("querychainvdfinfo", "Query vdf speed and etc from current block chain",
               {{"height", RPCArg::Type::NUM, RPCArg::Optional::NO,
                 "The summary information will be calculated from this height"}},
               RPCResult("\"{json}\" the basic information of the vdf from block chain"),
               RPCExamples(HelpExampleCli("querychainvdfinfo", "200000")))
            .Check(request);

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
                   {"count", RPCArg::Type::NUM, RPCArg::Optional::NO, "how many logs want to be generated"},
                   {"vdf_match_req", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "only show those vdf match the requires"},
               },
               RPCResult{"\"succ\" (result) The update tips history"},
               RPCExamples{HelpExampleCli("queryupdatetiphistory", "")})
            .Check(request);

    int nCount = atoi(request.params[0].get_str());
    bool fOnlyVdfMatches {false};
    if (request.params.size() > 1) {
        int val;
        if (!ParseInt32(request.params[1].get_str(), &val)) {
            throw std::runtime_error("cannot parse integer from parameter[1]");
        }
        fOnlyVdfMatches = val != 0;
    }

    auto params = Params().GetConsensus();

    LOCK(cs_main);
    auto pindex = ::ChainActive().Tip();
    UpdateTipLogHelper helper(pindex, Params());
    UniValue tips(UniValue::VARR);

    int nTotal { 0 };
    for (int i = 0; i < nCount; ++i) {
        UniValue entryVal = helper.PrintJson();
        if (fOnlyVdfMatches && entryVal["vdf-req-match"].get_str() == "false") {
            if (!helper.MoveToPrevIndex()) {
                break;
            }
            continue;
        }
        ++nTotal;
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
                        minerVal.pushKV("reward", ValueFromAmount(tx->vout[0].nValue));
                        // accumulate
                        CAmount nAccumulate = GetBlockAccumulateSubsidy(pindex, params);
                        minerVal.pushKV("accumulate", ValueFromAmount(nAccumulate));
                        // save to entry
                        txVal.push_back(minerVal);
                    } else {
                        auto payload = ExtractTransactionDatacarrier(
                                *tx, pindex->nHeight,
                                {DATACARRIER_TYPE_BINDPLOTTER, DATACARRIER_TYPE_BINDCHIAFARMER,
                                 DATACARRIER_TYPE_CHIA_POINT, DATACARRIER_TYPE_CHIA_POINT_TERM_1,
                                 DATACARRIER_TYPE_CHIA_POINT_TERM_2, DATACARRIER_TYPE_CHIA_POINT_TERM_3,
                                 DATACARRIER_TYPE_CHIA_POINT_RETARGET});
                        if (payload) {
                            UniValue payloadVal(UniValue::VOBJ);
                            if (payload->type == DATACARRIER_TYPE_BINDPLOTTER ||
                                payload->type == DATACARRIER_TYPE_BINDCHIAFARMER) {
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
                                payloadVal.pushKV("amount", ValueFromAmount(tx->vout[0].nValue));
                                payloadVal.pushKV(
                                        "address",
                                        EncodeDestination(CTxDestination(static_cast<ScriptHash>(p->GetReceiverID()))));
                            } else if (payload->type == DATACARRIER_TYPE_CHIA_POINT_RETARGET) {
                                auto p = PointRetargetPayload::As(payload);
                                payloadVal.pushKV("action", "retarget");
                                payloadVal.pushKV("amount", ValueFromAmount(tx->vout[0].nValue));
                                payloadVal.pushKV(
                                        "address",
                                        EncodeDestination(CTxDestination(static_cast<ScriptHash>(p->GetReceiverID()))));
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
        tips.push_back(entryVal);
        // next
        if (!helper.MoveToPrevIndex()) {
            break;
        }
    }

    UniValue res(UniValue::VOBJ);
    res.pushKV("tips", tips);
    res.pushKV("total", nTotal);

    return res;
}

static UniValue querySupply(JSONRPCRequest const& request) {
    RPCHelpMan("querysupply", "Query distributed amount, burned amount from the height",
               {{"height", RPCArg::Type::NUM, RPCArg::Optional::NO, "The height to calculate the amounts"}},
               RPCResult{"\"succ\" (result) The result of the amounts"},
               RPCExamples{HelpExampleCli("querysupply", "200000")})
            .Check(request);

    LOCK(cs_main);

    // calculate from last height
    auto pindex = ::ChainActive().Tip();
    int nLastHeight = pindex->nHeight;

    int nRequestedHeight = atoi(request.params[0].get_str());
    if (nRequestedHeight == 0) {
        nRequestedHeight = nLastHeight;
    }

    auto const& params = Params().GetConsensus();

    // calculate from the calculation height
    int nHeightForCalculatingTotalSupply = GetHeightForCalculatingTotalSupply(nRequestedHeight, params);
    CCoinsViewCache const& view = ::ChainstateActive().CoinsTip();

    CAmount nBurned = view.GetAccountBalance(false, GetBurnToAccountID(), nullptr, nullptr, nullptr,
                                             &params.BHDIP009PledgeTerms, nHeightForCalculatingTotalSupply);
    CAmount nTotalSupplied = GetTotalSupplyBeforeHeight(nHeightForCalculatingTotalSupply, params) +
                             GetTotalSupplyBeforeBHDIP009(params) * (params.BHDIP009TotalAmountUpgradeMultiply - 1);
    CAmount nActualAmount = nTotalSupplied - nBurned;

    UniValue calcValue(UniValue::VOBJ);
    calcValue.pushKV("request_height", nRequestedHeight);
    calcValue.pushKV("calc_height", nHeightForCalculatingTotalSupply);
    calcValue.pushKV("total_supplied", ValueFromAmount(nTotalSupplied));
    calcValue.pushKV("burned", ValueFromAmount(nBurned));
    calcValue.pushKV("actual_supplied", ValueFromAmount(nActualAmount));

    CAmount nLastBurned = view.GetAccountBalance(false, GetBurnToAccountID(), nullptr, nullptr, nullptr,
                                                 &params.BHDIP009PledgeTerms, nLastHeight);
    CAmount nLastTotalSupplied = GetTotalSupplyBeforeHeight(nLastHeight, params) +
                                 GetTotalSupplyBeforeBHDIP009(params) * (params.BHDIP009TotalAmountUpgradeMultiply - 1);
    CAmount nLastActualAmount = nLastTotalSupplied - nLastBurned;

    UniValue lastValue(UniValue::VOBJ);
    lastValue.pushKV("last_height", nLastHeight);
    lastValue.pushKV("total_supplied", ValueFromAmount(nLastTotalSupplied));
    lastValue.pushKV("burned", ValueFromAmount(nLastBurned));
    lastValue.pushKV("actual_supplied", ValueFromAmount(nLastActualAmount));

    UniValue resValue(UniValue::VOBJ);
    resValue.pushKV("dist_height", params.BHDIP009CalculateDistributedAmountEveryHeights);
    resValue.pushKV("calc", calcValue);
    resValue.pushKV("last", lastValue);

    return resValue;
}

static UniValue queryPledgeInfo(JSONRPCRequest const& request) {
    auto const& params = Params().GetConsensus();

    UniValue resValue(UniValue::VOBJ);
    resValue.pushKV("retarget_min_heights", params.BHDIP009PledgeRetargetMinHeights);
    resValue.pushKV("capacity_eval_window", params.nCapacityEvalWindow);

    UniValue termsValue(UniValue::VARR);
    for (int i = 0; i < params.BHDIP009PledgeTerms.size(); ++i) {
        auto const& term = params.BHDIP009PledgeTerms[i];
        UniValue termValue(UniValue::VOBJ);
        termValue.pushKV("lock_height", term.nLockHeight);
        termValue.pushKV("actual_percent", term.nWeightPercent);
        termsValue.push_back(std::move(termValue));
    }
    resValue.pushKV("terms", termsValue);

    return resValue;
}

static UniValue dumpBurstCheckpoints(JSONRPCRequest const& request) {
    RPCHelpMan("dumpburstcheckpoints", "Dump checkpoints for burst blocks", {
        {"from_height", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "From this number of heights"}
    }, RPCResult("\"hash list\""), RPCExamples(HelpExampleCli("dumpburstcheckpoints", "xxx"))).Check(request);

    const int GAP_NUM = 2000;
    int nFromHeight = 310000;
    if (!request.params[0].isNull()) {
        nFromHeight = request.params[0].get_int();
    }

    LOCK(cs_main);
    auto const& params = Params().GetConsensus();
    UniValue res(UniValue::VARR);

    for (int nCurrHeight = nFromHeight; nCurrHeight < params.BHDIP009Height; nCurrHeight += GAP_NUM) {
        auto pindex = ::ChainActive()[nCurrHeight];
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("height", nCurrHeight);
        entry.pushKV("hash", pindex->GetBlockHash().GetHex());
        res.push_back(std::move(entry));
    }

    return res;
}

NODISCARD static UniValue dumpPosProof(CPosProof const& posProof, CVdfProof const& vdfProof, int nHeight) {
    UniValue res(UniValue::VOBJ);
    res.pushKV("height", nHeight);

    UniValue posVal(UniValue::VOBJ);
    posVal.pushKV("challenge", posProof.challenge.GetHex());
    posVal.pushKV("poolpk_puzzlehash", BytesToHex(posProof.vchPoolPkOrHash));
    posVal.pushKV("localpk", BytesToHex(posProof.vchLocalPk));
    posVal.pushKV("farmerpk", BytesToHex(posProof.vchFarmerPk));
    posVal.pushKV("plot_type", posProof.nPlotType);
    posVal.pushKV("plot_k", posProof.nPlotK);
    posVal.pushKV("proof", BytesToHex(posProof.vchProof));
    res.pushKV("pos", posVal);

    UniValue vdfVal(UniValue::VOBJ);
    vdfVal.pushKV("challenge", vdfProof.challenge.GetHex());
    vdfVal.pushKV("y", BytesToHex(vdfProof.vchY));
    vdfVal.pushKV("proof", BytesToHex(vdfProof.vchProof));
    vdfVal.pushKV("witness_type", vdfProof.nWitnessType);
    vdfVal.pushKV("iters", vdfProof.nVdfIters);
    vdfVal.pushKV("duration", vdfProof.nVdfDuration);
    res.pushKV("vdf", vdfVal);

    return res;
}

static UniValue dumpPosProofs(JSONRPCRequest const& request) {
    RPCHelpMan("dumpposproof", "Dump pos proofs", {
        {"count", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "how many blocks are wanted"}
    }, RPCResult("\"result\", the pos list in json array"), RPCExamples(HelpExampleCli("dumpposproof", "n"))).Check(request);

    LOCK(cs_main);
    auto pindex = ::ChainActive().Tip();

    auto const& params = Params().GetConsensus();
    int nNumBlocks = pindex->nHeight - params.BHDIP009Height + 1;

    if (request.params.size() == 1 && !ParseInt32("count", &nNumBlocks)) {
        throw std::runtime_error("cannot parse parameter `count`");
    }

    UniValue res(UniValue::VARR);
    for (int i = 0; i < nNumBlocks; ++i) {
        UniValue proofVal = dumpPosProof(pindex->chiaposFields.posProof, pindex->chiaposFields.vdfProof, pindex->nHeight);
        res.push_back(std::move(proofVal));
        pindex = pindex->pprev;
        if (pindex == nullptr) {
            break;
        }
    }
    return res;
}

struct PledgeTx {
    uint256 blockHash;
    int nHeight;
    uint256 txHash;
    CAccountID sender;
    CAccountID receiver;
    CAmount nReceivedAmount;
    CAmount nActualAmount;
    DatacarrierType pledgeType;
    DatacarrierType pointType;
    int nPointHeight;
    int nExpiresOnHeight;
    bool fAvailable;
    bool fInTerm;
};

using PledgeTxSet = std::map<uint256, PledgeTx>;

std::string GetStrFromAccountID(CAccountID const& accountID) {
    CTxDestination dest((ScriptHash)accountID);
    return EncodeDestination(dest);
}

UniValue ConvertPledgeTxToUniValue(PledgeTx const& pledgeTx) {
    UniValue resVal(UniValue::VOBJ);
    resVal.pushKV("blockHash", pledgeTx.blockHash.GetHex());
    resVal.pushKV("height", pledgeTx.nHeight);
    resVal.pushKV("txHash", pledgeTx.txHash.GetHex());
    resVal.pushKV("sender", GetStrFromAccountID(pledgeTx.sender));
    resVal.pushKV("receiver", GetStrFromAccountID(pledgeTx.receiver));
    resVal.pushKV("receivedAmount", ValueFromAmount(pledgeTx.nReceivedAmount));
    resVal.pushKV("actualAmount", ValueFromAmount(pledgeTx.nActualAmount));
    resVal.pushKV("type", DatacarrierTypeToString(pledgeTx.pledgeType));
    resVal.pushKV("pointType", DatacarrierTypeToString(pledgeTx.pointType));
    resVal.pushKV("pointHeight", pledgeTx.nPointHeight);
    resVal.pushKV("expiresOnHeight", pledgeTx.nExpiresOnHeight);
    resVal.pushKV("available", pledgeTx.fAvailable);
    resVal.pushKV("inTerm", pledgeTx.fInTerm);
    return resVal;
}

bool IsPledgeTx(PledgeTxSet const& txs, uint256 const& txHash) {
    return txs.find(txHash) != std::cend(txs);
}

void MarkPledgeToUnavailable(PledgeTxSet& txs, uint256 const& txHashToMark, uint256 const& txHashCurr) {
    auto it = txs.find(txHashToMark);
    if (it == std::cend(txs)) {
        // cannot find the prevous tx, throw error
        throw std::runtime_error(tinyformat::format("previous tx(%s) cannot be found from retarget tx(%s)", txHashToMark.GetHex(), txHashCurr.GetHex()));
    }
    it->second.fAvailable = false;
}

bool GetPledgeTx(PledgeTxSet const& txs, uint256 const& txHash, PledgeTx& outPledgeTx) {
    auto it = txs.find(txHash);
    if (it == std::cend(txs)) {
        return false;
    }
    outPledgeTx = it->second;
    return true;
}

static void StripPledgeTx(PledgeTxSet& pledgeTxs, CBlock const& block, int nHeight, Consensus::Params const& params) {
    for (auto const& tx : block.vtx) {
        if (tx->IsCoinBase() || !tx->IsUniform()) {
            continue;
        }
        // TODO check if the type of the tx is a withdraw then mark it to unavailable
        auto ppayload = ExtractTransactionDatacarrier(*tx, nHeight, {DATACARRIER_TYPE_BINDCHIAFARMER, DATACARRIER_TYPE_CHIA_POINT, DATACARRIER_TYPE_CHIA_POINT_TERM_1, DATACARRIER_TYPE_CHIA_POINT_TERM_2, DATACARRIER_TYPE_CHIA_POINT_TERM_3, DATACARRIER_TYPE_CHIA_POINT_RETARGET});
        if (ppayload == nullptr) {
            if (IsPledgeTx(pledgeTxs, tx->vin[0].prevout.hash)) {
                MarkPledgeToUnavailable(pledgeTxs, tx->vin[0].prevout.hash, tx->GetHash());
            }
        } else {
            assert(tx->vout.size() >= 2);
            PledgeTx pledgeTx;
            pledgeTx.blockHash = block.GetHash();
            pledgeTx.nHeight = nHeight;
            pledgeTx.txHash = tx->GetHash();
            // account IDs
            pledgeTx.sender = ExtractAccountID(tx->vout[0].scriptPubKey);
            pledgeTx.pledgeType = ppayload->type;
            pledgeTx.fAvailable = true;
            if (ppayload->type == DATACARRIER_TYPE_BINDCHIAFARMER) {
                pledgeTx.receiver = pledgeTx.sender;
                pledgeTx.nReceivedAmount = tx->vout[0].nValue;
                pledgeTx.nActualAmount = 0;
                pledgeTx.pointType = DATACARRIER_TYPE_BINDCHIAFARMER;
                pledgeTx.nPointHeight = 0;
                pledgeTx.nExpiresOnHeight = 99999999;
                pledgeTx.fInTerm = false;
            } else {
                if (ppayload->type == DATACARRIER_TYPE_CHIA_POINT_RETARGET) {
                    // TODO find the previous tx and mark it to unavailable
                    auto retargetPayload = PointRetargetPayload::As(ppayload);
                    pledgeTx.pointType = retargetPayload->GetPointType();
                    pledgeTx.nPointHeight = retargetPayload->nPointHeight;
                    auto txHash = tx->vin[0].prevout.hash;
                    PledgeTx originalPledgeTx;
                    if (!GetPledgeTx(pledgeTxs, txHash, originalPledgeTx)) {
                        throw std::runtime_error(tinyformat::format("cannot find original pledge-tx(%s)", txHash.GetHex()));
                    }
                    pledgeTx.nReceivedAmount = originalPledgeTx.nReceivedAmount;
                    MarkPledgeToUnavailable(pledgeTxs, txHash, tx->GetHash());
                } else {
                    // point
                    auto pointPayload = PointPayload::As(ppayload);
                    pledgeTx.receiver = pointPayload->GetReceiverID();
                    pledgeTx.nReceivedAmount = tx->vout[0].nValue;
                    pledgeTx.pointType = pledgeTx.pledgeType;
                    pledgeTx.nPointHeight = nHeight;
                }
                // check if it's state is in-term
                int nTermIndex = pledgeTx.pointType - DATACARRIER_TYPE_CHIA_POINT;
                auto const& term = params.BHDIP009PledgeTerms[nTermIndex];
                int nExpiresOnHeight = pledgeTx.nPointHeight + term.nLockHeight;
                pledgeTx.fInTerm = nHeight < nExpiresOnHeight;
                if (pledgeTx.fInTerm) {
                    pledgeTx.nActualAmount = term.nWeightPercent * pledgeTx.nReceivedAmount / 100;
                } else {
                    pledgeTx.nActualAmount = params.BHDIP009PledgeTerms[0].nWeightPercent * pledgeTx.nReceivedAmount / 100;
                }
                pledgeTx.nExpiresOnHeight = nExpiresOnHeight;
            }
            // save
            pledgeTxs[pledgeTx.txHash] = std::move(pledgeTx);
        }
    }
}

struct Amounts {
    CAmount received;
    CAmount actual;
};

static UniValue queryChainPledgeInfo(JSONRPCRequest const& request) {
    auto params = ::Params().GetConsensus();
    LOCK(cs_main);

    PledgeTxSet pledgeTxs;
    for (int nHeight = params.BHDIP009Height; nHeight < ::ChainActive().Height(); ++nHeight) {
        auto pindex = ::ChainActive()[nHeight];
        CBlock block;
        if (!ReadBlockFromDisk(block, pindex, params)) {
            throw std::runtime_error(tinyformat::format("cannot read block(%s) from disk", pindex->GetBlockHash().GetHex()));
        }
        StripPledgeTx(pledgeTxs, block, nHeight, params);
    }

    std::map<CAccountID, Amounts> accountIDAmount;

    UniValue txsVal(UniValue::VARR);
    CAmount nTotalPledge{0}, nActualPledge{0};
    for (auto const& pledgeTx : pledgeTxs) {
        txsVal.push_back(ConvertPledgeTxToUniValue(pledgeTx.second));
        if (pledgeTx.second.fAvailable) {
            nTotalPledge += pledgeTx.second.nReceivedAmount;
            nActualPledge += pledgeTx.second.nActualAmount;
            CAccountID receiver = pledgeTx.second.receiver;
            auto it = accountIDAmount.find(receiver);
            if (it == std::cend(accountIDAmount)) {
                // new
                accountIDAmount.insert(std::make_pair(receiver, Amounts{ pledgeTx.second.nReceivedAmount, pledgeTx.second.nActualAmount }));
            } else {
                auto& amounts = accountIDAmount[receiver];
                amounts.received += pledgeTx.second.nReceivedAmount;
                amounts.actual += pledgeTx.second.nActualAmount;
            }
        }
    }

    UniValue receiverVal(UniValue::VOBJ);
    for (auto const& receiverAmount: accountIDAmount) {
        UniValue amountsVal(UniValue::VOBJ);
        amountsVal.pushKV("received", ValueFromAmount(receiverAmount.second.received));
        amountsVal.pushKV("actual", ValueFromAmount(receiverAmount.second.actual));
        receiverVal.pushKV(GetStrFromAccountID(receiverAmount.first), amountsVal);
    }

    UniValue resVal(UniValue::VOBJ);

    UniValue summaryVal(UniValue::VOBJ);
    summaryVal.pushKV("total", ValueFromAmount(nTotalPledge));
    summaryVal.pushKV("actual", ValueFromAmount(nActualPledge));

    resVal.pushKV("summary", summaryVal);
    resVal.pushKV("receiver", receiverVal);
    resVal.pushKV("txs", txsVal);
    return resVal;
}

CTransaction create_burn_txouts_transaction(std::vector<COutPoint> const& outpoints, int nSpendHeight, CAmount& nOutValue)
{
    CMutableTransaction mtx;
    auto const& coinsView = ::ChainstateActive().CoinsTip();

    CAmount nTotalAmount { 0 };
    for (auto const& outpoint : outpoints) {
        Coin coin;
        if (!coinsView.GetCoin(outpoint, coin)) {
            throw std::runtime_error(tinyformat::format("cannot find the coin (%s, %d)", outpoint.hash.GetHex(), outpoint.n));
        }
        if (coin.IsSpent()) {
            throw std::runtime_error(tinyformat::format("the coin (%s, %d) has already spent", outpoint.hash.GetHex(), outpoint.n));
        }
        mtx.vin.push_back(CTxIn{ outpoint, CScript(), CTxIn::SEQUENCE_FINAL });
        nTotalAmount += coin.out.nValue;
    }

    // Make transaction to burn the txout
    std::vector<std::string> errors;
    CAmount nTxFee { static_cast<CAmount>(0.01 * COIN) };

    auto destBurn = GetBurnToDestination();
    auto scriptBurn = GetScriptForDestination(destBurn);
    auto nBurnAmount = nTotalAmount - nTxFee;
    mtx.vout.push_back(CTxOut(nBurnAmount, scriptBurn));

    nOutValue = nBurnAmount;
    return CTransaction(mtx);
}

std::tuple<uint256, CAmount> create_and_broadcast_burn_tx(int nSpendHeight, std::vector<COutPoint> const& outpoints, CAmount nMaxFee)
{
    std::string strErrorReason;
    CAmount value;
    auto tx = create_burn_txouts_transaction(outpoints, nSpendHeight, value);
    auto ptx = std::make_shared<CTransaction>(tx);
    auto txError = BroadcastTransaction(ptx, strErrorReason, nMaxFee, true, false);
    if (txError != TransactionError::OK) {
        std::stringstream strs;
        std::string strBroadcastError = TransactionErrorString(txError);
        strs << "err: " << strBroadcastError << ", reason: " << (strErrorReason.empty() ? "no reason" : strErrorReason) << ", txid: " << tx.GetHash().GetHex();
        throw std::runtime_error(strs.str());
    }
    return std::make_tuple(ptx->GetHash(), value);
}

UniValue burntxout(JSONRPCRequest const& request)
{
    constexpr auto nMaxFee = static_cast<CAmount>(0.01 * COIN);

    LOCK(cs_main);
    int nSpendHeight = ::ChainActive().Height();

    // txout: txid, n
    if (request.params.size() != 2) {
        throw std::runtime_error("invalid number of parameters, the number should be 2 with (txid, n)");
    }

    std::string strFilePath = request.params[0].get_str();
    if (fs::exists(strFilePath) && fs::is_regular_file(strFilePath)) {
        int32_t nMaxTxIns { 0 };
        if (!ParseInt32(request.params[1].get_str(), &nMaxTxIns)) {
            throw std::runtime_error("cannot parse int from argument 2 (max number of txins)");
        }
        // txins should be loaded from json file
        std::ifstream inf(strFilePath);
        if (!inf.is_open()) {
            throw std::runtime_error("cannot open file to read");
        }
        std::string strContent;
        std::copy(std::istream_iterator<char>(inf), std::istream_iterator<char>(), std::back_inserter(strContent));
        UniValue valTxOutsFromFile;
        valTxOutsFromFile.read(strContent);
        std::vector<UniValue> vWrongTxOuts;
        std::map<uint256, CAmount> mSentTxWithAmount;
        std::vector<COutPoint> outpoints;
        // parsed txouts, now read each of the txouts and put them to transaction
        for (auto const& valTxOutFromFile : valTxOutsFromFile.getValues()) {
            if (!valTxOutFromFile.exists("txid")) {
                vWrongTxOuts.push_back(valTxOutFromFile);
                continue;
            }
            if (!valTxOutFromFile.exists("n")) {
                vWrongTxOuts.push_back(valTxOutFromFile);
                continue;
            }
            if (!valTxOutFromFile.exists("value")) {
                vWrongTxOuts.push_back(valTxOutFromFile);
                continue;
            }
            uint256 txid;
            try {
                txid = ParseHashV(valTxOutFromFile["txid"], "txid");
            } catch (std::exception const&) {
                vWrongTxOuts.push_back(valTxOutFromFile);
                continue;
            }
            int32_t n;
            if (!ParseInt32(valTxOutFromFile["n"].get_str(), &n)) {
                vWrongTxOuts.push_back(valTxOutFromFile);
                continue;
            }
            CAmount nValueFromTxOut;
            if (!ParseInt64(valTxOutFromFile["value"].get_str(), &nValueFromTxOut)) {
                vWrongTxOuts.push_back(valTxOutFromFile);
                continue;
            }
            if (nValueFromTxOut > 0) {
                outpoints.emplace_back(txid, n);
                if (outpoints.size() >= nMaxTxIns) {
                    // create transaction and broadcast it to P2P network
                    uint256 txid;
                    CAmount nTotalBurn;
                    std::tie(txid, nTotalBurn) = create_and_broadcast_burn_tx(nSpendHeight, outpoints, nMaxFee);
                    mSentTxWithAmount.insert(std::make_pair(txid, nTotalBurn));
                    outpoints.clear();
                }
            }
        }
        if (!outpoints.empty()) {
            uint256 txid;
            CAmount nTotalBurn;
            std::tie(txid, nTotalBurn) = create_and_broadcast_burn_tx(nSpendHeight, outpoints, nMaxFee);
            mSentTxWithAmount.insert(std::make_pair(txid, nTotalBurn));
        }
        // create outputs
        UniValue valResult(UniValue::VOBJ);
        // wrong txouts
        UniValue valWrongTxOuts(UniValue::VARR);
        for (auto const& txout_val : vWrongTxOuts) {
            valWrongTxOuts.push_back(txout_val);
        }
        valResult.pushKV("wrongTxOuts", valWrongTxOuts);
        // committed transactions
        UniValue valSentTxIDWithAmount(UniValue::VOBJ);
        for (auto const& pairTxIDAmount : mSentTxWithAmount) {
            UniValue obj(UniValue::VOBJ);
            obj.pushKV("txid", pairTxIDAmount.first.GetHex());
            obj.pushKV("value", pairTxIDAmount.second);
            valSentTxIDWithAmount.push_back(obj);
        }
        valResult.pushKV("commitTx", valSentTxIDWithAmount);
        return valResult;
    }

    uint256 txid = ParseHashV(request.params[0], "txid");
    int32_t n;
    if (!ParseInt32(request.params[1].get_str(), &n)) {
        throw std::runtime_error("cannot convert argument 2 into integer value");
    }
    uint256 retTxid;
    CAmount nTotalBurn;
    std::tie(retTxid, nTotalBurn) = create_and_broadcast_burn_tx(nSpendHeight, { {txid, static_cast<uint32_t>(n)} }, nMaxFee);

    return retTxid.GetHex();
}

static CRPCCommand const commands[] = {
        {"chia", "checkchiapos", &checkChiapos, {}},
        {"chia", "querychallenge", &queryChallenge, {}},
        {"chia", "querynetspace", &queryNetspace, {}},
        {"chia", "querychainvdfinfo", &queryChainVdfInfo, {"height"}},
        {"chia", "queryminingrequirement", &queryMiningRequirement, {"address", "farmer-pk"}},
        {"chia", "submitproof", &submitProof, {"challenge", "quality_string", "pos_proof", "k", "pool_pk", "local_pk", "farmer_pk", "farmer_sk", "plot_id", "vdf_proof_vec", "reward_dest"}},
        {"chia", "generateburstblocks", &generateBurstBlocks, {"count"}},
        {"chia", "queryupdatetiphistory", &queryUpdateTipHistory, {"count"}},
        {"chia", "querysupply", &querySupply, {"height"}},
        {"chia", "querypledgeinfo", &queryPledgeInfo, {}},
        {"chia", "dumpburstcheckpoints", &dumpBurstCheckpoints, {}},
        {"chia", "submitvdfrequest", &submitVdfRequest, {"challenge", "iters"}},
        {"chia", "submitvdfproof", &submitVdfProof, {"challenge", "y", "proof", "witness_type", "iters", "duration"}},
        {"chia", "dumpposproofs", &dumpPosProofs, {"count"}},
        {"chia", "querychainpledgeinfo", &queryChainPledgeInfo, {}},
        {"chia", "burntxout", &burntxout, {"txid","n"} },
};

void RegisterChiaRPCCommands(CRPCTable& t) {
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++) {
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
    }
}

}  // namespace chiapos
