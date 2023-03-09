#include <chainparams.h>
#include <key_io.h>
#include <miner.h>
#include <net.h>
#include <netmessagemaker.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <util/strencodings.h>
#include <validation.h>

#include <cstdint>
#include <stdexcept>

#include "chiapos/kernel/bls_key.h"
#include "chiapos/kernel/calc_diff.h"
#include "chiapos/kernel/pos.h"
#include "chiapos/kernel/utils.h"
#include "consensus/params.h"
#include "logging.h"
#include "post.h"

#include "newblock_watcher.hpp"

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
    if (nTargetHeight == params.BHDIP009Height) {
        Bytes initialVdfProof(100, 0);
        res.pushKV("challenge", MakeChallenge(pindexPrev->GetBlockHash(), initialVdfProof).GetHex());
        res.pushKV("difficulty", params.BHDIP009StartDifficulty);
        res.pushKV("prev_vdf_iters", params.BHDIP009StartBlockIters);
        res.pushKV("prev_vdf_duration", params.BHDIP008TargetSpacing);
    } else {
        // We need to read the challenge from last block
        uint256 challenge = MakeChallenge(pindexPrev->GetBlockHash(), pindexPrev->chiaposFields.vdfProof.vchProof);
        res.pushKV("challenge", challenge.GetHex());
        res.pushKV("difficulty", pindexPrev->chiaposFields.nDifficulty);
        res.pushKV("prev_vdf_iters", pindexPrev->chiaposFields.vdfProof.nVdfIters);
        res.pushKV("prev_vdf_duration", pindexPrev->chiaposFields.vdfProof.nVdfDuration);
    }
    res.pushKV("prev_block_hash", pindexPrev->GetBlockHash().GetHex());
    res.pushKV("prev_block_height", pindexPrev->nHeight);
    res.pushKV("target_height", nTargetHeight);
    res.pushKV("target_duration", params.BHDIP008TargetSpacing);
    if (nTargetHeight < params.BHDIP009PlotIdBitsOfFilterEnableOnHeight) {
        res.pushKV("filter_bits", 0);
    } else {
        res.pushKV("filter_bits", params.BHDIP009PlotIdBitsOfFilter);
    }
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
                       uint256 const& initialChallenge, chiapos::Bytes const& vchFarmerSk, uint64_t nQuality, CPosProof const& posProof,
                       CVdfProof const& vdfProof, std::vector<CVdfProof> const& vVoidBlock) {
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
            LogPrintf("%s: the chain has been changed since last challenge\n", __func__);
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
            uint64_t quality = CalculateQuality(posProof);
            uint64_t quality_chain = CalculateQuality(pindexCurr->chiaposFields.posProof);
            if (quality < quality_chain) {
                // The quality is too low, and it will not be accepted by the chain
                LogPrintf("%s(drop proofs): the quality is lower than the existing block(quality=%s), skip our(quality=%s) block\n", __func__,
                        FormatNumberStr(std::to_string(quality_chain)), FormatNumberStr(std::to_string(quality)));
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
                pindexPrev, GetScriptForDestination(rewardDest), farmerSk, nQuality, posProof, vdfProof, vVoidBlock);
        if (ptemplate == nullptr) {
            throw std::runtime_error("cannot generate new block, the template object is null");
        }
        pblock.reset(new CBlock(ptemplate->block));
    }

    if (pblock == nullptr) {
        throw std::runtime_error("pblock is null, cannot release new block");
    }
    ReleaseBlock(pblock, params);

    LogPrintf("%s: Initial challenge: %s, generated new block and now is releasing...\n", __func__,
              initialChallenge.GetHex());

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
    posProof.vchFarmerPk = MakeBytes(farmerSk.GetPubkey());
    // VDF proof
    CVdfProof vdfProof = ParseVdfProof(request.params[5]);
    // Void blocks
    std::vector<CVdfProof> vVoidBlock;
    for (UniValue const& val : request.params[6].getValues()) {
        CVdfProof vdf = ParseVdfProof(val);
        vVoidBlock.push_back(std::move(vdf));
    }
    // Reward address
    std::string strRewardDest = request.params[7].get_str();
    CTxDestination rewardDest = DecodeDestination(strRewardDest);
    if (!IsValidDestination(rewardDest)) {
        throw std::runtime_error("The reward destination is invalid");
    }
    // Quality for the PoS
    uint64_t nQuality = request.params[8].get_int64();

    if (IsTheBestPos(posProof)) {
        // We should put it to the chain immediately
        LogPrintf("%s: The best proof (quality=%s) we have, now commit it to the chain.\n", __func__, chiapos::FormatNumberStr(std::to_string(nQuality)));
        GenerateChiaBlock(hashPrevBlock, nHeightOfPrevBlock, rewardDest, initialChallenge, vchFarmerSk, nQuality, posProof, vdfProof, vVoidBlock);
    } else {
        LogPrintf("%s: Our proof (quality=%s) isn't good enough, delaying the commit.\n", __func__, chiapos::FormatNumberStr(std::to_string(nQuality)));
        if (!IsBlockWatcherRunning()) {
            StartBlockWatcher();
        }
        GetBlockWatcher().WaitForBlock(10,
                std::bind(GenerateChiaBlock, hashPrevBlock, nHeightOfPrevBlock, rewardDest, initialChallenge, vchFarmerSk, nQuality, posProof, vdfProof, vVoidBlock),
                [hashPrevBlock]() -> bool {
                    LOCK(cs_main);
                    CBlockIndex* pindex = ::ChainActive().Tip();
                    return pindex && pindex->GetBlockHash() != hashPrevBlock;
                }
        );
    }

    return true;
}

static UniValue queryVdf(JSONRPCRequest const& request) {
    RPCHelpMan(
            "queryvdf", "Query Vdf proof that received from P2P network",
            {{"challenge", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The challenge of the vdf proof"},
             {"iters_limits", RPCArg::Type::NUM, RPCArg::Optional::NO, "The proof must reaches the number of iters"}},
            RPCResult{"\"result\" (object) The vdf proof result"}, RPCExamples{HelpExampleCli("queryvdf", "xxxxxx")})
            .Check(request);

    uint256 challenge = ParseHashV(request.params[0], "challenge");
    uint64_t nItersLimits = request.params[1].get_int64();

    optional<CVdfProof> proof = QueryReceivedVdfProofPacket(challenge);
    if (proof.has_value() && proof->nVdfIters >= nItersLimits) {
        UniValue result(UniValue::VOBJ);
        result.pushKV("challenge", proof->challenge.GetHex());
        result.pushKV("iters", proof->nVdfIters);
        result.pushKV("y", BytesToHex(proof->vchY));
        result.pushKV("proof", BytesToHex(proof->vchProof));
        result.pushKV("witness_type", proof->nWitnessType);
        result.pushKV("duration", static_cast<uint64_t>(proof->nVdfDuration));
        return result;
    }
    throw std::runtime_error("cannot find a valid vdf");
}

static UniValue queryNetspace(JSONRPCRequest const& request) {
    RPCHelpMan(
        "querynetspace", "Query current netspace",
        {},
        RPCResult{"\"result\" (uint64) The netspace in TB"},
        RPCExamples{HelpExampleCli("querynetspace", "")})
        .Check(request);

    LOCK(cs_main);

    auto params = Params().GetConsensus();
    auto pledgeParams = poc::CalculatePledgeParams(::ChainActive().Height(), params);

    CBlockIndex* pindex = ::ChainActive().Tip();
    auto netspace = poc::CalculateAverageNetworkSpace(pindex, params);
    auto netspaceTB = netspace / 1000 / 1000 / 1000 / 1000;

    UniValue res(UniValue::VOBJ);
    res.pushKV("netCapacityTB", pledgeParams.nNetCapacityTB);
    res.pushKV("calculatedOnHeight", pledgeParams.nCalcHeight);
    res.pushKV("supplied", pledgeParams.supplied / COIN);
    res.pushKV("netspace", chiapos::FormatNumberStr(std::to_string(netspace.GetLow64())));
    res.pushKV("netspace_TB", netspaceTB.getdouble());

    return res;
}

static UniValue requireVdf(JSONRPCRequest const& request) {
    RPCHelpMan("requirevdf", "Require a VDF proof",
               {{"challenge", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The challenge of the vdf proof"},
                {"iters", RPCArg::Type::NUM, RPCArg::Optional::NO, "The number of iters"}},
               RPCResult{"\"succ\" (bool) True means the proof has been accepted successfully"},
               RPCExamples{HelpExampleCli("requirevdf", "xxxxx,1000")})
            .Check(request);

    uint256 challenge = ParseHashV(request.params[0], "challenge");
    uint64_t nIters = request.params[1].get_int64();

    auto vdf = chiapos::QueryReceivedVdfProofPacket(challenge);
    if (vdf.has_value() && vdf->nVdfIters >= nIters) {
        LogPrintf("%s: the vdf proof has already found from current node, use `queryVdf' to retrieve it\n", __func__);
        return true;
    }

    if (chiapos::IsTimelordRunning()) {
        chiapos::UpdateChallengeToTimelord(challenge, nIters);
    }

    chiapos::SendRequireVdfOverP2PNetwork(g_connman.get(), challenge, nIters);
    return true;
}

static UniValue submitVdf(JSONRPCRequest const& request) {
    RPCHelpMan("submitvdf", "Submit a Vdf proof object to core",
               {
                       {"challenge", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The challenge of the vdf proof"},
                       {"y", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "form y"},
                       {"proof", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "proof"},
                       {"witness_type", RPCArg::Type::NUM, RPCArg::Optional::NO, "witness_type"},
                       {"iters", RPCArg::Type::NUM, RPCArg::Optional::NO, "number of iters for VDF proof"},
                       {"duration", RPCArg::Type::NUM, RPCArg::Optional::NO, "how many seconds the computing takes"},
               },
               RPCResult{"\"succ\" (bool) True means the proof has been accepted successfully"},
               RPCExamples{HelpExampleCli("submitvdf", "xxxx,xxxx,1000,xxxx,xxxx")})
            .Check(request);

    CVdfProof proof;
    proof.challenge = ParseHashV(request.params[0], "challenge");
    proof.vchY = ParseHexV(request.params[1], "y");
    proof.vchProof = ParseHexV(request.params[2], "proof");
    proof.nWitnessType = request.params[3].get_int();
    proof.nVdfIters = request.params[4].get_int64();
    proof.nVdfDuration = request.params[5].get_int64();
    SubmitVdfProofPacket(proof);

    // Send proof to P2P network
    SendVdfProofOverP2PNetwork(g_connman.get(), proof);

    return true;
}

static UniValue submitPos(JSONRPCRequest const& request) {
    RPCHelpMan("submitpos", "Submit a found pos to p2p network",
        {
            {"challenge", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the challenge for the proof"},
            {"pkhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the public key or hash depends the plot type"},
            {"localpk", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the local public key from plot file"},
            {"farmerpk", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the farmer public key generated from chia mnemonic"},
            {"plottype", RPCArg::Type::NUM, RPCArg::Optional::NO, "the type of the plot file"},
            {"plotk", RPCArg::Type::NUM, RPCArg::Optional::NO, "the size `k` of the plot file"},
            {"proof", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the pos proof"},
            {"groupHash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Group hash"},
            {"totalSize", RPCArg::Type::NUM, RPCArg::Optional::NO, "total size"},
        },
        RPCResult("\"succ\" (bool) True means the pos is accepted and will be published"),
        RPCExamples(HelpExampleCli("submitpos", "xxx"))
    ).Check(request);

    CPosProof pos;
    pos.challenge = ParseHashV(request.params[0], "challenge");
    pos.vchPoolPkOrHash = ParseHexV(request.params[1], "public-key or hash");
    pos.vchLocalPk = ParseHexV(request.params[2], "local public-key");
    pos.vchFarmerPk = ParseHexV(request.params[3], "farmer public-key");
    pos.nPlotType = request.params[4].get_int();
    pos.nPlotK = request.params[5].get_int();
    pos.vchProof = ParseHexV(request.params[6], "proof of space");

    uint256 groupHash = ParseHashV(request.params[7], "group hash");
    uint64_t nTotalSize = request.params[8].get_int64();

    LOCK(cs_main);
    int nTargetHeight = ::ChainActive().Height() + 1;
    CValidationState state;
    auto params = Params().GetConsensus();
    if (!chiapos::CheckPosProof(pos, state, params, nTargetHeight)) {
        throw std::runtime_error("invalid proof");
    }

    SavePosQuality(pos, groupHash, nTotalSize);
    SendPosPreviewOverP2PNetwork(g_connman.get(), pos, groupHash, nTotalSize);

    return true;
}

static UniValue queryMinerNetspace(JSONRPCRequest const& request) {
    RPCHelpMan(
            "queryminernetspace",
            "Query the netspace those are reported from miner",
            {},
            RPCResult("\"{json}\" The netspace from miner in json format"),
            RPCExamples(HelpExampleCli("queryminernetspace", ""))).Check(request);

    LOCK(cs_main);
    auto const& view = ::ChainstateActive().CoinsDB();
    uint64_t nNetSpace{0};
    auto minerGroups = QueryAllMinerGroups();
    UniValue res(UniValue::VOBJ);
    for (auto const& entry : minerGroups) {
        UniValue groupVal(UniValue::VOBJ);
        CPlotterBindData bindData(CChiaFarmerPk(entry.first));
        auto entries = view.GetBindPlotterEntries(bindData);
        // accounts
        UniValue accountsVal(UniValue::VARR);
        for (auto const& entry : entries) {
            std::string address_str = EncodeDestination((ScriptHash)entry.second.accountID);
            accountsVal.push_back(address_str);
        }
        groupVal.pushKV("accounts", accountsVal);
        // devices
        UniValue devicesVal(UniValue::VARR);
        uint64_t nTotalSize{0};
        for (auto const& group : entry.second) {
            if (MakeNumberTB(group.second) / 1000 < 100) {
                UniValue deviceEntryVal(UniValue::VOBJ);
                deviceEntryVal.pushKV("device", group.first.GetHex());
                deviceEntryVal.pushKV("sizeTB", MakeNumberStr(MakeNumberTB(group.second)));
                devicesVal.push_back(deviceEntryVal);
                nTotalSize += group.second;
            }
        }
        uint64_t nTotalSizeTB = MakeNumberTB(nTotalSize);
        nNetSpace += nTotalSize;
        groupVal.pushKV("sizeTB", MakeNumberStr(nTotalSizeTB));
        groupVal.pushKV("devices", devicesVal);
        res.pushKV(BytesToHex(entry.first), groupVal);
    }
    res.pushKV("netspace", MakeNumberStr(nNetSpace));
    uint64_t nNetspaceTB = MakeNumberTB(nNetSpace);
    res.pushKV("netspaceTB", MakeNumberStr(nNetspaceTB));

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

static CRPCCommand const commands[] = {
        {"chia", "checkchiapos", &checkChiapos, {}},
        {"chia", "querychallenge", &queryChallenge, {}},
        {"chia", "submitvdf", &submitVdf, {}},
        {"chia", "requirevdf", &requireVdf, {}},
        {"chia", "queryvdf", &queryVdf, {}},
        {"chia", "querynetspace", &queryNetspace, {}},
        {"chia", "queryminernetspace", &queryMinerNetspace, {}},
        {"chia", "submitpos", &submitPos, {}},
        {"chia",
         "submitproof",
         &submitProof,
         {"challenge", "quality_string", "pos_proof", "k", "pool_pk", "local_pk", "farmer_pk", "farmer_sk", "plot_id",
          "vdf_proof_vec", "reward_dest"}},
        {"chia", "generateburstblocks", &generateBurstBlocks, {}},
};

void RegisterChiaRPCCommands(CRPCTable& t) {
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++) {
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
    }
}

}  // namespace chiapos
