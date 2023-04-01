#include "rpc_client.h"

#include <chiapos/kernel/bls_key.h>
#include <chiapos/kernel/utils.h>

#include <fstream>
#include <iostream>

#include <chiapos/bhd_types.h>

namespace miner {

std::string DepositTermToString(DepositTerm term) {
    switch (term) {
        case DepositTerm::NoTerm:
            return "noterm";
        case DepositTerm::Term1:
            return "term1";
        case DepositTerm::Term2:
            return "term2";
        case DepositTerm::Term3:
            return "term3";
    }
    return "wrong_term_value";
}

DepositTerm DepositTermFromString(std::string const& str) {
    if (str == "noterm") {
        return DepositTerm::NoTerm;
    } else if (str == "term1") {
        return DepositTerm::Term1;
    } else if (str == "term2") {
        return DepositTerm::Term2;
    } else if (str == "term3") {
        return DepositTerm::Term3;
    }
    return DepositTerm::NoTerm;
}

RPCClient::RPCClient(bool no_proxy, std::string url, std::string const& cookie_path_str)
        : m_no_proxy(no_proxy), m_cookie_path_str(cookie_path_str), m_url(std::move(url)) {
    if (cookie_path_str.empty()) {
        throw std::runtime_error("cookie is empty, cannot connect to btchd core");
    }
    LoadCookie();
}

RPCClient::RPCClient(bool no_proxy, std::string url, std::string user, std::string passwd)
        : m_no_proxy(no_proxy), m_url(std::move(url)), m_user(std::move(user)), m_passwd(std::move(passwd)) {}

void RPCClient::LoadCookie() {
    fs::path cookie_path(m_cookie_path_str);
    std::ifstream cookie_reader(cookie_path.string());
    if (!cookie_reader.is_open()) {
        std::stringstream ss;
        ss << "cannot open to read " << cookie_path;
        throw std::runtime_error(ss.str());
    }
    std::string auth_str;
    std::getline(cookie_reader, auth_str);
    if (auth_str.empty()) {
        throw std::runtime_error("cannot read auth string from `.cookie`");
    }
    auto pos = auth_str.find_first_of(':');
    std::string user_str = auth_str.substr(0, pos);
    std::string passwd_str = auth_str.substr(pos + 1);
    m_user = std::move(user_str);
    m_passwd = std::move(passwd_str);
}

std::string const& RPCClient::GetCookiePath() const { return m_cookie_path_str; }

bool RPCClient::CheckChiapos() {
    auto res = SendMethod(m_no_proxy, "checkchiapos");
    return res.result.get_bool();
}

RPCClient::Challenge RPCClient::QueryChallenge() {
    auto res = SendMethod(m_no_proxy, "querychallenge");
    Challenge ch;
    ch.challenge = uint256S(res.result["challenge"].get_str());
    ch.difficulty = res.result["difficulty"].get_int64();
    ch.prev_block_hash = uint256S(res.result["prev_block_hash"].get_str());
    ch.prev_block_height = res.result["prev_block_height"].get_int();
    ch.prev_vdf_iters = res.result["prev_vdf_iters"].get_int64();
    ch.prev_vdf_duration = res.result["prev_vdf_duration"].get_int64();
    ch.target_height = res.result["target_height"].get_int();
    ch.target_duration = res.result["target_duration"].get_int64();
    ch.filter_bits = res.result["filter_bits"].get_int();
    ch.base_iters = res.result["base_iters"].get_int();
    return ch;
}

RPCClient::PledgeParams RPCClient::QueryNetspace() {
    auto res = SendMethod(m_no_proxy, "querynetspace");
    PledgeParams params;
    params.netCapacityTB = res.result["netCapacityTB"].get_int64();
    params.calculatedOnHeight = res.result["calculatedOnHeight"].get_int64();
    params.supplied = res.result["supplied"].get_int64();
    return params;
}

RPCClient::VdfProof RPCClient::QueryVdf(uint256 const& challenge, uint64_t iters_limits) {
    Result res = SendMethod(m_no_proxy, "queryvdf", challenge, iters_limits);
    VdfProof proof;
    proof.challenge = uint256S(res.result["challenge"].get_str());
    proof.iters = res.result["iters"].get_int64();
    proof.y = chiapos::MakeArray<chiapos::VDF_FORM_SIZE>(chiapos::BytesFromHex(res.result["y"].get_str()));
    proof.proof = chiapos::BytesFromHex(res.result["proof"].get_str());
    proof.witness_type = res.result["witness_type"].get_int();
    proof.duration = res.result["duration"].get_int();
    return proof;
}

bool RPCClient::RequireVdf(uint256 const& challenge, uint64_t iters) {
    Result res = SendMethod(m_no_proxy, "requirevdf", challenge, iters);
    return res.result.getBool();
}

bool RPCClient::SubmitVdf(VdfProof const& vdf) {
    Result res = SendMethod(m_no_proxy, "submitvdf", vdf.challenge, vdf.y, vdf.proof, vdf.witness_type, vdf.iters,
                            vdf.duration);
    return res.result.getBool();
}

void RPCClient::SubmitProof(ProofPack const& proof_pack) {
    SendMethod(m_no_proxy, "submitproof", proof_pack.prev_block_hash, proof_pack.prev_block_height,
               proof_pack.pos.challenge, proof_pack.pos, proof_pack.farmer_sk, proof_pack.vdf, proof_pack.reward_dest);
}

chiapos::Bytes RPCClient::BindPlotter(std::string const& address, chiapos::SecreKey const& farmerSk) {
    auto res = SendMethod(m_no_proxy, "bindchiaplotter", address, farmerSk);
    return chiapos::BytesFromHex(res.result.get_str());
}

std::vector<RPCClient::BindRecord> RPCClient::ListBindTxs(std::string const& address, int count, int skip,
                                                          bool include_watchonly, bool include_invalid) {
    auto res = SendMethod(m_no_proxy, "listbindplotters", count, skip, include_watchonly, include_invalid, address);
    if (!res.result.isArray()) {
        throw std::runtime_error("non-array value is received from core");
    }
    std::vector<BindRecord> records;
    for (auto const& entry : res.result.getValues()) {
        BindRecord rec;
        rec.tx_id = chiapos::BytesFromHex(entry["txid"].get_str());
        rec.address = entry["address"].get_str();
        rec.farmer_pk = entry["plotterId"].get_str();
        rec.block_hash = chiapos::BytesFromHex(entry["blockhash"].get_str());
        rec.block_height = entry["blockheight"].get_int();
        rec.active = entry["active"].get_bool();
        rec.valid = entry["valid"].getBool();
        records.push_back(std::move(rec));
    }
    return records;
}

chiapos::Bytes RPCClient::Deposit(std::string const& address, int amount, DepositTerm term) {
    auto res = SendMethod(m_no_proxy, "sendpledgetoaddress", address, amount, "no comment", "no comment", false, false,
                          1, "UNSET", DepositTermToString(term));
    return chiapos::BytesFromHex(res.result.get_str());
}

std::vector<RPCClient::PledgeRecord> RPCClient::ListDepositTxs(int count, int skip, bool include_watchonly,
                                                               bool include_invalid) {
    auto res = SendMethod(m_no_proxy, "listpledges", count, skip, include_watchonly, include_invalid);
    if (!res.result.isArray()) {
        throw std::runtime_error("non-array value is received from core");
    }
    std::vector<PledgeRecord> result;
    for (UniValue const& entry : res.result.getValues()) {
        PledgeRecord rec;
        rec.tx_id = chiapos::BytesFromHex(entry["txid"].get_str());
        rec.amount = entry["amount"].get_real();
        rec.revoked = entry["revoked"].get_bool();
        rec.valid = entry["valid"].get_bool();
        if (rec.valid) {
            rec.height = entry["blockheight"].get_int();
        }
        DatacarrierType payload_type = (DatacarrierType)entry["payloadType"].get_int();
        if (payload_type == DATACARRIER_TYPE_CHIA_POINT_RETARGET) {
            auto point_type = (DatacarrierType)entry["pointType"].get_int();
            rec.term = (DepositTerm)(point_type - DATACARRIER_TYPE_CHIA_POINT);
            rec.point_height = entry["pointHeight"].get_int();
            rec.retarget = true;
        } else {
            rec.term = (DepositTerm)(payload_type - DATACARRIER_TYPE_CHIA_POINT);
            rec.retarget = false;
            rec.point_height = rec.height;
        }
        rec.from = entry["from"].get_str();
        rec.to = entry["to"].get_str();
        result.push_back(std::move(rec));
    }
    return result;
}

chiapos::Bytes RPCClient::Withdraw(chiapos::Bytes const& tx_id) {
    auto res = SendMethod(m_no_proxy, "withdrawpledge", chiapos::BytesToHex(tx_id));
    return chiapos::BytesFromHex(res.result.get_str());
}

bool RPCClient::GenerateBurstBlocks(int count) {
    auto res = SendMethod(m_no_proxy, "generateburstblocks", count);
    return res.result.get_bool();
}

chiapos::Bytes RPCClient::RetargetPledge(chiapos::Bytes const& tx_id, std::string const& address) {
    auto res = SendMethod(m_no_proxy, "retargetpledge", tx_id, address);
    return chiapos::BytesFromHex(res.result.get_str());
}

RPCClient::MiningRequirement RPCClient::QueryMiningRequirement(std::string const& address,
                                                               chiapos::PubKey const& farmer_pk) {
    auto res = SendMethod(m_no_proxy, "queryminingrequirement", address, farmer_pk);
    MiningRequirement mining_requirement;
    mining_requirement.req = res.result["require"].get_int64();
    mining_requirement.mined_count = res.result["mined"].get_int();
    mining_requirement.total_count = res.result["count"].get_int();
    mining_requirement.burned = res.result["burned"].get_int64();
    mining_requirement.supplied = res.result["supplied"].get_int64();
    mining_requirement.accumulate = res.result["accumulate"].get_int64();
    mining_requirement.height = res.result["height"].get_int();
    return mining_requirement;
}

void RPCClient::BuildRPCJson(UniValue& params, std::string const& val) { params.push_back(val); }

void RPCClient::BuildRPCJson(UniValue& params, chiapos::Bytes const& val) {
    params.push_back(chiapos::BytesToHex(val));
}

void RPCClient::BuildRPCJson(UniValue& params, bool val) { params.push_back(UniValue(val)); }

void RPCClient::BuildRPCJson(UniValue& params, uint256 const& val) { params.push_back(val.GetHex()); }

void RPCClient::BuildRPCJson(UniValue& params, PosProof const& proof) {
    UniValue val(UniValue::VOBJ);
    val.pushKV("challenge", proof.challenge.GetHex());
    val.pushKV("k", proof.k);
    val.pushKV("pool_pk_or_hash", chiapos::BytesToHex(chiapos::ToBytes(proof.pool_pk_or_hash)));
    val.pushKV("plot_type", static_cast<int>(chiapos::GetType(proof.pool_pk_or_hash)));
    val.pushKV("local_pk", chiapos::BytesToHex(chiapos::MakeBytes(proof.local_pk)));
    val.pushKV("proof", chiapos::BytesToHex(proof.proof));
    params.push_back(val);
}

void RPCClient::BuildRPCJson(UniValue& params, VdfProof const& proof) {
    UniValue val(UniValue::VOBJ);
    val.pushKV("challenge", proof.challenge.GetHex());
    val.pushKV("y", chiapos::BytesToHex(chiapos::MakeBytes(proof.y)));
    val.pushKV("proof", chiapos::BytesToHex(proof.proof));
    val.pushKV("iters", proof.iters);
    val.pushKV("witness_type", proof.witness_type);
    val.pushKV("duration", proof.duration);
    params.push_back(val);
}

void RPCClient::BuildRPCJsonWithParams(UniValue& out_params) {}

}  // namespace miner
