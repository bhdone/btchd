#include "config.h"

#include <chiapos/kernel/bls_key.h>
#include <chiapos/kernel/utils.h>

#include <algorithm>

#include "tinyformat.h"

#include "keyman.h"

namespace miner {

Config::Config() { m_timelord_endpoints.push_back("timelord.bhd.one:19191"); }

std::string Config::ToJsonString() const {
    UniValue root(UniValue::VOBJ);
    root.pushKV("reward", m_reward_dest);
    root.pushKV("seed", m_seed);
    root.pushKV("testnet", m_testnet);
    root.pushKV("noproxy", m_no_proxy);

    UniValue plot_path_list(UniValue::VARR);
    for (auto const& str : m_plot_path_list) {
        plot_path_list.push_back(str);
    }
    root.pushKV("plotPath", plot_path_list);

    UniValue rpc(UniValue::VOBJ);
    rpc.pushKV("host", m_rpc.url);
    rpc.pushKV("user", m_rpc.user);
    rpc.pushKV("password", m_rpc.passwd);

    root.pushKV("rpc", rpc);

    UniValue timelord_endpoints(UniValue::VARR);
    for (auto const& endpoint : m_timelord_endpoints) {
        timelord_endpoints.push_back(UniValue(endpoint));
    }
    root.pushKV("timelords", timelord_endpoints);

    UniValue allowed_ks(UniValue::VARR);
    for (auto const& k : m_allowed_k_vec) {
        allowed_ks.push_back((int)k);
    }
    root.pushKV("allowedPlotK", allowed_ks);

    return root.write(4);
}

void Config::ParseFromJsonString(std::string const& json_str) {
    std::string s(json_str);

    UniValue root;
    bool succ = root.read(json_str);
    if (!succ) {
        throw std::runtime_error("cannot parse json string, check the json syntax");
    }

    std::vector<std::string> root_keys = root.getKeys();
    if (root.exists("rpc") && root["rpc"].isObject()) {
        UniValue rpc = root["rpc"].get_obj();
        if (rpc.exists("host") && rpc["host"].isStr()) {
            m_rpc.url = rpc["host"].get_str();
        }
        if (rpc.exists("user") && rpc["user"].isStr()) {
            m_rpc.user = rpc["user"].get_str();
        }
        if (rpc.exists("password") && rpc["password"].isStr()) {
            m_rpc.passwd = rpc["password"].get_str();
        }
    }

    if (m_rpc.url.empty()) {
        throw std::runtime_error("field `rpc.url` is empty");
    }

    if (root.exists("reward") && root["reward"].isStr()) {
        m_reward_dest = root["reward"].get_str();
    }

    if (m_reward_dest.empty()) {
        throw std::runtime_error("field `reward_dest` is empty");
    }

    if (root.exists("plotPath") && root["plotPath"].isArray()) {
        m_plot_path_list.clear();
        auto plot_path_list = root["plotPath"].getValues();
        for (UniValue const& val : plot_path_list) {
            std::string path_str = val.get_str();
            if (!fs::exists(path_str) || !fs::is_directory(path_str)) {
                continue;
            }
            m_plot_path_list.push_back(std::move(path_str));
        }
    }

    if (root.exists("timelords") && root["timelords"].isArray()) {
        m_timelord_endpoints.clear();
        for (UniValue const& val : root["timelords"].getValues()) {
            std::string endpoint = val.get_str();
            m_timelord_endpoints.push_back(std::move(endpoint));
        }
    }

    if (root.exists("seed") && root["seed"].isStr()) {
        m_seed = root["seed"].get_str();
    }

    if (m_seed.empty()) {
        throw std::runtime_error("field `seed` is empty");
    }

    if (root.exists("testnet") && root["testnet"].isBool()) {
        m_testnet = root["testnet"].get_bool();
    }

    if (root.exists("noproxy") && root["noproxy"].isBool()) {
        m_no_proxy = root["noproxy"].get_bool();
    }

    if (root.exists("allowedPlotK")) {
        m_allowed_k_vec.clear();
        auto k_vals = root["allowedPlotK"].getValues();
        for (UniValue k_val : k_vals) {
            m_allowed_k_vec.push_back(k_val.get_int());
        }
    }
}

Config::RPC Config::GetRPC() const { return m_rpc; }

std::vector<std::string> const& Config::GetPlotPath() const { return m_plot_path_list; }

std::string Config::GetRewardDest() const { return m_reward_dest; }

std::string Config::GetSeed() const { return m_seed; }

bool Config::Testnet() const { return m_testnet; }

bool Config::NoProxy() const { return m_no_proxy; }

chiapos::SecreKey Config::GetFarmerSk() const {
    keyman::Wallet wallet(m_seed, "");
    keyman::Key key = wallet.GetFarmerKey(0);
    return chiapos::MakeArray<chiapos::SK_LEN>(chiapos::MakeBytes(key.GetPrivateKey()));
}

chiapos::PubKey Config::GetFarmerPk() const {
    keyman::Wallet wallet(m_seed, "");
    keyman::Key key = wallet.GetFarmerKey(0);
    return chiapos::MakeArray<chiapos::PK_LEN>(chiapos::MakeBytes(key.GetPublicKey()));
}

std::vector<std::string> Config::GetTimelordEndpoints() const { return m_timelord_endpoints; }

std::vector<uint8_t> Config::GetAllowedKs() const { return m_allowed_k_vec; }

}  // namespace miner
