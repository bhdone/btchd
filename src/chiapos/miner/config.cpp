#include "config.h"

#include <chiapos/kernel/bls_key.h>
#include <chiapos/kernel/utils.h>

#include <algorithm>

#include "keyman.h"

namespace miner {

bool Config::Valid() const {
    if (m_plot_path_list.empty()) {
        return false;
    }
    bool contains_empty_str = std::count_if(std::begin(m_plot_path_list), std::end(m_plot_path_list),
                                            [](std::string const& path_str) { return path_str.empty(); });
    if (contains_empty_str) {
        return false;
    }
    if (m_reward_dest.empty()) {
        return false;
    }
    if (m_seed.empty()) {
        return false;
    }
    if (m_rpc.url.empty()) {
        return false;
    }
    return true;
}

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
    return root.write();
}

void Config::ParseFromJsonString(std::string const& json_str) {
    std::string s(json_str), errs;

    UniValue root;
    root.read(json_str);

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

    if (root.exists("reward") && root["reward"].isStr()) {
        m_reward_dest = root["reward"].get_str();
    }

    if (root.exists("plotPath") && root["plotPath"].isArray()) {
        m_plot_path_list.clear();
        auto plot_path_list = root["plotPath"].getValues();
        for (UniValue const& val : plot_path_list) {
            m_plot_path_list.push_back(val.get_str());
        }
    }

    if (root.exists("seed") && root["seed"].isStr()) {
        m_seed = root["seed"].get_str();
    }

    if (root.exists("testnet") && root["testnet"].isBool()) {
        m_testnet = root["testnet"].get_bool();
    }

    if (root.exists("noproxy") && root["noproxy"].isBool()) {
        m_no_proxy = root["noproxy"].get_bool();
    }
}

Config::RPC Config::GetRPC() const { return m_rpc; }

std::vector<std::string> const& Config::GetPlotPath() const { return m_plot_path_list; }

std::string Config::GetRewardDest() const { return m_reward_dest; }

std::string Config::GetSeed() const { return m_seed; }

bool Config::Testnet() const { return m_testnet; }

bool Config::NoProxy() const { return m_no_proxy; }


void Config::SetSeed(std::string seed) { m_seed = std::move(seed); }

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

}  // namespace miner
