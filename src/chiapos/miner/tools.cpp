#include "tools.h"

#include <chiapos/kernel/utils.h>
#include <plog/Log.h>

#include <fstream>

#include <chiapos/bhd_types.h>

namespace tools {

miner::Config ParseConfig(std::string const& config_path) {
    // Read config
    std::ifstream in(config_path);
    if (!in.is_open()) {
        throw std::runtime_error("cannot open config file to read");
    }

    std::stringstream ss;
    std::string line;
    while (!in.eof()) {
        std::getline(in, line);
        ss << line << std::endl;
    }

    std::string json_str = ss.str();

    miner::Config config;
    config.ParseFromJsonString(json_str);

    return config;
}

std::unique_ptr<miner::RPCClient> CreateRPCClient(bool no_proxy, std::string const& cookie_path, std::string const& url,
                                                  std::string const& wallet) {
    auto res = chiapos::MakeUnique<miner::RPCClient>(no_proxy, url, cookie_path);
    res->SetWallet(wallet);
    return res;
}

std::unique_ptr<miner::RPCClient> CreateRPCClient(bool no_proxy, std::string const& user, std::string const& passwd,
                                                  std::string const& url, std::string const& wallet) {
    auto res = chiapos::MakeUnique<miner::RPCClient>(no_proxy, url, user, passwd);
    res->SetWallet(wallet);
    return res;
}

std::unique_ptr<miner::RPCClient> CreateRPCClient(miner::Config const& config,
                                                  std::string const& cookie_path) {
    if (!config.GetRPC().user.empty() && !config.GetRPC().passwd.empty()) {
        PLOG_INFO << "Creating RPC client by using username/password...";
        return CreateRPCClient(config.NoProxy(), config.GetRPC().user, config.GetRPC().passwd, config.GetRPC().url,
                               config.GetRPC().wallet);
    } else {
        PLOG_INFO << "Creating RPC client by using cookie file: " << cookie_path;
        return CreateRPCClient(config.NoProxy(), cookie_path, config.GetRPC().url, config.GetRPC().wallet);
    }
}

std::string GetDefaultDataDir(bool is_testnet, std::string const& filename) {
#ifdef _WIN32
    std::string home_str = getenv("APPDATA");
    Path path(home_str);
    path /= "btchd";
#endif

#ifdef __APPLE__
    std::string home_str = getenv("HOME");
    Path path(home_str);
    path = path / "Library" / "Application Support" / "btchd";
#endif

#ifdef __linux__
    std::string home_str = getenv("HOME");
    Path path(home_str);
    path /= ".btchd";
#endif

    if (is_testnet) {
        path /= "testnet3";
    }
    if (filename.empty()) {
        return path.string();
    } else {
        return (path / filename).string();
    }
}

}  // namespace tools
