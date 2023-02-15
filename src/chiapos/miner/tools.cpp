#include "tools.h"

#include <chiapos/kernel/utils.h>
#include <plog/Log.h>

#include <fstream>

#include "bhd_types.h"

namespace tools {

miner::Config ParseConfig(std::string const& config_path) {
    // Read config
    std::ifstream in(config_path);
    if (!in.is_open()) {
        throw std::runtime_error("cannot open config file to read");
    }

    // Find the file size
    in.seekg(0, std::ios::end);
    auto size = in.tellg();
    in.seekg(0, std::ios::beg);

    std::string json_str(size, 0);
    in.read(&(*json_str.begin()), size);

    miner::Config config;
    config.ParseFromJsonString(json_str);

    if (!config.Valid()) {
        throw std::runtime_error("config is invalid, please fix it before mining");
    }
    return config;
}

std::unique_ptr<miner::RPCClient> CreateRPCClient(bool no_proxy, std::string const& cookie_path,
                                                  std::string const& url) {
    return chiapos::MakeUnique<miner::RPCClient>(no_proxy, url, cookie_path);
}

std::unique_ptr<miner::RPCClient> CreateRPCClient(bool no_proxy, std::string const& user, std::string const& passwd,
                                                  std::string const& url) {
    return chiapos::MakeUnique<miner::RPCClient>(no_proxy, url, user, passwd);
}

std::unique_ptr<miner::RPCClient> CreateRPCClient(miner::Config const& config,
                                                  std::string const& cookie_path) {
    if (!config.GetRPC().user.empty() && !config.GetRPC().passwd.empty()) {
        PLOG_INFO << "Creating RPC client by using username/password...";
        return CreateRPCClient(config.NoProxy(), config.GetRPC().user, config.GetRPC().passwd, config.GetRPC().url);
    } else {
        PLOG_INFO << "Creating RPC client by using cookie file: " << cookie_path;
        return CreateRPCClient(config.NoProxy(), cookie_path, config.GetRPC().url);
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
