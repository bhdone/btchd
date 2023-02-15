#ifndef BTCHD_MINER_TOOLS_H
#define BTCHD_MINER_TOOLS_H

#include "config.h"
#include "rpc_client.h"

namespace tools {

miner::Config ParseConfig(std::string const& config_path);

std::unique_ptr<miner::RPCClient> CreateRPCClient(bool no_proxy, std::string const& cookie_path, std::string const& url);

std::unique_ptr<miner::RPCClient> CreateRPCClient(bool no_proxy, std::string const& user, std::string const& passwd, std::string const& url);

std::unique_ptr<miner::RPCClient> CreateRPCClient(miner::Config const& config, std::string const& cookie_path);

std::string GetDefaultDataDir(bool is_testnet, std::string const& filename = "");

} // namespace tools

#endif
