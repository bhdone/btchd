#ifndef BHD_MINER_CONFIG_H
#define BHD_MINER_CONFIG_H

#include <chiapos/kernel/bls_key.h>
#include <chiapos/kernel/chiapos_types.h>
#include <chiapos/kernel/pos.h>

#include <univalue.h>

#include <string>

namespace miner {

class Config {
public:
    struct RPC {
        std::string url;
        std::string user;
        std::string passwd;
        std::string wallet;
    };

    std::string ToJsonString() const;

    void ParseFromJsonString(std::string const& json_str);

    RPC GetRPC() const;

    std::vector<std::string> const& GetPlotPath() const;

    std::string GetRewardDest() const;

    std::vector<std::string> GetSeeds() const;

    bool Testnet() const;

    bool NoProxy() const;

    std::vector<std::string> GetTimelordEndpoints() const;

    std::vector<uint8_t> GetAllowedKs() const;

private:
    RPC m_rpc;
    std::string m_reward_dest;
    std::vector<std::string> m_plot_path_list;
    std::vector<std::string> m_seeds;
    bool m_testnet{true};
    bool m_no_proxy{true};
    std::vector<std::string> m_timelord_endpoints;
    std::vector<uint8_t> m_allowed_k_vec;
};

}  // namespace miner

#endif
