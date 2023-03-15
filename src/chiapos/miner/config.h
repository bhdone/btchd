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
    };

    Config();

    std::string ToJsonString() const;

    void ParseFromJsonString(std::string const& json_str);

    RPC GetRPC() const;

    std::vector<std::string> const& GetPlotPath() const;

    std::string GetRewardDest() const;

    std::string GetSeed() const;

    bool Testnet() const;

    bool NoProxy() const;

    void SetSeed(std::string seed);

    chiapos::SecreKey GetFarmerSk() const;

    chiapos::PubKey GetFarmerPk() const;

    std::vector<std::string> GetTimelordEndpoints() const;

private:
    RPC m_rpc;
    std::string m_reward_dest;
    std::vector<std::string> m_plot_path_list;
    std::string m_seed;
    bool m_testnet{true};
    bool m_no_proxy{true};
    std::vector<std::string> m_timelord_endpoints;
};

}  // namespace miner

#endif
