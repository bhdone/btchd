#ifndef BHD_MINER_MINER_HPP
#define BHD_MINER_MINER_HPP

#include <chiapos/kernel/bls_key.h>
#include <chiapos/kernel/chiapos_types.h>

#include <functional>
#include <mutex>
#include <string>
#include <optional>

#include "prover.h"
#include "rpc_client.h"

#include <chiapos/timelord_cli/timelord_client.h>

namespace miner {
namespace pos {
chiapos::optional<RPCClient::PosProof> QueryBestPosProof(Prover& prover, uint256 const& challenge,
                                                         int difficulty_constant_factor_bits, int filter_bits,
                                                         std::string* out_plot_path = nullptr);
}

using TimelordClientPtr = std::shared_ptr<TimelordClient>;

/// Miner is a state machine
class Miner {
public:
    Miner(RPCClient& client, Prover& prover, chiapos::SecreKey farmer_sk, chiapos::PubKey farmer_pk,
          std::string reward_dest, int difficulty_constant_factor_bits);

    ~Miner();

    void StartTimelord(std::vector<std::string> const& endpoints, uint16_t default_port);

    int Run();

private:
    enum class State { RequireChallenge, FindPoS, WaitVDF, ProcessVDF, SubmitProofs };

    enum class BreakReason { Error, Timeout, ChallengeIsChanged, VDFIsAcquired };

    TimelordClientPtr PrepareTimelordClient(std::string const& hostname, unsigned short port);

    /// A thread proc to check the challenge or the VDF from P2P network
    BreakReason CheckAndBreak(std::atomic_bool& running, int timeout_seconds, uint256 const& initial_challenge,
                              uint256 const& current_challenge, uint64_t iters_limits, std::mutex& vdf_write_lock,
                              chiapos::optional<RPCClient::VdfProof>& out_vdf);

    static std::string ToString(State state);

    void TimelordProc();

    chiapos::optional<ProofDetail> QueryProofFromTimelord(uint256 const& challenge, uint64_t iters) const;

    void SaveProof(uint256 const& challenge, ProofDetail const& detail);

private:
    // utilities
    RPCClient& m_client;
    Prover& m_prover;
    chiapos::SecreKey m_farmer_sk;
    chiapos::PubKey m_farmer_pk;
    std::string m_reward_dest;
    int m_difficulty_constant_factor_bits;
    // State
    std::atomic<State> m_state{State::RequireChallenge};
    // thread and timelord
    asio::io_context m_ioc;
    std::unique_ptr<std::thread> m_pthread_timelord;
    std::vector<TimelordClientPtr> m_timelord_vec;
    mutable std::mutex m_mtx_proofs;
    std::map<uint256, std::vector<ProofDetail>> m_proofs;
    std::set<uint256> m_submit_history;
    std::atomic_bool m_shutting_down{false};
};

}  // namespace miner

#endif
