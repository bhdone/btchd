#ifndef BHD_MINER_MINER_HPP
#define BHD_MINER_MINER_HPP

#include <chiapos/kernel/bls_key.h>
#include <chiapos/kernel/chiapos_types.h>

#include <functional>
#include <mutex>
#include <string>

#include "prover.h"
#include "rpc_client.h"

namespace miner {
namespace pos {
chiapos::optional<RPCClient::PosProof> QueryBestPosProof(Prover& prover, uint256 const& challenge,
                                                         int difficulty_constant_factor_bits, int filter_bits,
                                                         std::string* out_plot_path = nullptr);
}

/// Miner is a state machine
class Miner {
public:
    Miner(RPCClient& client, Prover& prover, chiapos::SecreKey farmer_sk, chiapos::PubKey farmer_pk,
          std::string reward_dest, int difficulty_constant_factor_bits, int filter_bits);

    int Run();

private:
    enum class State { RequireChallenge, FindPoS, WaitVDF, ProcessVDF, SubmitProofs };

    enum class BreakReason { Custom, ChallengeIsChanged, VDFIsAcquired };

    /// A thread proc to check the challenge or the VDF from P2P network
    BreakReason CheckAndBreak(std::atomic_bool& running, uint256 const& initial_challenge,
                              uint256 const& current_challenge, uint64_t iters_limits, std::mutex& vdf_write_lock,
                              chiapos::optional<RPCClient::VdfProof>& out_vdf);

    static std::string ToString(State state);

private:
    // utilities
    RPCClient& m_client;
    Prover& m_prover;
    chiapos::SecreKey m_farmer_sk;
    chiapos::PubKey m_farmer_pk;
    std::string m_reward_dest;
    int m_difficulty_constant_factor_bits;
    int m_filter_bits;
    // State
    std::atomic<State> m_state{State::RequireChallenge};
};

}  // namespace miner

#endif
