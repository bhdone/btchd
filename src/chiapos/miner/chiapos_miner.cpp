#include "chiapos_miner.h"

#include <arith_uint256.h>
#include <chiapos/kernel/calc_diff.h>
#include <chiapos/kernel/pos.h>
#include <chiapos/kernel/utils.h>
#include <chiapos/kernel/vdf.h>
#include <chiapos/miner/bhd_types.h>
#include <chiapos/miner/rpc_client.h>
#include <plog/Log.h>
#include <uint256.h>
#include <vdf_computer.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <tuple>
#include <vector>

namespace miner {
namespace pos {

chiapos::QualityStringPack QueryTheBestQualityString(std::vector<chiapos::QualityStringPack> const& qs_pack_vec,
                                                     uint256 const& challenge, int difficulty_constant_factor_bits) {
    assert(!qs_pack_vec.empty());
    chiapos::QualityStringPack res;
    uint64_t best_quality{0};
    for (chiapos::QualityStringPack const& qs_pack : qs_pack_vec) {
        uint256 mixed_quality_string = chiapos::GetMixedQualityString(qs_pack.quality_str.ToBytes(), challenge);
        uint64_t quality = chiapos::CalculateQuality(mixed_quality_string, qs_pack.k);
        if (quality >= best_quality) {
            res = qs_pack;
            best_quality = quality;
        }
    }
    return res;
}

chiapos::optional<RPCClient::PosProof> QueryBestPosProof(Prover& prover, uint256 const& challenge,
                                                         int difficulty_constant_factor_bits, int filter_bits,
                                                         std::string* out_plot_path) {
    auto qs_pack_vec = prover.GetQualityStrings(challenge, filter_bits);
    if (qs_pack_vec.empty()) {
        // No prove can pass the filter
        return {};
    }
    chiapos::QualityStringPack qs_pack =
            QueryTheBestQualityString(qs_pack_vec, challenge, difficulty_constant_factor_bits);
    uint256 mixed_quality_string = chiapos::GetMixedQualityString(qs_pack.quality_str.ToBytes(), challenge);
    if (out_plot_path) {
        *out_plot_path = qs_pack.plot_path;
    }
    chiapos::PlotMemo memo = Prover::ReadPlotMemo(qs_pack.plot_path);
    RPCClient::PosProof proof;
    proof.mixed_quality_string = mixed_quality_string;
    proof.quality = chiapos::CalculateQuality(mixed_quality_string, qs_pack.k);
    proof.challenge = challenge;
    proof.k = qs_pack.k;
    proof.plot_id = chiapos::MakeUint256(memo.plot_id);
    proof.pool_pk_or_hash = chiapos::MakePubKeyOrHash(memo.plot_id_type, memo.pool_pk_or_puzzle_hash);
    proof.local_pk = chiapos::MakeArray<chiapos::PK_LEN>(Prover::CalculateLocalPkBytes(memo.local_master_sk));
    proof.proof = Prover::QueryFullProof(qs_pack.plot_path, challenge, qs_pack.index);
#ifdef DEBUG
    bool verified = chiapos::VerifyPos(challenge, proof.local_pk, chiapos::MakeArray<chiapos::PK_LEN>(memo.farmer_pk),
                                       proof.pool_pk_or_hash, proof.k, proof.proof, nullptr, filter_bits);
    assert(verified);
#endif
    return proof;
}

}  // namespace pos

Miner::Miner(RPCClient& client, Prover& prover, chiapos::SecreKey farmer_sk, chiapos::PubKey farmer_pk,
             std::string reward_dest, int difficulty_constant_factor_bits, int filter_bits)
        : m_client(client),
          m_prover(prover),
          m_farmer_sk(std::move(farmer_sk)),
          m_farmer_pk(std::move(farmer_pk)),
          m_reward_dest(std::move(reward_dest)),
          m_difficulty_constant_factor_bits(difficulty_constant_factor_bits),
          m_filter_bits(filter_bits) {}

int Miner::Run() {
    RPCClient::Challenge queried_challenge;
    uint256 current_challenge;
    chiapos::optional<RPCClient::PosProof> pos;
    std::mutex vdf_mtx;
    chiapos::optional<RPCClient::VdfProof> vdf;
    std::vector<RPCClient::VdfProof> void_block_vec;
    uint64_t iters;
    while (1) {
        std::this_thread::yield();
        PLOG_INFO << "Status: " << ToString(m_state);
        if (m_state == State::RequireChallenge) {
            if (!m_client.CheckChiapos()) {
                continue;
            }
            PLOG_INFO << "--> chia pos is ready";
            // Reset variables
            pos.reset();
            vdf.reset();
            void_block_vec.clear();
            // Query challenge
            queried_challenge = m_client.QueryChallenge();
            current_challenge = queried_challenge.challenge;
            PLOG_INFO << "--> challenge is ready: " << current_challenge.GetHex();
            m_state = State::FindPoS;
        } else if (m_state == State::FindPoS) {
            PLOG_INFO << "--> finding PoS for challenge: " << current_challenge.GetHex()
                      << ", dcf_bits: " << m_difficulty_constant_factor_bits << ", filter_bits: " << m_filter_bits;
            pos = pos::QueryBestPosProof(m_prover, current_challenge, m_difficulty_constant_factor_bits, m_filter_bits);
            if (pos.has_value()) {
                // Check plot-id
                chiapos::PlotId plot_id = chiapos::MakePlotId(pos->local_pk, m_farmer_pk, pos->pool_pk_or_hash);
                if (plot_id != pos->plot_id) {
                    // The provided mnemonic is invalid or it doesn't match to the farmer
                    PLOG_ERROR << "--> !!! Invalid mnemonic! Please check and fix your configure file!";
                    return 1;
                }
                // Get the iters from PoS
                PLOG_INFO << "--> PoS has been found, quality: "
                          << chiapos::FormatNumberStr(std::to_string(pos->quality));
                iters = chiapos::CalculateIterationsQuality(pos->mixed_quality_string, pos->k,
                                                            queried_challenge.difficulty,
                                                            m_difficulty_constant_factor_bits);
                PLOG_INFO << "--> Calculated iters=" << chiapos::FormatNumberStr(std::to_string(iters)) << ", with k=" << static_cast<int>(pos->k)
                          << ", difficulty=" << queried_challenge.difficulty
                          << ", dcf_bits=" << m_difficulty_constant_factor_bits;
            } else {
                // Get the iters for next void block
                PLOG_INFO << "--> PoS cannot be found";
                iters = queried_challenge.prev_vdf_iters / queried_challenge.prev_vdf_duration *
                        queried_challenge.target_duration;
            }
            m_state = State::WaitVDF;
        } else if (m_state == State::WaitVDF) {
            PLOG_INFO << "--> request VDF proof for challenge: " << current_challenge.GetHex() << ", iters: " << chiapos::FormatNumberStr(std::to_string(iters));
            m_client.RequireVdf(current_challenge, iters);
            PLOG_INFO << "--> waiting for VDF proofs...";
            std::atomic_bool running{true};
            BreakReason reason =
                    CheckAndBreak(running, queried_challenge.challenge, current_challenge, iters, vdf_mtx, vdf);
            if (reason == BreakReason::ChallengeIsChanged) {
                PLOG_INFO << "--> challenge has been changed";
                m_state = State::RequireChallenge;
            } else if (reason == BreakReason::VDFIsAcquired) {
                PLOG_INFO << "--> a VDF proof has been received";
                m_state = State::ProcessVDF;
            }
        } else if (m_state == State::ProcessVDF) {
            if (pos.has_value()) {
                PLOG_INFO << "--> all proofs are ready to submit";
                m_state = State::SubmitProofs;
            } else {
                PLOG_INFO << "--> no valid PoS, trying to find another one";
                current_challenge = chiapos::MakeChallenge(current_challenge, vdf->proof);
                void_block_vec.push_back(*vdf);
                m_state = State::FindPoS;
            }
        } else if (m_state == State::SubmitProofs) {
            PLOG_INFO << "--> preparing proofs";
            RPCClient::ProofPack pp;
            pp.prev_block_hash = queried_challenge.prev_block_hash;
            pp.prev_block_height = queried_challenge.prev_block_height;
            pp.pos = *pos;
            pp.vdf = *vdf;
            pp.void_block_vec = void_block_vec;
            pp.farmer_sk = m_farmer_sk;
            pp.reward_dest = m_reward_dest;
            try {
                m_client.SubmitProof(pp);
                PLOG_INFO << "--> proofs have been submitted";
            } catch (std::exception const& e) {
                PLOG_ERROR << "--> SubmitProof throws an exception: " << e.what();
            }
            m_state = State::RequireChallenge;
        }
    }
    return 0;
}

Miner::BreakReason Miner::CheckAndBreak(std::atomic_bool& running, uint256 const& initial_challenge,
                                        uint256 const& current_challenge, uint64_t iters_limits,
                                        std::mutex& vdf_write_lock, chiapos::optional<RPCClient::VdfProof>& out_vdf) {
    while (running) {
        try {
            // Query current challenge, compare
            RPCClient::Challenge ch = m_client.QueryChallenge();
            if (ch.challenge != initial_challenge) {
                // Challenge is changed
                return BreakReason::ChallengeIsChanged;
            }
            // Query VDF and when the VDF is ready we break the VDF computer and use the VDF proof
            RPCClient::VdfProof vdf = m_client.QueryVdf(current_challenge, iters_limits);
            // VDF is ready
            {
                std::lock_guard<std::mutex> lg(vdf_write_lock);
                out_vdf = vdf;
            }
            return BreakReason::VDFIsAcquired;
        } catch (std::exception const& e) {
            // We cannot query the valid VDF
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
    return BreakReason::Custom;
}

std::string Miner::ToString(State state) {
    switch (state) {
        case State::RequireChallenge:
            return "RequireChallenge";
        case State::FindPoS:
            return "FindPoS";
        case State::WaitVDF:
            return "WaitVDF";
        case State::ProcessVDF:
            return "ProcessVDF";
        case State::SubmitProofs:
            return "SubmitProofs";
    }
    assert(false);
}

}  // namespace miner
