#include "chiapos_miner.h"

#include <arith_uint256.h>
#include <plog/Log.h>

#include <uint256.h>
#include <vdf_computer.h>

#include <chiapos/bhd_types.h>

#include <chiapos/kernel/calc_diff.h>
#include <chiapos/kernel/pos.h>
#include <chiapos/kernel/utils.h>
#include <chiapos/kernel/vdf.h>

#include <chiapos/miner/rpc_client.h>

#include <atomic>
#include <boost/asio.hpp>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <tuple>
#include <vector>

#include <chiapos/timelord_cli/msg_ids.h>
#include <chiapos/timelord_cli/timelord_client.h>

#include <tinyformat.h>

namespace miner {
namespace pos {

bool IsZeroBytes(Bytes const& bytes) {
    for (uint8_t byte : bytes) {
        if (byte != 0) {
            return false;
        }
    }
    return true;
}

chiapos::QualityStringPack QueryTheBestQualityString(std::vector<chiapos::QualityStringPack> const& qs_pack_vec,
                                                     uint256 const& challenge, uint64_t difficulty,
                                                     int difficulty_constant_factor_bits) {
    assert(!qs_pack_vec.empty());
    chiapos::QualityStringPack res;
    int64_t best_iters{-1};
    double best_quality_in_plot;
    arith_uint256 best_quality;
    for (chiapos::QualityStringPack const& qs_pack : qs_pack_vec) {
        Bytes quality_string = qs_pack.quality_str.ToBytes();
        assert(!IsZeroBytes(quality_string));
        uint256 mixed_quality_string = chiapos::GetMixedQualityString(quality_string, challenge);
        double quality_in_plot;
        arith_uint256 quality;
        uint64_t iters =
                chiapos::CalculateIterationsQuality(mixed_quality_string, difficulty, difficulty_constant_factor_bits,
                                                    qs_pack.k, &quality_in_plot, &quality);
        PLOGD << tinyformat::format("checking pos, quality_in_plot=%1.3f, quality=%e, iters=%lld, k=%d",
                                    quality_in_plot, quality.getdouble(), chiapos::MakeNumberStr(iters),
                                    (int)qs_pack.k);
        if (best_iters == -1 || iters < best_iters) {
            res = qs_pack;
            best_iters = iters;
            best_quality_in_plot = quality_in_plot;
            best_quality = quality;
        }
    }
    if (best_iters != -1) {
        PLOGI << tinyformat::format("Best proof is queried, quality_in_plot=%1.3f, quality=%e, iters=%lld, k=%d",
                                    best_quality_in_plot, best_quality.getdouble(), chiapos::MakeNumberStr(best_iters),
                                    res.k);
    }
    return res;
}

chiapos::optional<RPCClient::PosProof> QueryBestPosProof(Prover& prover, uint256 const& challenge, uint64_t difficulty,
                                                         int difficulty_constant_factor_bits, int filter_bits,
                                                         std::string* out_plot_path) {
    auto qs_pack_vec = prover.GetQualityStrings(challenge, filter_bits);
    PLOG_INFO << "total " << qs_pack_vec.size() << " answer(s), filter_bits=" << filter_bits;
    if (qs_pack_vec.empty()) {
        // No prove can pass the filter
        return {};
    }
    chiapos::QualityStringPack qs_pack =
            QueryTheBestQualityString(qs_pack_vec, challenge, difficulty, difficulty_constant_factor_bits);
    Bytes quality_string = qs_pack.quality_str.ToBytes();
    uint256 mixed_quality_string = chiapos::GetMixedQualityString(quality_string, challenge);
    if (out_plot_path) {
        *out_plot_path = qs_pack.plot_path;
    }
    chiapos::PlotMemo memo;
    if (!Prover::ReadPlotMemo(qs_pack.plot_path, memo)) {
        return {};
    }
    RPCClient::PosProof proof;
    proof.mixed_quality_string = mixed_quality_string;
    proof.iters = chiapos::CalculateIterationsQuality(mixed_quality_string, difficulty, difficulty_constant_factor_bits,
                                                      qs_pack.k);
    proof.challenge = challenge;
    proof.k = qs_pack.k;
    proof.plot_id = chiapos::MakeUint256(memo.plot_id);
    proof.pool_pk_or_hash = chiapos::MakePubKeyOrHash(memo.plot_id_type, memo.pool_pk_or_puzzle_hash);
    proof.local_pk = chiapos::MakeArray<chiapos::PK_LEN>(Prover::CalculateLocalPkBytes(memo.local_master_sk));
    if (!Prover::QueryFullProof(qs_pack.plot_path, challenge, qs_pack.index, proof.proof)) {
        return {};
    }
    PLOGI << "iters=" << chiapos::FormatNumberStr(std::to_string(proof.iters)) << ", k=" << (int)proof.k
          << ", farmer-pk: " << chiapos::BytesToHex(memo.farmer_pk);
#ifdef DEBUG
    bool verified = chiapos::VerifyPos(challenge, proof.local_pk, chiapos::MakeArray<chiapos::PK_LEN>(memo.farmer_pk),
                                       proof.pool_pk_or_hash, proof.k, proof.proof, nullptr, filter_bits);
    assert(verified);
#endif
    return proof;
}

}  // namespace pos

Miner::Miner(RPCClient& client, Prover& prover, chiapos::SecreKey farmer_sk, chiapos::PubKey farmer_pk,
             std::string reward_dest, int difficulty_constant_factor_bits)
        : m_client(client),
          m_prover(prover),
          m_farmer_sk(std::move(farmer_sk)),
          m_farmer_pk(std::move(farmer_pk)),
          m_reward_dest(std::move(reward_dest)),
          m_difficulty_constant_factor_bits(difficulty_constant_factor_bits) {}

Miner::~Miner() {
    if (m_pthread_timelord) {
        PLOGI << "exiting timelord client...";
        m_shutting_down = true;
        for (auto ptr : m_timelord_vec) {
            ptr->Exit();
        }
        m_pthread_timelord->join();
    }
}

void Miner::StartTimelord(std::vector<std::string> const& endpoints, uint16_t default_port) {
    PLOGI << tinyformat::format("start timelord total %d client...", endpoints.size());
    for (auto const& endpoint : endpoints) {
        auto p = endpoint.find_first_of(':');
        std::string hostname;
        uint16_t port{default_port};
        if (p != std::string::npos) {
            hostname = endpoint.substr(0, p);
            std::string port_str = endpoint.substr(p + 1);
            port = std::atoi(port_str.c_str());
        } else {
            hostname = endpoint;
        }
        m_timelord_vec.push_back(PrepareTimelordClient(hostname, port));
    }
    m_pthread_timelord.reset(new std::thread(std::bind(&Miner::TimelordProc, this)));
}

int Miner::Run() {
    int const ERROR_RECOVER_WAIT_SECONDS = 3;
    RPCClient::Challenge queried_challenge;
    chiapos::optional<RPCClient::PosProof> pos;
    chiapos::optional<RPCClient::VdfProof> vdf;
    std::vector<RPCClient::VdfProof> void_block_vec;
    std::string curr_plot_path;
    uint64_t vdf_speed{100000};
    while (1) {
        try {
            std::this_thread::yield();
            PLOG_INFO << "==== Status: " << ToString(m_state) << " ====";
            if (m_state == State::RequireChallenge) {
                if (!m_client.CheckChiapos()) {
                    continue;
                }
                PLOG_INFO << "chia pos is ready";
                // Reset variables
                pos.reset();
                vdf.reset();
                void_block_vec.clear();
                m_current_challenge.SetNull();
                m_current_iters = 0;
                // Query challenge
                queried_challenge = m_client.QueryChallenge();
                if (m_submit_history.find(queried_challenge.challenge) != std::end(m_submit_history)) {
                    PLOG_INFO << "proof is already submitted, waiting for next challenge...";
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                } else {
                    m_current_challenge = queried_challenge.challenge;
                    PLOG_INFO << "challenge is ready: " << m_current_challenge.GetHex()
                              << ", target height: " << queried_challenge.target_height
                              << ", filter_bits: " << queried_challenge.filter_bits;
                    m_state = State::FindPoS;
                }
            } else if (m_state == State::FindPoS) {
                PLOG_INFO << "finding PoS for challenge: " << m_current_challenge.GetHex()
                          << ", dcf_bits: " << m_difficulty_constant_factor_bits
                          << ", filter_bits: " << queried_challenge.filter_bits;
                pos = pos::QueryBestPosProof(m_prover, m_current_challenge, queried_challenge.difficulty,
                                             m_difficulty_constant_factor_bits, queried_challenge.filter_bits,
                                             &curr_plot_path);
                if (pos.has_value()) {
                    // Check plot-id
                    chiapos::PlotId plot_id = chiapos::MakePlotId(pos->local_pk, m_farmer_pk, pos->pool_pk_or_hash);
                    if (plot_id != pos->plot_id) {
                        // The provided mnemonic is invalid or it doesn't match to the farmer
                        PLOG_ERROR << "!!! Invalid mnemonic! Please check and fix your configure file! Plot path: "
                                   << curr_plot_path;
                        return 1;
                    }
                    // Get the iters from PoS
                    m_current_iters = pos->iters;
                    PLOG_INFO << "calculated, iters=" << chiapos::FormatNumberStr(std::to_string(m_current_iters))
                              << ", with k=" << static_cast<int>(pos->k)
                              << ", difficulty=" << chiapos::MakeNumberStr(queried_challenge.difficulty)
                              << ", dcf_bits=" << m_difficulty_constant_factor_bits;
                } else {
                    // Get the iters for next void block
                    PLOG_INFO << "PoS cannot be found";
                    m_current_iters = queried_challenge.prev_vdf_iters / queried_challenge.prev_vdf_duration *
                                      queried_challenge.target_duration;
                }
                m_state = State::WaitVDF;
            } else if (m_state == State::WaitVDF) {
                std::string estimate_time_str{"n/a"};
                int estimate_seconds = m_current_iters / vdf_speed;
                estimate_time_str = tinyformat::format(
                        "%s seconds (%s), vdf speed=%s ips", chiapos::MakeNumberStr(estimate_seconds),
                        chiapos::FormatTime(estimate_seconds), chiapos::MakeNumberStr(vdf_speed));
                PLOG_INFO << "request VDF proof for challenge: " << m_current_challenge.GetHex()
                          << ", iters: " << chiapos::FormatNumberStr(std::to_string(m_current_iters));
                PLOGI << "estimate time: " << estimate_time_str;
                m_client.RequireVdf(m_current_challenge, m_current_iters);
                PLOG_INFO << "waiting for VDF proofs...";
                std::atomic_bool running{true};
                BreakReason reason =
                        CheckAndBreak(running, queried_challenge.target_duration * 1.5, queried_challenge.challenge,
                                      m_current_challenge, m_current_iters, vdf);
                if (reason == BreakReason::ChallengeIsChanged) {
                    PLOG_INFO << "!!!!! Challenge is changed !!!!!";
                    m_state = State::RequireChallenge;
                } else if (reason == BreakReason::VDFIsAcquired) {
                    PLOG_INFO << "a VDF proof has been received";
                    assert(vdf.has_value());
                    if (vdf->duration >= 3) {
                        vdf_speed = vdf->iters / vdf->duration;
                        PLOGI << tinyformat::format("vdf speed is updated to %s ips",
                                                    chiapos::MakeNumberStr(vdf_speed));
                    }
                    m_state = State::ProcessVDF;
                } else if (reason == BreakReason::Error) {
                    // The challenge monitor returns without a valid reason
                    // the connection to the RPC service might has errors
                    // So we reset the state to RequireChallenge and wait
                    // until the service is recovered
                    m_state = State::RequireChallenge;
                } else if (reason == BreakReason::Timeout) {
                    m_state = State::WaitVDF;  // request vdf again
                }
            } else if (m_state == State::ProcessVDF) {
                if (pos.has_value()) {
                    PLOG_INFO << "all proofs are ready to submit";
                    m_state = State::SubmitProofs;
                } else {
                    PLOG_INFO << "no valid PoS, trying to find another one";
                    m_current_challenge = chiapos::MakeChallenge(m_current_challenge, vdf->proof);
                    void_block_vec.push_back(*vdf);
                    m_state = State::FindPoS;
                }
            } else if (m_state == State::SubmitProofs) {
                PLOG_INFO << "preparing proofs";
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
                    m_submit_history.insert(queried_challenge.challenge);
                    PLOG_INFO << "$$$$$ Proofs have been submitted $$$$$";
                } catch (std::exception const& e) {
                    PLOG_ERROR << "SubmitProof throws an exception: " << e.what();
                }
                m_state = State::RequireChallenge;
            }
        } catch (NetError const& e) {
            // The network has errors, need to load cookie file if it is the way to verify login
            PLOG_ERROR << "NetError: " << e.what();
            if (fs::exists(m_client.GetCookiePath()) && fs::is_regular_file(m_client.GetCookiePath())) {
                m_client.LoadCookie();
            }
            std::this_thread::sleep_for(std::chrono::seconds(ERROR_RECOVER_WAIT_SECONDS));
        } catch (RPCError const& e) {
            PLOG_ERROR << "RPCError: " << e.what();
            std::this_thread::sleep_for(std::chrono::seconds(ERROR_RECOVER_WAIT_SECONDS));
        } catch (std::exception const& e) {
            PLOG_ERROR << "Mining error: " << e.what();
            std::this_thread::sleep_for(std::chrono::seconds(ERROR_RECOVER_WAIT_SECONDS));
        }
    }
    return 0;
}

TimelordClientPtr Miner::PrepareTimelordClient(std::string const& hostname, unsigned short port) {
    PLOGI << "Establishing connection to timelord " << hostname << ":" << port;
    auto ptimelord_client = std::make_shared<TimelordClient>(m_ioc);
    auto pweak_timelord = std::weak_ptr<TimelordClient>(ptimelord_client);
    ptimelord_client->SetConnectionHandler([this, pweak_timelord]() {
        PLOGI << "Connected to timelord";
        auto ptimelord_client = pweak_timelord.lock();
        if (ptimelord_client == nullptr) {
            return;
        }
        if (!m_current_challenge.IsNull()) {
            ptimelord_client->Calc(m_current_challenge, m_current_iters);
        }
    });
    ptimelord_client->SetErrorHandler(
            [this, hostname, port, pweak_timelord](FrontEndClient::ErrorType type, std::string const& errs) {
                PLOGE << "Timelord client " << hostname << ":" << port
                      << ", reports error: type=" << static_cast<int>(type) << ", errs: " << errs;
                // remove the pointer from vec
                auto ptimelord = pweak_timelord.lock();
                if (ptimelord) {
                    auto it = std::remove(std::begin(m_timelord_vec), std::end(m_timelord_vec), ptimelord);
                    m_timelord_vec.erase(it, std::end(m_timelord_vec));
                    ptimelord->Exit();
                }
                // We need to re-try to connect to timelord server here
                if (!m_shutting_down) {
                    // prepare to reconnect
                    // wait 3 seconds
                    int const RECONNECT_WAIT_SECONDS = 3;
                    PLOGI << "Establish connection to timelord after " << RECONNECT_WAIT_SECONDS << " seconds";
                    auto ptimer = std::make_shared<asio::steady_timer>(m_ioc);
                    ptimer->expires_after(std::chrono::seconds(RECONNECT_WAIT_SECONDS));
                    ptimer->async_wait([this, hostname, port, ptimer](std::error_code const& ec) {
                        if (ec) {
                            return;
                        }
                        // ready to connect
                        m_timelord_vec.push_back(PrepareTimelordClient(hostname, port));
                    });
                }
            });
    ptimelord_client->SetProofReceiver(
            [this](uint256 const& challenge, ProofDetail const& detail) { SaveProof(challenge, detail); });
    ptimelord_client->Connect(hostname, port);
    return ptimelord_client;
}

Miner::BreakReason Miner::CheckAndBreak(std::atomic_bool& running, int timeout_seconds,
                                        uint256 const& initial_challenge, uint256 const& current_challenge,
                                        uint64_t iters, chiapos::optional<RPCClient::VdfProof>& out_vdf) {
    // before we get in the loop, we need to send the request to timelord if it is running
    if (m_pthread_timelord) {
        PLOGD << "request proof from timelord";
        asio::post(m_ioc, [this, current_challenge, iters]() {
            for (auto ptr : m_timelord_vec) {
                ptr->Calc(current_challenge, iters);
            }
        });
    }
    auto start_time = std::chrono::system_clock::now();
    while (running) {
        auto curr_time = std::chrono::system_clock::now();
        auto curr_seconds = std::chrono::duration_cast<std::chrono::seconds>(curr_time - start_time).count();
        if (curr_seconds >= timeout_seconds) {
            return BreakReason::Timeout;
        }
        try {
            // Query current challenge, compare
            RPCClient::Challenge ch = m_client.QueryChallenge();
            if (ch.challenge != initial_challenge) {
                // Challenge is changed
                return BreakReason::ChallengeIsChanged;
            }
            // Query proof from timelord if it is created
            if (m_pthread_timelord) {
                auto detail = QueryProofFromTimelord(current_challenge, iters);
                if (detail.has_value()) {
                    PLOGI << "queried vdf proof from timelord";
                    RPCClient::VdfProof vdf;
                    vdf.challenge = current_challenge;
                    vdf.y = chiapos::MakeVDFForm(detail->y);
                    vdf.proof = detail->proof;
                    vdf.witness_type = detail->witness_type;
                    vdf.iters = detail->iters;
                    vdf.duration = std::max(detail->duration, 1);
                    out_vdf = vdf;
                    return BreakReason::VDFIsAcquired;
                }
            }
            // Query VDF and when the VDF is ready we break the VDF computer and use the VDF proof
            RPCClient::VdfProof vdf = m_client.QueryVdf(current_challenge, iters);
            // VDF is ready
            out_vdf = vdf;
            return BreakReason::VDFIsAcquired;
        } catch (NetError const& e) {
            PLOGE << "NetError: " << e.what();
            return BreakReason::Error;
        } catch (RPCError const& e) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        } catch (std::exception const& e) {
            PLOGE << "unknown error: " << e.what();
            return BreakReason::Error;
        }
    }
    return BreakReason::Error;
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

void Miner::TimelordProc() { m_ioc.run(); }

chiapos::optional<ProofDetail> Miner::QueryProofFromTimelord(uint256 const& challenge, uint64_t iters) const {
    std::lock_guard<std::mutex> lg(m_mtx_proofs);
    auto it = m_proofs.find(challenge);
    if (it == std::end(m_proofs)) {
        return {};
    }
    for (auto const& detail : it->second) {
        if (detail.iters >= iters) {
            return detail;
        }
    }
    return {};
}

void Miner::SaveProof(uint256 const& challenge, ProofDetail const& detail) {
    std::lock_guard<std::mutex> lg(m_mtx_proofs);
    auto it = m_proofs.find(challenge);
    if (it == std::end(m_proofs)) {
        m_proofs.insert(std::make_pair(challenge, std::vector<ProofDetail>{detail}));
    } else {
        // exit if the proof does already exist
        it->second.push_back(detail);
    }
    PLOGI << "proof is saved.";
}

}  // namespace miner
