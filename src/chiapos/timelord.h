#ifndef BTCHD_VDF_RECEIVER_H
#define BTCHD_VDF_RECEIVER_H

#include <chiapos/kernel/chiapos_types.h>
#include <chiapos/miner/bhd_types.h>
#include <uint256.h>

#include <atomic>
#include <boost/asio.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/process.hpp>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <map>
#include <vector>

namespace proc = boost::process;

namespace net = boost::asio;
using net::ip::tcp;

namespace chiapos {

class CVdfClientProcManager {
public:
    CVdfClientProcManager(std::string vdf_client_path, std::string hostname, uint16_t port);

    void NewProc();

    int RemoveDeadChildren();

    void Wait();

    int GetCount() const { return m_children.size(); }

private:
    std::string m_vdf_client_path;
    std::string m_hostname;
    uint16_t m_port;
    std::vector<proc::child> m_children;
};

class CSocketWriter {
public:
    explicit CSocketWriter(tcp::socket& s);

    void AsyncWrite(Bytes buff);

private:
    void DoWriteNext();

private:
    std::deque<Bytes> m_buffs;
    tcp::socket& m_s;
};

struct Command {
    enum class CommandType { UNKNOWN, OK, STOP, PROOF };

    CommandType type{CommandType::UNKNOWN};
    std::string body;
    std::size_t consumed{0};

    static std::string CommandTypeToString(CommandType type) {
        switch (type) {
            case CommandType::UNKNOWN:
                return "UNKNOWN";
            case CommandType::OK:
                return "OK";
            case CommandType::STOP:
                return "STOP";
            case CommandType::PROOF:
                return "PROOF";
        }
        return "(error-command-type)";
    }
};

using CommandAnalyzer = std::function<Command(Bytes const&)>;

struct Proof {
    Bytes y;
    Bytes proof;
    uint8_t witness_type;
};

using ProofReceiver = std::function<void(Proof const& proof, uint64_t iters, uint64_t duration, uint256 challenge)>;

class CTimeSession;
using CTimeSessionPtr = std::shared_ptr<CTimeSession>;
using SessionNotify = std::function<void(CTimeSessionPtr)>;

enum class TimeType { S, N, T };

std::string TimeTypeToString(TimeType type);

class CTimeSession : public std::enable_shared_from_this<CTimeSession> {
public:
    CTimeSession(net::io_context& ioc, tcp::socket&& s, uint256 challenge, TimeType time_type, CommandAnalyzer cmd_analyzer);

    void Start(SessionNotify ready_callback, SessionNotify finished_callback, ProofReceiver receiver);

    void Stop();

    void Close();

    bool IsStopping() const;

    void CalcIters(uint64_t iters);

    uint256 const& GetChallenge() const;

private:
    uint64_t GetCurrDuration() const;

    void AsyncReadSomeNext();

    Command ParseCommand();

    void ExecuteCommand(Command const& cmd);

    void SendChallenge(uint256 const& challenge);

    void SendInitForm();

    void SendIters(uint64_t iters);

    void SendStrCmd(std::string const& cmd);

private:
    net::io_context& m_ioc;
    tcp::socket m_socket;
    uint256 m_challenge;
    TimeType m_time_type;
    std::chrono::system_clock::time_point m_start_time;
    CommandAnalyzer m_cmd_analyzer;
    SessionNotify m_ready_callback;
    SessionNotify m_finished_callback;
    ProofReceiver m_proof_receiver;
    CSocketWriter m_writer;
    Bytes m_temp;
    Bytes m_recv;
    std::vector<uint64_t> m_saved_iters;
    std::mutex m_saved_iters_mtx;
    std::atomic_bool m_ready{false};
    std::atomic_bool m_stopping{false};
};

class CTimeLord {
public:
    struct ProofRecord {
        Proof proof;
        uint64_t iters;
        uint64_t duration;
         uint256 challenge;
    };

    CTimeLord(net::io_context& ioc, std::string vdf_client_path, std::string hostname, uint16_t port);

    void Start(ProofReceiver receiver);

    void Stop();

    void GoChallenge(uint256 challenge, TimeType time_type, SessionNotify session_is_ready_callback);

    uint256 const& GetCurrentChallenge() const;

    bool QueryIters(uint256 const& challenge, uint64_t iters, ProofRecord& out);

    void CalcIters(uint256 const& challenge, uint64_t iters);

    void Wait();

private:
    void AcceptNext();

    void StopAllSessions();

    void HandleSessionIsFinished(CTimeSessionPtr psession);

    void HandleProof(Proof const& proof, uint64_t iters, uint64_t duration, uint256 challenge);

private:
    net::io_context& m_ioc;
    tcp::acceptor m_acceptor;
    uint256 m_challenge;
    TimeType m_time_type;
    std::string m_hostname;
    uint16_t m_port;
    SessionNotify m_session_is_ready_callback;
    ProofReceiver m_receiver;
    std::vector<CTimeSessionPtr> m_session_vec;
    std::mutex m_session_mtx;
    CVdfClientProcManager m_proc_man;
    bool m_exiting{false};
    std::mutex m_cached_proofs_mtx;
    std::map<uint256, std::vector<ProofRecord>> m_cached_proofs;
};

}  // namespace chiapos

#endif
