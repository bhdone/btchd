#include "timelord.h"

#include <chiapos/kernel/utils.h>
#include <chiapos/kernel/vdf.h>
#include <compat/byteswap.h>
#include <plog/Log.h>
#include <vdf_computer.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

using std::placeholders::_1;
using std::placeholders::_2;
using std::placeholders::_3;
using std::placeholders::_4;

namespace chiapos {

namespace {

Command AnalyzeStrCmd(Bytes const& buf, char const* cmd_str, Command::CommandType type) {
    PLOG_DEBUG << "checking command: " << cmd_str;
    Command res;
    if (buf.size() < std::strlen(cmd_str)) {
        return res;
    }
    if (std::memcmp(buf.data(), cmd_str, std::strlen(cmd_str)) == 0) {
        PLOG_DEBUG << "recv command: " << cmd_str;
        res.body = cmd_str;
        res.type = type;
        res.consumed = res.body.size();
    }
    return res;
}

uint64_t bswap_common(uint64_t x) { return __bswap_64(x); }

uint32_t bswap_common(uint32_t x) { return __bswap_32(x); }

struct Slice {
    uint8_t const* p{nullptr};
    std::size_t n{0};
};

Slice MakeSlice(Bytes const& buf, uint64_t offset) {
    assert(offset < buf.size());
    Slice s;
    s.p = buf.data() + offset;
    s.n = buf.size() - offset;
    return s;
}

template <typename Int>
std::tuple<Int, bool> IntFromBytes(Slice const& slice) {
    if (slice.n < sizeof(Int)) {
        return std::make_tuple(0, false);
    }
    Int x;
    std::memcpy(&x, slice.p, sizeof(Int));
    return std::make_tuple(bswap_common(x), true);
}

std::tuple<Proof, uint64_t> ParseProofIters(Bytes const& buf) {
    Proof proof;
    // Analyze proof from bytes
    bool succ;
    uint64_t offset{0};
    // Read iterators
    uint64_t iters;
    std::tie(iters, succ) = IntFromBytes<uint64_t>(MakeSlice(buf, 0));
    if (!succ) {
        return std::make_tuple(proof, 0);
    }
    offset += sizeof(iters);
    // Read y
    uint64_t y_size;
    std::tie(y_size, succ) = IntFromBytes<uint64_t>(MakeSlice(buf, offset));
    if (!succ) {
        return std::make_tuple(proof, 0);
    }
    offset += sizeof(y_size);
    if (buf.size() - offset < y_size) {
        return std::make_tuple(proof, 0);
    }
    proof.y.resize(y_size);
    std::memcpy(proof.y.data(), buf.data() + offset, y_size);
    offset += y_size;
    // Read witness type
    if (buf.size() - offset == 0) {
        return std::make_tuple(proof, 0);
    }
    proof.witness_type = buf.data()[offset++];
    // Read proof
    std::size_t remain_size = buf.size() - offset;
    proof.proof.resize(remain_size);
    std::memcpy(proof.proof.data(), buf.data() + offset, remain_size);
    // Return proof
    PLOG_DEBUG << "proof is received:";
    PLOG_DEBUG << "== y(len=" << proof.y.size() << "): " << BytesToHex(proof.y);
    PLOG_DEBUG << "== proof(len=" << proof.proof.size() << "): " << BytesToHex(proof.proof);
    PLOG_DEBUG << "== witness_type: " << static_cast<int>(proof.witness_type);
    return std::make_tuple(proof, iters);
}

Bytes MakeChallengeBuf(uint256 const& challenge) {
    auto disc = vdf::utils::CreateDiscriminant(MakeBytes(challenge));
    std::string disc_str = disc.FormatString();
    int disc_size = disc_str.size();
    std::string disc_size_str = std::to_string(disc_size);
    assert(disc_size_str.size() <= 3);
    std::size_t size = disc_str.size() + 3;
    Bytes buf(size, 0);
    std::memcpy(buf.data(), disc_size_str.data(), disc_size_str.size());
    std::memcpy(buf.data() + 3, disc_str.data(), disc_str.size());
    return buf;
}

Bytes MakeFormBuf(VdfForm const& form) {
    Bytes form_buf(form.size() + 1);
    form_buf[0] = form.size();
    std::memcpy(form_buf.data() + 1, form.data(), form.size());
    return form_buf;
}

Command AnalyzeProofCommand(Bytes const& buf) {
    Command cmd;
    bool succ;
    uint32_t size;
    std::tie(size, succ) = IntFromBytes<uint32_t>(MakeSlice(buf, 0));
    if (!succ) {
        return cmd;
    }
    if (buf.size() - sizeof(size) < size) {
        return cmd;
    }
    cmd.body = std::string(buf.begin() + sizeof(size), buf.end());
    cmd.type = Command::CommandType::PROOF;
    cmd.consumed = sizeof(size) + cmd.body.size();
    return cmd;
}

class VDFCommandAnalyzer {
public:
    VDFCommandAnalyzer() {
        m_analyzers.push_back(std::bind(AnalyzeStrCmd, std::placeholders::_1, "OK", Command::CommandType::OK));
        m_analyzers.push_back(std::bind(AnalyzeStrCmd, std::placeholders::_1, "STOP", Command::CommandType::STOP));
        m_analyzers.push_back(AnalyzeProofCommand);
    }

    Command operator()(Bytes const& buf) const {
        Command cmd;
        PLOG_DEBUG << "total " << m_analyzers.size() << " analyzers";
        for (CommandAnalyzer const& analyzer : m_analyzers) {
            cmd = analyzer(buf);
            if (cmd.type != Command::CommandType::UNKNOWN) {
                break;
            }
        }
        return cmd;
    }

private:
    std::vector<CommandAnalyzer> m_analyzers;
};

}  // namespace

CVdfClientProcManager::CVdfClientProcManager(std::string vdf_client_path, std::string hostname, uint16_t port)
        : m_vdf_client_path(std::move(vdf_client_path)), m_hostname(std::move(hostname)), m_port(port) {}

void CVdfClientProcManager::NewProc() {
    PLOG_DEBUG << "creating new process: " << m_vdf_client_path << " " << m_hostname << " " << m_port;
    std::stringstream ss_cmd;
    ss_cmd << m_vdf_client_path << " " << m_hostname << " " << m_port << " 0";
    proc::child c(ss_cmd.str());
    m_children.push_back(std::move(c));
}

int CVdfClientProcManager::RemoveDeadChildren() {
    auto i = std::remove_if(std::begin(m_children), std::end(m_children),
                            [](proc::child& child) { return !child.running(); });
    int d = std::distance(i, std::end(m_children));
    m_children.erase(i, std::end(m_children));
    return d;
}

void CVdfClientProcManager::Wait() {
    PLOG_DEBUG << "waiting all processes(total " << m_children.size() << ") of vdf_client to exit...";
    for (proc::child& child : m_children) {
        child.wait();
    }
}

CSocketWriter::CSocketWriter(tcp::socket& s) : m_s(s) {}

void CSocketWriter::AsyncWrite(Bytes buff) {
    PLOG_DEBUG << "prepare to write total " << buff.size() << " bytes";
    bool do_write = m_buffs.empty();
    m_buffs.push_back(std::move(buff));
    if (do_write) {
        DoWriteNext();
    }
}

void CSocketWriter::DoWriteNext() {
    assert(!m_buffs.empty());
    Bytes const& buf = m_buffs.front();
    net::async_write(m_s, net::buffer(buf), [this](boost::system::error_code const& ec, std::size_t size) {
        if (ec) {
            PLOG_ERROR << "write error: " << ec.message();
            return;
        }
        PLOG_DEBUG << "total wrote " << size << " bytes";
        m_buffs.pop_front();
        if (!m_buffs.empty()) {
            DoWriteNext();
        }
    });
}

std::string TimeTypeToString(TimeType type) {
    switch (type) {
        case TimeType::S:
            return "S";
        case TimeType::N:
            return "N";
        case TimeType::T:
            return "T";
    }
    return "(error-timetype)";
}

CTimeSession::CTimeSession(net::io_context& ioc, tcp::socket&& s, uint256 challenge, TimeType time_type, CommandAnalyzer cmd_analyzer)
        : m_ioc(ioc),
          m_socket(std::move(s)),
          m_challenge(std::move(challenge)),
          m_time_type(time_type),
          m_cmd_analyzer(std::move(cmd_analyzer)),
          m_writer(m_socket),
          m_temp(4096, 0) {}

void CTimeSession::Start(SessionNotify ready_callback, SessionNotify finished_callback, ProofReceiver receiver) {
    PLOG_DEBUG << "session start with challenge: " << m_challenge.GetHex();
    m_ready_callback = std::move(ready_callback);
    m_finished_callback = std::move(finished_callback);
    m_proof_receiver = std::move(receiver);
    // type
    SendStrCmd(TimeTypeToString(m_time_type));
    // challenge
    SendChallenge(m_challenge);
    // initial form (zero)
    SendInitForm();
    // Start to read
    AsyncReadSomeNext();
}

void CTimeSession::Stop() {
    if (m_stopping) {
        return;
    }
    m_stopping = true;
    // wait 5 seconds and close this session if it still exists
    auto timer = std::make_shared<net::deadline_timer>(m_ioc);
    timer->expires_from_now(boost::posix_time::seconds(5));
    auto weak_self = std::weak_ptr<CTimeSession>(shared_from_this());
    timer->async_wait([timer, weak_self](boost::system::error_code const& ec) {
        if (ec) {
            // error occurs
            PLOG_ERROR << "error when wait to close a session: " << ec.message();
            return;
        }
        if (!weak_self.expired()) {
            auto self = weak_self.lock();
            PLOG_ERROR << "force to close a session";
            self->Close(); // force to close the session
        } else {
            PLOG_DEBUG << "the session is already deleted, cannot force to close it, skipping...";
        }
    });
    // Tell the vdf_client to quit
    PLOG_DEBUG << "sending iters=0 to stop the session";
    CalcIters(0);
}

void CTimeSession::Close() {
    boost::system::error_code ignored_ec;
    m_socket.shutdown(tcp::socket::shutdown_both, ignored_ec);
    m_socket.close(ignored_ec);
}

bool CTimeSession::IsStopping() const { return m_stopping; }

void CTimeSession::CalcIters(uint64_t iters) {
    if (!m_ready) {
        PLOG_WARNING << "trying to start a calculation on an unprepared session, send it later... challenge="
                     << m_challenge.GetHex() << ", iters=" << iters;
        std::lock_guard<std::mutex> lg(m_saved_iters_mtx);
        m_saved_iters.push_back(iters);
        return;
    }
    SendIters(iters);
}

uint256 const& CTimeSession::GetChallenge() const {
    return m_challenge;
}

uint64_t CTimeSession::GetCurrDuration() const {
    auto now = std::chrono::system_clock::now();
    uint64_t duration = std::chrono::duration_cast<std::chrono::seconds>(now - m_start_time).count();
    return duration;
}

void CTimeSession::AsyncReadSomeNext() {
    auto self = shared_from_this();
    m_socket.async_read_some(net::buffer(m_temp), [self](boost::system::error_code const& ec, std::size_t size) {
        if (ec) {
            if (ec != net::error::eof) {
                // Only show the error message when it isn't `eof`.
                PLOG_ERROR << "error occurs when reading: " << ec.message();
            }
            self->m_finished_callback(self);
            return;
        }
        if (size) {
            PLOG_DEBUG << "total read " << size << " bytes";
            std::size_t original_size = self->m_recv.size();
            self->m_recv.resize(self->m_recv.size() + size);
            memcpy(self->m_recv.data() + original_size, self->m_temp.data(), size);
            PLOG_DEBUG << "m_recv.size()=" << self->m_recv.size();
            // Parse and run command
            self->ExecuteCommand(self->ParseCommand());
        }
        self->AsyncReadSomeNext();
    });
}

Command CTimeSession::ParseCommand() {
    PLOG_DEBUG << "analyzing command: " << m_recv[0] << m_recv[1];
    Command cmd = m_cmd_analyzer(m_recv);
    if (cmd.type != Command::CommandType::UNKNOWN) {
        assert(cmd.body.empty() == false && cmd.consumed != 0 && cmd.consumed >= cmd.body.size());
        Bytes new_recv(m_recv.size() - cmd.consumed);
        memcpy(new_recv.data(), m_recv.data() + cmd.consumed, m_recv.size() - cmd.consumed);
        m_recv = new_recv;
    }
    PLOG_DEBUG << "parsed command: " << Command::CommandTypeToString(cmd.type) << ", remains " << m_recv.size()
               << " bytes";
    return cmd;
}

void CTimeSession::ExecuteCommand(Command const& cmd) {
    PLOG_DEBUG << "execute command: " << Command::CommandTypeToString(cmd.type);
    if (cmd.type == Command::CommandType::OK) {
        // The session is ready for iters
        PLOG_DEBUG << "ready to send iters";
        m_start_time = std::chrono::system_clock::now();
        m_ready = true;
        {
            std::lock_guard<std::mutex> lg(m_saved_iters_mtx);
            for (uint64_t iters : m_saved_iters) {
                CalcIters(iters);
            }
            m_saved_iters.clear();
        }
        m_ready_callback(shared_from_this());
    } else if (cmd.type == Command::CommandType::STOP) {
        // The vdf_client is about to close, we should close current session as well
        SendStrCmd("ACK");
        PLOG_DEBUG << "shutdown socket";
        boost::system::error_code ignored_ec;
        m_socket.shutdown(tcp::socket::shutdown_receive, ignored_ec);
    } else if (cmd.type == Command::CommandType::PROOF) {
        // Analyze the proof back and invoke the receiver
        PLOG_DEBUG << "proof is ready";
        Proof proof;
        uint64_t iters;
        std::tie(proof, iters) = ParseProofIters(BytesFromHex(cmd.body));
        m_proof_receiver(proof, iters, GetCurrDuration(), m_challenge);
    }
}

void CTimeSession::SendChallenge(uint256 const& challenge) {
    PLOG_DEBUG << "sending challenge: " << challenge.GetHex();
    Bytes challenge_buf = MakeChallengeBuf(challenge);
    m_writer.AsyncWrite(std::move(challenge_buf));
}

void CTimeSession::SendInitForm() {
    PLOG_DEBUG << "sending initial form";
    Bytes initial_form = MakeFormBuf(MakeZeroForm());
    m_writer.AsyncWrite(std::move(initial_form));
}

void CTimeSession::SendIters(uint64_t iters) {
    PLOG_DEBUG << "sending iters: " << iters;
    std::string iters_str = std::to_string(iters);
    std::string size_str = std::to_string(iters_str.size());
    if (size_str.size() == 1) {
        size_str = std::string("0") + size_str;
    }
    PLOG_DEBUG << "size_str: " << size_str;
    Bytes buf(2 + iters_str.size(), '\0');
    std::memcpy(buf.data(), size_str.data(), 2);
    std::memcpy(buf.data() + 2, iters_str.data(), iters_str.size());
    m_writer.AsyncWrite(std::move(buf));
}

void CTimeSession::SendStrCmd(std::string const& cmd) {
    PLOG_DEBUG << "sending str command: " << cmd;
    Bytes buf(cmd.size(), '\0');
    std::memcpy(buf.data(), cmd.data(), cmd.size());
    m_writer.AsyncWrite(std::move(buf));
}

CTimeLord::CTimeLord(net::io_context& ioc, std::string vdf_client_path, std::string hostname, uint16_t port)
        : m_ioc(ioc),
          m_acceptor(ioc),
          m_hostname(std::move(hostname)),
          m_port(port),
          m_proc_man(vdf_client_path, m_hostname, m_port) {}

void CTimeLord::Start(ProofReceiver receiver) {
    PLOG_DEBUG << "preparing...";
    m_receiver = std::move(receiver);
    // start listening
    tcp::endpoint endpoint(net::ip::address::from_string(m_hostname), m_port);
    m_acceptor.open(endpoint.protocol());
    m_acceptor.set_option(tcp::acceptor::reuse_address(true));
    m_acceptor.bind(endpoint);
    m_acceptor.listen();
    // Listen to next session
    AcceptNext();
}

void CTimeLord::Stop() {
    // Tell all client to stop
    PLOG_DEBUG << "stopping... total " << m_session_vec.size() << " session(s)";
    m_exiting = true;
    boost::system::error_code ignored_ec;
    m_acceptor.close(ignored_ec);
    StopAllSessions();
}

void CTimeLord::GoChallenge(uint256 challenge, TimeType time_type, SessionNotify session_is_ready_callback) {
    PLOG_DEBUG << "challenge is changed " << challenge.GetHex();
    m_challenge = std::move(challenge);
    m_time_type = time_type;
    m_session_is_ready_callback = std::move(session_is_ready_callback);
    // Notify to exit for all connected sessions
    StopAllSessions();
    // Waiting for 5 seconds to remove all dead processes
    auto timer = std::make_shared<net::deadline_timer>(m_ioc);
    timer->expires_from_now(boost::posix_time::seconds(5));
    timer->async_wait([this, timer](boost::system::error_code const& ec) {
        int num_removed = m_proc_man.RemoveDeadChildren();
        PLOG_DEBUG << "removed total " << num_removed << " dead child(children), " << m_proc_man.GetCount() << " child(children) remain(s)";
    });
    // Create new process
    m_proc_man.NewProc();
}

uint256 const& CTimeLord::GetCurrentChallenge() const { return m_challenge; }

bool CTimeLord::QueryIters(uint256 const& challenge, uint64_t iters, ProofRecord& out) {
    std::lock_guard<std::mutex> _guard(m_cached_proofs_mtx);
    auto i = m_cached_proofs.find(challenge);
    if (i == std::end(m_cached_proofs)) {
        return false;
    }
    auto j = std::find_if(std::begin(i->second), std::end(i->second), [iters](ProofRecord const& proof_record) {
        return iters == proof_record.iters;
    });
    if (j == std::end(i->second)) {
        return false;
    }
    out = *j;
    return true;
}

void CTimeLord::CalcIters(uint256 const& challenge, uint64_t iters) {
    {
        std::lock_guard<std::mutex> lg(m_session_mtx);
        for (CTimeSessionPtr psession : m_session_vec) {
            if (!psession->IsStopping() && psession->GetChallenge() == challenge) {
                psession->CalcIters(iters);
                return; // There should has only 1 session to do the job
            }
        }
    }
    // we cannot find a valid session for the challenge
    PLOG_DEBUG << "There is no session for challenge: " << challenge.GetHex()
        << ", iters=" << chiapos::FormatNumberStr(std::to_string(iters));
}

void CTimeLord::Wait() {
    PLOG_DEBUG << "waiting all processes to exit";
    m_proc_man.Wait();
}

void CTimeLord::AcceptNext() {
    m_acceptor.async_accept([this](boost::system::error_code const& ec, tcp::socket peer) {
        if (ec) {
            PLOG_ERROR << "error occurs when accepting next session... " << ec.message();
        } else {
            PLOG_DEBUG << "new session is established";
            // Create new session
            std::lock_guard<std::mutex> lg(m_session_mtx);
            auto new_session =
                    std::make_shared<CTimeSession>(m_ioc, std::move(peer), m_challenge, m_time_type, VDFCommandAnalyzer());
            new_session->Start(m_session_is_ready_callback,
                               std::bind(&CTimeLord::HandleSessionIsFinished, this, std::placeholders::_1),
                               std::bind(&CTimeLord::HandleProof, this, _1, _2, _3, _4));
            m_session_vec.push_back(new_session);
        }
        // Next
        if (!m_exiting) {
            AcceptNext();
        }
    });
}

void CTimeLord::StopAllSessions() {
    std::lock_guard<std::mutex> lg(m_session_mtx);
    for (CTimeSessionPtr psession : m_session_vec) {
        psession->Stop();
    }
}

void CTimeLord::HandleSessionIsFinished(CTimeSessionPtr psession) {
    m_ioc.post([this, psession]() {
        std::lock_guard<std::mutex> lg(m_session_mtx);
        auto i = std::remove(std::begin(m_session_vec), std::end(m_session_vec), psession);
        if (i != std::end(m_session_vec)) {
            m_session_vec.erase(i);
            PLOG_DEBUG << "session is removed, " << m_session_vec.size() << " session(s) left";
        }
    });
}

void CTimeLord::HandleProof(Proof const& proof, uint64_t iters, uint64_t duration, uint256 challenge) {
    {
        // Cache the proof
        std::lock_guard<std::mutex> _guard(m_cached_proofs_mtx);
        auto i = m_cached_proofs.find(challenge);
        if (i == std::end(m_cached_proofs)) {
            m_cached_proofs[challenge] = {};
            i = m_cached_proofs.find(challenge); // Re-assign the iterator
        }
        ProofRecord proof_record;
        proof_record.proof = proof;
        proof_record.iters = iters;
        proof_record.duration = duration;
        proof_record.challenge = challenge;
        i->second.push_back(proof_record);
    }
    // Invoke callback
    m_receiver(proof, iters, duration, challenge);
}

}  // namespace chiapos
