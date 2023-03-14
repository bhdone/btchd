#ifndef TIMELORD_CLIENT_H
#define TIMELORD_CLIENT_H

#include <functional>

#include <vector>
#include <deque>
#include <map>

#include <boost/asio.hpp>
namespace asio = boost::asio;
using asio::ip::tcp;

using error_code = boost::system::error_code;

#include <uint256.h>

#include <chiapos/bhd_types.h>

class UniValue;

class FrontEndClient
{
public:
    enum class ErrorType { CONN, READ, WRITE, CLOSE };
    using ConnectionHandler = std::function<void()>;
    using MessageHandler = std::function<void(UniValue const&)>;
    using ErrorHandler = std::function<void(ErrorType err_type, std::string const& errs)>;
    using CloseHandler = std::function<void()>;

    explicit FrontEndClient(asio::io_context& ioc);

    void SetConnectionHandler(ConnectionHandler conn_handler);

    void SetMessageHandler(MessageHandler msg_handler);

    void SetErrorHandler(ErrorHandler err_handler);

    void SetCloseHandler(CloseHandler close_handler);

    void Connect(std::string const& host, unsigned short port);

    bool SendMessage(UniValue const& msg);

    void SendShutdown();

    void Exit();

private:
    void DoReadNext();

    void DoSendNext();

    asio::io_context& ioc_;
    std::unique_ptr<tcp::socket> ps_;
    asio::streambuf read_buf_;
    std::vector<uint8_t> send_buf_;
    std::deque<std::string> sending_msgs_;
    ConnectionHandler conn_handler_;
    MessageHandler msg_handler_;
    ErrorHandler err_handler_;
    CloseHandler close_handler_;
};

struct ProofDetail {
    Bytes y;
    Bytes proof;
    uint8_t witness_type;
    uint64_t iters;
    int duration;
};

using ProofReceiver = std::function<void(uint256 const& challenge, ProofDetail const& detail)>;

class TimelordClient
{
public:
    using ConnectionHandler = std::function<void()>;
    using ErrorHandler = std::function<void(FrontEndClient::ErrorType type, std::string const& errs)>;
    using MessageHandler = std::function<void(UniValue const& msg)>;

    explicit TimelordClient(asio::io_context& ioc);

    void SetConnectionHandler(ConnectionHandler conn_handler);

    void SetErrorHandler(ErrorHandler err_handler);

    void SetProofReceiver(ProofReceiver proof_receiver);

    bool Calc(uint256 const& challenge, uint64_t iters);

    void Connect(std::string const& host, unsigned short port);

    void Exit();

    void RequestServiceShutdown();

private:
    void DoWriteNextPing();

    void DoWaitPong();

    void HandleConnect();

    void HandleMessage(UniValue const& msg);

    void HandleMessage_Pong(UniValue const& msg);

    void HandleMessage_Proof(UniValue const& msg);

    void HandleMessage_CalcReply(UniValue const& msg);

    void HandleError(FrontEndClient::ErrorType type, std::string const& errs);

    void HandleClose();

    asio::io_context& ioc_;
    FrontEndClient client_;
    std::map<int, MessageHandler> msg_handlers_;
    asio::steady_timer timer_pingpong_;
    std::unique_ptr<asio::steady_timer> ptimer_waitpong_;
    ConnectionHandler conn_handler_;
    ErrorHandler err_handler_;
    ProofReceiver proof_receiver_;
};

#endif
