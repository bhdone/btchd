#include "timelord_client.h"

#include <chiapos/kernel/utils.h>
#include <plog/Log.h>
#include <univalue.h>

#include <memory>

#include "msg_ids.h"

static int const SECONDS_TO_PING = 60;
static int const WAIT_PONG_TIMEOUT_SECONDS = 10;

using std::placeholders::_1;
using std::placeholders::_2;

FrontEndClient::FrontEndClient(asio::io_context& ioc) : ioc_(ioc) {}

void FrontEndClient::SetConnectionHandler(ConnectionHandler conn_handler) { conn_handler_ = std::move(conn_handler); }

void FrontEndClient::SetMessageHandler(MessageHandler msg_handler) { msg_handler_ = std::move(msg_handler); }

void FrontEndClient::SetErrorHandler(ErrorHandler err_handler) { err_handler_ = std::move(err_handler); }

void FrontEndClient::SetCloseHandler(CloseHandler close_handler) { close_handler_ = std::move(close_handler); }

void FrontEndClient::Connect(std::string const& host, unsigned short port) {
    // solve the address
    tcp::resolver r(ioc_);
    try {
        PLOGD << "resolving ip from " << host << "...";
        tcp::resolver::query q(std::string(host), std::to_string(port));
        auto it_result = r.resolve(q);
        if (it_result == std::end(tcp::resolver::results_type())) {
            // cannot resolve the ip from host name
            throw std::runtime_error("cannot resolve hostname");
        }
        // retrieve the first result and start the connection
        PLOGD << "connecting...";
        ps_.reset(new tcp::socket(ioc_));
        ps_->async_connect(*it_result, [this](error_code const& ec) {
            PLOGD << "connected";
            if (ec) {
                PLOGE << ec.message();
                err_handler_(FrontEndClient::ErrorType::CONN, ec.message());
                return;
            }
            DoReadNext();
            conn_handler_();
        });
    } catch (std::exception const& e) {
        PLOGE << e.what();
    }
}

void FrontEndClient::SendMessage(UniValue const& msg) {
    if (ps_ == nullptr) {
        throw std::runtime_error("please connect to server before sending message");
    }
    bool do_send = sending_msgs_.empty();
    sending_msgs_.push_back(msg.write());
    if (do_send) {
        DoSendNext();
    }
}

void FrontEndClient::SendShutdown() {
    bool do_send = sending_msgs_.empty();
    sending_msgs_.push_back("shutdown");
    if (do_send) {
        DoSendNext();
    }
}

void FrontEndClient::Exit() {
    if (ps_) {
        error_code ignored_ec;
        ps_->shutdown(tcp::socket::shutdown_both, ignored_ec);
        ps_->close(ignored_ec);
        ps_.reset();
        // callback
        close_handler_();
    }
}

void FrontEndClient::DoReadNext() {
    asio::async_read_until(*ps_, read_buf_, '\0', [this](error_code const& ec, std::size_t bytes) {
        if (ec) {
            if (ec != asio::error::eof) {
                PLOGE << ec.message();
                err_handler_(FrontEndClient::ErrorType::READ, ec.message());
            }
            Exit();
            return;
        }
        std::string result = static_cast<char const*>(read_buf_.data().data());
        read_buf_.consume(bytes);
        try {
            UniValue msg;
            msg.read(result);
            msg_handler_(msg);
        } catch (std::exception const& e) {
            PLOGE << "READ: " << e.what();
            PLOGE << "DATA total=" << bytes << ": " << result;
            err_handler_(FrontEndClient::ErrorType::READ, ec.message());
        }
        DoReadNext();
    });
}

void FrontEndClient::DoSendNext() {
    assert(!sending_msgs_.empty());
    auto const& msg = sending_msgs_.front();
    send_buf_.resize(msg.size() + 1);
    memcpy(send_buf_.data(), msg.data(), msg.size());
    send_buf_[msg.size()] = '\0';
    asio::async_write(*ps_, asio::buffer(send_buf_), [this](error_code const& ec, std::size_t bytes) {
        if (ec) {
            err_handler_(FrontEndClient::ErrorType::WRITE, ec.message());
            Exit();
            return;
        }
        sending_msgs_.pop_front();
        if (!sending_msgs_.empty()) {
            DoSendNext();
        }
    });
}

TimelordClient::TimelordClient(asio::io_context& ioc) : ioc_(ioc), client_(ioc), timer_pingpong_(ioc) {
    msg_handlers_.insert(std::make_pair(static_cast<int>(TimelordMsgs::PONG),
                                        std::bind(&TimelordClient::HandleMessage_Pong, this, _1)));
    msg_handlers_.insert(std::make_pair(static_cast<int>(TimelordMsgs::PROOF),
                                        std::bind(&TimelordClient::HandleMessage_Proof, this, _1)));
    msg_handlers_.insert(std::make_pair(static_cast<int>(TimelordMsgs::CALC_REPLY),
                                        std::bind(&TimelordClient::HandleMessage_CalcReply, this, _1)));
}

void TimelordClient::SetConnectionHandler(ConnectionHandler conn_handler) { conn_handler_ = std::move(conn_handler); }

void TimelordClient::SetErrorHandler(ErrorHandler err_handler) { err_handler_ = std::move(err_handler); }

void TimelordClient::SetProofReceiver(ProofReceiver proof_receiver) { proof_receiver_ = std::move(proof_receiver); }

void TimelordClient::Calc(uint256 const& challenge, uint64_t iters) {
    UniValue msg(UniValue::VOBJ);
    msg.pushKV("id", static_cast<int>(TimelordClientMsgs::CALC));
    msg.pushKV("challenge", challenge.GetHex());
    msg.pushKV("iters", iters);
    client_.SendMessage(msg);
}

void TimelordClient::RequestServiceShutdown() { client_.SendShutdown(); }

void TimelordClient::Connect(std::string const& host, unsigned short port) {
    client_.SetConnectionHandler(std::bind(&TimelordClient::HandleConnect, this));
    client_.SetMessageHandler(std::bind(&TimelordClient::HandleMessage, this, _1));
    client_.SetErrorHandler(std::bind(&TimelordClient::HandleError, this, _1, _2));
    client_.SetCloseHandler(std::bind(&TimelordClient::HandleClose, this));
    client_.Connect(host, port);
}

void TimelordClient::Exit() {
    error_code ignored_ec;
    timer_pingpong_.cancel(ignored_ec);
    client_.Exit();
}

void TimelordClient::DoWriteNextPing() {
    timer_pingpong_.expires_after(std::chrono::seconds(SECONDS_TO_PING));
    timer_pingpong_.async_wait([this](error_code const& ec) {
        if (ec) {
            return;
        }
        UniValue msg(UniValue::VOBJ);
        msg.pushKV("id", static_cast<int>(TimelordClientMsgs::PING));
        client_.SendMessage(msg);
        DoWaitPong();
        DoWriteNextPing();
    });
}

void TimelordClient::DoWaitPong() {
    ptimer_waitpong_.reset(new asio::steady_timer(ioc_));
    ptimer_waitpong_->expires_after(std::chrono::seconds(WAIT_PONG_TIMEOUT_SECONDS));
    ptimer_waitpong_->async_wait([this](error_code const& ec) {
        if (!ec) {
            // timeout, report error
            PLOGE << "PONG timeout, the connection might be dead";
        }
        ptimer_waitpong_.reset();
    });
}

void TimelordClient::HandleConnect() {
    if (conn_handler_) {
        conn_handler_();
    }
    DoWriteNextPing();
}

void TimelordClient::HandleMessage(UniValue const& msg) {
    auto msg_id = msg["id"].get_int();
    PLOGI << "msgid: " << TimelordMsgIdToString(static_cast<TimelordMsgs>(msg_id));
    auto it = msg_handlers_.find(msg_id);
    if (it != std::end(msg_handlers_)) {
        it->second(msg);
    }
}

void TimelordClient::HandleMessage_Pong(UniValue const& msg) {
    if (ptimer_waitpong_) {
        error_code ignored_ec;
        ptimer_waitpong_->cancel(ignored_ec);
    }
}

void TimelordClient::HandleMessage_Proof(UniValue const& msg) {
    if (proof_receiver_) {
        auto challenge = uint256S(msg["challenge"].get_str());
        ProofDetail detail;
        detail.y = chiapos::BytesFromHex(msg["y"].get_str());
        detail.proof = chiapos::BytesFromHex(msg["proof"].get_str());
        detail.witness_type = msg["witness_type"].get_int();
        detail.iters = msg["iters"].get_int64();
        detail.duration = msg["duration"].get_int();
        proof_receiver_(challenge, detail);
    }
}

void TimelordClient::HandleMessage_CalcReply(UniValue const& msg) {
    bool calculating = msg["calculating"].get_bool();
    uint256 challenge = uint256S(msg["challenge"].get_str());
    if (msg.exists("y")) {
        // we got proof immediately
        ProofDetail detail;
        detail.y = chiapos::BytesFromHex(msg["y"].get_str());
        detail.proof = chiapos::BytesFromHex(msg["proof"].get_str());
        detail.witness_type = msg["witness_type"].get_int();
        detail.iters = msg["iters"].get_int64();
        detail.duration = msg["duration"].get_int();
        if (proof_receiver_) {
            proof_receiver_(challenge, detail);
        }
    } else if (!calculating) {
        PLOGE << "timelord reports that the challenge " << challenge.GetHex() << " won't be calculated";
    }
}

void TimelordClient::HandleError(FrontEndClient::ErrorType type, std::string const& errs) {
    if (err_handler_) {
        err_handler_(type, errs);
    }
}

void TimelordClient::HandleClose() {}
