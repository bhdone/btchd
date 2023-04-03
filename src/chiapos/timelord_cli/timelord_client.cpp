#include "timelord_client.h"

#include <chiapos/kernel/utils.h>

#include <univalue.h>

#include <tinyformat.h>
#include <plog/Log.h>

#include <memory>

#include "msg_ids.h"

static int const SECONDS_TO_PING = 60;
static int const WAIT_PONG_TIMEOUT_SECONDS = 10;

using std::placeholders::_1;

FrontEndClient::FrontEndClient(asio::io_context& ioc) : ioc_(ioc), s_(ioc) {}

void FrontEndClient::Connect(std::string const& host, unsigned short port, ConnectionHandler conn_handler,
                             MessageHandler msg_handler, ErrorHandler err_handler) {
    if (st_ != Status::READY) {
        throw std::runtime_error("the client is not ready");
    }
    st_ = Status::CONNECTING;
    assert(conn_handler);
    assert(msg_handler);
    assert(err_handler);
    conn_handler_ = std::move(conn_handler);
    msg_handler_ = std::move(msg_handler);
    err_handler_ = std::move(err_handler);
    // solve the address
    tcp::resolver r(ioc_);
    try {
        tcp::resolver::query q(std::string(host), std::to_string(port));
        auto it_result = r.resolve(q);
        if (it_result == std::end(tcp::resolver::results_type())) {
            // cannot resolve the ip from host name
            asio::post(ioc_, [this, host]() {
                PLOGE << tinyformat::format("Failed to resolve host=%s", host);
                err_handler_(FrontEndClient::ErrorType::CONN, "cannot resolve host");
            });
            return;
        }
        // retrieve the first result and start the connection
        s_.async_connect(*it_result, [this](error_code const& ec) {
            if (ec) {
                PLOGE << tinyformat::format("Error on connect: %s", ec.message());
                st_ = Status::CLOSED;
                err_handler_(FrontEndClient::ErrorType::CONN, ec.message());
                return;
            }
            st_ = Status::CONNECTED;
            DoReadNext();
            conn_handler_();
        });
    } catch (std::exception const& e) {
        PLOGE << tinyformat::format("error on connecting, %s", e.what());
    }
}

bool FrontEndClient::SendMessage(UniValue const& msg) {
    if (st_ != Status::CONNECTED) {
        return false;
    }
    asio::post(ioc_, [this, msg]() {
        bool do_send = sending_msgs_.empty();
        sending_msgs_.push_back(msg.write());
        if (do_send) {
            DoSendNext();
        }
    });
    return true;
}

void FrontEndClient::Exit() {
    if (st_ == Status::CLOSED || st_ == Status::READY) {
        return;
    }
    st_ = Status::CLOSED;
    asio::post(ioc_, [this]() {
        error_code ignored_ec;
        s_.shutdown(tcp::socket::shutdown_both, ignored_ec);
        s_.close(ignored_ec);
    });
}

void FrontEndClient::DoReadNext() {
    asio::async_read_until(s_, read_buf_, '\0', [this](error_code const& ec, std::size_t bytes) {
        if (ec) {
            if (ec != asio::error::operation_aborted && ec != asio::error::eof) {
                PLOGE << tinyformat::format("read error, %s", ec.message());
                err_handler_(FrontEndClient::ErrorType::READ, ec.message());
            }
            return;
        }
        std::string result = static_cast<char const*>(read_buf_.data().data());
        read_buf_.consume(bytes);
        try {
            UniValue msg;
            msg.read(result);
            msg_handler_(msg);
        } catch (std::exception const& e) {
            PLOGE << tinyformat::format("read error, %s, total read=%d bytes", e.what(), bytes);
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
    asio::async_write(s_, asio::buffer(send_buf_), [this](error_code const& ec, std::size_t bytes) {
        if (ec) {
            err_handler_(FrontEndClient::ErrorType::WRITE, ec.message());
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

bool TimelordClient::Calc(uint256 const& challenge, uint64_t iters, Bytes const& farmer_pk, uint256 const& group_hash,
                          uint64_t total_size) {
    UniValue msg(UniValue::VOBJ);
    msg.pushKV("id", static_cast<int>(TimelordClientMsgs::CALC));
    msg.pushKV("challenge", challenge.GetHex());
    msg.pushKV("iters", iters);
    UniValue netspace(UniValue::VOBJ);
    netspace.pushKV("farmer_pk", chiapos::BytesToHex(farmer_pk));
    netspace.pushKV("group_hash", group_hash.GetHex());
    netspace.pushKV("total_size", total_size);
    msg.pushKV("netspace", netspace);
    return client_.SendMessage(msg);
}

void TimelordClient::Connect(std::string const& host, unsigned short port) {
    client_.Connect(
            host, port,
            [this]() {
                conn_handler_();
                DoWriteNextPing();
            },
            [this](UniValue const& msg) {
                auto msg_id = msg["id"].get_int();
                PLOGD << tinyformat::format("(timelord): msgid=%s",
                                            TimelordMsgIdToString(static_cast<TimelordMsgs>(msg_id)));
                auto it = msg_handlers_.find(msg_id);
                if (it != std::end(msg_handlers_)) {
                    it->second(msg);
                }
            },
            [this](FrontEndClient::ErrorType type, std::string const& errs) { err_handler_(type, errs); });
}

void TimelordClient::Exit() {
    asio::post(ioc_, [this]() {
        error_code ignored_ec;
        timer_pingpong_.cancel(ignored_ec);
    });
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
        if (client_.SendMessage(msg)) {
            DoWaitPong();
            DoWriteNextPing();
        }
    });
}

void TimelordClient::DoWaitPong() {
    ptimer_waitpong_.reset(new asio::steady_timer(ioc_));
    ptimer_waitpong_->expires_after(std::chrono::seconds(WAIT_PONG_TIMEOUT_SECONDS));
    ptimer_waitpong_->async_wait([this](error_code const& ec) {
        ptimer_waitpong_.reset();
        if (!ec) {
            // timeout, report error
            PLOGE << tinyformat::format("PONG timeout, the connection might be dead");
            err_handler_(FrontEndClient::ErrorType::READ, "PING/PONG timeout");
        }
    });
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
        PLOGE << tinyformat::format("delay challenge=%s", challenge.GetHex());
    }
}
