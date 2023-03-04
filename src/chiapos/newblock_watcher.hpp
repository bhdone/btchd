#ifndef CHIATIMER_HPP
#define CHIATIMER_HPP

#include <atomic>
#include <thread>
#include <memory>
#include <chrono>
#include <functional>

#include <boost/asio.hpp>
namespace asio = boost::asio;
using error_code = boost::system::error_code;

#include <logging.h>

namespace chiapos {

class NewBlockWatcher {
public:
    using NewTipDetector = std::function<bool()>;
    using TimeoutHandler = std::function<void()>;

    NewBlockWatcher() : timer_(ioc_) {}

    bool IsRunning() const { return running_; }

    void Start() {
        running_ = true;
        DoWait1Sec();
        pthread_.reset(new std::thread(std::bind(&NewBlockWatcher::ThreadProc, this)));
    }

    void WaitForBlock(int timeout_secs, TimeoutHandler timeout_handler, NewTipDetector detector) {
        asio::post(ioc_, [this, timeout_secs, timeout_handler, detector]() {
            WaitEntry entry;
            entry.start_time = time(nullptr);
            entry.secs_to_wait = timeout_secs;
            entry.timeout_handler = timeout_handler;
            entry.detector = detector;
            entry.del = false;
            wait_entries_.push_back(std::move(entry));
        });
    }

    void Exit() {
        error_code ignored_ec;
        timer_.cancel(ignored_ec);
        if (pthread_ && pthread_->joinable()) {
            pthread_->join();
        }
    }

private:
    void DoWait1Sec() {
        timer_.expires_after(std::chrono::seconds(1));
        timer_.async_wait([this](error_code const& ec) {
            if (ec) {
                LogPrintf("%s error occurs: %s\n", __func__, ec.message());
                running_ = false;
                return;
            }
            time_t now = time(nullptr);
            for (auto& entry : wait_entries_) {
                time_t secs_passed = now - entry.start_time;
                if (secs_passed >= entry.secs_to_wait || entry.detector()) {
                    entry.del = true;
                    try {
                        entry.timeout_handler();
                    } catch (std::exception const& e) {
                        LogPrintf("%s: %s\n", __func__, e.what());
                    }
                }
            }
            auto it = std::remove_if(std::begin(wait_entries_), std::end(wait_entries_),
                                     [](WaitEntry const& entry) { return entry.del; });
            wait_entries_.erase(it, std::end(wait_entries_));
            DoWait1Sec();
        });
    }

    void ThreadProc() {
        LogPrintf("%s: Starting IO...\n", __func__);
        ioc_.run();
        LogPrintf("%s: Exit.\n", __func__);
    }

    asio::io_context ioc_;
    asio::steady_timer timer_;
    std::atomic_bool running_{false};
    std::unique_ptr<std::thread> pthread_;

    struct WaitEntry {
        time_t start_time;
        int secs_to_wait;
        TimeoutHandler timeout_handler;
        NewTipDetector detector;
        bool del{false};
    };
    std::vector<WaitEntry> wait_entries_;
};

}  // namespace chiapos

#endif
