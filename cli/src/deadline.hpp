#pragma once

#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <format>
#include <mutex>
#include <string>
#include <thread>

#include <spelunk/common/diagnostic.hpp>

namespace spelunk::cli {

// A CLI-only hard deadline: it also stops non-cooperative work (including
// blocked input). Core/GUI users do not acquire a process-wide timer.
class CommandDeadline {
public:
    explicit CommandDeadline(std::chrono::milliseconds budget) {
        if (budget.count() == 0) return;
        const auto end = std::chrono::steady_clock::now() + budget;
        const std::string message = std::format("command exceeded {} ms timeout", budget.count());
        const std::string message_line = diagnostic::json
            ? std::format("{{\"type\":\"error\",\"kind\":\"timeout\",\"message\":\"{}\"}}\n", message)
            : std::format("spelunk: timeout: {}\n", message);
        worker_ = std::thread([this, end, message_line] {
            std::unique_lock lock(mutex_);
            if (wake_.wait_until(lock, end, [this] { return finished_; })) return;
            // stderr may itself be a full pipe or locked by an analysis
            // thread. Give reporting a bounded grace period, never let it
            // prevent the deadline from terminating the process.
            try {
                std::thread([message_line] {
                    std::fwrite(message_line.data(), 1, message_line.size(), stderr);
                    std::fflush(stderr);
                    std::_Exit(124);
                }).detach();
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            } catch (...) {
                // Even an exhausted thread budget must not disable timeout.
            }
            // Do not run destructors concurrently with analysis or flush an
            // unfinished stdout record. Completed JSON records flush eagerly.
            std::_Exit(124);
        });
    }

    ~CommandDeadline() {
        if (!worker_.joinable()) return;
        {
            std::lock_guard lock(mutex_);
            finished_ = true;
        }
        wake_.notify_one();
        worker_.join();
    }

    CommandDeadline(const CommandDeadline&) = delete;
    CommandDeadline& operator=(const CommandDeadline&) = delete;

private:
    std::mutex mutex_;
    std::condition_variable wake_;
    bool finished_ = false;
    std::thread worker_;
};

}  // namespace spelunk::cli
