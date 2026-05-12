#pragma once

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string_view>

namespace ember {

// Set EMBER_TIMING=1 in the environment to surface ScopedTimer output on
// stderr. Disabled by default - the constructor reads the env var once
// per process and short-circuits both the clock read and the print, so a
// timer in a hot loop costs ~zero when the env var is unset.
[[nodiscard]] inline bool timing_enabled() noexcept {
    static const bool v = [] {
        const char* s = std::getenv("EMBER_TIMING");
        return s != nullptr && *s != '\0' && *s != '0';
    }();
    return v;
}

// RAII wall-clock timer. On scope exit, prints "[timing] <label>: <ms>"
// to stderr if timing is enabled. Use to attribute cost to phases the
// caller already labels (load, IPA, resolve_calls, format_struct, ...).
class ScopedTimer {
public:
    explicit ScopedTimer(std::string_view label) noexcept : label_(label) {
        if (timing_enabled()) start_ = std::chrono::steady_clock::now();
    }

    ~ScopedTimer() {
        if (!timing_enabled()) return;
        const auto end = std::chrono::steady_clock::now();
        const auto us  = std::chrono::duration_cast<std::chrono::microseconds>(
                            end - start_).count();
        std::fprintf(stderr, "[timing] %.*s: %lld.%03lld ms\n",
                     static_cast<int>(label_.size()), label_.data(),
                     static_cast<long long>(us / 1000),
                     static_cast<long long>(us % 1000));
    }

    ScopedTimer(const ScopedTimer&)            = delete;
    ScopedTimer& operator=(const ScopedTimer&) = delete;

private:
    std::string_view                       label_;
    std::chrono::steady_clock::time_point  start_;
};

}  // namespace ember
