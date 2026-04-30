#pragma once

#include <algorithm>
#include <cstdlib>
#include <thread>

namespace ember {

// Compute a worker thread count for parallel-fan-out passes
// (TEEF compute, CFG sweep, function discovery, etc).
//
// Honors the `EMBER_THREADS` environment variable when set: lets users
// cap thread oversubscription on shared boxes ("3 ember cascades + 1
// recognize all running, please don't spawn 16 threads each").
//
// Resolution order:
//   - If EMBER_THREADS is set to a positive integer, use that
//     (still floored at 1, capped at the caller's `default_cap`).
//   - Otherwise: min(hardware_concurrency, default_cap), floored at 1.
//
// `default_cap` is the historical per-call cap (most ember sites use
// 8 or 16) — kept so a low-spec box still gets the smaller of
// (its core count) and (the algorithm's I/O-saturation point).
[[nodiscard]] inline unsigned thread_pool_size(unsigned default_cap) noexcept {
    const unsigned hw = std::max(1u, std::thread::hardware_concurrency());
    unsigned env_cap = 0;
    if (const char* s = std::getenv("EMBER_THREADS")) {
        char* end = nullptr;
        const unsigned long v = std::strtoul(s, &end, 10);
        if (end && *end == '\0' && v > 0 && v < (1u << 20)) {
            env_cap = static_cast<unsigned>(v);
        }
    }
    const unsigned cap = env_cap ? std::min(env_cap, default_cap) : default_cap;
    return std::max(1u, std::min(hw, cap));
}

}  // namespace ember
