#pragma once

#include <chrono>
#include <cstdio>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <utility>

#include <ember/common/progress.hpp>

namespace ember::cli {

// Multi-line live-redrawing progress panel for long CPU-bound passes
// (corpus TEEF build, --recognize sweeps). Three lines on a TTY,
// repainted via ANSI cursor-up so there's no scrollback noise:
//
//   TEEF fingerprint (16 threads)
//     ████████████████░░░░░░░░░░░░░░░░░░░░░░░░  41.2%   58,431 / 142,000
//     rate 1247 fn/s   elapsed 47s   eta 1m 7s   skip 12%
//
// Falls back to a single carriage-return line on dumb terminals;
// silent when EMBER_QUIET=1 or stderr isn't a TTY (`progress_enabled()`).
//
// ETA uses a 5-second windowed rate so the estimate stabilizes
// quickly and tracks rate changes during heterogeneous workloads
// (small fns chew through fast, then a 500ms VM-protected dispatcher
// drops the rate - a cumulative-average ETA would lag by minutes).
//
// Float formatting goes through snprintf rather than std::format to
// avoid the libc++ 16 (macOS apple-clang job) gap on `{:.Nf}`
// specifiers - this class compiles into core indirectly via the CLI
// shim, so portable formatting matters.
class ProgressPanel {
public:
    ProgressPanel() = default;
    ~ProgressPanel() {
        if (active_) finish();
    }
    ProgressPanel(const ProgressPanel&) = delete;
    ProgressPanel& operator=(const ProgressPanel&) = delete;

    // Begin a new pass.
    void start(std::string label, std::size_t total, unsigned threads) {
        std::lock_guard lock(mu_);
        enabled_ = progress_enabled();
        active_  = true;
        label_   = std::move(label);
        total_   = total;
        threads_ = threads;
        t_start_ = std::chrono::steady_clock::now();
        samples_.clear();
        last_lines_   = 0;
        first_render_ = true;
        if (enabled_) {
            // Initial header so the user sees something immediately
            // even before the first tick lands.
            render_locked(0, 0, t_start_, /*final=*/false);
        } else {
            std::fprintf(stderr, "ember: %s - %zu items on %u thread%s\n",
                         label_.c_str(), total_, threads_,
                         threads_ == 1 ? "" : "s");
            std::fflush(stderr);
        }
    }

    // Update with done/skip counts. Safe to call from a single ticker
    // thread; not safe to call concurrently with itself or finish().
    void tick(std::size_t done, std::size_t skip = 0) {
        if (!active_) return;
        const auto now = std::chrono::steady_clock::now();
        std::lock_guard lock(mu_);
        push_sample_locked(now, done);
        if (enabled_) render_locked(done, skip, now, /*final=*/false);
    }

    // Final summary frame. Leaves the panel in scrollback so the user
    // can see the completed run.
    void finish(std::size_t done = 0, std::size_t skip = 0) {
        std::lock_guard lock(mu_);
        if (!active_) return;
        if (done == 0) done = total_;
        const auto now = std::chrono::steady_clock::now();
        push_sample_locked(now, done);
        if (enabled_) {
            render_locked(done, skip, now, /*final=*/true);
        } else {
            const double elapsed =
                std::chrono::duration<double>(now - t_start_).count();
            const double rate = elapsed > 0.0
                ? static_cast<double>(done) / elapsed : 0.0;
            char buf[256];
            std::snprintf(buf, sizeof(buf),
                "ember: %s done - %zu items in %s (%.0f/s)\n",
                label_.c_str(), done,
                fmt_duration(elapsed).c_str(), rate);
            std::fputs(buf, stderr);
            std::fflush(stderr);
        }
        active_ = false;
    }

private:
    struct Sample {
        std::chrono::steady_clock::time_point t;
        std::size_t done;
    };

    void push_sample_locked(std::chrono::steady_clock::time_point t,
                            std::size_t done) {
        samples_.push_back({t, done});
        // Keep a 5-second rolling window for rate computation.
        while (samples_.size() > 1 &&
               std::chrono::duration<double>(t - samples_.front().t).count() > 5.0) {
            samples_.pop_front();
        }
    }

    [[nodiscard]] double windowed_rate_locked() const {
        if (samples_.size() < 2) return 0.0;
        const auto& a = samples_.front();
        const auto& b = samples_.back();
        const double dt = std::chrono::duration<double>(b.t - a.t).count();
        if (dt <= 0.0) return 0.0;
        if (b.done < a.done) return 0.0;
        return static_cast<double>(b.done - a.done) / dt;
    }

    static std::string fmt_duration(double s) {
        char buf[32];
        if (s < 1.0) {
            std::snprintf(buf, sizeof(buf), "%dms", static_cast<int>(s * 1000.0));
        } else if (s < 60.0) {
            std::snprintf(buf, sizeof(buf), "%ds", static_cast<int>(s));
        } else if (s < 3600.0) {
            const int m = static_cast<int>(s) / 60;
            const int rem_s = static_cast<int>(s) % 60;
            std::snprintf(buf, sizeof(buf), "%dm %ds", m, rem_s);
        } else {
            const int h = static_cast<int>(s) / 3600;
            const int rem_m = (static_cast<int>(s) / 60) % 60;
            std::snprintf(buf, sizeof(buf), "%dh %dm", h, rem_m);
        }
        return buf;
    }

    static std::string fmt_count(std::size_t n) {
        // Thousands-separator formatting - easier to scan
        // 142,857 than 142857 at a glance.
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%zu", n);
        const std::size_t len = std::strlen(buf);
        std::string out;
        out.reserve(len + len / 3);
        for (std::size_t i = 0; i < len; ++i) {
            if (i > 0 && (len - i) % 3 == 0) out += ',';
            out += buf[i];
        }
        return out;
    }

    void erase_prior_locked() {
        if (first_render_ || last_lines_ == 0) return;
        // Move to start of first rendered line, then clear from cursor
        // to the end of the screen - single repaint with no flicker.
        std::fputc('\r', stderr);
        for (int i = 0; i < last_lines_ - 1; ++i) {
            std::fputs("\033[1A", stderr);
        }
        std::fputs("\033[J", stderr);
    }

    void render_locked(std::size_t done, std::size_t skip,
                       std::chrono::steady_clock::time_point now, bool final) {
        const double elapsed =
            std::chrono::duration<double>(now - t_start_).count();
        const double rate = windowed_rate_locked();
        const double eta  = (rate > 0.0 && total_ > done)
                          ? static_cast<double>(total_ - done) / rate : 0.0;
        const double pct  = total_ > 0
                          ? 100.0 * static_cast<double>(done)
                                  / static_cast<double>(total_) : 0.0;

        constexpr int kBarCells = 40;
        const std::size_t safe_total = total_ > 0 ? total_ : 1;
        int filled = static_cast<int>(
            (static_cast<double>(kBarCells) * static_cast<double>(done))
            / static_cast<double>(safe_total));
        if (filled < 0) filled = 0;
        if (filled > kBarCells) filled = kBarCells;

        std::string bar;
        bar.reserve(static_cast<std::size_t>(kBarCells) * 3);
        for (int i = 0; i < kBarCells; ++i) {
            bar += (i < filled) ? "█" : "░";  // █ ░
        }

        // ANSI styles. Cyan label, green bar, dim stats.
        constexpr const char* kCyan  = "\033[36m";
        constexpr const char* kGreen = "\033[32m";
        constexpr const char* kDim   = "\033[2m";
        constexpr const char* kReset = "\033[0m";

        erase_prior_locked();
        first_render_ = false;

        char hdr[256];
        std::snprintf(hdr, sizeof(hdr),
            "%s%s%s %s(%u thread%s)%s",
            kCyan, label_.c_str(), kReset,
            kDim, threads_, threads_ == 1 ? "" : "s", kReset);
        std::fputs(hdr, stderr);
        std::fputc('\n', stderr);

        char bar_line[512];
        std::snprintf(bar_line, sizeof(bar_line),
            "  %s%s%s %5.1f%%   %s / %s",
            kGreen, bar.c_str(), kReset, pct,
            fmt_count(done).c_str(), fmt_count(total_).c_str());
        std::fputs(bar_line, stderr);
        std::fputc('\n', stderr);

        // "-" placeholder when rate/eta aren't meaningful yet (cold
        // start, only one sample) or no longer apply (done == total).
        char rate_buf[32];
        if (rate > 0.0) std::snprintf(rate_buf, sizeof(rate_buf), "%.0f/s", rate);
        else            std::snprintf(rate_buf, sizeof(rate_buf), "-");
        char eta_buf[32];
        if (done >= total_)        std::snprintf(eta_buf, sizeof(eta_buf), "-");
        else if (rate > 0.0)       std::snprintf(eta_buf, sizeof(eta_buf), "%s",
                                                 fmt_duration(eta).c_str());
        else                       std::snprintf(eta_buf, sizeof(eta_buf), "-");

        char stat_line[512];
        if (skip > 0 && done > 0) {
            const double pct_skip =
                100.0 * static_cast<double>(skip) / static_cast<double>(done);
            std::snprintf(stat_line, sizeof(stat_line),
                "  %srate%s %s   %selapsed%s %s   %seta%s %s   "
                "%sskip%s %.0f%%",
                kDim, kReset, rate_buf,
                kDim, kReset, fmt_duration(elapsed).c_str(),
                kDim, kReset, eta_buf,
                kDim, kReset, pct_skip);
        } else {
            std::snprintf(stat_line, sizeof(stat_line),
                "  %srate%s %s   %selapsed%s %s   %seta%s %s",
                kDim, kReset, rate_buf,
                kDim, kReset, fmt_duration(elapsed).c_str(),
                kDim, kReset, eta_buf);
        }
        std::fputs(stat_line, stderr);
        last_lines_ = 3;
        if (final) std::fputc('\n', stderr);
        std::fflush(stderr);
    }

    bool        active_       = false;
    bool        enabled_      = false;
    bool        first_render_ = true;
    int         last_lines_   = 0;
    std::string label_;
    std::size_t total_   = 0;
    unsigned    threads_ = 1;
    std::chrono::steady_clock::time_point t_start_;
    std::deque<Sample> samples_;
    std::mutex  mu_;
};

}  // namespace ember::cli
