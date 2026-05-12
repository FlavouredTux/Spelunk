// Process control for the perf backend. No PTRACE_* anywhere - the
// child is spawned with plain fork+execvpe, and "stop" semantics are
// driven by SIGSTOP/SIGCONT instead of tracer-side waitpid stops.
//
// stop_at_entry: best-effort. After fork the parent immediately
// SIGSTOPs the new pid; the child may already be a few user
// instructions into its new image by the time the signal is
// delivered (kernel context-switch latency), but everything stops
// before the first cont(). Unlike the ptrace path, we do NOT have
// regs at the SIGSTOP point - perf only samples on a HW BP/WP hit
// - so the first get_regs after entry returns an all-zero Registers
// with present == 0. That's the documented gap; users who need
// regs-at-entry can set a HW BP at the executable's entry address
// before resuming.
//
// pidfd_open: required so wait_event() can poll(2) on a single fd
// for process death without being the parent (matters for attach).
// The launch path could use waitpid, but using pidfd uniformly keeps
// the event loop simple.

#include "perf_target.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_pidfd_open
#  define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_send_signal
#  define SYS_pidfd_send_signal 424
#endif

extern char** environ;

namespace ember::debug::linux_perf {

namespace {

[[nodiscard]] Error errno_io(const char* op) {
    return Error::io(std::string(op) + ": " + std::strerror(errno));
}

[[nodiscard]] int sys_pidfd_open(pid_t pid) {
    return static_cast<int>(::syscall(SYS_pidfd_open, pid, 0u));
}

struct OwnedArgv {
    std::vector<char*> ptrs;
    ~OwnedArgv() { for (auto* p : ptrs) if (p) std::free(p); }
};

OwnedArgv build_argv(const std::string& program,
                     const std::vector<std::string>& args) {
    OwnedArgv a;
    a.ptrs.reserve(args.size() + 2);
    a.ptrs.push_back(::strdup(program.c_str()));
    for (const auto& s : args) a.ptrs.push_back(::strdup(s.c_str()));
    a.ptrs.push_back(nullptr);
    return a;
}

OwnedArgv build_envp(const std::vector<std::string>& env) {
    OwnedArgv a;
    a.ptrs.reserve(env.size() + 1);
    for (const auto& s : env) a.ptrs.push_back(::strdup(s.c_str()));
    a.ptrs.push_back(nullptr);
    return a;
}

addr_t parse_hex(std::string_view s) {
    addr_t v = 0;
    for (char c : s) {
        const int d = (c >= '0' && c <= '9') ? c - '0'
                    : (c >= 'a' && c <= 'f') ? c - 'a' + 10
                    : (c >= 'A' && c <= 'F') ? c - 'A' + 10
                    : -1;
        if (d < 0) break;
        v = (v << 4) | static_cast<addr_t>(d);
    }
    return v;
}

std::vector<LoadedImage> read_proc_maps(pid_t pid) {
    std::vector<LoadedImage> out;
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE* f = std::fopen(path, "r");
    if (!f) return out;

    char line[4096];
    while (std::fgets(line, sizeof(line), f)) {
        std::string_view sv(line);
        const auto path_pos = sv.find('/');
        if (path_pos == std::string_view::npos) continue;

        const auto dash = sv.find('-');
        if (dash == std::string_view::npos) continue;

        const addr_t start = parse_hex(sv.substr(0, dash));
        if (start == 0) continue;

        std::string fpath(sv.substr(path_pos));
        while (!fpath.empty() && (fpath.back() == ' ' || fpath.back() == '\t' ||
                                  fpath.back() == '\r' || fpath.back() == '\n')) {
            fpath.pop_back();
        }

        bool found = false;
        for (auto& img : out) {
            if (img.path == fpath) {
                if (start < img.base) img.base = start;
                found = true;
                break;
            }
        }
        if (!found) out.push_back({fpath, start});
    }
    std::fclose(f);
    return out;
}

std::vector<pid_t> read_task_tids(pid_t pid) {
    std::vector<pid_t> out;
    char dirpath[64];
    std::snprintf(dirpath, sizeof(dirpath), "/proc/%d/task", pid);

    DIR* d = ::opendir(dirpath);
    if (!d) return out;
    while (auto* e = ::readdir(d)) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        out.push_back(static_cast<pid_t>(std::atoi(e->d_name)));
    }
    ::closedir(d);
    return out;
}

}  // namespace

[[nodiscard]] Result<std::unique_ptr<Target>>
launch_perf(const LaunchOptions& opts) {
    if (opts.program.empty()) {
        return std::unexpected(Error::invalid_format(
            "debugger: launch: program path is empty"));
    }

    int errpipe[2] = {-1, -1};
    if (::pipe2(errpipe, O_CLOEXEC) < 0) {
        return std::unexpected(errno_io("pipe2"));
    }

    const pid_t child = ::fork();
    if (child < 0) {
        const int saved = errno;
        ::close(errpipe[0]);
        ::close(errpipe[1]);
        errno = saved;
        return std::unexpected(errno_io("fork"));
    }

    if (child == 0) {
        // ---- Child ----
        ::close(errpipe[0]);

        auto bail = [&]() {
            const int e = errno;
            ssize_t n = ::write(errpipe[1], &e, sizeof(e));
            (void)n;
            ::_exit(127);
        };

        if (!opts.cwd.empty()) {
            if (::chdir(opts.cwd.c_str()) < 0) bail();
        }

        OwnedArgv argv = build_argv(opts.program, opts.args);
        OwnedArgv envv = build_envp(opts.env);
        char** envp = opts.env.empty() ? environ : envv.ptrs.data();

        ::execvpe(opts.program.c_str(), argv.ptrs.data(), envp);
        bail();
    }

    // ---- Parent ----
    ::close(errpipe[1]);

    // Wait for the errpipe to close (= successful execve via CLOEXEC)
    // or to deliver an errno (= exec failure). MUST happen before any
    // SIGSTOP attempt: SIGSTOP'ing the child pre-exec keeps the pipe
    // open and parks us forever in this read.
    int child_errno = 0;
    ssize_t n = ::read(errpipe[0], &child_errno, sizeof(child_errno));
    ::close(errpipe[0]);
    if (n > 0 && child_errno != 0) {
        int reaped = 0;
        ::waitpid(child, &reaped, 0);
        errno = child_errno;
        return std::unexpected(errno_io("launch"));
    }

    // execve has completed in the kernel. If stop_at_entry, freeze
    // the new task NOW - the SIGSTOP is queued before the kernel's
    // final signal-check before returning to user mode at the new
    // image's _start, so the child stops before any user instruction
    // in the new image runs. Worst-case scheduling latency may let a
    // few ld.so / libc init instructions slip through; this is the
    // documented best-effort gap. Use the ptrace backend if the few-
    // instruction race matters.
    if (opts.stop_at_entry) {
        if (::kill(child, SIGSTOP) < 0 && errno != ESRCH) {
            const int saved = errno;
            ::waitpid(child, nullptr, 0);
            errno = saved;
            return std::unexpected(errno_io("kill SIGSTOP (entry)"));
        }
    }

    const int pidfd = sys_pidfd_open(child);
    if (pidfd < 0) {
        const int saved = errno;
        ::kill(child, SIGKILL);
        ::waitpid(child, nullptr, 0);
        errno = saved;
        return std::unexpected(errno_io("pidfd_open"));
    }

    auto t = std::make_unique<PerfTarget>(
        static_cast<ProcessId>(child), pidfd, /*spawned=*/true);
    auto& ts = t->thread_state(static_cast<ThreadId>(child));
    ts.paused = opts.stop_at_entry;
    return t;
}

[[nodiscard]] Result<std::unique_ptr<Target>>
attach_perf(ProcessId pid) {
    const pid_t main_tid = static_cast<pid_t>(pid);

    const int pidfd = sys_pidfd_open(main_tid);
    if (pidfd < 0) return std::unexpected(errno_io("pidfd_open"));

    auto t = std::make_unique<PerfTarget>(pid, pidfd, /*spawned=*/false);

    // Seed thread map from /proc/<pid>/task. The perf backend has no
    // CLONE event - new threads will be discovered lazily on the
    // first sample that names them. Listing them up front lets
    // images() / threads() report a sensible state to the REPL right
    // after attach.
    for (pid_t tid : read_task_tids(main_tid)) {
        (void)t->thread_state(static_cast<ThreadId>(tid));
    }
    if (t->thread_state_map().empty()) {
        // Process vanished between pidfd_open and the task scan.
        (void)t->thread_state(static_cast<ThreadId>(main_tid));
    }
    return t;
}

Result<void> PerfTarget::detach() {
    // Wake the target if we'd left it SIGSTOPped, then close every
    // perf fd. The destructor handles pidfd / mem_fd / slot teardown,
    // but we mark the target dead-ish here so wait_event won't try to
    // poll the now-empty fd set.
    bool any_paused = false;
    for (auto& [_, ts] : thread_state_) {
        if (ts.paused) { any_paused = true; break; }
    }
    if (any_paused) {
        if (::kill(static_cast<pid_t>(pid_v_), SIGCONT) < 0 && errno != ESRCH) {
            return std::unexpected(errno_io("kill SIGCONT (detach)"));
        }
    }
    for (auto& s : slots_) close_slot(s);
    for (auto& [_, ts] : thread_state_) ts.paused = false;
    return {};
}

Result<void> PerfTarget::kill() {
    if (::kill(static_cast<pid_t>(pid_v_), SIGKILL) < 0) {
        if (errno != ESRCH) return std::unexpected(errno_io("kill"));
    }
    if (spawned_) {
        int status = 0;
        while (::waitpid(static_cast<pid_t>(pid_v_), &status, WNOHANG) == 0) {
            // Drain - give the kernel a moment after SIGKILL.
            ::usleep(1000);
        }
    }
    for (auto& s : slots_) close_slot(s);
    thread_state_map().clear();
    dead_ = true;
    return {};
}

std::vector<LoadedImage> PerfTarget::images() const {
    return read_proc_maps(static_cast<pid_t>(pid_v_));
}

}  // namespace ember::debug::linux_perf
