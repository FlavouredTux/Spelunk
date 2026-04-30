// Process control for the Linux ptrace backend: launch + attach +
// detach + kill, plus the /proc/<pid>/maps reader that powers
// LinuxTarget::images() and the /proc/<pid>/task walker that lets
// attach_linux pick up sibling threads at attach time.

// _GNU_SOURCE is supplied by glibc's features.h via <features.h> with
// the default _DEFAULT_SOURCE feature test, plus CMake doesn't set
// _POSIX_C_SOURCE here, so execvpe/pipe2 are visible without an
// explicit define. If a future toolchain changes that, this file
// will fail to compile and we'll add the define back.

#include "ptrace_target.hpp"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char** environ;

namespace ember::debug::linux_ {

namespace {

// Default ptrace options applied to every traced thread. EXITKILL
// makes accidental tracer crashes safe — the tracee dies with us
// instead of being orphaned in a stopped state. TRACECLONE fans new
// threads into our event stream automatically.
constexpr long kPtraceOptions =
    static_cast<long>(PTRACE_O_TRACECLONE)    |
    static_cast<long>(PTRACE_O_TRACEEXEC)     |
    static_cast<long>(PTRACE_O_TRACEEXIT)     |
    static_cast<long>(PTRACE_O_TRACEFORK)     |
    static_cast<long>(PTRACE_O_TRACEVFORK)    |
    static_cast<long>(PTRACE_O_TRACESYSGOOD)  |   // syscall-stops marked as SIGTRAP|0x80
    static_cast<long>(PTRACE_O_EXITKILL);

[[nodiscard]] Error errno_io(const char* op) {
    return Error::io(std::string(op) + ": " + std::strerror(errno));
}

[[nodiscard]] void* as_ptrace_data(long v) {
    return reinterpret_cast<void*>(static_cast<std::uintptr_t>(v));
}

// argv / envp owners for the brief window between fork and exec.
// Each pointer is malloc'd via strdup; the destructor frees them
// only if exec failed (the successful exec replaces the address
// space and the destructor never runs).
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

// Parse one hex address from the start of a string; stops at the
// first non-hex char. Returns 0 on a leading non-hex byte.
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

// One LoadedImage per unique path with at least one file-backed
// mapping. Base = lowest mapping start for that path — for an ELF
// the kernel maps the lowest-vaddr PT_LOAD here, so the base lands
// on the ELF header.
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
        if (path_pos == std::string_view::npos) continue;  // [vdso] / [stack] / anon

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

// Walk /proc/<pid>/task — the kernel's truth for thread membership.
// attach_linux uses this once at seize time; ongoing thread tracking
// rides on PTRACE_EVENT_CLONE in the event loop.
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
launch_linux(const LaunchOptions& opts) {
    if (opts.program.empty()) {
        return std::unexpected(Error::invalid_format(
            "debugger: launch: program path is empty"));
    }

    // CLOEXEC pipe so the child can post errno back if anything
    // before exec fails. A successful exec closes the write end and
    // the parent's read returns EOF.
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
        if (::ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) bail();

        OwnedArgv argv = build_argv(opts.program, opts.args);
        OwnedArgv envv = build_envp(opts.env);
        char** envp = opts.env.empty() ? environ : envv.ptrs.data();

        ::execvpe(opts.program.c_str(), argv.ptrs.data(), envp);
        bail();
    }

    // ---- Parent ----
    ::close(errpipe[1]);

    int child_errno = 0;
    ssize_t n = ::read(errpipe[0], &child_errno, sizeof(child_errno));
    ::close(errpipe[0]);
    if (n > 0 && child_errno != 0) {
        int reaped = 0;
        ::waitpid(child, &reaped, 0);
        errno = child_errno;
        return std::unexpected(errno_io("launch"));
    }

    // Wait for the post-exec SIGTRAP. The kernel stops the tracee
    // exactly once after a successful execve so we can land here
    // with everything mapped and ready to set options on.
    int status = 0;
    if (::waitpid(child, &status, 0) < 0) {
        return std::unexpected(errno_io("waitpid (post-exec)"));
    }
    if (!WIFSTOPPED(status)) {
        return std::unexpected(Error::io(
            "debugger: launch: tracee did not stop after exec"));
    }

    if (::ptrace(PTRACE_SETOPTIONS, child, nullptr,
                 as_ptrace_data(kPtraceOptions)) < 0) {
        return std::unexpected(errno_io("setoptions"));
    }

    auto t = std::make_unique<LinuxTarget>(static_cast<ProcessId>(child));
    t->mark_attached(true);
    t->add_thread(static_cast<ThreadId>(child));

    if (!opts.stop_at_entry) {
        if (::ptrace(PTRACE_CONT, child, nullptr, nullptr) < 0) {
            return std::unexpected(errno_io("cont"));
        }
    }
    return t;
}

[[nodiscard]] Result<std::unique_ptr<Target>>
attach_linux(ProcessId pid) {
    const pid_t main_tid = static_cast<pid_t>(pid);

    // SEIZE + INTERRUPT is the modern attach: it sets options
    // atomically and the resulting stop is a group-stop trap that
    // doesn't perturb the tracee's signal mask the way classic
    // PTRACE_ATTACH (which delivers SIGSTOP) does.
    if (::ptrace(PTRACE_SEIZE, main_tid, nullptr,
                 as_ptrace_data(kPtraceOptions)) < 0) {
        return std::unexpected(errno_io("seize"));
    }
    if (::ptrace(PTRACE_INTERRUPT, main_tid, nullptr, nullptr) < 0) {
        return std::unexpected(errno_io("interrupt"));
    }
    int status = 0;
    if (::waitpid(main_tid, &status, __WALL) < 0) {
        return std::unexpected(errno_io("waitpid (attach)"));
    }

    auto t = std::make_unique<LinuxTarget>(pid);
    t->mark_attached(true);
    t->add_thread(static_cast<ThreadId>(main_tid));

    // Pick up every other thread that already exists. PTRACE_O_TRACECLONE
    // handles future ones automatically via the event loop.
    for (pid_t tid : read_task_tids(main_tid)) {
        if (tid == main_tid) continue;
        if (::ptrace(PTRACE_SEIZE, tid, nullptr,
                     as_ptrace_data(kPtraceOptions)) < 0) {
            // A thread can vanish between read_task_tids and SEIZE;
            // ESRCH is benign, anything else is a real failure.
            if (errno == ESRCH) continue;
            return std::unexpected(errno_io("seize (sibling)"));
        }
        if (::ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) < 0) {
            if (errno == ESRCH) continue;
            return std::unexpected(errno_io("interrupt (sibling)"));
        }
        int sib_status = 0;
        ::waitpid(tid, &sib_status, __WALL);
        t->add_thread(static_cast<ThreadId>(tid));
    }
    return t;
}

Result<void> LinuxTarget::detach() {
    if (!is_attached()) return {};
    bool any_err  = false;
    int  last_err = 0;
    for (const auto& [tid, _] : thread_state_map()) {
        if (::ptrace(PTRACE_DETACH, static_cast<pid_t>(tid),
                     nullptr, nullptr) < 0) {
            if (errno == ESRCH) continue;  // already gone
            any_err  = true;
            last_err = errno;
        }
    }
    mark_attached(false);
    if (any_err) {
        errno = last_err;
        return std::unexpected(errno_io("detach"));
    }
    return {};
}

Result<void> LinuxTarget::kill() {
    if (::kill(static_cast<pid_t>(pid()), SIGKILL) < 0) {
        if (errno != ESRCH) return std::unexpected(errno_io("kill"));
    }
    // Reap every remaining thread so we don't leave zombies behind.
    int status = 0;
    while (::waitpid(-1, &status, __WALL | WNOHANG) > 0) { /* drain */ }
    mark_attached(false);
    thread_state_map().clear();
    return {};
}

std::vector<LoadedImage> LinuxTarget::images() const {
    return read_proc_maps(static_cast<pid_t>(pid_v_));
}

}  // namespace ember::debug::linux_
