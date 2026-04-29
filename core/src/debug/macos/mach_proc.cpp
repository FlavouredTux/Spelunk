// Process control for the macOS Mach backend.
//
// Launch: posix_spawn with POSIX_SPAWN_START_SUSPENDED so the tracee
// is held at its first instruction, then task_for_pid + Mach
// exception-port registration before the optional task_resume.
//
// task_for_pid privilege caveat — failure here is overwhelmingly
// the cause of "the debugger doesn't work on macOS." The ember
// binary needs ONE of:
//
//   * com.apple.security.cs.debugger entitlement at codesign time
//     (the modern, ship-able answer)
//   * running as root with SIP disabled (development-only)
//   * the tracee carrying the get-task-allow entitlement (debug
//     builds typically do)
//
// We surface KERN_FAILURE here as a precise io error so users know
// exactly what to fix.

#include "mach_target.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <format>
#include <string>
#include <vector>

#include <signal.h>
#include <spawn.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <libproc.h>          // proc_regionfilename, PROC_PIDPATHINFO_MAXSIZE
#include <mach/mach.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/mach_vm.h>
#include <mach/task.h>
#include <mach/thread_act.h>
#include <mach/thread_state.h>
#include <mach/exception_types.h>
#include <mach/vm_region.h>

extern char** environ;

namespace ember::debug::mach_ {

namespace {

[[nodiscard]] Error mach_io(const char* op, kern_return_t kr) {
    return Error::io(std::format("{}: {}", op,
                                 ::mach_error_string(kr)));
}

[[nodiscard]] Error errno_io(const char* op) {
    return Error::io(std::string(op) + ": " + std::strerror(errno));
}

// Allocate a receive port with a corresponding send right inserted
// into our own port-name space, then register it as the task's
// exception port for breakpoint / access / arith / software /
// crash / corpse traps. EXCEPTION_DEFAULT delivers
// `exception_raise` messages (we receive thread + task ports as
// out-of-line descriptors, plus the exception type and code).
//
// The state-flavor argument is x86_THREAD_STATE64; with the DEFAULT
// behaviour the kernel does NOT include thread state in the message
// itself (state-flavor only matters for STATE / STATE_IDENTITY
// behaviours), but we pass it for forward compat in case we add
// inline state retrieval later.
[[nodiscard]] Result<mach_port_t> install_exception_port(mach_port_t task_port) {
    mach_port_t exc = MACH_PORT_NULL;
    kern_return_t kr = ::mach_port_allocate(
        ::mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exc);
    if (kr != KERN_SUCCESS) return std::unexpected(mach_io("mach_port_allocate", kr));

    kr = ::mach_port_insert_right(
        ::mach_task_self(), exc, exc, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        ::mach_port_destroy(::mach_task_self(), exc);
        return std::unexpected(mach_io("mach_port_insert_right", kr));
    }

    kr = ::task_set_exception_ports(
        task_port,
        EXC_MASK_BREAKPOINT | EXC_MASK_BAD_ACCESS |
            EXC_MASK_BAD_INSTRUCTION | EXC_MASK_ARITHMETIC |
            EXC_MASK_SOFTWARE | EXC_MASK_CRASH,
        exc,
        EXCEPTION_DEFAULT,
        x86_THREAD_STATE64);
    if (kr != KERN_SUCCESS) {
        ::mach_port_destroy(::mach_task_self(), exc);
        return std::unexpected(mach_io("task_set_exception_ports", kr));
    }
    return exc;
}

void enumerate_initial_threads(MachOTarget& t, mach_port_t task_port) {
    thread_act_array_t threads = nullptr;
    mach_msg_type_number_t count = 0;
    if (::task_threads(task_port, &threads, &count) != KERN_SUCCESS) return;
    for (mach_msg_type_number_t i = 0; i < count; ++i) {
        t.add_thread(static_cast<ThreadId>(threads[i]));
    }
    if (threads) {
        ::vm_deallocate(::mach_task_self(),
                        reinterpret_cast<vm_address_t>(threads),
                        count * sizeof(thread_act_t));
    }
}

// argv / envp owners for the launch path. Each entry is malloc'd
// via strdup; freed at the end of launch (posix_spawn copies the
// arrays into the child via shared mem).
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

}  // namespace

[[nodiscard]] Result<std::unique_ptr<Target>>
launch_macos(const LaunchOptions& opts) {
    if (opts.program.empty()) {
        return std::unexpected(Error::invalid_format(
            "debugger: launch: program path is empty"));
    }

    posix_spawnattr_t attr;
    if (::posix_spawnattr_init(&attr) != 0) {
        return std::unexpected(errno_io("posix_spawnattr_init"));
    }
    // SUSPENDED: tracee is held at its first instruction (technically
    // dyld's __dyld_start) so we can wire up the exception port
    // before any instruction has run. Resume happens via task_resume
    // when the user calls cont() — or here when stop_at_entry=false.
    ::posix_spawnattr_setflags(&attr,
        POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_SETPGROUP);

    OwnedArgv argv = build_argv(opts.program, opts.args);
    OwnedArgv envv = build_envp(opts.env);
    char** envp = opts.env.empty() ? environ : envv.ptrs.data();

    pid_t child = 0;
    const int rc = ::posix_spawn(&child, opts.program.c_str(),
                                 nullptr, &attr,
                                 argv.ptrs.data(), envp);
    ::posix_spawnattr_destroy(&attr);
    if (rc != 0) {
        errno = rc;
        return std::unexpected(errno_io("posix_spawn"));
    }

    mach_port_t task_port = MACH_PORT_NULL;
    kern_return_t kr = ::task_for_pid(::mach_task_self(), child, &task_port);
    if (kr != KERN_SUCCESS) {
        ::kill(child, SIGKILL);
        ::waitpid(child, nullptr, 0);
        return std::unexpected(Error::io(std::format(
            "task_for_pid({}) failed: {} — codesign ember with the "
            "com.apple.security.cs.debugger entitlement, or run as root "
            "with SIP disabled, or build the tracee with get-task-allow",
            child, ::mach_error_string(kr))));
    }

    auto exc = install_exception_port(task_port);
    if (!exc) {
        ::mach_port_deallocate(::mach_task_self(), task_port);
        ::kill(child, SIGKILL);
        ::waitpid(child, nullptr, 0);
        return std::unexpected(std::move(exc).error());
    }

    auto t = std::make_unique<MachOTarget>(static_cast<ProcessId>(child),
                                           task_port, *exc);
    t->mark_attached(true);
    enumerate_initial_threads(*t, task_port);

    if (!opts.stop_at_entry) {
        if (auto kr2 = ::task_resume(task_port); kr2 != KERN_SUCCESS) {
            return std::unexpected(mach_io("task_resume", kr2));
        }
        for (auto& [_, ts] : t->thread_state_map()) ts.paused = false;
    }
    return t;
}

[[nodiscard]] Result<std::unique_ptr<Target>>
attach_macos(ProcessId pid) {
    mach_port_t task_port = MACH_PORT_NULL;
    kern_return_t kr = ::task_for_pid(::mach_task_self(),
                                      static_cast<pid_t>(pid), &task_port);
    if (kr != KERN_SUCCESS) {
        return std::unexpected(Error::io(std::format(
            "task_for_pid({}) failed: {} — codesign ember with the "
            "com.apple.security.cs.debugger entitlement, or run as root "
            "with SIP disabled",
            pid, ::mach_error_string(kr))));
    }

    if (auto kr2 = ::task_suspend(task_port); kr2 != KERN_SUCCESS) {
        ::mach_port_deallocate(::mach_task_self(), task_port);
        return std::unexpected(mach_io("task_suspend", kr2));
    }

    auto exc = install_exception_port(task_port);
    if (!exc) {
        ::task_resume(task_port);
        ::mach_port_deallocate(::mach_task_self(), task_port);
        return std::unexpected(std::move(exc).error());
    }

    auto t = std::make_unique<MachOTarget>(pid, task_port, *exc);
    t->mark_attached(true);
    enumerate_initial_threads(*t, task_port);
    return t;
}

Result<void> MachOTarget::detach() {
    if (!is_attached()) return {};
    // Leave the tracee running. Restoring previous exception ports
    // properly would require us to have snapshotted them on attach
    // (task_get_exception_ports); for v0 we just drop ours and the
    // kernel falls back to the default crash reporter / signal
    // handlers. Real debuggers save+restore — note for v1.
    if (task_port_) ::task_resume(task_port_);
    if (exc_port_)  ::mach_port_destroy (::mach_task_self(), exc_port_);
    if (task_port_) ::mach_port_deallocate(::mach_task_self(), task_port_);
    exc_port_  = 0;
    task_port_ = 0;
    mark_attached(false);
    thread_state_map().clear();
    return {};
}

Result<void> MachOTarget::kill() {
    if (::kill(static_cast<pid_t>(pid_v_), SIGKILL) < 0) {
        if (errno != ESRCH) return std::unexpected(errno_io("kill"));
    }
    int status = 0;
    while (::waitpid(static_cast<pid_t>(pid_v_), &status, WNOHANG) > 0) { /* drain */ }
    if (exc_port_)  ::mach_port_destroy (::mach_task_self(), exc_port_);
    if (task_port_) ::mach_port_deallocate(::mach_task_self(), task_port_);
    exc_port_  = 0;
    task_port_ = 0;
    mark_attached(false);
    thread_state_map().clear();
    return {};
}

std::vector<LoadedImage> MachOTarget::images() const {
    // Walk every region in the tracee's address space; for each
    // executable region, recover the file backing via
    // proc_regionfilename and dedupe by path.
    std::vector<LoadedImage> out;
    if (task_port_ == 0) return out;

    mach_vm_address_t addr = 0;
    while (true) {
        mach_vm_size_t size = 0;
        natural_t      depth = 0;
        vm_region_submap_info_data_64_t info{};
        mach_msg_type_number_t info_cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = ::mach_vm_region_recurse(
            task_port_, &addr, &size, &depth,
            reinterpret_cast<vm_region_recurse_info_t>(&info), &info_cnt);
        if (kr != KERN_SUCCESS) break;
        if (size == 0) break;

        if (info.protection & VM_PROT_EXECUTE) {
            char path[PROC_PIDPATHINFO_MAXSIZE] = {};
            const int len = ::proc_regionfilename(
                static_cast<pid_t>(pid_v_), addr, path, sizeof(path));
            if (len > 0) {
                std::string p(path, static_cast<std::size_t>(len));
                bool found = false;
                for (auto& img : out) {
                    if (img.path == p) {
                        if (addr < img.base) img.base = addr;
                        found = true;
                        break;
                    }
                }
                if (!found) out.push_back({std::move(p),
                                           static_cast<addr_t>(addr)});
            }
        }
        addr += size;
    }
    return out;
}

}  // namespace ember::debug::mach_
