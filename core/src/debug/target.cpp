#include <ember/debug/target.hpp>

#if defined(__linux__) && defined(__x86_64__)
#define EMBER_DBG_LINUX_X64 1
#include "linux/ptrace_target.hpp"
#include "linux/perf_target.hpp"
#endif

#if defined(__APPLE__) && defined(__x86_64__)
#define EMBER_DBG_MACOS_X64 1
#include "macos/mach_target.hpp"
#endif

namespace ember::debug {

[[nodiscard]] Result<std::unique_ptr<Target>>
launch(const LaunchOptions& opts) {
#if defined(EMBER_DBG_LINUX_X64)
    switch (opts.backend) {
        case BackendKind::Perf:
            return linux_perf::launch_perf(opts);
        case BackendKind::Ptrace:
        case BackendKind::Default:
            return linux_::launch_linux(opts);
    }
    return std::unexpected(Error::unsupported(
        "debugger: launch: unknown backend kind"));
#elif defined(EMBER_DBG_MACOS_X64)
    if (opts.backend != BackendKind::Default) {
        return std::unexpected(Error::unsupported(
            "debugger: launch: only the Default backend is supported on macOS"));
    }
    return mach_::launch_macos(opts);
#else
    (void)opts;
    return std::unexpected(Error::unsupported(
        "debugger: launch is only implemented on x86-64 Linux and macOS"));
#endif
}

[[nodiscard]] Result<std::unique_ptr<Target>>
attach(ProcessId pid, BackendKind kind) {
#if defined(EMBER_DBG_LINUX_X64)
    switch (kind) {
        case BackendKind::Perf:
            return linux_perf::attach_perf(pid);
        case BackendKind::Ptrace:
        case BackendKind::Default:
            return linux_::attach_linux(pid);
    }
    return std::unexpected(Error::unsupported(
        "debugger: attach: unknown backend kind"));
#elif defined(EMBER_DBG_MACOS_X64)
    if (kind != BackendKind::Default) {
        return std::unexpected(Error::unsupported(
            "debugger: attach: only the Default backend is supported on macOS"));
    }
    return mach_::attach_macos(pid);
#else
    (void)pid;
    (void)kind;
    return std::unexpected(Error::unsupported(
        "debugger: attach is only implemented on x86-64 Linux and macOS"));
#endif
}

}  // namespace ember::debug
