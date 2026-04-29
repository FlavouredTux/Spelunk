#include <ember/debug/target.hpp>

#if defined(__linux__) && defined(__x86_64__)
#define EMBER_DBG_LINUX_X64 1
#include "linux/ptrace_target.hpp"
#endif

namespace ember::debug {

[[nodiscard]] Result<std::unique_ptr<Target>>
launch(const LaunchOptions& opts) {
#ifdef EMBER_DBG_LINUX_X64
    return linux_::launch_linux(opts);
#else
    (void)opts;
    return std::unexpected(Error::unsupported(
        "debugger: launch is only implemented on x86-64 Linux"));
#endif
}

[[nodiscard]] Result<std::unique_ptr<Target>>
attach(ProcessId pid) {
#ifdef EMBER_DBG_LINUX_X64
    return linux_::attach_linux(pid);
#else
    (void)pid;
    return std::unexpected(Error::unsupported(
        "debugger: attach is only implemented on x86-64 Linux"));
#endif
}

}  // namespace ember::debug
