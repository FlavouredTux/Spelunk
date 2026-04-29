#include <ember/debug/target.hpp>

#if defined(__linux__) && defined(__x86_64__)
#define EMBER_DBG_LINUX_X64 1
#include "linux/ptrace_target.hpp"
#endif

#if defined(__APPLE__) && defined(__x86_64__)
#define EMBER_DBG_MACOS_X64 1
#include "macos/mach_target.hpp"
#endif

namespace ember::debug {

[[nodiscard]] Result<std::unique_ptr<Target>>
launch(const LaunchOptions& opts) {
#if defined(EMBER_DBG_LINUX_X64)
    return linux_::launch_linux(opts);
#elif defined(EMBER_DBG_MACOS_X64)
    return mach_::launch_macos(opts);
#else
    (void)opts;
    return std::unexpected(Error::unsupported(
        "debugger: launch is only implemented on x86-64 Linux and macOS"));
#endif
}

[[nodiscard]] Result<std::unique_ptr<Target>>
attach(ProcessId pid) {
#if defined(EMBER_DBG_LINUX_X64)
    return linux_::attach_linux(pid);
#elif defined(EMBER_DBG_MACOS_X64)
    return mach_::attach_macos(pid);
#else
    (void)pid;
    return std::unexpected(Error::unsupported(
        "debugger: attach is only implemented on x86-64 Linux and macOS"));
#endif
}

}  // namespace ember::debug
