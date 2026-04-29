#pragma once

#include <ember/common/types.hpp>

namespace ember::debug {

// OS-level identifiers. Linux: pid_t / tid_t fit in u32 for any
// reasonable kernel.pid_max (defaults 4M, max 2^22). macOS: mach_port_t
// is u32 by definition. Keep them as plain aliases — strong typedefs
// gain little here and force conversions in the REPL parser.
using ProcessId = u32;
using ThreadId  = u32;

}  // namespace ember::debug
