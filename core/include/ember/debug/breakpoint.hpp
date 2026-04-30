#pragma once

#include <ember/common/types.hpp>

namespace ember::debug {

using BreakpointId = u32;

enum class BreakpointKind : u8 {
    Software,   // int3 (0xCC) byte patch
};

struct Breakpoint {
    BreakpointId   id      = 0;
    addr_t         addr    = 0;
    BreakpointKind kind    = BreakpointKind::Software;
    bool           enabled = true;
};

using WatchpointId = u32;

// x86 hardware-debug-register data watchpoints. The CPU does not
// support read-only watches — DR7's "data read/write" mode (`11`)
// covers reads, and "data write" (`01`) is the only narrower form.
// We expose Write and ReadWrite; users asking for "read" get
// ReadWrite (it'll fire on writes too, but it'll fire on reads,
// which is what they actually wanted).
enum class WatchMode : u8 {
    Write,       // DR7 type bits = 01
    ReadWrite,   // DR7 type bits = 11
};

struct Watchpoint {
    WatchpointId id      = 0;
    addr_t       addr    = 0;
    u8           size    = 8;     // 1, 2, 4, or 8
    WatchMode    mode    = WatchMode::ReadWrite;
    bool         enabled = true;
};

}  // namespace ember::debug
