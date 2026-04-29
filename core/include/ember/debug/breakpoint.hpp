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

}  // namespace ember::debug
