#pragma once

#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/common/types.hpp>

namespace ember {

// One detected interpreter-style "VM dispatcher" inside a binary. The
// canonical shape is:
//
//   movzx <idx>, byte ptr [<bc_ptr>]    ; load 1-byte opcode
//   jmp   qword ptr [rip + table + idx*8]
//
// or the same pattern with the table base loaded into a register via a
// preceding `lea`. Both `call`-then-fallthrough and tail-`jmp` variants
// are accepted. The detector cares about the dispatch site, not how the
// handlers themselves run — most are short, return to the dispatch loop,
// and reuse the same `idx` register's update sequence.
//
// `function_addr` is the function whose CFG contains the dispatch.
// `dispatch_addr` is the indirect jmp/call instruction itself.
// `table_addr` is the absolute VA of the handler table.
// `handlers` lists the unique code addresses found in the table.
struct VmDispatcher {
    addr_t              function_addr = 0;
    addr_t              dispatch_addr = 0;
    addr_t              table_addr    = 0;
    std::vector<addr_t> handlers;
};

// Scan every defined function in the binary for a dispatch shape. Empty
// for arches the x64 decoder doesn't handle. Conservative — only emits a
// match when ≥ 8 valid code-pointer handlers are found, so a stray
// indirect jump through some constant table won't false-positive.
[[nodiscard]] std::vector<VmDispatcher>
detect_vm_dispatchers(const Binary& b);

}  // namespace ember
