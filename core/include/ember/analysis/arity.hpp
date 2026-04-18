#pragma once

#include <ember/binary/binary.hpp>
#include <ember/common/types.hpp>

namespace ember {

// Infer the arity of a SysV x86-64 function by linearly decoding up to 128
// instructions from its entry and tracking which of the arg registers
// (rdi, rsi, rdx, rcx, r8, r9) are read before being written.
// A single leading unconditional `jmp <rel>` is followed transparently
// (bounded), so thin wrappers report the underlying callee's arity.
// Arity = (max index of live-in arg reg) + 1, clamped to [0, 6].
// Returns 6 when the function entry cannot be resolved (caller falls back).
[[nodiscard]] u8 infer_sysv_arity(const Binary& b, addr_t target) noexcept;

}  // namespace ember
