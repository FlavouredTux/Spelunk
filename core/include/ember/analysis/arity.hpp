#pragma once

#include <ember/binary/binary.hpp>
#include <ember/common/types.hpp>
#include <ember/ir/abi.hpp>

namespace ember {

// Infer the arity of an x86-64 function by linearly decoding up to 128
// instructions from its entry and tracking which of the arg registers are
// read before being written. The arg-register set depends on `abi`:
//   SysV:  rdi, rsi, rdx, rcx, r8, r9 (clamped to [0, 6])
//   Win64: rcx, rdx, r8, r9           (clamped to [0, 4])
// A single leading unconditional `jmp <rel>` is followed transparently
// (bounded) so thin wrappers report the underlying callee's arity.
// Returns the max arity for the ABI when the function entry cannot be
// resolved (caller falls back).
[[nodiscard]] u8 infer_arity(const Binary& b, addr_t target, Abi abi) noexcept;

// Back-compat wrapper: infers `Abi` from the binary's (format, arch) and
// calls `infer_arity`. Call sites that have a Binary handy should prefer
// this overload.
[[nodiscard]] u8 infer_arity(const Binary& b, addr_t target) noexcept;

}  // namespace ember
