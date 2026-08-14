#pragma once

#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/common/types.hpp>
#include <ember/ir/abi.hpp>
#include <ember/ir/ir.hpp>

namespace ember {

// One source-level register argument recovered from the callee body. PPC uses
// independent GPR and FPR sequences, so a scalar arity cannot describe a
// mixed signature or tell a call site how to interleave the two banks.
// pointer_like records opaque pointer evidence without inventing a pointee
// type from mixed-width structure accesses.
struct InferredArgument {
    Reg    reg          = Reg::None;
    IrType type         = IrType::I64;
    bool   pointer_like = false;
};

// Recover register arguments in likely source order. For PPC, the order is a
// stable merge of the GPR and FPR lanes using each live-in's first meaningful
// use; order within each ABI lane is always preserved. Other architectures
// return the inferred integer-register prefix.
[[nodiscard]] std::vector<InferredArgument>
infer_arguments(const Binary& b, addr_t target, Abi abi) noexcept;

[[nodiscard]] std::vector<InferredArgument>
infer_arguments(const Binary& b, addr_t target) noexcept;

// Infer the scalar source-argument count. x86-64 tracks which integer arg
// registers are read before being written. PPC lifts the callee and combines
// live-in GPR/FPR lanes through infer_arguments(). The register set depends on
// `abi`:
//   SysV:  rdi, rsi, rdx, rcx, r8, r9 (clamped to [0, 6])
//   Win64: rcx, rdx, r8, r9           (clamped to [0, 4])
// A single leading unconditional `jmp <rel>` is followed transparently
// (bounded) so thin wrappers report the underlying callee's arity.
// x86 returns the max arity for the ABI when the function entry cannot be
// resolved; PPC returns zero when lifting fails.
[[nodiscard]] u8 infer_arity(const Binary& b, addr_t target, Abi abi) noexcept;

// Back-compat wrapper: infers `Abi` from the binary's (format, arch) and
// calls `infer_arity`. Call sites that have a Binary handy should prefer
// this overload.
[[nodiscard]] u8 infer_arity(const Binary& b, addr_t target) noexcept;

}  // namespace ember
