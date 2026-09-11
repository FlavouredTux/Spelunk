#pragma once

#include <optional>
#include <span>
#include <string>
#include <utility>
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
    // Entry-stack-pointer-relative ABI slot for an overflow parameter.
    // Register arguments leave this empty even though some ABIs reserve home
    // space for them. Reg::None plus a populated offset is therefore a real
    // stack-passed source argument, not an unknown register location.
    std::optional<i64> stack_offset;
    // Signature-backed aggregate metadata. register_count is the number of
    // consecutive integer words occupied by this single source parameter;
    // aggregate_type/size let the emitter rebuild a C compound literal from
    // those words while keeping following arguments aligned.
    u8          register_count = 1;
    u32         aggregate_size = 0;
    std::string aggregate_type;

    InferredArgument() = default;
    InferredArgument(Reg r, IrType t, bool pointer = false,
                     std::optional<i64> stack = std::nullopt,
                     u8 words = 1, u32 aggregate_bytes = 0,
                     std::string aggregate_name = {}) noexcept
        : reg(r), type(t), pointer_like(pointer), stack_offset(stack),
          register_count(words), aggregate_size(aggregate_bytes),
          aggregate_type(std::move(aggregate_name)) {}
};

// Add scalar XMM live-ins to an integer parameter prefix. Typed call
// arguments supply evidence for values forwarded without local arithmetic.
void extend_x64_fp_arguments(const IrFunction& fn, Abi abi,
                             std::vector<InferredArgument>& arguments,
                             std::span<const IrValue> call_arguments = {});

// Recover register arguments in likely source order. For PPC, the order is a
// stable merge of the GPR and FPR lanes using each live-in's first meaningful
// use; order within each ABI lane is always preserved. Other architectures
// return the inferred integer-register prefix; x86-64 adds scalar XMM lanes.
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
