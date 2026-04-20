#pragma once

#include <span>

#include <ember/binary/arch.hpp>
#include <ember/binary/format.hpp>
#include <ember/common/types.hpp>
#include <ember/disasm/register.hpp>

namespace ember {

// Which calling convention the lifter, arity inferencer, signature
// inferencer, and emitter should assume for a binary. Only x86-64 ABIs
// are modelled today — ARM64 variants (AAPCS64, Windows ARM64) would
// be separate enum values if/when we extend decoding there.
enum class Abi : u8 {
    // Fallback for non-x86-64 or unknown targets. Code paths that
    // read ABI tables should treat Unknown as SysV — it's the majority
    // case and matches legacy pre-Abi behaviour.
    Unknown,
    SysVAmd64,
    Win64,
};

[[nodiscard]] constexpr Abi abi_for(Format f, Arch a) noexcept {
    if (a != Arch::X86_64) return Abi::Unknown;
    return (f == Format::Pe) ? Abi::Win64 : Abi::SysVAmd64;
}

// Integer/pointer argument registers in order.
//   SysV:  rdi, rsi, rdx, rcx, r8, r9        (6 args then stack)
//   Win64: rcx, rdx, r8, r9                  (4 args, 32-byte shadow, then stack)
[[nodiscard]] std::span<const Reg> int_arg_regs(Abi a) noexcept;

// Caller-saved integer registers. Any call may destroy these.
//   SysV:  rax, rcx, rdx, rsi, rdi, r8-r11
//   Win64: rax, rcx, rdx, r8-r11             (rsi, rdi are callee-saved)
[[nodiscard]] std::span<const Reg> caller_saved_int_regs(Abi a) noexcept;

}  // namespace ember
