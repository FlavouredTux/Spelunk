#pragma once

#include <cstddef>
#include <span>

#include <ember/binary/arch.hpp>
#include <ember/binary/format.hpp>
#include <ember/common/types.hpp>
#include <ember/disasm/register.hpp>

namespace ember {

inline constexpr std::size_t kMaxAbiIntArgs = 8;
inline constexpr std::size_t kMaxAbiFpArgs = 13;
inline constexpr std::size_t kMaxAbiRegArgs = kMaxAbiIntArgs + kMaxAbiFpArgs;
// Keep bounded storage for recovered overflow parameters as well as the
// register banks. This is deliberately a presentation/analysis cap rather
// than an ABI limit; signatures beyond it remain available to the annotation
// path, while heuristic recovery stays resistant to corrupt stack offsets.
inline constexpr std::size_t kMaxAbiArgs = 32;

// Which calling convention the lifter, arity inferencer, signature
// inferencer, and emitter should assume for a binary.
enum class Abi : u8 {
    Unknown,
    SysVAmd64,
    Win64,
    Ppc32Sysv,
    Ppc64ElfV2Le,
    Ppc64ElfV1Be,
    Aapcs64,
    AapcsArm32,
};

[[nodiscard]] constexpr Abi abi_for(Format f, Arch a, Endian e = Endian::Unknown) noexcept {
    if (a == Arch::X86_64) {
        // Minidump and the raw-regions loader come from Windows processes,
        // so they share Win64. Everything else x86_64 (ELF, Mach-O, the
        // generic case) is SysV.
        const bool windows =
            f == Format::Pe || f == Format::Minidump || f == Format::RawRegions;
        return windows ? Abi::Win64 : Abi::SysVAmd64;
    }
    if (a == Arch::Arm64) {
        // AAPCS64 is the universal AArch64 ABI for Linux + macOS + Windows
        // user-mode, modulo small platform-specific tweaks (Apple uses
        // 64-bit longs and stack-passes parameters tightly; we don't
        // distinguish those at this level).
        return Abi::Aapcs64;
    }
    if (a == Arch::Arm) {
        // AAPCS (arm-eabi): r0-r3 carry the first four integer/pointer args,
        // r0 (r0:r1 for 64-bit) the return. Applies to ELF and PE (Windows
        // on ARM) alike; the base-standard (soft-float-abi register use) is
        // what we model - VFP argument passing is not distinguished here.
        return Abi::AapcsArm32;
    }
    if ((f == Format::Elf || f == Format::Dol || f == Format::Rel) &&
        a == Arch::Ppc32) {
        return Abi::Ppc32Sysv;
    }
    if (f == Format::Elf && a == Arch::Ppc64) {
        return (e == Endian::Big) ? Abi::Ppc64ElfV1Be : Abi::Ppc64ElfV2Le;
    }
    return Abi::Unknown;
}

// Integer/pointer argument registers in order.
//   SysV:  rdi, rsi, rdx, rcx, r8, r9        (6 args then stack)
//   Win64: rcx, rdx, r8, r9                  (4 args, 32-byte shadow, then stack)
//   PPC32/PPC64: r3-r10                      (8 args then stack)
[[nodiscard]] std::span<const Reg> int_arg_regs(Abi a) noexcept;

// Caller-saved integer registers. Any call may destroy these.
//   SysV:  rax, rcx, rdx, rsi, rdi, r8-r11
//   Win64: rax, rcx, rdx, r8-r11             (rsi, rdi are callee-saved)
//   PPC32/PPC64: r0, r3-r12, lr, ctr         (r2/TOC intentionally preserved)
[[nodiscard]] std::span<const Reg> caller_saved_int_regs(Abi a) noexcept;

// Floating-point / vector argument registers in order.
//   SysV / Win64: xmm0..xmm7
//   AAPCS64:      v0..v7
//   PPC32 SysV:   f1..f8
//   PPC64 ELF:    f1..f13
[[nodiscard]] std::span<const Reg> fp_arg_regs(Abi a) noexcept;

// Caller-saved floating-point registers. PPC calls may destroy f0..f13;
// exposing that fact to SSA prevents a value left in f1 by an earlier call
// from being mistaken for a later floating-point argument.
[[nodiscard]] std::span<const Reg> caller_saved_fp_regs(Abi a) noexcept;

// True when argument registers are assigned by a single positional slot
// shared across the integer and FP register files: the Nth argument uses
// the Nth int reg if integer, else the Nth FP reg, and an int argument
// still consumes (skips) the matching FP slot and vice versa. This is the
// Win64 model. SysV / AAPCS64 instead draw int and FP args from two
// independent sequences, so they return false.
[[nodiscard]] bool abi_positional_arg_slots(Abi a) noexcept;

[[nodiscard]] Reg int_return_reg(Abi a) noexcept;
// Scalar floating-point return register. PPC SysV returns float/double in f1.
// This is a candidate lane, not proof that every call returns a float; callers
// must select it from a known signature or concrete dataflow evidence.
[[nodiscard]] Reg fp_return_reg(Abi a) noexcept;

}  // namespace ember
