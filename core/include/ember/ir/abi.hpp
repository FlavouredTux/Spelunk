#pragma once

#include <cstddef>
#include <span>

#include <ember/binary/arch.hpp>
#include <ember/binary/format.hpp>
#include <ember/common/types.hpp>
#include <ember/disasm/register.hpp>

namespace ember {

inline constexpr std::size_t kMaxAbiIntArgs = 8;

// Which calling convention the lifter, arity inferencer, signature
// inferencer, and emitter should assume for a binary.
enum class Abi : u8 {
    Unknown,
    SysVAmd64,
    Win64,
    Ppc64ElfV2Le,
    Ppc64ElfV1Be,
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
    if (f == Format::Elf && a == Arch::Ppc64) {
        return (e == Endian::Big) ? Abi::Ppc64ElfV1Be : Abi::Ppc64ElfV2Le;
    }
    return Abi::Unknown;
}

// Integer/pointer argument registers in order.
//   SysV:  rdi, rsi, rdx, rcx, r8, r9        (6 args then stack)
//   Win64: rcx, rdx, r8, r9                  (4 args, 32-byte shadow, then stack)
//   PPC64: r3-r10                            (8 args then stack)
[[nodiscard]] std::span<const Reg> int_arg_regs(Abi a) noexcept;

// Caller-saved integer registers. Any call may destroy these.
//   SysV:  rax, rcx, rdx, rsi, rdi, r8-r11
//   Win64: rax, rcx, rdx, r8-r11             (rsi, rdi are callee-saved)
//   PPC64: r0, r3-r12, lr, ctr               (r2/TOC intentionally preserved)
[[nodiscard]] std::span<const Reg> caller_saved_int_regs(Abi a) noexcept;

[[nodiscard]] Reg int_return_reg(Abi a) noexcept;
[[nodiscard]] Reg fp_return_reg(Abi a) noexcept;

}  // namespace ember
