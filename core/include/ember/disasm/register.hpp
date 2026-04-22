#pragma once

#include <string_view>

#include <ember/common/types.hpp>

namespace ember {

enum class Reg : u8 {
    None = 0,

    Al, Cl, Dl, Bl, Ah, Ch, Dh, Bh,
    Spl, Bpl, Sil, Dil,
    R8b, R9b, R10b, R11b, R12b, R13b, R14b, R15b,

    Ax, Cx, Dx, Bx, Sp, Bp, Si, Di,
    R8w, R9w, R10w, R11w, R12w, R13w, R14w, R15w,

    Eax, Ecx, Edx, Ebx, Esp, Ebp, Esi, Edi,
    R8d, R9d, R10d, R11d, R12d, R13d, R14d, R15d,

    Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi,
    R8, R9, R10, R11, R12, R13, R14, R15,

    Es, Cs, Ss, Ds, Fs, Gs,

    Rip,

    // 128-bit SSE registers. For now we model them as scalar holders
    // (one float or double each); packed/SIMD semantics are not modeled.
    Xmm0,  Xmm1,  Xmm2,  Xmm3,  Xmm4,  Xmm5,  Xmm6,  Xmm7,
    Xmm8,  Xmm9,  Xmm10, Xmm11, Xmm12, Xmm13, Xmm14, Xmm15,

    PpcR0,  PpcR1,  PpcR2,  PpcR3,  PpcR4,  PpcR5,  PpcR6,  PpcR7,
    PpcR8,  PpcR9,  PpcR10, PpcR11, PpcR12, PpcR13, PpcR14, PpcR15,
    PpcR16, PpcR17, PpcR18, PpcR19, PpcR20, PpcR21, PpcR22, PpcR23,
    PpcR24, PpcR25, PpcR26, PpcR27, PpcR28, PpcR29, PpcR30, PpcR31,
    PpcLr, PpcCtr,

    // Sentinel. Always last. Size tables (kCanonical in ir/ssa.cpp,
    // reg_name in disasm/register.cpp) static_assert against this so adding
    // a register without updating them is a compile error.
    Count,
};

[[nodiscard]] constexpr unsigned reg_size(Reg r) noexcept {
    const auto v = static_cast<unsigned>(r);
    if (v == 0) return 0;
    if (v <= static_cast<unsigned>(Reg::R15b))  return 1;
    if (v <= static_cast<unsigned>(Reg::R15w))  return 2;
    if (v <= static_cast<unsigned>(Reg::R15d))  return 4;
    if (v <= static_cast<unsigned>(Reg::R15))   return 8;
    if (v <= static_cast<unsigned>(Reg::Gs))    return 2;
    if (v == static_cast<unsigned>(Reg::Rip))   return 8;
    if (v >= static_cast<unsigned>(Reg::Xmm0) &&
        v <= static_cast<unsigned>(Reg::Xmm15)) return 16;
    if (v >= static_cast<unsigned>(Reg::PpcR0) &&
        v <= static_cast<unsigned>(Reg::PpcR31)) return 8;
    if (v == static_cast<unsigned>(Reg::PpcLr) ||
        v == static_cast<unsigned>(Reg::PpcCtr)) return 8;
    return 0;
}

[[nodiscard]] constexpr bool is_xmm(Reg r) noexcept {
    const auto v = static_cast<unsigned>(r);
    return v >= static_cast<unsigned>(Reg::Xmm0) &&
           v <= static_cast<unsigned>(Reg::Xmm15);
}

[[nodiscard]] std::string_view reg_name(Reg r) noexcept;

}  // namespace ember
