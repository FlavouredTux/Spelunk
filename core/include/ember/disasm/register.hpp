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
    return 0;
}

[[nodiscard]] constexpr bool is_xmm(Reg r) noexcept {
    const auto v = static_cast<unsigned>(r);
    return v >= static_cast<unsigned>(Reg::Xmm0) &&
           v <= static_cast<unsigned>(Reg::Xmm15);
}

[[nodiscard]] std::string_view reg_name(Reg r) noexcept;

}  // namespace ember
