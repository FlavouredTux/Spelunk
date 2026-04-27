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

    // AArch64 GPRs. X0..X28 are general-purpose, X29 is the frame pointer
    // (FP), X30 is the link register (LR). Xsp is the stack pointer (a
    // separate physical register, not a special encoding of x31). Xzr is
    // the zero-encoding sink — reads return zero, writes are discarded;
    // we keep it around so the lifter can recognise the alias.
    X0,  X1,  X2,  X3,  X4,  X5,  X6,  X7,
    X8,  X9,  X10, X11, X12, X13, X14, X15,
    X16, X17, X18, X19, X20, X21, X22, X23,
    X24, X25, X26, X27, X28, X29, X30,
    Xsp, Xzr,

    // 32-bit views of the GPRs (W*, Wsp, Wzr). Sub-register reads/writes
    // mirror x86-64's eax/rax semantics: a W-write zero-extends into the
    // 64-bit X. Canonicalised to the matching X register.
    W0,  W1,  W2,  W3,  W4,  W5,  W6,  W7,
    W8,  W9,  W10, W11, W12, W13, W14, W15,
    W16, W17, W18, W19, W20, W21, W22, W23,
    W24, W25, W26, W27, W28, W29, W30,
    Wsp, Wzr,

    // 128-bit SIMD/FP registers. AArch64 also exposes 32/64-bit views
    // (S0..S31, D0..D31) but the decoder mostly hands these out as Vn
    // typed by the instruction; the size-specific aliases stay implicit
    // for now.
    V0,  V1,  V2,  V3,  V4,  V5,  V6,  V7,
    V8,  V9,  V10, V11, V12, V13, V14, V15,
    V16, V17, V18, V19, V20, V21, V22, V23,
    V24, V25, V26, V27, V28, V29, V30, V31,

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
    if (v >= static_cast<unsigned>(Reg::X0) &&
        v <= static_cast<unsigned>(Reg::Xzr)) return 8;
    if (v >= static_cast<unsigned>(Reg::W0) &&
        v <= static_cast<unsigned>(Reg::Wzr)) return 4;
    if (v >= static_cast<unsigned>(Reg::V0) &&
        v <= static_cast<unsigned>(Reg::V31)) return 16;
    return 0;
}

[[nodiscard]] constexpr bool is_xmm(Reg r) noexcept {
    const auto v = static_cast<unsigned>(r);
    return v >= static_cast<unsigned>(Reg::Xmm0) &&
           v <= static_cast<unsigned>(Reg::Xmm15);
}

[[nodiscard]] constexpr bool is_aarch64_gpr(Reg r) noexcept {
    const auto v = static_cast<unsigned>(r);
    return (v >= static_cast<unsigned>(Reg::X0) &&
            v <= static_cast<unsigned>(Reg::Xzr)) ||
           (v >= static_cast<unsigned>(Reg::W0) &&
            v <= static_cast<unsigned>(Reg::Wzr));
}

[[nodiscard]] constexpr bool is_aarch64_vector(Reg r) noexcept {
    const auto v = static_cast<unsigned>(r);
    return v >= static_cast<unsigned>(Reg::V0) &&
           v <= static_cast<unsigned>(Reg::V31);
}

[[nodiscard]] std::string_view reg_name(Reg r) noexcept;

}  // namespace ember
