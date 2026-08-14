#include <ember/ir/abi.hpp>

namespace ember {

namespace {

constexpr Reg kSysvArgRegs[6] = {
    Reg::Rdi, Reg::Rsi, Reg::Rdx, Reg::Rcx, Reg::R8, Reg::R9,
};
constexpr Reg kWin64ArgRegs[4] = {
    Reg::Rcx, Reg::Rdx, Reg::R8, Reg::R9,
};

constexpr Reg kSysvCallerSaved[9] = {
    Reg::Rax, Reg::Rcx, Reg::Rdx, Reg::Rsi, Reg::Rdi,
    Reg::R8,  Reg::R9,  Reg::R10, Reg::R11,
};
constexpr Reg kWin64CallerSaved[7] = {
    Reg::Rax, Reg::Rcx, Reg::Rdx,
    Reg::R8,  Reg::R9,  Reg::R10, Reg::R11,
};
constexpr Reg kPpcArgRegs[8] = {
    Reg::PpcR3, Reg::PpcR4, Reg::PpcR5, Reg::PpcR6,
    Reg::PpcR7, Reg::PpcR8, Reg::PpcR9, Reg::PpcR10,
};
constexpr Reg kPpcCallerSaved[13] = {
    Reg::PpcR0, Reg::PpcR3, Reg::PpcR4,  Reg::PpcR5,  Reg::PpcR6,
    Reg::PpcR7, Reg::PpcR8, Reg::PpcR9,  Reg::PpcR10, Reg::PpcR11,
    Reg::PpcR12, Reg::PpcLr, Reg::PpcCtr,
};

// AAPCS64: x0..x7 carry the first eight integer/pointer arguments, x0/x1
// carry the integer return. x8 is the indirect-result location for
// large-aggregate returns (we don't model that). x9..x15 are caller-saved;
// x16/x17 (IP0/IP1) are intra-procedure-call corruptible; x18 is platform-
// reserved; x19..x28 are callee-saved. x29 is FP, x30 is LR.
constexpr Reg kAapcs64ArgRegs[8] = {
    Reg::X0, Reg::X1, Reg::X2, Reg::X3,
    Reg::X4, Reg::X5, Reg::X6, Reg::X7,
};

// xmm0..xmm7 carry the first eight FP/vector args on both SysV and Win64.
// Win64 only assigns the first four positionally, but keeping all eight
// here lets the positional-slot logic key off the slot index uniformly.
constexpr Reg kX86FpArgRegs[8] = {
    Reg::Xmm0, Reg::Xmm1, Reg::Xmm2, Reg::Xmm3,
    Reg::Xmm4, Reg::Xmm5, Reg::Xmm6, Reg::Xmm7,
};
constexpr Reg kWin64FpArgRegs[4] = {
    Reg::Xmm0, Reg::Xmm1, Reg::Xmm2, Reg::Xmm3,
};
constexpr Reg kAapcs64FpArgRegs[8] = {
    Reg::V0, Reg::V1, Reg::V2, Reg::V3,
    Reg::V4, Reg::V5, Reg::V6, Reg::V7,
};
constexpr Reg kPpc32FpArgRegs[8] = {
    Reg::PpcF1, Reg::PpcF2, Reg::PpcF3, Reg::PpcF4,
    Reg::PpcF5, Reg::PpcF6, Reg::PpcF7, Reg::PpcF8,
};
constexpr Reg kPpc64FpArgRegs[13] = {
    Reg::PpcF1, Reg::PpcF2,  Reg::PpcF3,  Reg::PpcF4,
    Reg::PpcF5, Reg::PpcF6,  Reg::PpcF7,  Reg::PpcF8,
    Reg::PpcF9, Reg::PpcF10, Reg::PpcF11, Reg::PpcF12,
    Reg::PpcF13,
};
constexpr Reg kPpcCallerSavedFp[14] = {
    Reg::PpcF0, Reg::PpcF1, Reg::PpcF2,  Reg::PpcF3,
    Reg::PpcF4, Reg::PpcF5, Reg::PpcF6,  Reg::PpcF7,
    Reg::PpcF8, Reg::PpcF9, Reg::PpcF10, Reg::PpcF11,
    Reg::PpcF12, Reg::PpcF13,
};
// AAPCS (arm-eabi): r0..r3 carry the first four integer/pointer args and
// r0 (r0:r1 for 64-bit) the integer return. r0..r3 and r12 (IP) are
// caller-saved along with r14 (LR); r4..r11 are callee-saved.
constexpr Reg kArm32ArgRegs[4] = {
    Reg::ArmR0, Reg::ArmR1, Reg::ArmR2, Reg::ArmR3,
};
constexpr Reg kArm32CallerSaved[6] = {
    Reg::ArmR0, Reg::ArmR1, Reg::ArmR2, Reg::ArmR3,
    Reg::ArmR12, Reg::Alr,
};

constexpr Reg kAapcs64CallerSaved[18] = {
    Reg::X0,  Reg::X1,  Reg::X2,  Reg::X3,
    Reg::X4,  Reg::X5,  Reg::X6,  Reg::X7,
    Reg::X8,
    Reg::X9,  Reg::X10, Reg::X11, Reg::X12, Reg::X13, Reg::X14, Reg::X15,
    Reg::X16, Reg::X17,
};

}  // namespace

std::span<const Reg> int_arg_regs(Abi a) noexcept {
    switch (a) {
        case Abi::Ppc32Sysv:
        case Abi::Ppc64ElfV2Le:
        case Abi::Ppc64ElfV1Be: return kPpcArgRegs;
        case Abi::Win64:        return kWin64ArgRegs;
        case Abi::Aapcs64:      return kAapcs64ArgRegs;
        case Abi::AapcsArm32:   return kArm32ArgRegs;
        case Abi::SysVAmd64:
        case Abi::Unknown:
        default:         return kSysvArgRegs;
    }
}

std::span<const Reg> caller_saved_int_regs(Abi a) noexcept {
    switch (a) {
        case Abi::Ppc32Sysv:
        case Abi::Ppc64ElfV2Le:
        case Abi::Ppc64ElfV1Be: return kPpcCallerSaved;
        case Abi::Win64:        return kWin64CallerSaved;
        case Abi::Aapcs64:      return kAapcs64CallerSaved;
        case Abi::AapcsArm32:   return kArm32CallerSaved;
        case Abi::SysVAmd64:
        case Abi::Unknown:
        default:         return kSysvCallerSaved;
    }
}

std::span<const Reg> fp_arg_regs(Abi a) noexcept {
    switch (a) {
        case Abi::Aapcs64:      return kAapcs64FpArgRegs;
        case Abi::AapcsArm32:   // VFP arg passing not modelled.
                                return {};
        case Abi::Ppc32Sysv:    return kPpc32FpArgRegs;
        case Abi::Ppc64ElfV2Le:
        case Abi::Ppc64ElfV1Be: return kPpc64FpArgRegs;
        case Abi::Win64:        return kWin64FpArgRegs;
        case Abi::SysVAmd64:
        case Abi::Unknown:
        default:                return kX86FpArgRegs;
    }
}

std::span<const Reg> caller_saved_fp_regs(Abi a) noexcept {
    switch (a) {
        case Abi::Ppc32Sysv:
        case Abi::Ppc64ElfV2Le:
        case Abi::Ppc64ElfV1Be: return kPpcCallerSavedFp;
        default:                return {};
    }
}

bool abi_positional_arg_slots(Abi a) noexcept {
    return a == Abi::Win64;
}

Reg int_return_reg(Abi a) noexcept {
    switch (a) {
        case Abi::Ppc32Sysv:
        case Abi::Ppc64ElfV2Le:
        case Abi::Ppc64ElfV1Be: return Reg::PpcR3;
        case Abi::Aapcs64:      return Reg::X0;
        case Abi::AapcsArm32:   return Reg::ArmR0;
        case Abi::Win64:
        case Abi::SysVAmd64:
        case Abi::Unknown:
        default:               return Reg::Rax;
    }
}

Reg fp_return_reg(Abi a) noexcept {
    switch (a) {
        case Abi::Win64:
        case Abi::SysVAmd64:
        case Abi::Unknown:
            return Reg::Xmm0;
        case Abi::Aapcs64:
            return Reg::V0;
        case Abi::Ppc32Sysv:
        case Abi::Ppc64ElfV2Le:
        case Abi::Ppc64ElfV1Be:
            return Reg::PpcF1;
        default:
            return Reg::None;
    }
}

}  // namespace ember
