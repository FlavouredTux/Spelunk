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
constexpr Reg kPpc64ArgRegs[8] = {
    Reg::PpcR3, Reg::PpcR4, Reg::PpcR5, Reg::PpcR6,
    Reg::PpcR7, Reg::PpcR8, Reg::PpcR9, Reg::PpcR10,
};
constexpr Reg kPpc64CallerSaved[13] = {
    Reg::PpcR0, Reg::PpcR3, Reg::PpcR4,  Reg::PpcR5,  Reg::PpcR6,
    Reg::PpcR7, Reg::PpcR8, Reg::PpcR9,  Reg::PpcR10, Reg::PpcR11,
    Reg::PpcR12, Reg::PpcLr, Reg::PpcCtr,
};

}  // namespace

std::span<const Reg> int_arg_regs(Abi a) noexcept {
    switch (a) {
        case Abi::Ppc64ElfV2Le:
        case Abi::Ppc64ElfV1Be: return kPpc64ArgRegs;
        case Abi::Win64: return kWin64ArgRegs;
        case Abi::SysVAmd64:
        case Abi::Unknown:
        default:         return kSysvArgRegs;
    }
}

std::span<const Reg> caller_saved_int_regs(Abi a) noexcept {
    switch (a) {
        case Abi::Ppc64ElfV2Le:
        case Abi::Ppc64ElfV1Be: return kPpc64CallerSaved;
        case Abi::Win64: return kWin64CallerSaved;
        case Abi::SysVAmd64:
        case Abi::Unknown:
        default:         return kSysvCallerSaved;
    }
}

Reg int_return_reg(Abi a) noexcept {
    switch (a) {
        case Abi::Ppc64ElfV2Le:
        case Abi::Ppc64ElfV1Be: return Reg::PpcR3;
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
        case Abi::Ppc64ElfV2Le:
        case Abi::Ppc64ElfV1Be:
        default:
            return Reg::None;
    }
}

}  // namespace ember
