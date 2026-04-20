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

}  // namespace

std::span<const Reg> int_arg_regs(Abi a) noexcept {
    switch (a) {
        case Abi::Win64: return kWin64ArgRegs;
        case Abi::SysVAmd64:
        case Abi::Unknown:
        default:         return kSysvArgRegs;
    }
}

std::span<const Reg> caller_saved_int_regs(Abi a) noexcept {
    switch (a) {
        case Abi::Win64: return kWin64CallerSaved;
        case Abi::SysVAmd64:
        case Abi::Unknown:
        default:         return kSysvCallerSaved;
    }
}

}  // namespace ember
