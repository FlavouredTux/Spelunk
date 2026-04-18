#pragma once

#include <string_view>

namespace ember {

enum class Arch {
    Unknown,
    X86,
    X86_64,
    Arm,
    Arm64,
    Riscv32,
    Riscv64,
};

[[nodiscard]] constexpr std::string_view arch_name(Arch a) noexcept {
    switch (a) {
        case Arch::Unknown: return "unknown";
        case Arch::X86:     return "x86";
        case Arch::X86_64:  return "x86_64";
        case Arch::Arm:     return "arm";
        case Arch::Arm64:   return "arm64";
        case Arch::Riscv32: return "riscv32";
        case Arch::Riscv64: return "riscv64";
    }
    return "unknown";
}

[[nodiscard]] constexpr unsigned arch_pointer_bits(Arch a) noexcept {
    switch (a) {
        case Arch::X86:
        case Arch::Arm:
        case Arch::Riscv32:
            return 32;
        case Arch::X86_64:
        case Arch::Arm64:
        case Arch::Riscv64:
            return 64;
        case Arch::Unknown:
            break;
    }
    return 0;
}

}  // namespace ember
