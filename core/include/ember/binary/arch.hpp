#pragma once

#include <string_view>

#include <ember/common/types.hpp>

namespace ember {

enum class Arch {
    Unknown,
    X86,
    X86_64,
    Arm,
    Arm64,
    Ppc32,
    Ppc64,
    Riscv32,
    Riscv64,
};

enum class Endian : u8 {
    Unknown = 0,
    Little,
    Big,
};

[[nodiscard]] constexpr std::string_view arch_name(Arch a) noexcept {
    switch (a) {
        case Arch::Unknown: return "unknown";
        case Arch::X86:     return "x86";
        case Arch::X86_64:  return "x86_64";
        case Arch::Arm:     return "arm";
        case Arch::Arm64:   return "arm64";
        case Arch::Ppc32:   return "ppc32";
        case Arch::Ppc64:   return "ppc64";
        case Arch::Riscv32: return "riscv32";
        case Arch::Riscv64: return "riscv64";
    }
    return "unknown";
}

[[nodiscard]] constexpr std::string_view endian_name(Endian e) noexcept {
    switch (e) {
        case Endian::Little: return "little";
        case Endian::Big:    return "big";
        case Endian::Unknown:
            break;
    }
    return "unknown";
}

[[nodiscard]] constexpr unsigned arch_pointer_bits(Arch a) noexcept {
    switch (a) {
        case Arch::X86:
        case Arch::Arm:
        case Arch::Ppc32:
        case Arch::Riscv32:
            return 32;
        case Arch::X86_64:
        case Arch::Arm64:
        case Arch::Ppc64:
        case Arch::Riscv64:
            return 64;
        case Arch::Unknown:
            break;
    }
    return 0;
}

}  // namespace ember
