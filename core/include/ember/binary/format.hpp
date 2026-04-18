#pragma once

#include <string_view>

namespace ember {

enum class Format {
    Unknown,
    Elf,
    Pe,
    MachO,
};

[[nodiscard]] constexpr std::string_view format_name(Format f) noexcept {
    switch (f) {
        case Format::Unknown: return "unknown";
        case Format::Elf:     return "elf";
        case Format::Pe:      return "pe";
        case Format::MachO:   return "mach-o";
    }
    return "unknown";
}

}  // namespace ember
