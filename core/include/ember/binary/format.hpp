#pragma once

#include <string_view>

namespace ember {

enum class Format {
    Unknown,
    Elf,
    Pe,
    MachO,
    // Microsoft minidump (.dmp): captures the live state of one or more
    // modules from a running Windows process. Treated as a Binary so the
    // decoder/CFG/IR/emitter pipeline runs unchanged on a runtime image.
    Minidump,
    // Hand-rolled (vaddr, size, flags, file) manifest pointing at a set
    // of raw region dumps. Used for Scylla-style scrape workflows where
    // an attacker dumped pages out of a process with no surrounding
    // minidump container.
    RawRegions,
};

[[nodiscard]] constexpr std::string_view format_name(Format f) noexcept {
    switch (f) {
        case Format::Unknown:    return "unknown";
        case Format::Elf:        return "elf";
        case Format::Pe:         return "pe";
        case Format::MachO:      return "mach-o";
        case Format::Minidump:   return "minidump";
        case Format::RawRegions: return "raw-regions";
    }
    return "unknown";
}

}  // namespace ember
