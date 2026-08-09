#pragma once

#include <string>

#include <ember/common/types.hpp>

namespace ember {

// One loader-visible relocation. `site` is the synthetic/runtime address of
// the patched field, while `target` is the resolved S + A value when the
// referenced symbol is known. The raw architecture relocation number remains
// available so format-specific comparisons do not lose information.
struct Relocation {
    addr_t     site = 0;
    addr_t     target = 0;
    i64        addend = 0;
    u32        type = 0;
    // Format-native module/section coordinates. ELF and fixed-image formats
    // leave these zero; Wii REL uses them to resolve an initially unknown
    // cross-module edge after the peer module has been loaded.
    u32        source_section = 0;
    u32        target_module = 0;
    u32        target_section = 0;
    u8         width = 0;
    bool       pc_relative = false;
    bool       applied = false;
    std::string type_name;
    std::string symbol_name;
    std::string section_name;
};

}  // namespace ember
