#pragma once

#include <string>
#include <string_view>

#include <ember/common/types.hpp>

namespace ember {

enum class SymbolKind {
    Unknown,
    Function,
    Object,
    Section,
    File,
};

[[nodiscard]] constexpr std::string_view symbol_kind_name(SymbolKind k) noexcept {
    switch (k) {
        case SymbolKind::Unknown:  return "unknown";
        case SymbolKind::Function: return "function";
        case SymbolKind::Object:   return "object";
        case SymbolKind::Section:  return "section";
        case SymbolKind::File:     return "file";
    }
    return "unknown";
}

struct Symbol {
    std::string name;
    // For defined symbols: the symbol's virtual address.
    // For imports: the PLT stub's address (set once resolved via PLT scan;
    // 0 if the stub address could not be identified).
    addr_t      addr      = 0;
    u64         size      = 0;
    SymbolKind  kind      = SymbolKind::Unknown;
    bool        is_import = false;
    bool        is_export = false;
    // For imports: the GOT slot address that the dynamic linker fills with
    // the resolved target. 0 for non-imports or if no matching relocation
    // was found.
    addr_t      got_addr  = 0;
};

}  // namespace ember
