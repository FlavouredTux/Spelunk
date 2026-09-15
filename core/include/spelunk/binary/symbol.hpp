#pragma once

#include <string>
#include <string_view>

#include <spelunk/common/types.hpp>

namespace spelunk {

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

// Remove loader/linker decorations from an import name while preserving the
// symbol spelling itself. MachOBinary already removes the C-ABI underscore
// from Symbol names; request that step only when handling a raw Mach-O name.
[[nodiscard]] constexpr std::string_view
strip_import_name_decorations(std::string_view name,
                              bool strip_macho_c_prefix = false) noexcept {
    const auto bang = name.rfind('!');
    if (bang != std::string_view::npos && bang != 0 && bang + 1 < name.size()) {
        name.remove_prefix(bang + 1);
    }
    if (name.starts_with("__imp_")) name.remove_prefix(6);

    // Preserve MSVC C++ mangling, but canonicalize x86 stdcall, fastcall, and
    // vectorcall names into identifiers callers can look up and render.
    if (name.empty() || name.starts_with('?')) return name;
    const auto call_suffix = name.rfind('@');
    if (call_suffix != std::string_view::npos &&
        call_suffix + 1 < name.size()) {
        bool numeric_suffix = true;
        for (std::size_t i = call_suffix + 1; i < name.size(); ++i) {
            if (name[i] < '0' || name[i] > '9') {
                numeric_suffix = false;
                break;
            }
        }
        if (numeric_suffix) {
            if ((name.front() == '_' || name.front() == '@') &&
                call_suffix > 1) {
                return {name.data() + 1, call_suffix - 1};
            }
            // `name@@N` is also a possible numeric ELF default version; both
            // interpretations are transport decoration for these consumers.
            if (call_suffix > 1 && name[call_suffix - 1] == '@') {
                return {name.data(), call_suffix - 1};
            }
        }
    }

    if (strip_macho_c_prefix && name.starts_with('_')) name.remove_prefix(1);

    // Only remove a non-empty, identifier-like ELF version suffix from an
    // otherwise ordinary symbol.
    if (name.starts_with('@')) return name;
    const auto at = name.find('@');
    if (at == std::string_view::npos || at == 0) return name;
    std::size_t version = at + 1;
    if (version < name.size() && name[version] == '@') ++version;
    if (version == name.size()) return name;

    bool has_identifier_char = false;
    for (std::size_t i = version; i < name.size(); ++i) {
        const char c = name[i];
        const bool alpha = (c >= 'a' && c <= 'z') ||
                           (c >= 'A' && c <= 'Z');
        if (alpha || c == '_') {
            has_identifier_char = true;
        } else if (!((c >= '0' && c <= '9') || c == '.' || c == '-')) {
            return name;
        }
    }
    return has_identifier_char
        ? std::string_view{name.data(), at}
        : name;
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

}  // namespace spelunk
