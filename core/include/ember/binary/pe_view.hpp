#pragma once

#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/binary/symbol.hpp>
#include <ember/common/error.hpp>
#include <ember/common/types.hpp>

// Free-function view over a PE32+ image already addressable through a
// `Binary` (so reads go via `bin.bytes_at(image_base + rva)`). Lets the
// PE parsers run against any backing store: `PeBinary` for on-disk
// images, `MinidumpBinary` for in-memory module captures.
namespace ember::pe {

// Optional-header data-directory entry. RVA-based; callers add image_base
// to get an absolute VA. Index with the standard IMAGE_DIRECTORY_ENTRY_*
// constants (EXPORT=0, IMPORT=1, EXCEPTION=3, ...). Size==0 means absent.
struct DataDirectory { u32 virtual_address; u32 size; };

[[nodiscard]] inline std::span<const std::byte>
bytes_at_rva(const Binary& bin, addr_t image_base, u32 rva) noexcept {
    return bin.bytes_at(image_base + static_cast<addr_t>(rva));
}

[[nodiscard]] inline bool
rva_is_mapped(const Binary& bin, addr_t image_base, u32 rva,
              std::size_t min_size = 1) noexcept {
    return bytes_at_rva(bin, image_base, rva).size() >= min_size;
}

[[nodiscard]] inline std::string_view
cstr_at_rva(const Binary& bin, addr_t image_base, u32 rva) noexcept {
    const auto span = bytes_at_rva(bin, image_base, rva);
    if (span.empty()) return {};
    const char* const start = reinterpret_cast<const char*>(span.data());
    std::size_t len = 0;
    while (len < span.size() && start[len] != '\0') ++len;
    if (len == span.size()) return {};   // unterminated → treat as missing
    return std::string_view(start, len);
}

// Walks IMAGE_DIRECTORY_ENTRY_IMPORT. Appends one is_import=true Symbol
// per IAT slot to `out`; if `got_to_name` is non-null, also records each
// (slot-VA → name) so the caller can cross-reference IAT thunks later.
[[nodiscard]] Result<void>
collect_imports(const Binary& bin,
                addr_t image_base,
                std::span<const DataDirectory> dirs,
                std::vector<Symbol>& out,
                std::unordered_map<addr_t, std::string>* got_to_name = nullptr);

// Walks IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT. Same shape as collect_imports.
[[nodiscard]] Result<void>
collect_delay_imports(const Binary& bin,
                      addr_t image_base,
                      std::span<const DataDirectory> dirs,
                      std::vector<Symbol>& out,
                      std::unordered_map<addr_t, std::string>* got_to_name = nullptr);

// Walks IMAGE_DIRECTORY_ENTRY_EXPORT. Appends one is_export=true Symbol
// per named export (and one Ordinal#N per unnamed slot) to `out`.
[[nodiscard]] Result<void>
collect_exports(const Binary& bin,
                addr_t image_base,
                std::span<const DataDirectory> dirs,
                std::vector<Symbol>& out);

}  // namespace ember::pe
