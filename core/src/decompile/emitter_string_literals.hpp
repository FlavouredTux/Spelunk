#pragma once

#include <cstddef>
#include <map>
#include <optional>
#include <string>

#include <spelunk/common/types.hpp>

namespace spelunk {

class Binary;

namespace emit {

// Per-binary string-literal decoding used while rendering pseudo-C. This is
// intentionally private to the emitter implementation: callers receive raw,
// decoded string contents. Rendering call sites add C/C++ quoting and escapes.
class BinaryStringLiterals {
public:
    explicit BinaryStringLiterals(const Binary* binary);

    // Resolve an address as a NUL-terminated C string and return its raw bytes.
    // The common default threshold is cached; threshold-specific probes
    // deliberately are not.
    [[nodiscard]] std::optional<std::string>
    try_c_string_at(u64 addr, std::size_t min_printable = 2) const;

    // Resolve an address in Mach-O's __cfstring section as a compile-time
    // Core Foundation string record.
    [[nodiscard]] std::optional<std::string>
    try_cfstring_at(u64 addr) const;

private:
    static void append_utf8(std::string& out, u32 cp);

    const Binary* binary_ = nullptr;
    addr_t cfstring_lo_ = 0;
    u64 cfstring_size_ = 0;
    mutable std::map<u64, std::optional<std::string>> c_string_cache_;
};

}  // namespace emit
}  // namespace spelunk
