#include <ember/analysis/libcxx_string.hpp>

#include <cstring>
#include <optional>
#include <string>

#include <ember/common/types.hpp>

namespace ember {

std::optional<std::string>
decode_libcxx_string(const Binary& b, addr_t va) {
    auto obj = b.bytes_at(va);
    if (obj.size() < 24) return std::nullopt;

    // First byte's low bit is the is_long flag in both layouts (short and
    // long overlay their first byte as the same union discriminator). On
    // x86_64/arm64 little-endian this is also the low bit of __cap_ in the
    // long form and __size_ in the short form.
    const u8 first   = static_cast<u8>(obj[0]);
    const bool is_long = (first & 1u) != 0;

    auto is_printable = [](u8 c) {
        if (c == 0 || c == '\t' || c == '\n' || c == '\r') return true;
        return c >= 0x20 && c <= 0x7e;
    };

    if (!is_long) {
        // Short form: size is stored as first_byte >> 1 (bit 0 = is_long),
        // inline data starts at offset 1. Capacity is exactly 22 on x86_64.
        const u8 size = first >> 1;
        if (size > 22) return std::nullopt;
        std::string s;
        s.reserve(size);
        for (u8 i = 0; i < size; ++i) {
            const u8 c = static_cast<u8>(obj[1 + i]);
            if (c == 0) break;
            if (!is_printable(c)) return std::nullopt;
            s.push_back(static_cast<char>(c));
        }
        return s;
    }

    // Long form: three 8-byte fields — cap (with is_long in bit 0), size,
    // data pointer. Mask the flag bit out of cap before sanity checks.
    u64 cap = 0, size = 0, data_ptr = 0;
    std::memcpy(&cap,      obj.data() + 0,  8);
    std::memcpy(&size,     obj.data() + 8,  8);
    std::memcpy(&data_ptr, obj.data() + 16, 8);
    cap &= ~u64{1};
    if (size > cap) return std::nullopt;
    if (size > 1'000'000u) return std::nullopt;  // sanity
    if (data_ptr == 0) return std::nullopt;

    auto data_bytes = b.bytes_at(static_cast<addr_t>(data_ptr));
    if (data_bytes.size() < size) return std::nullopt;
    std::string s;
    s.reserve(static_cast<std::size_t>(size));
    for (u64 i = 0; i < size; ++i) {
        const u8 c = static_cast<u8>(data_bytes[i]);
        if (c == 0) break;
        if (!is_printable(c)) return std::nullopt;
        s.push_back(static_cast<char>(c));
    }
    return s;
}

}  // namespace ember
