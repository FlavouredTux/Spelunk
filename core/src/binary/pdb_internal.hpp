#pragma once

#include <cstddef>
#include <span>
#include <string>

#include <spelunk/common/bytes.hpp>
#include <spelunk/common/types.hpp>

namespace spelunk::pdb::detail {

// Read a null-terminated string from `body` starting at `pos`,
// advancing `pos` past the terminator. Caps at `body.size()` to keep
// hostile / corrupt PDBs from running off the end.
static inline std::string read_cstr_advance(std::span<const std::byte> body,
                                            std::size_t& pos) {
    const std::size_t start = pos;
    while (pos < body.size() && body[pos] != std::byte{0}) ++pos;
    std::string out(reinterpret_cast<const char*>(body.data() + start),
                    pos - start);
    if (pos < body.size()) ++pos;     // skip null terminator
    return out;
}

// CodeView record walker (used for both symbol streams and TPI). Each
// record is `u16 length` (excluding itself), `u16 kind`, then
// kind-specific bytes. Total advancement = length + 2.
//
// `body_handler` receives (kind, body_span) for each record; returning
// false bails out early.
template <typename F>
static void for_each_record(std::span<const std::byte> stream, F body_handler) {
    std::size_t cursor = 0;
    while (cursor + 4 <= stream.size()) {
        const u16 reclen = read_le_at<u16>(stream.data() + cursor);
        if (reclen < 2) return;
        const std::size_t total = static_cast<std::size_t>(reclen) + 2u;
        if (cursor + total > stream.size()) return;

        const u16 kind = read_le_at<u16>(stream.data() + cursor + 2);
        const std::byte* body = stream.data() + cursor + 4;
        const std::size_t body_len = total - 4;

        if (!body_handler(kind, std::span(body, body_len))) return;
        cursor += total;
    }
}

}  // namespace spelunk::pdb::detail
