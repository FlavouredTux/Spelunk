// String-literal recovery: rodata/CFString lookups the emitter renders inline.
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <spelunk/binary/binary.hpp>
#include <spelunk/binary/format.hpp>
#include <spelunk/binary/section.hpp>
#include <spelunk/common/types.hpp>

#include "emitter_string_literals.hpp"

namespace spelunk::emit {

namespace {

[[nodiscard]] bool range_contains(addr_t start, u64 size, u64 address) noexcept {
    return address >= start && address - start < size;
}

}  // namespace

BinaryStringLiterals::BinaryStringLiterals(const Binary* binary)
    : binary_(binary) {
    if (!binary_ || binary_->format() != Format::MachO) return;
    for (const Section& section : binary_->sections()) {
        const std::string_view name = section.name;
        if (name == "__cfstring" || name.ends_with(",__cfstring")) {
            cfstring_lo_ = section.vaddr;
            cfstring_size_ = section.size;
            break;
        }
    }
}

std::optional<std::string> BinaryStringLiterals::try_c_string_at(
    u64 addr, std::size_t min_printable) const {
    if (!binary_) return std::nullopt;
    if (min_printable == 2) {
        auto it = c_string_cache_.find(addr);
        if (it != c_string_cache_.end()) return it->second;
    }

    for (const Section& section : binary_->sections()) {
        if (!range_contains(section.vaddr, section.size, addr)) continue;
        // Code bytes frequently contain two printable opcode bytes before
        // a zero and used to masquerade as handler/function strings.
        if (section.flags.executable) return std::nullopt;
        break;
    }

    std::optional<std::string> result;
    auto span = binary_->bytes_at(static_cast<addr_t>(addr));
    const std::size_t max_len = 512;
    if (!span.empty()) {
        std::string s;
        s.reserve(64);
        bool terminated = false;
        std::size_t printable_count = 0;
        std::size_t escape_required_count = 0;
        const std::size_t limit = std::min(span.size(), max_len);
        for (std::size_t i = 0; i < limit; ++i) {
            const auto c = static_cast<unsigned char>(span[i]);
            if (c == 0) { terminated = true; break; }
            // Common whitespace bytes are legitimate string
            // content, count toward the printable-threshold heuristic.
            if (c == '\t' || c == '\n' || c == '\r' || c == '\\' || c == '"') {
                s.push_back(static_cast<char>(c));
                ++printable_count;
                continue;
            }
            if (c >= 0x20 && c <= 0x7e) {
                s.push_back(static_cast<char>(c));
                ++printable_count;
                continue;
            }
            // Keep high-bit / control bytes in the decoded value. They still
            // participate in the string-likelihood heuristic here; the
            // renderer is responsible for their C-literal spelling.
            s.push_back(static_cast<char>(c));
            ++escape_required_count;
        }
        // Heuristic for "this is actually a string": at least 2
        // printable characters (excluding bytes that need hex escapes), with
        // printable bytes outnumbering escape-required ones. Two-char format
        // specifiers like "%d", "%s", "%c" and short keywords like "OK",
        // "No" are real string content in codegen tables; the tiebreak still
        // keeps `*(u64*)(" ")`-style noise out.
        if (terminated && printable_count >= min_printable &&
            printable_count >= escape_required_count) {
            result = std::move(s);
        }
    }
    if (min_printable == 2) c_string_cache_.emplace(addr, result);
    return result;
}

void BinaryStringLiterals::append_utf8(std::string& out, u32 cp) {
    if (cp <= 0x7f) {
        out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7ff) {
        out.push_back(static_cast<char>(0xc0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    } else if (cp <= 0xffff) {
        out.push_back(static_cast<char>(0xe0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    } else {
        out.push_back(static_cast<char>(0xf0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    }
}

std::optional<std::string>
BinaryStringLiterals::try_cfstring_at(u64 addr) const {
    if (!binary_) return std::nullopt;
    if (!range_contains(cfstring_lo_, cfstring_size_, addr)) {
        return std::nullopt;
    }
    // Each entry is 32 bytes: u64 isa; u32 flags; u32 pad; u64 data;
    // u64 length. Offsets: data at +16, length at +24.
    auto bytes = binary_->bytes_at(static_cast<addr_t>(addr));
    if (bytes.size() < 32) return std::nullopt;
    u32 flags = 0;
    u64 data_ptr = 0, length = 0;
    std::memcpy(&flags,    bytes.data() + 8,  4);
    std::memcpy(&data_ptr, bytes.data() + 16, 8);
    std::memcpy(&length,   bytes.data() + 24, 8);
    if (data_ptr == 0 || length == 0 || length > 1'000'000) return std::nullopt;
    auto strb = binary_->bytes_at(static_cast<addr_t>(data_ptr));
    if (strb.size() < length) return std::nullopt;
    const bool maybe_utf16 = length * 2 <= strb.size() && [&] {
        bool saw_wide_marker = false;
        for (u64 i = 0; i < length; ++i) {
            const auto hi = static_cast<unsigned char>(strb[i * 2 + 1]);
            if (hi == 0 || (hi >= 0xd8 && hi <= 0xdf)) {
                saw_wide_marker = true;
                continue;
            }
            return false;
        }
        return saw_wide_marker;
    }();
    if (maybe_utf16) {
        std::string s;
        for (u64 i = 0; i < length; ++i) {
            u16 w1 = static_cast<u16>(
                static_cast<unsigned char>(strb[i * 2]) |
                (static_cast<u16>(static_cast<unsigned char>(strb[i * 2 + 1])) << 8));
            if (w1 >= 0xd800 && w1 <= 0xdbff) {
                if (i + 1 >= length) return std::nullopt;
                ++i;
                const u16 w2 = static_cast<u16>(
                    static_cast<unsigned char>(strb[i * 2]) |
                    (static_cast<u16>(static_cast<unsigned char>(strb[i * 2 + 1])) << 8));
                if (w2 < 0xdc00 || w2 > 0xdfff) return std::nullopt;
                append_utf8(s, 0x10000u +
                    (((static_cast<u32>(w1) - 0xd800u) << 10) |
                     (static_cast<u32>(w2) - 0xdc00u)));
                continue;
            }
            if (w1 >= 0xdc00 && w1 <= 0xdfff) return std::nullopt;
            if (w1 < 0x20 && w1 != '\t' && w1 != '\n' && w1 != '\r') {
                return std::nullopt;
            }
            append_utf8(s, w1);
        }
        (void)flags;
        return s;
    }
    std::string s;
    s.reserve(static_cast<std::size_t>(length));
    for (u64 i = 0; i < length; ++i) {
        const auto c = static_cast<unsigned char>(strb[i]);
        if (c == 0) break;
        // CFString can be UTF-8 or UTF-16; be generous and accept any UTF-8
        // byte. Reject unsupported controls; rendering adds literal escapes.
        if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') return std::nullopt;
        s.push_back(static_cast<char>(c));
    }
    return s;
}

}  // namespace spelunk::emit
