#pragma once

#include <cstddef>
#include <optional>

#include <spelunk/binary/symbol.hpp>
#include <spelunk/common/bytes.hpp>
#include <spelunk/common/types.hpp>

namespace spelunk::elf {

inline constexpr std::size_t kPhdr64Size = 56;
inline constexpr std::size_t kPhdr32Size = 32;
inline constexpr std::size_t kShdr64Size = 64;
inline constexpr std::size_t kShdr32Size = 40;
inline constexpr std::size_t kSym64Size  = 24;
inline constexpr std::size_t kSym32Size  = 16;
inline constexpr std::size_t kRela64Size = 24;

namespace pt {
inline constexpr u32 LOAD         = 1;
inline constexpr u32 DYNAMIC      = 2;
inline constexpr u32 GNU_EH_FRAME = 0x6474e550;
}  // namespace pt

// DT_* tags consumed by the program-header fallback.
namespace dt {
inline constexpr u64 NULL_      = 0;
inline constexpr u64 PLTRELSZ   = 2;
inline constexpr u64 HASH       = 4;
inline constexpr u64 STRTAB     = 5;
inline constexpr u64 SYMTAB     = 6;
inline constexpr u64 RELA       = 7;
inline constexpr u64 RELASZ     = 8;
inline constexpr u64 STRSZ      = 10;
inline constexpr u64 SYMENT     = 11;
inline constexpr u64 JMPREL     = 23;
inline constexpr u64 GNU_HASH   = 0x6ffffef5;
}  // namespace dt

namespace rx64 {
inline constexpr u32 GLOB_DAT  = 6;
inline constexpr u32 JUMP_SLOT = 7;
}  // namespace rx64

namespace sht {
inline constexpr u32 NULL_        = 0;
inline constexpr u32 SYMTAB       = 2;
inline constexpr u32 STRTAB       = 3;
inline constexpr u32 RELA         = 4;
inline constexpr u32 NOBITS       = 8;
inline constexpr u32 REL          = 9;
inline constexpr u32 DYNSYM       = 11;
inline constexpr u32 SYMTAB_SHNDX = 18;
inline constexpr u32 CAFE_EXPORTS = 0x80000001;
inline constexpr u32 CAFE_IMPORTS = 0x80000002;
}  // namespace sht

namespace shn {
inline constexpr u16 UNDEF     = 0;
inline constexpr u16 LORESERVE = 0xff00;
inline constexpr u16 COMMON    = 0xfff2;
inline constexpr u16 XINDEX    = 0xffff;
}  // namespace shn

namespace stt {
inline constexpr u8 OBJECT  = 1;
inline constexpr u8 FUNC    = 2;
inline constexpr u8 SECTION = 3;
inline constexpr u8 FILE_   = 4;
}  // namespace stt

template <typename T>
[[nodiscard]] T read_at(Endian endian, const std::byte* p) noexcept {
    return endian == Endian::Big ? read_be_at<T>(p) : read_le_at<T>(p);
}

struct Shdr {
    u32 name;
    u32 type;
    u64 flags;
    u64 addr;
    u64 offset;
    u64 size;
    u32 link;
    u32 info;
    u64 addralign;
    u64 entsize;
};

[[nodiscard]] inline Shdr
read_shdr(Endian endian, const std::byte* p, bool is_64bit) noexcept {
    if (!is_64bit) {
        return {
            read_at<u32>(endian, p + 0x00),
            read_at<u32>(endian, p + 0x04),
            read_at<u32>(endian, p + 0x08),
            read_at<u32>(endian, p + 0x0c),
            read_at<u32>(endian, p + 0x10),
            read_at<u32>(endian, p + 0x14),
            read_at<u32>(endian, p + 0x18),
            read_at<u32>(endian, p + 0x1c),
            read_at<u32>(endian, p + 0x20),
            read_at<u32>(endian, p + 0x24),
        };
    }
    return {
        read_at<u32>(endian, p + 0x00),
        read_at<u32>(endian, p + 0x04),
        read_at<u64>(endian, p + 0x08),
        read_at<u64>(endian, p + 0x10),
        read_at<u64>(endian, p + 0x18),
        read_at<u64>(endian, p + 0x20),
        read_at<u32>(endian, p + 0x28),
        read_at<u32>(endian, p + 0x2c),
        read_at<u64>(endian, p + 0x30),
        read_at<u64>(endian, p + 0x38),
    };
}

[[nodiscard]] inline Shdr
shdr_at(Endian endian, const std::byte* table, u32 index,
        bool is_64bit) noexcept {
    const std::size_t size = is_64bit ? kShdr64Size : kShdr32Size;
    return read_shdr(endian,
                     table + static_cast<std::size_t>(index) * size,
                     is_64bit);
}

[[nodiscard]] inline std::optional<addr_t>
align_up_bounded(addr_t value, addr_t alignment, addr_t maximum) noexcept {
    if (value > maximum) return std::nullopt;
    if (alignment <= 1) return value;
    const addr_t remainder = value % alignment;
    if (remainder == 0) return value;
    const addr_t padding = alignment - remainder;
    if (padding > maximum - value) return std::nullopt;
    return value + padding;
}

[[nodiscard]] inline SymbolKind symbol_kind_from_info(u8 info) noexcept {
    switch (info & 0xf) {
        case stt::FUNC:    return SymbolKind::Function;
        case stt::OBJECT:  return SymbolKind::Object;
        case stt::SECTION: return SymbolKind::Section;
        case stt::FILE_:   return SymbolKind::File;
        default:           return SymbolKind::Unknown;
    }
}

}  // namespace spelunk::elf
