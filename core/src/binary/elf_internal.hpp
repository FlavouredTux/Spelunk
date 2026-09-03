#pragma once

#include <cstddef>

#include <ember/binary/symbol.hpp>
#include <ember/common/bytes.hpp>
#include <ember/common/types.hpp>

namespace ember::elf {

inline constexpr std::size_t kPhdr64Size = 56;
inline constexpr std::size_t kPhdr32Size = 32;
inline constexpr std::size_t kSym64Size  = 24;
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

[[nodiscard]] inline SymbolKind symbol_kind_from_info(u8 info) noexcept {
    switch (info & 0xf) {
        case stt::FUNC:    return SymbolKind::Function;
        case stt::OBJECT:  return SymbolKind::Object;
        case stt::SECTION: return SymbolKind::Section;
        case stt::FILE_:   return SymbolKind::File;
        default:           return SymbolKind::Unknown;
    }
}

}  // namespace ember::elf
