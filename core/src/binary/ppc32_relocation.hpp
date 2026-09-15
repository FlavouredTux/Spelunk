#pragma once

#include <cstddef>
#include <span>
#include <string_view>

#include <spelunk/binary/arch.hpp>
#include <spelunk/common/types.hpp>

namespace spelunk::ppc32 {

// PowerPC System V/EABI relocation numbers plus Nintendo's REL stream
// control records. Keeping the raw values here lets both loaders preserve
// their format-native relocation type fields.
namespace type {
inline constexpr u32 NONE = 0;
inline constexpr u32 ADDR32 = 1;
inline constexpr u32 ADDR24 = 2;
inline constexpr u32 ADDR16 = 3;
inline constexpr u32 ADDR16_LO = 4;
inline constexpr u32 ADDR16_HI = 5;
inline constexpr u32 ADDR16_HA = 6;
inline constexpr u32 ADDR14 = 7;
inline constexpr u32 ADDR14_BRTAKEN = 8;
inline constexpr u32 ADDR14_BRNTAKEN = 9;
inline constexpr u32 REL24 = 10;
inline constexpr u32 REL14 = 11;
inline constexpr u32 REL14_BRTAKEN = 12;
inline constexpr u32 REL14_BRNTAKEN = 13;
inline constexpr u32 UADDR32 = 24;
inline constexpr u32 REL32 = 26;
inline constexpr u32 GHS_REL16_HA = 251;
inline constexpr u32 GHS_REL16_HI = 252;
inline constexpr u32 GHS_REL16_LO = 253;
inline constexpr u32 EMB_SDA21 = 109;

inline constexpr u32 DOLPHIN_NOP = 201;
inline constexpr u32 DOLPHIN_SECTION = 202;
inline constexpr u32 DOLPHIN_END = 203;
inline constexpr u32 DOLPHIN_MRKREF = 204;
}  // namespace type

struct RelocationInfo {
    std::string_view name = "R_PPC_UNKNOWN";
    u8 width = 0;
    u8 alignment = 1;
    bool pc_relative = false;
    bool branch = false;
    bool callable = false;
    bool elf_supported = false;
};

[[nodiscard]] RelocationInfo info(u32 type) noexcept;

// PowerPC relocation expressions wrap in the 32-bit target address space.
[[nodiscard]] u32 resolve(addr_t symbol, i64 addend) noexcept;

// Encode an already resolved S+A value. Returns false for an unsupported type,
// an undersized field, or a value outside the relocation's signed range. A
// false result never modifies field bytes.
[[nodiscard]] bool encode(std::span<std::byte> field, u32 type,
                          Endian endian, u32 resolved,
                          addr_t place) noexcept;

}  // namespace spelunk::ppc32
