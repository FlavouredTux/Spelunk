#include "ppc32_relocation.hpp"

#include <bit>
#include <cstring>
#include <limits>

namespace ember::ppc32 {
namespace {

template <typename T>
[[nodiscard]] T read_at(Endian endian, const std::byte* input) noexcept {
    T value{};
    std::memcpy(&value, input, sizeof(value));
    if constexpr (sizeof(T) > 1) {
        if ((endian == Endian::Big &&
             std::endian::native == std::endian::little) ||
            (endian == Endian::Little &&
             std::endian::native == std::endian::big)) {
            value = std::byteswap(value);
        }
    }
    return value;
}

template <typename T>
void write_at(Endian endian, std::byte* output, T value) noexcept {
    if constexpr (sizeof(T) > 1) {
        if ((endian == Endian::Big &&
             std::endian::native == std::endian::little) ||
            (endian == Endian::Little &&
             std::endian::native == std::endian::big)) {
            value = std::byteswap(value);
        }
    }
    std::memcpy(output, &value, sizeof(value));
}

[[nodiscard]] i64 signed_value(u32 value) noexcept {
    if (value <= static_cast<u32>(std::numeric_limits<i32>::max())) {
        return static_cast<i64>(value);
    }
    return static_cast<i64>(value) - 0x1'0000'0000LL;
}

[[nodiscard]] bool fits_signed(u32 value, u32 alignment_mask,
                               i64 minimum, i64 maximum) noexcept {
    if ((value & alignment_mask) != 0) return false;
    const i64 signed_result = signed_value(value);
    return signed_result >= minimum && signed_result <= maximum;
}

[[nodiscard]] u32 relative(u32 resolved, addr_t place) noexcept {
    return resolved - static_cast<u32>(place);
}

[[nodiscard]] u32 branch_prediction_bit(u32 relocation_type,
                                        u32 resolved,
                                        addr_t place) noexcept {
    constexpr u32 kPredictionBit = 0x00200000;
    const bool predict_taken =
        relocation_type == type::ADDR14_BRTAKEN ||
        relocation_type == type::REL14_BRTAKEN;
    const bool backwards = signed_value(relative(resolved, place)) < 0;
    return predict_taken != backwards ? kPredictionBit : 0u;
}

}  // namespace

RelocationInfo info(u32 relocation_type) noexcept {
    using namespace type;
    switch (relocation_type) {
        case NONE:
            return {.name = "R_PPC_NONE"};
        case ADDR32:
            return {.name = "R_PPC_ADDR32", .width = 4, .alignment = 4,
                    .elf_supported = true};
        case REL32:
            return {.name = "R_PPC_REL32", .width = 4, .alignment = 4,
                    .pc_relative = true, .elf_supported = true};
        case GHS_REL16_HA:
            return {.name = "R_PPC_GHS_REL16_HA", .width = 2, .alignment = 2,
                    .pc_relative = true, .elf_supported = true};
        case GHS_REL16_HI:
            return {.name = "R_PPC_GHS_REL16_HI", .width = 2, .alignment = 2,
                    .pc_relative = true, .elf_supported = true};
        case GHS_REL16_LO:
            return {.name = "R_PPC_GHS_REL16_LO", .width = 2, .alignment = 2,
                    .pc_relative = true, .elf_supported = true};
        case ADDR24:
            return {.name = "R_PPC_ADDR24", .width = 4, .alignment = 4,
                    .branch = true, .callable = true, .elf_supported = true};
        case ADDR16:
            return {.name = "R_PPC_ADDR16", .width = 2, .alignment = 2,
                    .elf_supported = true};
        case ADDR16_LO:
            return {.name = "R_PPC_ADDR16_LO", .width = 2, .alignment = 2,
                    .elf_supported = true};
        case ADDR16_HI:
            return {.name = "R_PPC_ADDR16_HI", .width = 2, .alignment = 2,
                    .elf_supported = true};
        case ADDR16_HA:
            return {.name = "R_PPC_ADDR16_HA", .width = 2, .alignment = 2,
                    .elf_supported = true};
        case ADDR14:
            return {.name = "R_PPC_ADDR14", .width = 4, .alignment = 4,
                    .branch = true, .elf_supported = true};
        case ADDR14_BRTAKEN:
            return {.name = "R_PPC_ADDR14_BRTAKEN", .width = 4,
                    .alignment = 4, .branch = true, .elf_supported = true};
        case ADDR14_BRNTAKEN:
            return {.name = "R_PPC_ADDR14_BRNTAKEN", .width = 4,
                    .alignment = 4, .branch = true, .elf_supported = true};
        case REL24:
            return {.name = "R_PPC_REL24", .width = 4, .alignment = 4,
                    .pc_relative = true, .branch = true, .callable = true,
                    .elf_supported = true};
        case REL14:
            return {.name = "R_PPC_REL14", .width = 4, .alignment = 4,
                    .pc_relative = true, .branch = true,
                    .elf_supported = true};
        case REL14_BRTAKEN:
            return {.name = "R_PPC_REL14_BRTAKEN", .width = 4,
                    .alignment = 4, .pc_relative = true, .branch = true,
                    .elf_supported = true};
        case REL14_BRNTAKEN:
            return {.name = "R_PPC_REL14_BRNTAKEN", .width = 4,
                    .alignment = 4, .pc_relative = true, .branch = true,
                    .elf_supported = true};
        case UADDR32:
            return {.name = "R_PPC_UADDR32", .width = 4};
        case EMB_SDA21:
            return {.name = "R_PPC_EMB_SDA21", .width = 4, .alignment = 4};
        case DOLPHIN_MRKREF:
            return {.name = "R_DOLPHIN_MRKREF"};
        default:
            return {};
    }
}

u32 resolve(addr_t symbol, i64 addend) noexcept {
    return static_cast<u32>(symbol) + static_cast<u32>(addend);
}

bool encode(std::span<std::byte> field, u32 relocation_type,
            Endian endian, u32 resolved, addr_t place) noexcept {
    const RelocationInfo properties = info(relocation_type);
    if (properties.width == 0 || field.size() < properties.width ||
        place % properties.alignment != 0) {
        return false;
    }

    using namespace type;
    switch (relocation_type) {
        case ADDR32:
        case UADDR32:
            write_at<u32>(endian, field.data(), resolved);
            return true;
        case REL32:
            write_at<u32>(endian, field.data(), relative(resolved, place));
            return true;
        case GHS_REL16_HA:
            write_at<u16>(endian, field.data(), static_cast<u16>((relative(resolved, place) + 0x8000u) >> 16));
            return true;
        case GHS_REL16_HI:
            write_at<u16>(endian, field.data(), static_cast<u16>(relative(resolved, place) >> 16));
            return true;
        case GHS_REL16_LO:
            write_at<u16>(endian, field.data(), static_cast<u16>(relative(resolved, place)));
            return true;
        case ADDR24:
            if (!fits_signed(resolved, 3u, -0x02000000LL, 0x01fffffcLL)) {
                return false;
            }
            write_at<u32>(endian, field.data(),
                (read_at<u32>(endian, field.data()) & ~0x03fffffcu) |
                (resolved & 0x03fffffcu));
            return true;
        case ADDR16:
            if (!fits_signed(resolved, 0u, -0x8000LL, 0x7fffLL)) return false;
            write_at<u16>(endian, field.data(), static_cast<u16>(resolved));
            return true;
        case ADDR16_LO:
            write_at<u16>(endian, field.data(), static_cast<u16>(resolved));
            return true;
        case ADDR16_HI:
            write_at<u16>(endian, field.data(),
                          static_cast<u16>(resolved >> 16));
            return true;
        case ADDR16_HA:
            write_at<u16>(endian, field.data(),
                static_cast<u16>((resolved + 0x8000u) >> 16));
            return true;
        case ADDR14:
        case ADDR14_BRTAKEN:
        case ADDR14_BRNTAKEN: {
            if (!fits_signed(resolved, 3u, -0x8000LL, 0x7ffcLL)) return false;
            u32 word = read_at<u32>(endian, field.data());
            word = (word & ~0x0000fffcu) | (resolved & 0x0000fffcu);
            if (relocation_type != ADDR14) {
                constexpr u32 kPredictionBit = 0x00200000;
                word = (word & ~kPredictionBit) |
                    branch_prediction_bit(relocation_type, resolved, place);
            }
            write_at<u32>(endian, field.data(), word);
            return true;
        }
        case REL24: {
            const u32 delta = relative(resolved, place);
            if (!fits_signed(delta, 3u, -0x02000000LL, 0x01fffffcLL)) {
                return false;
            }
            write_at<u32>(endian, field.data(),
                (read_at<u32>(endian, field.data()) & ~0x03fffffcu) |
                (delta & 0x03fffffcu));
            return true;
        }
        case REL14:
        case REL14_BRTAKEN:
        case REL14_BRNTAKEN: {
            const u32 delta = relative(resolved, place);
            if (!fits_signed(delta, 3u, -0x8000LL, 0x7ffcLL)) return false;
            u32 word = read_at<u32>(endian, field.data());
            word = (word & ~0x0000fffcu) | (delta & 0x0000fffcu);
            if (relocation_type != REL14) {
                constexpr u32 kPredictionBit = 0x00200000;
                word = (word & ~kPredictionBit) |
                    branch_prediction_bit(relocation_type, resolved, place);
            }
            write_at<u32>(endian, field.data(), word);
            return true;
        }
        default:
            return false;
    }
}

}  // namespace ember::ppc32
