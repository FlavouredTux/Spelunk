#include "ppc32_relocation.hpp"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <span>

namespace {

int failures = 0;

void check(bool condition, const char* message) {
    if (condition) return;
    std::fprintf(stderr, "FAIL: %s\n", message);
    ++failures;
}

std::array<std::byte, 4> big_endian(spelunk::u32 value) {
    return {
        std::byte{static_cast<spelunk::u8>(value >> 24)},
        std::byte{static_cast<spelunk::u8>(value >> 16)},
        std::byte{static_cast<spelunk::u8>(value >> 8)},
        std::byte{static_cast<spelunk::u8>(value)},
    };
}

spelunk::u32 read_big_endian(const std::array<std::byte, 4>& bytes) {
    return (static_cast<spelunk::u32>(bytes[0]) << 24) |
           (static_cast<spelunk::u32>(bytes[1]) << 16) |
           (static_cast<spelunk::u32>(bytes[2]) << 8) |
           static_cast<spelunk::u32>(bytes[3]);
}

void test_branch_prediction() {
    using namespace spelunk::ppc32;
    constexpr spelunk::u32 kInstruction = 0x41820000;
    constexpr spelunk::u32 kPrediction = 0x00200000;
    constexpr spelunk::addr_t kPlace = 0x1000;

    struct Case {
        spelunk::u32 type;
        spelunk::u32 target;
        spelunk::u32 displacement;
        bool prediction_set;
        const char* message;
    };
    constexpr std::array cases{
        Case{type::REL14_BRTAKEN, 0x1100, 0x0100, true,
             "forward BRTAKEN sets the prediction bit"},
        Case{type::REL14_BRTAKEN, 0x0f00, 0xff00, false,
             "backward BRTAKEN inverts the prediction bit"},
        Case{type::REL14_BRNTAKEN, 0x1100, 0x0100, false,
             "forward BRNTAKEN clears the prediction bit"},
        Case{type::REL14_BRNTAKEN, 0x0f00, 0xff00, true,
             "backward BRNTAKEN inverts the prediction bit"},
    };

    for (const auto& test : cases) {
        auto field = big_endian(kInstruction | kPrediction);
        check(encode(field, test.type, spelunk::Endian::Big,
                     test.target, kPlace), test.message);
        const spelunk::u32 word = read_big_endian(field);
        check((word & 0x0000fffcu) == test.displacement, test.message);
        check(((word & kPrediction) != 0) == test.prediction_set,
              test.message);
    }

    auto absolute = big_endian(kInstruction);
    check(encode(absolute, type::ADDR14_BRTAKEN, spelunk::Endian::Big,
                 0x2000, kPlace),
          "absolute ADDR14_BRTAKEN is supported");
    check((read_big_endian(absolute) & (kPrediction | 0x0000fffcu)) ==
              (kPrediction | 0x2000),
          "absolute ADDR14_BRTAKEN writes field and prediction");

    absolute = big_endian(kInstruction | kPrediction);
    check(encode(absolute, type::ADDR14_BRTAKEN, spelunk::Endian::Big,
                 0x0800, kPlace),
          "backward absolute ADDR14_BRTAKEN is supported");
    check((read_big_endian(absolute) & kPrediction) == 0,
          "backward absolute BRTAKEN inverts prediction");
}

void test_metadata_and_alignment() {
    using namespace spelunk::ppc32;
    check(info(type::ADDR14).elf_supported &&
              info(type::ADDR14_BRTAKEN).elf_supported &&
              info(type::ADDR14_BRNTAKEN).elf_supported,
          "ELF supports the absolute 14-bit branch family");
    check(!info(type::UADDR32).elf_supported,
          "ELF keeps UADDR32 outside its supported subset");
    check(info(type::EMB_SDA21).width == 4,
          "EMB_SDA21 reports its instruction width");
    check(info(type::NONE).name == "R_PPC_NONE" &&
              info(type::UADDR32).name == "R_PPC_UADDR32",
          "recognized unencoded relocations retain their names");

    auto aligned = big_endian(0);
    check(encode(aligned, type::ADDR32, spelunk::Endian::Big,
                 0x12345678, 0x1000) &&
              read_big_endian(aligned) == 0x12345678,
          "aligned ADDR32 writes the full word");

    auto unaligned = big_endian(0xaabbccdd);
    const auto before = unaligned;
    check(!encode(unaligned, type::ADDR32, spelunk::Endian::Big,
                  0x12345678, 0x1001) && unaligned == before,
          "unaligned ADDR32 is rejected without modifying bytes");
    check(encode(unaligned, type::UADDR32, spelunk::Endian::Big,
                 0x12345678, 0x1001) &&
              read_big_endian(unaligned) == 0x12345678,
          "UADDR32 permits an unaligned field");

    auto out_of_range = big_endian(0x4182aaaau);
    const auto original = out_of_range;
    check(!encode(out_of_range, type::ADDR14, spelunk::Endian::Big,
                  0x8000, 0x1000) && out_of_range == original,
          "out-of-range ADDR14 leaves the instruction unchanged");
}

}  // namespace

int main() {
    test_branch_prediction();
    test_metadata_and_alignment();
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
