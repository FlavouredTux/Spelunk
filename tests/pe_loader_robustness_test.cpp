#include <ember/binary/pe.hpp>
#include <ember/binary/pe_view.hpp>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {

int failures = 0;

void check(bool condition, const char* message) {
    if (condition) return;
    std::fprintf(stderr, "FAIL: %s\n", message);
    ++failures;
}

void put16(std::vector<std::byte>& bytes, std::size_t offset,
           ember::u16 value) {
    bytes[offset] = static_cast<std::byte>(value);
    bytes[offset + 1] = static_cast<std::byte>(value >> 8);
}

void put32(std::vector<std::byte>& bytes, std::size_t offset,
           ember::u32 value) {
    for (unsigned index = 0; index < 4; ++index) {
        bytes[offset + index] = static_cast<std::byte>(value >> (index * 8));
    }
}

void put64(std::vector<std::byte>& bytes, std::size_t offset,
           ember::u64 value) {
    for (unsigned index = 0; index < 8; ++index) {
        bytes[offset + index] = static_cast<std::byte>(value >> (index * 8));
    }
}

struct PeFixture {
    ember::u16 machine = 0x8664;
    ember::u64 image_base = 0x140000000;
    ember::u32 size_of_image = 0x3000;
    ember::u32 entry_rva = 0;
    ember::u32 section_rva = 0x1000;
    ember::u32 virtual_size = 0x300;
    ember::u32 raw_size = 0x20;
    ember::u32 raw_offset = 0x200;
    std::size_t file_size = 0x220;
};

std::vector<std::byte> make_pe(const PeFixture& fixture = {}) {
    constexpr std::size_t kPeOffset = 0x80;
    constexpr std::size_t kCoffOffset = kPeOffset + 4;
    constexpr std::size_t kOptionalOffset = kCoffOffset + 20;
    constexpr std::size_t kOptionalSize = 0xf0;
    constexpr std::size_t kSectionOffset = kOptionalOffset + kOptionalSize;

    std::vector<std::byte> bytes(fixture.file_size);
    bytes[0] = std::byte{'M'};
    bytes[1] = std::byte{'Z'};
    put32(bytes, 0x3c, static_cast<ember::u32>(kPeOffset));
    bytes[kPeOffset] = std::byte{'P'};
    bytes[kPeOffset + 1] = std::byte{'E'};

    put16(bytes, kCoffOffset, fixture.machine);
    put16(bytes, kCoffOffset + 2, 1);
    put16(bytes, kCoffOffset + 0x10,
          static_cast<ember::u16>(kOptionalSize));

    put16(bytes, kOptionalOffset, 0x20b);
    put32(bytes, kOptionalOffset + 0x10, fixture.entry_rva);
    put64(bytes, kOptionalOffset + 0x18, fixture.image_base);
    put32(bytes, kOptionalOffset + 0x20, 0x1000);
    put32(bytes, kOptionalOffset + 0x24, 0x200);
    put32(bytes, kOptionalOffset + 0x38, fixture.size_of_image);
    put32(bytes, kOptionalOffset + 0x3c, 0x200);
    put32(bytes, kOptionalOffset + 0x6c, 0);

    constexpr std::array name{
        std::byte{'.'}, std::byte{'d'}, std::byte{'a'}, std::byte{'t'},
        std::byte{'a'}, std::byte{0}, std::byte{0}, std::byte{0},
    };
    std::ranges::copy(name, bytes.begin() + kSectionOffset);
    put32(bytes, kSectionOffset + 0x08, fixture.virtual_size);
    put32(bytes, kSectionOffset + 0x0c, fixture.section_rva);
    put32(bytes, kSectionOffset + 0x10, fixture.raw_size);
    put32(bytes, kSectionOffset + 0x14, fixture.raw_offset);
    put32(bytes, kSectionOffset + 0x24, 0xc0000040);
    return bytes;
}

void test_image_extent_and_zero_fill() {
    auto loaded = ember::PeBinary::load_from_buffer(make_pe());
    check(loaded.has_value(), "valid PE32+ fixture loads");
    if (!loaded) return;

    check((*loaded)->mapped_size() == 0x3000,
          "mapped size uses SizeOfImage");
    check((*loaded)->sections().size() == 1 &&
              (*loaded)->sections()[0].size == 0x300 &&
              (*loaded)->sections()[0].data.size() == 0x20,
          "section retains virtual size and file-backed prefix");
    check(!(*loaded)->bytes_at(0x14000101f).empty() &&
              (*loaded)->bytes_at(0x140001020).empty(),
          "zero-filled section tail is not exposed as file bytes");
}

void test_section_and_header_bounds() {
    PeFixture truncated_raw;
    truncated_raw.virtual_size = 1;
    truncated_raw.raw_size = 0x40;
    truncated_raw.raw_offset = 0x210;
    check(!ember::PeBinary::load_from_buffer(make_pe(truncated_raw)),
          "initialized section raw range must fit the file");

    PeFixture virtual_overflow;
    virtual_overflow.section_rva = 0x2000;
    virtual_overflow.virtual_size = 0x2000;
    check(!ember::PeBinary::load_from_buffer(make_pe(virtual_overflow)),
          "section virtual range must fit SizeOfImage");

    PeFixture wrapping_virtual_range;
    wrapping_virtual_range.section_rva = 0xfffffff0;
    wrapping_virtual_range.virtual_size = 0x40;
    check(!ember::PeBinary::load_from_buffer(make_pe(wrapping_virtual_range)),
          "section RVA addition is widened before validation");

    PeFixture zero_image;
    zero_image.size_of_image = 0;
    zero_image.section_rva = 0;
    zero_image.virtual_size = 0;
    zero_image.raw_size = 0;
    zero_image.raw_offset = 0;
    check(!ember::PeBinary::load_from_buffer(make_pe(zero_image)),
          "zero SizeOfImage is rejected");

    PeFixture address_overflow;
    address_overflow.image_base =
        std::numeric_limits<ember::addr_t>::max() - 0x1000;
    check(!ember::PeBinary::load_from_buffer(make_pe(address_overflow)),
          "image base plus SizeOfImage cannot wrap");

    PeFixture bad_entry;
    bad_entry.entry_rva = bad_entry.size_of_image;
    const auto bad_entry_result =
        ember::PeBinary::load_from_buffer(make_pe(bad_entry));
    check(!bad_entry_result &&
              bad_entry_result.error().message.find("outside SizeOfImage") !=
                  std::string::npos,
          "entry RVA must lie inside SizeOfImage");

    PeFixture i386_pe32_plus;
    i386_pe32_plus.machine = 0x014c;
    check(!ember::PeBinary::load_from_buffer(make_pe(i386_pe32_plus)),
          "I386 machine cannot claim a PE32+ optional header");

    PeFixture arm64_pe32_plus;
    arm64_pe32_plus.machine = 0xaa64;
    auto arm64 = ember::PeBinary::load_from_buffer(make_pe(arm64_pe32_plus));
    check(arm64.has_value() && (*arm64)->arch() == ember::Arch::Arm64,
          "ARM64 PE32+ remains supported");
}

class MockBinary final : public ember::Binary {
public:
    void add_region(ember::addr_t base, std::vector<std::byte> bytes) {
        regions_.push_back({base, std::move(bytes)});
    }

    [[nodiscard]] ember::Format format() const noexcept override {
        return ember::Format::Pe;
    }
    [[nodiscard]] ember::Arch arch() const noexcept override {
        return ember::Arch::X86_64;
    }
    [[nodiscard]] ember::Endian endian() const noexcept override {
        return ember::Endian::Little;
    }
    [[nodiscard]] ember::addr_t entry_point() const noexcept override {
        return 0;
    }
    [[nodiscard]] std::span<const ember::Section>
    sections() const noexcept override {
        return {};
    }
    [[nodiscard]] std::span<const ember::Symbol>
    symbols() const noexcept override {
        return symbols_;
    }
    [[nodiscard]] std::span<const std::byte>
    image() const noexcept override {
        return {};
    }
    [[nodiscard]] std::span<const std::byte>
    bytes_at(ember::addr_t address) const noexcept override {
        for (const auto& region : regions_) {
            if (address < region.base) continue;
            const auto offset = address - region.base;
            if (offset >= region.bytes.size()) continue;
            return std::span<const std::byte>(region.bytes).subspan(
                static_cast<std::size_t>(offset));
        }
        return {};
    }

protected:
    [[nodiscard]] std::vector<ember::Symbol>&
    mutable_symbols() noexcept override {
        return symbols_;
    }

private:
    struct Region {
        ember::addr_t base;
        std::vector<std::byte> bytes;
    };
    std::vector<Region> regions_;
    std::vector<ember::Symbol> symbols_;
};

std::vector<std::byte> import_descriptor(ember::u32 int_rva,
                                         ember::u32 name_rva,
                                         ember::u32 iat_rva) {
    std::vector<std::byte> bytes(20);
    put32(bytes, 0, int_rva);
    put32(bytes, 0x0c, name_rva);
    put32(bytes, 0x10, iat_rva);
    return bytes;
}

void test_import_rva_overflow() {
    MockBinary empty;
    empty.add_region(0, {std::byte{0x7f}});
    std::vector<ember::pe::DataDirectory> directories(14);
    std::vector<ember::Symbol> symbols;

    directories[1] = {0xfffffff8, 20};
    check(!ember::pe::collect_imports(empty, 0, directories, symbols),
          "import directory range cannot wrap the RVA space");
    directories[1] = {};
    directories[13] = {0xfffffff0, 32};
    check(!ember::pe::collect_delay_imports(empty, 0, directories, symbols),
          "delay-import directory range cannot wrap the RVA space");

    MockBinary overflowing_name;
    overflowing_name.add_region(
        0x1000, import_descriptor(0x1200, 0x1100, 0x1200));
    overflowing_name.add_region(0x1100,
        {std::byte{'x'}, std::byte{0}});
    std::vector<std::byte> name_table(16);
    put64(name_table, 0, 0xffffffffu);
    overflowing_name.add_region(0x1200, std::move(name_table));
    directories[13] = {};
    directories[1] = {0x1000, 20};
    check(!ember::pe::collect_imports(
              overflowing_name, 0, directories, symbols),
          "hint/name RVA addition cannot wrap");

    MockBinary oversized_name_rva;
    oversized_name_rva.add_region(
        0x1000, import_descriptor(0x1200, 0x1100, 0x1200));
    oversized_name_rva.add_region(0x1100,
        {std::byte{'x'}, std::byte{0}});
    std::vector<std::byte> oversized_name_table(16);
    put64(oversized_name_table, 0, 0x100000000ull);
    oversized_name_rva.add_region(0x1200, std::move(oversized_name_table));
    check(!ember::pe::collect_imports(
              oversized_name_rva, 0, directories, symbols),
          "64-bit import name values are rejected in a real INT");

    MockBinary unterminated_table;
    unterminated_table.add_region(
        0x1000, import_descriptor(0x1200, 0x1100, 0x1200));
    unterminated_table.add_region(0x1100,
        {std::byte{'x'}, std::byte{0}});
    std::vector<std::byte> one_thunk(8);
    constexpr ember::u64 kOrdinal = 0x8000000000000000ull;
    put64(one_thunk, 0, kOrdinal | 1);
    unterminated_table.add_region(0x1200, std::move(one_thunk));
    check(!ember::pe::collect_imports(
              unterminated_table, 0, directories, symbols),
          "import thunk tables require a null terminator");

    MockBinary resolved_iat;
    resolved_iat.add_region(
        0x1000, import_descriptor(0, 0x1100, 0x1200));
    resolved_iat.add_region(0x1100,
        {std::byte{'x'}, std::byte{0}});
    std::vector<std::byte> runtime_iat(16);
    put64(runtime_iat, 0, 0x00007fff12345678ull);
    resolved_iat.add_region(0x1200, std::move(runtime_iat));
    symbols.clear();
    const auto resolved_iat_result = ember::pe::collect_imports(
        resolved_iat, 0, directories, symbols);
    check(resolved_iat_result.has_value() && symbols.empty(),
          "runtime-resolved IAT fallback is skipped without rejecting exports");

    MockBinary overflowing_table;
    overflowing_table.add_region(
        0x1000, import_descriptor(0xfffffff8, 0x1100, 0xfffffff8));
    overflowing_table.add_region(0x1100,
        {std::byte{'x'}, std::byte{0}});
    std::vector<std::byte> high_table(24);
    put64(high_table, 0, kOrdinal | 1);
    put64(high_table, 8, kOrdinal | 2);
    overflowing_table.add_region(0xfffffff8, std::move(high_table));
    symbols.clear();
    check(!ember::pe::collect_imports(
              overflowing_table, 0, directories, symbols),
          "import thunk-table advancement cannot wrap");

    check(ember::pe::bytes_at_rva(
              empty, std::numeric_limits<ember::addr_t>::max() - 3, 4)
              .empty(),
          "image-base plus RVA cannot wrap");
}

void test_export_va_overflow() {
    const ember::addr_t image_base =
        std::numeric_limits<ember::addr_t>::max() - 0x2000;
    std::vector<std::byte> image(0x230);
    put32(image, 0x10, 1);       // ordinal base
    put32(image, 0x14, 1);       // number of functions
    put32(image, 0x18, 1);       // number of names
    put32(image, 0x1c, 0x1100);  // export address table
    put32(image, 0x20, 0x1200);  // export name table
    put32(image, 0x24, 0x1210);  // export ordinal table
    put32(image, 0x100, 0x3000); // function RVA overflows image_base
    put32(image, 0x200, 0x1220);
    put16(image, 0x210, 0);
    image[0x220] = std::byte{'f'};
    image[0x221] = std::byte{0};

    MockBinary binary;
    binary.add_region(image_base + 0x1000, std::move(image));
    std::vector<ember::pe::DataDirectory> directories(1);
    directories[0] = {0x1000, 40};
    std::vector<ember::Symbol> symbols;
    check(!ember::pe::collect_exports(
              binary, image_base, directories, symbols),
          "export VA addition cannot wrap");
}

}  // namespace

int main() {
    test_image_extent_and_zero_fill();
    test_section_and_header_bounds();
    test_import_rva_overflow();
    test_export_va_overflow();
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
