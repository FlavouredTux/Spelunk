#include <cstdlib>
#include <iostream>
#include <vector>

#include <ember/binary/pe.hpp>
#include <ember/common/bytes.hpp>

namespace {

using namespace ember;

void put16(std::vector<std::byte>& b, std::size_t off, u16 v) {
    b[off + 0] = static_cast<std::byte>(v & 0xffu);
    b[off + 1] = static_cast<std::byte>((v >> 8) & 0xffu);
}

void put32(std::vector<std::byte>& b, std::size_t off, u32 v) {
    for (std::size_t i = 0; i < 4; ++i) {
        b[off + i] = static_cast<std::byte>((v >> (i * 8)) & 0xffu);
    }
}

void put64(std::vector<std::byte>& b, std::size_t off, u64 v) {
    for (std::size_t i = 0; i < 8; ++i) {
        b[off + i] = static_cast<std::byte>((v >> (i * 8)) & 0xffu);
    }
}

void section(std::vector<std::byte>& b, std::size_t off, const char* name,
             u32 vsize, u32 vrva, u32 rsize, u32 roff, u32 chars) {
    for (std::size_t i = 0; i < 8 && name[i] != '\0'; ++i) {
        b[off + i] = static_cast<std::byte>(name[i]);
    }
    put32(b, off + 0x08, vsize);
    put32(b, off + 0x0c, vrva);
    put32(b, off + 0x10, rsize);
    put32(b, off + 0x14, roff);
    put32(b, off + 0x24, chars);
}

void check(bool ok, const char* msg) {
    if (ok) return;
    std::cerr << "pe_reloc_test: " << msg << "\n";
    std::exit(1);
}

}  // namespace

int main() {
    constexpr addr_t image_base = 0x140000000;
    constexpr u32 text_rva = 0x1000;
    constexpr u32 rdata_rva = 0x2000;
    constexpr u32 reloc_rva = 0x3000;
    constexpr u32 text_off = 0x200;
    constexpr u32 rdata_off = 0x400;
    constexpr u32 reloc_off = 0x600;
    constexpr u32 slot_rva = rdata_rva + 0x18;
    constexpr addr_t target = image_base + text_rva + 0x40;

    std::vector<std::byte> b(0x800);
    b[0] = std::byte{'M'};
    b[1] = std::byte{'Z'};
    put32(b, 0x3c, 0x80);
    b[0x80] = std::byte{'P'};
    b[0x81] = std::byte{'E'};

    const std::size_t coff = 0x84;
    put16(b, coff + 0x00, 0x8664);
    put16(b, coff + 0x02, 3);
    put16(b, coff + 0x10, 240);
    put16(b, coff + 0x12, 0x22);

    const std::size_t opt = coff + 20;
    put16(b, opt + 0x00, 0x20b);
    put32(b, opt + 0x10, text_rva);
    put64(b, opt + 0x18, image_base);
    put32(b, opt + 0x20, 0x1000);
    put32(b, opt + 0x24, 0x200);
    put32(b, opt + 0x38, 0x4000);
    put32(b, opt + 0x3c, 0x200);
    put32(b, opt + 0x6c, 16);
    put32(b, opt + 0x70 + 5 * 8, reloc_rva);
    put32(b, opt + 0x70 + 5 * 8 + 4, 12);

    const std::size_t sec = opt + 240;
    section(b, sec + 0 * 40, ".text", 1, text_rva, 0x200, text_off,
            0x60000020);
    section(b, sec + 1 * 40, ".rdata", 0x20, rdata_rva, 0x200, rdata_off,
            0x40000040);
    section(b, sec + 2 * 40, ".reloc", 12, reloc_rva, 0x200, reloc_off,
            0x40000040);

    b[text_off] = std::byte{0xc3};
    put64(b, rdata_off + 0x18, target);
    put32(b, reloc_off + 0, rdata_rva);
    put32(b, reloc_off + 4, 12);
    put16(b, reloc_off + 8, static_cast<u16>((10u << 12) | 0x18u));
    put16(b, reloc_off + 10, 0);

    auto malformed_exports = b;
    put32(malformed_exports, opt + 0x70, rdata_rva);
    put32(malformed_exports, opt + 0x74, 40);
    put32(malformed_exports, sec + 1 * 40 + 0x08, 0x200);
    put32(malformed_exports, rdata_off + 0x14, 0xffffffff);

    auto pe = PeBinary::load_from_buffer(std::move(b));
    check(pe.has_value(), "synthetic PE should load");

    const auto relocs = (*pe)->relocated_qwords();
    check(relocs.size() == 1, "expected one DIR64 relocation");
    const auto it = relocs.find(image_base + slot_rva);
    check(it != relocs.end(), "relocated slot VA missing");
    check(it->second == target, "relocated target VA mismatch");
    check(!PeBinary::load_from_buffer(std::move(malformed_exports)),
          "oversized export count must be rejected before allocation");
    return 0;
}
