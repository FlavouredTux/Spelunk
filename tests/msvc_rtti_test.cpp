#include <cstdlib>
#include <iostream>
#include <vector>

#include <ember/analysis/discovery.hpp>
#include <ember/analysis/msvc_rtti.hpp>
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

void put_cstr(std::vector<std::byte>& b, std::size_t off, const char* s) {
    for (std::size_t i = 0; s[i] != '\0'; ++i) {
        b[off + i] = static_cast<std::byte>(s[i]);
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
    std::cerr << "msvc_rtti_test: " << msg << "\n";
    std::exit(1);
}

}  // namespace

int main() {
    constexpr addr_t image_base = 0x140000000;
    constexpr u32 text_rva = 0x1000;
    constexpr u32 rdata_rva = 0x2000;
    constexpr u32 text_off = 0x200;
    constexpr u32 rdata_off = 0x400;
    constexpr u32 text_size = 0x10;
    constexpr u32 rdata_size = 0x300;

    constexpr u32 vtable_rva = rdata_rva + 0x08;
    constexpr u32 col_rva = rdata_rva + 0x40;
    constexpr u32 td_derived_rva = rdata_rva + 0x80;
    constexpr u32 td_base_rva = rdata_rva + 0xb0;
    constexpr u32 chd_rva = rdata_rva + 0xe0;
    constexpr u32 bca_rva = rdata_rva + 0x100;
    constexpr u32 bcd_derived_rva = rdata_rva + 0x120;
    constexpr u32 bcd_base_rva = rdata_rva + 0x140;

    std::vector<std::byte> b(0x800);
    b[0] = std::byte{'M'};
    b[1] = std::byte{'Z'};
    put32(b, 0x3c, 0x80);
    b[0x80] = std::byte{'P'};
    b[0x81] = std::byte{'E'};

    const std::size_t coff = 0x84;
    put16(b, coff + 0x00, 0x8664);
    put16(b, coff + 0x02, 2);
    put16(b, coff + 0x10, 240);
    put16(b, coff + 0x12, 0x22);

    const std::size_t opt = coff + 20;
    put16(b, opt + 0x00, 0x20b);
    put32(b, opt + 0x10, text_rva);
    put64(b, opt + 0x18, image_base);
    put32(b, opt + 0x20, 0x1000);
    put32(b, opt + 0x24, 0x200);
    put32(b, opt + 0x38, 0x3000);
    put32(b, opt + 0x3c, 0x200);
    put32(b, opt + 0x6c, 16);

    const std::size_t sec = opt + 240;
    section(b, sec + 0 * 40, ".text", text_size, text_rva, 0x200, text_off,
            0x40000040);
    section(b, sec + 1 * 40, ".rdata", rdata_size, rdata_rva, 0x400, rdata_off,
            0x40000040);

    b[text_off] = std::byte{0xc3};

    put64(b, rdata_off + 0x00, image_base + col_rva);
    put64(b, rdata_off + 0x08, image_base + text_rva);

    put32(b, rdata_off + 0x40, 1);
    put32(b, rdata_off + 0x4c, td_derived_rva);
    put32(b, rdata_off + 0x50, chd_rva);
    put32(b, rdata_off + 0x54, col_rva);

    put_cstr(b, rdata_off + 0x80 + 16, ".?AVDerived@@");
    put_cstr(b, rdata_off + 0xb0 + 16, ".?AVBase@@");

    put32(b, rdata_off + 0xe0 + 0, 0);
    put32(b, rdata_off + 0xe0 + 4, 0);
    put32(b, rdata_off + 0xe0 + 8, 2);
    put32(b, rdata_off + 0xe0 + 12, bca_rva);

    put32(b, rdata_off + 0x100, bcd_derived_rva);
    put32(b, rdata_off + 0x104, bcd_base_rva);

    put32(b, rdata_off + 0x120 + 0, td_derived_rva);
    put32(b, rdata_off + 0x120 + 4, 2);
    put32(b, rdata_off + 0x120 + 20, 0);

    put32(b, rdata_off + 0x140 + 0, td_base_rva);
    put32(b, rdata_off + 0x140 + 4, 1);
    put32(b, rdata_off + 0x140 + 8, 0x10);
    put32(b, rdata_off + 0x140 + 12, 0xffffffffu);
    put32(b, rdata_off + 0x140 + 16, 0);
    put32(b, rdata_off + 0x140 + 20, 0x40);

    auto pe = PeBinary::load_from_buffer(std::move(b));
    check(pe.has_value(), "synthetic PE should load");
    check(!(*pe)->sections()[0].flags.executable,
          "synthetic .text should not carry the executable flag");
    check(addr_in_code_section(**pe, image_base + text_rva),
          "named PE .text should remain canonical code");

    const auto classes = parse_msvc_rtti(**pe);
    check(classes.size() == 1, "expected one MSVC RTTI class");
    check(classes[0].pretty_name == "Derived", "derived class name");
    check(classes[0].vtable == image_base + vtable_rva, "vtable VA");
    check(classes[0].methods.size() == 1, "one vtable method");
    check(classes[0].methods[0] == image_base + text_rva, "method VA");
    check(classes[0].bases.size() == 1, "self base skipped, real base kept");
    check(classes[0].bases[0].pretty_name == "Base", "base class name");
    check(classes[0].bases[0].mdisp == 0x10, "base member displacement");
    check(classes[0].bases[0].pdisp == -1, "base vbtable displacement");
    check(classes[0].bases[0].attributes == 0x40, "base attributes");

    return 0;
}
