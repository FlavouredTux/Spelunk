#include <spelunk/analysis/cfg_builder.hpp>
#include <spelunk/analysis/function.hpp>
#include <spelunk/binary/raw_regions.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/disasm/x64_decoder.hpp>
#include <spelunk/ir/ssa.hpp>

#include <algorithm>
#include <array>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <initializer_list>

namespace fs = std::filesystem;

namespace {

int fails = 0;

// Lay `code` at the region start and a PIC offset table at +0x40, decode the
// function, and check its switch has exactly `cases` targets. Each table is
// followed by entries that still point into code, as when the next switch's
// table sits right behind it; a guard that is missed lets the table probe
// run on into them.
void check_switch(const char* name, std::initializer_list<unsigned char> code,
                  std::initializer_list<int> table_targets, std::size_t cases,
                  spelunk::Reg index) {
    constexpr spelunk::addr_t base = 0x1000;
    std::array<unsigned char, 0x60> image{};
    image.fill(0xcc);
    std::copy(code.begin(), code.end(), image.begin());
    std::size_t slot = 0x40;
    for (const int target : table_targets) {
        const auto offset = static_cast<unsigned>(target - 0x40);
        for (unsigned byte = 0; byte < 4; ++byte)
            image[slot + byte] = static_cast<unsigned char>(offset >> (8 * byte));
        slot += 4;
    }

    const fs::path path = fs::temp_directory_path() / "spelunk_jump_table_bound.bin";
    {
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        f.write(reinterpret_cast<const char*>(image.data()),
                static_cast<std::streamsize>(image.size()));
    }
    auto binary = spelunk::RawRegionsBinary::load_from_raw_bytes(path, base);
    fs::remove(path);
    if (!binary) {
        std::fprintf(stderr, "FAIL %s: load raw bytes\n", name);
        ++fails;
        return;
    }
    const spelunk::X64Decoder decoder;
    const spelunk::CfgBuilder builder(**binary, decoder, false);
    const auto function = builder.build(base);
    if (!function) {
        std::fprintf(stderr, "FAIL %s: build CFG\n", name);
        ++fails;
        return;
    }
    bool found = false;
    for (const auto& block : function->blocks) {
        if (block.kind != spelunk::BlockKind::Switch) continue;
        found = true;
        if (block.case_values.size() != cases) {
            std::fprintf(stderr, "FAIL %s: %zu cases, expected %zu\n", name,
                         block.case_values.size(), cases);
            ++fails;
        }
        if (spelunk::canonical_reg(block.switch_index) != index) {
            std::fprintf(stderr, "FAIL %s: wrong switch index register\n", name);
            ++fails;
        }
    }
    if (!found) {
        std::fprintf(stderr, "FAIL %s: no switch block\n", name);
        ++fails;
    }
}

}  // namespace

int main() {
    // `cmp byte ptr [rdi + 0x10], 2; ja` compares the selector in memory and
    // reloads it with movzx before indexing.
    check_switch("memory guard",
                 {
                     0x80, 0x7f, 0x10, 0x02,                    // 00 cmp byte ptr [rdi+0x10], 2
                     0x77, 0x26,                                // 04 ja 2c
                     0x0f, 0xb6, 0x47, 0x10,                    // 06 movzx eax, byte ptr [rdi+0x10]
                     0x48, 0x8d, 0x15, 0x2f, 0x00, 0x00, 0x00,  // 0a lea rdx, [rip+0x2f] -> 40
                     0x48, 0x63, 0x04, 0x82,                    // 11 movsxd rax, [rdx+rax*4]
                     0x48, 0x01, 0xd0,                          // 15 add rax, rdx
                     0xff, 0xe0,                                // 18 jmp rax
                     0xb8, 0x00, 0x00, 0x00, 0x00, 0xc3,        // 1a case 0
                     0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3,        // 20 case 1
                     0xb8, 0x02, 0x00, 0x00, 0x00, 0xc3,        // 26 case 2
                     0xb8, 0xff, 0xff, 0xff, 0xff, 0xc3,        // 2c default
                 },
                 {0x1a, 0x20, 0x26, 0x1b, 0x21}, 3, spelunk::Reg::Rax);
    // `cmp edx, 2; jbe table_block` branches into the jump's block when in
    // range and falls through to the default.
    check_switch("jbe into the table block",
                 {
                     0x83, 0xfa, 0x02,                          // 00 cmp edx, 2
                     0x76, 0x0b,                                // 03 jbe 10
                     0xb8, 0xff, 0xff, 0xff, 0xff, 0xc3,        // 05 default
                     0xcc, 0xcc, 0xcc, 0xcc, 0xcc,              // 0b
                     0x48, 0x8d, 0x0d, 0x29, 0x00, 0x00, 0x00,  // 10 lea rcx, [rip+0x29] -> 40
                     0x48, 0x63, 0x04, 0x91,                    // 17 movsxd rax, [rcx+rdx*4]
                     0x48, 0x01, 0xc8,                          // 1b add rax, rcx
                     0xff, 0xe0,                                // 1e jmp rax
                     0xb8, 0x00, 0x00, 0x00, 0x00, 0xc3,        // 20 case 0
                     0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3,        // 26 case 1
                     0xb8, 0x02, 0x00, 0x00, 0x00, 0xc3,        // 2c case 2
                 },
                 {0x20, 0x26, 0x2c, 0x21, 0x27}, 3, spelunk::Reg::Rdx);
    // `and edx, 3` masks the index into range with no compare.
    check_switch("mask guard",
                 {
                     0x83, 0xe2, 0x03,                          // 00 and edx, 3
                     0x48, 0x8d, 0x0d, 0x36, 0x00, 0x00, 0x00,  // 03 lea rcx, [rip+0x36] -> 40
                     0x48, 0x63, 0x04, 0x91,                    // 0a movsxd rax, [rcx+rdx*4]
                     0x48, 0x01, 0xc8,                          // 0e add rax, rcx
                     0xff, 0xe0,                                // 11 jmp rax
                     0xb8, 0x00, 0x00, 0x00, 0x00, 0xc3,        // 13 case 0
                     0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3,        // 19 case 1
                     0xb8, 0x02, 0x00, 0x00, 0x00, 0xc3,        // 1f case 2
                     0xb8, 0x03, 0x00, 0x00, 0x00, 0xc3,        // 25 case 3
                 },
                 {0x13, 0x19, 0x1f, 0x25, 0x14, 0x1a}, 4, spelunk::Reg::Rdx);
    return fails == 0 ? 0 : 1;
}
