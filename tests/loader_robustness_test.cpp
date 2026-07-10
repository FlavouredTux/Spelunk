#include <ember/binary/macho.hpp>
#include <ember/binary/minidump.hpp>

#include <array>
#include <cstdio>
#include <vector>

namespace {

int fails = 0;

void check(bool condition, const char* message) {
    if (condition) return;
    std::fprintf(stderr, "FAIL: %s\n", message);
    ++fails;
}

void put32(std::vector<std::byte>& bytes, std::size_t off, ember::u32 value) {
    for (unsigned i = 0; i < 4; ++i) {
        bytes[off + i] = static_cast<std::byte>((value >> (i * 8)) & 0xff);
    }
}

std::vector<std::byte> minidump_header(std::size_t size = 32) {
    std::vector<std::byte> bytes(size);
    put32(bytes, 0, 0x504d444d);
    put32(bytes, 4, 0x0000a793);
    return bytes;
}

void test_minidump_rejects_invalid_rvas() {
    {
        auto bytes = minidump_header();
        put32(bytes, 8, 1);
        put32(bytes, 12, 0xffffffff);
        check(!ember::MinidumpBinary::load_from_buffer(std::move(bytes)),
              "minidump rejects wrapped directory RVA");
    }

    constexpr std::array<ember::u32, 5> consumed_streams{7, 4, 5, 9, 16};
    for (ember::u32 type : consumed_streams) {
        auto bytes = minidump_header(44);
        put32(bytes, 8, 1);
        put32(bytes, 12, 32);
        put32(bytes, 32, type);
        put32(bytes, 36, 16);
        put32(bytes, 40, 0xffffffff);
        check(!ember::MinidumpBinary::load_from_buffer(std::move(bytes)),
              "minidump rejects consumed stream outside file");
    }
}

void test_minidump_counts_are_bounded_by_stream() {
    auto bytes = minidump_header(48);
    put32(bytes, 8, 1);
    put32(bytes, 12, 32);
    put32(bytes, 32, 5);   // MemoryListStream
    put32(bytes, 36, 4);   // only the count belongs to this stream
    put32(bytes, 40, 44);
    put32(bytes, 44, 1);   // claims one 16-byte descriptor
    check(!ember::MinidumpBinary::load_from_buffer(std::move(bytes)),
          "minidump range count cannot consume neighboring streams");
}

std::vector<std::byte> macho_header(ember::u32 ncmds, ember::u32 sizeofcmds) {
    std::vector<std::byte> bytes(32 + sizeofcmds);
    put32(bytes, 0, 0xfeedfacf);
    put32(bytes, 4, 0x01000007);  // CPU_TYPE_X86_64
    put32(bytes, 16, ncmds);
    put32(bytes, 20, sizeofcmds);
    return bytes;
}

void test_macho_validates_command_count_before_allocating() {
    check(!ember::MachOBinary::load_from_buffer(macho_header(0xffffffff, 0)),
          "Mach-O rejects impossible load-command count");
    check(!ember::MachOBinary::load_from_buffer(macho_header(1, 0)),
          "Mach-O rejects command count without command bytes");

    auto malformed = macho_header(1, 8);
    put32(malformed, 32, 1);
    put32(malformed, 36, 4);  // cmdsize must be at least 8
    check(!ember::MachOBinary::load_from_buffer(std::move(malformed)),
          "Mach-O rejects undersized load command");
}

}  // namespace

int main() {
    test_minidump_rejects_invalid_rvas();
    test_minidump_counts_are_bounded_by_stream();
    test_macho_validates_command_count_before_allocating();
    return fails == 0 ? 0 : 1;
}
