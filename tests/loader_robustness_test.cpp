#include <ember/binary/dol.hpp>
#include <ember/binary/elf.hpp>
#include <ember/binary/macho.hpp>
#include <ember/binary/minidump.hpp>
#include <ember/binary/pdb.hpp>
#include <ember/binary/pe.hpp>
#include <ember/binary/rel.hpp>

#include <array>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <utility>
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

}  // namespace

// Every file under tests/fuzz/corpus once made a loader crash or
// allocate an absurd amount. Each is fed to every loader; the only
// requirement is that the process survives.
void test_fuzz_corpus_replays_cleanly() {
#ifdef EMBER_FUZZ_CORPUS_DIR
    namespace fs = std::filesystem;
    std::size_t replayed = 0;
    for (const auto& entry : fs::recursive_directory_iterator(EMBER_FUZZ_CORPUS_DIR)) {
        if (!entry.is_regular_file()) continue;
        std::ifstream in(entry.path(), std::ios::binary);
        std::vector<char> raw((std::istreambuf_iterator<char>(in)),
                              std::istreambuf_iterator<char>());
        std::vector<std::byte> bytes(raw.size());
        for (std::size_t i = 0; i < raw.size(); ++i) bytes[i] = static_cast<std::byte>(raw[i]);
        (void)ember::ElfBinary::load_from_buffer(bytes);
        (void)ember::PeBinary::load_from_buffer(bytes);
        (void)ember::MachOBinary::load_from_buffer(bytes);
        (void)ember::MinidumpBinary::load_from_buffer(bytes);
        (void)ember::DolBinary::load_from_buffer(bytes);
        (void)ember::RelBinary::load_from_buffer(bytes);
        (void)ember::pdb::load_pdb_from_buffer(bytes);
        ++replayed;
    }
    check(replayed >= 2, "fuzz corpus inputs were found and replayed");
#endif
}

int main() {
    test_minidump_rejects_invalid_rvas();
    test_minidump_counts_are_bounded_by_stream();
    test_fuzz_corpus_replays_cleanly();
    return fails == 0 ? 0 : 1;
}
