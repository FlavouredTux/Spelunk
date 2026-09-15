#include <spelunk/analysis/data_xrefs.hpp>
#include <spelunk/analysis/vtables.hpp>
#include <spelunk/binary/raw_regions.hpp>

#include <array>
#include <cstddef>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string>
#include <string_view>

namespace fs = std::filesystem;

namespace {

int fails = 0;

void fail(const char* ctx) {
    std::fprintf(stderr, "FAIL: %s\n", ctx);
    ++fails;
}

void write_file(const fs::path& path, const void* data, std::size_t size) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f.write(static_cast<const char*>(data), static_cast<std::streamsize>(size));
}

}  // namespace

int main() {
    const fs::path dir = fs::temp_directory_path() / "spelunk_raw_regions_test";
    fs::create_directories(dir);

    constexpr spelunk::addr_t base = 0x7fe341c0d000ull;
    constexpr spelunk::addr_t code = base + 0x2987800ull;
    constexpr spelunk::addr_t code2 = code + 1;
    constexpr spelunk::addr_t slot = base + 0x3000000ull;

    const std::array<unsigned char, 2> code_bytes{0xc3, 0xc3};
    const std::array<unsigned char, 16> data_bytes{
        static_cast<unsigned char>((code >> 0) & 0xff),
        static_cast<unsigned char>((code >> 8) & 0xff),
        static_cast<unsigned char>((code >> 16) & 0xff),
        static_cast<unsigned char>((code >> 24) & 0xff),
        static_cast<unsigned char>((code >> 32) & 0xff),
        static_cast<unsigned char>((code >> 40) & 0xff),
        static_cast<unsigned char>((code >> 48) & 0xff),
        static_cast<unsigned char>((code >> 56) & 0xff),
        static_cast<unsigned char>((code2 >> 0) & 0xff),
        static_cast<unsigned char>((code2 >> 8) & 0xff),
        static_cast<unsigned char>((code2 >> 16) & 0xff),
        static_cast<unsigned char>((code2 >> 24) & 0xff),
        static_cast<unsigned char>((code2 >> 32) & 0xff),
        static_cast<unsigned char>((code2 >> 40) & 0xff),
        static_cast<unsigned char>((code2 >> 48) & 0xff),
        static_cast<unsigned char>((code2 >> 56) & 0xff),
    };

    write_file(dir / "code.bin", code_bytes.data(), code_bytes.size());
    write_file(dir / "data.bin", data_bytes.data(), data_bytes.size());

    const fs::path manifest = dir / "regions.txt";
    const std::string manifest_text =
        "0x7fe344594800  0x2  r-x  code.bin\n"
        "0x7fe344c0d000  0x10  r--  data.bin\n";
    write_file(manifest, manifest_text.data(), manifest_text.size());

    auto loaded = spelunk::RawRegionsBinary::load_from_manifest(manifest);
    if (!loaded) {
        fail("load raw regions manifest");
        return fails == 0 ? 0 : 1;
    }

    const auto xrefs = spelunk::compute_data_xrefs(**loaded);
    auto it = xrefs.find(code);
    if (it == xrefs.end()) {
        fail("relocated pointer target was not indexed");
        return fails == 0 ? 0 : 1;
    }
    if (it->second.size() != 1) fail("unexpected xref count");
    else {
        const auto& xr = it->second.front();
        if (xr.from_pc != slot) fail("xref slot address");
        if (xr.to_addr != code) fail("xref target address");
        if (xr.kind != spelunk::DataXrefKind::CodePtr) fail("xref kind");
    }

    const auto vtables = spelunk::discover_runtime_vtables(**loaded);
    if (vtables.size() != 1) fail("runtime vtable count");
    else {
        if (vtables.front().vaddr != slot) fail("runtime vtable address");
        if (vtables.front().methods.size() != 2) fail("runtime vtable method count");
        if (vtables.front().methods[0] != code) fail("runtime vtable slot 0");
        if (vtables.front().methods[1] != code2) fail("runtime vtable slot 1");
    }

    auto expect_bad_manifest = [&](std::string_view name,
                                   std::string_view contents) {
        const fs::path path = dir / std::string(name);
        write_file(path, contents.data(), contents.size());
        if (spelunk::RawRegionsBinary::load_from_manifest(path)) {
            fail(std::string("accepted malformed manifest: ").append(name).c_str());
        }
    };
    expect_bad_manifest("overlap.txt",
        "0x1000 0x2 r-- code.bin\n0x1001 0x2 r-- code.bin\n");
    expect_bad_manifest("wrap.txt",
        "0xffffffffffffffff 0x2 r-- code.bin\n");
    expect_bad_manifest("zero.txt", "0x1000 0x0 r-- code.bin\n");
    expect_bad_manifest("flags.txt", "0x1000 0x2 read code.bin\n");
    expect_bad_manifest("extra.txt", "0x1000 0x2 r-- code.bin junk\n");
    if (spelunk::RawRegionsBinary::load_from_raw_bytes(
            dir / "code.bin", std::numeric_limits<spelunk::addr_t>::max())) {
        fail("accepted wrapping raw-bytes extent");
    }

    fs::remove_all(dir);
    return fails == 0 ? 0 : 1;
}
