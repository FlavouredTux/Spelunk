// libFuzzer harness for the PDB reader: MSF superblock, directory, DBI
// header and symbol records parsed from an arbitrary buffer.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include <spelunk/binary/pdb.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::vector<std::byte> buffer(size);
    if (size != 0) std::memcpy(buffer.data(), data, size);
    auto reader = spelunk::pdb::load_pdb_from_buffer(std::move(buffer));
    if (!reader) return 0;
    std::size_t touched = 0;
    for (const auto& sym : reader->publics) touched += sym.name.size();
    volatile const std::size_t touched_sink = touched;
    (void)touched_sink;
    return 0;
}
