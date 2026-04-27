#pragma once

#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

#include <ember/common/error.hpp>
#include <ember/common/types.hpp>

namespace ember::pdb {

// Public symbol from the PDB's symbol-record stream. Coordinates are
// (segment, offset) pairs — segment is a 1-based index into the PE's
// section table, offset is the byte offset inside that section. Resolving
// to a VA is the caller's responsibility (the PDB does not carry the
// image base or section addresses).
struct PublicSymbol {
    std::string name;
    u32         section_offset = 0;
    u16         segment        = 0;
    bool        is_function    = false;  // S_PUB32.flags bit 1
};

// Multi-Stream File container. The PDB v7 on-disk format is a stream of
// fixed-size blocks; logical "streams" are reconstructed by walking
// per-stream block lists out of the file directory. Provides random
// read-access to each stream as a contiguous byte buffer.
//
// Stream-index conventions (well-known):
//   1 = PDB Info        (signature, age, GUID — used to match against
//                        the .exe's CodeView entry; v1 doesn't verify)
//   2 = TPI             (type index)
//   3 = DBI             (debug info header + module list)
//   4 = IPI             (item index, since pdb v7)
//   ≥5 = module / GSI / PSI / SymRecord / contributions, indexed by
//         per-pdb fields in the DBI header
class Msf {
public:
    [[nodiscard]] static Result<Msf>
    from_buffer(std::vector<std::byte> data);

    [[nodiscard]] u32 num_streams() const noexcept {
        return static_cast<u32>(stream_sizes_.size());
    }
    [[nodiscard]] u32 stream_size(u32 idx) const noexcept {
        return idx < stream_sizes_.size() ? stream_sizes_[idx] : 0;
    }
    // Concatenate every block of stream `idx`, trimmed to its real size.
    // Returns an error if the stream is "deleted" (size == 0xFFFFFFFF) or
    // any block index is out of range. An empty stream → empty buffer
    // (not an error).
    [[nodiscard]] Result<std::vector<std::byte>>
    read_stream(u32 idx) const;

private:
    Msf() noexcept = default;

    std::vector<std::byte>           data_;
    u32                              block_size_ = 0;
    std::vector<u32>                 stream_sizes_;
    std::vector<std::vector<u32>>    stream_blocks_;
};

// Read the PDB at `path`, walk its DBI + symbol-record stream, return
// every S_PUB32 record. Order is preserved as the records appear in the
// PDB.
[[nodiscard]] Result<std::vector<PublicSymbol>>
load_publics(const std::filesystem::path& path);

// Lower-level entry: same, but from already-mmap'd PDB bytes. Used by the
// in-process unit test.
[[nodiscard]] Result<std::vector<PublicSymbol>>
load_publics_from_buffer(std::vector<std::byte> data);

}  // namespace ember::pdb
