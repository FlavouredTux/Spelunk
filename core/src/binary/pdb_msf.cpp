#include <ember/binary/pdb.hpp>

#include <array>
#include <cstddef>
#include <cstring>
#include <expected>
#include <format>
#include <utility>
#include <vector>

#include <ember/common/bytes.hpp>
#include <ember/common/error.hpp>
#include <ember/common/types.hpp>

namespace ember::pdb {

namespace {

// PDB v7 superblock magic - exactly 32 bytes.
constexpr std::array<u8, 32> kV7Magic{
    'M','i','c','r','o','s','o','f','t',' ','C','/','C','+','+',' ',
    'M','S','F',' ','7','.','0','0','\r','\n',0x1A,'D','S',0,0,0,
};

constexpr std::size_t kSuperblockSize = 56;

[[nodiscard]] inline u32 div_up(u32 a, u32 b) noexcept {
    // Widen the numerator before adding (b - 1) so a near-UINT32_MAX
    // value doesn't wrap and produce a tiny block count downstream.
    // Crafted PDBs would otherwise convince the directory walker to
    // read zero pages instead of the real (huge) page count, masking
    // truncation behind a clean parse.
    return static_cast<u32>(
        (static_cast<u64>(a) + static_cast<u64>(b) - 1) /
        static_cast<u64>(b));
}

}  // namespace

// MSF (Multi-Stream File) container.

Result<Msf> Msf::from_buffer(std::vector<std::byte> data) {
    if (data.size() < kSuperblockSize) {
        return std::unexpected(Error::truncated(std::format(
            "pdb: file too small ({} bytes) for MSF superblock", data.size())));
    }
    if (std::memcmp(data.data(), kV7Magic.data(), kV7Magic.size()) != 0) {
        return std::unexpected(Error::invalid_format(
            "pdb: not a v7 MSF file (magic mismatch)"));
    }

    Msf m;
    m.data_ = std::move(data);

    const ByteReader r(m.data_);
    auto block_size      = r.read_le<u32>(32 + 0);
    auto free_block_map  = r.read_le<u32>(32 + 4);
    auto num_blocks      = r.read_le<u32>(32 + 8);
    auto num_dir_bytes   = r.read_le<u32>(32 + 12);
    auto block_map_addr  = r.read_le<u32>(32 + 20);
    if (!block_size || !free_block_map || !num_blocks || !num_dir_bytes ||
        !block_map_addr) {
        return std::unexpected(Error::truncated("pdb: superblock fields"));
    }

    m.block_size_ = *block_size;
    if (m.block_size_ != 512 && m.block_size_ != 1024 &&
        m.block_size_ != 2048 && m.block_size_ != 4096 &&
        m.block_size_ != 8192 && m.block_size_ != 16384 &&
        m.block_size_ != 32768) {
        return std::unexpected(Error::invalid_format(std::format(
            "pdb: unusual block size {}", m.block_size_)));
    }
    if (static_cast<u64>(*num_blocks) * m.block_size_ > m.data_.size()) {
        return std::unexpected(Error::truncated(std::format(
            "pdb: header claims {} blocks ({}-byte each), file is {} bytes",
            *num_blocks, m.block_size_, m.data_.size())));
    }

    const u32 num_dir_blocks = div_up(*num_dir_bytes, m.block_size_);
    const std::size_t map_off = static_cast<std::size_t>(*block_map_addr) * m.block_size_;
    if (map_off > m.data_.size() ||
        m.data_.size() - map_off < static_cast<std::size_t>(num_dir_blocks) * 4) {
        return std::unexpected(Error::truncated("pdb: directory block map"));
    }
    std::vector<u32> dir_block_indices(num_dir_blocks);
    for (u32 i = 0; i < num_dir_blocks; ++i) {
        dir_block_indices[i] =
            read_le_at<u32>(m.data_.data() + map_off + i * 4u);
    }

    std::vector<std::byte> directory;
    directory.reserve(static_cast<std::size_t>(num_dir_blocks) * m.block_size_);
    for (u32 bi : dir_block_indices) {
        const std::size_t off = static_cast<std::size_t>(bi) * m.block_size_;
        if (off > m.data_.size() ||
            m.data_.size() - off < m.block_size_) {
            return std::unexpected(Error::truncated(std::format(
                "pdb: directory block {} out of range", bi)));
        }
        directory.insert(directory.end(),
                         m.data_.begin() + static_cast<std::ptrdiff_t>(off),
                         m.data_.begin() + static_cast<std::ptrdiff_t>(off + m.block_size_));
    }
    directory.resize(*num_dir_bytes);

    const ByteReader dr(directory);
    auto ns = dr.read_le<u32>(0);
    if (!ns) {
        return std::unexpected(Error::truncated("pdb: directory header"));
    }
    const u32 num_streams = *ns;
    if (num_streams > directory.size() / 4u) {
        return std::unexpected(Error::invalid_format(std::format(
            "pdb: directory claims {} streams in only {} bytes",
            num_streams, directory.size())));
    }

    m.stream_sizes_.resize(num_streams);
    std::vector<u32> stream_block_counts(num_streams, 0);
    std::size_t cursor = 4;
    for (u32 i = 0; i < num_streams; ++i) {
        auto sz = dr.read_le<u32>(cursor);
        if (!sz) return std::unexpected(std::move(sz).error());
        m.stream_sizes_[i] = *sz;
        stream_block_counts[i] =
            (*sz == 0xFFFFFFFFu) ? 0u : div_up(*sz, m.block_size_);
        cursor += 4;
    }
    m.stream_blocks_.resize(num_streams);
    for (u32 i = 0; i < num_streams; ++i) {
        m.stream_blocks_[i].resize(stream_block_counts[i]);
        for (u32 j = 0; j < stream_block_counts[i]; ++j) {
            auto bi = dr.read_le<u32>(cursor);
            if (!bi) return std::unexpected(std::move(bi).error());
            m.stream_blocks_[i][j] = *bi;
            cursor += 4;
        }
    }
    return m;
}

Result<std::vector<std::byte>> Msf::read_stream(u32 idx) const {
    if (idx >= stream_sizes_.size()) {
        return std::unexpected(Error::out_of_bounds(std::format(
            "pdb: stream {} >= num_streams {}", idx, stream_sizes_.size())));
    }
    if (stream_sizes_[idx] == 0xFFFFFFFFu) {
        return std::unexpected(Error::invalid_format(std::format(
            "pdb: stream {} is deleted", idx)));
    }
    std::vector<std::byte> out;
    out.reserve(stream_sizes_[idx]);
    for (u32 bi : stream_blocks_[idx]) {
        const std::size_t off = static_cast<std::size_t>(bi) * block_size_;
        if (off > data_.size() || data_.size() - off < block_size_) {
            return std::unexpected(Error::truncated(std::format(
                "pdb: stream {} block {} out of range", idx, bi)));
        }
        out.insert(out.end(),
                   data_.begin() + static_cast<std::ptrdiff_t>(off),
                   data_.begin() + static_cast<std::ptrdiff_t>(off + block_size_));
    }
    out.resize(stream_sizes_[idx]);
    return out;
}

}  // namespace ember::pdb
