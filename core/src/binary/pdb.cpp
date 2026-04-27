#include <ember/binary/pdb.hpp>

#include <array>
#include <cstddef>
#include <cstring>
#include <fstream>
#include <format>
#include <span>
#include <system_error>

#include <ember/common/bytes.hpp>

namespace ember::pdb {

namespace {

// PDB v7 superblock magic — exactly 32 bytes.
constexpr std::array<u8, 32> kV7Magic{
    'M','i','c','r','o','s','o','f','t',' ','C','/','C','+','+',' ',
    'M','S','F',' ','7','.','0','0','\r','\n',0x1A,'D','S',0,0,0,
};

constexpr std::size_t kSuperblockSize = 56;

// Symbol record kinds. Only the ones we look at.
constexpr u16 kSPub32     = 0x110E;
constexpr u16 kSGProc32   = 0x1110;
constexpr u16 kSLProc32   = 0x110F;
constexpr u16 kSGProc32Id = 0x1147;
constexpr u16 kSLProc32Id = 0x1146;

[[nodiscard]] inline u32 div_up(u32 a, u32 b) noexcept {
    return (a + b - 1) / b;
}

}  // namespace

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

    // The block map is one block of u32 indices. Each index points at a
    // directory block; concatenating those blocks yields num_dir_bytes
    // worth of stream-directory bytes.
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

    // Directory layout:
    //   u32 num_streams
    //   u32[num_streams] stream_sizes  (0xFFFFFFFF means "deleted")
    //   u32[total_blocks] block_indices  (concatenated per-stream)
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

namespace {

// DBI header layout (the v7 form, "NewDBI"). We only need:
//   +20: u16 sym_record_stream      — stream index for the symbol records
// Everything else (module list, section contributions, source info, …)
// stays unread; v1 only resolves public-symbol names.
[[nodiscard]] Result<u16>
read_sym_record_stream(std::span<const std::byte> dbi) {
    const ByteReader r(dbi);
    if (dbi.size() < 64) {
        return std::unexpected(Error::truncated("pdb: DBI header truncated"));
    }
    auto sig = r.read_le<i32>(0);
    if (!sig) return std::unexpected(std::move(sig).error());
    if (*sig != -1) {
        return std::unexpected(Error::invalid_format(std::format(
            "pdb: DBI signature {:#x} != 0xffffffff (only NewDBI supported)",
            static_cast<u32>(*sig))));
    }
    auto sym = r.read_le<u16>(20);
    if (!sym) return std::unexpected(std::move(sym).error());
    return *sym;
}

// CodeView record header walker. Each record is `u16 length` (not
// counting the length field itself), followed by `u16 kind` and
// kind-specific bytes. Records are 4-byte aligned in the stream — the
// `length` field tells us exactly how far to advance, including any
// trailing padding (CodeView pads with f1/f2/f3 bytes).
void walk_records(std::span<const std::byte> stream,
                  std::vector<PublicSymbol>& out) {
    std::size_t cursor = 0;
    while (cursor + 4 <= stream.size()) {
        const u16 reclen =
            read_le_at<u16>(stream.data() + cursor);
        if (reclen < 2) return;  // length excludes itself; minimum useful = 2
        const std::size_t total = static_cast<std::size_t>(reclen) + 2u;
        if (cursor + total > stream.size()) return;

        const u16 kind = read_le_at<u16>(stream.data() + cursor + 2);
        const std::byte* body = stream.data() + cursor + 4;
        const std::size_t body_len = total - 4;

        if (kind == kSPub32 && body_len >= 11) {
            // u32 flags, u32 offset, u16 segment, char[] name (null-term)
            PublicSymbol s;
            const u32 flags  = read_le_at<u32>(body + 0);
            s.section_offset = read_le_at<u32>(body + 4);
            s.segment        = read_le_at<u16>(body + 8);
            s.is_function    = (flags & 0x2u) != 0;
            const char* name_p = reinterpret_cast<const char*>(body + 10);
            const std::size_t name_max = body_len - 10;
            std::size_t name_len = 0;
            while (name_len < name_max && name_p[name_len] != '\0') ++name_len;
            s.name.assign(name_p, name_len);
            if (!s.name.empty() && s.segment != 0) {
                out.push_back(std::move(s));
            }
        } else if ((kind == kSGProc32 || kind == kSLProc32 ||
                    kind == kSGProc32Id || kind == kSLProc32Id) &&
                   body_len >= 35) {
            // Procedure record: parent/end/next pointers (u32×3),
            // proc length (u32), debug start/end (u32×2), type index (u32),
            // offset (u32), segment (u16), flags (u8), name (null-term).
            // We keep these alongside S_PUB32 so functions get sized
            // ranges where the publics stream alone only has start
            // addresses.
            PublicSymbol s;
            s.section_offset = read_le_at<u32>(body + 24);
            s.segment        = read_le_at<u16>(body + 28);
            s.is_function    = true;
            const char* name_p = reinterpret_cast<const char*>(body + 31);
            const std::size_t name_max = body_len - 31;
            std::size_t name_len = 0;
            while (name_len < name_max && name_p[name_len] != '\0') ++name_len;
            s.name.assign(name_p, name_len);
            if (!s.name.empty() && s.segment != 0) {
                out.push_back(std::move(s));
            }
        }

        cursor += total;
    }
}

[[nodiscard]] Result<std::vector<std::byte>>
read_file(const std::filesystem::path& path) {
    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    if (ec) {
        return std::unexpected(Error::io(std::format(
            "pdb: cannot stat '{}': {}", path.string(), ec.message())));
    }
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        return std::unexpected(Error::io(std::format(
            "pdb: cannot open '{}'", path.string())));
    }
    std::vector<std::byte> buf(static_cast<std::size_t>(size));
    if (size > 0) {
        f.read(reinterpret_cast<char*>(buf.data()),
               static_cast<std::streamsize>(size));
        if (!f) {
            return std::unexpected(Error::io(std::format(
                "pdb: short read on '{}'", path.string())));
        }
    }
    return buf;
}

}  // namespace

Result<std::vector<PublicSymbol>>
load_publics_from_buffer(std::vector<std::byte> data) {
    auto msf = Msf::from_buffer(std::move(data));
    if (!msf) return std::unexpected(std::move(msf).error());

    // DBI = stream 3. Read its header to find the symbol-record stream.
    auto dbi = msf->read_stream(3);
    if (!dbi) return std::unexpected(std::move(dbi).error());
    if (dbi->empty()) {
        return std::unexpected(Error::invalid_format(
            "pdb: DBI stream is empty (no debug info)"));
    }

    auto sym_idx = read_sym_record_stream(*dbi);
    if (!sym_idx) return std::unexpected(std::move(sym_idx).error());

    auto sym_stream = msf->read_stream(*sym_idx);
    if (!sym_stream) return std::unexpected(std::move(sym_stream).error());

    std::vector<PublicSymbol> out;
    walk_records(*sym_stream, out);
    return out;
}

Result<std::vector<PublicSymbol>>
load_publics(const std::filesystem::path& path) {
    auto buf = read_file(path);
    if (!buf) return std::unexpected(std::move(buf).error());
    return load_publics_from_buffer(std::move(*buf));
}

}  // namespace ember::pdb
