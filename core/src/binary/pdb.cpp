#include <ember/binary/pdb.hpp>

#include <array>
#include <cstddef>
#include <cstring>
#include <fstream>
#include <format>
#include <span>
#include <system_error>
#include <utility>

#include <ember/common/bytes.hpp>

namespace ember::pdb {

namespace {

// PDB v7 superblock magic — exactly 32 bytes.
constexpr std::array<u8, 32> kV7Magic{
    'M','i','c','r','o','s','o','f','t',' ','C','/','C','+','+',' ',
    'M','S','F',' ','7','.','0','0','\r','\n',0x1A,'D','S',0,0,0,
};

constexpr std::size_t kSuperblockSize = 56;

// ---------------------------------------------------------------------------
// Symbol record kinds. Only the ones we look at.
// ---------------------------------------------------------------------------
constexpr u16 kSEnd       = 0x0006;
constexpr u16 kSBlock32   = 0x1103;
constexpr u16 kSBPRel32   = 0x110B;
constexpr u16 kSLData32   = 0x110C;
constexpr u16 kSGData32   = 0x110D;
constexpr u16 kSPub32     = 0x110E;
constexpr u16 kSLProc32   = 0x110F;
constexpr u16 kSGProc32   = 0x1110;
constexpr u16 kSRegRel32  = 0x1111;
constexpr u16 kSLProc32Id = 0x1146;
constexpr u16 kSGProc32Id = 0x1147;
constexpr u16 kSInlineSite    = 0x114D;
constexpr u16 kSInlineSiteEnd = 0x114E;
constexpr u16 kSProcEnd       = 0x114F;

// ---------------------------------------------------------------------------
// CodeView leaf (type record) kinds.
// ---------------------------------------------------------------------------
constexpr u16 kLfModifier = 0x1001;
constexpr u16 kLfPointer  = 0x1002;
constexpr u16 kLfProc     = 0x1008;
constexpr u16 kLfMFunc    = 0x1009;
constexpr u16 kLfArgList  = 0x1201;
constexpr u16 kLfFieldList = 0x1203;
constexpr u16 kLfBitfield = 0x1205;
constexpr u16 kLfArray    = 0x1503;
constexpr u16 kLfClass    = 0x1504;
constexpr u16 kLfStructure = 0x1505;
constexpr u16 kLfUnion    = 0x1506;
constexpr u16 kLfEnum     = 0x1507;
constexpr u16 kLfAlias    = 0x150A;

// ---------------------------------------------------------------------------
// Numeric-leaf prefix codes (variant-length lengths and sizes encoded
// inline within type records).
// ---------------------------------------------------------------------------
constexpr u16 kLfChar      = 0x8000;   // i8
constexpr u16 kLfShort     = 0x8001;   // i16
constexpr u16 kLfUShort    = 0x8002;   // u16
constexpr u16 kLfLong      = 0x8003;   // i32
constexpr u16 kLfULong     = 0x8004;   // u32
constexpr u16 kLfReal32    = 0x8005;
constexpr u16 kLfReal64    = 0x8006;
constexpr u16 kLfQuadword  = 0x8009;   // i64
constexpr u16 kLfUQuadword = 0x800A;   // u64

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

[[nodiscard]] inline u32 div_up(u32 a, u32 b) noexcept {
    return (a + b - 1) / b;
}

// Round up to the next 4-byte boundary. CodeView records (type and
// symbol both) are always 4-byte aligned even when the kind-specific
// fields don't naturally land that way; the trailing f1/f2/f3 padding
// the writer emits is what keeps the stream parseable.
[[nodiscard]] inline std::size_t align_up_4(std::size_t n) noexcept {
    return (n + 3) & ~std::size_t{3};
}

// Parse a CodeView numeric leaf starting at `body[pos]`. The first
// u16 is either an inline value (< 0x8000) or a leaf-code that names
// the actual type. On success, `value_out` carries the unsigned
// 64-bit promoted value and `pos` advances past the leaf.
//
// Returns false on truncated / unknown leaves; the caller treats
// "unknown" as zero (reasonable default for an unknown-size struct).
[[nodiscard]] bool read_numeric_leaf(std::span<const std::byte> body,
                                     std::size_t& pos, u64& value_out) noexcept {
    if (pos + 2 > body.size()) return false;
    const u16 head = read_le_at<u16>(body.data() + pos);
    pos += 2;
    if (head < 0x8000) { value_out = head; return true; }
    switch (head) {
        case kLfChar: {
            if (pos + 1 > body.size()) return false;
            value_out = static_cast<u64>(static_cast<i8>(body[pos++]));
            return true;
        }
        case kLfShort: {
            if (pos + 2 > body.size()) return false;
            const i16 v = static_cast<i16>(read_le_at<u16>(body.data() + pos));
            value_out = static_cast<u64>(static_cast<i64>(v));
            pos += 2; return true;
        }
        case kLfUShort: {
            if (pos + 2 > body.size()) return false;
            value_out = read_le_at<u16>(body.data() + pos); pos += 2; return true;
        }
        case kLfLong: {
            if (pos + 4 > body.size()) return false;
            const i32 v = static_cast<i32>(read_le_at<u32>(body.data() + pos));
            value_out = static_cast<u64>(static_cast<i64>(v));
            pos += 4; return true;
        }
        case kLfULong: {
            if (pos + 4 > body.size()) return false;
            value_out = read_le_at<u32>(body.data() + pos); pos += 4; return true;
        }
        case kLfQuadword: {
            if (pos + 8 > body.size()) return false;
            value_out = read_le_at<u64>(body.data() + pos); pos += 8; return true;
        }
        case kLfUQuadword: {
            if (pos + 8 > body.size()) return false;
            value_out = read_le_at<u64>(body.data() + pos); pos += 8; return true;
        }
        case kLfReal32: {
            if (pos + 4 > body.size()) return false;
            value_out = read_le_at<u32>(body.data() + pos); pos += 4; return true;
        }
        case kLfReal64: {
            if (pos + 8 > body.size()) return false;
            value_out = read_le_at<u64>(body.data() + pos); pos += 8; return true;
        }
        default:
            return false;
    }
}

// Read a null-terminated string from `body` starting at `pos`,
// advancing `pos` past the terminator. Caps at `body.size()` to keep
// hostile / corrupt PDBs from running off the end.
std::string read_cstr_advance(std::span<const std::byte> body,
                              std::size_t& pos) {
    const std::size_t start = pos;
    while (pos < body.size() && body[pos] != std::byte{0}) ++pos;
    std::string out(reinterpret_cast<const char*>(body.data() + start),
                    pos - start);
    if (pos < body.size()) ++pos;     // skip null terminator
    return out;
}

}  // namespace

// ---------------------------------------------------------------------------
// MSF (Multi-Stream File) container — same as before. Only the prologue
// has been factored out from the legacy load_publics path; logic
// unchanged so existing tests still parse the synthetic MSF the test
// builds.
// ---------------------------------------------------------------------------

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

namespace {

// ---------------------------------------------------------------------------
// PDB info stream (stream 1). Layout:
//   u32 Version
//   u32 Signature
//   u32 Age
//   GUID Guid (16 bytes; mixed-endian Microsoft format, but we keep
//              raw bytes — comparing against the PE's CodeView record
//              compares the same raw 16 bytes).
// Trailing data (named-stream table, feature flags) we ignore — the
// only consumer is GUID/age matching against the PE binary.
// ---------------------------------------------------------------------------
[[nodiscard]] Result<PdbInfo>
parse_pdb_info(std::span<const std::byte> stream) {
    if (stream.size() < 28) {
        return std::unexpected(Error::truncated(
            "pdb: PDB info stream truncated"));
    }
    PdbInfo info;
    info.version   = read_le_at<u32>(stream.data() + 0);
    info.signature = read_le_at<u32>(stream.data() + 4);
    info.age       = read_le_at<u32>(stream.data() + 8);
    std::memcpy(info.guid.data(), stream.data() + 12, 16);
    return info;
}

// ---------------------------------------------------------------------------
// DBI header layout (the v7 form, "NewDBI"). We read enough of it to
// locate (a) the symbol-record stream — the legacy publics-only path —
// and (b) the module list — the per-compile-unit symbol streams that
// carry S_GPROC32 with type indices.
//
// Header lives at +0..+64 of the DBI stream. Variable-size data
// follows in the order:
//   ModInfoSize bytes — array of ModInfo records
//   SectionContributionSize bytes
//   SectionMapSize bytes
//   SourceInfoSize bytes
//   TypeServerMapSize bytes
//   ECSize bytes
//   OptionalDbgHeader (DbgHeaderSize bytes — array of u16 stream indices)
// ---------------------------------------------------------------------------
struct DbiHeader {
    u16 sym_record_stream      = 0xFFFF;
    u16 global_stream_index    = 0xFFFF;
    u16 public_stream_index    = 0xFFFF;
    u32 mod_info_size          = 0;
    u32 section_contrib_size   = 0;
    u32 section_map_size       = 0;
    u32 source_info_size       = 0;
    u32 type_server_map_size   = 0;
    u32 ec_size                = 0;
    u32 optional_dbg_size      = 0;
    u16 machine                = 0;
    u32 mod_info_offset        = 64;     // always — variable data starts after fixed header
};

[[nodiscard]] Result<DbiHeader>
parse_dbi_header(std::span<const std::byte> dbi) {
    if (dbi.size() < 64) {
        return std::unexpected(Error::truncated("pdb: DBI header truncated"));
    }
    const ByteReader r(dbi);
    auto sig = r.read_le<i32>(0);
    if (!sig) return std::unexpected(std::move(sig).error());
    if (*sig != -1) {
        return std::unexpected(Error::invalid_format(std::format(
            "pdb: DBI signature {:#x} != 0xffffffff (only NewDBI supported)",
            static_cast<u32>(*sig))));
    }
    DbiHeader h;
    h.global_stream_index   = read_le_at<u16>(dbi.data() + 12);
    h.public_stream_index   = read_le_at<u16>(dbi.data() + 16);
    h.sym_record_stream     = read_le_at<u16>(dbi.data() + 20);
    h.mod_info_size         = read_le_at<u32>(dbi.data() + 24);
    h.section_contrib_size  = read_le_at<u32>(dbi.data() + 28);
    h.section_map_size      = read_le_at<u32>(dbi.data() + 32);
    h.source_info_size      = read_le_at<u32>(dbi.data() + 36);
    h.type_server_map_size  = read_le_at<u32>(dbi.data() + 40);
    // skip MFCTypeServerIndex (u32) at +44 — unused
    h.ec_size               = read_le_at<u32>(dbi.data() + 48);
    h.optional_dbg_size     = read_le_at<u16>(dbi.data() + 52);
    // Flags at +54 (u16), Machine at +56 (u16), Padding at +60 (u32).
    h.machine               = read_le_at<u16>(dbi.data() + 56);
    return h;
}

// One module's location info: which stream holds its symbol records,
// how many bytes of that stream to walk. Module name is informational
// — we keep it for diagnostics but don't surface it.
struct ModuleEntry {
    u16         sym_stream    = 0xFFFF;
    u32         sym_byte_size = 0;
    std::string module_name;
};

// Parse the ModInfo array that follows the DBI header. Each entry is
// 64 bytes of fixed-size fields followed by two null-terminated UTF-8
// strings (module name, object filename), padded up to 4-byte align.
[[nodiscard]] std::vector<ModuleEntry>
parse_dbi_modules(std::span<const std::byte> dbi, const DbiHeader& h) {
    std::vector<ModuleEntry> mods;
    if (h.mod_info_size == 0) return mods;
    if (h.mod_info_offset + h.mod_info_size > dbi.size()) return mods;
    const auto block = dbi.subspan(h.mod_info_offset, h.mod_info_size);

    std::size_t pos = 0;
    while (pos + 64 <= block.size()) {
        ModuleEntry e;
        // Layout (only the fields we care about):
        //   +34: u16 ModuleSymStream
        //   +36: u32 SymByteSize  (bytes in the module stream that are
        //                          symbol records before C11/C13 chunks)
        e.sym_stream    = read_le_at<u16>(block.data() + pos + 34);
        e.sym_byte_size = read_le_at<u32>(block.data() + pos + 36);

        // Two strings starting at +64. Read first (module name), skip
        // second (obj file name) — but track length so we can advance.
        std::size_t sp = pos + 64;
        e.module_name = read_cstr_advance(block, sp);
        // skip obj file name
        const std::size_t before_obj = sp;
        (void)before_obj;
        read_cstr_advance(block, sp);
        // Align the cursor up to 4 bytes — ModInfo records are 4-byte
        // aligned in the stream.
        sp = align_up_4(sp);
        if (sp <= pos) break;       // defensive — corrupt layout
        mods.push_back(std::move(e));
        pos = sp;
    }
    return mods;
}

// ---------------------------------------------------------------------------
// CodeView record walker (used for both symbol streams and TPI). Each
// record is `u16 length` (excluding itself), `u16 kind`, then
// kind-specific bytes. Total advancement = length + 2.
//
// `body_handler` receives (kind, body_span, body_len) for each record;
// returning false bails out early.
// ---------------------------------------------------------------------------
template <typename F>
void for_each_record(std::span<const std::byte> stream, F body_handler) {
    std::size_t cursor = 0;
    while (cursor + 4 <= stream.size()) {
        const u16 reclen = read_le_at<u16>(stream.data() + cursor);
        if (reclen < 2) return;
        const std::size_t total = static_cast<std::size_t>(reclen) + 2u;
        if (cursor + total > stream.size()) return;

        const u16 kind = read_le_at<u16>(stream.data() + cursor + 2);
        const std::byte* body = stream.data() + cursor + 4;
        const std::size_t body_len = total - 4;

        if (!body_handler(kind, std::span(body, body_len))) return;
        cursor += total;
    }
}

// ---------------------------------------------------------------------------
// Symbol-stream walker. Picks up S_PUB32 / S_*PROC32 / S_*DATA32 records
// regardless of which stream they came from (publics, globals, or
// per-module). Procedure type indices are kept for downstream
// signature injection; data type indices are kept for future global-
// variable type rendering.
// ---------------------------------------------------------------------------
struct SymbolBuckets {
    std::vector<PublicSymbol>* publics = nullptr;
    std::vector<ProcSymbol>*   procs   = nullptr;
    std::vector<DataSymbol>*   data    = nullptr;
};

void walk_symbol_records(std::span<const std::byte> stream, SymbolBuckets b) {
    // CodeView symbol streams are flat sequences with implicit nesting:
    // a procedure (S_GPROC32 / S_LPROC32) opens a scope that closes at
    // the matching S_END / S_PROC_END. Inner S_BLOCK32 / S_INLINESITE
    // records add layers we don't otherwise care about, but we count
    // them so the procedure's S_END is correctly identified. Locals
    // (S_BPREL32 / S_REGREL32) seen at any depth inside a proc scope
    // are attached to the enclosing proc.
    std::optional<std::size_t> current_proc_idx;
    int                        scope_depth = 0;
    auto pop_scope = [&]() {
        if (scope_depth > 0) {
            --scope_depth;
            if (scope_depth == 0) current_proc_idx.reset();
        }
    };
    for_each_record(stream, [&](u16 kind, std::span<const std::byte> body) {
        const std::size_t body_len = body.size();
        switch (kind) {
            case kSPub32: {
                if (b.publics == nullptr || body_len < 11) break;
                PublicSymbol s;
                const u32 flags  = read_le_at<u32>(body.data() + 0);
                s.section_offset = read_le_at<u32>(body.data() + 4);
                s.segment        = read_le_at<u16>(body.data() + 8);
                s.is_function    = (flags & 0x2u) != 0;
                std::size_t pos = 10;
                s.name = read_cstr_advance(body, pos);
                if (!s.name.empty() && s.segment != 0) {
                    b.publics->push_back(std::move(s));
                }
                break;
            }
            case kSGProc32:
            case kSLProc32:
            case kSGProc32Id:
            case kSLProc32Id: {
                if (b.procs == nullptr || body_len < 35) break;
                ProcSymbol s;
                // u32 Parent, End, Next; u32 CodeSize; u32 DbgStart, DbgEnd;
                // u32 TypeIndex; u32 Offset; u16 Segment; u8 Flags; cstr name.
                s.length         = read_le_at<u32>(body.data() + 12);
                s.type_index     = read_le_at<u32>(body.data() + 24);
                s.section_offset = read_le_at<u32>(body.data() + 28);
                s.segment        = read_le_at<u16>(body.data() + 32);
                s.is_id_record   = (kind == kSGProc32Id || kind == kSLProc32Id);
                std::size_t pos = 35;
                s.name = read_cstr_advance(body, pos);
                if (!s.name.empty() && s.segment != 0) {
                    b.procs->push_back(std::move(s));
                    current_proc_idx = b.procs->size() - 1;
                    scope_depth = 1;
                }
                break;
            }
            case kSBlock32:
            case kSInlineSite:
                if (current_proc_idx) ++scope_depth;
                break;
            case kSEnd:
            case kSProcEnd:
            case kSInlineSiteEnd:
                pop_scope();
                break;
            case kSBPRel32: {
                // body: i32 Offset, u32 TypeIndex, cstr Name.
                if (b.procs == nullptr || !current_proc_idx) break;
                if (body_len < 9) break;
                LocalVarSymbol l;
                l.frame_offset = static_cast<i32>(read_le_at<u32>(body.data() + 0));
                l.type_index   = read_le_at<u32>(body.data() + 4);
                l.reg          = 0;     // implicit BP
                std::size_t pos = 8;
                l.name = read_cstr_advance(body, pos);
                if (!l.name.empty()) {
                    (*b.procs)[*current_proc_idx].locals.push_back(std::move(l));
                }
                break;
            }
            case kSRegRel32: {
                // body: u32 Offset, u32 TypeIndex, u16 Register, cstr Name.
                if (b.procs == nullptr || !current_proc_idx) break;
                if (body_len < 11) break;
                LocalVarSymbol l;
                l.frame_offset = static_cast<i32>(read_le_at<u32>(body.data() + 0));
                l.type_index   = read_le_at<u32>(body.data() + 4);
                l.reg          = read_le_at<u16>(body.data() + 8);
                std::size_t pos = 10;
                l.name = read_cstr_advance(body, pos);
                if (!l.name.empty()) {
                    (*b.procs)[*current_proc_idx].locals.push_back(std::move(l));
                }
                break;
            }
            case kSGData32:
            case kSLData32: {
                if (b.data == nullptr || body_len < 10) break;
                DataSymbol s;
                s.type_index     = read_le_at<u32>(body.data() + 0);
                s.section_offset = read_le_at<u32>(body.data() + 4);
                s.segment        = read_le_at<u16>(body.data() + 8);
                s.is_local       = (kind == kSLData32);
                std::size_t pos = 10;
                s.name = read_cstr_advance(body, pos);
                if (!s.name.empty() && s.segment != 0) {
                    b.data->push_back(std::move(s));
                }
                break;
            }
            default:
                break;
        }
        return true;
    });
}

// ---------------------------------------------------------------------------
// One module's symbol stream begins with `u32 signature` (must be 4 =
// CV_SIGNATURE_C13 for modern PDBs; older = 1 = C11) followed by
// `sym_byte_size - 4` bytes of symbol records, then C11ByteSize bytes
// of legacy line tables, then C13ByteSize bytes of subsections we
// don't care about (line tables, file checksums, inlinees).
// ---------------------------------------------------------------------------
void walk_module_stream(std::span<const std::byte> stream, u32 sym_byte_size,
                        SymbolBuckets b) {
    if (sym_byte_size < 4 || sym_byte_size > stream.size()) return;
    const u32 sig = read_le_at<u32>(stream.data());
    // Signatures: 1 = C7, 2 = C11, 3 = C13_NEW (rare), 4 = C13.
    // Refuse anything we don't recognize — bailing is safer than
    // misparsing the body.
    if (sig != 4 && sig != 2 && sig != 1) return;
    walk_symbol_records(stream.subspan(4, sym_byte_size - 4), b);
}

// ---------------------------------------------------------------------------
// TPI stream parser. The fixed 56-byte header tells us:
//   TypeIndexBegin / TypeIndexEnd — the [begin, end) range our records
//   cover. Indices below ti_begin_ refer to primitive types and don't
//   live in this stream.
//   TypeRecordBytes — bytes of records following the header.
// ---------------------------------------------------------------------------

[[nodiscard]] TypeRecord parse_pointer(std::span<const std::byte> body) {
    TypeRecord t;
    t.kind = TypeRecord::Kind::Pointer;
    if (body.size() < 8) return t;
    t.base_type   = read_le_at<u32>(body.data() + 0);
    const u32 a   = read_le_at<u32>(body.data() + 4);
    // PtrAttribs bit fields:
    //   bits 0..4  pointer kind (4=near32, 0xc=64bit)
    //   bits 5..7  pointer mode (0=ptr, 1=lvref, 2=ptr-to-data-member,
    //                            3=ptr-to-method, 4=rvref)
    //   bit  9     is_volatile
    //   bit  10    is_const
    //   bit  11    is_unaligned
    //   bits 13..18 size in bytes (6 bits)
    const u8 mode = static_cast<u8>((a >> 5) & 0x7);
    t.is_volatile = (a & (1u << 9))  != 0;
    t.is_const    = (a & (1u << 10)) != 0;
    t.is_unaligned= (a & (1u << 11)) != 0;
    const u8 size = static_cast<u8>((a >> 13) & 0x3F);
    if (size > 0) t.ptr_size = size;
    else t.ptr_size = 8;     // default to 64-bit on x64; correct for our scope
    t.is_reference  = (mode == 1 || mode == 4);
    t.is_rvalue_ref = (mode == 4);
    return t;
}

[[nodiscard]] TypeRecord parse_modifier(std::span<const std::byte> body) {
    TypeRecord t;
    t.kind = TypeRecord::Kind::Modifier;
    if (body.size() < 6) return t;
    t.base_type   = read_le_at<u32>(body.data() + 0);
    const u16 m   = read_le_at<u16>(body.data() + 4);
    t.is_const     = (m & 1u) != 0;
    t.is_volatile  = (m & 2u) != 0;
    t.is_unaligned = (m & 4u) != 0;
    return t;
}

[[nodiscard]] TypeRecord parse_proc(std::span<const std::byte> body) {
    TypeRecord t;
    t.kind = TypeRecord::Kind::Procedure;
    // Body layout (after the u16 length + u16 kind prefix):
    //   u32 ReturnType, u8 CallConv, u8 FuncAttrs, u16 NumParams, u32 ArgList
    // = 12 bytes minimum (16 once 4-byte aligned padding is added).
    if (body.size() < 12) return t;
    t.base_type   = read_le_at<u32>(body.data() + 0);
    t.call_conv   = static_cast<u8>(body[4]);
    // body[5] = func attribs
    t.param_count = read_le_at<u16>(body.data() + 6);
    t.arg_list    = read_le_at<u32>(body.data() + 8);
    return t;
}

[[nodiscard]] TypeRecord parse_mfunc(std::span<const std::byte> body) {
    TypeRecord t;
    t.kind = TypeRecord::Kind::MFunction;
    // u32 ReturnType, u32 ClassType, u32 ThisType, u8 CC, u8 Attrs,
    // u16 NumParams, u32 ArgList, i32 ThisAdjust = 24 bytes minimum.
    if (body.size() < 24) return t;
    t.base_type   = read_le_at<u32>(body.data() + 0);
    t.class_type  = read_le_at<u32>(body.data() + 4);
    t.this_type   = read_le_at<u32>(body.data() + 8);
    t.call_conv   = static_cast<u8>(body[12]);
    t.param_count = read_le_at<u16>(body.data() + 14);
    t.arg_list    = read_le_at<u32>(body.data() + 16);
    return t;
}

[[nodiscard]] TypeRecord parse_arg_list(std::span<const std::byte> body) {
    TypeRecord t;
    t.kind = TypeRecord::Kind::ArgList;
    if (body.size() < 4) return t;
    const u32 n = read_le_at<u32>(body.data() + 0);
    if (n > (body.size() - 4) / 4) return t;
    t.arg_types.reserve(n);
    for (u32 i = 0; i < n; ++i) {
        t.arg_types.push_back(read_le_at<u32>(body.data() + 4 + i * 4));
    }
    return t;
}

[[nodiscard]] TypeRecord parse_array(std::span<const std::byte> body) {
    TypeRecord t;
    t.kind = TypeRecord::Kind::Array;
    if (body.size() < 8) return t;
    t.base_type  = read_le_at<u32>(body.data() + 0);   // element type
    t.index_type = read_le_at<u32>(body.data() + 4);
    std::size_t pos = 8;
    u64 sz = 0;
    if (read_numeric_leaf(body, pos, sz)) t.array_size_bytes = sz;
    return t;
}

[[nodiscard]] TypeRecord parse_aggregate(u16 kind, std::span<const std::byte> body) {
    TypeRecord t;
    if (kind == kLfStructure || kind == kLfClass) {
        t.kind = TypeRecord::Kind::Structure;
    } else if (kind == kLfUnion) {
        t.kind = TypeRecord::Kind::Union;
    } else if (kind == kLfEnum) {
        t.kind = TypeRecord::Kind::Enum;
    }
    if (body.size() < 8) return t;
    // u16 NumMembers; u16 Properties; u32 FieldList;
    const u16 props = read_le_at<u16>(body.data() + 2);
    t.is_forward_ref = (props & 0x80u) != 0;     // CV_PROP_FWDREF
    t.field_list = read_le_at<u32>(body.data() + 4);
    std::size_t pos = 8;
    if (kind == kLfEnum) {
        // u32 UnderlyingType
        if (body.size() < 12) return t;
        t.base_type = read_le_at<u32>(body.data() + 8);
        pos = 12;
        // Enum then has its name (no size leaf — enums get their size
        // from the underlying type).
        t.name = read_cstr_advance(body, pos);
    } else if (kind == kLfUnion) {
        // u16 NumMembers (already read), u16 Props, u32 FieldList,
        // [size leaf], [name].
        u64 sz = 0;
        if (read_numeric_leaf(body, pos, sz)) t.size_bytes = sz;
        t.name = read_cstr_advance(body, pos);
    } else {
        // Structure / Class: NumMembers, Props, FieldList, DerivedFrom,
        // VShape, [size leaf], [name].
        if (body.size() < 16) return t;
        // body+8 = DerivedFrom (u32), body+12 = VShape (u32)
        pos = 16;
        u64 sz = 0;
        if (read_numeric_leaf(body, pos, sz)) t.size_bytes = sz;
        t.name = read_cstr_advance(body, pos);
    }
    return t;
}

[[nodiscard]] TypeRecord parse_bitfield(std::span<const std::byte> body) {
    TypeRecord t;
    t.kind = TypeRecord::Kind::Bitfield;
    if (body.size() < 6) return t;
    t.base_type   = read_le_at<u32>(body.data() + 0);
    // body[4] = bit-length, body[5] = bit-position; we don't need them
    // for type rendering.
    return t;
}

[[nodiscard]] TypeRecord parse_alias(std::span<const std::byte> body) {
    TypeRecord t;
    t.kind = TypeRecord::Kind::Alias;
    if (body.size() < 4) return t;
    t.base_type = read_le_at<u32>(body.data() + 0);
    std::size_t pos = 4;
    t.name = read_cstr_advance(body, pos);
    return t;
}

}  // namespace

Result<TpiTable> TpiTable::parse(std::span<const std::byte> tpi_stream) {
    if (tpi_stream.size() < 56) {
        return std::unexpected(Error::truncated("pdb: TPI header truncated"));
    }
    TpiTable t;
    const auto hdr = tpi_stream.subspan(0, 56);
    // Layout fields we use:
    //   +0  Version
    //   +4  HeaderSize
    //   +8  TypeIndexBegin   (typically 0x1000)
    //   +12 TypeIndexEnd
    //   +16 TypeRecordBytes
    const u32 header_size       = read_le_at<u32>(hdr.data() + 4);
    t.ti_begin_                 = read_le_at<u32>(hdr.data() + 8);
    t.ti_end_                   = read_le_at<u32>(hdr.data() + 12);
    const u32 type_record_bytes = read_le_at<u32>(hdr.data() + 16);

    if (header_size < 56 || header_size > tpi_stream.size()) {
        return std::unexpected(Error::invalid_format(std::format(
            "pdb: TPI header size {} outside stream {}",
            header_size, tpi_stream.size())));
    }
    if (t.ti_end_ < t.ti_begin_) {
        return std::unexpected(Error::invalid_format(std::format(
            "pdb: TPI ti_end {} < ti_begin {}", t.ti_end_, t.ti_begin_)));
    }
    if (header_size + type_record_bytes > tpi_stream.size()) {
        return std::unexpected(Error::truncated(std::format(
            "pdb: TPI claims {} record bytes after {}-byte header in {}-byte stream",
            type_record_bytes, header_size, tpi_stream.size())));
    }
    if (t.ti_end_ == t.ti_begin_) {
        // No types — empty table is valid.
        return t;
    }

    const auto records_span = tpi_stream.subspan(header_size, type_record_bytes);
    const u32 expected = t.ti_end_ - t.ti_begin_;
    t.records_.resize(expected);

    u32 ti_cursor = t.ti_begin_;
    for_each_record(records_span, [&](u16 kind, std::span<const std::byte> body) {
        if (ti_cursor >= t.ti_end_) return false;
        const u32 slot = ti_cursor - t.ti_begin_;
        switch (kind) {
            case kLfPointer:  t.records_[slot] = parse_pointer(body);  break;
            case kLfModifier: t.records_[slot] = parse_modifier(body); break;
            case kLfProc:     t.records_[slot] = parse_proc(body);     break;
            case kLfMFunc:    t.records_[slot] = parse_mfunc(body);    break;
            case kLfArgList:  t.records_[slot] = parse_arg_list(body); break;
            case kLfArray:    t.records_[slot] = parse_array(body);    break;
            case kLfStructure:
            case kLfClass:
            case kLfUnion:
            case kLfEnum:     t.records_[slot] = parse_aggregate(kind, body); break;
            case kLfBitfield: t.records_[slot] = parse_bitfield(body); break;
            case kLfAlias:    t.records_[slot] = parse_alias(body);    break;
            case kLfFieldList:
                // Field lists are referenced by aggregate records but
                // we don't mine them yet — record presence so the
                // aggregate's field_list -> nullptr lookup doesn't
                // confuse callers.
                break;
            default:
                // Unrecognized leaves stay as Kind::Unknown (default).
                break;
        }
        ++ti_cursor;
        return true;
    });

    return t;
}

const TypeRecord* TpiTable::lookup(u32 type_index) const noexcept {
    if (type_index < ti_begin_ || type_index >= ti_end_) return nullptr;
    const u32 slot = type_index - ti_begin_;
    if (slot >= records_.size()) return nullptr;
    return &records_[slot];
}

namespace {

// Render a primitive type index. Below 0x1000 these encode (mode, type)
// bit-packed:
//   bits 0..7  primitive subtype
//   bits 8..10 mode (0=direct, 1..3 16-bit ptrs, 4=near32, 5=far32, 6=near64)
//   bits 11..15 size class
//
// We render the underlying primitive name and prefix with a `*` for
// any pointer mode.
std::string render_primitive(u32 ti) {
    const u32 sub  = ti & 0xFFu;
    const u32 mode = (ti >> 8) & 0x7u;
    auto name_for = [&]() -> std::string {
        switch (sub) {
            case 0x00: return "void_t";    // T_NOTYPE / T_ABS — rare
            case 0x03: return "void";
            case 0x08: return "HRESULT";
            // Signed-char aliases: 0x10 = signed char, 0x70 = char (rchar).
            case 0x10: return "signed char";
            case 0x11: return "short";
            case 0x12: return "long";
            case 0x13: return "long long";
            case 0x20: return "unsigned char";
            case 0x21: return "unsigned short";
            case 0x22: return "unsigned long";
            case 0x23: return "unsigned long long";
            case 0x30: return "bool";
            case 0x31: return "bool16";
            case 0x32: return "bool32";
            case 0x40: return "float";
            case 0x41: return "double";
            case 0x42: return "long double";
            case 0x68: return "int8_t";    // 8-bit int
            case 0x69: return "uint8_t";
            case 0x70: return "char";      // T_RCHAR
            case 0x71: return "wchar_t";
            case 0x72: return "int16_t";   // T_INT2
            case 0x73: return "uint16_t";
            case 0x74: return "int";       // T_INT4
            case 0x75: return "unsigned int";
            case 0x76: return "int64_t";
            case 0x77: return "uint64_t";
            case 0x7A: return "char16_t";
            case 0x7B: return "char32_t";
            case 0x7C: return "char8_t";
            default:
                return std::format("__primtype_{:#x}", sub);
        }
    };
    auto base = name_for();
    if (mode != 0) {
        // Any non-zero mode = pointer-flavored variant. We don't
        // distinguish near/far/huge here — Ember decompiles 64-bit
        // binaries; the size is implicit.
        base += "*";
    }
    return base;
}

}  // namespace

std::string TpiTable::render_type(u32 type_index, int depth) const {
    if (depth > 8) return "?";   // recursion guard — pathological PDBs only
    if (type_index < ti_begin_) return render_primitive(type_index);

    const TypeRecord* r = lookup(type_index);
    if (!r) return std::format("__t_{:#x}", type_index);

    auto add_qualifiers = [](std::string& out, bool c, bool v) {
        if (c) out = "const " + out;
        if (v) out = "volatile " + out;
    };

    switch (r->kind) {
        case TypeRecord::Kind::Unknown:
            return std::format("__t_{:#x}", type_index);

        case TypeRecord::Kind::Pointer: {
            std::string base = render_type(r->base_type, depth + 1);
            add_qualifiers(base, r->is_const, r->is_volatile);
            base += r->is_rvalue_ref ? "&&"
                  : r->is_reference  ? "&"
                                     : "*";
            return base;
        }

        case TypeRecord::Kind::Modifier: {
            std::string base = render_type(r->base_type, depth + 1);
            add_qualifiers(base, r->is_const, r->is_volatile);
            return base;
        }

        case TypeRecord::Kind::Array: {
            const std::string elem = render_type(r->base_type, depth + 1);
            // Approximate count from byte size / element size — too
            // expensive to chase down sizeof through arbitrary types,
            // so we just print the byte size as a comment.
            return std::format("{}[/* {} bytes */]", elem, r->array_size_bytes);
        }

        case TypeRecord::Kind::Procedure:
        case TypeRecord::Kind::MFunction: {
            // Function types only show up as the pointee of LF_POINTER
            // (or the member-function class type); render to a brief
            // signature so users see something useful instead of "?".
            const std::string ret = render_type(r->base_type, depth + 1);
            return ret + "()";
        }

        case TypeRecord::Kind::Structure:
        case TypeRecord::Kind::Union: {
            if (!r->name.empty()) {
                // Use plain `Foo` rather than `struct Foo` — easier on
                // the eyes in pseudo-C output, and matches what
                // FunctionSig.params already look like for user-typed
                // signatures.
                return r->name;
            }
            return r->kind == TypeRecord::Kind::Union
                ? std::string("union /* anon */")
                : std::string("struct /* anon */");
        }

        case TypeRecord::Kind::Enum:
            return r->name.empty() ? std::string("enum /* anon */")
                                    : r->name;

        case TypeRecord::Kind::Bitfield:
            return render_type(r->base_type, depth + 1);

        case TypeRecord::Kind::Alias:
            return r->name.empty()
                ? render_type(r->base_type, depth + 1)
                : r->name;

        case TypeRecord::Kind::ArgList:
            // ArgList isn't a real "type" — caller mishandled if it
            // ever asks for one.
            return "(arglist)";
    }
    return "?";
}

namespace {

// One-shot record walker that pulls every relevant symbol out of the
// global symbol record stream (the legacy path) — same as before, but
// now lives inside walk_symbol_records so the publics-only test
// fixture continues to work.
void walk_global_symbol_stream(std::span<const std::byte> stream,
                               std::vector<PublicSymbol>& out) {
    SymbolBuckets b{};
    b.publics = &out;
    walk_symbol_records(stream, b);
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

// ---------------------------------------------------------------------------
// Top-level orchestrator. Walks every interesting stream and packs the
// results into a PdbReader. Sub-parses past the MSF/DBI prologue are
// best-effort: a corrupt TPI doesn't fail the whole load, since the
// publics+procs payload is usable on its own.
// ---------------------------------------------------------------------------

Result<PdbReader>
load_pdb_from_buffer(std::vector<std::byte> data) {
    auto msf = Msf::from_buffer(std::move(data));
    if (!msf) return std::unexpected(std::move(msf).error());

    PdbReader rdr;

    // Stream 1: PDB info (GUID + age). Best-effort.
    if (msf->stream_size(1) > 0) {
        if (auto info_bytes = msf->read_stream(1); info_bytes) {
            if (auto info = parse_pdb_info(*info_bytes); info) {
                rdr.info = *info;
            }
        }
    }

    // Stream 3: DBI header, then mod-info list.
    auto dbi = msf->read_stream(3);
    if (!dbi) return std::unexpected(std::move(dbi).error());
    if (dbi->empty()) {
        return std::unexpected(Error::invalid_format(
            "pdb: DBI stream is empty (no debug info)"));
    }
    auto dbi_hdr = parse_dbi_header(*dbi);
    if (!dbi_hdr) return std::unexpected(std::move(dbi_hdr).error());

    // The legacy path — global symbol-record stream — is still the most
    // reliable source of S_PUB32. Walk it first so even a corrupt
    // module list doesn't lose the public names.
    if (dbi_hdr->sym_record_stream != 0xFFFF &&
        dbi_hdr->sym_record_stream < msf->num_streams()) {
        if (auto sr = msf->read_stream(dbi_hdr->sym_record_stream); sr) {
            walk_global_symbol_stream(*sr, rdr.publics);
            // The publics stream (PSI) doesn't typically also carry
            // S_GDATA32 records — those live in module streams — but if
            // a producer chose to put them here we still want them.
            SymbolBuckets b{};
            b.data = &rdr.globals;
            walk_symbol_records(*sr, b);
        }
    }

    // Module streams: each compile unit's symbol records, including
    // S_GPROC32 with type indices. This is where the type-injection
    // payoff comes from.
    auto mods = parse_dbi_modules(*dbi, *dbi_hdr);
    for (const auto& m : mods) {
        if (m.sym_stream == 0xFFFF) continue;
        if (m.sym_stream >= msf->num_streams()) continue;
        if (m.sym_byte_size == 0) continue;
        auto stream = msf->read_stream(m.sym_stream);
        if (!stream) continue;
        SymbolBuckets b{};
        b.procs = &rdr.procs;
        b.data  = &rdr.globals;
        walk_module_stream(*stream, m.sym_byte_size, b);
    }

    // Stream 2: TPI. Best-effort.
    if (msf->stream_size(2) >= 56) {
        if (auto tpi_bytes = msf->read_stream(2); tpi_bytes) {
            if (auto tpi = TpiTable::parse(*tpi_bytes); tpi) {
                rdr.types = std::move(*tpi);
            }
        }
    }

    return rdr;
}

Result<PdbReader>
load_pdb(const std::filesystem::path& path) {
    auto buf = read_file(path);
    if (!buf) return std::unexpected(std::move(buf).error());
    return load_pdb_from_buffer(std::move(*buf));
}

// ---------------------------------------------------------------------------
// Legacy entry — kept for the existing pdb_test.cpp fixture and any
// callers that only need names. Implemented in terms of the orchestrator
// so there's a single parsing path.
// ---------------------------------------------------------------------------

Result<std::vector<PublicSymbol>>
load_publics_from_buffer(std::vector<std::byte> data) {
    auto rdr = load_pdb_from_buffer(std::move(data));
    if (!rdr) return std::unexpected(std::move(rdr).error());
    return std::move(rdr->publics);
}

Result<std::vector<PublicSymbol>>
load_publics(const std::filesystem::path& path) {
    auto buf = read_file(path);
    if (!buf) return std::unexpected(std::move(buf).error());
    return load_publics_from_buffer(std::move(*buf));
}

}  // namespace ember::pdb
