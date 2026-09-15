#include <spelunk/binary/pdb.hpp>

#include <cstddef>
#include <cstring>
#include <expected>
#include <filesystem>
#include <format>
#include <fstream>
#include <ios>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <spelunk/common/bytes.hpp>
#include <spelunk/common/error.hpp>
#include <spelunk/common/types.hpp>

#include "pdb_internal.hpp"

namespace spelunk::pdb {

namespace {

using detail::for_each_record;
using detail::read_cstr_advance;

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
// Helpers.
// ---------------------------------------------------------------------------

// Round up to the next 4-byte boundary. CodeView records (type and
// symbol both) are always 4-byte aligned even when the kind-specific
// fields don't naturally land that way; the trailing f1/f2/f3 padding
// the writer emits is what keeps the stream parseable.
[[nodiscard]] inline std::size_t align_up_4(std::size_t n) noexcept {
    return (n + 3) & ~std::size_t{3};
}

// ---------------------------------------------------------------------------
// PDB info stream (stream 1). Layout:
//   u32 Version
//   u32 Signature
//   u32 Age
//   GUID Guid (16 bytes; mixed-endian Microsoft format, but we keep
//              raw bytes - comparing against the PE's CodeView record
//              compares the same raw 16 bytes).
// Trailing data (named-stream table, feature flags) we ignore - the
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
// locate (a) the symbol-record stream - the legacy publics-only path -
// and (b) the module list - the per-compile-unit symbol streams that
// carry S_GPROC32 with type indices.
//
// Header lives at +0..+64 of the DBI stream. Variable-size data
// follows in the order:
//   ModInfoSize bytes - array of ModInfo records
//   SectionContributionSize bytes
//   SectionMapSize bytes
//   SourceInfoSize bytes
//   TypeServerMapSize bytes
//   ECSize bytes
//   OptionalDbgHeader (DbgHeaderSize bytes - array of u16 stream indices)
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
    u32 mod_info_offset        = 64;     // always - variable data starts after fixed header
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
    // skip MFCTypeServerIndex (u32) at +44 - unused
    h.ec_size               = read_le_at<u32>(dbi.data() + 48);
    h.optional_dbg_size     = read_le_at<u16>(dbi.data() + 52);
    // Flags at +54 (u16), Machine at +56 (u16), Padding at +60 (u32).
    h.machine               = read_le_at<u16>(dbi.data() + 56);
    return h;
}

// One module's location info: which stream holds its symbol records,
// how many bytes of that stream to walk. Module name is informational
// - we keep it for diagnostics but don't surface it.
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
    // Widen the bounds check: both fields are u32 and a hostile DBI
    // header with mod_info_size near UINT32_MAX would wrap the sum
    // and slip past `> dbi.size()`, then UB at subspan(). Same shape
    // as the div_up fix above.
    if (static_cast<u64>(h.mod_info_offset) +
        static_cast<u64>(h.mod_info_size) > dbi.size()) return mods;
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
        // second (obj file name) - but track length so we can advance.
        std::size_t sp = pos + 64;
        e.module_name = read_cstr_advance(block, sp);
        // skip obj file name
        const std::size_t before_obj = sp;
        (void)before_obj;
        read_cstr_advance(block, sp);
        // Align the cursor up to 4 bytes - ModInfo records are 4-byte
        // aligned in the stream.
        sp = align_up_4(sp);
        if (sp <= pos) break;       // defensive - corrupt layout
        mods.push_back(std::move(e));
        pos = sp;
    }
    return mods;
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
    // Refuse anything we don't recognize - bailing is safer than
    // misparsing the body.
    if (sig != 4 && sig != 2 && sig != 1) return;
    walk_symbol_records(stream.subspan(4, sym_byte_size - 4), b);
}

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

    // The legacy path - global symbol-record stream - is still the most
    // reliable source of S_PUB32. Walk it first so even a corrupt
    // module list doesn't lose the public names.
    if (dbi_hdr->sym_record_stream != 0xFFFF &&
        dbi_hdr->sym_record_stream < msf->num_streams()) {
        if (auto sr = msf->read_stream(dbi_hdr->sym_record_stream); sr) {
            walk_global_symbol_stream(*sr, rdr.publics);
            // The publics stream (PSI) doesn't typically also carry
            // S_GDATA32 records - those live in module streams - but if
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
// Legacy entry - kept for the existing pdb_test.cpp fixture and any
// callers that only need names. Implemented in terms of the orchestrator
// so there's a single parsing path.
// ---------------------------------------------------------------------------

Result<std::vector<PublicSymbol>>
load_publics_from_buffer(std::vector<std::byte> data) {
    auto rdr = load_pdb_from_buffer(std::move(data));
    if (!rdr) return std::unexpected(std::move(rdr).error());
    return std::move(rdr->publics);
}

}  // namespace spelunk::pdb
