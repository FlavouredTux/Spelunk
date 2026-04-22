#include <ember/binary/macho.hpp>

#include <algorithm>
#include <cstring>
#include <format>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <ember/common/bytes.hpp>
#include <ember/disasm/instruction.hpp>
#include <ember/disasm/x64_decoder.hpp>

namespace ember {

namespace {

// Magic + CPU
constexpr u32 MH_MAGIC_64         = 0xFEEDFACFu;
constexpr u32 CPU_TYPE_X86_64     = 0x01000007u;
constexpr u32 CPU_TYPE_ARM64      = 0x0100000Cu;

// Load command IDs (only the ones we consume).
constexpr u32 LC_SEGMENT_64       = 0x19u;
constexpr u32 LC_SYMTAB               = 0x02u;
constexpr u32 LC_DYSYMTAB             = 0x0Bu;
constexpr u32 LC_DYLD_INFO            = 0x22u;
constexpr u32 LC_DYLD_INFO_ONLY       = 0x80000022u;
constexpr u32 LC_DYLD_CHAINED_FIXUPS  = 0x80000034u;
constexpr u32 LC_DATA_IN_CODE         = 0x29u;
constexpr u32 LC_MAIN             = 0x80000028u;
constexpr u32 LC_FUNCTION_STARTS  = 0x26u;

// VM protection flags.
constexpr u32 VM_PROT_READ        = 0x1u;
constexpr u32 VM_PROT_WRITE       = 0x2u;
constexpr u32 VM_PROT_EXECUTE     = 0x4u;

// Section types (flags & SECTION_TYPE).
constexpr u32 SECTION_TYPE_MASK         = 0x000000FFu;
constexpr u32 S_SYMBOL_STUBS            = 0x08u;

// nlist n_type flags.
constexpr u8 N_STAB = 0xE0u;
constexpr u8 N_TYPE = 0x0Eu;
constexpr u8 N_EXT  = 0x01u;
constexpr u8 N_UNDF = 0x00u;
constexpr u8 N_SECT = 0x0Eu;

// Bind opcodes (BIND_OPCODE_MASK = 0xF0).
constexpr u8 BIND_OPCODE_MASK                             = 0xF0u;
constexpr u8 BIND_IMMEDIATE_MASK                          = 0x0Fu;
constexpr u8 BIND_OPCODE_DONE                             = 0x00u;
constexpr u8 BIND_OPCODE_SET_DYLIB_ORDINAL_IMM            = 0x10u;
constexpr u8 BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB           = 0x20u;
constexpr u8 BIND_OPCODE_SET_DYLIB_SPECIAL_IMM            = 0x30u;
constexpr u8 BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM    = 0x40u;
constexpr u8 BIND_OPCODE_SET_TYPE_IMM                     = 0x50u;
constexpr u8 BIND_OPCODE_SET_ADDEND_SLEB                  = 0x60u;
constexpr u8 BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB      = 0x70u;
constexpr u8 BIND_OPCODE_ADD_ADDR_ULEB                    = 0x80u;
constexpr u8 BIND_OPCODE_DO_BIND                          = 0x90u;
constexpr u8 BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB            = 0xA0u;
constexpr u8 BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED      = 0xB0u;
constexpr u8 BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xC0u;

[[nodiscard]] Arch arch_from_cpu(u32 cputype) noexcept {
    switch (cputype) {
        case CPU_TYPE_X86_64: return Arch::X86_64;
        case CPU_TYPE_ARM64:  return Arch::Arm64;
        default:              return Arch::Unknown;
    }
}

// Read a null-terminated name from a fixed-width char buffer (e.g. segname[16]).
[[nodiscard]] std::string read_fixed_cstr(const std::byte* p, std::size_t max) {
    std::size_t n = 0;
    while (n < max && p[n] != std::byte{0}) ++n;
    return std::string(reinterpret_cast<const char*>(p), n);
}

[[nodiscard]] u64 read_uleb128(const std::byte*& p, const std::byte* end) noexcept {
    u64 result = 0;
    unsigned shift = 0;
    while (p < end) {
        const u8 b = static_cast<u8>(*p++);
        result |= static_cast<u64>(b & 0x7F) << shift;
        if ((b & 0x80) == 0) break;
        shift += 7;
        if (shift >= 64) break;
    }
    return result;
}

[[nodiscard]] i64 read_sleb128(const std::byte*& p, const std::byte* end) noexcept {
    i64 result = 0;
    unsigned shift = 0;
    u8 b = 0;
    while (p < end) {
        b = static_cast<u8>(*p++);
        result |= static_cast<i64>(b & 0x7F) << shift;
        shift += 7;
        if ((b & 0x80) == 0) break;
        if (shift >= 64) break;
    }
    if (shift < 64 && (b & 0x40)) {
        result |= -(static_cast<i64>(1) << shift);
    }
    return result;
}

// Bind records collected from the LC_DYLD_INFO opcode stream OR from the
// modern LC_DYLD_CHAINED_FIXUPS format. Both converge on (slot vaddr,
// imported-symbol name) — ordinal/addend/type don't affect rendering.
struct BindRec { addr_t vaddr; std::string name; };

// One LC_SEGMENT_64 we've processed, used while resolving section vmaddrs
// referenced by bind opcodes.
struct SegInfo {
    addr_t vmaddr;
    u64    vmsize;
    u64    fileoff;
    u64    filesize;
    std::string name;
};

void parse_bind_stream(
    std::span<const std::byte> bytes,
    std::span<const SegInfo> segs,
    std::vector<BindRec>& out,
    bool is_lazy)
{
    const std::byte* p = bytes.data();
    const std::byte* end = p + bytes.size();
    std::string symbol_name;
    int seg_index = 0;
    u64 seg_offset = 0;

    auto commit = [&]() {
        if (symbol_name.empty()) return;
        if (seg_index < 0 || static_cast<std::size_t>(seg_index) >= segs.size()) return;
        const auto& s = segs[static_cast<std::size_t>(seg_index)];
        out.push_back({static_cast<addr_t>(s.vmaddr + seg_offset), symbol_name});
    };

    while (p < end) {
        const u8 byte = static_cast<u8>(*p++);
        const u8 opcode = byte & BIND_OPCODE_MASK;
        const u8 imm    = byte & BIND_IMMEDIATE_MASK;

        switch (opcode) {
        case BIND_OPCODE_DONE:
            // In lazy_bind, DONE separates records rather than ending the stream.
            if (!is_lazy) return;
            break;
        case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
            break;
        case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
            (void)read_uleb128(p, end);
            break;
        case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
            break;
        case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: {
            const std::byte* s = p;
            while (p < end && *p != std::byte{0}) ++p;
            symbol_name.assign(reinterpret_cast<const char*>(s),
                               static_cast<std::size_t>(p - s));
            if (p < end) ++p;  // skip NUL
            break;
        }
        case BIND_OPCODE_SET_TYPE_IMM:
            break;
        case BIND_OPCODE_SET_ADDEND_SLEB:
            (void)read_sleb128(p, end);
            break;
        case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            seg_index = imm;
            seg_offset = read_uleb128(p, end);
            break;
        case BIND_OPCODE_ADD_ADDR_ULEB:
            seg_offset += read_uleb128(p, end);
            break;
        case BIND_OPCODE_DO_BIND:
            commit();
            seg_offset += 8;
            break;
        case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
            commit();
            seg_offset += 8;
            seg_offset += read_uleb128(p, end);
            break;
        case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
            commit();
            seg_offset += 8;
            seg_offset += static_cast<u64>(imm) * 8u;
            break;
        case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: {
            const u64 count = read_uleb128(p, end);
            const u64 skip  = read_uleb128(p, end);
            for (u64 j = 0; j < count; ++j) {
                commit();
                seg_offset += 8 + skip;
            }
            break;
        }
        default:
            // Unknown opcode — bail rather than corrupt the stream.
            return;
        }
    }
}

// LC_DYLD_CHAINED_FIXUPS decoder. Modern Mach-O (macOS 11+ target) stops
// emitting LC_DYLD_INFO bind opcodes and instead stamps 64-bit chained
// pointers directly into the binary, linked via `__chainfixups` metadata
// in __LINKEDIT.
//
// Layout we produce the same as parse_bind_stream: (slot_vaddr, name).
// Scope: handles the x86_64 / arm64 macOS pointer formats (DYLD_CHAINED_
// PTR_64 = 6 and PTR_ARM64E = 2 with bind bit set). Unknown pointer
// formats are skipped cleanly; the loader falls back to whatever symbols
// the nlist table alone yielded.
void parse_chained_fixups(
    std::span<const std::byte> data,
    std::span<const SegInfo> segs,
    std::span<std::byte> image,
    std::vector<BindRec>& out)
{
    // Preferred load address of the image — chained-rebase `target` fields
    // are encoded relative to this, matching dyld's `runtimeOffset`
    // semantics. On typical PIE binaries this is __TEXT.vmaddr (the
    // segment whose fileoff==0 and which hosts the mach_header). Fall
    // back to any segment with fileoff==0 for non-standard layouts
    // (renamed __TEXT, single-segment dylibs, etc.); finally to the
    // first non-__PAGEZERO segment so we degrade gracefully rather
    // than emit zero-based rebases.
    u64 image_base = 0;
    for (const auto& s : segs) {
        if (s.fileoff == 0 && s.name == "__TEXT") { image_base = s.vmaddr; break; }
    }
    if (image_base == 0) {
        for (const auto& s : segs) {
            if (s.fileoff == 0 && s.vmaddr != 0) { image_base = s.vmaddr; break; }
        }
    }
    if (image_base == 0 && !segs.empty()) image_base = segs.front().vmaddr;

    if (data.size() < 32) return;
    auto rd32 = [&](std::size_t off) -> std::optional<u32> {
        if (off + 4 > data.size()) return std::nullopt;
        u32 v = 0; std::memcpy(&v, data.data() + off, 4); return v;
    };
    auto rd16 = [&](std::size_t off) -> std::optional<u16> {
        if (off + 2 > data.size()) return std::nullopt;
        u16 v = 0; std::memcpy(&v, data.data() + off, 2); return v;
    };
    auto rd64 = [&](std::size_t off) -> std::optional<u64> {
        if (off + 8 > data.size()) return std::nullopt;
        u64 v = 0; std::memcpy(&v, data.data() + off, 8); return v;
    };

    auto version       = rd32(0);
    auto starts_off    = rd32(4);
    auto imports_off   = rd32(8);
    auto symbols_off   = rd32(12);
    auto imports_count = rd32(16);
    auto imports_fmt   = rd32(20);
    if (!version || *version != 0) return;
    if (!starts_off || !imports_off || !symbols_off || !imports_count || !imports_fmt)
        return;

    // Resolve each ordinal to its symbol name. Only imports_format == 1
    // (DYLD_CHAINED_IMPORT) is handled; formats 2/3 add a 32/64-bit addend
    // but have the same name_offset semantics up to an entry-size delta.
    const std::size_t entry_size =
        (*imports_fmt == 1) ? 4 : (*imports_fmt == 2) ? 8 : 16;
    if (*imports_fmt < 1 || *imports_fmt > 3) return;

    auto import_name = [&](u32 ordinal) -> std::string {
        if (ordinal >= *imports_count) return {};
        const std::size_t ent = *imports_off +
            static_cast<std::size_t>(ordinal) * entry_size;
        auto raw = rd32(ent);
        if (!raw) return {};
        const u32 name_offset = (*raw >> 9);
        const std::size_t nameoff = *symbols_off + name_offset;
        if (nameoff >= data.size()) return {};
        std::string s;
        for (std::size_t i = nameoff;
             i < data.size() && i < nameoff + 1024; ++i) {
            char c = static_cast<char>(data[i]);
            if (c == 0) break;
            s.push_back(c);
        }
        return s;
    };

    // Walk starts_in_image → starts_in_segment → each page's chain.
    auto seg_count = rd32(*starts_off);
    if (!seg_count) return;
    for (u32 si = 0; si < *seg_count; ++si) {
        auto seg_info_off = rd32(*starts_off + 4 + si * 4);
        if (!seg_info_off || *seg_info_off == 0) continue;
        const std::size_t sig = *starts_off + *seg_info_off;
        auto size        = rd32(sig);
        auto page_size   = rd16(sig + 4);
        auto ptr_format  = rd16(sig + 6);
        auto seg_offset  = rd64(sig + 8);
        auto page_count  = rd16(sig + 18);
        if (!size || !page_size || !ptr_format || !seg_offset || !page_count)
            continue;

        // Only DYLD_CHAINED_PTR_64 (6) and its kernel-variant (12) are the
        // common formats for user binaries on x86_64 / arm64. arm64e uses
        // format 2 which needs different bit-packing; skip for now.
        if (*ptr_format != 6 && *ptr_format != 12) continue;
        if (si >= segs.size()) continue;
        const u64 seg_vaddr = segs[si].vmaddr;

        for (u16 pi = 0; pi < *page_count; ++pi) {
            auto page_start = rd16(sig + 20 + pi * 2);
            if (!page_start) break;
            if (*page_start == 0xFFFF) continue;   // DYLD_CHAINED_PTR_START_NONE

            u64 chain_vaddr = seg_vaddr + *seg_offset +
                              static_cast<u64>(pi) * *page_size + *page_start;
            // Walk the chain via image bytes. `image` spans the whole file,
            // but chained pointers live in mapped segments where fileoff
            // offset = vaddr - seg_vaddr + seg.fileoff.
            u32 steps = 0;
            while (steps++ < 1'000'000) {
                // Map vaddr back to file offset.
                const auto& sref = segs[si];
                if (chain_vaddr < sref.vmaddr ||
                    chain_vaddr >= sref.vmaddr + sref.vmsize) break;
                const u64 fo = sref.fileoff + (chain_vaddr - sref.vmaddr);
                if (fo + 8 > image.size()) break;
                u64 raw = 0;
                std::memcpy(&raw, image.data() + fo, 8);
                const bool is_bind = (raw >> 63) & 1;
                const u64  next    = (raw >> 51) & 0xFFFu;
                if (is_bind) {
                    const u32 ordinal = static_cast<u32>(raw & 0xFFFFFFu);
                    std::string name = import_name(ordinal);
                    if (!name.empty()) {
                        out.push_back({static_cast<addr_t>(chain_vaddr),
                                       std::move(name)});
                    }
                } else {
                    // Rebase. Resolve to a real VA and write it back to
                    // the in-memory buffer so later consumers (RTTI
                    // walker, ObjC scanner, generic section reads) see
                    // a plain pointer rather than the chain descriptor.
                    // Without this, every pointer in __DATA_CONST that
                    // lives on a fixup chain reads as a packed bitfield.
                    //
                    // dyld_chained_ptr_64_rebase bit layout:
                    //   target  [ 0:35]  vmaddr offset from image base
                    //   high8   [36:43]  ObjC tagged-pointer / type bits,
                    //                    dyld OR's these into the top byte
                    //   reserved[44:50]  zero
                    //   next    [51:62]  4-byte stride to next chain entry
                    //   bind    [   63]  == 0 here (we're in the rebase arm)
                    const u64 target = raw & ((u64{1} << 36) - 1);
                    const u64 high8  = (raw >> 36) & 0xFFu;
                    const u64 real   = (image_base + target) | (high8 << 56);
                    std::memcpy(image.data() + fo, &real, 8);
                }
                if (next == 0) break;
                chain_vaddr += next * 4u;  // stride is 4 on format 6
            }
        }
    }
}

// Strip a leading underscore used by Mach-O's C-ABI name mangling so that
// e.g. `_malloc` matches the libc arity table as `malloc`.
[[nodiscard]] std::string demangle_macho(std::string_view n) {
    if (!n.empty() && n.front() == '_') return std::string(n.substr(1));
    return std::string(n);
}

// Read a NUL-terminated C string at a virtual address using the segment map.
// Returns empty if the address is out of range or the string is absurdly
// long / non-printable (guards against corrupted ObjC pointers).
[[nodiscard]] std::string
read_cstring_at(std::span<const LoadSegment> segs, addr_t vaddr) {
    for (const auto& seg : segs) {
        if (vaddr < seg.vaddr) continue;
        const u64 off = vaddr - seg.vaddr;
        if (off >= seg.filesz) continue;
        if (seg.data.empty()) continue;
        auto tail = seg.data.subspan(static_cast<std::size_t>(off));
        std::string out;
        out.reserve(64);
        const std::size_t max_len = std::min<std::size_t>(tail.size(), 512u);
        for (std::size_t i = 0; i < max_len; ++i) {
            const u8 c = static_cast<u8>(tail[i]);
            if (c == 0) return out;
            if (c < 0x20 || c > 0x7E) return {};
            out.push_back(static_cast<char>(c));
        }
        return {};  // no NUL within limit
    }
    return {};
}

// Read 8 bytes at a vmaddr via the segment map (pointer-sized fields in
// __DATA/__objc_* sections). Returns 0 when out of range.
[[nodiscard]] u64
read_u64_at(std::span<const LoadSegment> segs, addr_t vaddr) {
    for (const auto& seg : segs) {
        if (vaddr < seg.vaddr) continue;
        const u64 off = vaddr - seg.vaddr;
        if (off + 8 > seg.filesz) continue;
        if (seg.data.empty()) continue;
        return read_le_at<u64>(seg.data.data() + static_cast<std::size_t>(off));
    }
    return 0;
}

[[nodiscard]] u32
read_u32_at(std::span<const LoadSegment> segs, addr_t vaddr) {
    for (const auto& seg : segs) {
        if (vaddr < seg.vaddr) continue;
        const u64 off = vaddr - seg.vaddr;
        if (off + 4 > seg.filesz) continue;
        if (seg.data.empty()) continue;
        return read_le_at<u32>(seg.data.data() + static_cast<std::size_t>(off));
    }
    return 0;
}

}  // namespace

Result<std::unique_ptr<MachOBinary>>
MachOBinary::load_from_buffer(std::vector<std::byte> buffer) {
    std::unique_ptr<MachOBinary> self(new MachOBinary(std::move(buffer)));
    if (auto rv = self->parse(); !rv) {
        return std::unexpected(std::move(rv).error());
    }
    return self;
}

Result<void> MachOBinary::parse() {
    const ByteReader r(buffer_);

    if (r.size() < 32) {
        return std::unexpected(Error::truncated(std::format(
            "macho: file smaller than mach_header_64 ({} < 32)", r.size())));
    }

    const std::byte* const hdr = buffer_.data();
    const u32 magic    = read_le_at<u32>(hdr + 0);
    if (magic != MH_MAGIC_64) {
        return std::unexpected(Error::invalid_format(std::format(
            "macho: not a 64-bit Mach-O (magic = {:#x})", magic)));
    }
    endian_ = Endian::Little;
    const u32 cputype  = read_le_at<u32>(hdr + 4);
    const u32 ncmds    = read_le_at<u32>(hdr + 16);
    const u32 sizeofcmds = read_le_at<u32>(hdr + 20);
    arch_ = arch_from_cpu(cputype);

    // Collect raw command slices. We iterate twice: once to pull segments
    // (needed before bind opcodes can resolve addresses), then again for
    // symtab/dysymtab/dyld_info/main.
    const std::size_t cmd_start = 32;
    auto cmds_bytes = r.slice(cmd_start, sizeofcmds);
    if (!cmds_bytes) return std::unexpected(std::move(cmds_bytes).error());

    // Load commands are variable-length; collect (offset, cmd, cmdsize) triples.
    struct LCRef { std::size_t off; u32 cmd; u32 size; };
    std::vector<LCRef> lcs;
    lcs.reserve(ncmds);
    {
        std::size_t p = 0;
        const std::size_t limit = cmds_bytes->size();
        for (u32 i = 0; i < ncmds; ++i) {
            if (p + 8 > limit) break;
            const u32 cmd  = read_le_at<u32>(cmds_bytes->data() + p);
            const u32 size = read_le_at<u32>(cmds_bytes->data() + p + 4);
            if (size < 8 || p + size > limit) break;
            lcs.push_back({cmd_start + p, cmd, size});
            p += size;
        }
    }

    std::vector<SegInfo> seg_info;

    // ---- Pass 1: LC_SEGMENT_64 ---------------------------------------------
    for (const auto& lc : lcs) {
        if (lc.cmd != LC_SEGMENT_64) continue;
        auto lcb = r.slice(lc.off, lc.size);
        if (!lcb) continue;
        const std::byte* const p = lcb->data();

        std::string segname = read_fixed_cstr(p + 8, 16);
        const u64 vmaddr   = read_le_at<u64>(p + 24);
        const u64 vmsize   = read_le_at<u64>(p + 32);
        const u64 fileoff  = read_le_at<u64>(p + 40);
        const u64 filesize = read_le_at<u64>(p + 48);
        const u32 initprot = read_le_at<u32>(p + 60);
        const u32 nsects   = read_le_at<u32>(p + 64);

        seg_info.push_back({static_cast<addr_t>(vmaddr), vmsize, fileoff, filesize, segname});

        // Skip the __PAGEZERO no-map segment so it doesn't pollute bytes_at().
        if (vmsize > 0 && !(segname == "__PAGEZERO")) {
            LoadSegment seg;
            seg.vaddr      = static_cast<addr_t>(vmaddr);
            seg.memsz      = vmsize;
            seg.filesz     = filesize;
            seg.readable   = (initprot & VM_PROT_READ)    != 0;
            seg.writable   = (initprot & VM_PROT_WRITE)   != 0;
            seg.executable = (initprot & VM_PROT_EXECUTE) != 0;
            if (filesize > 0) {
                if (auto bytes = r.slice(fileoff, filesize); bytes) {
                    seg.data = *bytes;
                }
            }
            segments_.push_back(std::move(seg));
        }

        // Parse sections contiguously after the segment_command_64 header (72 bytes).
        const std::size_t sect_table = 72;
        for (u32 s = 0; s < nsects; ++s) {
            const std::size_t so = sect_table + static_cast<std::size_t>(s) * 80;
            if (so + 80 > lc.size) break;
            const std::byte* const sp = p + so;
            const std::string sectname = read_fixed_cstr(sp + 0, 16);
            // const std::string segn_s   = read_fixed_cstr(sp + 16, 16);
            const u64 addr    = read_le_at<u64>(sp + 32);
            const u64 size    = read_le_at<u64>(sp + 40);
            const u32 offset  = read_le_at<u32>(sp + 48);
            const u32 flags   = read_le_at<u32>(sp + 64);

            Section out;
            out.name = segname + "," + sectname;
            out.vaddr = static_cast<addr_t>(addr);
            out.file_offset = offset;
            out.size = size;
            out.flags.allocated  = true;
            out.flags.readable   = (initprot & VM_PROT_READ)    != 0;
            out.flags.writable   = (initprot & VM_PROT_WRITE)   != 0;
            out.flags.executable = (initprot & VM_PROT_EXECUTE) != 0;
            // ZEROFILL / BSS-ish sections have offset=0; everything else has bytes.
            const u32 stype = flags & SECTION_TYPE_MASK;
            (void)stype;
            if (offset != 0 && size > 0) {
                if (auto data = r.slice(offset, size); data) out.data = *data;
            }
            sections_.push_back(std::move(out));
        }
    }

    // ---- Pass 2: LC_SYMTAB / LC_DYSYMTAB / LC_DYLD_INFO_ONLY / LC_MAIN ------
    std::span<const std::byte> symtab_bytes;
    std::span<const std::byte> strtab_bytes;
    u32 nsyms = 0;

    std::span<const std::byte> bind_bytes;
    std::span<const std::byte> lazy_bind_bytes;
    std::span<const std::byte> weak_bind_bytes;
    std::span<const std::byte> chained_fixups_bytes;
    std::span<const std::byte> data_in_code_bytes;

    bool     have_entryoff = false;
    u64      entryoff      = 0;

    std::span<const std::byte> fn_starts_bytes;

    for (const auto& lc : lcs) {
        auto lcb = r.slice(lc.off, lc.size);
        if (!lcb) continue;
        const std::byte* const p = lcb->data();
        switch (lc.cmd) {
        case LC_SYMTAB: {
            const u32 symoff  = read_le_at<u32>(p + 8);
            const u32 ns      = read_le_at<u32>(p + 12);
            const u32 stroff  = read_le_at<u32>(p + 16);
            const u32 strsize = read_le_at<u32>(p + 20);
            nsyms = ns;
            if (auto s = r.slice(symoff, static_cast<std::size_t>(ns) * 16); s)
                symtab_bytes = *s;
            if (auto s = r.slice(stroff, strsize); s)
                strtab_bytes = *s;
            break;
        }
        case LC_DYSYMTAB:
            // The indirect symbol table would be useful for tying __stubs
            // directly to symbol indices, but the bind-opcode + stubs-scan
            // pipeline already covers every real import, so leave it for
            // later if it becomes necessary.
            break;
        case LC_DYLD_INFO:
        case LC_DYLD_INFO_ONLY: {
            const u32 bind_off       = read_le_at<u32>(p + 16);
            const u32 bind_size      = read_le_at<u32>(p + 20);
            const u32 weak_bind_off  = read_le_at<u32>(p + 24);
            const u32 weak_bind_size = read_le_at<u32>(p + 28);
            const u32 lazy_bind_off  = read_le_at<u32>(p + 32);
            const u32 lazy_bind_size = read_le_at<u32>(p + 36);
            if (bind_size > 0) {
                if (auto s = r.slice(bind_off, bind_size); s) bind_bytes = *s;
            }
            if (lazy_bind_size > 0) {
                if (auto s = r.slice(lazy_bind_off, lazy_bind_size); s) lazy_bind_bytes = *s;
            }
            if (weak_bind_size > 0) {
                if (auto s = r.slice(weak_bind_off, weak_bind_size); s) weak_bind_bytes = *s;
            }
            break;
        }
        case LC_MAIN: {
            entryoff = read_le_at<u64>(p + 8);
            have_entryoff = true;
            break;
        }
        case LC_FUNCTION_STARTS: {
            // linkedit_data_command: cmd, cmdsize, dataoff, datasize
            const u32 dataoff  = read_le_at<u32>(p + 8);
            const u32 datasize = read_le_at<u32>(p + 12);
            if (datasize > 0) {
                if (auto s = r.slice(dataoff, datasize); s) fn_starts_bytes = *s;
            }
            break;
        }
        case LC_DYLD_CHAINED_FIXUPS: {
            const u32 dataoff  = read_le_at<u32>(p + 8);
            const u32 datasize = read_le_at<u32>(p + 12);
            if (datasize > 0) {
                if (auto s = r.slice(dataoff, datasize); s) chained_fixups_bytes = *s;
            }
            break;
        }
        case LC_DATA_IN_CODE: {
            const u32 dataoff  = read_le_at<u32>(p + 8);
            const u32 datasize = read_le_at<u32>(p + 12);
            if (datasize > 0) {
                if (auto s = r.slice(dataoff, datasize); s) data_in_code_bytes = *s;
            }
            break;
        }
        default: break;
        }
    }

    // Resolve LC_MAIN's file-offset entryoff to a VM address by finding which
    // segment's fileoff range contains it (typically __TEXT).
    if (have_entryoff) {
        for (const auto& s : seg_info) {
            if (entryoff >= s.fileoff && entryoff < s.fileoff + s.filesize) {
                entry_ = static_cast<addr_t>(s.vmaddr + (entryoff - s.fileoff));
                break;
            }
        }
        if (entry_ == 0) entry_ = static_cast<addr_t>(entryoff);
    }

    // ---- Parse the nlist symbol table -------------------------------------
    // Imports are nlist entries with N_TYPE == N_UNDF; their name is in the
    // string table; we'll later point Symbol.addr at a __stubs slot via the
    // indirect symbol table, and Symbol.got_addr at the filled-in pointer slot.
    std::unordered_map<std::string, std::size_t> import_by_name;
    std::vector<std::size_t> sym_index_to_symbols(nsyms, std::size_t(-1));

    if (!symtab_bytes.empty() && !strtab_bytes.empty()) {
        const ByteReader str(strtab_bytes);
        for (u32 k = 0; k < nsyms; ++k) {
            const std::byte* const np = symtab_bytes.data() + static_cast<std::size_t>(k) * 16;
            const u32 n_strx = read_le_at<u32>(np + 0);
            const u8  n_type = read_le_at<u8> (np + 4);
            const u64 n_value= read_le_at<u64>(np + 8);

            if (n_type & N_STAB) continue;  // debug stabs — ignore

            std::string name;
            if (auto nm = str.read_cstr(n_strx); nm) name = std::string(*nm);

            const u8 type_bits = n_type & N_TYPE;
            const bool is_undef = (type_bits == N_UNDF) && ((n_type & N_EXT) != 0);

            Symbol sym;
            sym.name      = name;
            sym.addr      = static_cast<addr_t>(n_value);
            sym.kind      = is_undef ? SymbolKind::Function : SymbolKind::Unknown;
            sym.is_import = is_undef;
            sym.is_export = !is_undef && ((n_type & N_EXT) != 0);

            if (is_undef) {
                sym.addr = 0;  // filled in later via __stubs
                if (!name.empty()) {
                    import_by_name.emplace(name, symbols_.size());
                }
            } else if (type_bits == N_SECT) {
                // Defined-in-section. Without function size info (LC_FUNCTION_STARTS
                // is separate), we leave size=0 and rely on the CFG builder to find
                // function boundaries. Kind defaults to Function for now; objects
                // tagged by section won't always be distinguishable here, but the
                // emitter only cares about Function for call targets.
                sym.kind = SymbolKind::Function;
            }

            if (!name.empty() || sym.is_import) {
                sym_index_to_symbols[k] = symbols_.size();
                symbols_.push_back(std::move(sym));
            }
        }
    }

    // ---- Parse bind/lazy_bind/weak_bind opcodes ---------------------------
    // Builds slot_vaddr → name for every imported data/func pointer. The
    // lazy_bind stream covers __la_symbol_ptr slots (which are what __stubs
    // indirect through), so scanning it is essential for named calls to work.
    std::vector<BindRec> binds;
    binds.reserve(256);
    if (!bind_bytes.empty())      parse_bind_stream(bind_bytes,      seg_info, binds, false);
    if (!weak_bind_bytes.empty()) parse_bind_stream(weak_bind_bytes, seg_info, binds, false);
    if (!lazy_bind_bytes.empty()) parse_bind_stream(lazy_bind_bytes, seg_info, binds, true);
    // Modern builds emit LC_DYLD_CHAINED_FIXUPS instead of LC_DYLD_INFO
    // opcodes. Parse both — newer linkers occasionally emit both, older
    // ones only one.
    if (!chained_fixups_bytes.empty()) {
        parse_chained_fixups(chained_fixups_bytes, seg_info, buffer_, binds);
    }

    // LC_DATA_IN_CODE: list of (file_offset, length, kind) marking embedded
    // data inside __TEXT. Convert each file offset into a VA using the
    // segment map so the CFG walker can steer around them.
    if (!data_in_code_bytes.empty()) {
        const std::size_t n = data_in_code_bytes.size() / 8;
        data_in_code_.reserve(n);
        for (std::size_t i = 0; i < n; ++i) {
            const std::byte* e = data_in_code_bytes.data() + i * 8;
            const u32 foff   = read_le_at<u32>(e + 0);
            const u16 len    = read_le_at<u16>(e + 4);
            const u16 kind   = read_le_at<u16>(e + 6);
            // Resolve file offset to vaddr via the segment map.
            addr_t va = 0;
            for (const auto& s : seg_info) {
                if (foff >= s.fileoff && foff < s.fileoff + s.filesize) {
                    va = static_cast<addr_t>(s.vmaddr + (foff - s.fileoff));
                    break;
                }
            }
            if (va != 0) {
                data_in_code_.push_back({va, len, kind});
            }
        }
    }

    std::unordered_map<addr_t, std::string> slot_to_name;
    slot_to_name.reserve(binds.size());
    for (auto& b : binds) slot_to_name.emplace(b.vaddr, std::move(b.name));

    // Attach got_addr to imports by name — the bind opcodes give us the
    // slot (la_symbol_ptr / got) addresses, which are what the emitter uses
    // to render indirect calls through the GOT as named calls.
    for (auto& sym : symbols_) {
        if (!sym.is_import || sym.got_addr != 0) continue;
        for (const auto& [addr, name] : slot_to_name) {
            if (name == sym.name) { sym.got_addr = addr; break; }
        }
    }

    // ---- Stub scan: __stubs → __la_symbol_ptr slot → name ----------------
    // We mirror the ELF PLT scan: decode each `jmp qword [rip + D]` in a
    // section whose SECTION_TYPE is S_SYMBOL_STUBS. The RIP-relative target
    // is the __la_symbol_ptr slot; slot_to_name gives us the import.
    if (arch_ == Arch::X86_64 && !slot_to_name.empty()) {
        // Find __stubs sections by walking the segment/section tables once more.
        // We've stored sections in sections_ already but without flags, so redo
        // the walk to check SECTION_TYPE.
        std::unordered_map<std::string, addr_t> import_stub_addr;
        const X64Decoder dec;

        for (const auto& lc : lcs) {
            if (lc.cmd != LC_SEGMENT_64) continue;
            auto lcb = r.slice(lc.off, lc.size);
            if (!lcb) continue;
            const std::byte* const p = lcb->data();
            const u32 nsects = read_le_at<u32>(p + 64);
            for (u32 s = 0; s < nsects; ++s) {
                const std::size_t so = 72 + static_cast<std::size_t>(s) * 80;
                if (so + 80 > lc.size) break;
                const std::byte* const sp = p + so;
                const u64 addr    = read_le_at<u64>(sp + 32);
                const u64 size    = read_le_at<u64>(sp + 40);
                const u32 offset  = read_le_at<u32>(sp + 48);
                const u32 flags   = read_le_at<u32>(sp + 64);
                const u32 stype   = flags & SECTION_TYPE_MASK;
                if (stype != S_SYMBOL_STUBS) continue;
                if (offset == 0 || size == 0) continue;
                auto data = r.slice(offset, size);
                if (!data) continue;

                addr_t ip = static_cast<addr_t>(addr);
                std::size_t off = 0;
                while (off < data->size()) {
                    auto remaining = data->subspan(off);
                    auto decoded = dec.decode(remaining, ip);
                    if (!decoded) { ip += 1; off += 1; continue; }
                    const Instruction& insn = *decoded;
                    if (insn.mnemonic == Mnemonic::Jmp && insn.num_operands == 1) {
                        const Operand& op = insn.operands[0];
                        if (op.kind == Operand::Kind::Memory &&
                            op.mem.base == Reg::Rip &&
                            op.mem.index == Reg::None &&
                            op.mem.has_disp) {
                            const addr_t slot = ip + insn.length +
                                                static_cast<addr_t>(op.mem.disp);
                            auto it = slot_to_name.find(slot);
                            if (it != slot_to_name.end()) {
                                import_stub_addr.try_emplace(it->second, ip);
                            }
                        }
                    }
                    ip  += insn.length;
                    off += insn.length;
                }
            }
        }

        for (auto& sym : symbols_) {
            if (!sym.is_import || sym.addr != 0) continue;
            auto it = import_stub_addr.find(sym.name);
            if (it == import_stub_addr.end()) continue;
            sym.addr = it->second;
        }
    }

    // Strip the leading `_` that Mach-O prepends to C symbols, so that
    // `strlen` (and everything the emitter's name-based logic keys on)
    // matches without the caller having to know about it.
    for (auto& sym : symbols_) {
        if (!sym.name.empty() && sym.name.front() == '_') {
            sym.name = demangle_macho(sym.name);
        }
    }

    // Synthesize `main` at the LC_MAIN entry *before* LC_FUNCTION_STARTS runs,
    // so that pass leaves the entry address to the conventional name instead
    // of stamping `sub_<hex>` on top.
    if (entry_ != 0) {
        bool named_here = false;
        for (const auto& s : symbols_) {
            if (!s.is_import && s.addr == entry_ && !s.name.empty()) {
                named_here = true; break;
            }
        }
        if (!named_here) {
            Symbol m;
            m.name = "main";
            m.addr = entry_;
            m.kind = SymbolKind::Function;
            symbols_.push_back(std::move(m));
        }
    }

    // ---- LC_FUNCTION_STARTS: full function-boundary map -------------------
    // Mach-O rarely carries nlist sizes, and release binaries drop most
    // internal names — but LC_FUNCTION_STARTS is almost always present and
    // lists every function's starting address as a ULEB128 delta stream.
    // Decoding it lets us: (a) fill in `size` on every existing function
    // symbol (next_start - this_start), and (b) add synthetic `sub_<hex>`
    // entries for the rest so the CFG builder, arity inference, call graph,
    // and UI sidebar all see the complete function set.
    if (!fn_starts_bytes.empty()) {
        addr_t text_base = 0;
        u64    text_end  = 0;
        for (const auto& s : seg_info) {
            if (s.name == "__TEXT") {
                text_base = s.vmaddr;
                text_end  = s.vmaddr + s.vmsize;
                break;
            }
        }
        if (text_base != 0) {
            std::vector<addr_t> starts;
            const std::byte* bp = fn_starts_bytes.data();
            const std::byte* be = bp + fn_starts_bytes.size();
            addr_t cur = text_base;
            while (bp < be) {
                const u64 delta = read_uleb128(bp, be);
                if (delta == 0) break;  // terminator
                cur += delta;
                starts.push_back(cur);
            }
            std::ranges::sort(starts);
            starts.erase(std::ranges::unique(starts).begin(), starts.end());

            // Cache existing non-import function addresses for O(1) overlap checks.
            std::unordered_map<addr_t, std::size_t> existing_by_addr;
            for (std::size_t i = 0; i < symbols_.size(); ++i) {
                const auto& s = symbols_[i];
                if (s.is_import) continue;
                if (s.kind != SymbolKind::Function) continue;
                existing_by_addr.emplace(s.addr, i);
            }

            for (std::size_t i = 0; i < starts.size(); ++i) {
                const addr_t a = starts[i];
                const u64 end = (i + 1 < starts.size()) ? starts[i + 1] : text_end;
                const u64 sz  = (end > a) ? (end - a) : 0;

                if (auto it = existing_by_addr.find(a); it != existing_by_addr.end()) {
                    if (symbols_[it->second].size == 0) symbols_[it->second].size = sz;
                    continue;
                }
                Symbol synth;
                synth.name = std::format("sub_{:x}", a);
                synth.addr = a;
                synth.size = sz;
                synth.kind = SymbolKind::Function;
                symbols_.push_back(std::move(synth));
            }
        }
    }

    // ---- ObjC method scan: __objc_classlist → [Class method] names -------
    // For each class_t pointer in __objc_classlist we read:
    //   class_t { isa; superclass; cache; vtable; class_ro_t* data; }   (5 * 8)
    //   class_ro_t { flags; instance_*; ivar_layout; char* name;
    //                method_list_t* methods; ... }
    //   method_list_t { u32 entsize; u32 count; method_t methods[count]; }
    //   method_t { char* name; char* types; imp; }   (3 * 8 by default)
    // We fire a Function symbol at each imp with a human-readable name,
    // which makes the decompile output show Objective-C method names where
    // `sub_<hex>` would otherwise appear.
    {
        const Section* classlist = nullptr;
        for (const auto& s : sections_) {
            // Section names are "__SEG,__NAME"; match on the suffix.
            if (s.name.size() >= 17 &&
                s.name.substr(s.name.size() - 16) == "__objc_classlist") {
                classlist = &s; break;
            }
        }
        if (classlist && classlist->size >= 8) {
            const std::size_t n_classes = static_cast<std::size_t>(classlist->size / 8);
            auto also_scan_ro = [&](addr_t ro_ptr, std::string_view cls_name, bool meta) {
                if (ro_ptr == 0) return;
                // class_ro_t.name at offset 24, methods at offset 32 (on 64-bit).
                const addr_t name_ptr    = static_cast<addr_t>(read_u64_at(segments_, ro_ptr + 24));
                const addr_t methods_ptr = static_cast<addr_t>(read_u64_at(segments_, ro_ptr + 32));
                std::string final_cls(cls_name);
                if (final_cls.empty() && name_ptr) {
                    final_cls = read_cstring_at(segments_, name_ptr);
                }
                if (final_cls.empty() || !methods_ptr) return;

                const u32 entsize = read_u32_at(segments_, methods_ptr + 0);
                const u32 count   = read_u32_at(segments_, methods_ptr + 4);
                // Sanity: entsize for method_t is typically 24 (three 8-byte
                // pointers); newer binaries may use a 12-byte relative-pointer
                // layout indicated by the top bits of entsize. Bail on that
                // variant for now.
                const u32 real_entsize = entsize & 0xFFFCu;
                if (real_entsize != 24) return;
                if (count > 100000) return;  // sanity

                const char prefix = meta ? '+' : '-';
                for (u32 m = 0; m < count; ++m) {
                    const addr_t base = methods_ptr + 8 +
                                        static_cast<addr_t>(m) * real_entsize;
                    const addr_t sel_ptr = static_cast<addr_t>(read_u64_at(segments_, base + 0));
                    const addr_t imp     = static_cast<addr_t>(read_u64_at(segments_, base + 16));
                    if (!sel_ptr || !imp) continue;
                    std::string sel = read_cstring_at(segments_, sel_ptr);
                    if (sel.empty()) continue;

                    // Prefer the ObjC name over a synthetic `sub_<hex>` entry
                    // created by LC_FUNCTION_STARTS.
                    Symbol s;
                    s.name = std::format("{}[{} {}]", prefix, final_cls, sel);
                    s.addr = imp;
                    s.kind = SymbolKind::Function;
                    symbols_.push_back(std::move(s));
                }
            };

            for (std::size_t i = 0; i < n_classes; ++i) {
                const addr_t slot     = classlist->vaddr + static_cast<addr_t>(i) * 8u;
                const addr_t cls_ptr  = static_cast<addr_t>(read_u64_at(segments_, slot));
                if (cls_ptr == 0) continue;
                // class_t layout: 5 * 8; `data` (class_ro_t*) at +32. The low
                // bit of data is a realized flag — mask it off.
                const addr_t meta_ptr = static_cast<addr_t>(read_u64_at(segments_, cls_ptr + 0));
                const addr_t ro_ptr   = static_cast<addr_t>(read_u64_at(segments_, cls_ptr + 32)) & ~addr_t{1};
                // Grab the class name from instance ro so we can pass it to
                // the metaclass scan too (class methods list sits on the isa).
                const addr_t name_ptr = static_cast<addr_t>(read_u64_at(segments_, ro_ptr + 24));
                std::string cls_name = name_ptr ? read_cstring_at(segments_, name_ptr) : std::string{};

                also_scan_ro(ro_ptr, cls_name, /*meta=*/false);
                if (meta_ptr) {
                    const addr_t meta_ro = static_cast<addr_t>(read_u64_at(segments_, meta_ptr + 32)) & ~addr_t{1};
                    also_scan_ro(meta_ro, cls_name, /*meta=*/true);
                }
            }
        }
    }

    // Sort + dedupe, mirroring ELF.
    std::ranges::sort(symbols_, [](const Symbol& a, const Symbol& b) noexcept {
        if (a.is_import != b.is_import) return a.is_import < b.is_import;
        if (a.addr      != b.addr)      return a.addr < b.addr;
        if (a.name      != b.name)      return a.name < b.name;
        return a.size < b.size;
    });
    auto dups = std::ranges::unique(symbols_,
        [](const Symbol& a, const Symbol& b) noexcept {
            return a.addr == b.addr
                && a.size == b.size
                && a.is_import == b.is_import
                && a.name == b.name;
        });
    symbols_.erase(dups.begin(), dups.end());
    return {};
}

}  // namespace ember
