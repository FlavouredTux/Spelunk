#include <ember/analysis/eh_frame.hpp>

#include <cstddef>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include <ember/binary/binary.hpp>
#include <ember/binary/macho.hpp>
#include <ember/common/bytes.hpp>
#include <ember/common/types.hpp>

namespace ember {

namespace {

// DW_EH_PE_* encoding bits from the Itanium exception-handling ABI.
enum : u8 {
    DW_EH_PE_absptr   = 0x00,
    DW_EH_PE_uleb128  = 0x01,
    DW_EH_PE_udata2   = 0x02,
    DW_EH_PE_udata4   = 0x03,
    DW_EH_PE_udata8   = 0x04,
    DW_EH_PE_sleb128  = 0x09,
    DW_EH_PE_sdata2   = 0x0A,
    DW_EH_PE_sdata4   = 0x0B,
    DW_EH_PE_sdata8   = 0x0C,

    DW_EH_PE_pcrel    = 0x10,
    DW_EH_PE_textrel  = 0x20,
    DW_EH_PE_datarel  = 0x30,
    DW_EH_PE_funcrel  = 0x40,
    DW_EH_PE_aligned  = 0x50,
    DW_EH_PE_indirect = 0x80,

    DW_EH_PE_omit     = 0xFF,
};

// ---------------- primitive readers over a (data, cursor) pair ---------------

struct Reader {
    std::span<const std::byte> buf;
    std::size_t pos = 0;

    bool eof() const { return pos >= buf.size(); }
    bool remaining(std::size_t n) const { return pos + n <= buf.size(); }

    bool get(u8& v) {
        if (!remaining(1)) return false;
        v = static_cast<u8>(buf[pos++]);
        return true;
    }
    template <class T>
    bool get_le(T& v) {
        if (!remaining(sizeof(T))) return false;
        std::memcpy(&v, buf.data() + pos, sizeof(T));
        pos += sizeof(T);
        return true;
    }
    bool get_uleb128(u64& v) {
        v = 0;
        unsigned shift = 0;
        while (true) {
            if (eof()) return false;
            const u8 b = static_cast<u8>(buf[pos++]);
            v |= static_cast<u64>(b & 0x7F) << shift;
            if ((b & 0x80) == 0) return true;
            shift += 7;
            if (shift >= 64) return false;
        }
    }
    bool get_sleb128(i64& v) {
        v = 0;
        unsigned shift = 0;
        u8 b = 0;
        while (true) {
            if (eof()) return false;
            b = static_cast<u8>(buf[pos++]);
            v |= static_cast<i64>(b & 0x7F) << shift;
            shift += 7;
            if ((b & 0x80) == 0) break;
            if (shift >= 64) return false;
        }
        if (shift < 64 && (b & 0x40)) {
            v |= -(static_cast<i64>(1) << shift);
        }
        return true;
    }
    bool get_cstr(std::string& out) {
        out.clear();
        while (!eof()) {
            const char c = static_cast<char>(buf[pos++]);
            if (c == 0) return true;
            out.push_back(c);
        }
        return false;
    }
};

// Read a DW_EH_PE-encoded pointer. `data_base` is the absolute load address
// of this section (so pcrel can be resolved); `cursor_vaddr` is the address
// of the byte currently being read (pcrel offset source).
[[nodiscard]] std::optional<u64>
read_encoded(Reader& r, u8 encoding, u64 data_base, u64 cursor_vaddr) {
    if (encoding == DW_EH_PE_omit) return std::nullopt;
    const std::size_t start_pos = r.pos;
    const u64 start_vaddr = cursor_vaddr + (start_pos - r.pos);
    (void)start_vaddr;  // placeholder; we recompute below for the raw bytes

    // We need the pre-read vaddr for pcrel; compute it now.
    const u64 read_at = cursor_vaddr;

    u64 raw = 0;
    const u8 fmt = encoding & 0x0F;
    switch (fmt) {
        case DW_EH_PE_absptr: {
            u64 v = 0;
            if (!r.get_le(v)) return std::nullopt;
            raw = v;
            break;
        }
        case DW_EH_PE_uleb128: {
            u64 v = 0;
            if (!r.get_uleb128(v)) return std::nullopt;
            raw = v;
            break;
        }
        case DW_EH_PE_udata2: {
            u16 v = 0;
            if (!r.get_le(v)) return std::nullopt;
            raw = v;
            break;
        }
        case DW_EH_PE_udata4: {
            u32 v = 0;
            if (!r.get_le(v)) return std::nullopt;
            raw = v;
            break;
        }
        case DW_EH_PE_udata8: {
            u64 v = 0;
            if (!r.get_le(v)) return std::nullopt;
            raw = v;
            break;
        }
        case DW_EH_PE_sleb128: {
            i64 v = 0;
            if (!r.get_sleb128(v)) return std::nullopt;
            raw = static_cast<u64>(v);
            break;
        }
        case DW_EH_PE_sdata2: {
            i16 v = 0;
            if (!r.get_le(v)) return std::nullopt;
            raw = static_cast<u64>(static_cast<i64>(v));
            break;
        }
        case DW_EH_PE_sdata4: {
            i32 v = 0;
            if (!r.get_le(v)) return std::nullopt;
            raw = static_cast<u64>(static_cast<i64>(v));
            break;
        }
        case DW_EH_PE_sdata8: {
            i64 v = 0;
            if (!r.get_le(v)) return std::nullopt;
            raw = static_cast<u64>(v);
            break;
        }
        default:
            return std::nullopt;
    }

    // If the value is 0 under a fixed-width encoding, the ABI treats it as
    // "no pointer" regardless of the base adjustment. This is how LSDA =
    // absent is signalled in most FDEs.
    if (raw == 0 && fmt != DW_EH_PE_absptr) return u64{0};

    const u8 rel = encoding & 0x70;
    u64 val = raw;
    switch (rel) {
        case 0:                  /* absolute */ break;
        case DW_EH_PE_pcrel:     val = read_at + raw; break;
        case DW_EH_PE_datarel:   val = data_base + raw; break;
        case DW_EH_PE_textrel:   val = data_base + raw; break;  // approx
        case DW_EH_PE_funcrel:   val = data_base + raw; break;  // approx
        default:                 return std::nullopt;
    }
    if (encoding & DW_EH_PE_indirect) {
        // Indirect means the resolved value is the *address* of the actual
        // pointer. We don't follow the indirection here (it'd be a load from
        // a GOT-style slot); we still return the computed address so callers
        // that only need to consume the bytes can proceed.
    }
    return val;
}

// Find the __eh_frame / .eh_frame section. Also returns its vaddr.
struct EhFrameSpan {
    std::span<const std::byte> bytes;
    u64 vaddr = 0;
};

[[nodiscard]] std::optional<EhFrameSpan>
find_eh_frame(const Binary& b) {
    for (const auto& s : b.sections()) {
        const std::string_view name = s.name;
        // ELF uses ".eh_frame"; Mach-O exposes "__eh_frame" (the loader
        // strips the "__TEXT," segment prefix).
        if (name == "__eh_frame" || name == ".eh_frame" ||
            name == "__TEXT,__eh_frame") {
            if (s.data.empty()) return std::nullopt;
            return EhFrameSpan{s.data, static_cast<u64>(s.vaddr)};
        }
    }
    return std::nullopt;
}

// Augmentation data extracted from a CIE — just what the FDEs need to
// decode their own fields and LSDA pointers.
struct CieInfo {
    u8 lsda_enc    = DW_EH_PE_omit;
    u8 fde_ptr_enc = DW_EH_PE_absptr;
    bool has_augmentation = false;
};

[[nodiscard]] std::optional<CieInfo>
parse_cie(Reader& cr, u64 cie_vaddr) {
    // version
    u8 version = 0;
    if (!cr.get(version)) return std::nullopt;
    // Accept any v1-v4 CIE. GCC emits v1 typically; some variants use v3.
    if (version < 1 || version > 4) return std::nullopt;

    std::string aug;
    if (!cr.get_cstr(aug)) return std::nullopt;

    if (version == 4) {
        u8 addr_size = 0, segment_size = 0;
        if (!cr.get(addr_size)) return std::nullopt;
        if (!cr.get(segment_size)) return std::nullopt;
    }

    // code_align (uleb), data_align (sleb), return_reg (uleb on v>=3)
    u64 u; i64 s;
    if (!cr.get_uleb128(u)) return std::nullopt;
    if (!cr.get_sleb128(s)) return std::nullopt;
    if (version == 1) {
        u8 rr = 0;
        if (!cr.get(rr)) return std::nullopt;
    } else {
        if (!cr.get_uleb128(u)) return std::nullopt;
    }

    CieInfo out;
    out.has_augmentation = !aug.empty() && aug.front() == 'z';
    if (!out.has_augmentation) return out;

    // augmentation length (uleb)
    u64 aug_len = 0;
    if (!cr.get_uleb128(aug_len)) return std::nullopt;
    const std::size_t aug_end = cr.pos + static_cast<std::size_t>(aug_len);
    if (aug_end > cr.buf.size()) return std::nullopt;

    // Process each character of `aug` past the leading 'z'.
    for (std::size_t i = 1; i < aug.size(); ++i) {
        const char c = aug[i];
        if (c == 'L') {
            u8 enc = 0;
            if (!cr.get(enc)) return std::nullopt;
            out.lsda_enc = enc;
        } else if (c == 'R') {
            u8 enc = 0;
            if (!cr.get(enc)) return std::nullopt;
            out.fde_ptr_enc = enc;
        } else if (c == 'P') {
            u8 enc = 0;
            if (!cr.get(enc)) return std::nullopt;
            // Personality pointer — encoded ptr. We don't use it but must
            // consume the correct number of bytes. Emulate with read_encoded
            // into a throwaway; cursor_vaddr is approximate here and the
            // pointer value itself is irrelevant.
            if (!read_encoded(cr, enc, 0, cie_vaddr)) return std::nullopt;
        } else if (c == 'S') {
            // signal frame, no payload
        } else if (c == 'B' || c == 'G') {
            // uncommon; skip 1-byte encodings conservatively
            u8 ignore = 0;
            (void)cr.get(ignore);
        } else {
            // Unknown augmentation char. The rest of augmentation_data is
            // opaque to us — skip by resetting cr.pos to aug_end below.
            break;
        }
    }
    cr.pos = aug_end;
    return out;
}

void parse_lsda(std::span<const std::byte> lsda_bytes,
                u64 lsda_vaddr,
                u64 pc_begin,
                LpMap& out) {
    Reader lr{lsda_bytes, 0};

    u8 lpstart_enc = 0;
    if (!lr.get(lpstart_enc)) return;
    u64 lp_start = pc_begin;
    if (lpstart_enc != DW_EH_PE_omit) {
        auto v = read_encoded(lr, lpstart_enc, lsda_vaddr,
                              lsda_vaddr + lr.pos);
        if (!v) return;
        lp_start = *v;
    }

    u8 ttype_enc = 0;
    if (!lr.get(ttype_enc)) return;
    if (ttype_enc != DW_EH_PE_omit) {
        u64 ttype_off = 0;
        if (!lr.get_uleb128(ttype_off)) return;
        (void)ttype_off;  // not needed for call-site → lp mapping
    }

    u8 cs_enc = 0;
    if (!lr.get(cs_enc)) return;
    u64 cs_len = 0;
    if (!lr.get_uleb128(cs_len)) return;

    const std::size_t cs_end = lr.pos + static_cast<std::size_t>(cs_len);
    if (cs_end > lr.buf.size()) return;
    // Real LSDAs have dozens to a few hundred call-site entries. A bogus
    // one (misaligned parse, wrong encoding guess) can drive us through
    // megabytes of unrelated bytes. Cap at something generous but bounded.
    constexpr std::size_t kMaxEntriesPerLsda = 2048;
    std::size_t emitted = 0;

    while (lr.pos < cs_end) {
        if (emitted >= kMaxEntriesPerLsda) return;
        auto cs_start = read_encoded(lr, cs_enc, lsda_vaddr,
                                     lsda_vaddr + lr.pos);
        if (!cs_start) return;
        auto cs_length = read_encoded(lr, cs_enc, lsda_vaddr,
                                      lsda_vaddr + lr.pos);
        if (!cs_length) return;
        auto cs_lp = read_encoded(lr, cs_enc, lsda_vaddr,
                                  lsda_vaddr + lr.pos);
        if (!cs_lp) return;
        u64 cs_action = 0;
        if (!lr.get_uleb128(cs_action)) return;
        ++emitted;

        if (*cs_lp == 0) continue;  // no landing pad for this range

        const addr_t range_start = static_cast<addr_t>(pc_begin + *cs_start);
        const addr_t range_end   = static_cast<addr_t>(
            pc_begin + *cs_start + *cs_length);
        const addr_t lp_addr     = static_cast<addr_t>(lp_start + *cs_lp);

        // We record the landing pad at the RANGE's start address. Callers
        // have the call address; a more precise mapping would walk from
        // call-site address back to the covering range. For the emitter's
        // annotation pass this granularity is enough — the call appears at
        // or near the range start.
        LandingPad lp;
        lp.lp_addr      = lp_addr;
        lp.action_index = cs_action;
        out[range_start] = lp;
        (void)range_end;
    }
}

// --------- Apple compact-unwind (__TEXT,__unwind_info) LSDA extraction -------

// The header, sentinel index entry, and LSDA-index entries are all fixed-
// layout little-endian structs. For our purposes we only need the LSDA
// pointer per function; compact-encoding semantics themselves don't matter.
struct CompactUnwindLsda { u64 function_vaddr; u64 lsda_vaddr; };

// The mach_header sits at the __TEXT segment's vmaddr, which is the base
// that compact-unwind offsets are measured from. This is strictly lower
// than the __TEXT,__text section's vmaddr (the header itself + any load
// commands + any preceding sections take up the first N bytes of __TEXT).
// MachOBinary exposes segments directly; for anything else we fall back
// to the lowest readable section vaddr, which is usually close enough.
[[nodiscard]] u64 mach_text_base(const Binary& b) {
    if (const auto* mo = dynamic_cast<const MachOBinary*>(&b); mo) {
        // __PAGEZERO has vaddr 0 + no permissions; skip it and pick the
        // lowest *readable* segment (== __TEXT on every real Mach-O).
        u64 best = ~u64{0};
        for (const auto& seg : mo->segments()) {
            if (!seg.readable) continue;
            if (seg.vaddr == 0) continue;
            if (seg.vaddr < best) best = seg.vaddr;
        }
        if (best != ~u64{0}) return best;
    }
    u64 best = ~u64{0};
    for (const auto& s : b.sections()) {
        if (s.vaddr == 0) continue;
        if (static_cast<u64>(s.vaddr) < best) best = static_cast<u64>(s.vaddr);
    }
    return best == ~u64{0} ? 0u : best;
}

[[nodiscard]] std::vector<CompactUnwindLsda>
parse_compact_unwind(const Binary& b) {
    std::vector<CompactUnwindLsda> out;
    u64 sec_vaddr = 0;
    std::span<const std::byte> bytes;
    for (const auto& s : b.sections()) {
        const std::string_view n = s.name;
        if (n == "__unwind_info" || n == "__TEXT,__unwind_info" ||
            n.ends_with(",__unwind_info")) {
            bytes = s.data;
            sec_vaddr = static_cast<u64>(s.vaddr);
            break;
        }
    }
    if (bytes.size() < 28) return out;

    auto rd32 = [&](std::size_t off) -> std::optional<u32> {
        if (off + 4 > bytes.size()) return std::nullopt;
        u32 v = 0;
        std::memcpy(&v, bytes.data() + off, 4);
        return v;
    };

    auto version = rd32(0);
    if (!version || *version != 1) return out;
    auto idx_off = rd32(20);
    auto idx_cnt = rd32(24);
    if (!idx_off || !idx_cnt || *idx_cnt < 2) return out;

    const u64 text_base = mach_text_base(b);

    // First-level index entries are 12 bytes each.
    // (functionOffset, secondLevelPagesSectionOffset, lsdaIndexArraySectionOffset)
    struct FirstIdx { u32 fn_off, pages_off, lsda_idx_off; };
    std::vector<FirstIdx> first;
    first.reserve(*idx_cnt);
    for (u32 i = 0; i < *idx_cnt; ++i) {
        const std::size_t p = *idx_off + i * 12;
        auto a = rd32(p), bp = rd32(p + 4), c = rd32(p + 8);
        if (!a || !bp || !c) return out;
        first.push_back({*a, *bp, *c});
    }

    // The LSDA index array is contiguous bytes between consecutive first-
    // level entries' lsda_idx_off fields. Each entry is
    //   (functionOffset, lsdaOffset)
    // both u32, offsets from text_base.
    //
    // Sanity: real LSDAs must live inside the __unwind_info section bounds,
    // and real groups produce <= a few thousand entries. Anything wildly
    // outside that is a sign we mis-walked the format and we bail.
    constexpr u32 kMaxGroupEntries = 8192;
    const u32 sec_end = static_cast<u32>(bytes.size());
    for (std::size_t i = 0; i + 1 < first.size(); ++i) {
        const u32 start = first[i].lsda_idx_off;
        const u32 end   = first[i + 1].lsda_idx_off;
        if (start == 0 || end <= start) continue;
        if (start >= sec_end || end > sec_end) continue;
        const u32 n = (end - start) / 8;
        if (n > kMaxGroupEntries) continue;
        for (u32 k = 0; k < n; ++k) {
            const std::size_t p = start + k * 8;
            auto fn = rd32(p), lsda = rd32(p + 4);
            if (!fn || !lsda) break;
            if (*lsda == 0) continue;
            CompactUnwindLsda e;
            e.function_vaddr = text_base + *fn;
            e.lsda_vaddr     = text_base + *lsda;
            out.push_back(e);
        }
    }
    (void)sec_vaddr;
    return out;
}

}  // namespace

LpMap parse_landing_pads(const Binary& b) {
    LpMap out;

    // Apple compact-unwind contributes LSDA pointers too — Mach-O binaries
    // built on modern SDKs use compact encoding primarily, with .eh_frame
    // only as backup or omitted entirely for leaf functions.
    for (const auto& cu : parse_compact_unwind(b)) {
        auto lsda_bytes = b.bytes_at(static_cast<addr_t>(cu.lsda_vaddr));
        if (!lsda_bytes.empty()) {
            parse_lsda(lsda_bytes, cu.lsda_vaddr, cu.function_vaddr, out);
        }
    }

    auto eh = find_eh_frame(b);
    if (!eh) return out;

    // Map cie_offset (absolute position within section) → CieInfo, so FDEs
    // can look up their parent CIE's augmentation.
    std::map<std::size_t, CieInfo> cies;
    Reader top{eh->bytes, 0};

    while (top.pos + 4 <= top.buf.size()) {
        const std::size_t entry_off = top.pos;
        u32 length = 0;
        if (!top.get_le(length)) break;
        if (length == 0) break;  // terminator / padding
        std::size_t entry_len = length;
        if (length == 0xFFFFFFFFu) {
            // 64-bit length extension — rare in practice; bail out safely.
            break;
        }
        const std::size_t payload_end = top.pos + entry_len;
        if (payload_end > top.buf.size()) break;

        u32 cie_id = 0;
        if (!top.get_le(cie_id)) break;

        std::span<const std::byte> inner(
            eh->bytes.data() + top.pos,
            payload_end - top.pos);
        Reader rd{inner, 0};

        const u64 entry_vaddr = eh->vaddr + entry_off;
        const u64 cie_id_vaddr = entry_vaddr + 4;
        (void)cie_id_vaddr;

        if (cie_id == 0) {
            // This is a CIE.
            const u64 cie_vaddr = entry_vaddr;
            auto info = parse_cie(rd, cie_vaddr);
            if (info) cies[entry_off] = *info;
        } else {
            // FDE. cie_id is a BACKWARD offset from the cie_id field's own
            // position to the CIE's length field.
            const std::size_t cie_ptr_pos = top.pos - 4;  // where cie_id lived
            const std::size_t cie_off = (cie_id <= cie_ptr_pos)
                ? (cie_ptr_pos - cie_id)
                : 0;
            auto ci_it = cies.find(cie_off);
            if (ci_it == cies.end()) {
                top.pos = payload_end;
                continue;
            }
            const CieInfo& ci = ci_it->second;

            // pc_begin + pc_range using fde_ptr_enc
            const u64 pc_begin_vaddr = entry_vaddr + 4 + 4 + rd.pos;
            auto pc_begin_v = read_encoded(rd, ci.fde_ptr_enc,
                                           eh->vaddr, pc_begin_vaddr);
            if (!pc_begin_v) { top.pos = payload_end; continue; }
            auto pc_range_v = read_encoded(
                rd, ci.fde_ptr_enc & 0x0F,  // range is same format, no pcrel
                eh->vaddr, entry_vaddr + 4 + 4 + rd.pos);
            if (!pc_range_v) { top.pos = payload_end; continue; }
            (void)pc_range_v;

            std::optional<u64> lsda_addr;
            if (ci.has_augmentation) {
                u64 fde_aug_len = 0;
                if (!rd.get_uleb128(fde_aug_len)) { top.pos = payload_end; continue; }
                const std::size_t aug_end = rd.pos + static_cast<std::size_t>(fde_aug_len);
                if (ci.lsda_enc != DW_EH_PE_omit && fde_aug_len > 0) {
                    auto lsda_vaddr = entry_vaddr + 4 + 4 + rd.pos;
                    lsda_addr = read_encoded(rd, ci.lsda_enc, eh->vaddr,
                                             lsda_vaddr);
                }
                rd.pos = aug_end;
            }

            if (lsda_addr && *lsda_addr != 0) {
                auto lsda_bytes = b.bytes_at(static_cast<addr_t>(*lsda_addr));
                if (!lsda_bytes.empty()) {
                    parse_lsda(lsda_bytes, *lsda_addr, *pc_begin_v, out);
                }
            }
        }

        top.pos = payload_end;
    }

    return out;
}

// Same CIE/FDE walk as parse_landing_pads, but collecting (pc_begin,
// pc_range) for every FDE instead of landing-pad entries. Used for
// function-boundary recovery on stripped binaries where .eh_frame is
// often the only remaining source of function starts.
std::vector<FdeExtent> enumerate_fde_extents(const Binary& b) {
    std::vector<FdeExtent> out;
    auto eh = find_eh_frame(b);
    if (!eh) return out;

    std::map<std::size_t, CieInfo> cies;
    Reader top{eh->bytes, 0};

    while (top.pos + 4 <= top.buf.size()) {
        const std::size_t entry_off = top.pos;
        u32 length = 0;
        if (!top.get_le(length)) break;
        if (length == 0) break;
        if (length == 0xFFFFFFFFu) break;

        const std::size_t payload_end = top.pos + length;
        if (payload_end > top.buf.size()) break;

        u32 cie_id = 0;
        if (!top.get_le(cie_id)) break;

        std::span<const std::byte> inner(
            eh->bytes.data() + top.pos,
            payload_end - top.pos);
        Reader rd{inner, 0};

        const u64 entry_vaddr = eh->vaddr + entry_off;

        if (cie_id == 0) {
            auto info = parse_cie(rd, entry_vaddr);
            if (info) cies[entry_off] = *info;
        } else {
            const std::size_t cie_ptr_pos = top.pos - 4;
            const std::size_t cie_off = (cie_id <= cie_ptr_pos)
                ? (cie_ptr_pos - cie_id) : 0;
            auto ci_it = cies.find(cie_off);
            if (ci_it == cies.end()) { top.pos = payload_end; continue; }
            const CieInfo& ci = ci_it->second;

            const u64 pc_begin_vaddr = entry_vaddr + 4 + 4 + rd.pos;
            auto pc_begin_v = read_encoded(rd, ci.fde_ptr_enc,
                                           eh->vaddr, pc_begin_vaddr);
            if (!pc_begin_v) { top.pos = payload_end; continue; }
            auto pc_range_v = read_encoded(
                rd, ci.fde_ptr_enc & 0x0F,
                eh->vaddr, entry_vaddr + 4 + 4 + rd.pos);
            if (!pc_range_v) { top.pos = payload_end; continue; }

            if (*pc_begin_v != 0 && *pc_range_v != 0) {
                out.push_back({static_cast<addr_t>(*pc_begin_v), *pc_range_v});
            }
        }
        top.pos = payload_end;
    }
    return out;
}

}  // namespace ember
