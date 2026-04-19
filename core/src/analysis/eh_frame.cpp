#include <ember/analysis/eh_frame.hpp>

#include <cstddef>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include <ember/binary/binary.hpp>
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

    while (lr.pos < cs_end) {
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

}  // namespace

LpMap parse_landing_pads(const Binary& b) {
    LpMap out;
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

}  // namespace ember
