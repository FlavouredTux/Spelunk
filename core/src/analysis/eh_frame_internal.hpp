#pragma once

// Shared primitives for the .eh_frame / __eh_frame parser. Used by
// both the landing-pad / FDE-extent extractors (eh_frame.cpp) and
// the DWARF CFI virtual machine (cfi.cpp).
//
// Header-only; everything inline. Only a handful of TUs include this
// so the bloat is negligible compared to the alternative of an extra
// translation unit.

#include <cstddef>
#include <cstring>
#include <limits>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include <ember/binary/binary.hpp>
#include <ember/common/types.hpp>

namespace ember::ehfi {

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

// Cursor over a (data, position) pair with LEB128 + size-prefixed
// reads. All reads bounds-check; failures return false and leave
// `pos` at an unspecified location (callers are expected to bail).
struct Reader {
    std::span<const std::byte> buf;
    std::size_t pos = 0;

    [[nodiscard]] bool eof()              const { return pos >= buf.size(); }
    [[nodiscard]] bool remaining(std::size_t n) const {
        return pos <= buf.size() && n <= buf.size() - pos;
    }

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

// Read a DW_EH_PE-encoded pointer. `data_base` is the absolute load
// address of this section (so pcrel/datarel can be resolved);
// `cursor_vaddr` is the address of the byte currently being read
// (the pcrel offset source).
[[nodiscard]] inline std::optional<u64>
read_encoded(Reader& r, u8 encoding, u64 data_base, u64 cursor_vaddr) {
    if (encoding == DW_EH_PE_omit) return std::nullopt;

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
        default: return std::nullopt;
    }

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
        // Indirect means the resolved value is the *address* of the
        // actual pointer. We don't follow the indirection here; we
        // still return the computed address so callers that only
        // need to consume the bytes can proceed.
    }
    return val;
}

struct EhFrameSpan {
    std::span<const std::byte> bytes;
    u64 vaddr = 0;
};

[[nodiscard]] inline std::optional<EhFrameSpan>
find_eh_frame(const Binary& b) {
    for (const auto& s : b.sections()) {
        const std::string_view name = s.name;
        // ELF uses ".eh_frame"; Mach-O exposes "__eh_frame".
        if (name == "__eh_frame" || name == ".eh_frame" ||
            name == "__TEXT,__eh_frame") {
            if (s.data.empty()) return std::nullopt;
            return EhFrameSpan{s.data, static_cast<u64>(s.vaddr)};
        }
    }
    return std::nullopt;
}

// Augmentation + factor information extracted from a CIE. The
// landing-pad path needs only `lsda_enc` / `fde_ptr_enc`; the CFI
// VM also needs the alignment factors, return-address register,
// and the initial-instructions span that runs before each FDE's
// own instruction stream.
struct CieInfo {
    u8     lsda_enc                = DW_EH_PE_omit;
    u8     fde_ptr_enc             = DW_EH_PE_absptr;
    bool   has_augmentation        = false;
    u64    code_alignment_factor   = 1;
    i64    data_alignment_factor   = 1;
    u64    return_address_register = 16;  // RIP for x86-64 by convention
    std::span<const std::byte> initial_instructions;
};

[[nodiscard]] inline std::optional<CieInfo>
parse_cie(Reader& cr, u64 cie_vaddr) {
    u8 version = 0;
    if (!cr.get(version)) return std::nullopt;
    // Accept v1-v4. GCC emits v1; some variants use v3.
    if (version < 1 || version > 4) return std::nullopt;

    std::string aug;
    if (!cr.get_cstr(aug)) return std::nullopt;

    if (version == 4) {
        u8 addr_size = 0, segment_size = 0;
        if (!cr.get(addr_size)) return std::nullopt;
        if (!cr.get(segment_size)) return std::nullopt;
    }

    CieInfo out;

    u64 caf = 0;
    i64 daf = 0;
    if (!cr.get_uleb128(caf)) return std::nullopt;
    if (!cr.get_sleb128(daf)) return std::nullopt;
    out.code_alignment_factor = caf;
    out.data_alignment_factor = daf;

    u64 ret_reg = 16;
    if (version == 1) {
        u8 rr = 0;
        if (!cr.get(rr)) return std::nullopt;
        ret_reg = rr;
    } else {
        if (!cr.get_uleb128(ret_reg)) return std::nullopt;
    }
    out.return_address_register = ret_reg;

    out.has_augmentation = !aug.empty() && aug.front() == 'z';
    if (!out.has_augmentation) {
        out.initial_instructions = cr.buf.subspan(cr.pos);
        return out;
    }

    u64 aug_len = 0;
    if (!cr.get_uleb128(aug_len)) return std::nullopt;
    if (aug_len > cr.buf.size() - cr.pos) return std::nullopt;
    const std::size_t aug_start = cr.pos;
    const auto aug_size = static_cast<std::size_t>(aug_len);
    const std::size_t aug_end =
        aug_start + aug_size;
    Reader augmentation{cr.buf.subspan(aug_start, aug_size), 0};

    for (std::size_t i = 1; i < aug.size(); ++i) {
        const char c = aug[i];
        if (c == 'L') {
            u8 enc = 0;
            if (!augmentation.get(enc)) return std::nullopt;
            out.lsda_enc = enc;
        } else if (c == 'R') {
            u8 enc = 0;
            if (!augmentation.get(enc)) return std::nullopt;
            out.fde_ptr_enc = enc;
        } else if (c == 'P') {
            u8 enc = 0;
            if (!augmentation.get(enc)) return std::nullopt;
            if (!read_encoded(augmentation, enc, 0, cie_vaddr)) {
                return std::nullopt;
            }
        } else if (c == 'S' || c == 'B' || c == 'G') {
            // Signal-frame and AArch64 signing/tagging markers carry no
            // augmentation-data byte.
        } else {
            // Unknown augmentation char - rest of augmentation_data is
            // opaque; jump past it via aug_end below.
            break;
        }
    }
    cr.pos = aug_end;
    out.initial_instructions = cr.buf.subspan(cr.pos);
    return out;
}

// The common portion of an FDE: its associated CIE, covered address range,
// and the payload that follows the FDE augmentation data. Extent discovery
// intentionally uses pc_begin/pc_range even when augmentation_valid is false;
// the unwind consumer rejects those entries because their instruction boundary
// is unknown. LSDA decoding remains best-effort, matching its previous parser,
// while the extent scan remains deliberately tolerant.
struct DecodedFde {
    CieInfo cie;
    u64 pc_begin = 0;
    u64 pc_range = 0;
    std::optional<u64> lsda_address;
    std::span<const std::byte> instructions;
    bool augmentation_valid = true;
};

enum class FdeVisit {
    Continue,
    Stop,
};

// Walk the 32-bit-length .eh_frame form used by the existing parser. Record
// framing, CIE lookup, and encoded PC/range reads live here so extent, LSDA,
// and unwind consumers cannot drift into subtly different interpretations.
// The callback may stop the walk early, which is useful for PC-based unwind
// lookup.
template <class Visitor>
inline void for_each_decoded_fde(const Binary& b, Visitor&& visitor) {
    auto eh = find_eh_frame(b);
    if (!eh) return;

    std::map<std::size_t, CieInfo> cies;
    Reader top{eh->bytes, 0};

    while (top.pos + sizeof(u32) <= top.buf.size()) {
        const std::size_t entry_off = top.pos;
        u32 length = 0;
        if (!top.get_le(length)) break;
        if (length == 0 || length == 0xFFFF'FFFFu) break;
        if (length < sizeof(u32)) break;

        if (length > top.buf.size() - top.pos) break;
        const std::size_t payload_end = top.pos + length;

        u32 cie_id = 0;
        if (!top.get_le(cie_id)) break;

        const std::span<const std::byte> inner(
            eh->bytes.data() + top.pos,
            payload_end - top.pos);
        Reader rd{inner, 0};
        const u64 entry_vaddr = eh->vaddr + entry_off;

        if (cie_id == 0) {
            if (auto info = parse_cie(rd, entry_vaddr)) {
                cies[entry_off] = *info;
            }
            top.pos = payload_end;
            continue;
        }

        // In .eh_frame, the CIE pointer is a backwards offset from the
        // pointer field itself to the CIE's length field.
        const std::size_t cie_ptr_pos = top.pos - sizeof(cie_id);
        if (cie_id > cie_ptr_pos) {
            top.pos = payload_end;
            continue;
        }
        const std::size_t cie_off = cie_ptr_pos - cie_id;
        const auto ci_it = cies.find(cie_off);
        if (ci_it == cies.end()) {
            top.pos = payload_end;
            continue;
        }

        const CieInfo& cie = ci_it->second;
        auto pc_begin = read_encoded(
            rd, cie.fde_ptr_enc, eh->vaddr,
            entry_vaddr + sizeof(length) + sizeof(cie_id) + rd.pos);
        if (!pc_begin) {
            top.pos = payload_end;
            continue;
        }
        auto pc_range = read_encoded(
            rd, cie.fde_ptr_enc & 0x0F, eh->vaddr,
            entry_vaddr + sizeof(length) + sizeof(cie_id) + rd.pos);
        if (!pc_range) {
            top.pos = payload_end;
            continue;
        }
        if (*pc_range > std::numeric_limits<u64>::max() - *pc_begin) {
            top.pos = payload_end;
            continue;
        }

        DecodedFde fde;
        fde.cie = cie;
        fde.pc_begin = *pc_begin;
        fde.pc_range = *pc_range;

        if (cie.has_augmentation) {
            u64 augmentation_length = 0;
            if (!rd.get_uleb128(augmentation_length)) {
                fde.augmentation_valid = false;
            } else {
                const std::size_t augmentation_start = rd.pos;
                if (augmentation_length >
                    rd.buf.size() - augmentation_start) {
                    fde.augmentation_valid = false;
                } else {
                    const auto augmentation_size =
                        static_cast<std::size_t>(augmentation_length);
                    Reader augmentation{
                        rd.buf.subspan(augmentation_start, augmentation_size),
                        0};
                    if (cie.lsda_enc != DW_EH_PE_omit &&
                        augmentation_size != 0) {
                        fde.lsda_address = read_encoded(
                            augmentation, cie.lsda_enc, eh->vaddr,
                            entry_vaddr + sizeof(length) + sizeof(cie_id) +
                                augmentation_start);
                    }
                    rd.pos = augmentation_start + augmentation_size;
                }
            }
        }

        if (fde.augmentation_valid) {
            fde.instructions = rd.buf.subspan(rd.pos);
        }
        if (visitor(fde) == FdeVisit::Stop) return;
        top.pos = payload_end;
    }
}

}  // namespace ember::ehfi
