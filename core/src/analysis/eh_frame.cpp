#include <ember/analysis/eh_frame.hpp>

#include <cstddef>
#include <cstring>
#include <map>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/binary/macho.hpp>
#include <ember/common/bytes.hpp>
#include <ember/common/types.hpp>

#include "eh_frame_internal.hpp"

namespace ember {

namespace {

using ehfi::Reader;
using ehfi::CieInfo;
using ehfi::read_encoded;
using ehfi::find_eh_frame;
using ehfi::parse_cie;
using ehfi::DW_EH_PE_omit;

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
