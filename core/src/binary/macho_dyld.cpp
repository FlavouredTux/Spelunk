#include "macho_internal.hpp"

#include <cstddef>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <ember/common/types.hpp>

namespace ember::macho {

namespace {

// dyld_chained_starts_in_segment::pointer_format.
constexpr u16 DYLD_CHAINED_PTR_ARM64E            = 1u;
constexpr u16 DYLD_CHAINED_PTR_64                = 2u;
constexpr u16 DYLD_CHAINED_PTR_64_OFFSET         = 6u;
constexpr u16 DYLD_CHAINED_PTR_ARM64E_KERNEL     = 7u;
constexpr u16 DYLD_CHAINED_PTR_ARM64E_USERLAND   = 9u;
constexpr u16 DYLD_CHAINED_PTR_ARM64E_FIRMWARE   = 10u;
constexpr u16 DYLD_CHAINED_PTR_ARM64E_USERLAND24 = 12u;
constexpr u16 DYLD_CHAINED_PTR_START_NONE        = 0xFFFFu;
constexpr u16 DYLD_CHAINED_PTR_START_MULTI       = 0x8000u;
constexpr u16 DYLD_CHAINED_PTR_START_LAST        = 0x8000u;

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

[[nodiscard]] i64 read_sleb128(const std::byte*& p,
                               const std::byte* end) noexcept {
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

[[nodiscard]] bool arm64e_pointer_format(u16 fmt) noexcept {
    return fmt == DYLD_CHAINED_PTR_ARM64E ||
           fmt == DYLD_CHAINED_PTR_ARM64E_KERNEL ||
           fmt == DYLD_CHAINED_PTR_ARM64E_USERLAND ||
           fmt == DYLD_CHAINED_PTR_ARM64E_FIRMWARE ||
           fmt == DYLD_CHAINED_PTR_ARM64E_USERLAND24;
}

[[nodiscard]] u64 arm64e_stride(u16 fmt) noexcept {
    return (fmt == DYLD_CHAINED_PTR_ARM64E ||
            fmt == DYLD_CHAINED_PTR_ARM64E_FIRMWARE) ? 4u : 8u;
}

[[nodiscard]] bool arm64e_target_is_offset(u16 fmt) noexcept {
    return fmt == DYLD_CHAINED_PTR_ARM64E_USERLAND ||
           fmt == DYLD_CHAINED_PTR_ARM64E_USERLAND24;
}

// Walk a single DYLD_CHAINED_PTR_64 chain starting at `start_vaddr` inside
// `seg`. Binds are appended to `out`; rebases are resolved in place into
// `image` so downstream consumers see plain pointers. The 1M-step cap
// guards against malformed chains that self-reference.
void walk_chain_64(std::span<std::byte>     image,
                   const SegInfo&           seg,
                   u64                      image_base,
                   u64                      start_vaddr,
                   bool                     target_is_offset,
                   auto&&                   import_name,
                   std::vector<BindRec>&    out)
{
    u64 chain_vaddr = start_vaddr;
    for (u32 steps = 0; steps < 1'000'000; ++steps) {
        if (chain_vaddr < seg.vmaddr ||
            chain_vaddr >= seg.vmaddr + seg.vmsize) return;
        const u64 fo = seg.fileoff + (chain_vaddr - seg.vmaddr);
        if (fo + 8 > image.size()) return;

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
            // Rebase. Resolve to a real VA and write it back to the in-memory
            // buffer so later consumers (RTTI walker, ObjC scanner, generic
            // section reads) see a plain pointer rather than the chain
            // descriptor. Without this, every pointer in __DATA_CONST that
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
            const u64 real   = ((target_is_offset ? image_base : 0) + target) |
                               (high8 << 56);
            std::memcpy(image.data() + fo, &real, 8);
        }
        if (next == 0) return;
        chain_vaddr += next * 4u;  // stride is 4 on format 6
    }
}

void walk_chain_arm64e(std::span<std::byte>     image,
                       const SegInfo&           seg,
                       u64                      image_base,
                       u64                      start_vaddr,
                       u16                      ptr_format,
                       auto&&                   import_name,
                       std::vector<BindRec>&    out)
{
    const u64 stride = arm64e_stride(ptr_format);
    u64 chain_vaddr = start_vaddr;
    for (u32 steps = 0; steps < 1'000'000; ++steps) {
        if (chain_vaddr < seg.vmaddr ||
            chain_vaddr >= seg.vmaddr + seg.vmsize) return;
        const u64 fo = seg.fileoff + (chain_vaddr - seg.vmaddr);
        if (fo + 8 > image.size()) return;

        u64 raw = 0;
        std::memcpy(&raw, image.data() + fo, 8);
        const bool is_auth = (raw >> 63) & 1u;
        const bool is_bind = (raw >> 62) & 1u;
        const u64  next    = (raw >> 51) & 0x7FFu;

        if (is_bind) {
            const u32 ordinal = (ptr_format == DYLD_CHAINED_PTR_ARM64E_USERLAND24)
                ? static_cast<u32>(raw & 0xFFFFFFu)
                : static_cast<u32>(raw & 0xFFFFu);
            std::string name = import_name(ordinal);
            if (!name.empty()) {
                out.push_back({static_cast<addr_t>(chain_vaddr), std::move(name)});
            }
        } else {
            u64 real = 0;
            if (is_auth) {
                // dyld_chained_ptr_arm64e_auth_rebase::target is a 32-bit
                // vm offset for userland formats and a vmaddr elsewhere.
                const u64 target = raw & 0xFFFFFFFFu;
                real = (arm64e_target_is_offset(ptr_format) ? image_base : 0) + target;
            } else {
                const u64 target = raw & ((u64{1} << 43) - 1);
                const u64 high8  = (raw >> 43) & 0xFFu;
                real = ((arm64e_target_is_offset(ptr_format) ? image_base : 0) + target) |
                       (high8 << 56);
            }
            std::memcpy(image.data() + fo, &real, 8);
        }
        if (next == 0) return;
        chain_vaddr += next * stride;
    }
}

void walk_chained_fixup_start(std::span<std::byte>     image,
                              const SegInfo&           seg,
                              u64                      image_base,
                              u64                      chain_vaddr,
                              u16                      ptr_format,
                              auto&&                   import_name,
                              std::vector<BindRec>&    out)
{
    if (ptr_format == DYLD_CHAINED_PTR_64 ||
        ptr_format == DYLD_CHAINED_PTR_64_OFFSET) {
        walk_chain_64(image, seg, image_base, chain_vaddr,
                      ptr_format == DYLD_CHAINED_PTR_64_OFFSET,
                      import_name, out);
    } else if (arm64e_pointer_format(ptr_format)) {
        walk_chain_arm64e(image, seg, image_base, chain_vaddr,
                          ptr_format, import_name, out);
    }
}

}  // namespace

[[nodiscard]] u64 read_uleb128(const std::byte*& p,
                               const std::byte* end) noexcept {
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

[[nodiscard]] u64 macho_image_base(std::span<const SegInfo> segs) noexcept {
    for (const auto& s : segs) {
        if (s.fileoff == 0 && s.name == "__TEXT") return s.vmaddr;
    }
    for (const auto& s : segs) {
        if (s.fileoff == 0 && s.vmaddr != 0) return s.vmaddr;
    }
    return segs.empty() ? 0 : segs.front().vmaddr;
}

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
    constexpr u64 kMaxBindActions = 1u << 20;
    u64 bind_actions = 0;

    auto commit = [&]() -> bool {
        if (++bind_actions > kMaxBindActions) return false;
        if (symbol_name.empty()) return true;
        if (seg_index < 0 || static_cast<std::size_t>(seg_index) >= segs.size()) return false;
        const auto& s = segs[static_cast<std::size_t>(seg_index)];
        if (seg_offset > s.vmsize || 8 > s.vmsize - seg_offset) return false;
        if (seg_offset > std::numeric_limits<addr_t>::max() - s.vmaddr) return false;
        out.push_back({static_cast<addr_t>(s.vmaddr + seg_offset), symbol_name});
        return true;
    };
    auto advance = [&](u64 delta) -> bool {
        if (delta > std::numeric_limits<u64>::max() - seg_offset) return false;
        seg_offset += delta;
        return true;
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
            if (!advance(read_uleb128(p, end))) return;
            break;
        case BIND_OPCODE_DO_BIND:
            if (!commit() || !advance(8)) return;
            break;
        case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
            if (!commit() || !advance(8) ||
                !advance(read_uleb128(p, end))) return;
            break;
        case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
            if (!commit() || !advance(8 + static_cast<u64>(imm) * 8u)) return;
            break;
        case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: {
            const u64 count = read_uleb128(p, end);
            const u64 skip  = read_uleb128(p, end);
            if (count > kMaxBindActions - bind_actions ||
                skip > std::numeric_limits<u64>::max() - 8) return;
            for (u64 j = 0; j < count; ++j) {
                if (!commit() || !advance(8 + skip)) return;
            }
            break;
        }
        default:
            // Unknown opcode - bail rather than corrupt the stream.
            return;
        }
    }
}

// Dyld export trie nodes carry terminal export info plus a trie of child
// edge labels. Modern stripped Mach-O binaries can omit useful exported
// names from LC_SYMTAB while keeping them here for dyld, so recover them
// as Symbol rows before final sort/dedupe.
void parse_export_trie(std::span<const std::byte> data,
                       u64 image_base,
                       std::vector<ExportRec>& out)
{
    constexpr u64 EXPORT_SYMBOL_FLAGS_KIND_MASK = 0x03u;
    constexpr u64 EXPORT_SYMBOL_FLAGS_KIND_REGULAR = 0x00u;
    constexpr u64 EXPORT_SYMBOL_FLAGS_REEXPORT = 0x08u;
    constexpr u64 EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER = 0x10u;

    if (data.empty()) return;

    struct Work { std::size_t off; std::string prefix; };
    std::vector<Work> stack;
    stack.push_back({0, {}});

    std::unordered_set<std::size_t> visited;
    for (u32 guard = 0; !stack.empty() && guard < 1'000'000; ++guard) {
        Work w = std::move(stack.back());
        stack.pop_back();
        if (w.off >= data.size()) continue;
        if (!visited.insert(w.off).second) continue;

        const std::byte* p = data.data() + w.off;
        const std::byte* const end = data.data() + data.size();
        const u64 terminal_size = read_uleb128(p, end);
        if (terminal_size > static_cast<u64>(end - p)) continue;
        const std::byte* children = p + terminal_size;

        if (terminal_size != 0 && !w.prefix.empty()) {
            const u64 flags = read_uleb128(p, children);
            const u64 kind = flags & EXPORT_SYMBOL_FLAGS_KIND_MASK;
            if ((flags & EXPORT_SYMBOL_FLAGS_REEXPORT) == 0 &&
                kind == EXPORT_SYMBOL_FLAGS_KIND_REGULAR) {
                const u64 offset = read_uleb128(p, children);
                out.push_back({static_cast<addr_t>(image_base + offset),
                               w.prefix});
            } else if ((flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) != 0) {
                const u64 stub_offset = read_uleb128(p, children);
                out.push_back({static_cast<addr_t>(image_base + stub_offset),
                               w.prefix});
            }
        }

        p = children;
        if (p >= end) continue;
        const u8 child_count = static_cast<u8>(*p++);
        for (u8 i = 0; i < child_count; ++i) {
            std::string edge;
            while (p < end && *p != std::byte{0}) {
                const char c = static_cast<char>(*p++);
                if (c < 0x20 || c > 0x7e) { edge.clear(); break; }
                edge.push_back(c);
                if (edge.size() > 1024) { edge.clear(); break; }
            }
            if (p >= end) break;
            ++p;  // NUL
            const u64 child_off = read_uleb128(p, end);
            if (edge.empty() || child_off >= data.size()) continue;
            stack.push_back({static_cast<std::size_t>(child_off),
                             w.prefix + edge});
        }
    }
}

// LC_DYLD_CHAINED_FIXUPS decoder. Modern Mach-O (macOS 11+ target) stops
// emitting LC_DYLD_INFO bind opcodes and instead stamps 64-bit chained
// pointers directly into the binary, linked via `__chainfixups` metadata
// in __LINKEDIT.
//
// Layout we produce the same as parse_bind_stream: (slot_vaddr, name).
// Handles 64-bit chained pointers and arm64e userland/kernel/firmware
// formats, including authenticated arm64e rebases. Unknown pointer formats
// are skipped cleanly; the loader falls back to whatever symbols the nlist
// table alone yielded.
void parse_chained_fixups(
    std::span<const std::byte> data,
    std::span<const SegInfo> segs,
    std::span<std::byte> image,
    std::vector<BindRec>& out)
{
    // Preferred load address of the image - chained-rebase `target` fields
    // are encoded relative to this, matching dyld's `runtimeOffset`
    // semantics. On typical PIE binaries this is __TEXT.vmaddr (the
    // segment whose fileoff==0 and which hosts the mach_header). Fall
    // back to any segment with fileoff==0 for non-standard layouts
    // (renamed __TEXT, single-segment dylibs, etc.); finally to the
    // first non-__PAGEZERO segment so we degrade gracefully rather
    // than emit zero-based rebases.
    const u64 image_base = macho_image_base(segs);

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

    // Resolve each ordinal to its symbol name. Formats 1/2 share the
    // 23-bit name_offset field; format 3 stores a 32-bit name_offset in the
    // high half of the first word. Addends are ignored because rendering only
    // needs the imported-symbol name for the bound slot.
    const std::size_t entry_size =
        (*imports_fmt == 1) ? 4 : (*imports_fmt == 2) ? 8 : 16;
    if (*imports_fmt < 1 || *imports_fmt > 3) return;

    auto import_name = [&](u32 ordinal) -> std::string {
        if (ordinal >= *imports_count) return {};
        const std::size_t ent = *imports_off +
            static_cast<std::size_t>(ordinal) * entry_size;
        u32 name_offset = 0;
        if (*imports_fmt == 3) {
            // dyld_chained_import_addend64:
            //   lib_ordinal:16, weak_import:1, reserved:15, name_offset:32
            auto raw = rd64(ent);
            if (!raw) return {};
            name_offset = static_cast<u32>(*raw >> 32);
        } else {
            // dyld_chained_import / dyld_chained_import_addend:
            //   lib_ordinal:8, weak_import:1, name_offset:23
            auto raw = rd32(ent);
            if (!raw) return {};
            name_offset = (*raw >> 9);
        }
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
    if (*starts_off > data.size() - 4u) return;
    const std::size_t available_seg_offsets =
        (data.size() - *starts_off - 4u) / 4u;
    if (*seg_count > available_seg_offsets || *seg_count > segs.size()) return;
    for (u32 si = 0; si < *seg_count; ++si) {
        auto seg_info_off = rd32(*starts_off + 4 + si * 4);
        if (!seg_info_off || *seg_info_off == 0) continue;
        const std::size_t sig = *starts_off + *seg_info_off;
        auto size        = rd32(sig);
        auto page_size   = rd16(sig + 4);
        auto ptr_format  = rd16(sig + 6);
        auto seg_offset  = rd64(sig + 8);
        auto page_count  = rd16(sig + 20);
        if (!size || !page_size || !ptr_format || !seg_offset || !page_count)
            continue;
        if (*size < 22) continue;
        const std::size_t page_starts_off = sig + 22;
        const std::size_t page_starts_end =
            page_starts_off + static_cast<std::size_t>(*page_count) * 2u;
        if (page_starts_end > data.size()) continue;

        if (si >= segs.size()) continue;
        const u64 seg_vaddr = segs[si].vmaddr;

        const SegInfo& seg = segs[si];
        for (u16 pi = 0; pi < *page_count; ++pi) {
            auto page_start = rd16(page_starts_off + pi * 2);
            if (!page_start) break;
            if (*page_start == DYLD_CHAINED_PTR_START_NONE) continue;

            auto walk_page_start = [&](u16 off) {
                const u64 chain_vaddr = seg_vaddr + *seg_offset +
                                        static_cast<u64>(pi) * *page_size +
                                        off;
                walk_chained_fixup_start(image, seg, image_base, chain_vaddr,
                                         *ptr_format, import_name, out);
            };

            if ((*page_start & DYLD_CHAINED_PTR_START_MULTI) == 0) {
                walk_page_start(*page_start);
                continue;
            }

            constexpr u16 kStartOffsetMask =
                static_cast<u16>(~DYLD_CHAINED_PTR_START_MULTI);
            std::size_t chain_idx = static_cast<std::size_t>(*page_start & kStartOffsetMask);
            const std::size_t chain_starts_off = page_starts_end;
            for (u32 guard = 0; guard < 1'000'000; ++guard) {
                auto chain_start = rd16(chain_starts_off + chain_idx * 2u);
                if (!chain_start) break;
                walk_page_start(static_cast<u16>(*chain_start & kStartOffsetMask));
                if ((*chain_start & DYLD_CHAINED_PTR_START_LAST) != 0) break;
                ++chain_idx;
            }
        }
    }
}

}  // namespace ember::macho
