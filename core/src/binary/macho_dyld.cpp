#include "macho_internal.hpp"

#include <bit>
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

[[nodiscard]] std::optional<i64>
read_sleb128(const std::byte*& p, const std::byte* end) noexcept {
    u64 result = 0;
    unsigned shift = 0;
    for (unsigned byte_index = 0; byte_index < 10; ++byte_index) {
        if (p == end) return std::nullopt;
        const u8 byte = static_cast<u8>(*p++);
        const u8 payload = byte & 0x7fu;

        // A signed 64-bit LEB may use ten bytes, but the final byte contains
        // only the sign-extension bit. Any other payload overflows i64, and a
        // continuation bit would require an eleventh byte.
        if (byte_index == 9) {
            if ((byte & 0x80u) != 0 || (payload != 0 && payload != 0x7fu)) {
                return std::nullopt;
            }
            result |= static_cast<u64>(payload & 1u) << 63;
        } else {
            result |= static_cast<u64>(payload) << shift;
        }

        if ((byte & 0x80u) == 0) {
            const unsigned consumed = shift + 7;
            if (consumed < 64 && (byte & 0x40u) != 0) {
                result |= ~u64{0} << consumed;
            }
            return std::bit_cast<i64>(result);
        }
        shift += 7;
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::size_t>
chain_file_offset(std::span<const std::byte> image, const SegInfo& seg,
                  u64 page_vaddr, u64 page_size,
                  u64 chain_vaddr) noexcept {
    if (chain_vaddr < page_vaddr) return std::nullopt;
    const u64 page_offset = chain_vaddr - page_vaddr;
    // Formats with a four-byte stride may place an eight-byte pointer at
    // page_size-4. The chain entry starts on this page even though the qword
    // straddles into the next backed page.
    if (page_offset >= page_size) return std::nullopt;
    if (chain_vaddr < seg.vmaddr) return std::nullopt;
    const u64 segment_offset = chain_vaddr - seg.vmaddr;
    if (segment_offset > seg.vmsize || 8 > seg.vmsize - segment_offset) {
        return std::nullopt;
    }
    if (segment_offset > seg.filesize || 8 > seg.filesize - segment_offset) {
        return std::nullopt;
    }
    if (seg.fileoff > image.size()) return std::nullopt;
    const u64 available = static_cast<u64>(image.size()) - seg.fileoff;
    if (segment_offset > available || 8 > available - segment_offset) {
        return std::nullopt;
    }
    return static_cast<std::size_t>(seg.fileoff + segment_offset);
}

[[nodiscard]] bool advance_chain(u64& chain_vaddr, u64 delta) noexcept {
    if (delta > std::numeric_limits<u64>::max() - chain_vaddr) return false;
    chain_vaddr += delta;
    return true;
}

[[nodiscard]] bool arm64e_pointer_format(u16 fmt) noexcept {
    return fmt == DYLD_CHAINED_PTR_ARM64E ||
           fmt == DYLD_CHAINED_PTR_ARM64E_KERNEL ||
           fmt == DYLD_CHAINED_PTR_ARM64E_USERLAND ||
           fmt == DYLD_CHAINED_PTR_ARM64E_FIRMWARE ||
           fmt == DYLD_CHAINED_PTR_ARM64E_USERLAND24;
}

[[nodiscard]] u64 arm64e_stride(u16 fmt) noexcept {
    return (fmt == DYLD_CHAINED_PTR_ARM64E_KERNEL ||
            fmt == DYLD_CHAINED_PTR_ARM64E_FIRMWARE) ? 4u : 8u;
}

[[nodiscard]] bool arm64e_unauth_target_is_offset(u16 fmt) noexcept {
    return fmt == DYLD_CHAINED_PTR_ARM64E_KERNEL ||
           fmt == DYLD_CHAINED_PTR_ARM64E_USERLAND ||
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
                   u64                      page_vaddr,
                   u64                      page_size,
                   bool                     target_is_offset,
                   auto&&                   import_name,
                   std::vector<BindRec>&    out)
{
    u64 chain_vaddr = start_vaddr;
    for (u32 steps = 0; steps < 1'000'000; ++steps) {
        const auto file_offset = chain_file_offset(
            image, seg, page_vaddr, page_size, chain_vaddr);
        if (!file_offset) return;

        u64 raw = 0;
        std::memcpy(&raw, image.data() + *file_offset, 8);
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
            u64 real = target;
            if (target_is_offset) {
                real = image_base;
                if (!advance_chain(real, target)) return;
            }
            real |= high8 << 56;
            std::memcpy(image.data() + *file_offset, &real, 8);
        }
        if (next == 0) return;
        if (!advance_chain(chain_vaddr, next * 4u)) return;
    }
}

void walk_chain_arm64e(std::span<std::byte>     image,
                       const SegInfo&           seg,
                       u64                      image_base,
                       u64                      start_vaddr,
                       u64                      page_vaddr,
                       u64                      page_size,
                       u16                      ptr_format,
                       auto&&                   import_name,
                       std::vector<BindRec>&    out)
{
    const u64 stride = arm64e_stride(ptr_format);
    u64 chain_vaddr = start_vaddr;
    for (u32 steps = 0; steps < 1'000'000; ++steps) {
        const auto file_offset = chain_file_offset(
            image, seg, page_vaddr, page_size, chain_vaddr);
        if (!file_offset) return;

        u64 raw = 0;
        std::memcpy(&raw, image.data() + *file_offset, 8);
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
                // runtime offset from the image base in every supported
                // arm64e pointer format.
                const u64 target = raw & 0xFFFFFFFFu;
                real = image_base;
                if (!advance_chain(real, target)) return;
            } else {
                const u64 target = raw & ((u64{1} << 43) - 1);
                const u64 high8  = (raw >> 43) & 0xFFu;
                real = target;
                if (arm64e_unauth_target_is_offset(ptr_format)) {
                    real = image_base;
                    if (!advance_chain(real, target)) return;
                }
                real |= high8 << 56;
            }
            std::memcpy(image.data() + *file_offset, &real, 8);
        }
        if (next == 0) return;
        if (!advance_chain(chain_vaddr, next * stride)) return;
    }
}

void walk_chained_fixup_start(std::span<std::byte>     image,
                              const SegInfo&           seg,
                              u64                      image_base,
                              u64                      chain_vaddr,
                              u64                      page_vaddr,
                              u64                      page_size,
                              u16                      ptr_format,
                              auto&&                   import_name,
                              std::vector<BindRec>&    out)
{
    if (ptr_format == DYLD_CHAINED_PTR_64 ||
        ptr_format == DYLD_CHAINED_PTR_64_OFFSET) {
        walk_chain_64(image, seg, image_base, chain_vaddr,
                      page_vaddr, page_size,
                      ptr_format == DYLD_CHAINED_PTR_64_OFFSET,
                      import_name, out);
    } else if (arm64e_pointer_format(ptr_format)) {
        walk_chain_arm64e(image, seg, image_base, chain_vaddr,
                          page_vaddr, page_size,
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
    for (const auto& s : segs) {
        const bool null_reservation =
            s.vmaddr == 0 && s.fileoff == 0 && s.filesize == 0;
        if (s.name != "__PAGEZERO" && !null_reservation) return s.vmaddr;
    }
    return 0;
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
            if (!read_sleb128(p, end)) return;
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
                if (offset <= std::numeric_limits<u64>::max() - image_base) {
                    out.push_back({static_cast<addr_t>(image_base + offset),
                                   w.prefix});
                }
            } else if ((flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) != 0) {
                const u64 stub_offset = read_uleb128(p, children);
                if (stub_offset <=
                    std::numeric_limits<u64>::max() - image_base) {
                    out.push_back({
                        static_cast<addr_t>(image_base + stub_offset),
                        w.prefix});
                }
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
    auto symbols_fmt   = rd32(24);
    if (!version || *version != 0) return;
    if (!starts_off || !imports_off || !symbols_off || !imports_count ||
        !imports_fmt || !symbols_fmt || *symbols_fmt != 0)
        return;

    // Resolve each ordinal to its symbol name. Formats 1/2 share the
    // 23-bit name_offset field; format 3 stores a 32-bit name_offset in the
    // high half of the first word. Addends are ignored because rendering only
    // needs the imported-symbol name for the bound slot.
    const std::size_t entry_size =
        (*imports_fmt == 1) ? 4 : (*imports_fmt == 2) ? 8 : 16;
    if (*imports_fmt < 1 || *imports_fmt > 3) return;

    const std::size_t starts_base = static_cast<std::size_t>(*starts_off);
    const std::size_t imports_base = static_cast<std::size_t>(*imports_off);
    const std::size_t symbols_base = static_cast<std::size_t>(*symbols_off);
    if (starts_base < 28 || starts_base >= imports_base ||
        imports_base > symbols_base || symbols_base > data.size()) {
        return;
    }
    if (static_cast<std::size_t>(*imports_count) >
        (symbols_base - imports_base) / entry_size) {
        return;
    }

    auto import_name = [&](u32 ordinal) -> std::string {
        if (ordinal >= *imports_count) return {};
        const std::size_t ordinal_offset =
            static_cast<std::size_t>(ordinal) * entry_size;
        const std::size_t ent = imports_base + ordinal_offset;
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
        if (symbols_base >= data.size() ||
            static_cast<std::size_t>(name_offset) >=
                data.size() - symbols_base) {
            return {};
        }
        const std::size_t nameoff =
            symbols_base + static_cast<std::size_t>(name_offset);
        std::string s;
        for (std::size_t i = nameoff;
             i < data.size() && i - nameoff < 1024; ++i) {
            char c = static_cast<char>(data[i]);
            if (c == 0) break;
            s.push_back(c);
        }
        return s;
    };

    // Walk starts_in_image → starts_in_segment → each page's chain.
    if (4 > imports_base - starts_base) return;
    auto seg_count = rd32(starts_base);
    if (!seg_count) return;
    const std::size_t seg_offsets_base = starts_base + 4u;
    if (seg_offsets_base > imports_base) return;
    const std::size_t available_seg_offsets =
        (imports_base - seg_offsets_base) / 4u;
    if (*seg_count > available_seg_offsets || *seg_count > segs.size()) return;
    const std::size_t seg_records_begin =
        seg_offsets_base + static_cast<std::size_t>(*seg_count) * 4u;
    for (u32 si = 0; si < *seg_count; ++si) {
        const std::size_t seg_offset_entry =
            seg_offsets_base + static_cast<std::size_t>(si) * 4u;
        auto seg_info_off = rd32(seg_offset_entry);
        if (!seg_info_off || *seg_info_off == 0) continue;
        if (static_cast<std::size_t>(*seg_info_off) >
            imports_base - starts_base) {
            continue;
        }
        const std::size_t sig =
            starts_base + static_cast<std::size_t>(*seg_info_off);
        if (sig < seg_records_begin) continue;
        auto size = rd32(sig);
        if (!size || *size < 22 ||
            sig > imports_base ||
            static_cast<std::size_t>(*size) > imports_base - sig) {
            continue;
        }
        const std::size_t record_end = sig + static_cast<std::size_t>(*size);
        auto page_size  = rd16(sig + 4);
        auto ptr_format = rd16(sig + 6);
        auto seg_offset = rd64(sig + 8);
        auto page_count = rd16(sig + 20);
        if (!page_size || !ptr_format || !seg_offset || !page_count) continue;
        if (*page_size != 0x1000 && *page_size != 0x4000) continue;
        const std::size_t page_starts_off = sig + 22;
        const std::size_t page_starts_size =
            static_cast<std::size_t>(*page_count) * 2u;
        if (page_starts_size > record_end - page_starts_off) continue;

        if (si >= segs.size()) continue;
        const SegInfo& seg = segs[si];
        if (seg.vmaddr - image_base != *seg_offset) {
            continue;
        }
        for (u16 pi = 0; pi < *page_count; ++pi) {
            auto page_start = rd16(page_starts_off + pi * 2);
            if (!page_start) break;
            if (*page_start == DYLD_CHAINED_PTR_START_NONE) continue;

            u64 page_vaddr = seg.vmaddr;
            if (!advance_chain(page_vaddr,
                               static_cast<u64>(pi) * *page_size)) {
                continue;
            }
            auto valid_page_start = [&](u16 off) {
                u16 alignment = 1;
                if (*ptr_format == DYLD_CHAINED_PTR_64 ||
                    *ptr_format == DYLD_CHAINED_PTR_64_OFFSET) {
                    alignment = 4;
                } else if (arm64e_pointer_format(*ptr_format)) {
                    alignment = static_cast<u16>(arm64e_stride(*ptr_format));
                }
                return static_cast<u64>(off) < *page_size &&
                       off % alignment == 0;
            };
            auto walk_page_start = [&](u16 off) {
                if (!valid_page_start(off)) return;
                u64 chain_vaddr = page_vaddr;
                if (!advance_chain(chain_vaddr, off)) return;
                walk_chained_fixup_start(image, seg, image_base, chain_vaddr,
                                         page_vaddr, *page_size,
                                         *ptr_format, import_name, out);
            };

            // MULTI starts are a 32-bit chained-pointer feature. This loader
            // only accepts 64-bit Mach-O pointer formats, so fail closed.
            if ((*page_start & DYLD_CHAINED_PTR_START_MULTI) != 0) continue;
            walk_page_start(*page_start);
        }
    }
}

}  // namespace ember::macho
