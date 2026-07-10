#include <ember/binary/macho.hpp>

#include <algorithm>
#include <cstring>
#include <format>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
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
constexpr u32 LC_DYLD_EXPORTS_TRIE    = 0x80000033u;
constexpr u32 LC_DYLD_CHAINED_FIXUPS  = 0x80000034u;
constexpr u32 LC_DATA_IN_CODE         = 0x29u;
constexpr u32 LC_MAIN             = 0x80000028u;
constexpr u32 LC_FUNCTION_STARTS  = 0x26u;
constexpr u32 LC_UNIXTHREAD       = 0x05u;

// thread_state flavors used inside LC_UNIXTHREAD.
constexpr u32 X86_THREAD_STATE64  = 0x04u;
constexpr u32 ARM_THREAD_STATE64  = 0x06u;

// Fixed command sizes we dereference directly.
constexpr u32 SEGMENT_COMMAND_64_SIZE    = 72u;
constexpr u32 SECTION_64_SIZE            = 80u;
constexpr u32 SYMTAB_COMMAND_SIZE        = 24u;
constexpr u32 DYSYMTAB_COMMAND_SIZE      = 80u;
constexpr u32 DYLD_INFO_COMMAND_SIZE     = 48u;
constexpr u32 ENTRY_POINT_COMMAND_SIZE   = 24u;
constexpr u32 LINKEDIT_DATA_COMMAND_SIZE = 16u;

// VM protection flags.
constexpr u32 VM_PROT_READ        = 0x1u;
constexpr u32 VM_PROT_WRITE       = 0x2u;
constexpr u32 VM_PROT_EXECUTE     = 0x4u;

// Section types (flags & SECTION_TYPE).
constexpr u32 SECTION_TYPE_MASK          = 0x000000FFu;
constexpr u32 S_ZEROFILL                 = 0x01u;
constexpr u32 S_GB_ZEROFILL              = 0x0cu;
constexpr u32 S_THREAD_LOCAL_ZEROFILL    = 0x12u;
constexpr u32 S_NON_LAZY_SYMBOL_POINTERS = 0x06u;
constexpr u32 S_LAZY_SYMBOL_POINTERS     = 0x07u;
constexpr u32 S_SYMBOL_STUBS             = 0x08u;
constexpr u32 S_ATTR_SOME_INSTRUCTIONS   = 0x00000400u;
constexpr u32 S_ATTR_PURE_INSTRUCTIONS   = 0x80000000u;

constexpr u32 INDIRECT_SYMBOL_LOCAL     = 0x80000000u;
constexpr u32 INDIRECT_SYMBOL_ABS       = 0x40000000u;

[[nodiscard]] constexpr bool section_is_zerofill(u32 flags) noexcept {
    const u32 type = flags & SECTION_TYPE_MASK;
    return type == S_ZEROFILL || type == S_GB_ZEROFILL ||
           type == S_THREAD_LOCAL_ZEROFILL;
}

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

constexpr u32 OBJC_RELATIVE_METHOD_LIST_FLAG = 0x80000000u;
constexpr u32 OBJC_PREOPT_SEL_FLAG           = 0x40000000u;

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

[[nodiscard]] bool section_has_instructions(std::string_view sectname,
                                            u32 flags,
                                            u32 initprot) noexcept {
    if ((flags & (S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS)) != 0) {
        return true;
    }
    return sectname == "__text" && ((initprot & VM_PROT_EXECUTE) != 0);
}

[[nodiscard]] addr_t unixthread_entry(std::span<const std::byte> lc,
                                      Arch arch) noexcept {
    if (lc.size() < 16) return 0;
    const u32 flavor = read_le_at<u32>(lc.data() + 8);
    const u32 count  = read_le_at<u32>(lc.data() + 12);
    const std::size_t state = 16;

    if (arch == Arch::X86_64 && flavor == X86_THREAD_STATE64) {
        // x86_thread_state64_t: rax..r15, rip, rflags, cs, fs, gs.
        constexpr std::size_t rip_off = state + 16u * 8u;
        if (count < 34 || rip_off + 8 > lc.size()) return 0;
        return static_cast<addr_t>(read_le_at<u64>(lc.data() + rip_off));
    }
    if (arch == Arch::Arm64 && flavor == ARM_THREAD_STATE64) {
        // arm_thread_state64_t: x0..x28, fp, lr, sp, pc, cpsr, flags.
        constexpr std::size_t pc_off = state + 32u * 8u;
        if (count < 66 || pc_off + 8 > lc.size()) return 0;
        return static_cast<addr_t>(read_le_at<u64>(lc.data() + pc_off));
    }
    return 0;
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
// imported-symbol name) - ordinal/addend/type don't affect rendering.
struct BindRec { addr_t vaddr; std::string name; };
struct ExportRec { addr_t vaddr; std::string name; };

// One LC_SEGMENT_64 we've processed, used while resolving section vmaddrs
// referenced by bind opcodes.
struct SegInfo {
    addr_t vmaddr;
    u64    vmsize;
    u64    fileoff;
    u64    filesize;
    std::string name;
};

[[nodiscard]] i64 sign_extend_u64(u64 v, unsigned width) noexcept {
    const u64 sign = u64{1} << (width - 1);
    return static_cast<i64>((v ^ sign) - sign);
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

[[nodiscard]] bool executable_at(std::span<const Section> sections,
                                 addr_t va) noexcept {
    for (const auto& s : sections) {
        if (!s.flags.executable) continue;
        if (va >= s.vaddr && va < s.vaddr + s.size) return true;
    }
    return false;
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

[[nodiscard]] std::optional<addr_t>
resolve_lc_main_entry(u64 entryoff, std::span<const SegInfo> segs) noexcept {
    for (const auto& s : segs) {
        if (s.name != "__TEXT") continue;
        if (entryoff < s.vmsize) {
            return static_cast<addr_t>(s.vmaddr + entryoff);
        }
        break;
    }

    // Be permissive for hand-built fixtures and older local tests that wrote
    // LC_MAIN as a file offset. Real ld64 emits the __TEXT-relative form above.
    for (const auto& s : segs) {
        if (entryoff >= s.fileoff && entryoff < s.fileoff + s.filesize) {
            return static_cast<addr_t>(s.vmaddr + (entryoff - s.fileoff));
        }
    }
    return std::nullopt;
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

[[nodiscard]] u16
read_u16_at(std::span<const LoadSegment> segs, addr_t vaddr) {
    for (const auto& seg : segs) {
        if (vaddr < seg.vaddr) continue;
        const u64 off = vaddr - seg.vaddr;
        if (off + 2 > seg.filesz) continue;
        if (seg.data.empty()) continue;
        return read_le_at<u16>(seg.data.data() + static_cast<std::size_t>(off));
    }
    return 0;
}

[[nodiscard]] i32
read_i32_at(std::span<const LoadSegment> segs, addr_t vaddr) {
    return static_cast<i32>(read_u32_at(segs, vaddr));
}

[[nodiscard]] std::optional<addr_t>
decode_arm64_stub_slot(std::span<const std::byte> bytes, std::size_t off, addr_t ip) {
    if (off + 12 > bytes.size()) return std::nullopt;
    const u32 adrp = read_le_at<u32>(bytes.data() + off + 0);
    const u32 ldr  = read_le_at<u32>(bytes.data() + off + 4);
    const u32 br   = read_le_at<u32>(bytes.data() + off + 8);

    if ((adrp & 0x9F000000u) != 0x90000000u) return std::nullopt;
    const u32 reg = adrp & 0x1Fu;

    // LDR Xt, [Xn, #imm12] with 64-bit element width.
    if ((ldr & 0xFFC00000u) != 0xF9400000u) return std::nullopt;
    const u32 ldr_rt = ldr & 0x1Fu;
    const u32 ldr_rn = (ldr >> 5) & 0x1Fu;
    if (ldr_rt != reg || ldr_rn != reg) return std::nullopt;

    if ((br & 0xFFFFFC1Fu) != 0xD61F0000u) return std::nullopt;
    const u32 br_rn = (br >> 5) & 0x1Fu;
    if (br_rn != reg) return std::nullopt;

    const u32 immlo = (adrp >> 29) & 0x3u;
    const u32 immhi = (adrp >> 5) & 0x7FFFFu;
    const i64 page_delta = sign_extend_u64((static_cast<u64>(immhi) << 2) | immlo, 21) << 12;
    const addr_t page = (ip & ~addr_t{0xFFF}) + static_cast<addr_t>(page_delta);
    const u64 disp = static_cast<u64>((ldr >> 10) & 0xFFFu) * 8u;
    return page + static_cast<addr_t>(disp);
}

[[nodiscard]] const Section*
find_section_suffix(std::span<const Section> sections, std::string_view suffix) noexcept {
    for (const auto& s : sections) {
        const std::string_view n = s.name;
        if (n == suffix) return &s;
        if (n.ends_with(suffix)) return &s;
    }
    return nullptr;
}

void append_swift_symbol_piece(std::string& out, std::string_view name) {
    for (char c : name) {
        const bool ok = (c >= 'A' && c <= 'Z') ||
                        (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') ||
                        c == '_';
        out.push_back(ok ? c : '_');
    }
}

[[nodiscard]] std::string swift_symbol_name(std::string_view name) {
    std::string out = "swift_type_";
    append_swift_symbol_piece(out, name);
    return out;
}

[[nodiscard]] std::string swift_accessor_symbol_name(std::string_view name) {
    std::string out = swift_symbol_name(name);
    out += "_accessor";
    return out;
}

[[nodiscard]] std::string swift_field_symbol_name(std::string_view type_name,
                                                  std::string_view field_name) {
    std::string out = "swift_field_";
    append_swift_symbol_piece(out, type_name);
    out.push_back('_');
    append_swift_symbol_piece(out, field_name);
    return out;
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
    if (ncmds > sizeofcmds / 8u) {
        return std::unexpected(Error::invalid_format(std::format(
            "macho: {} load commands cannot fit in {} bytes", ncmds, sizeofcmds)));
    }

    // Load commands are variable-length; collect (offset, cmd, cmdsize) triples.
    struct LCRef { std::size_t off; u32 cmd; u32 size; };
    std::vector<LCRef> lcs;
    lcs.reserve(ncmds);
    {
        std::size_t p = 0;
        const std::size_t limit = cmds_bytes->size();
        for (u32 i = 0; i < ncmds; ++i) {
            if (p > limit || 8 > limit - p) {
                return std::unexpected(Error::truncated(std::format(
                    "macho: load command {} header overruns command area", i)));
            }
            const u32 cmd  = read_le_at<u32>(cmds_bytes->data() + p);
            const u32 size = read_le_at<u32>(cmds_bytes->data() + p + 4);
            if (size < 8) {
                return std::unexpected(Error::invalid_format(std::format(
                    "macho: load command {} has invalid size {}", i, size)));
            }
            if (size > limit - p) {
                return std::unexpected(Error::truncated(std::format(
                    "macho: load command {} overruns command area", i)));
            }
            lcs.push_back({cmd_start + p, cmd, size});
            p += size;
        }
        if (p != limit) {
            return std::unexpected(Error::invalid_format(std::format(
                "macho: load commands consume {} of {} declared bytes", p, limit)));
        }
    }

    std::vector<SegInfo> seg_info;
    auto for_each_segment_section = [&](auto&& fn) {
        for (const auto& lc : lcs) {
            if (lc.cmd != LC_SEGMENT_64) continue;
            if (lc.size < SEGMENT_COMMAND_64_SIZE) continue;
            auto lcb = r.slice(lc.off, lc.size);
            if (!lcb) continue;
            const std::byte* const p = lcb->data();
            const u32 nsects = read_le_at<u32>(p + 64);
            for (u32 s = 0; s < nsects; ++s) {
                const std::size_t so = SEGMENT_COMMAND_64_SIZE +
                    static_cast<std::size_t>(s) * SECTION_64_SIZE;
                if (so + SECTION_64_SIZE > lc.size) break;
                fn(lc, p + so);
            }
        }
    };

    // ---- Pass 1: LC_SEGMENT_64 ---------------------------------------------
    for (const auto& lc : lcs) {
        if (lc.cmd != LC_SEGMENT_64) continue;
        if (lc.size < SEGMENT_COMMAND_64_SIZE) {
            return std::unexpected(Error::invalid_format(
                "macho: LC_SEGMENT_64 is smaller than its fixed header"));
        }
        auto lcb = r.slice(lc.off, lc.size);
        if (!lcb) return std::unexpected(std::move(lcb).error());
        const std::byte* const p = lcb->data();

        std::string segname = read_fixed_cstr(p + 8, 16);
        const u64 vmaddr   = read_le_at<u64>(p + 24);
        const u64 vmsize   = read_le_at<u64>(p + 32);
        const u64 fileoff  = read_le_at<u64>(p + 40);
        const u64 filesize = read_le_at<u64>(p + 48);
        const u32 initprot = read_le_at<u32>(p + 60);
        const u32 nsects   = read_le_at<u32>(p + 64);
        if (nsects > (lc.size - SEGMENT_COMMAND_64_SIZE) / SECTION_64_SIZE) {
            return std::unexpected(Error::invalid_format(std::format(
                "macho: segment {} declares {} sections outside its command",
                segname, nsects)));
        }
        if (vmsize > std::numeric_limits<u64>::max() - vmaddr) {
            return std::unexpected(Error::invalid_format(
                "macho: segment virtual range wraps"));
        }
        if (filesize > 0 && !r.slice(fileoff, filesize)) {
            return std::unexpected(Error::truncated(std::format(
                "macho: segment {} file range is outside the image", segname)));
        }

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
                auto bytes = r.slice(fileoff, filesize);
                if (!bytes) return std::unexpected(std::move(bytes).error());
                seg.data = *bytes;
            }
            segments_.push_back(std::move(seg));
        }

        // Parse sections contiguously after the segment_command_64 header.
        for (u32 s = 0; s < nsects; ++s) {
            const std::size_t so = SEGMENT_COMMAND_64_SIZE +
                static_cast<std::size_t>(s) * SECTION_64_SIZE;
            if (so + SECTION_64_SIZE > lc.size) break;
            const std::byte* const sp = p + so;
            const std::string sectname = read_fixed_cstr(sp + 0, 16);
            // const std::string segn_s   = read_fixed_cstr(sp + 16, 16);
            const u64 addr    = read_le_at<u64>(sp + 32);
            const u64 size    = read_le_at<u64>(sp + 40);
            const u32 offset  = read_le_at<u32>(sp + 48);
            const u32 flags   = read_le_at<u32>(sp + 64);
            const bool executable = section_has_instructions(sectname, flags, initprot);

            Section out;
            out.name = segname + "," + sectname;
            out.vaddr = static_cast<addr_t>(addr);
            out.file_offset = offset;
            out.size = size;
            out.flags.allocated  = true;
            out.flags.readable   = (initprot & VM_PROT_READ)    != 0;
            out.flags.writable   = (initprot & VM_PROT_WRITE)   != 0;
            out.flags.executable = executable;
            if (size > 0 && !section_is_zerofill(flags)) {
                auto data = r.slice(offset, size);
                if (!data) {
                    return std::unexpected(Error::truncated(std::format(
                        "macho: section {} initialized range is outside the image",
                        out.name)));
                }
                out.data = *data;
            }
            sections_.push_back(std::move(out));
        }
    }

    // ---- Pass 2: LC_SYMTAB / LC_DYSYMTAB / LC_DYLD_INFO_ONLY / LC_MAIN ------
    std::span<const std::byte> symtab_bytes;
    std::span<const std::byte> strtab_bytes;
    std::span<const std::byte> indirect_sym_bytes;
    u32 nsyms = 0;

    std::span<const std::byte> bind_bytes;
    std::span<const std::byte> lazy_bind_bytes;
    std::span<const std::byte> weak_bind_bytes;
    std::span<const std::byte> export_trie_bytes;
    std::span<const std::byte> chained_fixups_bytes;
    std::span<const std::byte> data_in_code_bytes;

    bool     have_entryoff = false;
    u64      entryoff      = 0;
    addr_t   unixthread_pc = 0;

    std::span<const std::byte> fn_starts_bytes;

    for (const auto& lc : lcs) {
        auto lcb = r.slice(lc.off, lc.size);
        if (!lcb) continue;
        const std::byte* const p = lcb->data();
        switch (lc.cmd) {
        case LC_SYMTAB: {
            if (lc.size < SYMTAB_COMMAND_SIZE) break;
            const u32 symoff  = read_le_at<u32>(p + 8);
            const u32 ns      = read_le_at<u32>(p + 12);
            const u32 stroff  = read_le_at<u32>(p + 16);
            const u32 strsize = read_le_at<u32>(p + 20);
            auto syms = r.slice(symoff, static_cast<std::size_t>(ns) * 16u);
            auto strs = r.slice(stroff, strsize);
            if (!syms || !strs) {
                return std::unexpected(Error::truncated(
                    "macho: LC_SYMTAB tables are outside the image"));
            }
            nsyms = ns;
            symtab_bytes = *syms;
            strtab_bytes = *strs;
            break;
        }
        case LC_DYSYMTAB: {
            if (lc.size < DYSYMTAB_COMMAND_SIZE) break;
            const u32 indirectsymoff = read_le_at<u32>(p + 56);
            const u32 nindirectsyms  = read_le_at<u32>(p + 60);
            if (nindirectsyms > 0) {
                if (auto s = r.slice(indirectsymoff,
                                     static_cast<std::size_t>(nindirectsyms) * 4); s) {
                    indirect_sym_bytes = *s;
                }
            }
            break;
        }
        case LC_DYLD_INFO:
        case LC_DYLD_INFO_ONLY: {
            if (lc.size < DYLD_INFO_COMMAND_SIZE) break;
            const u32 bind_off       = read_le_at<u32>(p + 16);
            const u32 bind_size      = read_le_at<u32>(p + 20);
            const u32 weak_bind_off  = read_le_at<u32>(p + 24);
            const u32 weak_bind_size = read_le_at<u32>(p + 28);
            const u32 lazy_bind_off  = read_le_at<u32>(p + 32);
            const u32 lazy_bind_size = read_le_at<u32>(p + 36);
            const u32 export_off     = read_le_at<u32>(p + 40);
            const u32 export_size    = read_le_at<u32>(p + 44);
            if (bind_size > 0) {
                if (auto s = r.slice(bind_off, bind_size); s) bind_bytes = *s;
            }
            if (lazy_bind_size > 0) {
                if (auto s = r.slice(lazy_bind_off, lazy_bind_size); s) lazy_bind_bytes = *s;
            }
            if (weak_bind_size > 0) {
                if (auto s = r.slice(weak_bind_off, weak_bind_size); s) weak_bind_bytes = *s;
            }
            if (export_size > 0) {
                if (auto s = r.slice(export_off, export_size); s) export_trie_bytes = *s;
            }
            break;
        }
        case LC_DYLD_EXPORTS_TRIE: {
            if (lc.size < LINKEDIT_DATA_COMMAND_SIZE) break;
            const u32 dataoff  = read_le_at<u32>(p + 8);
            const u32 datasize = read_le_at<u32>(p + 12);
            if (datasize > 0) {
                if (auto s = r.slice(dataoff, datasize); s) export_trie_bytes = *s;
            }
            break;
        }
        case LC_MAIN: {
            if (lc.size < ENTRY_POINT_COMMAND_SIZE) break;
            entryoff = read_le_at<u64>(p + 8);
            have_entryoff = true;
            break;
        }
        case LC_UNIXTHREAD: {
            if (unixthread_pc == 0) unixthread_pc = unixthread_entry(*lcb, arch_);
            break;
        }
        case LC_FUNCTION_STARTS: {
            if (lc.size < LINKEDIT_DATA_COMMAND_SIZE) break;
            // linkedit_data_command: cmd, cmdsize, dataoff, datasize
            const u32 dataoff  = read_le_at<u32>(p + 8);
            const u32 datasize = read_le_at<u32>(p + 12);
            if (datasize > 0) {
                if (auto s = r.slice(dataoff, datasize); s) fn_starts_bytes = *s;
            }
            break;
        }
        case LC_DYLD_CHAINED_FIXUPS: {
            if (lc.size < LINKEDIT_DATA_COMMAND_SIZE) break;
            const u32 dataoff  = read_le_at<u32>(p + 8);
            const u32 datasize = read_le_at<u32>(p + 12);
            if (datasize > 0) {
                if (auto s = r.slice(dataoff, datasize); s) chained_fixups_bytes = *s;
            }
            break;
        }
        case LC_DATA_IN_CODE: {
            if (lc.size < LINKEDIT_DATA_COMMAND_SIZE) break;
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
    // segment contains it. Real Mach-O encodes this as an offset from the
    // start of __TEXT; resolve_lc_main_entry keeps a file-offset fallback for
    // local synthetic fixtures.
    if (have_entryoff) {
        if (auto ep = resolve_lc_main_entry(entryoff, seg_info); ep) entry_ = *ep;
        else entry_ = static_cast<addr_t>(entryoff);
    }
    if (entry_ == 0 && unixthread_pc != 0) entry_ = unixthread_pc;

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
            const u8  n_sect = read_le_at<u8> (np + 5);
            const u64 n_value= read_le_at<u64>(np + 8);

            if (n_type & N_STAB) continue;  // debug stabs - ignore

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
                // n_sect is a 1-based index into the section table. Use it to
                // avoid treating named globals in __DATA / __const / __cstring
                // as functions; the emitter can then render loads from them by
                // symbol name.
                const std::size_t si = n_sect == 0 ? std::size_t(-1)
                    : static_cast<std::size_t>(n_sect - 1);
                const bool executable = si < sections_.size()
                    && sections_[si].flags.executable;
                sym.kind = executable ? SymbolKind::Function : SymbolKind::Object;
            }

            if (!name.empty() || sym.is_import) {
                sym_index_to_symbols[k] = symbols_.size();
                symbols_.push_back(std::move(sym));
            }
        }
    }

    // ---- Dyld export trie -------------------------------------------------
    // LC_DYLD_EXPORTS_TRIE / LC_DYLD_INFO.export_* names are authoritative
    // for what dyld exports, and modern stripped binaries may leave LC_SYMTAB
    // sparse. Add exported code/data names here so -s resolution and
    // --functions still see them.
    if (!export_trie_bytes.empty()) {
        std::vector<ExportRec> exports;
        parse_export_trie(export_trie_bytes, macho_image_base(seg_info), exports);
        for (auto& ex : exports) {
            if (ex.name.empty() || ex.vaddr == 0) continue;
            Symbol sym;
            sym.name = std::move(ex.name);
            sym.addr = ex.vaddr;
            sym.kind = executable_at(sections_, ex.vaddr)
                ? SymbolKind::Function
                : SymbolKind::Object;
            sym.is_export = true;
            symbols_.push_back(std::move(sym));
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
    // opcodes. Parse both - newer linkers occasionally emit both, older
    // ones only one.
    if (!chained_fixups_bytes.empty()) {
        parse_chained_fixups(chained_fixups_bytes, seg_info, buffer_, binds);
    }

    // Older or hand-linked Mach-O files can name lazy/non-lazy pointer slots
    // through LC_DYSYMTAB's indirect symbol table even when dyld bind opcodes
    // are sparse. Recover those slot -> import-name edges so the existing
    // __stubs scan can still render calls as `puts(...)` instead of
    // `sub_<stub>(...)`.
    if (!indirect_sym_bytes.empty() && !sym_index_to_symbols.empty()) {
        for_each_segment_section([&](const auto&, const std::byte* sp) {
            const u64 addr    = read_le_at<u64>(sp + 32);
            const u64 size    = read_le_at<u64>(sp + 40);
            const u32 flags   = read_le_at<u32>(sp + 64);
            const u32 first   = read_le_at<u32>(sp + 68);
            const u32 stype   = flags & SECTION_TYPE_MASK;
            if (stype != S_LAZY_SYMBOL_POINTERS &&
                stype != S_NON_LAZY_SYMBOL_POINTERS) {
                return;
            }
            const u64 count = size / 8u;
            for (u64 i = 0; i < count; ++i) {
                const u64 indirect_index = static_cast<u64>(first) + i;
                if ((indirect_index + 1u) * 4u > indirect_sym_bytes.size()) break;
                const u32 raw = read_le_at<u32>(
                    indirect_sym_bytes.data() + indirect_index * 4u);
                if ((raw & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) != 0) continue;
                if (raw >= sym_index_to_symbols.size()) continue;
                const std::size_t sym_idx = sym_index_to_symbols[raw];
                if (sym_idx == std::size_t(-1) || sym_idx >= symbols_.size()) continue;
                const auto& sym = symbols_[sym_idx];
                if (sym.name.empty()) continue;
                binds.push_back({static_cast<addr_t>(addr + i * 8u), sym.name});
            }
        });
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

    // Chained-fixups-only binaries can expose imports through bind records
    // without a useful undefined nlist row. Synthesize imports from those
    // records so GOT/stub lookup still has a Symbol to return.
    for (const auto& [addr, name] : slot_to_name) {
        if (name.empty()) continue;
        bool have_slot = false;
        for (const auto& sym : symbols_) {
            if (sym.is_import && sym.name == name && sym.got_addr == addr) {
                have_slot = true;
                break;
            }
        }
        if (have_slot) continue;
        Symbol sym;
        sym.name = name;
        sym.kind = SymbolKind::Function;
        sym.is_import = true;
        sym.got_addr = addr;
        import_by_name.emplace(sym.name, symbols_.size());
        symbols_.push_back(std::move(sym));
    }

    // Attach got_addr to imports by name - the bind opcodes give us the
    // slot (la_symbol_ptr / got) addresses, which are what the emitter uses
    // to render indirect calls through the GOT as named calls.
    for (auto& sym : symbols_) {
        if (!sym.is_import || sym.got_addr != 0) continue;
        for (const auto& [addr, name] : slot_to_name) {
            if (name == sym.name) { sym.got_addr = addr; break; }
        }
    }

    // ---- arm64 stubs: ADRP Xt; LDR Xt, [Xt,#imm]; BR Xt -----------------
    if (arch_ == Arch::Arm64 && !slot_to_name.empty()) {
        std::unordered_map<std::string, addr_t> import_stub_addr;

        for_each_segment_section([&](const auto&, const std::byte* sp) {
            const u64 addr    = read_le_at<u64>(sp + 32);
            const u64 size    = read_le_at<u64>(sp + 40);
            const u32 offset  = read_le_at<u32>(sp + 48);
            const u32 flags   = read_le_at<u32>(sp + 64);
            const u32 stype   = flags & SECTION_TYPE_MASK;
            if (stype != S_SYMBOL_STUBS) return;
            if (offset == 0 || size < 12) return;
            auto data = r.slice(offset, size);
            if (!data) return;

            for (std::size_t off = 0; off + 12 <= data->size(); off += 4) {
                const addr_t ip = static_cast<addr_t>(addr + off);
                auto slot = decode_arm64_stub_slot(*data, off, ip);
                if (!slot) continue;
                auto it = slot_to_name.find(*slot);
                if (it != slot_to_name.end()) {
                    import_stub_addr.try_emplace(it->second, ip);
                }
            }
        });

        for (auto& sym : symbols_) {
            if (!sym.is_import || sym.addr != 0) continue;
            auto it = import_stub_addr.find(sym.name);
            if (it == import_stub_addr.end()) continue;
            sym.addr = it->second;
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

        for_each_segment_section([&](const auto&, const std::byte* sp) {
            const u64 addr    = read_le_at<u64>(sp + 32);
            const u64 size    = read_le_at<u64>(sp + 40);
            const u32 offset  = read_le_at<u32>(sp + 48);
            const u32 flags   = read_le_at<u32>(sp + 64);
            const u32 stype   = flags & SECTION_TYPE_MASK;
            if (stype != S_SYMBOL_STUBS) return;
            if (offset == 0 || size == 0) return;
            auto data = r.slice(offset, size);
            if (!data) return;

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
        });

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
    // internal names - but LC_FUNCTION_STARTS is almost always present and
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
        const Section* classlist = find_section_suffix(sections_, "__objc_classlist");
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
                const bool relative = (entsize & OBJC_RELATIVE_METHOD_LIST_FLAG) != 0;
                const bool preopt_sel = (entsize & OBJC_PREOPT_SEL_FLAG) != 0;
                const u32 real_entsize = relative ? (entsize & 0x3FFFFFFFu)
                                                  : (entsize & 0xFFFCu);
                if ((!relative && real_entsize != 24) ||
                    ( relative && real_entsize < 12)) return;
                if (count > 100000) return;  // sanity

                const char prefix = meta ? '+' : '-';
                for (u32 m = 0; m < count; ++m) {
                    const addr_t base = methods_ptr + 8 +
                                        static_cast<addr_t>(m) * real_entsize;
                    addr_t sel_ptr = 0;
                    addr_t imp = 0;
                    if (relative) {
                        const i32 sel_delta = read_i32_at(segments_, base + 0);
                        const i32 imp_delta = read_i32_at(segments_, base + 8);
                        const addr_t sel_or_ref = static_cast<addr_t>(
                            static_cast<i64>(base + 0) + static_cast<i64>(sel_delta));
                        sel_ptr = preopt_sel
                            ? static_cast<addr_t>(read_u64_at(segments_, sel_or_ref))
                            : sel_or_ref;
                        imp = static_cast<addr_t>(
                            static_cast<i64>(base + 8) + static_cast<i64>(imp_delta));
                    } else {
                        sel_ptr = static_cast<addr_t>(read_u64_at(segments_, base + 0));
                        imp     = static_cast<addr_t>(read_u64_at(segments_, base + 16));
                    }
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
                // bit of data is a realized flag - mask it off.
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

    // ---- Swift nominal type descriptors ---------------------------------
    // __swift5_types contains i32 relative pointers to nominal type
    // descriptors. For class/struct/enum descriptors, TargetTypeContext-
    // Descriptor places a relative direct pointer to the type name at +8.
    // Naming the descriptor gives address/name resolution a foothold in
    // stripped Swift binaries without needing full Swift demangling.
    if (const Section* swift_types = find_section_suffix(sections_, "__swift5_types");
        swift_types && swift_types->size >= 4) {
        const std::size_t n = swift_types->size / 4;
        for (std::size_t i = 0; i < n; ++i) {
            const addr_t entry_va = swift_types->vaddr + static_cast<addr_t>(i) * 4u;
            const i32 desc_delta = read_i32_at(segments_, entry_va);
            const addr_t desc_va = static_cast<addr_t>(
                static_cast<i64>(entry_va) + static_cast<i64>(desc_delta));
            if (desc_va == 0) continue;

            const u32 flags = read_u32_at(segments_, desc_va + 0);
            const u32 kind = flags & 0x1Fu;
            if (kind != 16u && kind != 17u && kind != 18u) continue;

            const i32 name_delta = read_i32_at(segments_, desc_va + 8);
            const addr_t name_va = static_cast<addr_t>(
                static_cast<i64>(desc_va + 8) + static_cast<i64>(name_delta));
            std::string type_name = read_cstring_at(segments_, name_va);
            if (type_name.empty()) continue;

            Symbol s;
            s.name = swift_symbol_name(type_name);
            s.addr = desc_va;
            s.kind = SymbolKind::Object;
            symbols_.push_back(std::move(s));

            const i32 access_delta = read_i32_at(segments_, desc_va + 12);
            if (access_delta != 0) {
                const addr_t access_va = static_cast<addr_t>(
                    static_cast<i64>(desc_va + 12) +
                    static_cast<i64>(access_delta));
                if (!bytes_at(access_va).empty()) {
                    const bool already_named = std::ranges::any_of(symbols_,
                        [&](const Symbol& existing) {
                            return !existing.is_import &&
                                   existing.kind == SymbolKind::Function &&
                                   existing.addr == access_va;
                        });
                    if (!already_named) {
                        Symbol access;
                        access.name = swift_accessor_symbol_name(type_name);
                        access.addr = access_va;
                        access.kind = SymbolKind::Function;
                        symbols_.push_back(std::move(access));
                    }
                }
            }

            const i32 fields_delta = read_i32_at(segments_, desc_va + 16);
            if (fields_delta == 0) continue;
            const addr_t fields_va = static_cast<addr_t>(
                static_cast<i64>(desc_va + 16) + static_cast<i64>(fields_delta));
            const u16 record_size = read_u16_at(segments_, fields_va + 10);
            const u32 field_count = read_u32_at(segments_, fields_va + 12);
            if (record_size < 12 || field_count > 10000) continue;

            for (u32 f = 0; f < field_count; ++f) {
                const addr_t record_va = fields_va + 16 +
                    static_cast<addr_t>(f) * record_size;
                const i32 field_name_delta = read_i32_at(segments_, record_va + 8);
                if (field_name_delta == 0) continue;
                const addr_t field_name_va = static_cast<addr_t>(
                    static_cast<i64>(record_va + 8) +
                    static_cast<i64>(field_name_delta));
                std::string field_name = read_cstring_at(segments_, field_name_va);
                if (field_name.empty()) continue;

                Symbol field;
                field.name = swift_field_symbol_name(type_name, field_name);
                field.addr = field_name_va;
                field.kind = SymbolKind::Object;
                symbols_.push_back(std::move(field));
            }
        }
    }

    // Sort + dedupe, mirroring ELF.
    std::ranges::sort(symbols_, [](const Symbol& a, const Symbol& b) noexcept {
        if (a.is_import != b.is_import) return a.is_import < b.is_import;
        if (a.addr      != b.addr)      return a.addr < b.addr;
        if (a.got_addr  != b.got_addr)  return a.got_addr < b.got_addr;
        if (a.name      != b.name)      return a.name < b.name;
        return a.size < b.size;
    });
    auto dups = std::ranges::unique(symbols_,
        [](const Symbol& a, const Symbol& b) noexcept {
            return a.addr == b.addr
                && a.size == b.size
                && a.got_addr == b.got_addr
                && a.is_import == b.is_import
                && a.name == b.name;
        });
    symbols_.erase(dups.begin(), dups.end());
    return {};
}

}  // namespace ember
