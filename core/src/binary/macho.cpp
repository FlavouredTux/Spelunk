#include <ember/binary/macho.hpp>

#include <algorithm>
#include <cstddef>
#include <expected>
#include <format>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <ember/binary/arch.hpp>
#include <ember/binary/elf.hpp>
#include <ember/binary/section.hpp>
#include <ember/binary/symbol.hpp>
#include <ember/common/bytes.hpp>
#include <ember/common/error.hpp>
#include <ember/common/types.hpp>
#include <ember/disasm/instruction.hpp>
#include <ember/disasm/register.hpp>
#include <ember/disasm/x64_decoder.hpp>

#include "macho_internal.hpp"

namespace ember {

namespace {

using macho::BindRec;
using macho::ExportRec;
using macho::SegInfo;
using macho::macho_image_base;
using macho::parse_bind_stream;
using macho::parse_chained_fixups;
using macho::parse_export_trie;
using macho::read_uleb128;

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

// nlist n_type flags.
constexpr u8 N_STAB = 0xE0u;
constexpr u8 N_TYPE = 0x0Eu;
constexpr u8 N_EXT  = 0x01u;
constexpr u8 N_UNDF = 0x00u;
constexpr u8 N_SECT = 0x0Eu;

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

[[nodiscard]] i64 sign_extend_u64(u64 v, unsigned width) noexcept {
    const u64 sign = u64{1} << (width - 1);
    return static_cast<i64>((v ^ sign) - sign);
}

[[nodiscard]] bool executable_at(std::span<const Section> sections,
                                 addr_t va) noexcept {
    for (const auto& s : sections) {
        if (!s.flags.executable) continue;
        if (va >= s.vaddr && va < s.vaddr + s.size) return true;
    }
    return false;
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

// Strip a leading underscore used by Mach-O's C-ABI name mangling so that
// e.g. `_malloc` matches the libc arity table as `malloc`.
[[nodiscard]] std::string demangle_macho(std::string_view n) {
    if (!n.empty() && n.front() == '_') return std::string(n.substr(1));
    return std::string(n);
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

}  // namespace

Result<std::unique_ptr<MachOBinary>>
MachOBinary::load_from_buffer(std::vector<std::byte> buffer) {
    std::unique_ptr<MachOBinary> self(new MachOBinary(std::move(buffer)));
    if (auto rv = self->parse(); !rv) {
        return std::unexpected(std::move(rv).error());
    }
    return self;
}

struct MachOBinary::ParseState {
    struct LoadCommand { std::size_t off; u32 cmd; u32 size; };

    ByteReader r;
    std::vector<LoadCommand> lcs;
    std::vector<SegInfo>     seg_info;

    // __LINKEDIT slices located by the second load-command pass.
    std::span<const std::byte> symtab_bytes;
    std::span<const std::byte> strtab_bytes;
    std::span<const std::byte> indirect_sym_bytes;
    u32                        nsyms = 0;
    std::span<const std::byte> bind_bytes;
    std::span<const std::byte> lazy_bind_bytes;
    std::span<const std::byte> weak_bind_bytes;
    std::span<const std::byte> export_trie_bytes;
    std::span<const std::byte> chained_fixups_bytes;
    std::span<const std::byte> data_in_code_bytes;
    std::span<const std::byte> fn_starts_bytes;
    bool   have_entryoff = false;
    u64    entryoff      = 0;
    addr_t unixthread_pc = 0;

    // nlist index -> symbols_ index, for the indirect symbol table.
    std::vector<std::size_t>                sym_index_to_symbols;
    std::vector<BindRec>                    binds;
    std::unordered_map<addr_t, std::string> slot_to_name;

    explicit ParseState(std::span<const std::byte> image) noexcept : r(image) {}

    // Visit every section_64 header of every LC_SEGMENT_64.
    template <class Fn>
    void for_each_section(Fn&& fn) const {
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
    }
};

Result<void> MachOBinary::parse() {
    ParseState st(buffer_);
    if (auto res = read_load_commands(st); !res) return res;
    if (auto res = parse_segments(st); !res) return res;
    if (auto res = read_linkedit_commands(st); !res) return res;
    parse_nlist_symbols(st);
    add_exported_symbols(st);
    collect_bind_records(st);
    parse_data_in_code(st);
    attach_import_slots(st);
    resolve_import_stubs(st);
    strip_c_symbol_prefix();
    synthesize_entry_symbol();
    apply_function_starts(st);
    scan_objc_methods();
    scan_swift_types();
    finalize_symbols();
    return {};
}

// Validate mach_header_64 and index the variable-length load commands.
Result<void> MachOBinary::read_load_commands(ParseState& st) {
    if (st.r.size() < 32) {
        return std::unexpected(Error::truncated(std::format(
            "macho: file smaller than mach_header_64 ({} < 32)", st.r.size())));
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
    auto cmds_bytes = st.r.slice(cmd_start, sizeofcmds);
    if (!cmds_bytes) return std::unexpected(std::move(cmds_bytes).error());
    if (ncmds > sizeofcmds / 8u) {
        return std::unexpected(Error::invalid_format(std::format(
            "macho: {} load commands cannot fit in {} bytes", ncmds, sizeofcmds)));
    }

    st.lcs.reserve(ncmds);
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
            st.lcs.push_back({cmd_start + p, cmd, size});
            p += size;
        }
        if (p != limit) {
            return std::unexpected(Error::invalid_format(std::format(
                "macho: load commands consume {} of {} declared bytes", p, limit)));
        }
    }
    return {};
}

// LC_SEGMENT_64: segment map, mapped data, and the section table.
Result<void> MachOBinary::parse_segments(ParseState& st) {
    for (const auto& lc : st.lcs) {
        if (lc.cmd != LC_SEGMENT_64) continue;
        if (lc.size < SEGMENT_COMMAND_64_SIZE) {
            return std::unexpected(Error::invalid_format(
                "macho: LC_SEGMENT_64 is smaller than its fixed header"));
        }
        auto lcb = st.r.slice(lc.off, lc.size);
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
        if (filesize > 0 && !st.r.slice(fileoff, filesize)) {
            return std::unexpected(Error::truncated(std::format(
                "macho: segment {} file range is outside the image", segname)));
        }

        st.seg_info.push_back({static_cast<addr_t>(vmaddr), vmsize, fileoff, filesize, segname});

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
                auto bytes = st.r.slice(fileoff, filesize);
                if (!bytes) return std::unexpected(std::move(bytes).error());
                seg.data = *bytes;
            }
            segments_.push_back(seg);
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
                auto data = st.r.slice(offset, size);
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
    return {};
}

// LC_SYMTAB / LC_DYSYMTAB / LC_DYLD_INFO / LC_MAIN and the other
// __LINKEDIT commands, then the entry point they imply.
Result<void> MachOBinary::read_linkedit_commands(ParseState& st) {
    for (const auto& lc : st.lcs) {
        auto lcb = st.r.slice(lc.off, lc.size);
        if (!lcb) continue;
        const std::byte* const p = lcb->data();
        switch (lc.cmd) {
        case LC_SYMTAB: {
            if (lc.size < SYMTAB_COMMAND_SIZE) break;
            const u32 symoff  = read_le_at<u32>(p + 8);
            const u32 ns      = read_le_at<u32>(p + 12);
            const u32 stroff  = read_le_at<u32>(p + 16);
            const u32 strsize = read_le_at<u32>(p + 20);
            auto syms = st.r.slice(symoff, static_cast<std::size_t>(ns) * 16u);
            auto strs = st.r.slice(stroff, strsize);
            if (!syms || !strs) {
                return std::unexpected(Error::truncated(
                    "macho: LC_SYMTAB tables are outside the image"));
            }
            st.nsyms = ns;
            st.symtab_bytes = *syms;
            st.strtab_bytes = *strs;
            break;
        }
        case LC_DYSYMTAB: {
            if (lc.size < DYSYMTAB_COMMAND_SIZE) break;
            const u32 indirectsymoff = read_le_at<u32>(p + 56);
            const u32 nindirectsyms  = read_le_at<u32>(p + 60);
            if (nindirectsyms > 0) {
                if (auto s = st.r.slice(indirectsymoff,
                                     static_cast<std::size_t>(nindirectsyms) * 4); s) {
                    st.indirect_sym_bytes = *s;
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
                if (auto s = st.r.slice(bind_off, bind_size); s) st.bind_bytes = *s;
            }
            if (lazy_bind_size > 0) {
                if (auto s = st.r.slice(lazy_bind_off, lazy_bind_size); s) st.lazy_bind_bytes = *s;
            }
            if (weak_bind_size > 0) {
                if (auto s = st.r.slice(weak_bind_off, weak_bind_size); s) st.weak_bind_bytes = *s;
            }
            if (export_size > 0) {
                if (auto s = st.r.slice(export_off, export_size); s) st.export_trie_bytes = *s;
            }
            break;
        }
        case LC_DYLD_EXPORTS_TRIE: {
            if (lc.size < LINKEDIT_DATA_COMMAND_SIZE) break;
            const u32 dataoff  = read_le_at<u32>(p + 8);
            const u32 datasize = read_le_at<u32>(p + 12);
            if (datasize > 0) {
                if (auto s = st.r.slice(dataoff, datasize); s) st.export_trie_bytes = *s;
            }
            break;
        }
        case LC_MAIN: {
            if (lc.size < ENTRY_POINT_COMMAND_SIZE) break;
            st.entryoff = read_le_at<u64>(p + 8);
            st.have_entryoff = true;
            break;
        }
        case LC_UNIXTHREAD: {
            if (st.unixthread_pc == 0) st.unixthread_pc = unixthread_entry(*lcb, arch_);
            break;
        }
        case LC_FUNCTION_STARTS: {
            if (lc.size < LINKEDIT_DATA_COMMAND_SIZE) break;
            // linkedit_data_command: cmd, cmdsize, dataoff, datasize
            const u32 dataoff  = read_le_at<u32>(p + 8);
            const u32 datasize = read_le_at<u32>(p + 12);
            if (datasize > 0) {
                if (auto s = st.r.slice(dataoff, datasize); s) st.fn_starts_bytes = *s;
            }
            break;
        }
        case LC_DYLD_CHAINED_FIXUPS: {
            if (lc.size < LINKEDIT_DATA_COMMAND_SIZE) break;
            const u32 dataoff  = read_le_at<u32>(p + 8);
            const u32 datasize = read_le_at<u32>(p + 12);
            if (datasize > 0) {
                if (auto s = st.r.slice(dataoff, datasize); s) st.chained_fixups_bytes = *s;
            }
            break;
        }
        case LC_DATA_IN_CODE: {
            if (lc.size < LINKEDIT_DATA_COMMAND_SIZE) break;
            const u32 dataoff  = read_le_at<u32>(p + 8);
            const u32 datasize = read_le_at<u32>(p + 12);
            if (datasize > 0) {
                if (auto s = st.r.slice(dataoff, datasize); s) st.data_in_code_bytes = *s;
            }
            break;
        }
        default: break;
        }
    }

    // Resolve LC_MAIN's file-offset st.entryoff to a VM address by finding which
    // segment contains it. Real Mach-O encodes this as an offset from the
    // start of __TEXT; resolve_lc_main_entry keeps a file-offset fallback for
    // local synthetic fixtures.
    if (st.have_entryoff) {
        if (auto ep = resolve_lc_main_entry(st.entryoff, st.seg_info); ep) entry_ = *ep;
        else entry_ = static_cast<addr_t>(st.entryoff);
    }
    if (entry_ == 0 && st.unixthread_pc != 0) entry_ = st.unixthread_pc;
    return {};
}

// ---- Parse the nlist symbol table -------------------------------------
// Imports are nlist entries with N_TYPE == N_UNDF; their name is in the
// string table; we'll later point Symbol.addr at a __stubs slot via the
// indirect symbol table, and Symbol.got_addr at the filled-in pointer slot.
void MachOBinary::parse_nlist_symbols(ParseState& st) {
    st.sym_index_to_symbols.assign(st.nsyms, std::size_t(-1));

    if (!st.symtab_bytes.empty() && !st.strtab_bytes.empty()) {
        const ByteReader str(st.strtab_bytes);
        for (u32 k = 0; k < st.nsyms; ++k) {
            const std::byte* const np = st.symtab_bytes.data() + static_cast<std::size_t>(k) * 16;
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
                st.sym_index_to_symbols[k] = symbols_.size();
                symbols_.push_back(std::move(sym));
            }
        }
    }
}

// ---- Dyld export trie -------------------------------------------------
// LC_DYLD_EXPORTS_TRIE / LC_DYLD_INFO.export_* names are authoritative
// for what dyld exports, and modern stripped binaries may leave LC_SYMTAB
// sparse. Add exported code/data names here so -s resolution and
// --functions still see them.
void MachOBinary::add_exported_symbols(const ParseState& st) {
    if (!st.export_trie_bytes.empty()) {
        std::vector<ExportRec> exports;
        parse_export_trie(st.export_trie_bytes, macho_image_base(st.seg_info), exports);
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
}

// ---- Parse bind/lazy_bind/weak_bind opcodes ---------------------------
// Builds slot_vaddr → name for every imported data/func pointer. The
// lazy_bind stream covers __la_symbol_ptr slots (which are what __stubs
// indirect through), so scanning it is essential for named calls to work.
void MachOBinary::collect_bind_records(ParseState& st) {
    st.binds.reserve(256);
    if (!st.bind_bytes.empty())      parse_bind_stream(st.bind_bytes,      st.seg_info, st.binds, false);
    if (!st.weak_bind_bytes.empty()) parse_bind_stream(st.weak_bind_bytes, st.seg_info, st.binds, false);
    if (!st.lazy_bind_bytes.empty()) parse_bind_stream(st.lazy_bind_bytes, st.seg_info, st.binds, true);
    // Modern builds emit LC_DYLD_CHAINED_FIXUPS instead of LC_DYLD_INFO
    // opcodes. Parse both - newer linkers occasionally emit both, older
    // ones only one.
    if (!st.chained_fixups_bytes.empty()) {
        parse_chained_fixups(st.chained_fixups_bytes, st.seg_info, buffer_, st.binds);
    }

    // Older or hand-linked Mach-O files can name lazy/non-lazy pointer slots
    // through LC_DYSYMTAB's indirect symbol table even when dyld bind opcodes
    // are sparse. Recover those slot -> import-name edges so the existing
    // __stubs scan can still render calls as `puts(...)` instead of
    // `sub_<stub>(...)`.
    if (!st.indirect_sym_bytes.empty() && !st.sym_index_to_symbols.empty()) {
        st.for_each_section([&](const auto&, const std::byte* sp) {
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
                if ((indirect_index + 1u) * 4u > st.indirect_sym_bytes.size()) break;
                const u32 raw = read_le_at<u32>(
                    st.indirect_sym_bytes.data() + indirect_index * 4u);
                if ((raw & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) != 0) continue;
                if (raw >= st.sym_index_to_symbols.size()) continue;
                const std::size_t sym_idx = st.sym_index_to_symbols[raw];
                if (sym_idx == std::size_t(-1) || sym_idx >= symbols_.size()) continue;
                const auto& sym = symbols_[sym_idx];
                if (sym.name.empty()) continue;
                st.binds.push_back({static_cast<addr_t>(addr + i * 8u), sym.name});
            }
        });
    }

    st.slot_to_name.reserve(st.binds.size());
    for (auto& b : st.binds) st.slot_to_name.emplace(b.vaddr, std::move(b.name));
}

// LC_DATA_IN_CODE: list of (file_offset, length, kind) marking embedded
// data inside __TEXT. Convert each file offset into a VA using the
// segment map so the CFG walker can steer around them.
void MachOBinary::parse_data_in_code(const ParseState& st) {
    if (!st.data_in_code_bytes.empty()) {
        const std::size_t n = st.data_in_code_bytes.size() / 8;
        data_in_code_.reserve(n);
        for (std::size_t i = 0; i < n; ++i) {
            const std::byte* e = st.data_in_code_bytes.data() + i * 8;
            const u32 foff   = read_le_at<u32>(e + 0);
            const u16 len    = read_le_at<u16>(e + 4);
            const u16 kind   = read_le_at<u16>(e + 6);
            // Resolve file offset to vaddr via the segment map.
            addr_t va = 0;
            for (const auto& s : st.seg_info) {
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
}

// Synthesize imports that only bind records name, then give every
// import its GOT / lazy-pointer slot.
void MachOBinary::attach_import_slots(const ParseState& st) {
    for (const auto& [addr, name] : st.slot_to_name) {
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
        symbols_.push_back(std::move(sym));
    }

    // Attach got_addr to imports by name - the bind opcodes give us the
    // slot (la_symbol_ptr / got) addresses, which are what the emitter uses
    // to render indirect calls through the GOT as named calls.
    for (auto& sym : symbols_) {
        if (!sym.is_import || sym.got_addr != 0) continue;
        for (const auto& [addr, name] : st.slot_to_name) {
            if (name == sym.name) { sym.got_addr = addr; break; }
        }
    }
}

// Point each import's addr at its __stubs trampoline: ADRP/LDR/BR on
// arm64, `jmp qword [rip + D]` on x86-64 (mirroring the ELF PLT scan).
void MachOBinary::resolve_import_stubs(const ParseState& st) {
    if (arch_ == Arch::Arm64 && !st.slot_to_name.empty()) {
        std::unordered_map<std::string, addr_t> import_stub_addr;

        st.for_each_section([&](const auto&, const std::byte* sp) {
            const u64 addr    = read_le_at<u64>(sp + 32);
            const u64 size    = read_le_at<u64>(sp + 40);
            const u32 offset  = read_le_at<u32>(sp + 48);
            const u32 flags   = read_le_at<u32>(sp + 64);
            const u32 stype   = flags & SECTION_TYPE_MASK;
            if (stype != S_SYMBOL_STUBS) return;
            if (offset == 0 || size < 12) return;
            auto data = st.r.slice(offset, size);
            if (!data) return;

            for (std::size_t off = 0; off + 12 <= data->size(); off += 4) {
                const addr_t ip = static_cast<addr_t>(addr + off);
                auto slot = decode_arm64_stub_slot(*data, off, ip);
                if (!slot) continue;
                auto it = st.slot_to_name.find(*slot);
                if (it != st.slot_to_name.end()) {
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
    // is the __la_symbol_ptr slot; st.slot_to_name gives us the import.
    if (arch_ == Arch::X86_64 && !st.slot_to_name.empty()) {
        // Find __stubs sections by walking the segment/section tables once more.
        // We've stored sections in sections_ already but without flags, so redo
        // the walk to check SECTION_TYPE.
        std::unordered_map<std::string, addr_t> import_stub_addr;
        const X64Decoder dec;

        st.for_each_section([&](const auto&, const std::byte* sp) {
            const u64 addr    = read_le_at<u64>(sp + 32);
            const u64 size    = read_le_at<u64>(sp + 40);
            const u32 offset  = read_le_at<u32>(sp + 48);
            const u32 flags   = read_le_at<u32>(sp + 64);
            const u32 stype   = flags & SECTION_TYPE_MASK;
            if (stype != S_SYMBOL_STUBS) return;
            if (offset == 0 || size == 0) return;
            auto data = st.r.slice(offset, size);
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
                        auto it = st.slot_to_name.find(slot);
                        if (it != st.slot_to_name.end()) {
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
}

// Strip the leading `_` that Mach-O prepends to C symbols, so that
// `strlen` (and everything the emitter's name-based logic keys on)
// matches without the caller having to know about it.
void MachOBinary::strip_c_symbol_prefix() {
    for (auto& sym : symbols_) {
        if (!sym.name.empty() && sym.name.front() == '_') {
            sym.name = demangle_macho(sym.name);
        }
    }
}

// Synthesize `main` at the LC_MAIN entry *before* LC_FUNCTION_STARTS runs,
// so that pass leaves the entry address to the conventional name instead
// of stamping `sub_<hex>` on top.
void MachOBinary::synthesize_entry_symbol() {
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
}

// ---- LC_FUNCTION_STARTS: full function-boundary map -------------------
// Mach-O rarely carries nlist sizes, and release binaries drop most
// internal names - but LC_FUNCTION_STARTS is almost always present and
// lists every function's starting address as a ULEB128 delta stream.
// Decoding it lets us: (a) fill in `size` on every existing function
// symbol (next_start - this_start), and (b) add synthetic `sub_<hex>`
// entries for the rest so the CFG builder, arity inference, call graph,
// and UI sidebar all see the complete function set.
void MachOBinary::apply_function_starts(const ParseState& st) {
    if (!st.fn_starts_bytes.empty()) {
        addr_t text_base = 0;
        u64    text_end  = 0;
        for (const auto& s : st.seg_info) {
            if (s.name == "__TEXT") {
                text_base = s.vmaddr;
                text_end  = s.vmaddr + s.vmsize;
                break;
            }
        }
        if (text_base != 0) {
            std::vector<addr_t> starts;
            const std::byte* bp = st.fn_starts_bytes.data();
            const std::byte* be = bp + st.fn_starts_bytes.size();
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
}

// Sort + dedupe, mirroring ELF.
void MachOBinary::finalize_symbols() {
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
}

}  // namespace ember
