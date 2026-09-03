#include <ember/binary/elf.hpp>

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstring>
#include <expected>
#include <format>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <ember/binary/arch.hpp>
#include <ember/binary/relocation.hpp>
#include <ember/binary/section.hpp>
#include <ember/binary/symbol.hpp>
#include <ember/common/bytes.hpp>
#include <ember/common/error.hpp>
#include <ember/common/types.hpp>
#include <ember/disasm/instruction.hpp>
#include <ember/disasm/register.hpp>
#include <ember/disasm/x64_decoder.hpp>

#include "elf_internal.hpp"

namespace ember {

namespace {

constexpr std::size_t kEhdr64Size = 64;
constexpr std::size_t kEhdr32Size = 52;
constexpr std::size_t kShdr64Size = 64;
constexpr std::size_t kShdr32Size = 40;
constexpr std::size_t kSym32Size  = 16;
constexpr std::size_t kRela32Size = 12;
constexpr std::size_t kRel32Size  = 8;

using elf::kPhdr32Size;
using elf::kPhdr64Size;
using elf::kRela64Size;
using elf::kSym64Size;
using elf::read_at;
using elf::symbol_kind_from_info;

namespace pt = elf::pt;
namespace rx64 = elf::rx64;

namespace et {
constexpr u16 REL = 1;
}  // namespace et

namespace pf {
constexpr u32 X = 0x1;
constexpr u32 W = 0x2;
constexpr u32 R = 0x4;
}  // namespace pf

namespace ei {
constexpr std::size_t MAG0     = 0;
constexpr std::size_t CLASS    = 4;
constexpr std::size_t DATA     = 5;

constexpr u8 CLASS_64 = 2;
constexpr u8 CLASS_32 = 1;
constexpr u8 DATA_LSB = 1;
constexpr u8 DATA_MSB = 2;
}  // namespace ei

namespace em {
constexpr u16 I386    = 3;
constexpr u16 MIPS    = 8;
constexpr u16 PPC     = 20;
constexpr u16 PPC64   = 21;
constexpr u16 ARM     = 40;
constexpr u16 X86_64  = 62;
constexpr u16 AARCH64 = 183;
constexpr u16 RISCV   = 243;
}  // namespace em

namespace sht {
constexpr u32 NOBITS = 8;
constexpr u32 SYMTAB = 2;
constexpr u32 STRTAB = 3;
constexpr u32 DYNSYM = 11;
constexpr u32 RELA   = 4;
constexpr u32 REL    = 9;
}  // namespace sht

// ELF32 PowerPC relocation numbers from the PowerPC System V ABI/EABI.
namespace rppc {
constexpr u32 ADDR32 = 1;
constexpr u32 ADDR24 = 2;
constexpr u32 ADDR16 = 3;
constexpr u32 ADDR16_LO = 4;
constexpr u32 ADDR16_HI = 5;
constexpr u32 ADDR16_HA = 6;
constexpr u32 REL24 = 10;
constexpr u32 REL14 = 11;
constexpr u32 REL14_BRTAKEN = 12;
constexpr u32 REL14_BRNTAKEN = 13;
}  // namespace rppc

// R_*_RELATIVE values vary across architectures. Used by
// ElfBinary::relocated_qwords() to recognise dynamic-linker-patched
// pointers (.data.rel.ro slots that the static qword-value scan
// misses because their on-disk value is zero / sentinel).
[[nodiscard]] u32 relative_reloc_type_for(Arch a) noexcept {
    switch (a) {
        case Arch::X86_64:  return 8;
        case Arch::Arm64:   return 1027;
        case Arch::Ppc64:   return 22;
        default:            return 0;  // not modelled; relocated_qwords returns empty
    }
}

namespace shf {
constexpr u64 WRITE     = 0x1;
constexpr u64 ALLOC     = 0x2;
constexpr u64 EXECINSTR = 0x4;
}  // namespace shf

struct Shdr {
    u32 name;
    u32 type;
    u64 flags;
    u64 addr;
    u64 offset;
    u64 size;
    u32 link;
    u32 info;
    u64 addralign;
    u64 entsize;
};

[[nodiscard]] Shdr read_shdr(Endian endian, const std::byte* p,
                             bool is_64bit) noexcept {
    if (!is_64bit) {
        return {
            read_at<u32>(endian, p + 0x00),
            read_at<u32>(endian, p + 0x04),
            read_at<u32>(endian, p + 0x08),
            read_at<u32>(endian, p + 0x0c),
            read_at<u32>(endian, p + 0x10),
            read_at<u32>(endian, p + 0x14),
            read_at<u32>(endian, p + 0x18),
            read_at<u32>(endian, p + 0x1c),
            read_at<u32>(endian, p + 0x20),
            read_at<u32>(endian, p + 0x24),
        };
    }
    return {
        read_at<u32>(endian, p + 0x00),
        read_at<u32>(endian, p + 0x04),
        read_at<u64>(endian, p + 0x08),
        read_at<u64>(endian, p + 0x10),
        read_at<u64>(endian, p + 0x18),
        read_at<u64>(endian, p + 0x20),
        read_at<u32>(endian, p + 0x28),
        read_at<u32>(endian, p + 0x2c),
        read_at<u64>(endian, p + 0x30),
        read_at<u64>(endian, p + 0x38),
    };
}

[[nodiscard]] Shdr shdr_at(Endian endian, const std::byte* shtab, u16 idx,
                          bool is_64bit) noexcept {
    const std::size_t size = is_64bit ? kShdr64Size : kShdr32Size;
    return read_shdr(endian, shtab + static_cast<std::size_t>(idx) * size,
                     is_64bit);
}

[[nodiscard]] addr_t align_up(addr_t value, addr_t alignment) noexcept {
    if (alignment <= 1) return value;
    const addr_t remainder = value % alignment;
    return remainder == 0 ? value : value + (alignment - remainder);
}

template <typename T>
void write_at(Endian endian, std::byte* p, T value) noexcept {
    if constexpr (sizeof(T) > 1) {
        if ((endian == Endian::Big && std::endian::native == std::endian::little) ||
            (endian == Endian::Little && std::endian::native == std::endian::big)) {
            value = std::byteswap(value);
        }
    }
    std::memcpy(p, &value, sizeof(T));
}

[[nodiscard]] i64 sign_extend(u64 value, unsigned bits) noexcept {
    const u64 sign = u64{1} << (bits - 1);
    const u64 mask = (u64{1} << bits) - 1;
    value &= mask;
    return static_cast<i64>((value ^ sign) - sign);
}

[[nodiscard]] std::string_view ppc_relocation_name(u32 type) noexcept {
    switch (type) {
        case rppc::ADDR32:          return "R_PPC_ADDR32";
        case rppc::ADDR24:          return "R_PPC_ADDR24";
        case rppc::ADDR16:          return "R_PPC_ADDR16";
        case rppc::ADDR16_LO:       return "R_PPC_ADDR16_LO";
        case rppc::ADDR16_HI:       return "R_PPC_ADDR16_HI";
        case rppc::ADDR16_HA:       return "R_PPC_ADDR16_HA";
        case rppc::REL24:           return "R_PPC_REL24";
        case rppc::REL14:           return "R_PPC_REL14";
        case rppc::REL14_BRTAKEN:   return "R_PPC_REL14_BRTAKEN";
        case rppc::REL14_BRNTAKEN:  return "R_PPC_REL14_BRNTAKEN";
        default:                    return "R_PPC_UNKNOWN";
    }
}

[[nodiscard]] Arch arch_from_machine(u16 em, bool is_64bit) noexcept {
    switch (em) {
        case em::I386:    return Arch::X86;
        case em::PPC:     return Arch::Ppc32;
        case em::PPC64:   return Arch::Ppc64;
        case em::ARM:     return Arch::Arm;
        case em::X86_64:  return Arch::X86_64;
        case em::AARCH64: return Arch::Arm64;
        case em::RISCV:   return is_64bit ? Arch::Riscv64 : Arch::Riscv32;
        case em::MIPS:    return is_64bit ? Arch::Mips64  : Arch::Mips32;
        default:          return Arch::Unknown;
    }
}

}  // namespace

Result<std::unique_ptr<ElfBinary>>
ElfBinary::load_from_buffer(std::vector<std::byte> buffer) {
    std::unique_ptr<ElfBinary> self(new ElfBinary(std::move(buffer)));
    if (auto rv = self->parse(); !rv) {
        return std::unexpected(std::move(rv).error());
    }
    return self;
}

Result<ElfBinary::ParsedEhdr> ElfBinary::parse_ehdr() {
    const ByteReader r(buffer_);

    if (r.size() < kEhdr32Size) {
        return std::unexpected(Error::truncated(std::format(
            "elf: file smaller than ELF header ({} < {})", r.size(), kEhdr32Size)));
    }

    const std::byte* const ident = buffer_.data();
    if (ident[ei::MAG0 + 0] != std::byte{0x7f} ||
        ident[ei::MAG0 + 1] != std::byte{'E'}  ||
        ident[ei::MAG0 + 2] != std::byte{'L'}  ||
        ident[ei::MAG0 + 3] != std::byte{'F'}) {
        return std::unexpected(Error::invalid_format("elf: bad magic"));
    }

    const u8 ei_class = static_cast<u8>(ident[ei::CLASS]);
    const u8 ei_data  = static_cast<u8>(ident[ei::DATA]);
    if (ei_class != ei::CLASS_64 && ei_class != ei::CLASS_32) {
        return std::unexpected(Error::unsupported(std::format(
            "elf: unsupported ELF class {}", ei_class)));
    }
    if (ei_data != ei::DATA_LSB && ei_data != ei::DATA_MSB) {
        return std::unexpected(Error::unsupported(std::format(
            "elf: unsupported ELF byte order {}", ei_data)));
    }
    endian_ = (ei_data == ei::DATA_MSB) ? Endian::Big : Endian::Little;

    const bool is_64bit = ei_class == ei::CLASS_64;
    if (is_64bit && r.size() < kEhdr64Size) {
        return std::unexpected(Error::truncated(std::format(
            "elf: file smaller than ELF64 header ({} < {})", r.size(), kEhdr64Size)));
    }

    if (!is_64bit) {
        return ParsedEhdr{
            .is_64bit    = false,
            .e_type      = read_at<u16>(endian_, ident + 0x10),
            .e_machine   = read_at<u16>(endian_, ident + 0x12),
            .e_entry     = read_at<u32>(endian_, ident + 0x18),
            .e_phoff     = read_at<u32>(endian_, ident + 0x1c),
            .e_shoff     = read_at<u32>(endian_, ident + 0x20),
            .e_phentsize = read_at<u16>(endian_, ident + 0x2a),
            .e_phnum     = read_at<u16>(endian_, ident + 0x2c),
            .e_shentsize = read_at<u16>(endian_, ident + 0x2e),
            .e_shnum     = read_at<u16>(endian_, ident + 0x30),
            .e_shstrndx  = read_at<u16>(endian_, ident + 0x32),
        };
    }

    return ParsedEhdr{
        .is_64bit    = true,
        .e_type      = read_at<u16>(endian_, ident + 0x10),
        .e_machine   = read_at<u16>(endian_, ident + 0x12),
        .e_entry     = read_at<u64>(endian_, ident + 0x18),
        .e_phoff     = read_at<u64>(endian_, ident + 0x20),
        .e_shoff     = read_at<u64>(endian_, ident + 0x28),
        .e_phentsize = read_at<u16>(endian_, ident + 0x36),
        .e_phnum     = read_at<u16>(endian_, ident + 0x38),
        .e_shentsize = read_at<u16>(endian_, ident + 0x3a),
        .e_shnum     = read_at<u16>(endian_, ident + 0x3c),
        .e_shstrndx  = read_at<u16>(endian_, ident + 0x3e),
    };
}

// PT_LOAD is the authoritative runtime mapping. Relocatable .o files have
// no program headers; callers fall back to section-table lookup there.
Result<void> ElfBinary::parse_segments(const ParsedEhdr& h) {
    if (h.e_phnum == 0) return {};
    const std::size_t want_phdr_size = h.is_64bit ? kPhdr64Size : kPhdr32Size;
    if (h.e_phentsize != want_phdr_size) {
        return std::unexpected(Error::invalid_format(std::format(
            "elf: unexpected e_phentsize {} (want {})",
            h.e_phentsize, want_phdr_size)));
    }
    const ByteReader r(buffer_);
    const std::size_t phtab_bytes =
        static_cast<std::size_t>(h.e_phentsize) * h.e_phnum;
    auto phtab = r.slice(h.e_phoff, phtab_bytes);
    if (!phtab) return std::unexpected(std::move(phtab).error());

    segments_.reserve(h.e_phnum);
    for (u16 i = 0; i < h.e_phnum; ++i) {
        const std::byte* const p =
            phtab->data() + static_cast<std::size_t>(i) * want_phdr_size;
        const u32 p_type   = read_at<u32>(endian_, p + 0x00);
        u32 p_flags = 0;
        u64 p_offset = 0;
        u64 p_vaddr = 0;
        u64 p_filesz = 0;
        u64 p_memsz = 0;
        if (h.is_64bit) {
            p_flags  = read_at<u32>(endian_, p + 0x04);
            p_offset = read_at<u64>(endian_, p + 0x08);
            p_vaddr  = read_at<u64>(endian_, p + 0x10);
            p_filesz = read_at<u64>(endian_, p + 0x20);
            p_memsz  = read_at<u64>(endian_, p + 0x28);
        } else {
            p_offset = read_at<u32>(endian_, p + 0x04);
            p_vaddr  = read_at<u32>(endian_, p + 0x08);
            p_filesz = read_at<u32>(endian_, p + 0x10);
            p_memsz  = read_at<u32>(endian_, p + 0x14);
            p_flags  = read_at<u32>(endian_, p + 0x18);
        }

        if (p_type != pt::LOAD) continue;
        if (p_memsz == 0) continue;

        LoadSegment seg;
        seg.vaddr      = p_vaddr;
        seg.memsz      = p_memsz;
        seg.filesz     = p_filesz;
        seg.readable   = (p_flags & pf::R) != 0;
        seg.writable   = (p_flags & pf::W) != 0;
        seg.executable = (p_flags & pf::X) != 0;
        if (p_filesz > 0) {
            if (auto bytes = r.slice(p_offset, p_filesz); bytes) {
                seg.data = *bytes;
            } else {
                return std::unexpected(std::move(bytes).error());
            }
        }
        segments_.push_back(seg);
    }
    return {};
}

Result<void> ElfBinary::parse_sections(const ParsedEhdr& h) {
    if (h.e_shnum == 0) return {};
    const std::size_t want_shdr_size = h.is_64bit ? kShdr64Size : kShdr32Size;
    if (h.e_shentsize != want_shdr_size) {
        return std::unexpected(Error::invalid_format(std::format(
            "elf: unexpected e_shentsize {} (want {})",
            h.e_shentsize, want_shdr_size)));
    }
    if (h.e_shstrndx >= h.e_shnum) {
        return std::unexpected(Error::invalid_format(std::format(
            "elf: e_shstrndx {} >= e_shnum {}", h.e_shstrndx, h.e_shnum)));
    }

    const ByteReader r(buffer_);
    const std::size_t shtab_bytes =
        static_cast<std::size_t>(h.e_shentsize) * h.e_shnum;
    auto shtab = r.slice(h.e_shoff, shtab_bytes);
    if (!shtab) return std::unexpected(std::move(shtab).error());

    const Shdr shstr_hdr = shdr_at(endian_, shtab->data(), h.e_shstrndx,
                                   h.is_64bit);
    if (shstr_hdr.type != sht::STRTAB) {
        // A crafted ELF can point e_shstrndx at any in-range section
        // (the index check above doesn't guarantee the type). Without
        // this, every section name below is read from arbitrary
        // section bytes - symbol-by-name lookup, --refs-to, and
        // anything else that keys off section names quietly returns
        // garbage on malformed input.
        return std::unexpected(Error::invalid_format(std::format(
            "elf: e_shstrndx {} points to section type {} (want STRTAB)",
            h.e_shstrndx, shstr_hdr.type)));
    }
    auto shstr_bytes = r.slice(shstr_hdr.offset, shstr_hdr.size);
    if (!shstr_bytes) return std::unexpected(std::move(shstr_bytes).error());
    const ByteReader shstr_r(*shstr_bytes);

    sections_.reserve(h.e_shnum);
    section_bases_.assign(h.e_shnum, 0);
    constexpr addr_t kPpc32AddressMax = std::numeric_limits<u32>::max();
    addr_t reloc_cursor = 0x10000000;
    for (u16 i = 0; i < h.e_shnum; ++i) {
        const Shdr sh = shdr_at(endian_, shtab->data(), i, h.is_64bit);

        Section s;
        if (auto name = shstr_r.read_cstr(sh.name); name) {
            s.name = std::string(*name);
        } else {
            s.name = std::format("<section-{}>", i);
        }
        s.vaddr       = sh.addr;
        if (is_relocatable_ && (sh.flags & shf::ALLOC) != 0 && sh.size != 0) {
            const addr_t alignment = std::max<addr_t>(sh.addralign, 4);
            const addr_t base = align_up(reloc_cursor, alignment);
            if (base < reloc_cursor || base > kPpc32AddressMax ||
                sh.size > kPpc32AddressMax - base) {
                return std::unexpected(Error::invalid_format(
                    "elf: relocatable section layout exceeds the PPC32 address space"));
            }
            s.vaddr = base;
            section_bases_[i] = base;
            reloc_cursor = base + sh.size;
        } else {
            section_bases_[i] = sh.addr;
        }
        s.file_offset = sh.offset;
        s.size        = sh.size;
        s.flags.allocated  = (sh.flags & shf::ALLOC)     != 0;
        s.flags.writable   = (sh.flags & shf::WRITE)     != 0;
        s.flags.executable = (sh.flags & shf::EXECINSTR) != 0;
        s.flags.readable   = s.flags.allocated;

        if (sh.type != sht::NOBITS && sh.size > 0) {
            if (auto data = r.slice(sh.offset, sh.size); data) {
                s.data = *data;
            } else {
                if (is_relocatable_) {
                    return std::unexpected(std::move(data).error());
                }
                continue;
            }
        }
        sections_.push_back(std::move(s));
    }
    if (is_relocatable_) {
        if (reloc_cursor > kPpc32AddressMax - 0x100u) {
            return std::unexpected(Error::invalid_format(
                "elf: no PPC32 address space remains for external symbols"));
        }
        next_external_addr_ = align_up(reloc_cursor + 0x100, 16);
    }
    return {};
}

Result<void>
ElfBinary::parse_symbols(const ParsedEhdr& h,
                         std::vector<std::string>& dynsym_names,
                         u16& dynsym_section,
                         bool& dynsym_section_seen) {
    if (h.e_shnum == 0) return {};

    const ByteReader r(buffer_);
    const std::size_t shtab_bytes =
        static_cast<std::size_t>(h.e_shentsize) * h.e_shnum;
    auto shtab = r.slice(h.e_shoff, shtab_bytes);
    if (!shtab) return std::unexpected(std::move(shtab).error());

    // Count symtab entries up-front so the one reserve() covers both tables.
    // Cap by buffer size: a corrupt sh.size must not drive a huge reserve()
    // before the per-section slice() bounds-check runs below.
    const std::size_t sym_size = h.is_64bit ? kSym64Size : kSym32Size;
    const std::size_t abs_max_syms = buffer_.size() / sym_size;
    std::size_t total_syms = 0;
    for (u16 i = 0; i < h.e_shnum; ++i) {
        const Shdr sh = shdr_at(endian_, shtab->data(), i, h.is_64bit);
        if (sh.type != sht::SYMTAB && sh.type != sht::DYNSYM) continue;
        if (sh.entsize == sym_size) total_syms += sh.size / sym_size;
    }
    if (total_syms > abs_max_syms) total_syms = abs_max_syms;
    symbols_.reserve(total_syms);

    for (u16 i = 0; i < h.e_shnum; ++i) {
        const Shdr sh = shdr_at(endian_, shtab->data(), i, h.is_64bit);
        if (sh.type != sht::SYMTAB && sh.type != sht::DYNSYM) continue;
        if (sh.entsize != sym_size) {
            return std::unexpected(Error::invalid_format(std::format(
                "elf: unexpected sym entsize {} in section {} (want {})",
                sh.entsize, i, sym_size)));
        }
        if (sh.link >= h.e_shnum) {
            return std::unexpected(Error::invalid_format(std::format(
                "elf: symtab {} has bad strtab link {}", i, sh.link)));
        }

        const Shdr strtab_hdr = shdr_at(endian_, shtab->data(),
                                       static_cast<u16>(sh.link), h.is_64bit);
        if (strtab_hdr.type != sht::STRTAB) {
            // Same shape as the e_shstrndx guard above: the index
            // check earlier doesn't guarantee the linked section is a
            // string table. Crafted ELF would otherwise leak garbage
            // into every symbol name we surface.
            return std::unexpected(Error::invalid_format(std::format(
                "elf: symtab {} links to section type {} (want STRTAB)",
                i, strtab_hdr.type)));
        }
        auto strtab_bytes = r.slice(strtab_hdr.offset, strtab_hdr.size);
        if (!strtab_bytes) return std::unexpected(std::move(strtab_bytes).error());
        const ByteReader str_r(*strtab_bytes);

        auto sym_bytes = r.slice(sh.offset, sh.size);
        if (!sym_bytes) return std::unexpected(std::move(sym_bytes).error());

        const bool is_dynsym = (sh.type == sht::DYNSYM);
        const std::size_t count = sh.size / sym_size;
        const std::byte* const base = sym_bytes->data();
        auto& parsed_table = symbol_tables_[i];
        parsed_table.resize(count);

        if (is_dynsym) {
            dynsym_names.resize(count);
            dynsym_section = i;
            dynsym_section_seen = true;
        }

        for (std::size_t k = 0; k < count; ++k) {
            const std::byte* const p = base + k * sym_size;
            const u32 st_name  = read_at<u32>(endian_, p + 0);
            const u8  st_info  = h.is_64bit
                ? read_at<u8>(endian_, p + 4)
                : read_at<u8>(endian_, p + 12);
            const u16 st_shndx = h.is_64bit
                ? read_at<u16>(endian_, p + 6)
                : read_at<u16>(endian_, p + 14);
            const u64 st_value = h.is_64bit
                ? read_at<u64>(endian_, p + 8)
                : read_at<u32>(endian_, p + 4);
            const u64 st_size = h.is_64bit
                ? read_at<u64>(endian_, p + 16)
                : read_at<u32>(endian_, p + 8);

            std::string name;
            if (auto nm = str_r.read_cstr(st_name); nm) {
                name = std::string(*nm);
            }

            if (is_dynsym) {
                dynsym_names[k] = name;
            }

            addr_t resolved_addr = st_value;
            if (is_relocatable_ && st_shndx != 0 && st_shndx < section_bases_.size()) {
                resolved_addr = section_bases_[st_shndx] + st_value;
            }

            ParsedSymbol parsed;
            parsed.name = name;
            parsed.addr = resolved_addr;
            parsed.size = st_size;
            parsed.kind = symbol_kind_from_info(st_info);
            parsed.section_index = st_shndx;
            parsed.undefined = st_shndx == 0;
            parsed_table[k] = parsed;

            if (name.empty()) continue;

            Symbol sym;
            sym.name      = std::move(name);
            sym.addr      = resolved_addr;
            sym.size      = st_size;
            sym.kind      = symbol_kind_from_info(st_info);
            sym.is_import = (st_shndx == 0);
            sym.is_export = !sym.is_import &&
                (is_dynsym || (is_relocatable_ && (st_info >> 4) != 0));
            symbols_.push_back(std::move(sym));
        }
    }

    if (is_relocatable_ && entry_ == 0) {
        for (const auto& symbol : symbols_) {
            if (!symbol.is_import && symbol.kind == SymbolKind::Function && symbol.addr != 0) {
                entry_ = symbol.addr;
                break;
            }
        }
    }
    return {};
}

// On x86-64 the dynamic linker fills GOT slots via JUMP_SLOT (lazy PLT
// binding) or GLOB_DAT (global data imports). Both give us (slot_vaddr,
// dynsym_index) → name; we attach got_addr on each import by name.
Result<void>
ElfBinary::attach_got_addrs(const ParsedEhdr& h,
                            const std::vector<std::string>& dynsym_names,
                            u16 dynsym_section,
                            std::unordered_map<addr_t, std::string>& got_to_name) {
    if (h.e_shnum == 0 || !h.is_64bit) return {};

    const ByteReader r(buffer_);
    const std::size_t shtab_bytes =
        static_cast<std::size_t>(h.e_shentsize) * h.e_shnum;
    auto shtab = r.slice(h.e_shoff, shtab_bytes);
    if (!shtab) return std::unexpected(std::move(shtab).error());

    for (u16 i = 0; i < h.e_shnum; ++i) {
        const Shdr sh = shdr_at(endian_, shtab->data(), i, h.is_64bit);
        if (sh.type != sht::RELA) continue;
        if (sh.link != dynsym_section) continue;  // only rela→dynsym
        if (sh.entsize != kRela64Size) continue;
        if (sh.size == 0) continue;

        auto rela_bytes = r.slice(sh.offset, sh.size);
        if (!rela_bytes) continue;
        const std::size_t count = sh.size / kRela64Size;
        const std::byte* const base = rela_bytes->data();

        for (std::size_t k = 0; k < count; ++k) {
            const std::byte* const p = base + k * kRela64Size;
            const u64 r_offset = read_at<u64>(endian_, p + 0);
            const u64 r_info   = read_at<u64>(endian_, p + 8);
            const u32 r_type   = static_cast<u32>(r_info & 0xffffffffU);
            const u32 r_sym    = static_cast<u32>(r_info >> 32);

            if (r_type != rx64::JUMP_SLOT && r_type != rx64::GLOB_DAT) continue;
            if (r_sym >= dynsym_names.size()) continue;
            const std::string& name = dynsym_names[r_sym];
            if (name.empty()) continue;
            got_to_name.emplace(static_cast<addr_t>(r_offset), name);
        }
    }

    if (got_to_name.empty()) return {};
    std::unordered_map<std::string, addr_t> name_to_got;
    name_to_got.reserve(got_to_name.size());
    for (const auto& [g, n] : got_to_name) name_to_got.emplace(n, g);
    for (auto& sym : symbols_) {
        if (!sym.is_import) continue;
        auto it = name_to_got.find(sym.name);
        if (it == name_to_got.end()) continue;
        sym.got_addr = it->second;
    }
    return {};
}

Result<void> ElfBinary::parse_relocations(const ParsedEhdr& h) {
    if (!is_relocatable_ || arch_ != Arch::Ppc32 || h.is_64bit || h.e_shnum == 0) {
        return {};
    }

    const ByteReader reader(buffer_);
    const std::size_t shtab_bytes =
        static_cast<std::size_t>(h.e_shentsize) * h.e_shnum;
    auto shtab = reader.slice(h.e_shoff, shtab_bytes);
    if (!shtab) return std::unexpected(std::move(shtab).error());

    auto ensure_external_target = [&](ParsedSymbol& parsed,
                                      bool callable) -> addr_t {
        if (!parsed.undefined) return parsed.addr;
        if (parsed.name.empty()) return 0;
        if (next_external_addr_ > std::numeric_limits<u32>::max() - 15u) {
            return 0;
        }

        auto [it, inserted] = external_symbol_addrs_.try_emplace(
            parsed.name, next_external_addr_);
        if (inserted) next_external_addr_ += 16;
        parsed.addr = it->second;
        if (callable && parsed.kind == SymbolKind::Unknown) {
            parsed.kind = SymbolKind::Function;
        }
        for (auto& symbol : symbols_) {
            if (!symbol.is_import || symbol.name != parsed.name) continue;
            symbol.addr = parsed.addr;
            if (callable && symbol.kind == SymbolKind::Unknown) {
                symbol.kind = SymbolKind::Function;
            }
        }
        return parsed.addr;
    };

    for (u16 reloc_section_index = 0;
         reloc_section_index < h.e_shnum; ++reloc_section_index) {
        const Shdr reloc_sh = shdr_at(endian_, shtab->data(),
                                      reloc_section_index, false);
        if (reloc_sh.type != sht::REL && reloc_sh.type != sht::RELA) continue;
        if (reloc_sh.info >= h.e_shnum || reloc_sh.link >= h.e_shnum) {
            return std::unexpected(Error::invalid_format(std::format(
                "elf: relocation section {} has invalid target/symtab indices {}/{}",
                reloc_section_index, reloc_sh.info, reloc_sh.link)));
        }
        if (reloc_sh.info >= section_bases_.size() ||
            section_bases_[reloc_sh.info] == 0) {
            continue;  // debug/non-allocated section relocation
        }

        auto table_it = symbol_tables_.find(static_cast<u16>(reloc_sh.link));
        if (table_it == symbol_tables_.end()) {
            return std::unexpected(Error::invalid_format(std::format(
                "elf: relocation section {} links to an unparsed symbol table {}",
                reloc_section_index, reloc_sh.link)));
        }

        const bool has_explicit_addend = reloc_sh.type == sht::RELA;
        const std::size_t reloc_size = has_explicit_addend ? kRela32Size : kRel32Size;
        if (reloc_sh.entsize != reloc_size || reloc_sh.size % reloc_size != 0) {
            return std::unexpected(Error::invalid_format(std::format(
                "elf: relocation section {} has entry size {} (want {})",
                reloc_section_index, reloc_sh.entsize, reloc_size)));
        }
        auto reloc_bytes = reader.slice(reloc_sh.offset, reloc_sh.size);
        if (!reloc_bytes) return std::unexpected(std::move(reloc_bytes).error());

        const Shdr target_sh = shdr_at(endian_, shtab->data(),
                                       static_cast<u16>(reloc_sh.info), false);
        const std::string target_section_name = reloc_sh.info < sections_.size()
            ? sections_[reloc_sh.info].name
            : std::format("<section-{}>", reloc_sh.info);
        const std::size_t count = reloc_sh.size / reloc_size;
        for (std::size_t index = 0; index < count; ++index) {
            const std::byte* entry = reloc_bytes->data() + index * reloc_size;
            const u32 r_offset = read_at<u32>(endian_, entry + 0);
            const u32 r_info = read_at<u32>(endian_, entry + 4);
            const u32 r_type = r_info & 0xffu;
            const u32 r_symbol = r_info >> 8;
            if (r_symbol >= table_it->second.size()) {
                return std::unexpected(Error::invalid_format(std::format(
                    "elf: relocation {}:{} references symbol {} past {} entries",
                    reloc_section_index, index, r_symbol, table_it->second.size())));
            }

            ParsedSymbol& parsed = table_it->second[r_symbol];
            const bool pc_relative = r_type == rppc::REL24 ||
                r_type == rppc::REL14 || r_type == rppc::REL14_BRTAKEN ||
                r_type == rppc::REL14_BRNTAKEN;
            const bool callable = r_type == rppc::REL24 || r_type == rppc::ADDR24;
            const addr_t symbol_addr = ensure_external_target(parsed, callable);

            u8 width = 0;
            switch (r_type) {
                case rppc::ADDR16:
                case rppc::ADDR16_LO:
                case rppc::ADDR16_HI:
                case rppc::ADDR16_HA:
                    width = 2;
                    break;
                case rppc::ADDR32:
                case rppc::ADDR24:
                case rppc::REL24:
                case rppc::REL14:
                case rppc::REL14_BRTAKEN:
                case rppc::REL14_BRNTAKEN:
                    width = 4;
                    break;
                default:
                    break;
            }

            Relocation relocation;
            relocation.site = section_bases_[reloc_sh.info] + r_offset;
            relocation.type = r_type;
            relocation.width = width;
            relocation.pc_relative = pc_relative;
            relocation.type_name = std::string(ppc_relocation_name(r_type));
            relocation.symbol_name = parsed.name;
            relocation.section_name = target_section_name;

            const i64 explicit_addend = has_explicit_addend
                ? static_cast<i64>(read_at<i32>(endian_, entry + 8))
                : 0;
            relocation.addend = explicit_addend;

            if (width == 0) {
                const i64 resolved = static_cast<i64>(symbol_addr) + explicit_addend;
                if (resolved >= 0) relocation.target = static_cast<addr_t>(resolved);
                relocations_.push_back(std::move(relocation));
                continue;
            }
            if (r_offset > target_sh.size || width > target_sh.size - r_offset ||
                target_sh.type == sht::NOBITS ||
                target_sh.offset > buffer_.size() ||
                r_offset > buffer_.size() - target_sh.offset ||
                width > buffer_.size() - target_sh.offset - r_offset) {
                return std::unexpected(Error::out_of_bounds(std::format(
                    "elf: relocation {}:{} patch at {:#x} exceeds target section",
                    reloc_section_index, index, r_offset)));
            }

            std::byte* patch = buffer_.data() + target_sh.offset + r_offset;
            i64 addend = explicit_addend;
            if (!has_explicit_addend) {
                if (r_type == rppc::ADDR32) {
                    addend = static_cast<i64>(read_at<i32>(endian_, patch));
                } else if (r_type == rppc::ADDR24 || r_type == rppc::REL24) {
                    addend = sign_extend(read_at<u32>(endian_, patch) & 0x03fffffcu, 26);
                } else if (r_type == rppc::REL14 ||
                           r_type == rppc::REL14_BRTAKEN ||
                           r_type == rppc::REL14_BRNTAKEN) {
                    addend = sign_extend(read_at<u32>(endian_, patch) & 0x0000fffcu, 16);
                } else {
                    addend = read_at<i16>(endian_, patch);
                }
            }
            relocation.addend = addend;

            const i64 resolved = static_cast<i64>(symbol_addr) + addend;
            if (resolved >= 0) relocation.target = static_cast<addr_t>(resolved);
            bool applied = symbol_addr != 0;
            switch (r_type) {
                case rppc::ADDR32:
                    if (applied) write_at<u32>(endian_, patch, static_cast<u32>(resolved));
                    break;
                case rppc::ADDR24: {
                    const u64 value = static_cast<u64>(resolved);
                    applied = applied && (value & 3u) == 0 && value <= 0x03fffffcu;
                    if (applied) {
                        const u32 word = read_at<u32>(endian_, patch);
                        write_at<u32>(endian_, patch,
                            (word & ~0x03fffffcu) |
                            (static_cast<u32>(value) & 0x03fffffcu));
                    }
                    break;
                }
                case rppc::ADDR16:
                case rppc::ADDR16_LO:
                    if (applied) write_at<u16>(endian_, patch, static_cast<u16>(resolved));
                    break;
                case rppc::ADDR16_HI:
                    if (applied) {
                        write_at<u16>(endian_, patch,
                                      static_cast<u16>(static_cast<u64>(resolved) >> 16));
                    }
                    break;
                case rppc::ADDR16_HA:
                    if (applied) {
                        write_at<u16>(endian_, patch, static_cast<u16>(
                            (static_cast<u64>(resolved) + 0x8000u) >> 16));
                    }
                    break;
                case rppc::REL24: {
                    const i64 delta = resolved - static_cast<i64>(relocation.site);
                    applied = applied && (delta & 3) == 0 &&
                        delta >= -0x02000000LL && delta <= 0x01fffffcLL;
                    if (applied) {
                        const u32 word = read_at<u32>(endian_, patch);
                        write_at<u32>(endian_, patch,
                            (word & ~0x03fffffcu) |
                            (static_cast<u32>(delta) & 0x03fffffcu));
                    }
                    break;
                }
                case rppc::REL14:
                case rppc::REL14_BRTAKEN:
                case rppc::REL14_BRNTAKEN: {
                    const i64 delta = resolved - static_cast<i64>(relocation.site);
                    applied = applied && (delta & 3) == 0 &&
                        delta >= -0x8000LL && delta <= 0x7ffcLL;
                    if (applied) {
                        const u32 word = read_at<u32>(endian_, patch);
                        write_at<u32>(endian_, patch,
                            (word & ~0x0000fffcu) |
                            (static_cast<u32>(delta) & 0x0000fffcu));
                    }
                    break;
                }
                default:
                    applied = false;
                    break;
            }
            relocation.applied = applied;
            relocations_.push_back(std::move(relocation));
        }
    }
    return {};
}

// Walks each executable .plt* section; every `jmp qword [rip + D]` whose
// target GOT slot is in `got_to_name` gives us an import stub whose
// caller-visible address is the 16-byte-aligned slot start. Covers both
// classic `jmp [GOT]; push; jmp .plt[0]` and modern `endbr64; bnd jmp [GOT]`
// entries without enumerating prefix bytes.
void ElfBinary::scan_plt_stubs(
    const std::unordered_map<addr_t, std::string>& got_to_name) {
    if (got_to_name.empty() || arch_ != Arch::X86_64) return;

    std::unordered_map<std::string, addr_t> import_stub_addr;
    const X64Decoder dec;

    // Prefer .plt-named sections (normal ELFs with a section table). When
    // none exist - sectionless binaries synthesize their exec segment as
    // ".text" - fall back to scanning every executable section.
    bool any_plt = false;
    for (const auto& sec : sections_) {
        if (sec.flags.executable && sec.name.rfind(".plt", 0) == 0) {
            any_plt = true; break;
        }
    }
    for (const auto& sec : sections_) {
        if (!sec.flags.executable) continue;
        if (sec.data.empty()) continue;
        if (any_plt && sec.name.rfind(".plt", 0) != 0) continue;

        addr_t ip = sec.vaddr;
        std::size_t off = 0;
        while (off < sec.data.size()) {
            auto remaining = sec.data.subspan(off);
            auto decoded = dec.decode(remaining, ip);
            if (!decoded) { ip += 1; off += 1; continue; }
            const Instruction& insn = *decoded;

            if (insn.mnemonic == Mnemonic::Jmp && insn.num_operands == 1) {
                const Operand& op = insn.operands[0];
                if (op.kind == Operand::Kind::Memory &&
                    op.mem.base == Reg::Rip &&
                    op.mem.index == Reg::None &&
                    op.mem.has_disp) {
                    const addr_t got = ip + insn.length +
                                       static_cast<addr_t>(op.mem.disp);
                    auto it = got_to_name.find(got);
                    if (it != got_to_name.end()) {
                        const addr_t stub_start = ip & ~static_cast<addr_t>(0xF);
                        import_stub_addr.try_emplace(it->second, stub_start);
                    }
                }
            }

            ip  += insn.length;
            off += insn.length;
        }
    }

    for (auto& sym : symbols_) {
        if (!sym.is_import) continue;
        if (sym.addr != 0) continue;
        auto it = import_stub_addr.find(sym.name);
        if (it == import_stub_addr.end()) continue;
        sym.addr = it->second;
    }
}

void ElfBinary::sort_and_dedupe_symbols() {
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
}

bool ElfBinary::is_executable_addr(addr_t vaddr) const noexcept {
    for (const auto& seg : segments_) {
        if (vaddr < seg.vaddr) continue;
        if (vaddr >= seg.vaddr + seg.memsz) continue;
        return seg.executable;
    }
    for (const auto& sec : sections_) {
        if (vaddr < sec.vaddr) continue;
        if (vaddr >= sec.vaddr + sec.size) continue;
        return sec.flags.executable;
    }
    return false;
}

std::optional<addr_t>
ElfBinary::resolve_ppc64_descriptor_target(addr_t vaddr) const noexcept {
    if (arch_ != Arch::Ppc64 || endian_ != Endian::Big) return std::nullopt;
    if (vaddr == 0 || is_executable_addr(vaddr)) return std::nullopt;
    const auto bytes = bytes_at(vaddr);
    if (bytes.size() < sizeof(u64)) return std::nullopt;
    const addr_t target = read_at<u64>(endian_, bytes.data());
    if (target == 0 || target == vaddr) return std::nullopt;
    if (!is_executable_addr(target)) return std::nullopt;
    return target;
}

void ElfBinary::normalize_ppc64_descriptors() noexcept {
    if (auto target = resolve_ppc64_descriptor_target(entry_); target) {
        entry_ = *target;
    }
    for (auto& sym : symbols_) {
        if (sym.is_import || sym.kind != SymbolKind::Function || sym.addr == 0) continue;
        if (auto target = resolve_ppc64_descriptor_target(sym.addr); target) {
            sym.addr = *target;
        }
    }
}

Result<void> ElfBinary::parse() {
    auto hdr = parse_ehdr();
    if (!hdr) return std::unexpected(std::move(hdr).error());

    arch_  = arch_from_machine(hdr->e_machine, hdr->is_64bit);
    entry_ = hdr->e_entry;
    is_relocatable_ = hdr->e_type == et::REL;

    if (auto rv = parse_segments(*hdr);  !rv) return std::unexpected(rv.error());
    if (hdr->e_shnum == 0) return parse_from_phdr(*hdr);
    if (auto rv = parse_sections(*hdr);  !rv) {
        sections_.clear();
        if (is_relocatable_) return std::unexpected(rv.error());
        return parse_from_phdr(*hdr);
    }

    std::vector<std::string> dynsym_names;
    u16 dynsym_section = 0;
    bool dynsym_section_seen = false;
    if (auto rv = parse_symbols(*hdr, dynsym_names, dynsym_section,
                                dynsym_section_seen);
        !rv) {
        return std::unexpected(rv.error());
    }
    if (auto rv = parse_relocations(*hdr); !rv) {
        return std::unexpected(rv.error());
    }

    if (dynsym_section_seen) {
        std::unordered_map<addr_t, std::string> got_to_name;
        if (auto rv = attach_got_addrs(*hdr, dynsym_names, dynsym_section,
                                       got_to_name);
            !rv) {
            return std::unexpected(rv.error());
        }
        scan_plt_stubs(got_to_name);
    }

    normalize_ppc64_descriptors();
    sort_and_dedupe_symbols();
    return {};
}

std::map<addr_t, addr_t> ElfBinary::relocated_qwords() const {
    std::map<addr_t, addr_t> out;
    const u32 rel_type = relative_reloc_type_for(arch_);
    if (rel_type == 0) return out;

    // Re-derive the section table from buffer_. We could cache it on
    // load, but the rela tables are small relative to .text and this
    // path is only walked when --refs-to-loose runs. Keeping the
    // cached state minimal is a deliberate tradeoff.
    if (buffer_.size() < 64) return out;
    const ByteReader r(buffer_);
    const u8 ei_class = static_cast<u8>(buffer_[ei::CLASS]);
    if (ei_class != ei::CLASS_64) return out;  // 32-bit ELF unsupported here.

    auto e_shoff_bytes      = r.slice(0x28, 8);
    auto e_shentsize_bytes  = r.slice(0x3a, 2);
    auto e_shnum_bytes      = r.slice(0x3c, 2);
    if (!e_shoff_bytes || !e_shentsize_bytes || !e_shnum_bytes) return out;
    const u64 e_shoff     = read_at<u64>(endian_, e_shoff_bytes->data());
    const u16 e_shentsize = read_at<u16>(endian_, e_shentsize_bytes->data());
    const u16 e_shnum     = read_at<u16>(endian_, e_shnum_bytes->data());
    if (e_shentsize != kShdr64Size || e_shnum == 0) return out;

    auto shtab = r.slice(e_shoff,
                         static_cast<std::size_t>(e_shentsize) * e_shnum);
    if (!shtab) return out;

    // Walk every SHT_RELA. Filter to the RELATIVE-type rows and emit
    // (r_offset -> r_addend). r_offset is the slot's virtual address
    // (post-load); r_addend is the absolute target VA the dynamic
    // linker writes there at startup.
    for (u16 i = 0; i < e_shnum; ++i) {
        const Shdr sh = shdr_at(endian_, shtab->data(), i, true);
        if (sh.type != sht::RELA) continue;
        if (sh.entsize != kRela64Size) continue;
        if (sh.size == 0) continue;

        auto rela_bytes = r.slice(sh.offset, sh.size);
        if (!rela_bytes) continue;
        const std::size_t count = sh.size / kRela64Size;
        const std::byte* const base = rela_bytes->data();

        for (std::size_t k = 0; k < count; ++k) {
            const std::byte* const p = base + k * kRela64Size;
            const u64 r_offset = read_at<u64>(endian_, p + 0);
            const u64 r_info   = read_at<u64>(endian_, p + 8);
            const i64 r_addend = static_cast<i64>(read_at<u64>(endian_, p + 16));
            const u32 r_type   = static_cast<u32>(r_info & 0xffffffffU);
            if (r_type != rel_type) continue;
            // RELATIVE relocs have sym=0 by definition; r_addend is
            // the absolute target VA. Skip non-positive addends -
            // those are ELF padding / sentinel rows that don't
            // resolve to real code.
            if (r_addend <= 0) continue;
            out[static_cast<addr_t>(r_offset)] =
                static_cast<addr_t>(static_cast<u64>(r_addend));
        }
    }
    return out;
}

}  // namespace ember
