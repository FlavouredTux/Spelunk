#include <ember/binary/elf.hpp>

#include <algorithm>
#include <bit>
#include <cstddef>
#include <expected>
#include <format>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
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
#include "ppc32_relocation.hpp"

namespace ember {

namespace {

constexpr std::size_t kEhdr64Size = 64;
constexpr std::size_t kEhdr32Size = 52;
constexpr std::size_t kRela32Size = 12;
constexpr std::size_t kRel32Size  = 8;

using elf::align_up_bounded;
using elf::kPhdr32Size;
using elf::kPhdr64Size;
using elf::kRela64Size;
using elf::kShdr32Size;
using elf::kShdr64Size;
using elf::read_at;
using elf::read_shdr;
using elf::Shdr;
using elf::shdr_at;

namespace pt = elf::pt;
namespace rx64 = elf::rx64;
namespace shn = elf::shn;
namespace sht = elf::sht;

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

namespace rppc = ppc32::type;

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

[[nodiscard]] i64 sign_extend(u64 value, unsigned bits) noexcept {
    const u64 sign = u64{1} << (bits - 1);
    const u64 mask = (u64{1} << bits) - 1;
    value &= mask;
    return static_cast<i64>((value ^ sign) - sign);
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

addr_t ElfBinary::preferred_load_base() const noexcept {
    addr_t lo = 0;
    bool set = false;
    for (const auto& segment : segments_) {
        if (!set || segment.vaddr < lo) {
            lo = segment.vaddr;
            set = true;
        }
    }
    if (set) return lo;
    if (has_load_segments_) return 0;
    for (const auto& section : sections_) {
        if (!section.flags.allocated || section.size == 0) continue;
        if (lo == 0 || section.vaddr < lo) lo = section.vaddr;
    }
    return lo;
}

addr_t ElfBinary::mapped_size() const noexcept {
    constexpr addr_t kMax = std::numeric_limits<addr_t>::max();
    addr_t lo = kMax;
    bool set = false;
    for (const auto& segment : segments_) {
        if (segment.memsz == 0) continue;
        if (!set || segment.vaddr < lo) lo = segment.vaddr;
        set = true;
    }
    if (set) {
        addr_t span = 0;
        for (const auto& segment : segments_) {
            if (segment.memsz == 0) continue;
            const addr_t offset = segment.vaddr - lo;
            if (segment.memsz > kMax - offset) return kMax;
            const addr_t end = offset + segment.memsz;
            if (end > span) span = end;
        }
        return span;
    }
    if (has_load_segments_) return 0;

    lo = kMax;
    set = false;
    for (const auto& section : sections_) {
        if (!section.flags.allocated || section.size == 0) continue;
        if (!set || section.vaddr < lo) lo = section.vaddr;
        set = true;
    }
    if (!set) return 0;

    addr_t span = 0;
    for (const auto& section : sections_) {
        if (!section.flags.allocated || section.size == 0) continue;
        const addr_t offset = section.vaddr - lo;
        if (section.size > kMax - offset) return kMax;
        const addr_t end = offset + section.size;
        if (end > span) span = end;
    }
    return span;
}

std::span<const std::byte>
ElfBinary::bytes_at(addr_t vaddr) const noexcept {
    for (const auto& segment : segments_) {
        if (vaddr < segment.vaddr) continue;
        const u64 offset = vaddr - segment.vaddr;
        if (offset >= segment.memsz) continue;
        if (offset >= segment.filesz) return {};
        if (segment.data.empty()) continue;
        return segment.data.subspan(static_cast<std::size_t>(offset));
    }
    if (has_load_segments_) return {};
    return Binary::bytes_at(vaddr);
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

    ParsedEhdr h;
    u16 raw_phnum = 0;
    u16 raw_shnum = 0;
    u16 raw_shstrndx = 0;
    if (!is_64bit) {
        h = ParsedEhdr{
            .is_64bit    = false,
            .e_type      = read_at<u16>(endian_, ident + 0x10),
            .e_machine   = read_at<u16>(endian_, ident + 0x12),
            .e_entry     = read_at<u32>(endian_, ident + 0x18),
            .e_phoff     = read_at<u32>(endian_, ident + 0x1c),
            .e_shoff     = read_at<u32>(endian_, ident + 0x20),
            .e_phentsize = read_at<u16>(endian_, ident + 0x2a),
            .e_shentsize = read_at<u16>(endian_, ident + 0x2e),
            .e_phnum     = 0,
            .e_shnum     = 0,
            .e_shstrndx  = 0,
        };
        raw_phnum = read_at<u16>(endian_, ident + 0x2c);
        raw_shnum = read_at<u16>(endian_, ident + 0x30);
        raw_shstrndx = read_at<u16>(endian_, ident + 0x32);
    } else {
        h = ParsedEhdr{
            .is_64bit    = true,
            .e_type      = read_at<u16>(endian_, ident + 0x10),
            .e_machine   = read_at<u16>(endian_, ident + 0x12),
            .e_entry     = read_at<u64>(endian_, ident + 0x18),
            .e_phoff     = read_at<u64>(endian_, ident + 0x20),
            .e_shoff     = read_at<u64>(endian_, ident + 0x28),
            .e_phentsize = read_at<u16>(endian_, ident + 0x36),
            .e_shentsize = read_at<u16>(endian_, ident + 0x3a),
            .e_phnum     = 0,
            .e_shnum     = 0,
            .e_shstrndx  = 0,
        };
        raw_phnum = read_at<u16>(endian_, ident + 0x38);
        raw_shnum = read_at<u16>(endian_, ident + 0x3c);
        raw_shstrndx = read_at<u16>(endian_, ident + 0x3e);
    }

    h.e_phnum = raw_phnum;
    h.e_shnum = raw_shnum;
    h.e_shstrndx = raw_shstrndx;

    const bool extended_shnum = raw_shnum == 0 && h.e_shoff != 0;
    const bool extended_shstrndx = raw_shstrndx == shn::XINDEX;
    constexpr u16 kPnXnum = 0xffff;
    const bool extended_phnum = raw_phnum == kPnXnum;

    if (h.e_shoff == 0) {
        if (raw_shnum != 0 || extended_shstrndx || extended_phnum) {
            return std::unexpected(Error::invalid_format(
                "elf: extended section/program numbering requires section header 0"));
        }
        return h;  // genuinely sectionless ELF
    }

    if (extended_shnum || extended_shstrndx || extended_phnum) {
        const std::size_t shdr_size = is_64bit ? kShdr64Size : kShdr32Size;
        if (h.e_shentsize != shdr_size) {
            return std::unexpected(Error::invalid_format(std::format(
                "elf: extended numbering with e_shentsize {} (want {})",
                h.e_shentsize, shdr_size)));
        }
        auto sh0_bytes = r.slice(h.e_shoff, shdr_size);
        if (!sh0_bytes) return std::unexpected(std::move(sh0_bytes).error());
        const Shdr sh0 = read_shdr(endian_, sh0_bytes->data(), is_64bit);
        if (sh0.type != sht::NULL_) {
            return std::unexpected(Error::invalid_format(std::format(
                "elf: extended numbering section 0 has type {} (want NULL)",
                sh0.type)));
        }

        if (extended_shnum) {
            if (sh0.size < shn::LORESERVE ||
                sh0.size > std::numeric_limits<u32>::max()) {
                return std::unexpected(Error::invalid_format(std::format(
                    "elf: invalid extended section count {}", sh0.size)));
            }
            h.e_shnum = static_cast<u32>(sh0.size);
        }
        if (extended_shstrndx) {
            if (sh0.link < shn::LORESERVE) {
                return std::unexpected(Error::invalid_format(std::format(
                    "elf: invalid extended section-name index {}", sh0.link)));
            }
            h.e_shstrndx = sh0.link;
        }
        if (extended_phnum) {
            if (sh0.info < kPnXnum) {
                return std::unexpected(Error::invalid_format(std::format(
                    "elf: invalid extended program-header count {}", sh0.info)));
            }
            h.e_phnum = sh0.info;
        }
    }
    return h;
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
    for (u32 i = 0; i < h.e_phnum; ++i) {
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
        has_load_segments_ = true;
        if (p_filesz > p_memsz) {
            return std::unexpected(Error::invalid_format(std::format(
                "elf: PT_LOAD {} has p_filesz {:#x} greater than p_memsz {:#x}",
                i, p_filesz, p_memsz)));
        }
        const u64 interval_max = h.is_64bit
            ? std::numeric_limits<u64>::max()
            : std::numeric_limits<u32>::max();
        if (p_memsz > interval_max - p_vaddr) {
            return std::unexpected(Error::invalid_format(std::format(
                "elf: PT_LOAD {} virtual interval overflows ELF{} address space",
                i, h.is_64bit ? 64 : 32)));
        }
        if (p_filesz > interval_max - p_offset) {
            return std::unexpected(Error::invalid_format(std::format(
                "elf: PT_LOAD {} file interval overflows ELF{} offset space",
                i, h.is_64bit ? 64 : 32)));
        }
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
    const u64 class_address_max = h.is_64bit
        ? std::numeric_limits<u64>::max()
        : std::numeric_limits<u32>::max();
    addr_t reloc_cursor = 0x10000000;
    for (u32 i = 0; i < h.e_shnum; ++i) {
        const Shdr sh = shdr_at(endian_, shtab->data(), i, h.is_64bit);

        // Extended numbering reuses section zero's size/link/info fields.
        // It remains SHT_NULL and must not expose those metadata words as a
        // mapped section or file slice.
        if (i == 0 && sh.type == sht::NULL_) {
            sections_.emplace_back();
            continue;
        }

        if (sh.addralign > 1 && !std::has_single_bit(sh.addralign)) {
            return std::unexpected(Error::invalid_format(std::format(
                "elf: section {} has non-power-of-two alignment {}",
                i, sh.addralign)));
        }

        if ((sh.flags & shf::ALLOC) != 0 && sh.size != 0 &&
            (sh.addr > class_address_max ||
             sh.size - 1 > class_address_max - sh.addr)) {
            return std::unexpected(Error::invalid_format(std::format(
                "elf: allocated section {} exceeds the ELF{} address space",
                i, h.is_64bit ? 64 : 32)));
        }

        Section s;
        if (auto name = shstr_r.read_cstr(sh.name); name) {
            s.name = std::string(*name);
        } else {
            s.name = std::format("<section-{}>", i);
        }
        s.vaddr       = sh.addr;
        if (is_relocatable_ && (sh.flags & shf::ALLOC) != 0 && sh.size != 0) {
            const addr_t alignment = std::max<addr_t>(sh.addralign, 4);
            const auto base = align_up_bounded(
                reloc_cursor, alignment, kPpc32AddressMax);
            if (!base || sh.size - 1 > kPpc32AddressMax - *base) {
                return std::unexpected(Error::invalid_format(
                    "elf: relocatable section layout exceeds the PPC32 address space"));
            }
            s.vaddr = *base;
            section_bases_[i] = *base;
            reloc_cursor = *base + sh.size;
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
        const auto external_base = align_up_bounded(
            reloc_cursor + 0x100, 16, kPpc32AddressMax);
        if (!external_base) {
            return std::unexpected(Error::invalid_format(
                "elf: cannot align PPC32 external-symbol storage"));
        }
        next_external_addr_ = *external_base;
    }
    return {};
}

// On x86-64 the dynamic linker fills GOT slots via JUMP_SLOT (lazy PLT
// binding) or GLOB_DAT (global data imports). Both give us (slot_vaddr,
// dynsym_index) → name; we attach got_addr on each import by name.
Result<void>
ElfBinary::attach_got_addrs(const ParsedEhdr& h,
                            const std::vector<std::string>& dynsym_names,
                            u32 dynsym_section,
                            std::unordered_map<addr_t, std::string>& got_to_name) {
    if (h.e_shnum == 0 || !h.is_64bit || arch_ != Arch::X86_64) return {};

    const ByteReader r(buffer_);
    const std::size_t shtab_bytes =
        static_cast<std::size_t>(h.e_shentsize) * h.e_shnum;
    auto shtab = r.slice(h.e_shoff, shtab_bytes);
    if (!shtab) return std::unexpected(std::move(shtab).error());

    for (u32 i = 0; i < h.e_shnum; ++i) {
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

    struct RelocationTarget {
        addr_t addr = 0;
        bool available = false;
    };
    auto ensure_external_target = [&](ParsedSymbol& parsed,
                                      bool callable) -> RelocationTarget {
        if (!parsed.undefined) return {parsed.addr, true};
        if (parsed.name.empty()) return {};
        auto it = external_symbol_addrs_.find(parsed.name);
        if (it == external_symbol_addrs_.end()) {
            const auto aligned = align_up_bounded(
                next_external_addr_, 16, std::numeric_limits<u32>::max());
            if (!aligned || *aligned > std::numeric_limits<u32>::max() - 15u) {
                return {};
            }
            it = external_symbol_addrs_.emplace(parsed.name, *aligned).first;
            next_external_addr_ = *aligned + 16;
        }
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
        return {parsed.addr, true};
    };

    for (u32 reloc_section_index = 0;
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

        auto table_it = symbol_tables_.find(reloc_sh.link);
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
                                       reloc_sh.info, false);
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
            const ppc32::RelocationInfo properties = ppc32::info(r_type);
            const bool ghs_half = r_type >= rppc::GHS_REL16_HA && r_type <= rppc::GHS_REL16_LO;
            const bool supported = properties.elf_supported && (has_explicit_addend || !ghs_half);
            const RelocationTarget target = ensure_external_target(
                parsed, supported && properties.callable);
            const addr_t symbol_addr = target.addr;
            const u8 width = supported ? properties.width : 0;

            Relocation relocation;
            relocation.site = section_bases_[reloc_sh.info] + r_offset;
            relocation.type = r_type;
            relocation.width = width;
            relocation.pc_relative = supported && properties.pc_relative;
            relocation.type_name = std::string(properties.name);
            relocation.symbol_name = parsed.name;
            relocation.section_name = target_section_name;

            const i64 explicit_addend = has_explicit_addend
                ? static_cast<i64>(read_at<i32>(endian_, entry + 8))
                : 0;
            relocation.addend = explicit_addend;

            if (width == 0) {
                const u32 resolved = ppc32::resolve(symbol_addr, explicit_addend);
                relocation.target = resolved;
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
                if (r_type == rppc::ADDR32 || r_type == rppc::REL32) {
                    addend = static_cast<i64>(read_at<i32>(endian_, patch));
                } else if (r_type == rppc::ADDR24 || r_type == rppc::REL24) {
                    addend = sign_extend(read_at<u32>(endian_, patch) & 0x03fffffcu, 26);
                } else if (r_type == rppc::ADDR14 ||
                           r_type == rppc::ADDR14_BRTAKEN ||
                           r_type == rppc::ADDR14_BRNTAKEN ||
                           r_type == rppc::REL14 ||
                           r_type == rppc::REL14_BRTAKEN ||
                           r_type == rppc::REL14_BRNTAKEN) {
                    addend = sign_extend(read_at<u32>(endian_, patch) & 0x0000fffcu, 16);
                } else {
                    addend = read_at<i16>(endian_, patch);
                }
            }
            relocation.addend = addend;

            const u32 resolved = ppc32::resolve(symbol_addr, addend);
            relocation.target = resolved;
            relocation.applied = target.available && ppc32::encode(
                std::span<std::byte>{patch, width}, r_type, endian_,
                resolved, relocation.site);
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
        if (a.size != b.size) return a.size < b.size;
        return a.is_export > b.is_export;
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
        if (vaddr - seg.vaddr >= seg.memsz) continue;
        return seg.executable;
    }
    if (has_load_segments_) return false;
    for (const auto& sec : sections_) {
        if (vaddr < sec.vaddr) continue;
        if (vaddr - sec.vaddr >= sec.size) continue;
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
    is_cafe_ = !hdr->is_64bit && arch_ == Arch::Ppc32 && endian_ == Endian::Big &&
        buffer_[7] == std::byte{0xca};

    if (auto rv = decompress_cafe_sections(*hdr); !rv) return std::unexpected(rv.error());
    if (auto rv = parse_segments(*hdr);  !rv) return std::unexpected(rv.error());
    if (hdr->e_shnum == 0) return parse_from_phdr(*hdr);
    if (auto rv = parse_sections(*hdr);  !rv) {
        sections_.clear();
        if (is_relocatable_ || segments_.empty()) {
            return std::unexpected(rv.error());
        }
        return parse_from_phdr(*hdr);
    }

    std::vector<std::string> dynsym_names;
    u32 dynsym_section = 0;
    bool dynsym_section_seen = false;
    if (auto rv = parse_symbols(*hdr, dynsym_names, dynsym_section,
                                dynsym_section_seen);
        !rv) {
        return std::unexpected(rv.error());
    }
    if (auto rv = is_cafe_ ? link_cafe_sections(*hdr) : parse_relocations(*hdr); !rv) {
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
    const u16 raw_e_shnum = read_at<u16>(endian_, e_shnum_bytes->data());
    if (e_shentsize != kShdr64Size || e_shoff == 0) return out;
    u32 e_shnum = raw_e_shnum;
    if (raw_e_shnum == 0) {
        auto sh0_bytes = r.slice(e_shoff, kShdr64Size);
        if (!sh0_bytes) return out;
        const Shdr sh0 = read_shdr(endian_, sh0_bytes->data(), true);
        if (sh0.size < shn::LORESERVE ||
            sh0.size > std::numeric_limits<u32>::max()) {
            return out;
        }
        e_shnum = static_cast<u32>(sh0.size);
    }

    auto shtab = r.slice(e_shoff,
                         static_cast<std::size_t>(e_shentsize) * e_shnum);
    if (!shtab) return out;

    // Walk every SHT_RELA. Filter to the RELATIVE-type rows and emit
    // (r_offset -> r_addend). r_offset is the slot's virtual address
    // (post-load); r_addend is the absolute target VA the dynamic
    // linker writes there at startup.
    for (u32 i = 0; i < e_shnum; ++i) {
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
