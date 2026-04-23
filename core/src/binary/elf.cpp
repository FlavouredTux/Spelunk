#include <ember/binary/elf.hpp>

#include <algorithm>
#include <cstring>
#include <format>
#include <unordered_map>
#include <utility>
#include <vector>

#include <ember/analysis/eh_frame.hpp>
#include <ember/common/bytes.hpp>
#include <ember/disasm/instruction.hpp>
#include <ember/disasm/x64_decoder.hpp>

namespace ember {

namespace {

constexpr std::size_t kEhdr64Size = 64;
constexpr std::size_t kPhdr64Size = 56;
constexpr std::size_t kShdr64Size = 64;
constexpr std::size_t kSym64Size  = 24;
constexpr std::size_t kRela64Size = 24;

namespace pt {
constexpr u32 LOAD        = 1;
constexpr u32 DYNAMIC     = 2;
constexpr u32 GNU_EH_FRAME = 0x6474e550;
}  // namespace pt

// DT_* tags we consume. Everything else is ignored.
namespace dt {
constexpr u64 NULL_       = 0;
constexpr u64 PLTRELSZ    = 2;
constexpr u64 HASH        = 4;
constexpr u64 STRTAB      = 5;
constexpr u64 SYMTAB      = 6;
constexpr u64 RELA        = 7;
constexpr u64 RELASZ      = 8;
constexpr u64 STRSZ       = 10;
constexpr u64 SYMENT      = 11;
constexpr u64 JMPREL      = 23;
constexpr u64 GNU_HASH    = 0x6ffffef5;
}  // namespace dt

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
constexpr u8 DATA_LSB = 1;
constexpr u8 DATA_MSB = 2;
}  // namespace ei

namespace em {
constexpr u16 I386    = 3;
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
constexpr u32 DYNSYM = 11;
constexpr u32 RELA   = 4;
}  // namespace sht

// x86-64 relocation types (subset).
namespace rx64 {
constexpr u32 GLOB_DAT = 6;
constexpr u32 JUMP_SLOT = 7;
}  // namespace rx64

namespace shf {
constexpr u64 WRITE     = 0x1;
constexpr u64 ALLOC     = 0x2;
constexpr u64 EXECINSTR = 0x4;
}  // namespace shf

namespace stt {
constexpr u8 OBJECT  = 1;
constexpr u8 FUNC    = 2;
constexpr u8 SECTION = 3;
constexpr u8 FILE_   = 4;
}  // namespace stt

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

template <typename T>
[[nodiscard]] T read_at(Endian endian, const std::byte* p) noexcept {
    return endian == Endian::Big ? read_be_at<T>(p) : read_le_at<T>(p);
}

[[nodiscard]] Shdr read_shdr(Endian endian, const std::byte* p) noexcept {
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

[[nodiscard]] Shdr shdr_at(Endian endian, const std::byte* shtab, u16 idx) noexcept {
    return read_shdr(endian, shtab + static_cast<std::size_t>(idx) * kShdr64Size);
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
        default:          return Arch::Unknown;
    }
}

[[nodiscard]] SymbolKind symbol_kind_from_info(u8 info) noexcept {
    switch (info & 0xf) {
        case stt::FUNC:    return SymbolKind::Function;
        case stt::OBJECT:  return SymbolKind::Object;
        case stt::SECTION: return SymbolKind::Section;
        case stt::FILE_:   return SymbolKind::File;
        default:           return SymbolKind::Unknown;
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

    if (r.size() < kEhdr64Size) {
        return std::unexpected(Error::truncated(std::format(
            "elf: file smaller than ELF64 header ({} < {})", r.size(), kEhdr64Size)));
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
    if (ei_class != ei::CLASS_64) {
        return std::unexpected(Error::unsupported(std::format(
            "elf: only ELFCLASS64 supported (got {})", ei_class)));
    }
    if (ei_data != ei::DATA_LSB && ei_data != ei::DATA_MSB) {
        return std::unexpected(Error::unsupported(std::format(
            "elf: unsupported ELF byte order {}", ei_data)));
    }
    endian_ = (ei_data == ei::DATA_MSB) ? Endian::Big : Endian::Little;

    return ParsedEhdr{
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
    if (h.e_phentsize != kPhdr64Size) {
        return std::unexpected(Error::invalid_format(std::format(
            "elf: unexpected e_phentsize {} (want {})",
            h.e_phentsize, kPhdr64Size)));
    }
    const ByteReader r(buffer_);
    const std::size_t phtab_bytes =
        static_cast<std::size_t>(h.e_phentsize) * h.e_phnum;
    auto phtab = r.slice(h.e_phoff, phtab_bytes);
    if (!phtab) return std::unexpected(std::move(phtab).error());

    segments_.reserve(h.e_phnum);
    for (u16 i = 0; i < h.e_phnum; ++i) {
        const std::byte* const p =
            phtab->data() + static_cast<std::size_t>(i) * kPhdr64Size;
        const u32 p_type   = read_at<u32>(endian_, p + 0x00);
        const u32 p_flags  = read_at<u32>(endian_, p + 0x04);
        const u64 p_offset = read_at<u64>(endian_, p + 0x08);
        const u64 p_vaddr  = read_at<u64>(endian_, p + 0x10);
        const u64 p_filesz = read_at<u64>(endian_, p + 0x20);
        const u64 p_memsz  = read_at<u64>(endian_, p + 0x28);

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
        segments_.push_back(std::move(seg));
    }
    return {};
}

Result<void> ElfBinary::parse_sections(const ParsedEhdr& h) {
    if (h.e_shnum == 0) return {};
    if (h.e_shentsize != kShdr64Size) {
        return std::unexpected(Error::invalid_format(std::format(
            "elf: unexpected e_shentsize {} (want {})", h.e_shentsize, kShdr64Size)));
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

    const Shdr shstr_hdr = shdr_at(endian_, shtab->data(), h.e_shstrndx);
    auto shstr_bytes = r.slice(shstr_hdr.offset, shstr_hdr.size);
    if (!shstr_bytes) return std::unexpected(std::move(shstr_bytes).error());
    const ByteReader shstr_r(*shstr_bytes);

    sections_.reserve(h.e_shnum);
    for (u16 i = 0; i < h.e_shnum; ++i) {
        const Shdr sh = shdr_at(endian_, shtab->data(), i);

        Section s;
        if (auto name = shstr_r.read_cstr(sh.name); name) {
            s.name = std::string(*name);
        } else {
            s.name = std::format("<section-{}>", i);
        }
        s.vaddr       = sh.addr;
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
                continue;
            }
        }
        sections_.push_back(std::move(s));
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
    const std::size_t abs_max_syms = buffer_.size() / kSym64Size;
    std::size_t total_syms = 0;
    for (u16 i = 0; i < h.e_shnum; ++i) {
        const Shdr sh = shdr_at(endian_, shtab->data(), i);
        if (sh.type != sht::SYMTAB && sh.type != sht::DYNSYM) continue;
        if (sh.entsize == kSym64Size) total_syms += sh.size / kSym64Size;
    }
    if (total_syms > abs_max_syms) total_syms = abs_max_syms;
    symbols_.reserve(total_syms);

    for (u16 i = 0; i < h.e_shnum; ++i) {
        const Shdr sh = shdr_at(endian_, shtab->data(), i);
        if (sh.type != sht::SYMTAB && sh.type != sht::DYNSYM) continue;
        if (sh.entsize != kSym64Size) {
            return std::unexpected(Error::invalid_format(std::format(
                "elf: unexpected sym entsize {} in section {} (want {})",
                sh.entsize, i, kSym64Size)));
        }
        if (sh.link >= h.e_shnum) {
            return std::unexpected(Error::invalid_format(std::format(
                "elf: symtab {} has bad strtab link {}", i, sh.link)));
        }

        const Shdr strtab_hdr = shdr_at(endian_, shtab->data(), static_cast<u16>(sh.link));
        auto strtab_bytes = r.slice(strtab_hdr.offset, strtab_hdr.size);
        if (!strtab_bytes) return std::unexpected(std::move(strtab_bytes).error());
        const ByteReader str_r(*strtab_bytes);

        auto sym_bytes = r.slice(sh.offset, sh.size);
        if (!sym_bytes) return std::unexpected(std::move(sym_bytes).error());

        const bool is_dynsym = (sh.type == sht::DYNSYM);
        const std::size_t count = sh.size / kSym64Size;
        const std::byte* const base = sym_bytes->data();

        if (is_dynsym) {
            dynsym_names.resize(count);
            dynsym_section = i;
            dynsym_section_seen = true;
        }

        for (std::size_t k = 0; k < count; ++k) {
            const std::byte* const p = base + k * kSym64Size;
            const u32 st_name  = read_at<u32>(endian_, p + 0);
            const u8  st_info  = read_at<u8>(endian_, p + 4);
            const u16 st_shndx = read_at<u16>(endian_, p + 6);
            const u64 st_value = read_at<u64>(endian_, p + 8);
            const u64 st_size  = read_at<u64>(endian_, p + 16);

            std::string name;
            if (auto nm = str_r.read_cstr(st_name); nm) {
                name = std::string(*nm);
            }

            if (is_dynsym) {
                dynsym_names[k] = name;
            }

            if (name.empty()) continue;

            Symbol sym;
            sym.name      = std::move(name);
            sym.addr      = st_value;
            sym.size      = st_size;
            sym.kind      = symbol_kind_from_info(st_info);
            sym.is_import = (st_shndx == 0);
            sym.is_export = is_dynsym && !sym.is_import;
            symbols_.push_back(std::move(sym));
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
    if (h.e_shnum == 0) return {};

    const ByteReader r(buffer_);
    const std::size_t shtab_bytes =
        static_cast<std::size_t>(h.e_shentsize) * h.e_shnum;
    auto shtab = r.slice(h.e_shoff, shtab_bytes);
    if (!shtab) return std::unexpected(std::move(shtab).error());

    for (u16 i = 0; i < h.e_shnum; ++i) {
        const Shdr sh = shdr_at(endian_, shtab->data(), i);
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
    // none exist — sectionless binaries synthesize their exec segment as
    // ".text" — fall back to scanning every executable section.
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

// Resolve a runtime virtual address to a span of file bytes, using the
// parsed PT_LOAD segments. Returns an empty span if the address falls
// outside any loadable segment's file-backed region (BSS tail or beyond).
// Used by the phdr-only path, which cannot go through Section records
// because there are none.
[[nodiscard]] static std::span<const std::byte>
vaddr_slice(std::span<const LoadSegment> segs, addr_t vaddr, u64 want) {
    for (const auto& seg : segs) {
        if (vaddr < seg.vaddr) continue;
        const u64 off = vaddr - seg.vaddr;
        if (off >= seg.filesz) continue;
        const u64 avail = seg.filesz - off;
        const u64 n = want == 0 ? avail : std::min(want, avail);
        if (off + n < off || seg.data.size() < static_cast<std::size_t>(off + n)) continue;
        return seg.data.subspan(static_cast<std::size_t>(off),
                                static_cast<std::size_t>(n));
    }
    return {};
}

// Count dynsym entries from DT_GNU_HASH. The standard trick: walk each
// non-empty bucket, follow its chain until a chain word has bit 0 set
// (end-of-chain marker); the symbol index at that point is the last
// symbol in the bucket. The maximum across buckets + 1 is the count.
[[nodiscard]] static std::size_t
count_dynsym_gnu(std::span<const std::byte> gh, Endian endian) {
    if (gh.size() < 16) return 0;
    const u32 nbuckets   = read_at<u32>(endian, gh.data() + 0);
    const u32 symoffset  = read_at<u32>(endian, gh.data() + 4);
    const u32 bloom_size = read_at<u32>(endian, gh.data() + 8);
    const std::size_t header = 16;
    const std::size_t bloom  = static_cast<std::size_t>(bloom_size) * 8;  // 64-bit words
    const std::size_t buckets_off = header + bloom;
    const std::size_t chains_off  = buckets_off + static_cast<std::size_t>(nbuckets) * 4;
    if (gh.size() < chains_off) return 0;

    u32 max_idx = symoffset == 0 ? 0 : symoffset - 1;
    for (u32 i = 0; i < nbuckets; ++i) {
        const u32 b = read_at<u32>(endian, gh.data() + buckets_off + i * 4);
        if (b == 0) continue;
        if (b < symoffset) continue;  // malformed — skip
        u32 idx = b;
        while (true) {
            const std::size_t chain_off =
                chains_off + static_cast<std::size_t>(idx - symoffset) * 4;
            if (chain_off + 4 > gh.size()) return 0;
            const u32 ch = read_at<u32>(endian, gh.data() + chain_off);
            if (ch & 1u) break;
            idx++;
        }
        if (idx > max_idx) max_idx = idx;
    }
    return static_cast<std::size_t>(max_idx) + 1;
}

// DT_HASH is the SysV hash table. Second word is nchain == dynsym count.
[[nodiscard]] static std::size_t
count_dynsym_sysv(std::span<const std::byte> h, Endian endian) {
    if (h.size() < 8) return 0;
    const u32 nbucket = read_at<u32>(endian, h.data() + 0);
    const u32 nchain  = read_at<u32>(endian, h.data() + 4);
    const std::size_t need = 8ULL + static_cast<std::size_t>(nbucket) * 4
                               + static_cast<std::size_t>(nchain)  * 4;
    if (need > h.size()) return 0;
    return nchain;
}

// Build a synthetic Section record from a file-backed region, tagged
// with the given name and flags. Lets downstream passes (eh_frame parser,
// PLT scanner, strings scanner) keep iterating `sections()` uniformly.
[[nodiscard]] static Section
make_section(std::string name, addr_t vaddr,
             std::span<const std::byte> data,
             bool exec, bool write) {
    Section s;
    s.name        = std::move(name);
    s.vaddr       = vaddr;
    s.file_offset = 0;
    s.size        = data.size();
    s.flags.allocated  = true;
    s.flags.readable   = true;
    s.flags.writable   = write;
    s.flags.executable = exec;
    s.data        = data;
    return s;
}

Result<void> ElfBinary::parse_from_phdr(const ParsedEhdr& h) {
    if (h.e_phnum == 0) return {};  // neither shdrs nor phdrs — nothing to do

    const ByteReader r(buffer_);
    auto phtab = r.slice(h.e_phoff, static_cast<std::size_t>(h.e_phentsize) * h.e_phnum);
    if (!phtab) return std::unexpected(std::move(phtab).error());

    // First pass: locate PT_DYNAMIC and PT_GNU_EH_FRAME so we know what
    // metadata is recoverable. Both are optional — a statically-linked or
    // no-EH binary will legitimately lack one or both.
    addr_t dyn_vaddr = 0; u64 dyn_memsz = 0;
    addr_t eh_hdr_vaddr = 0; u64 eh_hdr_memsz = 0;
    for (u16 i = 0; i < h.e_phnum; ++i) {
        const std::byte* const p =
            phtab->data() + static_cast<std::size_t>(i) * kPhdr64Size;
        const u32 p_type  = read_at<u32>(endian_, p + 0x00);
        const u64 p_vaddr = read_at<u64>(endian_, p + 0x10);
        const u64 p_memsz = read_at<u64>(endian_, p + 0x28);
        if (p_type == pt::DYNAMIC)      { dyn_vaddr    = p_vaddr; dyn_memsz    = p_memsz; }
        if (p_type == pt::GNU_EH_FRAME) { eh_hdr_vaddr = p_vaddr; eh_hdr_memsz = p_memsz; }
    }

    // Synthesize one pseudo-section per PT_LOAD so downstream analyses
    // that iterate `sections()` (strings, emitter data lookups) still
    // find the bytes. Name reflects the usual purpose of each segment's
    // permission bits — these are not canonical section names, just the
    // closest thing that makes disasm + xrefs read naturally.
    for (const auto& seg : segments_) {
        if (seg.data.empty()) continue;
        std::string name = seg.executable ? ".text"
                        : seg.writable    ? ".data"
                        :                   ".rodata";
        sections_.push_back(make_section(std::move(name), seg.vaddr, seg.data,
                                         seg.executable, seg.writable));
    }

    // Parse PT_DYNAMIC entries. Each is a pair of 64-bit words (tag, val).
    std::span<const std::byte> dynsym_bytes, dynstr_bytes, hash_bytes, gnu_hash_bytes;
    std::span<const std::byte> jmprel_bytes, rela_bytes;
    addr_t dynsym_vaddr = 0;
    u64    syment       = kSym64Size;
    u64    jmprel_sz    = 0;
    u64    rela_sz      = 0;
    if (dyn_vaddr != 0 && dyn_memsz >= 16) {
        auto dyn = vaddr_slice(segments_, dyn_vaddr, dyn_memsz);
        addr_t hash_vaddr = 0, gnu_hash_vaddr = 0, jmprel_vaddr = 0;
        addr_t strtab_vaddr = 0, rela_vaddr = 0;
        u64    strsz = 0;
        const std::size_t entries = dyn.size() / 16;
        for (std::size_t i = 0; i < entries; ++i) {
            const u64 tag = read_at<u64>(endian_, dyn.data() + i * 16 + 0);
            const u64 val = read_at<u64>(endian_, dyn.data() + i * 16 + 8);
            if (tag == dt::NULL_)     break;
            if (tag == dt::STRTAB)    strtab_vaddr   = val;
            if (tag == dt::SYMTAB)    dynsym_vaddr   = val;
            if (tag == dt::STRSZ)     strsz          = val;
            if (tag == dt::SYMENT)    syment         = val;
            if (tag == dt::HASH)      hash_vaddr     = val;
            if (tag == dt::GNU_HASH)  gnu_hash_vaddr = val;
            if (tag == dt::JMPREL)    jmprel_vaddr   = val;
            if (tag == dt::PLTRELSZ)  jmprel_sz      = val;
            if (tag == dt::RELA)      rela_vaddr     = val;
            if (tag == dt::RELASZ)    rela_sz        = val;
        }
        if (strtab_vaddr != 0 && strsz > 0) {
            dynstr_bytes = vaddr_slice(segments_, strtab_vaddr, strsz);
        }
        if (hash_vaddr != 0) {
            hash_bytes = vaddr_slice(segments_, hash_vaddr, 0);
        }
        if (gnu_hash_vaddr != 0) {
            gnu_hash_bytes = vaddr_slice(segments_, gnu_hash_vaddr, 0);
        }
        if (jmprel_vaddr != 0 && jmprel_sz > 0) {
            jmprel_bytes = vaddr_slice(segments_, jmprel_vaddr, jmprel_sz);
        }
        if (rela_vaddr != 0 && rela_sz > 0) {
            rela_bytes = vaddr_slice(segments_, rela_vaddr, rela_sz);
        }
    }

    // Count dynsym entries. Three strategies, in preference order:
    //   1. DT_HASH's nchain — exact count, always correct when present
    //      (older toolchains; musl).
    //   2. strtab_vaddr - symtab_vaddr — exact when strtab immediately
    //      follows symtab in memory, which every standard linker does.
    //      Works when only DT_GNU_HASH is present (modern default).
    //   3. DT_GNU_HASH symoffset + chain walk — lower bound only (misses
    //      imports, which live at [0, symoffset) in GNU hash's layout),
    //      used as last resort if neither (1) nor (2) is usable.
    std::size_t dynsym_count = 0;
    addr_t strtab_for_count_vaddr = 0;
    // Reparse DT_STRTAB out of the dynamic segment for the vaddr alone —
    // we have dynstr_bytes (its content) but not the runtime address as
    // a cheap u64. The alternative (threading strtab_vaddr out of the
    // first parse loop) is more plumbing for no functional difference.
    if (dyn_vaddr != 0 && dyn_memsz >= 16) {
        auto dyn = vaddr_slice(segments_, dyn_vaddr, dyn_memsz);
        const std::size_t entries = dyn.size() / 16;
        for (std::size_t i = 0; i < entries; ++i) {
            const u64 tag = read_at<u64>(endian_, dyn.data() + i * 16 + 0);
            const u64 val = read_at<u64>(endian_, dyn.data() + i * 16 + 8);
            if (tag == dt::NULL_)  break;
            if (tag == dt::STRTAB) strtab_for_count_vaddr = val;
        }
    }
    if (!hash_bytes.empty()) {
        dynsym_count = count_dynsym_sysv(hash_bytes, endian_);
    }
    // The max r_sym referenced by any relocation is an exact lower bound
    // on dynsym size. DT_GNU_HASH alone can't give us the total (imports
    // live at indices [0, symoffset) and aren't in the hash), but every
    // import IS referenced by a relocation — so max_rsym+1 captures them.
    if (dynsym_count == 0) {
        u32 max_rsym = 0;
        auto scan_rela_for_max = [&](std::span<const std::byte> bytes) {
            const std::size_t count = bytes.size() / kRela64Size;
            for (std::size_t k = 0; k < count; ++k) {
                const u64 r_info = read_at<u64>(endian_, bytes.data() + k * kRela64Size + 8);
                const u32 r_sym  = static_cast<u32>(r_info >> 32);
                if (r_sym > max_rsym) max_rsym = r_sym;
            }
        };
        scan_rela_for_max(jmprel_bytes);
        scan_rela_for_max(rela_bytes);
        if (max_rsym > 0) dynsym_count = max_rsym + 1;
    }
    // strtab-dynsym adjacency is exact when both live in the same PT_LOAD
    // segment (the common linker layout). If they're in different segments
    // — as on obfuscated binaries that move .dynstr into a writable segment
    // — the gap spans unrelated bytes and the count is meaningless.
    if (dynsym_count == 0
        && dynsym_vaddr != 0 && strtab_for_count_vaddr > dynsym_vaddr
        && syment > 0) {
        bool same_segment = false;
        for (const auto& seg : segments_) {
            if (dynsym_vaddr < seg.vaddr) continue;
            if (dynsym_vaddr >= seg.vaddr + seg.memsz) continue;
            same_segment = (strtab_for_count_vaddr < seg.vaddr + seg.memsz);
            break;
        }
        if (same_segment) {
            const u64 span = strtab_for_count_vaddr - dynsym_vaddr;
            dynsym_count = static_cast<std::size_t>(span / syment);
        }
    }
    if (dynsym_count == 0 && !gnu_hash_bytes.empty()) {
        dynsym_count = count_dynsym_gnu(gnu_hash_bytes, endian_);
    }

    std::vector<std::string> dynsym_names;
    if (dynsym_count > 0 && dynsym_vaddr != 0 && !dynstr_bytes.empty()
        && syment == kSym64Size) {
        const u64 dynsym_bytes_sz = dynsym_count * syment;
        if (dynsym_bytes_sz / syment != dynsym_count) {
            dynsym_count = 0; // overflow — abandon dynsym parsing
        } else {
            dynsym_bytes = vaddr_slice(segments_, dynsym_vaddr, dynsym_bytes_sz);
        }
        const ByteReader str_r(dynstr_bytes);
        dynsym_names.resize(dynsym_count);
        for (std::size_t k = 0; k < dynsym_count; ++k) {
            if ((k + 1) * syment > dynsym_bytes.size()) break;
            const std::byte* const p = dynsym_bytes.data() + k * syment;
            const u32 st_name  = read_at<u32>(endian_, p + 0);
            const u8  st_info  = read_at<u8>(endian_, p + 4);
            const u16 st_shndx = read_at<u16>(endian_, p + 6);
            const u64 st_value = read_at<u64>(endian_, p + 8);
            const u64 st_size  = read_at<u64>(endian_, p + 16);

            std::string name;
            if (auto nm = str_r.read_cstr(st_name); nm) name = std::string(*nm);
            dynsym_names[k] = name;
            if (name.empty()) continue;

            Symbol sym;
            sym.name      = std::move(name);
            sym.addr      = st_value;
            sym.size      = st_size;
            sym.kind      = symbol_kind_from_info(st_info);
            sym.is_import = (st_shndx == 0);
            sym.is_export = !sym.is_import;
            symbols_.push_back(std::move(sym));
        }
    }

    normalize_ppc64_descriptors();

    // Synthesize .dynsym / .dynstr / .eh_frame_hdr so passes that look for
    // them by name (the eh_frame analyser scans for `.eh_frame` and the
    // PLT scanner walks `.plt*`) have something to find. .plt isn't a
    // separate segment, but its bytes live inside the exec segment we
    // already named `.text`; leaving it unsynthesized means we skip PLT
    // stub→import resolution here, which is an accepted gap (pass 2).
    if (!dynsym_bytes.empty()) {
        sections_.push_back(make_section(".dynsym", dynsym_vaddr, dynsym_bytes, false, false));
    }
    if (!dynstr_bytes.empty()) {
        // Find its vaddr again — we stored it locally during parse.
        // Linear scan of segments so we don't have to plumb the vaddr out.
        addr_t va = 0;
        for (const auto& seg : segments_) {
            if (dynstr_bytes.data() >= seg.data.data() &&
                dynstr_bytes.data() <  seg.data.data() + seg.data.size()) {
                va = seg.vaddr + static_cast<addr_t>(dynstr_bytes.data() - seg.data.data());
                break;
            }
        }
        sections_.push_back(make_section(".dynstr", va, dynstr_bytes, false, false));
    }
    // .eh_frame_hdr lives at the PT_GNU_EH_FRAME vaddr; its first four
    // bytes are (version=1, eh_frame_ptr_enc, fde_count_enc, table_enc),
    // followed by the encoded eh_frame_ptr. Decoding that pointer gives us
    // .eh_frame's vaddr, which we can't recover any other way in a section-
    // less binary. We only need to support the one encoding GCC/clang
    // actually emit for eh_frame_ptr — DW_EH_PE_pcrel | DW_EH_PE_sdata4
    // (0x1B), a 4-byte signed offset relative to the byte being read.
    addr_t eh_frame_vaddr = 0;
    if (eh_hdr_vaddr != 0 && eh_hdr_memsz >= 8) {
        auto eh_hdr = vaddr_slice(segments_, eh_hdr_vaddr, eh_hdr_memsz);
        if (eh_hdr.size() >= 8) {
            sections_.push_back(make_section(".eh_frame_hdr", eh_hdr_vaddr, eh_hdr,
                                             false, false));
            const u8 eh_frame_ptr_enc = static_cast<u8>(eh_hdr[1]);
            if (eh_frame_ptr_enc == 0x1B) {  // pcrel | sdata4 — the common case
                const i32 raw = read_at<i32>(endian_, eh_hdr.data() + 4);
                // The pointer is read_at = eh_hdr_vaddr + 4 (offset of the
                // sdata4 field within .eh_frame_hdr).
                eh_frame_vaddr = static_cast<addr_t>(
                    static_cast<i64>(eh_hdr_vaddr + 4) + raw);
            }
        }
    }

    // Synthesize .eh_frame: we know the start vaddr but not a hard upper
    // bound. Hand the FDE walker the full rest of the containing segment;
    // its CIE/FDE length walk stops at the length==0 terminator naturally.
    if (eh_frame_vaddr != 0) {
        auto eh_bytes = vaddr_slice(segments_, eh_frame_vaddr, 0);
        if (!eh_bytes.empty()) {
            sections_.push_back(make_section(".eh_frame", eh_frame_vaddr, eh_bytes,
                                             false, false));
        }
    }

    // Walk every FDE in .eh_frame and seed a Function symbol for each.
    // On x86-64 GCC/clang emit unwind tables by default (-funwind-tables
    // is on unless you `-fno-*`), so this recovers essentially every
    // function in a stripped C++/C binary — what IDA/Ghidra do as well.
    // Named only if dynsym didn't already name that address; the FDE at
    // the entry point keeps the canonical `_start` name instead of `sub_`.
    std::unordered_map<addr_t, bool> named_defined;
    for (const auto& s : symbols_) {
        if (!s.is_import && s.addr != 0) named_defined[s.addr] = true;
    }
    const auto fdes = enumerate_fde_extents(*this);
    for (const auto& fde : fdes) {
        if (named_defined.count(fde.pc_begin)) continue;
        Symbol s;
        s.name      = (fde.pc_begin == entry_ && entry_ != 0)
                        ? std::string{"_start"}
                        : std::format("sub_{:x}", fde.pc_begin);
        s.addr      = fde.pc_begin;
        s.size      = fde.pc_range;
        s.kind      = SymbolKind::Function;
        s.is_import = false;
        s.is_export = true;
        symbols_.push_back(std::move(s));
        named_defined[fde.pc_begin] = true;
    }

    // Seed `_start` at the entry point if no FDE/dynsym already claimed it.
    // GCC does not emit an FDE for the hand-written _start stub in crt1.o
    // (leaf, no unwind), so when FDE recovery doesn't cover the entry this
    // fallback still surfaces one clickable function.
    if (entry_ != 0 && !named_defined.count(entry_)) {
        Symbol s;
        s.name      = "_start";
        s.addr      = entry_;
        s.size      = 0;
        s.kind      = SymbolKind::Function;
        s.is_import = false;
        s.is_export = true;
        symbols_.push_back(std::move(s));
    }

    // PLT → import attachment. Both DT_JMPREL (the PLT-specific rela
    // table on binaries that use lazy binding) and DT_RELA (the general
    // rela table; holds GLOB_DAT entries for imports on binaries that
    // bind at load time — tiny executables, -fno-plt builds) contribute
    // GOT-slot → name mappings. scan_plt_stubs then walks the executable
    // segments looking for `jmp [rip+disp]` stubs that target those slots
    // and attaches the resolved name to each import Symbol.
    std::unordered_map<addr_t, std::string> got_to_name;
    auto ingest_rela = [&](std::span<const std::byte> bytes) {
        if (bytes.empty() || dynsym_names.empty()) return;
        const std::size_t count = bytes.size() / kRela64Size;
        for (std::size_t k = 0; k < count; ++k) {
            const std::byte* const p = bytes.data() + k * kRela64Size;
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
    };
    ingest_rela(jmprel_bytes);
    ingest_rela(rela_bytes);
    if (!got_to_name.empty()) {
        // Mirror attach_got_addrs's effect: set Symbol.got_addr on matching
        // imports so the emitter can render indirect calls through the
        // correct name.
        std::unordered_map<std::string, addr_t> name_to_got;
        name_to_got.reserve(got_to_name.size());
        for (const auto& [g, n] : got_to_name) name_to_got.emplace(n, g);
        for (auto& sym : symbols_) {
            if (!sym.is_import) continue;
            auto it = name_to_got.find(sym.name);
            if (it == name_to_got.end()) continue;
            sym.got_addr = it->second;
        }
        scan_plt_stubs(got_to_name);
    }

    normalize_ppc64_descriptors();
    sort_and_dedupe_symbols();
    return {};
}

Result<void> ElfBinary::parse() {
    auto hdr = parse_ehdr();
    if (!hdr) return std::unexpected(std::move(hdr).error());

    arch_  = arch_from_machine(hdr->e_machine, /*is_64bit=*/true);
    entry_ = hdr->e_entry;

    if (auto rv = parse_segments(*hdr);  !rv) return std::unexpected(rv.error());
    if (hdr->e_shnum == 0) return parse_from_phdr(*hdr);
    if (auto rv = parse_sections(*hdr);  !rv) {
        sections_.clear();
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

}  // namespace ember
