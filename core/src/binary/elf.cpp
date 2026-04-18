#include <ember/binary/elf.hpp>

#include <algorithm>
#include <cstring>
#include <format>
#include <unordered_map>
#include <utility>
#include <vector>

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
constexpr u32 LOAD = 1;
}  // namespace pt

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
}  // namespace ei

namespace em {
constexpr u16 I386    = 3;
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

[[nodiscard]] Shdr read_shdr(const std::byte* p) noexcept {
    return {
        read_le_at<u32>(p + 0x00),
        read_le_at<u32>(p + 0x04),
        read_le_at<u64>(p + 0x08),
        read_le_at<u64>(p + 0x10),
        read_le_at<u64>(p + 0x18),
        read_le_at<u64>(p + 0x20),
        read_le_at<u32>(p + 0x28),
        read_le_at<u32>(p + 0x2c),
        read_le_at<u64>(p + 0x30),
        read_le_at<u64>(p + 0x38),
    };
}

[[nodiscard]] Arch arch_from_machine(u16 em, bool is_64bit) noexcept {
    switch (em) {
        case em::I386:    return Arch::X86;
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

Result<void> ElfBinary::parse() {
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
    if (ei_data != ei::DATA_LSB) {
        return std::unexpected(Error::unsupported(std::format(
            "elf: only ELFDATA2LSB supported (got {})", ei_data)));
    }

    const u16 e_machine   = read_le_at<u16>(ident + 0x12);
    const u64 e_entry     = read_le_at<u64>(ident + 0x18);
    const u64 e_phoff     = read_le_at<u64>(ident + 0x20);
    const u64 e_shoff     = read_le_at<u64>(ident + 0x28);
    const u16 e_phentsize = read_le_at<u16>(ident + 0x36);
    const u16 e_phnum     = read_le_at<u16>(ident + 0x38);
    const u16 e_shentsize = read_le_at<u16>(ident + 0x3a);
    const u16 e_shnum     = read_le_at<u16>(ident + 0x3c);
    const u16 e_shstrndx  = read_le_at<u16>(ident + 0x3e);

    arch_  = arch_from_machine(e_machine, /*is_64bit=*/true);
    entry_ = e_entry;

    // ---- Parse program headers (PT_LOAD segments) --------------------------
    // PT_LOAD is the authoritative runtime mapping. For relocatable .o files
    // there are no program headers; we fall through to sections in that case.
    if (e_phnum > 0) {
        if (e_phentsize != kPhdr64Size) {
            return std::unexpected(Error::invalid_format(std::format(
                "elf: unexpected e_phentsize {} (want {})",
                e_phentsize, kPhdr64Size)));
        }
        const std::size_t phtab_bytes =
            static_cast<std::size_t>(e_phentsize) * e_phnum;
        auto phtab = r.slice(e_phoff, phtab_bytes);
        if (!phtab) return std::unexpected(std::move(phtab).error());

        segments_.reserve(e_phnum);
        for (u16 i = 0; i < e_phnum; ++i) {
            const std::byte* const p =
                phtab->data() + static_cast<std::size_t>(i) * kPhdr64Size;
            const u32 p_type   = read_le_at<u32>(p + 0x00);
            const u32 p_flags  = read_le_at<u32>(p + 0x04);
            const u64 p_offset = read_le_at<u64>(p + 0x08);
            const u64 p_vaddr  = read_le_at<u64>(p + 0x10);
            const u64 p_filesz = read_le_at<u64>(p + 0x20);
            const u64 p_memsz  = read_le_at<u64>(p + 0x28);

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
    }

    // No sections? That's fine — we already have segments. Nothing else to do.
    if (e_shnum == 0) return {};

    if (e_shentsize != kShdr64Size) {
        return std::unexpected(Error::invalid_format(std::format(
            "elf: unexpected e_shentsize {} (want {})", e_shentsize, kShdr64Size)));
    }
    if (e_shstrndx >= e_shnum) {
        return std::unexpected(Error::invalid_format(std::format(
            "elf: e_shstrndx {} >= e_shnum {}", e_shstrndx, e_shnum)));
    }

    const std::size_t shtab_bytes = static_cast<std::size_t>(e_shentsize) * e_shnum;
    auto shtab = r.slice(e_shoff, shtab_bytes);
    if (!shtab) return std::unexpected(std::move(shtab).error());

    const auto shdr_at = [&](u16 idx) noexcept -> Shdr {
        return read_shdr(shtab->data() + static_cast<std::size_t>(idx) * kShdr64Size);
    };

    const Shdr shstr_hdr = shdr_at(e_shstrndx);
    auto shstr_bytes = r.slice(shstr_hdr.offset, shstr_hdr.size);
    if (!shstr_bytes) return std::unexpected(std::move(shstr_bytes).error());
    const ByteReader shstr_r(*shstr_bytes);

    sections_.reserve(e_shnum);
    for (u16 i = 0; i < e_shnum; ++i) {
        const Shdr sh = shdr_at(i);

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
            }
        }
        sections_.push_back(std::move(s));
    }

    // dynsym_names[k] is the raw name at position k in the .dynsym table,
    // indexed as relocations see it (empty string for unnamed entries).
    // This is what .rela.* relocation `sym` fields point into.
    std::vector<std::string> dynsym_names;
    u16 dynsym_section = 0;
    bool dynsym_section_seen = false;

    for (u16 i = 0; i < e_shnum; ++i) {
        const Shdr sh = shdr_at(i);
        if (sh.type != sht::SYMTAB && sh.type != sht::DYNSYM) continue;
        if (sh.entsize != kSym64Size) {
            return std::unexpected(Error::invalid_format(std::format(
                "elf: unexpected sym entsize {} in section {} (want {})",
                sh.entsize, i, kSym64Size)));
        }
        if (sh.link >= e_shnum) {
            return std::unexpected(Error::invalid_format(std::format(
                "elf: symtab {} has bad strtab link {}", i, sh.link)));
        }

        const Shdr strtab_hdr = shdr_at(static_cast<u16>(sh.link));
        auto strtab_bytes = r.slice(strtab_hdr.offset, strtab_hdr.size);
        if (!strtab_bytes) return std::unexpected(std::move(strtab_bytes).error());
        const ByteReader str_r(*strtab_bytes);

        auto sym_bytes = r.slice(sh.offset, sh.size);
        if (!sym_bytes) return std::unexpected(std::move(sym_bytes).error());

        const bool is_dynsym = (sh.type == sht::DYNSYM);
        const std::size_t count = sh.size / kSym64Size;
        symbols_.reserve(symbols_.size() + count);
        const std::byte* const base = sym_bytes->data();

        if (is_dynsym) {
            dynsym_names.resize(count);
            dynsym_section = i;
            dynsym_section_seen = true;
        }

        for (std::size_t k = 0; k < count; ++k) {
            const std::byte* const p = base + k * kSym64Size;
            const u32 st_name  = read_le_at<u32>(p + 0);
            const u8  st_info  = read_le_at<u8>(p + 4);
            const u16 st_shndx = read_le_at<u16>(p + 6);
            const u64 st_value = read_le_at<u64>(p + 8);
            const u64 st_size  = read_le_at<u64>(p + 16);

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

    // ---- Parse .rela.* sections: build got_addr → dynsym_name map ----------
    //
    // On x86-64 the dynamic linker fills GOT slots via JUMP_SLOT (for lazy
    // PLT binding of function imports) and GLOB_DAT (for global data
    // imports) relocations. Both give us (slot_vaddr, dynsym_index), which
    // we use to attach got_addr to each import Symbol by name.
    std::unordered_map<addr_t, std::string> got_to_name;

    if (dynsym_section_seen) {
        for (u16 i = 0; i < e_shnum; ++i) {
            const Shdr sh = shdr_at(i);
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
                const u64 r_offset = read_le_at<u64>(p + 0);
                const u64 r_info   = read_le_at<u64>(p + 8);
                const u32 r_type   = static_cast<u32>(r_info & 0xffffffffU);
                const u32 r_sym    = static_cast<u32>(r_info >> 32);

                if (r_type != rx64::JUMP_SLOT && r_type != rx64::GLOB_DAT) continue;
                if (r_sym >= dynsym_names.size()) continue;
                const std::string& name = dynsym_names[r_sym];
                if (name.empty()) continue;
                got_to_name.emplace(static_cast<addr_t>(r_offset), name);
            }
        }
    }

    // Attach got_addr to import Symbols by name (first match wins; dynamic
    // symbol names are unique within a binary).
    if (!got_to_name.empty()) {
        std::unordered_map<std::string, addr_t> name_to_got;
        name_to_got.reserve(got_to_name.size());
        for (const auto& [g, n] : got_to_name) name_to_got.emplace(n, g);
        for (auto& sym : symbols_) {
            if (!sym.is_import) continue;
            auto it = name_to_got.find(sym.name);
            if (it == name_to_got.end()) continue;
            sym.got_addr = it->second;
        }
    }

    // ---- Scan PLT sections: populate Symbol.addr for imports ---------------
    //
    // Walk each executable section whose name starts with ".plt". Decode
    // instructions linearly; every `jmp qword [rip + D]` either points at
    // a GOT slot we've already mapped (then we know the import) or isn't
    // an import stub (ignored). The stub's caller-visible address is taken
    // as the 16-byte-aligned slot start — this covers both classic
    // `jmp [GOT]; push; jmp .plt[0]` entries and modern
    // `endbr64; bnd jmp [GOT]` .plt.sec entries without needing to
    // enumerate prefix bytes.
    if (!got_to_name.empty() && arch_ == Arch::X86_64) {
        std::unordered_map<std::string, addr_t> import_stub_addr;
        const X64Decoder dec;

        for (const auto& sec : sections_) {
            if (!sec.flags.executable) continue;
            if (sec.data.empty()) continue;
            if (sec.name.rfind(".plt", 0) != 0) continue;  // starts with ".plt"

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
                            // Stub start = 16-byte-aligned floor of this jmp.
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
    return {};
}

}  // namespace ember
