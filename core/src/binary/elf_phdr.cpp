#include <ember/binary/elf.hpp>

#include <algorithm>
#include <cstddef>
#include <expected>
#include <format>
#include <span>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <ember/analysis/eh_frame.hpp>
#include <ember/binary/section.hpp>
#include <ember/binary/symbol.hpp>
#include <ember/common/bytes.hpp>
#include <ember/common/error.hpp>
#include <ember/common/types.hpp>

#include "elf_internal.hpp"

namespace ember {

namespace {

using elf::kPhdr64Size;
using elf::kRela64Size;
using elf::kSym64Size;
using elf::read_at;
using elf::symbol_kind_from_info;

namespace dt = elf::dt;
namespace pt = elf::pt;
namespace rx64 = elf::rx64;

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
        if (b < symoffset) continue;  // malformed - skip
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

}  // namespace

Result<void> ElfBinary::parse_from_phdr(const ParsedEhdr& h) {
    if (h.e_phnum == 0) return {};  // neither shdrs nor phdrs - nothing to do

    const ByteReader r(buffer_);
    auto phtab = r.slice(h.e_phoff, static_cast<std::size_t>(h.e_phentsize) * h.e_phnum);
    if (!phtab) return std::unexpected(std::move(phtab).error());

    if (!h.is_64bit) {
        for (const auto& seg : segments_) {
            if (seg.data.empty()) continue;
            std::string name = seg.executable ? ".text"
                            : seg.writable    ? ".data"
                            :                   ".rodata";
            sections_.push_back(make_section(std::move(name), seg.vaddr, seg.data,
                                             seg.executable, seg.writable));
        }
        if (entry_ != 0) {
            Symbol s;
            s.name      = "_start";
            s.addr      = entry_;
            s.size      = 0;
            s.kind      = SymbolKind::Function;
            s.is_import = false;
            s.is_export = true;
            symbols_.push_back(std::move(s));
        }
        sort_and_dedupe_symbols();
        return {};
    }

    // First pass: locate PT_DYNAMIC and PT_GNU_EH_FRAME so we know what
    // metadata is recoverable. Both are optional - a statically-linked or
    // no-EH binary will legitimately lack one or both.
    addr_t dyn_vaddr = 0; u64 dyn_memsz = 0;
    addr_t eh_hdr_vaddr = 0; u64 eh_hdr_memsz = 0;
    for (u32 i = 0; i < h.e_phnum; ++i) {
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
    // permission bits - these are not canonical section names, just the
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
    //   1. DT_HASH's nchain - exact count, always correct when present
    //      (older toolchains; musl).
    //   2. strtab_vaddr - symtab_vaddr - exact when strtab immediately
    //      follows symtab in memory, which every standard linker does.
    //      Works when only DT_GNU_HASH is present (modern default).
    //   3. DT_GNU_HASH symoffset + chain walk - lower bound only (misses
    //      imports, which live at [0, symoffset) in GNU hash's layout),
    //      used as last resort if neither (1) nor (2) is usable.
    std::size_t dynsym_count = 0;
    addr_t strtab_for_count_vaddr = 0;
    // Reparse DT_STRTAB out of the dynamic segment for the vaddr alone -
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
    // import IS referenced by a relocation - so max_rsym+1 captures them.
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
    // - as on obfuscated binaries that move .dynstr into a writable segment
    // - the gap spans unrelated bytes and the count is meaningless.
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
            dynsym_count = 0; // overflow - abandon dynsym parsing
        } else {
            dynsym_bytes = vaddr_slice(segments_, dynsym_vaddr, dynsym_bytes_sz);
        }
        // The count came from header arithmetic; the bytes we could map
        // are the real bound.
        dynsym_count = std::min(dynsym_count, dynsym_bytes.size() / syment);
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
        // Find its vaddr again - we stored it locally during parse.
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
    // actually emit for eh_frame_ptr - DW_EH_PE_pcrel | DW_EH_PE_sdata4
    // (0x1B), a 4-byte signed offset relative to the byte being read.
    addr_t eh_frame_vaddr = 0;
    if (eh_hdr_vaddr != 0 && eh_hdr_memsz >= 8) {
        auto eh_hdr = vaddr_slice(segments_, eh_hdr_vaddr, eh_hdr_memsz);
        if (eh_hdr.size() >= 8) {
            sections_.push_back(make_section(".eh_frame_hdr", eh_hdr_vaddr, eh_hdr,
                                             false, false));
            const u8 eh_frame_ptr_enc = static_cast<u8>(eh_hdr[1]);
            if (eh_frame_ptr_enc == 0x1B) {  // pcrel | sdata4 - the common case
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
    // function in a stripped C++/C binary - what IDA/Ghidra do as well.
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
    // bind at load time - tiny executables, -fno-plt builds) contribute
    // GOT-slot → name mappings. scan_plt_stubs then walks the executable
    // segments looking for `jmp [rip+disp]` stubs that target those slots
    // and attaches the resolved name to each import Symbol.
    std::unordered_map<addr_t, std::string> got_to_name;
    auto ingest_rela = [&](std::span<const std::byte> bytes) {
        if (arch_ != Arch::X86_64 || bytes.empty() || dynsym_names.empty()) return;
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

}  // namespace ember
