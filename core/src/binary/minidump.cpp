#include <ember/binary/minidump.hpp>

#include <algorithm>
#include <cstdio>
#include <format>
#include <unordered_set>
#include <utility>

#include <ember/binary/pe_view.hpp>
#include <ember/common/bytes.hpp>

namespace ember {

namespace {

// MINIDUMP_HEADER (Microsoft, see <DbgHelp.h>):
//   u32 Signature       == 'MDMP' (0x504D444D)
//   u32 Version         (low 16 bits 0xA793, high 16 bits implementation-specific)
//   u32 NumberOfStreams
//   u32 StreamDirectoryRva
//   u32 CheckSum
//   u32 TimeDateStamp
//   u64 Flags
constexpr u32 kMdmpSignature   = 0x504D444Du;
constexpr u16 kMdmpVersionLo   = 0xA793u;

constexpr std::size_t kHeaderSize          = 32;
constexpr std::size_t kDirectoryEntrySize  = 12;   // u32 stream_type, u32 size, u32 rva

// Stream type IDs we consume.
enum : u32 {
    kThreadListStream     = 3,
    kModuleListStream     = 4,
    kMemoryListStream     = 5,
    kSystemInfoStream     = 7,
    kMemory64ListStream   = 9,
    kMemoryInfoListStream = 16,
};

// SystemInfoStream: u16 ProcessorArchitecture at offset 0.
//   PROCESSOR_ARCHITECTURE_INTEL  = 0
//   PROCESSOR_ARCHITECTURE_ARM    = 5
//   PROCESSOR_ARCHITECTURE_AMD64  = 9
//   PROCESSOR_ARCHITECTURE_ARM64  = 12
[[nodiscard]] Arch arch_from_processor(u16 p) noexcept {
    switch (p) {
        case 0:  return Arch::X86;
        case 5:  return Arch::Arm;
        case 9:  return Arch::X86_64;
        case 12: return Arch::Arm64;
        default: return Arch::Unknown;
    }
}

// MEMORY_BASIC_INFORMATION protection bits we care about.
//   PAGE_EXECUTE          = 0x10
//   PAGE_EXECUTE_READ     = 0x20
//   PAGE_EXECUTE_READWRITE= 0x40
//   PAGE_EXECUTE_WRITECOPY= 0x80
//   PAGE_READONLY         = 0x02
//   PAGE_READWRITE        = 0x04
//   PAGE_WRITECOPY        = 0x08
[[nodiscard]] SectionFlags flags_from_protection(u32 prot) noexcept {
    SectionFlags f;
    f.allocated  = true;
    f.executable = (prot & 0xF0u) != 0;
    f.readable   = (prot & 0xF6u) != 0 || f.executable;
    f.writable   = (prot & 0xCCu) != 0;
    return f;
}

// Conservative default when MemoryInfoListStream is absent — assume the
// range is at least readable. The CFG walker only attempts decode on
// ranges flagged executable, so a too-permissive default doesn't hurt.
constexpr SectionFlags kDefaultFlags = {
    .readable = true, .writable = false, .executable = true, .allocated = true,
};

// PE32+ header offsets we walk in the in-memory image. Mirrors the
// constants in pe.cpp; duplicated here to keep this TU self-contained.
constexpr std::size_t kPeDosLfanewOff   = 0x3C;
constexpr std::size_t kPeNtSigSize      = 4;
constexpr std::size_t kPeCoffHdrSize    = 20;
constexpr std::size_t kPeOptMagicOff    = 0x00;
constexpr std::size_t kPeOptNumRvaOff   = 0x6C;
constexpr std::size_t kPeOptDataDirOff  = 0x70;
constexpr std::size_t kPeDataDirEntry   = 8;
constexpr u16         kPeOptMagicPlus   = 0x020b;

// Strip directory components and a trailing ".dll" / ".DLL" / ".exe" /
// etc. extension to derive the prefix used for collision-disambiguated
// imports. `kernel32.dll` → `kernel32`, `KERNEL32.DLL` → `KERNEL32`,
// `foo` (no dot) → `foo`.
[[nodiscard]] std::string module_prefix(std::string_view basename) {
    const auto dot = basename.find_last_of('.');
    if (dot == std::string_view::npos) return std::string(basename);
    return std::string(basename.substr(0, dot));
}

// Try to read DOS+NT+OptionalHeader64 directly from the in-memory copy
// at `module_base`. Returns the data-directory array; empty vector means
// "module headers not in the dump, or malformed — skip silently".
[[nodiscard]] std::vector<pe::DataDirectory>
read_module_data_dirs(const Binary& bin, addr_t module_base) {
    const auto dos = bin.bytes_at(module_base);
    if (dos.size() < kPeDosLfanewOff + 4) return {};
    if (dos[0] != std::byte{'M'} || dos[1] != std::byte{'Z'}) return {};

    const u32 e_lfanew = read_le_at<u32>(dos.data() + kPeDosLfanewOff);
    const auto nt = bin.bytes_at(module_base + e_lfanew);
    if (nt.size() < kPeNtSigSize + kPeCoffHdrSize) return {};
    if (nt[0] != std::byte{'P'} || nt[1] != std::byte{'E'} ||
        nt[2] != std::byte{0}   || nt[3] != std::byte{0}) return {};

    const std::byte* coff = nt.data() + kPeNtSigSize;
    const u16 opt_size = read_le_at<u16>(coff + 0x10);
    if (opt_size < kPeOptDataDirOff) return {};

    const auto opt = bin.bytes_at(module_base + e_lfanew +
                                   kPeNtSigSize + kPeCoffHdrSize);
    if (opt.size() < opt_size) return {};

    const u16 magic = read_le_at<u16>(opt.data() + kPeOptMagicOff);
    if (magic != kPeOptMagicPlus) return {};   // PE32 (32-bit) not supported

    const u32 num_rva = read_le_at<u32>(opt.data() + kPeOptNumRvaOff);
    const std::size_t cap = (opt_size - kPeOptDataDirOff) / kPeDataDirEntry;
    const std::size_t count = std::min<std::size_t>(num_rva, cap);

    std::vector<pe::DataDirectory> out;
    out.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        const std::byte* p = opt.data() + kPeOptDataDirOff + i * kPeDataDirEntry;
        out.push_back({read_le_at<u32>(p), read_le_at<u32>(p + 4)});
    }
    return out;
}

}  // namespace

std::span<const std::byte>
MinidumpBinary::bytes_at(addr_t vaddr) const noexcept {
    // Binary search by range.vaddr (ranges_ is sorted, non-overlapping).
    auto it = std::upper_bound(
        ranges_.begin(), ranges_.end(), vaddr,
        [](addr_t v, const Range& r) { return v < r.vaddr; });
    if (it == ranges_.begin()) return {};
    --it;
    if (vaddr < it->vaddr) return {};
    const u64 off = vaddr - it->vaddr;
    if (off >= it->size) return {};
    const std::size_t avail = static_cast<std::size_t>(it->size - off);
    if (it->file_off + off >= buffer_.size()) return {};
    const std::size_t bound =
        std::min<std::size_t>(avail, buffer_.size() - (it->file_off + off));
    return std::span<const std::byte>(
        buffer_.data() + it->file_off + off, bound);
}

Result<std::unique_ptr<MinidumpBinary>>
MinidumpBinary::load_from_buffer(std::vector<std::byte> buffer) {
    auto out = std::unique_ptr<MinidumpBinary>(new MinidumpBinary(std::move(buffer)));
    if (auto rv = out->parse(); !rv) return std::unexpected(std::move(rv).error());
    return out;
}

Result<void> MinidumpBinary::parse() {
    const ByteReader r(buffer_);
    if (buffer_.size() < kHeaderSize) {
        return std::unexpected(Error::truncated(std::format(
            "minidump: header needs {} bytes, have {}", kHeaderSize, buffer_.size())));
    }
    auto sig_r = r.read_le<u32>(0);
    if (!sig_r) return std::unexpected(std::move(sig_r).error());
    if (*sig_r != kMdmpSignature) {
        return std::unexpected(Error::invalid_format(std::format(
            "minidump: bad signature {:#x}, expected {:#x}", *sig_r, kMdmpSignature)));
    }
    auto ver_r = r.read_le<u32>(4);
    if (!ver_r) return std::unexpected(std::move(ver_r).error());
    if ((*ver_r & 0xFFFFu) != kMdmpVersionLo) {
        return std::unexpected(Error::invalid_format(std::format(
            "minidump: bad version low-word {:#x}", *ver_r & 0xFFFFu)));
    }
    auto nstreams_r = r.read_le<u32>(8);
    if (!nstreams_r) return std::unexpected(std::move(nstreams_r).error());
    auto dir_rva_r = r.read_le<u32>(12);
    if (!dir_rva_r) return std::unexpected(std::move(dir_rva_r).error());

    const u32 nstreams = *nstreams_r;
    const u32 dir_rva  = *dir_rva_r;
    if (nstreams > (buffer_.size() - dir_rva) / kDirectoryEntrySize) {
        return std::unexpected(Error::truncated(std::format(
            "minidump: directory of {} streams overruns file", nstreams)));
    }

    // Find the streams we care about. Multiple of any kind is unusual but
    // legal — last-wins semantics match what WinDbg does.
    struct Loc { u32 size = 0; u32 rva = 0; bool present = false; };
    Loc sysinfo, modules, mem_list, mem64_list, mem_info;
    for (u32 i = 0; i < nstreams; ++i) {
        const std::size_t base = dir_rva + i * kDirectoryEntrySize;
        const u32 type = read_le_at<u32>(buffer_.data() + base);
        const u32 size = read_le_at<u32>(buffer_.data() + base + 4);
        const u32 rva  = read_le_at<u32>(buffer_.data() + base + 8);
        switch (type) {
            case kSystemInfoStream:     sysinfo    = {size, rva, true}; break;
            case kModuleListStream:     modules    = {size, rva, true}; break;
            case kMemoryListStream:     mem_list   = {size, rva, true}; break;
            case kMemory64ListStream:   mem64_list = {size, rva, true}; break;
            case kMemoryInfoListStream: mem_info   = {size, rva, true}; break;
            case kThreadListStream:     break;  // not consumed (yet)
            default: break;
        }
    }

    // SystemInfoStream — sets arch. Absent → arch stays Unknown and the
    // decoder layer will refuse to make a decoder; that's fine, the user
    // can still browse sections with a disassembler that understands more.
    if (sysinfo.present && sysinfo.size >= 2) {
        const u16 proc = read_le_at<u16>(buffer_.data() + sysinfo.rva);
        arch_ = arch_from_processor(proc);
    }

    // Memory ranges. Memory64List is the modern, contiguous form: one
    // base RVA followed by a sequence of (vaddr, size) pairs.
    if (mem64_list.present && mem64_list.size >= 16) {
        const std::size_t base = mem64_list.rva;
        const u64 nranges  = read_le_at<u64>(buffer_.data() + base);
        const u64 base_rva = read_le_at<u64>(buffer_.data() + base + 8);
        if (nranges > (buffer_.size() - base - 16) / 16) {
            return std::unexpected(Error::truncated(std::format(
                "minidump: memory64 list claims {} ranges", nranges)));
        }
        std::size_t cursor = static_cast<std::size_t>(base_rva);
        ranges_.reserve(static_cast<std::size_t>(nranges));
        for (u64 i = 0; i < nranges; ++i) {
            const std::size_t e = base + 16 + static_cast<std::size_t>(i) * 16;
            const u64 va  = read_le_at<u64>(buffer_.data() + e);
            const u64 sz  = read_le_at<u64>(buffer_.data() + e + 8);
            if (cursor > buffer_.size() || sz > buffer_.size() - cursor) {
                return std::unexpected(Error::truncated(std::format(
                    "minidump: memory64 range [{:#x}, +{:#x}) overruns file",
                    va, sz)));
            }
            ranges_.push_back({va, sz, cursor, kDefaultFlags});
            cursor += static_cast<std::size_t>(sz);
        }
    } else if (mem_list.present && mem_list.size >= 4) {
        // Legacy MINIDUMP_MEMORY_LIST: u32 nranges, then
        // MINIDUMP_MEMORY_DESCRIPTOR[]. Each descriptor is 16 bytes:
        //   u64 StartOfMemoryRange
        //   u32 DataSize    \  these two form a MINIDUMP_LOCATION_DESCRIPTOR
        //   u32 Rva         /
        const std::size_t base = mem_list.rva;
        const u32 nranges = read_le_at<u32>(buffer_.data() + base);
        if (nranges > (buffer_.size() - base - 4) / 16) {
            return std::unexpected(Error::truncated(std::format(
                "minidump: memory list claims {} ranges", nranges)));
        }
        ranges_.reserve(nranges);
        for (u32 i = 0; i < nranges; ++i) {
            const std::size_t e = base + 4 + static_cast<std::size_t>(i) * 16;
            const u64 va  = read_le_at<u64>(buffer_.data() + e);
            const u32 sz  = read_le_at<u32>(buffer_.data() + e + 8);
            const u32 rva = read_le_at<u32>(buffer_.data() + e + 12);
            if (rva > buffer_.size() || sz > buffer_.size() - rva) {
                return std::unexpected(Error::truncated(std::format(
                    "minidump: memory range [{:#x}, +{:#x}) overruns file",
                    va, u64{sz})));
            }
            ranges_.push_back({va, sz, rva, kDefaultFlags});
        }
    }

    std::sort(ranges_.begin(), ranges_.end(),
              [](const Range& a, const Range& b) { return a.vaddr < b.vaddr; });

    // Optional MemoryInfoListStream — refines per-range page protection.
    // Layout: u32 SizeOfHeader, u32 SizeOfEntry, u64 NumberOfEntries,
    // then NumberOfEntries * SizeOfEntry bytes. Each entry's first 8
    // bytes are the BaseAddress (u64); Protect is at offset 0x18 (u32).
    if (mem_info.present && mem_info.size >= 16) {
        const std::size_t base = mem_info.rva;
        const u32 header_sz = read_le_at<u32>(buffer_.data() + base);
        const u32 entry_sz  = read_le_at<u32>(buffer_.data() + base + 4);
        const u64 nentries  = read_le_at<u64>(buffer_.data() + base + 8);
        if (entry_sz >= 0x1C && header_sz <= mem_info.size &&
            nentries <= (buffer_.size() - base - header_sz) / entry_sz) {
            for (u64 i = 0; i < nentries; ++i) {
                const std::size_t e = base + header_sz +
                                       static_cast<std::size_t>(i) * entry_sz;
                const u64 va   = read_le_at<u64>(buffer_.data() + e);
                const u32 prot = read_le_at<u32>(buffer_.data() + e + 0x18);
                // Apply to any range whose start matches; ranges captured
                // by the dumper align with the regions reported here.
                for (auto& rg : ranges_) {
                    if (rg.vaddr == va) {
                        rg.flags = flags_from_protection(prot);
                        break;
                    }
                }
            }
        }
    }

    // Synthesize one Section per range so the rest of the pipeline (CFG
    // walker, --info, scripting) sees something familiar.
    sections_.reserve(ranges_.size());
    for (const auto& rg : ranges_) {
        Section s;
        s.name        = std::format("mem_{:x}", rg.vaddr);
        s.vaddr       = rg.vaddr;
        s.file_offset = rg.file_off;
        s.size        = rg.size;
        s.flags       = rg.flags;
        const std::size_t bound =
            std::min<std::size_t>(static_cast<std::size_t>(rg.size),
                                   buffer_.size() - rg.file_off);
        s.data = std::span<const std::byte>(buffer_.data() + rg.file_off, bound);
        sections_.push_back(std::move(s));
    }

    // ModuleListStream: synthesize one Symbol per loaded module so the
    // user can `-s <module-basename>` to decompile from the module's
    // entry, then walk each module's in-memory PE headers to recover
    // its named exports + IAT imports. Modules whose headers were not
    // captured by the dumper are silently skipped (no PE walk done).
    //
    // MINIDUMP_MODULE layout (108 bytes):
    //   0x00  u64 BaseOfImage
    //   0x08  u32 SizeOfImage
    //   0x0C  u32 CheckSum
    //   0x10  u32 TimeDateStamp
    //   0x14  u32 ModuleNameRva   → MINIDUMP_STRING (u32 len_in_bytes + UTF-16LE)
    //   0x18  VS_FIXEDFILEINFO (52 bytes)
    //   0x4C  MINIDUMP_LOCATION_DESCRIPTOR CvRecord
    //   0x54  MINIDUMP_LOCATION_DESCRIPTOR MiscRecord
    //   0x5C  u64 reserved0
    //   0x64  u64 reserved1
    if (modules.present && modules.size >= 4) {
        const std::size_t base = modules.rva;
        const u32 nmods = read_le_at<u32>(buffer_.data() + base);
        if (nmods > (buffer_.size() - base - 4) / 108) {
            return std::unexpected(Error::truncated(std::format(
                "minidump: module list claims {} modules", nmods)));
        }
        symbols_.reserve(nmods);
        for (u32 i = 0; i < nmods; ++i) {
            const std::size_t e = base + 4 + static_cast<std::size_t>(i) * 108;
            const u64 mbase   = read_le_at<u64>(buffer_.data() + e);
            const u32 msize   = read_le_at<u32>(buffer_.data() + e + 0x08);
            const u32 name_rva = read_le_at<u32>(buffer_.data() + e + 0x14);

            std::string name;
            if (name_rva + 4 <= buffer_.size()) {
                const u32 name_bytes = read_le_at<u32>(buffer_.data() + name_rva);
                const std::size_t s_off = name_rva + 4;
                if (name_bytes <= buffer_.size() - s_off) {
                    // Decode the UTF-16LE string. ASCII-only fast path —
                    // a non-ASCII high byte gets replaced with '?' so we
                    // never produce an unprintable Symbol::name. Module
                    // names in practice are filesystem paths (ASCII).
                    name.reserve(name_bytes / 2);
                    for (u32 k = 0; k + 1 < name_bytes; k += 2) {
                        const u16 cu = read_le_at<u16>(buffer_.data() + s_off + k);
                        name.push_back(cu < 0x80 ? static_cast<char>(cu) : '?');
                    }
                    // Trim to basename — minidump stores full paths
                    // (e.g. C:\Windows\System32\kernel32.dll), but
                    // Ember's symbol display is friendlier with just
                    // `kernel32.dll`.
                    const auto sep = name.find_last_of("\\/");
                    if (sep != std::string::npos) name.erase(0, sep + 1);
                }
            }
            if (name.empty()) name = std::format("module_{:x}", mbase);

            Symbol s;
            s.name = std::move(name);
            s.addr = mbase;
            s.size = msize;
            s.kind = SymbolKind::Section;   // module spans aren't
                                            // functions; closest match
            const std::string mod_basename = s.name;
            symbols_.push_back(std::move(s));

            // Per-module PE walk. Wrap defensively — a malformed module
            // (corrupted in-memory headers, partial capture) must not
            // poison the load. read_module_data_dirs returns an empty
            // vector on any structural problem; we just skip those.
            const auto dirs = read_module_data_dirs(*this, mbase);
            if (dirs.empty()) continue;

            std::vector<Symbol> mod_syms;
            if (auto rv = pe::collect_exports(*this, mbase, dirs, mod_syms); !rv) {
                std::fprintf(stderr,
                    "minidump: module %s exports parse failed: %s\n",
                    mod_basename.c_str(), rv.error().message.c_str());
                continue;
            }
            if (auto rv = pe::collect_imports(*this, mbase, dirs, mod_syms); !rv) {
                std::fprintf(stderr,
                    "minidump: module %s imports parse failed: %s\n",
                    mod_basename.c_str(), rv.error().message.c_str());
                continue;
            }

            // Collision-prefix pass. The first occurrence of a name
            // across the whole symbol table keeps the bare form; later
            // duplicates (same name from another module) get
            // "<modulename>!" prepended so callers can still address
            // each one unambiguously.
            const std::string prefix = module_prefix(mod_basename);
            std::unordered_set<std::string> existing;
            existing.reserve(symbols_.size());
            for (const auto& sym : symbols_) existing.insert(sym.name);

            symbols_.reserve(symbols_.size() + mod_syms.size());
            for (auto& sym : mod_syms) {
                if (existing.contains(sym.name)) {
                    sym.name = std::format("{}!{}", prefix, sym.name);
                }
                existing.insert(sym.name);
                symbols_.push_back(std::move(sym));
            }
        }
    }

    return {};
}

}  // namespace ember
