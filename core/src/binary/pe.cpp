#include <ember/binary/pe.hpp>
#include <ember/binary/pe_view.hpp>

#include <algorithm>
#include <cstring>
#include <format>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

#include <ember/analysis/pe_unwind.hpp>
#include <ember/binary/pdb.hpp>
#include <ember/common/bytes.hpp>
#include <ember/disasm/instruction.hpp>
#include <ember/disasm/x64_decoder.hpp>

namespace ember {

namespace {

constexpr std::size_t kDosHdrMinSize = 0x40;
constexpr std::size_t kDosLfanewOff  = 0x3C;
constexpr std::size_t kNtSigSize     = 4;
constexpr std::size_t kCoffHdrSize   = 20;
constexpr std::size_t kSectionHdrSize = 40;
constexpr std::size_t kDataDirEntry  = 8;

// Optional header magic values.
constexpr u16 kOptMagicPe32    = 0x010b;
constexpr u16 kOptMagicPe32Plus = 0x020b;

// Offsets inside the IMAGE_FILE_HEADER (COFF header).
constexpr std::size_t kCoffMachineOff       = 0x00;
constexpr std::size_t kCoffNumSectionsOff   = 0x02;
constexpr std::size_t kCoffSizeOfOptHdrOff  = 0x10;

// Offsets inside the PE32+ IMAGE_OPTIONAL_HEADER64.
constexpr std::size_t kOptMagicOff            = 0x00;
constexpr std::size_t kOptAddressOfEntryOff   = 0x10;
constexpr std::size_t kOptImageBaseOff        = 0x18;
constexpr std::size_t kOptNumRvaAndSizesOff   = 0x6C;
constexpr std::size_t kOptDataDirOff          = 0x70;

// Machine types we care about.
constexpr u16 kMachineI386  = 0x014c;
constexpr u16 kMachineAmd64 = 0x8664;
constexpr u16 kMachineArm   = 0x01c0;
constexpr u16 kMachineArm64 = 0xaa64;

// IMAGE_SCN_* flags we map to SectionFlags.
constexpr u32 kScnCntCode    = 0x00000020;
constexpr u32 kScnCntInit    = 0x00000040;
constexpr u32 kScnCntUninit  = 0x00000080;
constexpr u32 kScnMemExecute = 0x20000000;
constexpr u32 kScnMemRead    = 0x40000000;
constexpr u32 kScnMemWrite   = 0x80000000;

// Data-directory indices we consume. The optional header carries 16 of
// these by convention; we only read the ones we use.
constexpr std::size_t kDdExport      = 0;
constexpr std::size_t kDdImport      = 1;
constexpr std::size_t kDdDebug       = 6;
constexpr std::size_t kDdTls         = 9;
constexpr std::size_t kDdDelayImport = 13;

// Import descriptor + export directory layout constants.
constexpr std::size_t kImportDescSize       = 20;
constexpr std::size_t kDelayImportDescSize  = 32;
constexpr u32         kDelayAttrRvaBased    = 0x1;
constexpr u64         kOrdinalFlagBit       = 0x8000'0000'0000'0000ULL;
constexpr std::size_t kExportDirSize        = 40;

[[nodiscard]] Arch arch_from_machine(u16 m) noexcept {
    switch (m) {
        case kMachineI386:  return Arch::X86;
        case kMachineAmd64: return Arch::X86_64;
        case kMachineArm:   return Arch::Arm;
        case kMachineArm64: return Arch::Arm64;
        default:            return Arch::Unknown;
    }
}

// Section names live in an 8-byte slot, NUL-padded on the right. Strings
// longer than 8 chars use a "/N" convention pointing into the COFF string
// table — COFF-object-only and rare in EXE/DLL images; we accept the
// short form and pass the "/N" literal through unmodified for v1.
//
// Some packers in the wild leave
// non-NUL garbage in the slot after the visible name, so a section that
// reads ".text" on disk comes back as ".text\xAA\xBB\xCC" and breaks
// every exact-match lookup downstream. Strip trailing non-printable
// bytes after the NUL stop so the canonical names round-trip.
[[nodiscard]] std::string read_section_name(const std::byte* p) noexcept {
    std::size_t len = 0;
    while (len < 8 && static_cast<char>(p[len]) != '\0') ++len;
    while (len > 0) {
        const auto c = static_cast<unsigned char>(p[len - 1]);
        if (c < 0x20 || c > 0x7E) --len;
        else break;
    }
    return std::string(reinterpret_cast<const char*>(p), len);
}

}  // namespace

Result<std::unique_ptr<PeBinary>>
PeBinary::load_from_buffer(std::vector<std::byte> buffer) {
    std::unique_ptr<PeBinary> self(new PeBinary(std::move(buffer)));
    if (auto rv = self->parse(); !rv) {
        return std::unexpected(std::move(rv).error());
    }
    return self;
}

Result<PeBinary::ParsedHeaders> PeBinary::parse_headers() {
    const ByteReader r(buffer_);

    if (r.size() < kDosHdrMinSize) {
        return std::unexpected(Error::truncated(std::format(
            "pe: file smaller than DOS header ({} < {})", r.size(), kDosHdrMinSize)));
    }

    // DOS magic "MZ". load_binary already sniffed this, but re-checking
    // here makes PeBinary::load_from_buffer standalone-callable.
    if (buffer_[0] != std::byte{'M'} || buffer_[1] != std::byte{'Z'}) {
        return std::unexpected(Error::invalid_format("pe: bad DOS 'MZ' magic"));
    }

    auto e_lfanew_r = r.read_le<u32>(kDosLfanewOff);
    if (!e_lfanew_r) return std::unexpected(std::move(e_lfanew_r).error());
    const std::size_t coff_sig_off = *e_lfanew_r;

    // PE signature: "PE\0\0".
    auto sig = r.slice(coff_sig_off, kNtSigSize);
    if (!sig) return std::unexpected(std::move(sig).error());
    if ((*sig)[0] != std::byte{'P'} || (*sig)[1] != std::byte{'E'} ||
        (*sig)[2] != std::byte{0}   || (*sig)[3] != std::byte{0}) {
        return std::unexpected(Error::invalid_format(std::format(
            "pe: bad NT signature at offset {:#x}", coff_sig_off)));
    }

    const std::size_t coff_off = coff_sig_off + kNtSigSize;
    auto coff = r.slice(coff_off, kCoffHdrSize);
    if (!coff) return std::unexpected(std::move(coff).error());

    const u16 machine      = read_le_at<u16>(coff->data() + kCoffMachineOff);
    const u16 num_sections = read_le_at<u16>(coff->data() + kCoffNumSectionsOff);
    const u16 opt_size     = read_le_at<u16>(coff->data() + kCoffSizeOfOptHdrOff);

    arch_ = arch_from_machine(machine);
    if (arch_ == Arch::Unknown) {
        return std::unexpected(Error::unsupported(std::format(
            "pe: unsupported machine type {:#x}", machine)));
    }
    if (num_sections == 0) {
        return std::unexpected(Error::invalid_format(
            "pe: COFF header reports zero sections"));
    }

    // Optional header. Must be at least large enough for the PE32+ fixed
    // portion (0x70 bytes) plus the data-directory count field itself.
    const std::size_t opt_off = coff_off + kCoffHdrSize;
    auto opt = r.slice(opt_off, opt_size);
    if (!opt) return std::unexpected(std::move(opt).error());

    if (opt_size < kOptDataDirOff) {
        return std::unexpected(Error::truncated(std::format(
            "pe: optional header size {:#x} < {:#x}", opt_size, kOptDataDirOff)));
    }

    const u16 opt_magic = read_le_at<u16>(opt->data() + kOptMagicOff);
    if (opt_magic == kOptMagicPe32) {
        return std::unexpected(Error::unsupported(
            "pe: PE32 (32-bit) not supported — PE32+ only"));
    }
    if (opt_magic != kOptMagicPe32Plus) {
        return std::unexpected(Error::invalid_format(std::format(
            "pe: unknown optional header magic {:#x}", opt_magic)));
    }

    const u32 entry_rva  = read_le_at<u32>(opt->data() + kOptAddressOfEntryOff);
    const u64 image_base = read_le_at<u64>(opt->data() + kOptImageBaseOff);
    const u32 num_rva    = read_le_at<u32>(opt->data() + kOptNumRvaAndSizesOff);

    return ParsedHeaders{
        .coff_off          = coff_off,
        .opt_off           = opt_off,
        .sec_tab_off       = opt_off + opt_size,
        .num_sections      = num_sections,
        .opt_size          = opt_size,
        .num_rva_and_sizes = num_rva,
        .image_base        = image_base,
        .entry_rva         = entry_rva,
    };
}

Result<void> PeBinary::parse_sections(const ParsedHeaders& h) {
    const ByteReader r(buffer_);
    const std::size_t sec_bytes =
        static_cast<std::size_t>(h.num_sections) * kSectionHdrSize;
    auto sec_tab = r.slice(h.sec_tab_off, sec_bytes);
    if (!sec_tab) return std::unexpected(std::move(sec_tab).error());

    sections_.reserve(h.num_sections);
    for (u16 i = 0; i < h.num_sections; ++i) {
        const std::byte* const p =
            sec_tab->data() + static_cast<std::size_t>(i) * kSectionHdrSize;

        const u32 virt_size      = read_le_at<u32>(p + 0x08);
        const u32 virt_rva       = read_le_at<u32>(p + 0x0C);
        const u32 raw_size       = read_le_at<u32>(p + 0x10);
        const u32 raw_ptr        = read_le_at<u32>(p + 0x14);
        const u32 characteristics = read_le_at<u32>(p + 0x24);

        Section s;
        s.name        = read_section_name(p + 0x00);
        s.vaddr       = h.image_base + static_cast<addr_t>(virt_rva);
        s.file_offset = static_cast<offset_t>(raw_ptr);
        s.size        = static_cast<u64>(virt_size);
        s.flags.readable   = (characteristics & kScnMemRead)    != 0;
        s.flags.writable   = (characteristics & kScnMemWrite)   != 0;
        s.flags.executable = (characteristics & kScnMemExecute) != 0;
        s.flags.allocated  = (characteristics & (kScnCntCode | kScnCntInit
                                                 | kScnCntUninit)) != 0;

        // File-backed bytes: min(VirtualSize, SizeOfRawData). SizeOfRawData
        // is rounded up to FileAlignment, so it can be larger than VS —
        // bytes past VS inside the raw-data slot are padding, not valid.
        // Uninitialized-data sections (.bss) usually have raw_size == 0;
        // their Section.data stays empty and the default bytes_at() walks
        // past them correctly.
        if (raw_size != 0 && virt_size != 0) {
            const std::size_t backed =
                std::min(static_cast<std::size_t>(raw_size),
                         static_cast<std::size_t>(virt_size));
            if (auto data = r.slice(raw_ptr, backed); data) {
                s.data = *data;
            }
            // A slice() failure here is either a short-read header (file
            // truncated) or a lying raw_ptr/raw_size; both are recoverable
            // by leaving Section.data empty — downstream will treat the
            // range as zero-init, same as .bss.
        }

        sections_.push_back(std::move(s));
    }
    return {};
}

Result<void> PeBinary::parse() {
    auto hdrs = parse_headers();
    if (!hdrs) return std::unexpected(std::move(hdrs).error());

    image_base_ = hdrs->image_base;
    entry_      = hdrs->image_base + static_cast<addr_t>(hdrs->entry_rva);

    // Data-directory array follows the fixed optional-header fields. Cap
    // the count at whatever fits inside the optional-header slice so a
    // malicious NumberOfRvaAndSizes can't read past it. The PE spec caps
    // this at 16 in practice but the field is u32 — trust the header size,
    // not the count.
    const std::size_t dd_capacity =
        (hdrs->opt_size > kOptDataDirOff)
            ? (hdrs->opt_size - kOptDataDirOff) / kDataDirEntry
            : 0;
    const std::size_t dd_count =
        std::min<std::size_t>(hdrs->num_rva_and_sizes, dd_capacity);

    const ByteReader r(buffer_);
    const std::size_t dd_off = hdrs->opt_off + kOptDataDirOff;
    data_dirs_.reserve(dd_count);
    for (std::size_t i = 0; i < dd_count; ++i) {
        const std::size_t p = dd_off + i * kDataDirEntry;
        auto va = r.read_le<u32>(p + 0);
        auto sz = r.read_le<u32>(p + 4);
        if (!va || !sz) break;
        data_dirs_.push_back({*va, *sz});
    }

    if (auto rv = parse_sections(*hdrs); !rv) return std::unexpected(rv.error());
    if (auto rv = validate_entry_rva(); !rv) return std::unexpected(rv.error());

    // Imports first (so got_addr lives on each Symbol before thunk scan
    // uses it to resolve stubs), then exports, then the thunk scan.
    std::unordered_map<addr_t, std::string> got_to_name;
    if (auto rv = parse_imports(got_to_name);       !rv) return std::unexpected(rv.error());
    if (auto rv = parse_delay_imports(got_to_name); !rv) return std::unexpected(rv.error());
    if (auto rv = parse_exports();                  !rv) return std::unexpected(rv.error());
    scan_iat_thunks(got_to_name);
    if (auto rv = parse_tls_callbacks();            !rv) return std::unexpected(rv.error());
    absorb_pdata_function_starts();
    parse_codeview_pdb_filename();
    sort_and_dedupe_symbols();
    return {};
}

Result<void> PeBinary::validate_entry_rva() const {
    if (entry_ == image_base_) return {};
    const auto entry_rva = static_cast<u32>(entry_ - image_base_);
    if (!rva_is_mapped(entry_rva)) {
        return std::unexpected(Error::invalid_format(std::format(
            "pe: entry RVA {:#x} does not map to file-backed bytes", entry_rva)));
    }
    return {};
}

Result<void> PeBinary::parse_tls_callbacks() {
    if (data_dirs_.size() <= kDdTls) return {};
    const auto& dd = data_dirs_[kDdTls];
    if (dd.size == 0 || dd.virtual_address == 0) return {};
    if (!rva_is_mapped(dd.virtual_address, 40)) return {};

    // IMAGE_TLS_DIRECTORY64 fields we use:
    //   +0x18: AddressOfCallBacks (u64 absolute VA → NULL-terminated u64[])
    // Other fields (StartAddressOfRawData, AddressOfIndex, SizeOfZeroFill,
    // Characteristics) describe the TLS data slot itself, which static
    // analysis doesn't act on.
    const auto tls = bytes_at_rva(dd.virtual_address);
    if (tls.size() < 40) return {};

    const u64 cb_array_va = read_le_at<u64>(tls.data() + 0x18);
    if (cb_array_va == 0) return {};

    // Walk callback array. Each entry is an absolute VA on PE+, terminated
    // by a zero entry. Cap at 256 to avoid a runaway loop on a corrupt
    // TLS directory pointing into junk.
    constexpr std::size_t kMaxCallbacks = 256;
    for (std::size_t i = 0; i < kMaxCallbacks; ++i) {
        const auto slot = bytes_at(cb_array_va + i * 8);
        if (slot.size() < 8) break;
        const u64 cb = read_le_at<u64>(slot.data());
        if (cb == 0) break;
        if (bytes_at(static_cast<addr_t>(cb)).empty()) continue;

        Symbol sym;
        sym.name = std::format("tls_callback_{}", i);
        sym.addr = cb;
        sym.kind = SymbolKind::Function;
        symbols_.push_back(std::move(sym));
    }
    return {};
}

std::span<const std::byte> PeBinary::bytes_at_rva(u32 rva) const noexcept {
    return pe::bytes_at_rva(*this, image_base_, rva);
}

bool PeBinary::rva_is_mapped(u32 rva, std::size_t min_size) const noexcept {
    return pe::rva_is_mapped(*this, image_base_, rva, min_size);
}

std::string_view PeBinary::cstr_at_rva(u32 rva) const noexcept {
    return pe::cstr_at_rva(*this, image_base_, rva);
}

Result<void>
PeBinary::parse_imports(std::unordered_map<addr_t, std::string>& got_to_name) {
    return pe::collect_imports(*this, image_base_, data_dirs_, symbols_, &got_to_name);
}

Result<void>
PeBinary::parse_delay_imports(std::unordered_map<addr_t, std::string>& got_to_name) {
    return pe::collect_delay_imports(*this, image_base_, data_dirs_, symbols_, &got_to_name);
}

Result<void> PeBinary::parse_exports() {
    return pe::collect_exports(*this, image_base_, data_dirs_, symbols_);
}

}  // namespace ember

namespace ember::pe {

Result<void>
collect_imports(const Binary& bin,
                addr_t image_base,
                std::span<const DataDirectory> dirs,
                std::vector<Symbol>& out,
                std::unordered_map<addr_t, std::string>* got_to_name) {
    if (dirs.size() <= kDdImport) return {};
    const auto& dd = dirs[kDdImport];
    if (dd.size == 0 || dd.virtual_address == 0) return {};
    if (!rva_is_mapped(bin, image_base, dd.virtual_address, kImportDescSize)) return {};

    // Array of IMAGE_IMPORT_DESCRIPTOR terminated by an all-zero record.
    // Cap the loop at dd.size / kImportDescSize so a malicious missing
    // terminator can't walk forever.
    const std::size_t max_descs = dd.size / kImportDescSize;
    u32 cur = dd.virtual_address;

    for (std::size_t i = 0; i < max_descs; ++i, cur += kImportDescSize) {
        const auto desc = bytes_at_rva(bin, image_base, cur);
        if (desc.size() < kImportDescSize) break;

        const u32 oft_rva     = read_le_at<u32>(desc.data() + 0x00);
        const u32 name_rva    = read_le_at<u32>(desc.data() + 0x0C);
        const u32 iat_rva     = read_le_at<u32>(desc.data() + 0x10);
        if ((oft_rva | name_rva | iat_rva) == 0) break;   // terminator
        if (!rva_is_mapped(bin, image_base, name_rva)) continue;

        // Walk INT and IAT in lockstep. INT gives us the hint/name; IAT
        // is the slot the loader overwrites with the resolved pointer.
        // If OriginalFirstThunk is zero (bound imports, older linkers),
        // fall back to FirstThunk for name lookup — the loader will
        // have overwritten it at runtime, but on the static image the
        // name entries are still intact.
        const u32 int_rva = (oft_rva != 0) ? oft_rva : iat_rva;

        for (u32 k = 0;; ++k) {
            const auto int_bytes = bytes_at_rva(bin, image_base, int_rva + k * 8);
            const auto iat_bytes = bytes_at_rva(bin, image_base, iat_rva + k * 8);
            if (int_bytes.size() < 8 || iat_bytes.size() < 8) break;
            const u64 thunk = read_le_at<u64>(int_bytes.data());
            if (thunk == 0) break;

            Symbol sym;
            sym.kind      = SymbolKind::Function;
            sym.is_import = true;
            sym.got_addr  = image_base + static_cast<addr_t>(iat_rva) + k * 8;

            if ((thunk & kOrdinalFlagBit) != 0) {
                const u16 ordinal = static_cast<u16>(thunk & 0xFFFFu);
                sym.name = std::format("Ordinal#{}", ordinal);
            } else {
                // IMAGE_IMPORT_BY_NAME: u16 hint, then C-string.
                const u32 hintname_rva = static_cast<u32>(thunk & 0xFFFF'FFFFULL);
                const auto nm = cstr_at_rva(bin, image_base, hintname_rva + 2);
                if (nm.empty()) continue;  // corrupt: no name, skip slot
                sym.name = std::string(nm);
            }

            if (got_to_name) got_to_name->emplace(sym.got_addr, sym.name);
            out.push_back(std::move(sym));
        }
    }
    return {};
}

// Delay-load descriptor format (ImgDelayDescr, 32 bytes):
//   u32 grAttrs;        // bit 0 set → all subsequent fields are RVAs
//   u32 rvaDLLName;
//   u32 rvaHmod;        // module-handle slot, populated at runtime
//   u32 rvaIAT;         // we treat this exactly like a regular IAT
//   u32 rvaINT;         // hint/name table, identical encoding to IMPORT
//   u32 rvaBoundIAT;    // pre-bound IAT (if linker bound at build time)
//   u32 rvaUnloadIAT;   // for FUnloadDelayLoadedDLL — we ignore
//   u32 dwTimeStamp;
// Walks identically to collect_imports once we've extracted INT/IAT RVAs.
// Older (non-x64) images had grAttrs == 0 with absolute VAs in every
// field — we reject those rather than try to guess the image base from
// addresses that may have been written under a different load address.
Result<void>
collect_delay_imports(const Binary& bin,
                      addr_t image_base,
                      std::span<const DataDirectory> dirs,
                      std::vector<Symbol>& out,
                      std::unordered_map<addr_t, std::string>* got_to_name) {
    if (dirs.size() <= kDdDelayImport) return {};
    const auto& dd = dirs[kDdDelayImport];
    if (dd.size == 0 || dd.virtual_address == 0) return {};
    if (!rva_is_mapped(bin, image_base, dd.virtual_address, kDelayImportDescSize)) return {};

    const std::size_t max_descs = dd.size / kDelayImportDescSize;
    u32 cur = dd.virtual_address;

    for (std::size_t i = 0; i < max_descs; ++i, cur += kDelayImportDescSize) {
        const auto desc = bytes_at_rva(bin, image_base, cur);
        if (desc.size() < kDelayImportDescSize) break;

        const u32 attrs    = read_le_at<u32>(desc.data() + 0x00);
        const u32 name_rva = read_le_at<u32>(desc.data() + 0x04);
        const u32 iat_rva  = read_le_at<u32>(desc.data() + 0x0C);
        const u32 int_rva  = read_le_at<u32>(desc.data() + 0x10);
        if ((attrs | name_rva | iat_rva | int_rva) == 0) break;  // terminator
        if (!rva_is_mapped(bin, image_base, name_rva)) continue;
        // Pre-x64 layout: ignore the slice rather than misread VAs as RVAs.
        if ((attrs & kDelayAttrRvaBased) == 0) continue;
        // Some linkers ship descriptors with no INT (rvaINT == 0); for the
        // statically-recorded names we *need* the INT, so skip — the IAT
        // alone is just patched function pointers at runtime.
        if (int_rva == 0 || iat_rva == 0) continue;

        for (u32 k = 0;; ++k) {
            const auto int_bytes = bytes_at_rva(bin, image_base, int_rva + k * 8);
            const auto iat_bytes = bytes_at_rva(bin, image_base, iat_rva + k * 8);
            if (int_bytes.size() < 8 || iat_bytes.size() < 8) break;
            const u64 thunk = read_le_at<u64>(int_bytes.data());
            if (thunk == 0) break;

            Symbol sym;
            sym.kind      = SymbolKind::Function;
            sym.is_import = true;
            sym.got_addr  = image_base + static_cast<addr_t>(iat_rva) + k * 8;

            if ((thunk & kOrdinalFlagBit) != 0) {
                const u16 ordinal = static_cast<u16>(thunk & 0xFFFFu);
                sym.name = std::format("Ordinal#{}", ordinal);
            } else {
                const u32 hintname_rva = static_cast<u32>(thunk & 0xFFFF'FFFFULL);
                const auto nm = cstr_at_rva(bin, image_base, hintname_rva + 2);
                if (nm.empty()) continue;
                sym.name = std::string(nm);
            }

            if (got_to_name) got_to_name->emplace(sym.got_addr, sym.name);
            out.push_back(std::move(sym));
        }
    }
    return {};
}

Result<void>
collect_exports(const Binary& bin,
                addr_t image_base,
                std::span<const DataDirectory> dirs,
                std::vector<Symbol>& out) {
    if (dirs.size() <= kDdExport) return {};
    const auto& dd = dirs[kDdExport];
    if (dd.size == 0 || dd.virtual_address == 0) return {};
    if (!rva_is_mapped(bin, image_base, dd.virtual_address, kExportDirSize)) return {};

    const auto edir = bytes_at_rva(bin, image_base, dd.virtual_address);
    if (edir.size() < kExportDirSize) return {};

    const u32 ordinal_base = read_le_at<u32>(edir.data() + 0x10);
    const u32 num_funcs    = read_le_at<u32>(edir.data() + 0x14);
    const u32 num_names    = read_le_at<u32>(edir.data() + 0x18);
    const u32 eat_rva      = read_le_at<u32>(edir.data() + 0x1C);
    const u32 ent_rva      = read_le_at<u32>(edir.data() + 0x20);
    const u32 eot_rva      = read_le_at<u32>(edir.data() + 0x24);

    // Forwarder exports point *into* the export data directory itself —
    // the RVA there is the "DLL.Symbol" redirect string, not a function
    // address. Skip them instead of emitting a garbage Symbol at a
    // string VA.
    const u32 dd_end = dd.virtual_address + dd.size;
    const auto is_forwarder = [&](u32 rva) noexcept {
        return rva >= dd.virtual_address && rva < dd_end;
    };

    // Named exports: walk ENT + EOT in parallel. EOT[i] is an index
    // into EAT (0-based, not ordinal-based).
    for (u32 i = 0; i < num_names; ++i) {
        const auto name_rva_bytes = bytes_at_rva(bin, image_base, ent_rva + i * 4);
        const auto ord_bytes      = bytes_at_rva(bin, image_base, eot_rva + i * 2);
        if (name_rva_bytes.size() < 4 || ord_bytes.size() < 2) break;
        const u32 name_rva = read_le_at<u32>(name_rva_bytes.data());
        const u16 eat_idx  = read_le_at<u16>(ord_bytes.data());
        if (eat_idx >= num_funcs) continue;

        const auto eat_bytes = bytes_at_rva(bin, image_base, eat_rva + eat_idx * 4);
        if (eat_bytes.size() < 4) continue;
        const u32 func_rva = read_le_at<u32>(eat_bytes.data());
        if (func_rva == 0 || is_forwarder(func_rva)) continue;

        const auto name = cstr_at_rva(bin, image_base, name_rva);
        if (name.empty()) continue;

        Symbol sym;
        sym.name      = std::string(name);
        sym.addr      = image_base + static_cast<addr_t>(func_rva);
        sym.kind      = SymbolKind::Function;
        sym.is_export = true;
        out.push_back(std::move(sym));
    }

    // Unnamed (ordinal-only) exports: any EAT slot not reached by EOT.
    // Build a bitmap of referenced indices, then emit "Ordinal#N" entries
    // for the gaps. Keeps addresses resolvable even without a name.
    std::vector<bool> named(num_funcs, false);
    for (u32 i = 0; i < num_names; ++i) {
        const auto ord_bytes = bytes_at_rva(bin, image_base, eot_rva + i * 2);
        if (ord_bytes.size() < 2) break;
        const u16 eat_idx = read_le_at<u16>(ord_bytes.data());
        if (eat_idx < num_funcs) named[eat_idx] = true;
    }
    for (u32 i = 0; i < num_funcs; ++i) {
        if (named[i]) continue;
        const auto eat_bytes = bytes_at_rva(bin, image_base, eat_rva + i * 4);
        if (eat_bytes.size() < 4) break;
        const u32 func_rva = read_le_at<u32>(eat_bytes.data());
        if (func_rva == 0 || is_forwarder(func_rva)) continue;

        Symbol sym;
        sym.name      = std::format("Ordinal#{}", ordinal_base + i);
        sym.addr      = image_base + static_cast<addr_t>(func_rva);
        sym.kind      = SymbolKind::Function;
        sym.is_export = true;
        out.push_back(std::move(sym));
    }
    return {};
}

}  // namespace ember::pe

namespace ember {

// Mirror of ElfBinary::scan_plt_stubs. Every `jmp qword ptr [rip + disp]`
// in an executable section whose RIP-relative target lands on a known IAT
// slot gives us the import stub's VA. MSVC and clang both emit these
// inline rather than in a dedicated section, so we scan *every* executable
// section rather than filtering by name.
//
// Hot path on cold-open: a naive "decode every offset" linear sweep over
// a 14 MB section costs ~300 ms. The opcode we're after is a fixed
// 6-byte sequence `FF 25 disp32`, so byte-pattern-scan for `FF 25`
// first and only fully decode the rare hits. Random byte distribution
// puts the candidate density at ~1/65k — three orders of magnitude
// fewer decode calls than the naive walk.
void PeBinary::scan_iat_thunks(
    const std::unordered_map<addr_t, std::string>& got_to_name) {
    if (got_to_name.empty() || arch_ != Arch::X86_64) return;

    std::unordered_map<std::string, addr_t> stub_by_name;
    const X64Decoder dec;

    constexpr std::byte kFF{0xFF};
    constexpr std::byte k25{0x25};

    for (const auto& sec : sections_) {
        if (!sec.flags.executable) continue;
        if (sec.data.empty()) continue;
        const auto bytes = sec.data;
        if (bytes.size() < 6) continue;

        // Linear byte-scan for `FF 25`. Each instruction is 6 bytes long
        // (FF 25 + 4-byte disp32), so when we land on a real one we can
        // resume scanning past it; when we hit a false positive (the
        // pattern inside an unrelated instruction's bytes), we just step
        // forward by 1.
        const addr_t base = sec.vaddr;
        const std::size_t end = bytes.size() - 1;
        for (std::size_t off = 0; off < end; ++off) {
            if (bytes[off] != kFF) continue;
            if (bytes[off + 1] != k25) continue;
            const addr_t ip = base + off;
            auto decoded = dec.decode(bytes.subspan(off), ip);
            if (!decoded) continue;
            const Instruction& insn = *decoded;
            if (insn.mnemonic != Mnemonic::Jmp || insn.num_operands != 1) {
                continue;
            }
            const Operand& op = insn.operands[0];
            if (op.kind != Operand::Kind::Memory) continue;
            if (op.mem.base != Reg::Rip) continue;
            if (op.mem.index != Reg::None) continue;
            if (!op.mem.has_disp) continue;
            const addr_t got = ip + insn.length +
                               static_cast<addr_t>(op.mem.disp);
            auto it = got_to_name.find(got);
            if (it == got_to_name.end()) continue;
            // First thunk wins for a given name — MSVC can emit
            // duplicate __imp_ thunks when a function is called from
            // multiple TUs with LTCG off.
            stub_by_name.try_emplace(it->second, ip);
            // Step past the consumed thunk. We still resume scanning
            // immediately after it (real code can place two thunks
            // back-to-back).
            off += insn.length - 1;     // -1 because the for-loop adds 1
        }
    }

    for (auto& sym : symbols_) {
        if (!sym.is_import) continue;
        if (sym.addr != 0) continue;
        auto it = stub_by_name.find(sym.name);
        if (it == stub_by_name.end()) continue;
        sym.addr = it->second;
    }
}

// Every non-leaf function on x64 carries a RUNTIME_FUNCTION in .pdata —
// this is PE's analogue of Mach-O LC_FUNCTION_STARTS. We (a) set size on
// every existing function symbol whose addr matches a .pdata begin, and
// (b) synthesize `sub_<hex>` entries for starts with no matching symbol.
// Without this, stripped PE EXEs show only exports + whatever linear
// sweep finds during CFG construction.
void PeBinary::absorb_pdata_function_starts() {
    const auto entries = parse_pe_pdata(*this);
    if (entries.empty()) return;

    std::unordered_map<addr_t, std::size_t> existing_by_addr;
    for (std::size_t i = 0; i < symbols_.size(); ++i) {
        const auto& s = symbols_[i];
        if (s.is_import) continue;
        if (s.kind != SymbolKind::Function) continue;
        existing_by_addr.emplace(s.addr, i);
    }

    for (const auto& e : entries) {
        const u64 size = (e.end > e.begin) ? (e.end - e.begin) : 0;
        if (auto it = existing_by_addr.find(e.begin); it != existing_by_addr.end()) {
            if (symbols_[it->second].size == 0) symbols_[it->second].size = size;
            continue;
        }
        Symbol synth;
        synth.name = std::format("sub_{:x}", e.begin);
        synth.addr = e.begin;
        synth.size = size;
        synth.kind = SymbolKind::Function;
        symbols_.push_back(std::move(synth));
    }
}

// Walk IMAGE_DIRECTORY_ENTRY_DEBUG. Each 28-byte entry has:
//   +0  Characteristics       u32 (must be 0)
//   +4  TimeDateStamp         u32
//   +8  MajorVersion/Minor    u16×2
//  +12  Type                  u32 (CODEVIEW = 2)
//  +16  SizeOfData            u32
//  +20  AddressOfRawData      u32 (RVA into the loaded image)
//  +24  PointerToRawData      u32 (file offset of the CV record)
// The CodeView "RSDS" record format inside the raw data:
//   +0  signature             "RSDS" (4 bytes)
//   +4  GUID                  16 bytes
//  +20  Age                   u32
//  +24  PdbFilename           null-terminated UTF-8
void PeBinary::parse_codeview_pdb_filename() {
    if (data_dirs_.size() <= kDdDebug) return;
    const auto& dd = data_dirs_[kDdDebug];
    if (dd.size == 0 || dd.virtual_address == 0) return;
    if (!rva_is_mapped(dd.virtual_address, dd.size)) return;

    const auto entries = bytes_at_rva(dd.virtual_address);
    if (entries.size() < dd.size) return;

    constexpr u32 kImageDebugTypeCodeview = 2;
    constexpr std::size_t kEntrySize = 28;
    for (std::size_t i = 0; i + kEntrySize <= dd.size; i += kEntrySize) {
        const std::byte* e = entries.data() + i;
        const u32 type    = read_le_at<u32>(e + 12);
        if (type != kImageDebugTypeCodeview) continue;
        const u32 raw_sz  = read_le_at<u32>(e + 16);
        const u32 raw_rva = read_le_at<u32>(e + 20);
        if (raw_sz < 24 + 1) continue;            // need at least an empty name
        if (!rva_is_mapped(raw_rva, raw_sz)) continue;
        const auto cv = bytes_at_rva(raw_rva);
        if (cv.size() < raw_sz) continue;

        // Match RSDS first (PDB v7); legacy NB10 (PDB v2) we ignore — the
        // current parser doesn't grok the older container format anyway.
        if (cv.size() < 4) continue;
        if (cv[0] != std::byte{'R'} || cv[1] != std::byte{'S'} ||
            cv[2] != std::byte{'D'} || cv[3] != std::byte{'S'}) continue;

        const std::size_t name_off = 24;          // signature + GUID + age
        if (raw_sz <= name_off) continue;
        const char* name_p = reinterpret_cast<const char*>(cv.data() + name_off);
        const std::size_t name_max = raw_sz - name_off;
        std::size_t name_len = 0;
        while (name_len < name_max && name_p[name_len] != '\0') ++name_len;
        if (name_len == 0) continue;
        pdb_filename_.assign(name_p, name_len);
        return;
    }
}

void PeBinary::sort_and_dedupe_symbols() {
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

Result<std::size_t>
PeBinary::attach_pdb_from_path(const std::filesystem::path& path) {
    auto rdr = pdb::load_pdb(path);
    if (!rdr) return std::unexpected(std::move(rdr).error());

    // Stash identity + path for the consumer-side mismatch check
    // (subcommands.cpp compares against the CodeView record). We do
    // NOT refuse the PDB here even on mismatch — the user may have
    // explicitly pointed --pdb at it, and a hard refusal at the
    // loader hides the warning we'd otherwise print.
    pdb_guid_           = rdr->info.guid;
    pdb_age_            = rdr->info.age;
    attached_pdb_path_  = path;

    // Resolve every (segment, offset) pair to an absolute VA. Keep
    // existing names — imports, exports, TLS callbacks all win on a
    // collision because they carry richer metadata (got_addr, is_import,
    // size). The PDB walk only contributes a name + address, which is
    // best-effort fallback information.
    std::unordered_map<addr_t, std::size_t> by_addr;
    by_addr.reserve(symbols_.size());
    for (std::size_t i = 0; i < symbols_.size(); ++i) {
        if (symbols_[i].addr != 0) by_addr.emplace(symbols_[i].addr, i);
    }

    auto resolve_va = [&](u16 segment, u32 offset) -> addr_t {
        if (segment == 0 || segment > sections_.size()) return 0;
        const Section& sec = sections_[segment - 1];
        const addr_t va = sec.vaddr + offset;
        return va < image_base_ ? 0 : va;
    };

    auto absorb_symbol = [&](addr_t va, std::string name, SymbolKind kind) {
        if (va == 0 || name.empty()) return false;
        if (auto it = by_addr.find(va); it != by_addr.end()) {
            // Already named — only fill in a name on a synthesized
            // `sub_<hex>` entry so the PDB upgrade is visible.
            Symbol& existing = symbols_[it->second];
            if (existing.name.starts_with("sub_")) {
                existing.name = std::move(name);
                return true;
            }
            return false;
        }
        Symbol s;
        s.name = std::move(name);
        s.addr = va;
        s.kind = kind;
        symbols_.push_back(std::move(s));
        by_addr.emplace(va, symbols_.size() - 1);
        return true;
    };

    std::size_t added = 0;
    for (const auto& p : rdr->publics) {
        if (absorb_symbol(resolve_va(p.segment, p.section_offset),
                          p.name,
                          p.is_function ? SymbolKind::Function : SymbolKind::Object)) {
            ++added;
        }
    }
    // Procs carry the same name+addr as publics for most builds, but
    // the *_ID variants only show up here. Run them through too.
    for (const auto& p : rdr->procs) {
        if (absorb_symbol(resolve_va(p.segment, p.section_offset),
                          p.name, SymbolKind::Function)) {
            ++added;
        }
    }
    // Globals: data symbols become Object-kind entries. Useful for
    // `extern int g_log_level;` style globals showing up in the
    // sidebar / symbols view with a real name.
    for (const auto& g : rdr->globals) {
        if (absorb_symbol(resolve_va(g.segment, g.section_offset),
                          g.name, SymbolKind::Object)) {
            ++added;
        }
    }

    // ----- Procedure → FunctionSig harvest --------------------------
    // For every proc symbol whose type_index points at an
    // LF_PROCEDURE / LF_MFUNCTION record, materialize a FunctionSig
    // (return type + arg list). Stored separately from the symbol
    // table; subcommands.cpp merges these into the per-emit
    // Annotations under user-explicit-still-wins precedence.
    auto resolve_args = [&](u32 arg_list_ti, u16 expected) -> std::vector<ParamSig> {
        std::vector<ParamSig> params;
        const pdb::TypeRecord* al = rdr->types.lookup(arg_list_ti);
        if (al && al->kind == pdb::TypeRecord::Kind::ArgList) {
            params.reserve(al->arg_types.size());
            for (std::size_t i = 0; i < al->arg_types.size(); ++i) {
                ParamSig p;
                p.type = rdr->types.render_type(al->arg_types[i]);
                p.name = std::format("a{}", i + 1);
                params.push_back(std::move(p));
            }
        } else if (expected > 0) {
            // No arg list (or unparseable) — fall back to N untyped
            // slots so we at least carry the right arity.
            params.reserve(expected);
            for (u16 i = 0; i < expected; ++i) {
                ParamSig p;
                p.type = "u64";
                p.name = std::format("a{}", i + 1);
                params.push_back(std::move(p));
            }
        }
        return params;
    };

    pdb_signatures_.clear();
    pdb_locals_.clear();
    for (const auto& p : rdr->procs) {
        const addr_t va = resolve_va(p.segment, p.section_offset);
        if (va == 0) continue;
        const pdb::TypeRecord* tr = rdr->types.lookup(p.type_index);
        if (tr &&
            (tr->kind == pdb::TypeRecord::Kind::Procedure ||
             tr->kind == pdb::TypeRecord::Kind::MFunction)) {
            FunctionSig sig;
            sig.return_type = rdr->types.render_type(tr->base_type);
            sig.params      = resolve_args(tr->arg_list, tr->param_count);
            // For member functions, prepend a synthetic `this` arg. We
            // render it as `Class*` (or `Class const*` if the this_type
            // is a const-qualified pointer in the PDB, but that's rare
            // enough to skip for v1).
            if (tr->kind == pdb::TypeRecord::Kind::MFunction && tr->class_type != 0) {
                ParamSig th;
                th.type = rdr->types.render_type(tr->class_type) + "*";
                th.name = "this";
                sig.params.insert(sig.params.begin(), std::move(th));
            }
            pdb_signatures_.emplace(va, std::move(sig));
        }
        if (!p.locals.empty()) {
            std::vector<PdbLocalHint> hints;
            hints.reserve(p.locals.size());
            for (const auto& l : p.locals) {
                PdbLocalHint h;
                h.name         = l.name;
                h.frame_offset = l.frame_offset;
                h.reg          = l.reg;
                h.type_str     = rdr->types.render_type(l.type_index);
                hints.push_back(std::move(h));
            }
            pdb_locals_.emplace(va, std::move(hints));
        }
    }

    sort_and_dedupe_symbols();
    invalidate_caches();
    return added;
}

}  // namespace ember
