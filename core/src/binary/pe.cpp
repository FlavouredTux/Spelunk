#include <spelunk/binary/pe.hpp>

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstring>
#include <expected>
#include <filesystem>
#include <format>
#include <limits>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

#include <spelunk/analysis/pe_unwind.hpp>
#include <spelunk/binary/arch.hpp>
#include <spelunk/binary/binary.hpp>
#include <spelunk/binary/pdb.hpp>
#include <spelunk/binary/pe_view.hpp>
#include <spelunk/binary/section.hpp>
#include <spelunk/binary/symbol.hpp>
#include <spelunk/common/annotations.hpp>
#include <spelunk/common/bytes.hpp>
#include <spelunk/common/error.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/disasm/instruction.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/disasm/x64_decoder.hpp>

namespace spelunk {

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
constexpr std::size_t kCoffSymbolPtrOff     = 0x08;
constexpr std::size_t kCoffSymbolCountOff   = 0x0c;
constexpr std::size_t kCoffSizeOfOptHdrOff  = 0x10;
constexpr std::size_t kCoffSymbolSize       = 18;

// Offsets inside the PE32+ IMAGE_OPTIONAL_HEADER64.
constexpr std::size_t kOptMagicOff            = 0x00;
constexpr std::size_t kOptAddressOfEntryOff   = 0x10;
constexpr std::size_t kOptImageBaseOff        = 0x18;
constexpr std::size_t kOptSizeOfImageOff      = 0x38;
constexpr std::size_t kOptNumRvaAndSizesOff   = 0x6C;
constexpr std::size_t kOptDataDirOff          = 0x70;

// PE32 IMAGE_OPTIONAL_HEADER32: BaseOfData and the 32-bit ImageBase move
// every field after them. Magic, entry and SizeOfImage are shared.
constexpr std::size_t kOpt32ImageBaseOff      = 0x1C;
constexpr std::size_t kOpt32NumRvaAndSizesOff = 0x5C;
constexpr std::size_t kOpt32DataDirOff        = 0x60;

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
constexpr std::size_t kDdBaseReloc   = 5;
constexpr std::size_t kDdDebug       = 6;
constexpr std::size_t kDdTls         = 9;

constexpr std::size_t kBaseRelocBlockSize   = 8;
constexpr u16         kRelocTypeAbsolute    = 0;
constexpr u16         kRelocTypeHighLow     = 3;
constexpr u16         kRelocTypeDir64       = 10;

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
// table - COFF-object-only and rare in EXE/DLL images; we accept the
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
    const u32 symbol_offset = read_le_at<u32>(coff->data() + kCoffSymbolPtrOff);
    const u32 symbol_count = read_le_at<u32>(coff->data() + kCoffSymbolCountOff);
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

    if (opt_size < 2) return std::unexpected(Error::truncated("pe: missing optional header magic"));

    const u16 opt_magic = read_le_at<u16>(opt->data() + kOptMagicOff);
    const bool pe32 = opt_magic == kOptMagicPe32;
    if (!pe32 && opt_magic != kOptMagicPe32Plus) {
        return std::unexpected(Error::invalid_format(std::format(
            "pe: unknown optional header magic {:#x}", opt_magic)));
    }
    if ((pe32 && arch_ != Arch::X86) ||
        (!pe32 && arch_ != Arch::X86_64 && arch_ != Arch::Arm64)) {
        return std::unexpected(Error::unsupported(std::format(
            "pe: machine type {:#x} is incompatible with {}", machine,
            pe32 ? "PE32" : "PE32+")));
    }
    const std::size_t dir_offset = pe32 ? kOpt32DataDirOff : kOptDataDirOff;
    if (opt_size < dir_offset) {
        return std::unexpected(Error::truncated(std::format(
            "pe: optional header size {:#x} < {:#x}", opt_size, dir_offset)));
    }

    const u32 entry_rva  = read_le_at<u32>(opt->data() + kOptAddressOfEntryOff);
    const u64 image_base = pe32 ? read_le_at<u32>(opt->data() + kOpt32ImageBaseOff)
                              : read_le_at<u64>(opt->data() + kOptImageBaseOff);
    const u32 size_of_image = read_le_at<u32>(
        opt->data() + kOptSizeOfImageOff);
    const u32 num_rva    = read_le_at<u32>(
        opt->data() + (pe32 ? kOpt32NumRvaAndSizesOff : kOptNumRvaAndSizesOff));
    if (size_of_image == 0 ||
        (pe32 && image_base + size_of_image > (u64{1} << 32)) ||
        size_of_image > std::numeric_limits<addr_t>::max() - image_base) {
        return std::unexpected(Error::invalid_format(
            "pe: SizeOfImage is zero or overflows the virtual address space"));
    }
    if (entry_rva != 0 && entry_rva >= size_of_image) {
        return std::unexpected(Error::invalid_format(std::format(
            "pe: entry RVA {:#x} lies outside SizeOfImage {:#x}",
            entry_rva, size_of_image)));
    }

    return ParsedHeaders{
        .coff_off          = coff_off,
        .opt_off           = opt_off,
        .sec_tab_off       = opt_off + opt_size,
        .num_sections      = num_sections,
        .opt_size          = opt_size,
        .coff_symbol_offset = symbol_offset,
        .coff_symbol_count = symbol_count,
        .num_rva_and_sizes = num_rva,
        .image_base        = image_base,
        .size_of_image     = size_of_image,
        .entry_rva         = entry_rva,
        .data_dir_offset   = dir_offset,
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

        const u64 virtual_end = static_cast<u64>(virt_rva) + virt_size;
        if (virtual_end > h.size_of_image) {
            return std::unexpected(Error::invalid_format(std::format(
                "pe: section {} virtual range [{:#x}, {:#x}) exceeds "
                "SizeOfImage {:#x}",
                i, virt_rva, virtual_end, h.size_of_image)));
        }
        if (raw_size != 0 &&
            (raw_ptr > buffer_.size() ||
             raw_size > buffer_.size() - raw_ptr)) {
            return std::unexpected(Error::out_of_bounds(std::format(
                "pe: section {} raw range [{:#x}, +{:#x}) exceeds file",
                i, raw_ptr, raw_size)));
        }

        Section s;
        s.name        = read_section_name(p + 0x00);
        if (s.name.starts_with('/') && h.coff_symbol_offset != 0 &&
            h.coff_symbol_count != 0) {
            u32 string_offset = 0;
            const std::string_view raw(s.name);
            const auto parsed = std::from_chars(
                raw.data() + 1, raw.data() + raw.size(), string_offset, 10);
            const u64 strings = static_cast<u64>(h.coff_symbol_offset) +
                static_cast<u64>(h.coff_symbol_count) * kCoffSymbolSize;
            if (parsed.ec == std::errc{} && string_offset >= 4 &&
                strings + 4 <= buffer_.size()) {
                const u32 string_size = read_le_at<u32>(buffer_.data() + strings);
                if (string_offset < string_size && strings + string_size <= buffer_.size()) {
                    const char* name = reinterpret_cast<const char*>(
                        buffer_.data() + strings + string_offset);
                    const std::size_t available = string_size - string_offset;
                    std::size_t length = 0;
                    while (length < available && name[length] != '\0') ++length;
                    if (length < available) s.name.assign(name, length);
                }
            }
        }
        s.vaddr       = h.image_base + static_cast<addr_t>(virt_rva);
        s.file_offset = static_cast<offset_t>(raw_ptr);
        s.size        = static_cast<u64>(virt_size);
        s.flags.readable   = (characteristics & kScnMemRead)    != 0;
        s.flags.writable   = (characteristics & kScnMemWrite)   != 0;
        s.flags.executable = (characteristics & (kScnMemExecute | kScnCntCode)) != 0;
        s.flags.allocated  = (characteristics & (kScnCntCode | kScnCntInit
                                                 | kScnCntUninit)) != 0;

        // File-backed bytes: min(VirtualSize, SizeOfRawData). SizeOfRawData
        // is rounded up to FileAlignment, so it can be larger than VS -
        // bytes past VS inside the raw-data slot are padding, not valid.
        // Uninitialized-data sections (.bss) usually have raw_size == 0;
        // their Section.data stays empty and the default bytes_at() walks
        // past them correctly.
        if (raw_size != 0 && virt_size != 0) {
            const std::size_t backed =
                std::min(static_cast<std::size_t>(raw_size),
                         static_cast<std::size_t>(virt_size));
            auto data = r.slice(raw_ptr, backed);
            if (!data) return std::unexpected(std::move(data).error());
            s.data = *data;
        }

        sections_.push_back(std::move(s));
    }
    return {};
}

void PeBinary::parse_coff_symbols(const ParsedHeaders& h) {
    if (h.coff_symbol_offset == 0 || h.coff_symbol_count == 0 ||
        h.coff_symbol_count > 5'000'000u) return;
    const u64 table_bytes = static_cast<u64>(h.coff_symbol_count) *
                            kCoffSymbolSize;
    const u64 table_end = static_cast<u64>(h.coff_symbol_offset) + table_bytes;
    if (table_end > buffer_.size() || table_end + 4 > buffer_.size()) return;
    const u32 string_size = read_le_at<u32>(buffer_.data() + table_end);
    if (string_size < 4 || table_end + string_size > buffer_.size()) return;

    const auto symbol_name = [&](const std::byte* record) -> std::string {
        const u32 zeroes = read_le_at<u32>(record);
        if (zeroes == 0) {
            const u32 offset = read_le_at<u32>(record + 4);
            if (offset < 4 || offset >= string_size) return {};
            const char* start = reinterpret_cast<const char*>(
                buffer_.data() + table_end + offset);
            const std::size_t available = string_size - offset;
            std::size_t length = 0;
            while (length < available && start[length] != '\0') ++length;
            if (length == available || length > 4096) return {};
            return std::string(start, length);
        }
        std::size_t length = 0;
        while (length < 8 && record[length] != std::byte{0}) ++length;
        return std::string(reinterpret_cast<const char*>(record), length);
    };

    for (u32 index = 0; index < h.coff_symbol_count;) {
        const u64 offset = static_cast<u64>(h.coff_symbol_offset) +
                           static_cast<u64>(index) * kCoffSymbolSize;
        if (offset + kCoffSymbolSize > table_end) break;
        const std::byte* record = buffer_.data() + offset;
        const u32 value = read_le_at<u32>(record + 8);
        const i16 section_number = read_le_at<i16>(record + 12);
        const u16 type = read_le_at<u16>(record + 14);
        const u8 storage_class = static_cast<u8>(record[16]);
        const u8 auxiliary_count = static_cast<u8>(record[17]);
        const u32 advance = 1u + auxiliary_count;
        if (advance > h.coff_symbol_count - index) break;
        const bool defined = section_number > 0 &&
            static_cast<std::size_t>(section_number) <= sections_.size();
        const bool externally_visible = storage_class == 2 || storage_class == 3;
        const bool function_type = (type & 0x20u) != 0;
        if (defined && externally_visible) {
            const Section& section = sections_[static_cast<std::size_t>(
                section_number - 1)];
            if (value <= section.size &&
                value <= std::numeric_limits<addr_t>::max() - section.vaddr) {
                const bool function = function_type && section.flags.executable;
                std::string name = symbol_name(record);
                if (!name.empty() && name != ".file" &&
                    (!name.starts_with('.') || function)) {
                    Symbol symbol;
                    symbol.name = std::move(name);
                    symbol.addr = section.vaddr + value;
                    symbol.kind = function
                        ? SymbolKind::Function : SymbolKind::Object;
                    if (function && auxiliary_count > 0) {
                        const u64 aux_offset = offset + kCoffSymbolSize;
                        if (aux_offset + kCoffSymbolSize <= table_end) {
                            const u32 total_size = read_le_at<u32>(
                                buffer_.data() + aux_offset + 4);
                            if (total_size <= section.size - value) {
                                symbol.size = total_size;
                            }
                        }
                    }
                    symbols_.push_back(std::move(symbol));
                }
            }
        }
        index += advance;
    }
}

Result<void> PeBinary::parse() {
    auto hdrs = parse_headers();
    if (!hdrs) return std::unexpected(std::move(hdrs).error());

    image_base_ = hdrs->image_base;
    size_of_image_ = hdrs->size_of_image;
    entry_      = hdrs->image_base + static_cast<addr_t>(hdrs->entry_rva);

    // Data-directory array follows the fixed optional-header fields. Cap
    // the count at whatever fits inside the optional-header slice so a
    // malicious NumberOfRvaAndSizes can't read past it. The PE spec caps
    // this at 16 in practice but the field is u32 - trust the header size,
    // not the count.
    const std::size_t dd_capacity =
        (hdrs->opt_size > hdrs->data_dir_offset)
            ? (hdrs->opt_size - hdrs->data_dir_offset) / kDataDirEntry
            : 0;
    const std::size_t dd_count =
        std::min<std::size_t>(hdrs->num_rva_and_sizes, dd_capacity);

    const ByteReader r(buffer_);
    const std::size_t dd_off = hdrs->opt_off + hdrs->data_dir_offset;
    data_dirs_.reserve(dd_count);
    for (std::size_t i = 0; i < dd_count; ++i) {
        const std::size_t p = dd_off + i * kDataDirEntry;
        auto va = r.read_le<u32>(p + 0);
        auto sz = r.read_le<u32>(p + 4);
        if (!va || !sz) break;
        data_dirs_.push_back({*va, *sz});
    }

    if (auto rv = parse_sections(*hdrs); !rv) return std::unexpected(rv.error());
    parse_coff_symbols(*hdrs);
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
    const std::size_t word = arch_ == Arch::X86 ? 4u : 8u;
    const std::size_t tls_size = word == 4 ? 24u : 40u;
    if (!rva_is_mapped(dd.virtual_address, tls_size)) return {};

    // IMAGE_TLS_DIRECTORY64 / IMAGE_TLS_DIRECTORY32 fields we use:
    //   +0x18 / +0x0c: AddressOfCallBacks (absolute VA → NULL-terminated
    //   array of pointer-sized entries)
    // Other fields (StartAddressOfRawData, AddressOfIndex, SizeOfZeroFill,
    // Characteristics) describe the TLS data slot itself, which static
    // analysis doesn't act on.
    const auto tls = bytes_at_rva(dd.virtual_address);
    if (tls.size() < tls_size) return {};

    const u64 cb_array_va = word == 4 ? read_le_at<u32>(tls.data() + 0x0c)
                                     : read_le_at<u64>(tls.data() + 0x18);
    if (cb_array_va == 0) return {};

    // Walk callback array. Each entry is an absolute VA, terminated
    // by a zero entry. Cap at 256 to avoid a runaway loop on a corrupt
    // TLS directory pointing into junk.
    constexpr std::size_t kMaxCallbacks = 256;
    for (std::size_t i = 0; i < kMaxCallbacks; ++i) {
        const std::size_t offset = i * word;
        if (offset > std::numeric_limits<addr_t>::max() - cb_array_va) {
            return std::unexpected(Error::invalid_format(
                "pe: TLS callback array address overflows"));
        }
        const auto slot = bytes_at(cb_array_va + offset);
        if (slot.size() < word) break;
        const u64 cb = word == 4 ? read_le_at<u32>(slot.data()) : read_le_at<u64>(slot.data());
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

std::map<addr_t, addr_t> PeBinary::relocated_qwords() const {
    std::map<addr_t, addr_t> out;
    if (arch_ != Arch::X86_64 && arch_ != Arch::X86) return out;
    const bool pe32 = arch_ == Arch::X86;
    if (data_dirs_.size() <= kDdBaseReloc) return out;
    const auto& dd = data_dirs_[kDdBaseReloc];
    if (dd.size == 0 || dd.virtual_address == 0) return out;
    if (!rva_is_mapped(dd.virtual_address, kBaseRelocBlockSize)) return out;

    constexpr u64 kRvaSpaceSize = u64{1} << 32;
    const u64 end = static_cast<u64>(dd.virtual_address) + dd.size;
    if (end > kRvaSpaceSize) return out;
    u64 cursor = dd.virtual_address;
    while (cursor + kBaseRelocBlockSize <= end) {
        const u32 block_rva = static_cast<u32>(cursor);
        const auto block = bytes_at_rva(block_rva);
        if (block.size() < kBaseRelocBlockSize) break;

        const u32 page_rva   = read_le_at<u32>(block.data() + 0);
        const u32 block_size = read_le_at<u32>(block.data() + 4);
        if (page_rva == 0 && block_size == 0) break;
        if (block_size < kBaseRelocBlockSize) break;
        if ((block_size & 1u) != 0) break;
        if (block_size > end - cursor) break;

        const auto bytes = bytes_at_rva(block_rva);
        if (bytes.size() < block_size) break;

        const std::size_t count = (block_size - kBaseRelocBlockSize) / 2;
        for (std::size_t i = 0; i < count; ++i) {
            const u16 raw = read_le_at<u16>(
                bytes.data() + kBaseRelocBlockSize + i * 2);
            const u16 type = static_cast<u16>(raw >> 12);
            const u16 off  = static_cast<u16>(raw & 0x0fffu);
            if (type == kRelocTypeAbsolute) continue;
            if (type != (pe32 ? kRelocTypeHighLow : kRelocTypeDir64)) continue;

            const u64 slot_rva_wide = static_cast<u64>(page_rva) + off;
            if (slot_rva_wide > std::numeric_limits<u32>::max()) continue;
            const u32 slot_rva = static_cast<u32>(slot_rva_wide);
            const auto slot = bytes_at_rva(slot_rva);
            if (slot.size() < (pe32 ? 4u : 8u)) continue;
            const u64 target = pe32 ? read_le_at<u32>(slot.data()) : read_le_at<u64>(slot.data());
            if (target == 0) continue;
            if (slot_rva <=
                std::numeric_limits<addr_t>::max() - image_base_) {
                out[image_base_ + static_cast<addr_t>(slot_rva)] =
                    static_cast<addr_t>(target);
            }
        }

        cursor += block_size;
    }

    return out;
}

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
// puts the candidate density at ~1/65k - three orders of magnitude
// fewer decode calls than the naive walk.
void PeBinary::scan_iat_thunks(
    const std::unordered_map<addr_t, std::string>& got_to_name) {
    if (got_to_name.empty() || (arch_ != Arch::X86_64 && arch_ != Arch::X86)) return;

    std::unordered_map<std::string, addr_t> stub_by_name;
    const X64Decoder dec(arch_ == Arch::X86_64);

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
            if (op.mem.base != (arch_ == Arch::X86 ? Reg::None : Reg::Rip)) continue;
            if (op.mem.index != Reg::None) continue;
            if (!op.mem.has_disp) continue;
            const addr_t got = arch_ == Arch::X86
                ? static_cast<u32>(op.mem.disp)
                : ip + insn.length + static_cast<addr_t>(op.mem.disp);
            auto it = got_to_name.find(got);
            if (it == got_to_name.end()) continue;
            // First thunk wins for a given name - MSVC can emit
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

// Every non-leaf function on x64 carries a RUNTIME_FUNCTION in .pdata -
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

        // Match RSDS first (PDB v7); legacy NB10 (PDB v2) we ignore - the
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
    // NOT refuse the PDB here even on mismatch - the user may have
    // explicitly pointed --pdb at it, and a hard refusal at the
    // loader hides the warning we'd otherwise print.
    pdb_guid_           = rdr->info.guid;
    pdb_age_            = rdr->info.age;
    attached_pdb_path_  = path;

    // Resolve every (segment, offset) pair to an absolute VA. Keep
    // existing names - imports, exports, TLS callbacks all win on a
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
            // Already named - only fill in a name on a synthesized
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
            // No arg list (or unparseable) - fall back to N untyped
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

}  // namespace spelunk
