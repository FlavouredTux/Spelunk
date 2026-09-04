#include <ember/binary/rel.hpp>

#include <algorithm>
#include <bit>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <expected>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/binary/relocation.hpp>
#include <ember/binary/section.hpp>
#include <ember/binary/symbol.hpp>
#include <ember/common/bytes.hpp>
#include <ember/common/error.hpp>
#include <ember/common/text.hpp>
#include <ember/common/types.hpp>

#include "ppc32_relocation.hpp"

namespace ember {
namespace {

constexpr std::size_t kHeaderV1Size = 0x40;
constexpr std::size_t kHeaderV2Size = 0x48;
constexpr std::size_t kHeaderV3Size = 0x4c;
constexpr std::size_t kSectionEntrySize = 8;
constexpr std::size_t kImportEntrySize = 8;
constexpr std::size_t kRelocEntrySize = 8;
constexpr addr_t kPpc32Max = std::numeric_limits<u32>::max();

namespace rppc = ppc32::type;

[[nodiscard]] addr_t align_up(addr_t value, addr_t alignment) noexcept {
    if (alignment <= 1) return value;
    const addr_t remainder = value % alignment;
    return remainder == 0 ? value : value + (alignment - remainder);
}

[[nodiscard]] std::vector<std::string_view> split_ws(std::string_view line) {
    std::vector<std::string_view> output;
    for (std::size_t index = 0; index < line.size();) {
        while (index < line.size() &&
               std::isspace(static_cast<unsigned char>(line[index]))) {
            ++index;
        }
        const std::size_t start = index;
        while (index < line.size() &&
               !std::isspace(static_cast<unsigned char>(line[index]))) {
            ++index;
        }
        if (start != index) output.push_back(line.substr(start, index - start));
    }
    return output;
}

[[nodiscard]] std::optional<u64> parse_integer(std::string_view text) noexcept {
    text = trim_space(text);
    int base = 10;
    if (text.starts_with("0x") || text.starts_with("0X")) {
        text.remove_prefix(2);
        base = 16;
    }
    if (text.empty()) return std::nullopt;
    u64 value = 0;
    const auto [end, error] = std::from_chars(
        text.data(), text.data() + text.size(), value, base);
    if (error != std::errc{} || end != text.data() + text.size()) return std::nullopt;
    return value;
}

struct RelSectionView {
    u32 file_offset = 0;
    u32 size = 0;
    bool executable = false;
};

struct RelHeaderView {
    u32 module_id = 0;
    u32 section_count = 0;
    u32 section_table_offset = 0;
    u32 version = 0;
    u32 bss_size = 0;
    u32 rel_offset = 0;
    u32 imp_offset = 0;
    u32 imp_size = 0;
    u8 prolog_section = 0;
    u8 epilog_section = 0;
    u8 unresolved_section = 0;
    u32 prolog_offset = 0;
    u32 epilog_offset = 0;
    u32 unresolved_offset = 0;
    u32 section_align = 4;
    u32 bss_align = 4;
    u32 fixed_boundary = 0;
    std::size_t header_size = kHeaderV1Size;
};

struct DecodedRelView {
    RelHeaderView header;
    std::vector<RelSectionView> sections;
};

[[nodiscard]] Result<DecodedRelView>
decode_rel_view(std::span<const std::byte> bytes) {
    if (bytes.size() < kHeaderV1Size) {
        return std::unexpected(Error::truncated(std::format(
            "rel: file smaller than v1 header ({} < {})",
            bytes.size(), kHeaderV1Size)));
    }

    auto word = [&](std::size_t offset) -> u32 {
        return read_be_at<u32>(bytes.data() + offset);
    };

    DecodedRelView output;
    auto& header = output.header;
    header.module_id = word(0x00);
    const u32 next = word(0x04);
    const u32 prev = word(0x08);
    header.section_count = word(0x0c);
    header.section_table_offset = word(0x10);
    header.version = word(0x1c);
    header.bss_size = word(0x20);
    header.rel_offset = word(0x24);
    header.imp_offset = word(0x28);
    header.imp_size = word(0x2c);
    header.prolog_section = static_cast<u8>(bytes[0x30]);
    header.epilog_section = static_cast<u8>(bytes[0x31]);
    header.unresolved_section = static_cast<u8>(bytes[0x32]);
    const u8 bss_section = static_cast<u8>(bytes[0x33]);
    header.prolog_offset = word(0x34);
    header.epilog_offset = word(0x38);
    header.unresolved_offset = word(0x3c);

    if (header.version < 1 || header.version > 3) {
        return std::unexpected(Error::unsupported(std::format(
            "rel: unsupported format version {}", header.version)));
    }
    header.header_size = header.version == 1
        ? kHeaderV1Size : (header.version == 2 ? kHeaderV2Size : kHeaderV3Size);
    if (bytes.size() < header.header_size) {
        return std::unexpected(Error::truncated(std::format(
            "rel: v{} header extends past file", header.version)));
    }
    if (next != 0 || prev != 0 || bss_section != 0) {
        return std::unexpected(Error::invalid_format(
            "rel: runtime next/prev/bss-section fields must be zero on disk"));
    }
    if (header.module_id == 0) {
        return std::unexpected(Error::invalid_format(
            "rel: module ID 0 is reserved for the main executable"));
    }
    if (header.section_count == 0 || header.section_count > 255) {
        return std::unexpected(Error::invalid_format(std::format(
            "rel: invalid section count {}", header.section_count)));
    }

    const u64 section_table_size =
        static_cast<u64>(header.section_count) * kSectionEntrySize;
    if (header.section_table_offset > bytes.size() ||
        section_table_size > bytes.size() - header.section_table_offset) {
        return std::unexpected(Error::out_of_bounds(
            "rel: section table extends past end of file"));
    }
    if (header.imp_size % kImportEntrySize != 0 ||
        header.imp_offset > bytes.size() ||
        header.imp_size > bytes.size() - header.imp_offset) {
        return std::unexpected(Error::out_of_bounds(
            "rel: invalid import table range or entry count"));
    }
    if (header.imp_size != 0 &&
        (header.rel_offset > bytes.size() ||
         bytes.size() - header.rel_offset < kRelocEntrySize)) {
        return std::unexpected(Error::out_of_bounds(
            "rel: relocation data starts outside the file"));
    }

    if (header.version >= 2) {
        header.section_align = word(0x40);
        header.bss_align = word(0x44);
        auto valid_alignment = [](u32 alignment) {
            return alignment == 0 || std::has_single_bit(alignment);
        };
        if (!valid_alignment(header.section_align) ||
            !valid_alignment(header.bss_align)) {
            return std::unexpected(Error::invalid_format(
                "rel: non-zero section and BSS alignments must be powers of two"));
        }
    }
    if (header.version >= 3) header.fixed_boundary = word(0x48);

    output.sections.reserve(header.section_count);
    std::vector<std::pair<u64, u64>> file_ranges;
    file_ranges.reserve(header.section_count);
    u64 total_bss_size = 0;
    bool saw_bss = false;
    bool saw_allocated_section = false;
    for (u32 index = 0; index < header.section_count; ++index) {
        const std::size_t entry =
            static_cast<std::size_t>(header.section_table_offset) +
            static_cast<std::size_t>(index) * kSectionEntrySize;
        RelSectionView section;
        const u32 offset_and_flags = read_be_at<u32>(bytes.data() + entry);
        section.file_offset = offset_and_flags & ~1u;
        section.size = read_be_at<u32>(bytes.data() + entry + 4);
        section.executable = (offset_and_flags & 1u) != 0;
        output.sections.push_back(section);

        if (index == 0 &&
            (offset_and_flags != 0 || section.size != 0)) {
            return std::unexpected(Error::invalid_format(
                "rel: reserved section 0 entry must be entirely zero"));
        }
        if (section.size == 0) continue;
        saw_allocated_section = true;

        if (section.file_offset == 0) {
            if (saw_bss) {
                return std::unexpected(Error::invalid_format(
                    "rel: multiple non-empty BSS sections"));
            }
            saw_bss = true;
            total_bss_size += section.size;
        } else {
            if (section.file_offset > bytes.size() ||
                section.size > bytes.size() - section.file_offset) {
                return std::unexpected(Error::out_of_bounds(std::format(
                    "rel: section {} [{:#x}, +{:#x}) extends past file",
                    index, section.file_offset, section.size)));
            }
            file_ranges.emplace_back(
                section.file_offset,
                static_cast<u64>(section.file_offset) + section.size);
        }
    }

    std::ranges::sort(file_ranges);
    for (std::size_t index = 1; index < file_ranges.size(); ++index) {
        if (file_ranges[index].first < file_ranges[index - 1].second) {
            return std::unexpected(Error::invalid_format(
                "rel: overlapping file-backed sections"));
        }
    }
    if (total_bss_size != header.bss_size) {
        return std::unexpected(Error::invalid_format(std::format(
            "rel: BSS size mismatch ({:#x} in sections, {:#x} in header)",
            total_bss_size, header.bss_size)));
    }
    if (!saw_allocated_section) {
        return std::unexpected(Error::invalid_format("rel: no allocated sections"));
    }

    auto validate_function_coordinate = [&](std::string_view name, u8 section_index,
                                             u32 offset) -> Result<void> {
        if (section_index == 0) {
            if (offset == 0) return {};
            return std::unexpected(Error::invalid_format(std::format(
                "rel: absent {} must use coordinate 0:0", name)));
        }
        if (section_index >= output.sections.size()) {
            return std::unexpected(Error::invalid_format(std::format(
                "rel: {} coordinate {}:{:#x} does not name executable section data",
                name, section_index, offset)));
        }
        const auto& section = output.sections[section_index];
        if (section.file_offset == 0 || !section.executable ||
            offset >= section.size || offset % 4 != 0) {
            return std::unexpected(Error::invalid_format(std::format(
                "rel: {} coordinate {}:{:#x} does not name executable section data",
                name, section_index, offset)));
        }
        return {};
    };
    if (auto result = validate_function_coordinate(
            "prolog", header.prolog_section, header.prolog_offset); !result) {
        return std::unexpected(std::move(result).error());
    }
    if (auto result = validate_function_coordinate(
            "epilog", header.epilog_section, header.epilog_offset); !result) {
        return std::unexpected(std::move(result).error());
    }
    if (auto result = validate_function_coordinate(
            "unresolved", header.unresolved_section,
            header.unresolved_offset); !result) {
        return std::unexpected(std::move(result).error());
    }

    if (header.version >= 3) {
        u64 retained_end = std::max<u64>(
            static_cast<u64>(header.header_size),
            static_cast<u64>(header.section_table_offset) + section_table_size);
        retained_end = std::max(
            retained_end,
            static_cast<u64>(header.imp_offset) + header.imp_size);
        for (const auto& range : file_ranges) {
            retained_end = std::max(retained_end, range.second);
        }
        if (header.fixed_boundary > bytes.size() ||
            header.fixed_boundary < retained_end ||
            header.fixed_boundary % 4 != 0) {
            return std::unexpected(Error::invalid_format(std::format(
                "rel: invalid OSLinkFixed retained-byte boundary {:#x}",
                header.fixed_boundary)));
        }
    }

    return output;
}

}  // namespace

bool looks_like_rel_path(const std::filesystem::path& path,
                         std::span<const std::byte> bytes) noexcept {
    if (bytes.size() < kHeaderV1Size) return false;
    try {
        std::string extension = path.extension().string();
        std::ranges::transform(extension, extension.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        // Explicitly named RELs should reach the parser so callers receive
        // the shared validator's detailed error instead of a format miss.
        if (extension == ".rel") return true;
        return decode_rel_view(bytes).has_value();
    } catch (...) {
        return false;
    }
}

Result<std::unique_ptr<RelBinary>>
RelBinary::load_from_buffer(std::vector<std::byte> buffer,
                            addr_t synthetic_base) {
    std::unique_ptr<RelBinary> self(
        new RelBinary(std::move(buffer), synthetic_base));
    if (auto result = self->parse(); !result) {
        return std::unexpected(std::move(result).error());
    }
    return self;
}

std::optional<addr_t>
RelBinary::section_address(u32 section, u32 offset) const noexcept {
    if (section >= section_bases_.size() || section_bases_[section] == 0 ||
        offset >= section_sizes_[section]) {
        return std::nullopt;
    }
    return section_bases_[section] + offset;
}

void RelBinary::adopt_linked_binary(std::unique_ptr<Binary> binary,
                                    std::string_view module_name) {
    if (!binary) return;
    Binary* linked = binary.get();
    linked_binaries_.push_back(std::move(binary));

    for (const auto& linked_section : linked->sections()) {
        Section section = linked_section;
        section.name = std::format("{}::{}", module_name, linked_section.name);
        sections_.push_back(std::move(section));
    }

    auto needs_qualification = [&](const Symbol& symbol) {
        if (symbol.name.empty() || symbol.name == "_prolog" ||
            symbol.name == "_epilog" || symbol.name == "_unresolved" ||
            symbol.name == "_start" || symbol.name.starts_with("sub_") ||
            symbol.name.starts_with("rel") || symbol.name.starts_with("dol_")) {
            return true;
        }
        return std::ranges::any_of(symbols_, [&](const Symbol& existing) {
            return !existing.is_import && existing.name == symbol.name &&
                   existing.addr != symbol.addr;
        });
    };
    for (const auto& linked_symbol : linked->symbols()) {
        if (linked_symbol.is_import) continue;
        Symbol symbol = linked_symbol;
        if (needs_qualification(symbol)) {
            symbol.name = std::format("{}::{}", module_name, symbol.name);
        }
        symbols_.push_back(std::move(symbol));
    }
    for (const auto& linked_relocation : linked->relocations()) {
        Relocation relocation = linked_relocation;
        relocation.section_name = std::format(
            "{}::{}", module_name, linked_relocation.section_name);
        relocations_.push_back(std::move(relocation));
    }

    sort_and_dedupe_symbols();
    invalidate_caches();
}

void RelBinary::add_known_function(std::string name, u8 section, u32 offset) {
    if (section == 0 || section >= section_bases_.size()) return;
    if (section_bases_[section] == 0 || offset >= section_sizes_[section]) return;

    Symbol symbol;
    symbol.name = std::move(name);
    symbol.addr = section_bases_[section] + offset;
    symbol.kind = SymbolKind::Function;
    symbol.is_export = true;
    symbols_.push_back(std::move(symbol));
}

Result<void> RelBinary::parse() {
    auto decoded = decode_rel_view(buffer_);
    if (!decoded) return std::unexpected(std::move(decoded).error());
    const auto& header = decoded->header;
    const ByteReader reader(buffer_);
    module_id_ = header.module_id;
    version_ = header.version;

    // The SDK treats zero alignment fields as no additional constraint.
    const u32 section_align = std::max(header.section_align, 1u);
    const u32 bss_align = std::max(header.bss_align, 1u);
    section_bases_.assign(header.section_count, 0);
    section_offsets_.assign(header.section_count, 0);
    section_sizes_.assign(header.section_count, 0);
    sections_.reserve(header.section_count);

    addr_t cursor = synthetic_base_;
    bool named_text = false;
    for (u32 index = 0; index < header.section_count; ++index) {
        const auto& decoded_section = decoded->sections[index];
        section_offsets_[index] = decoded_section.file_offset;
        section_sizes_[index] = decoded_section.size;
        if (decoded_section.size == 0) continue;

        const bool is_bss = decoded_section.file_offset == 0;
        const addr_t alignment = is_bss ? bss_align : section_align;
        const addr_t base = align_up(cursor, alignment);
        if (base < cursor || base > kPpc32Max ||
            decoded_section.size > kPpc32Max - base) {
            return std::unexpected(Error::invalid_format(
                "rel: synthetic section layout exceeds PPC32 address space"));
        }
        cursor = base + decoded_section.size;
        section_bases_[index] = base;

        Section section;
        if (is_bss) {
            section.name = ".bss";
        } else if (decoded_section.executable && !named_text) {
            section.name = ".text";
            named_text = true;
        } else if (header.section_count >= 7 && index == 2) {
            section.name = ".ctors";
        } else if (header.section_count >= 7 && index == 3) {
            section.name = ".dtors";
        } else if (header.section_count >= 7 && index == 4) {
            section.name = ".rodata";
        } else if (header.section_count >= 7 && index == 5) {
            section.name = ".data";
        } else {
            section.name = std::format(".section{}", index);
        }
        section.vaddr = base;
        section.file_offset = decoded_section.file_offset;
        section.size = decoded_section.size;
        section.flags.readable = true;
        section.flags.writable = !decoded_section.executable;
        section.flags.executable = decoded_section.executable;
        section.flags.allocated = true;
        if (!is_bss) {
            section.data = *reader.slice(
                decoded_section.file_offset, decoded_section.size);
        }
        sections_.push_back(std::move(section));
    }

    // Small/homebrew RELs often omit the empty ctor/dtor/rodata sections.
    // In that shape, the final file-backed non-code section is conventional
    // `.data`, so give DTK's section-relative symbols a useful anchor.
    if (std::ranges::none_of(sections_, [](const Section& section) {
            return section.name == ".data";
        })) {
        auto candidate = std::ranges::find_if(sections_.rbegin(), sections_.rend(),
            [](const Section& section) {
                return !section.flags.executable && !section.data.empty();
            });
        if (candidate != sections_.rend()) candidate->name = ".data";
    }

    load_base_ = sections_.front().vaddr;
    addr_t high = load_base_;
    for (const auto& section : sections_) {
        load_base_ = std::min(load_base_, section.vaddr);
        high = std::max(high, section.vaddr + section.size);
    }
    mapped_size_ = high - load_base_;

    add_known_function("_prolog", header.prolog_section, header.prolog_offset);
    add_known_function("_epilog", header.epilog_section, header.epilog_offset);
    add_known_function(
        "_unresolved", header.unresolved_section, header.unresolved_offset);
    if (const auto prolog = std::ranges::find_if(symbols_, [](const Symbol& symbol) {
            return symbol.name == "_prolog";
        }); prolog != symbols_.end()) {
        entry_ = prolog->addr;
    } else {
        const auto executable = std::ranges::find_if(sections_, [](const Section& section) {
            return section.flags.executable;
        });
        if (executable != sections_.end()) {
            entry_ = executable->vaddr;
            Symbol start;
            start.name = "_start";
            start.addr = entry_;
            start.kind = SymbolKind::Function;
            start.is_export = true;
            symbols_.push_back(std::move(start));
        }
    }

    if (auto result = parse_relocations(
            header.rel_offset, header.imp_offset, header.imp_size,
            header.fixed_boundary); !result) {
        return result;
    }
    sort_and_dedupe_symbols();
    return {};
}

Result<void> RelBinary::parse_relocations(u32 rel_offset, u32 imp_offset,
                                          u32 imp_size, u32 fixed_boundary) {
    if (imp_size == 0) return {};

    const u64 import_end = static_cast<u64>(imp_offset) + imp_size;
    if (rel_offset >= imp_offset && rel_offset < import_end) {
        return std::unexpected(Error::invalid_format(
            "rel: relocation data starts inside the import table"));
    }
    const std::size_t relocation_end = rel_offset < imp_offset
        ? static_cast<std::size_t>(imp_offset) : buffer_.size();

    struct ImportStream {
        u32 target_module;
        u32 offset;
    };
    const std::size_t import_count = imp_size / kImportEntrySize;
    std::vector<ImportStream> imports;
    imports.reserve(import_count);
    std::vector<u32> stream_starts;
    stream_starts.reserve(import_count);
    std::unordered_map<u32, std::size_t> stream_owners;
    stream_owners.reserve(import_count);
    std::unordered_map<u32, std::size_t> module_owners;
    module_owners.reserve(import_count);
    bool saw_fixed_only_import = false;
    for (std::size_t import_index = 0; import_index < import_count; ++import_index) {
        const std::size_t import_at = imp_offset + import_index * kImportEntrySize;
        const u32 target_module = read_be_at<u32>(buffer_.data() + import_at);
        const u32 stream_offset = read_be_at<u32>(buffer_.data() + import_at + 4);
        const auto [owner, inserted] = stream_owners.emplace(stream_offset, import_index);
        if (!inserted) {
            return std::unexpected(Error::invalid_format(std::format(
                "rel: import relocation streams {} and {} share start {:#x}",
                owner->second, import_index, stream_offset)));
        }
        const auto [module_owner, module_inserted] =
            module_owners.emplace(target_module, import_index);
        if (!module_inserted) {
            return std::unexpected(Error::invalid_format(std::format(
                "rel: import descriptors {} and {} duplicate target module {}",
                module_owner->second, import_index, target_module)));
        }
        if (version_ >= 3) {
            const bool fixed_only = target_module == 0 || target_module == module_id_;
            if (fixed_only) {
                saw_fixed_only_import = true;
            } else if (saw_fixed_only_import) {
                return std::unexpected(Error::invalid_format(std::format(
                    "rel: external module {} import follows a self/DOL import",
                    target_module)));
            }
        }
        if (stream_offset < rel_offset || stream_offset > relocation_end ||
            relocation_end - stream_offset < kRelocEntrySize ||
            stream_offset % 4 != 0) {
            return std::unexpected(Error::out_of_bounds(std::format(
                "rel: import {} relocation stream has invalid start {:#x}",
                import_index, stream_offset)));
        }
        imports.push_back({target_module, stream_offset});
        stream_starts.push_back(stream_offset);
    }
    std::ranges::sort(stream_starts);
    if (stream_starts.front() != rel_offset) {
        return std::unexpected(Error::invalid_format(std::format(
            "rel: first relocation stream {:#x} does not match rel offset {:#x}",
            stream_starts.front(), rel_offset)));
    }

    for (std::size_t import_index = 0; import_index < imports.size(); ++import_index) {
        const u32 target_module = imports[import_index].target_module;
        const u32 stream_offset = imports[import_index].offset;
        const auto start = std::ranges::lower_bound(stream_starts, stream_offset);
        const std::size_t stream_end = std::next(start) == stream_starts.end()
            ? relocation_end : static_cast<std::size_t>(*std::next(start));
        u64 source_offset = 0;
        u8 source_section = 0xff;
        bool found_end = false;
        std::size_t consumed_end = stream_offset;
        for (std::size_t stream_at = stream_offset;
             stream_at < stream_end &&
             stream_end - stream_at >= kRelocEntrySize;
             stream_at += kRelocEntrySize) {
            const u16 delta = read_be_at<u16>(buffer_.data() + stream_at);
            const u8 type = static_cast<u8>(buffer_[stream_at + 2]);
            const u8 target_section = static_cast<u8>(buffer_[stream_at + 3]);
            const u32 addend = read_be_at<u32>(buffer_.data() + stream_at + 4);

            if (type == rppc::NONE || type == rppc::DOLPHIN_NOP) {
                source_offset += delta;
                if (source_offset > std::numeric_limits<u32>::max()) {
                    return std::unexpected(Error::invalid_format(
                        "rel: relocation source offset overflow"));
                }
                continue;
            }
            if (type == rppc::DOLPHIN_SECTION) {
                if (target_section >= section_bases_.size() ||
                    section_bases_[target_section] == 0) {
                    return std::unexpected(Error::invalid_format(std::format(
                        "rel: relocation stream selects invalid section {}",
                        target_section)));
                }
                source_section = target_section;
                source_offset = 0;
                continue;
            }
            if (type == rppc::DOLPHIN_END) {
                found_end = true;
                consumed_end = stream_at + kRelocEntrySize;
                break;
            }
            if (source_section == 0xff) {
                return std::unexpected(Error::invalid_format(
                    "rel: relocation appears before R_DOLPHIN_SECTION"));
            }
            source_offset += delta;
            if (source_offset > std::numeric_limits<u32>::max()) {
                return std::unexpected(Error::invalid_format(
                    "rel: relocation source offset overflow"));
            }
            const ppc32::RelocationInfo properties = ppc32::info(type);
            const u8 width = properties.width;
            const u8 required_alignment = properties.alignment;
            if (source_offset % required_alignment != 0) {
                return std::unexpected(Error::invalid_format(std::format(
                    "rel: {} source offset {:#x} violates {}-byte alignment",
                    properties.name, source_offset, required_alignment)));
            }
            const u32 field_offset = static_cast<u32>(source_offset);
            const u8 storage_width = width == 0 ? 4 : width;
            if (field_offset > section_sizes_[source_section] ||
                storage_width > section_sizes_[source_section] - field_offset) {
                return std::unexpected(Error::out_of_bounds(std::format(
                    "rel: relocation source {}:{:#x} exceeds section",
                    source_section, field_offset)));
            }

            bool target_known = false;
            addr_t target = 0;
            std::string target_name;
            if (target_module == module_id_) {
                if (target_section >= section_bases_.size() ||
                    section_bases_[target_section] == 0 ||
                    addend >= section_sizes_[target_section]) {
                    return std::unexpected(Error::invalid_format(std::format(
                        "rel: self relocation targets invalid section/offset {}:{:#x}",
                        target_section, addend)));
                }
                target = section_bases_[target_section] + addend;
                target_known = true;
                auto existing = std::ranges::find_if(symbols_, [&](const Symbol& symbol) {
                    return !symbol.is_import && symbol.addr == target;
                });
                if (existing != symbols_.end()) {
                    target_name = existing->name;
                } else {
                    target_name = std::format("rel{}_s{}_{:08x}",
                                              module_id_, target_section, addend);
                    Symbol symbol;
                    symbol.name = target_name;
                    symbol.addr = target;
                    symbol.kind = properties.branch
                        ? SymbolKind::Function : SymbolKind::Object;
                    symbols_.push_back(std::move(symbol));
                }
            } else if (target_module == 0) {
                target = addend;
                target_known = target != 0;
                target_name = std::format("dol_{:08x}", addend);
                Symbol symbol;
                symbol.name = target_name;
                symbol.addr = target;
                symbol.kind = properties.branch
                    ? SymbolKind::Function : SymbolKind::Object;
                symbol.is_import = true;
                symbols_.push_back(std::move(symbol));
            } else {
                target_name = std::format("rel{}_s{}_{:08x}",
                                          target_module, target_section, addend);
                Symbol symbol;
                symbol.name = target_name;
                symbol.kind = properties.branch
                    ? SymbolKind::Function : SymbolKind::Object;
                symbol.is_import = true;
                symbols_.push_back(std::move(symbol));
            }

            Relocation relocation;
            relocation.site = section_bases_[source_section] + field_offset;
            relocation.target = target;
            relocation.addend = addend;
            relocation.type = type;
            relocation.source_section = source_section;
            relocation.target_module = target_module;
            relocation.target_section = target_section;
            relocation.width = width;
            relocation.pc_relative = properties.pc_relative;
            relocation.type_name = std::string(properties.name);
            relocation.symbol_name = target_name;
            const auto source = std::ranges::find_if(sections_, [&](const Section& section) {
                return section.vaddr == section_bases_[source_section];
            });
            relocation.section_name = source != sections_.end()
                ? source->name : std::format("section{}", source_section);

            if (target_known) {
                auto applied = apply_relocation(relocation, target);
                if (!applied) return std::unexpected(std::move(applied).error());
                relocation.applied = *applied;
            }
            relocations_.push_back(std::move(relocation));
        }
        if (!found_end) {
            return std::unexpected(Error::truncated(std::format(
                "rel: import {} relocation stream [{:#x}, {:#x}) has no "
                "R_DOLPHIN_END", import_index, stream_offset, stream_end)));
        }
        if (version_ >= 3) {
            if (fixed_boundary > stream_offset && fixed_boundary < consumed_end) {
                return std::unexpected(Error::invalid_format(std::format(
                    "rel: OSLinkFixed boundary {:#x} cuts import {} stream "
                    "[{:#x}, {:#x})", fixed_boundary, import_index,
                    stream_offset, consumed_end)));
            }
            if (target_module != 0 && target_module != module_id_ &&
                consumed_end > fixed_boundary) {
                return std::unexpected(Error::invalid_format(std::format(
                    "rel: OSLinkFixed boundary {:#x} discards required module {} "
                    "relocation stream", fixed_boundary, target_module)));
            }
        }
    }
    return {};
}

Result<bool> RelBinary::apply_relocation(Relocation& relocation,
                                         addr_t target) {
    const u32 source_section = relocation.source_section;
    if (relocation.width == 0 || source_section >= section_bases_.size() ||
        section_bases_[source_section] == 0 ||
        section_offsets_[source_section] == 0) {
        return false;
    }
    if (relocation.site < section_bases_[source_section]) {
        return std::unexpected(Error::invalid_format(
            "rel: relocation site precedes its source section"));
    }

    const addr_t relative_site = relocation.site - section_bases_[source_section];
    if (relative_site > std::numeric_limits<u32>::max()) {
        return std::unexpected(Error::out_of_bounds(
            "rel: relocation site offset exceeds PPC32"));
    }
    const u32 field_offset = static_cast<u32>(relative_site);
    if (field_offset > section_sizes_[source_section] ||
        relocation.width > section_sizes_[source_section] - field_offset) {
        return std::unexpected(Error::out_of_bounds(
            "rel: relocation patch exceeds its source section"));
    }
    const u64 patch_offset = static_cast<u64>(section_offsets_[source_section]) +
                             field_offset;
    if (patch_offset > buffer_.size() ||
        relocation.width > buffer_.size() - patch_offset) {
        return std::unexpected(Error::out_of_bounds(
            "rel: relocation patch extends past file"));
    }

    std::byte* patch = buffer_.data() + patch_offset;
    const u32 value = ppc32::resolve(target, 0);
    const bool applied = ppc32::encode(
        std::span<std::byte>{patch, relocation.width}, relocation.type,
        Endian::Big, value, relocation.site);
    relocation.target = value;
    return applied;
}

void RelBinary::sort_and_dedupe_symbols() {
    auto is_placeholder = [](std::string_view name) {
        if (const auto scope = name.rfind("::"); scope != std::string_view::npos) {
            name = name.substr(scope + 2);
        }
        return name.empty() || name == "_prolog" || name == "_epilog" ||
               name == "_unresolved" || name == "_start" ||
               name.starts_with("sub_") || name.starts_with("rel") ||
               name.starts_with("dol_");
    };
    std::ranges::sort(symbols_, [&](const Symbol& lhs, const Symbol& rhs) {
        if (lhs.addr != rhs.addr) return lhs.addr < rhs.addr;
        if (lhs.is_import != rhs.is_import) return lhs.is_import < rhs.is_import;
        if (lhs.kind != rhs.kind) return lhs.kind < rhs.kind;
        const bool lhs_placeholder = is_placeholder(lhs.name);
        const bool rhs_placeholder = is_placeholder(rhs.name);
        if (lhs_placeholder != rhs_placeholder) return !lhs_placeholder;
        return lhs.name < rhs.name;
    });
    auto unique = std::ranges::unique(symbols_, {}, [](const Symbol& symbol) {
        return std::tuple{symbol.addr, symbol.is_import, symbol.kind, symbol.name};
    });
    symbols_.erase(unique.begin(), unique.end());
}

Result<std::size_t>
RelBinary::attach_dtk_symbols_from_path(const std::filesystem::path& path) {
    std::ifstream input(path);
    if (!input) {
        return std::unexpected(Error::io(std::format(
            "cannot open '{}'", path.string())));
    }

    std::size_t added = 0;
    std::size_t line_number = 0;
    std::string line;
    while (std::getline(input, line)) {
        ++line_number;
        if (!line.empty() && line.back() == '\r') line.pop_back();

        const auto slash = line.find("//");
        const std::string_view attributes = slash == std::string::npos
            ? std::string_view{} : trim_space(std::string_view(line).substr(slash + 2));
        std::string_view declaration = trim_space(std::string_view(line).substr(0, slash));
        if (declaration.empty() || declaration.starts_with('#')) continue;

        const auto equal = declaration.find('=');
        const auto colon = declaration.rfind(':');
        if (equal == std::string_view::npos || colon == std::string_view::npos ||
            colon < equal) {
            return std::unexpected(Error::invalid_format(std::format(
                "dtk REL symbols: {}:{}: expected NAME = SECTION:OFFSET",
                path.string(), line_number)));
        }

        const std::string_view name = trim_space(declaration.substr(0, equal));
        const std::string_view section_name = trim_space(
            declaration.substr(equal + 1, colon - equal - 1));
        std::string_view offset_text = trim_space(declaration.substr(colon + 1));
        if (offset_text.ends_with(';')) {
            offset_text = trim_space(offset_text.substr(0, offset_text.size() - 1));
        }
        const auto relative_offset = parse_integer(offset_text);
        if (name.empty() || !relative_offset) {
            return std::unexpected(Error::invalid_format(std::format(
                "dtk REL symbols: {}:{}: invalid name or offset",
                path.string(), line_number)));
        }

        const auto section = std::ranges::find_if(sections_, [&](const Section& candidate) {
            return candidate.name == section_name;
        });
        if (section == sections_.end()) {
            // DTK symbol sets may retain labels for stripped debug/empty
            // sections. They have no addressable bytes in this REL.
            continue;
        }
        std::optional<SymbolKind> declared_kind;
        u64 declared_size = 0;
        bool is_export = true;
        for (const auto token : split_ws(attributes)) {
            if (token.starts_with("type:")) {
                const auto value = token.substr(5);
                if (value == "function") declared_kind = SymbolKind::Function;
                else if (value == "object" || value == "label") {
                    declared_kind = SymbolKind::Object;
                }
            } else if (token.starts_with("size:")) {
                const auto value = parse_integer(token.substr(5));
                if (!value) {
                    return std::unexpected(Error::invalid_format(std::format(
                        "dtk REL symbols: {}:{}: invalid size attribute",
                        path.string(), line_number)));
                }
                declared_size = *value;
            } else if (token == "scope:local") {
                is_export = false;
            }
        }
        if (*relative_offset > section->size) {
            return std::unexpected(Error::out_of_bounds(std::format(
                "dtk REL symbols: {}:{}: offset {:#x} exceeds {}",
                path.string(), line_number, *relative_offset, section_name)));
        }
        if (declared_size > section->size - *relative_offset) {
            return std::unexpected(Error::out_of_bounds(std::format(
                "dtk REL symbols: {}:{}: symbol '{}' size {:#x} escapes {}",
                path.string(), line_number, name, declared_size, section_name)));
        }

        Symbol symbol;
        symbol.name = std::string(name);
        symbol.addr = section->vaddr + *relative_offset;
        symbol.size = declared_size;
        symbol.kind = declared_kind.value_or(
            section->flags.executable ? SymbolKind::Function : SymbolKind::Object);
        symbol.is_export = is_export;
        const bool duplicate = std::ranges::any_of(symbols_, [&](const Symbol& existing) {
            return !existing.is_import && existing.addr == symbol.addr &&
                   existing.name == symbol.name;
        });
        if (duplicate) continue;
        symbols_.push_back(std::move(symbol));
        ++added;
    }

    sort_and_dedupe_symbols();
    invalidate_caches();
    return added;
}

Result<std::size_t>
link_rel_modules(std::span<RelLinkModule> modules, const Binary* main_dol) {
    std::unordered_map<u32, RelLinkModule*> by_id;
    by_id.reserve(modules.size());
    for (auto& module : modules) {
        if (!module.binary) {
            return std::unexpected(Error::invalid_format(
                "rel link: context contains a null module"));
        }
        const u32 id = module.binary->module_id();
        const auto [existing, inserted] = by_id.emplace(id, &module);
        if (!inserted) {
            return std::unexpected(Error::invalid_format(std::format(
                "rel link: duplicate module ID {} ('{}' and '{}')", id,
                existing->second->name, module.name)));
        }
    }

    auto is_placeholder = [](std::string_view name) {
        return name.empty() || name == "_prolog" || name == "_epilog" ||
               name == "_unresolved" || name == "_start" ||
               name.starts_with("sub_") || name.starts_with("rel") ||
               name.starts_with("dol_");
    };
    auto best_name_at = [&](const Binary& binary, addr_t target)
        -> std::optional<std::string> {
        const Symbol* best = nullptr;
        for (const auto& symbol : binary.symbols()) {
            if (symbol.is_import || symbol.addr != target ||
                (symbol.kind != SymbolKind::Function &&
                 symbol.kind != SymbolKind::Object)) {
                continue;
            }
            if (!best || (is_placeholder(best->name) &&
                          !is_placeholder(symbol.name))) {
                best = &symbol;
            }
        }
        if (best) return best->name;
        if (const auto* containing = binary.defined_object_at(target)) {
            const addr_t offset = target - containing->addr;
            if (offset == 0) return containing->name;
            return std::format("{}+{:#x}", containing->name, offset);
        }
        return std::nullopt;
    };

    std::size_t resolved = 0;
    for (auto& source_module : modules) {
        RelBinary& source = *source_module.binary;
        bool symbols_changed = false;
        for (auto& relocation : source.relocations_) {
            if (relocation.target_module == source.module_id_) continue;

            addr_t target = relocation.target;
            std::optional<std::string> resolved_name;
            if (relocation.target_module == 0) {
                if (!main_dol || target == 0) continue;
                resolved_name = best_name_at(*main_dol, target);
                if (!resolved_name) continue;
            } else {
                const auto peer = by_id.find(relocation.target_module);
                if (peer == by_id.end()) continue;
                const auto address = peer->second->binary->section_address(
                    relocation.target_section,
                    static_cast<u32>(relocation.addend));
                if (!address) {
                    return std::unexpected(Error::invalid_format(std::format(
                        "rel link: module {} relocation at {:#x} targets invalid "
                        "module {} section {} offset {:#x}",
                        source.module_id(), relocation.site,
                        relocation.target_module, relocation.target_section,
                        relocation.addend)));
                }
                target = *address;
                resolved_name = best_name_at(*peer->second->binary, target);
                if (!resolved_name) {
                    resolved_name = std::format("{}::rel{}_s{}_{:08x}",
                        peer->second->name, relocation.target_module,
                        relocation.target_section, relocation.addend);
                }
                auto applied = source.apply_relocation(relocation, target);
                if (!applied) return std::unexpected(std::move(applied).error());
                relocation.applied = *applied;
            }

            const std::string old_name = relocation.symbol_name;
            relocation.target = target;
            relocation.symbol_name = *resolved_name;
            bool updated_import = false;
            for (auto& symbol : source.symbols_) {
                if (!symbol.is_import || symbol.name != old_name) continue;
                symbol.name = *resolved_name;
                symbol.addr = target;
                updated_import = true;
                symbols_changed = true;
            }
            if (!updated_import) {
                const bool already_present = std::ranges::any_of(
                    source.symbols_, [&](const Symbol& symbol) {
                        return symbol.is_import && symbol.addr == target &&
                               symbol.name == *resolved_name;
                    });
                if (!already_present) {
                    Symbol symbol;
                    symbol.name = *resolved_name;
                    symbol.addr = target;
                    symbol.kind = ppc32::info(relocation.type).branch
                        ? SymbolKind::Function : SymbolKind::Object;
                    symbol.is_import = true;
                    source.symbols_.push_back(std::move(symbol));
                    symbols_changed = true;
                }
            }
            ++resolved;
        }
        if (symbols_changed) {
            source.sort_and_dedupe_symbols();
            source.invalidate_caches();
        }
    }
    return resolved;
}

}  // namespace ember
