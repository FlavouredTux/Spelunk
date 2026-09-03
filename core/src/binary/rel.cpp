#include <ember/binary/rel.hpp>

#include <algorithm>
#include <bit>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <cstring>
#include <expected>
#include <filesystem>
#include <format>
#include <fstream>
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

namespace ember {
namespace {

constexpr std::size_t kHeaderV1Size = 0x40;
constexpr std::size_t kHeaderV2Size = 0x48;
constexpr std::size_t kHeaderV3Size = 0x4c;
constexpr std::size_t kSectionEntrySize = 8;
constexpr std::size_t kImportEntrySize = 8;
constexpr std::size_t kRelocEntrySize = 8;
constexpr addr_t kPpc32Max = std::numeric_limits<u32>::max();

namespace rppc {
constexpr u8 NONE = 0;
constexpr u8 ADDR32 = 1;
constexpr u8 ADDR24 = 2;
constexpr u8 ADDR16 = 3;
constexpr u8 ADDR16_LO = 4;
constexpr u8 ADDR16_HI = 5;
constexpr u8 ADDR16_HA = 6;
constexpr u8 REL24 = 10;
constexpr u8 REL14 = 11;
constexpr u8 REL14_BRTAKEN = 12;
constexpr u8 REL14_BRNTAKEN = 13;
constexpr u8 UADDR32 = 24;
constexpr u8 EMB_SDA21 = 109;
constexpr u8 DOLPHIN_NOP = 201;
constexpr u8 DOLPHIN_SECTION = 202;
constexpr u8 DOLPHIN_END = 203;
constexpr u8 DOLPHIN_MRKREF = 204;
}  // namespace rppc

[[nodiscard]] addr_t align_up(addr_t value, addr_t alignment) noexcept {
    if (alignment <= 1) return value;
    const addr_t remainder = value % alignment;
    return remainder == 0 ? value : value + (alignment - remainder);
}

template <typename T>
void write_be(std::byte* output, T value) noexcept {
    if constexpr (sizeof(T) > 1 && std::endian::native == std::endian::little) {
        value = std::byteswap(value);
    }
    std::memcpy(output, &value, sizeof(T));
}

[[nodiscard]] std::string_view relocation_name(u8 type) noexcept {
    switch (type) {
        case rppc::NONE:             return "R_PPC_NONE";
        case rppc::ADDR32:           return "R_PPC_ADDR32";
        case rppc::ADDR24:           return "R_PPC_ADDR24";
        case rppc::ADDR16:           return "R_PPC_ADDR16";
        case rppc::ADDR16_LO:        return "R_PPC_ADDR16_LO";
        case rppc::ADDR16_HI:        return "R_PPC_ADDR16_HI";
        case rppc::ADDR16_HA:        return "R_PPC_ADDR16_HA";
        case rppc::REL24:            return "R_PPC_REL24";
        case rppc::REL14:            return "R_PPC_REL14";
        case rppc::REL14_BRTAKEN:    return "R_PPC_REL14_BRTAKEN";
        case rppc::REL14_BRNTAKEN:   return "R_PPC_REL14_BRNTAKEN";
        case rppc::UADDR32:          return "R_PPC_UADDR32";
        case rppc::EMB_SDA21:        return "R_PPC_EMB_SDA21";
        case rppc::DOLPHIN_MRKREF:   return "R_DOLPHIN_MRKREF";
        default:                     return "R_PPC_UNKNOWN";
    }
}

[[nodiscard]] u8 relocation_width(u8 type) noexcept {
    switch (type) {
        case rppc::ADDR16:
        case rppc::ADDR16_LO:
        case rppc::ADDR16_HI:
        case rppc::ADDR16_HA:
            return 2;
        case rppc::ADDR32:
        case rppc::UADDR32:
        case rppc::ADDR24:
        case rppc::REL24:
        case rppc::REL14:
        case rppc::REL14_BRTAKEN:
        case rppc::REL14_BRNTAKEN:
            return 4;
        default:
            return 0;
    }
}

[[nodiscard]] bool is_branch_relocation(u8 type) noexcept {
    return type == rppc::ADDR24 || type == rppc::REL24 ||
           type == rppc::REL14 || type == rppc::REL14_BRTAKEN ||
           type == rppc::REL14_BRNTAKEN;
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

}  // namespace

bool looks_like_rel_path(const std::filesystem::path& path,
                         std::span<const std::byte> bytes) noexcept {
    if (bytes.size() < kHeaderV1Size) return false;
    std::string extension = path.extension().string();
    std::ranges::transform(extension, extension.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    // Preserve useful parser diagnostics for an explicitly named REL, even
    // when its header is malformed. DTK's virtual filesystem extraction,
    // however, commonly resolves `foo.bin:nlzss` to a file literally named
    // `nlzss`, so extension-only detection cannot be the whole story.
    if (extension == ".rel") return true;

    auto word = [&](std::size_t offset) -> u32 {
        return read_be_at<u32>(bytes.data() + offset);
    };
    const u32 next = word(0x04);
    const u32 prev = word(0x08);
    const u32 section_count = word(0x0c);
    const u32 section_table_offset = word(0x10);
    const u32 version = word(0x1c);
    const u32 bss_size = word(0x20);
    const u32 rel_offset = word(0x24);
    const u32 imp_offset = word(0x28);
    const u32 imp_size = word(0x2c);
    const u8 prolog_section = static_cast<u8>(bytes[0x30]);
    const u8 epilog_section = static_cast<u8>(bytes[0x31]);
    const u8 unresolved_section = static_cast<u8>(bytes[0x32]);
    const u8 bss_section = static_cast<u8>(bytes[0x33]);

    if (version < 1 || version > 3 || next != 0 || prev != 0 ||
        bss_section != 0 || section_count == 0 || section_count > 255) {
        return false;
    }
    const std::size_t header_size = version == 1
        ? kHeaderV1Size : (version == 2 ? kHeaderV2Size : kHeaderV3Size);
    if (bytes.size() < header_size) return false;

    const u64 section_table_size =
        static_cast<u64>(section_count) * kSectionEntrySize;
    if (section_table_offset > bytes.size() ||
        section_table_size > bytes.size() - section_table_offset ||
        imp_size % kImportEntrySize != 0 || imp_offset > bytes.size() ||
        imp_size > bytes.size() - imp_offset) {
        return false;
    }
    if (imp_size != 0 &&
        (rel_offset > bytes.size() || bytes.size() - rel_offset < kRelocEntrySize)) {
        return false;
    }
    if (version >= 2 && (word(0x40) == 0 || word(0x44) == 0)) return false;

    auto valid_entry_section = [&](u8 section) {
        return section == 0 || section < section_count;
    };
    if (!valid_entry_section(prolog_section) ||
        !valid_entry_section(epilog_section) ||
        !valid_entry_section(unresolved_section)) {
        return false;
    }

    u64 total_bss_size = 0;
    bool saw_allocated_section = false;
    for (u32 index = 0; index < section_count; ++index) {
        const std::size_t entry =
            static_cast<std::size_t>(section_table_offset) +
            index * kSectionEntrySize;
        const u32 file_offset = read_be_at<u32>(bytes.data() + entry) & ~1u;
        const u32 size = read_be_at<u32>(bytes.data() + entry + 4);
        if (size == 0) continue;
        saw_allocated_section = true;
        if (file_offset == 0) {
            total_bss_size += size;
        } else if (file_offset > bytes.size() || size > bytes.size() - file_offset) {
            return false;
        }
    }
    return saw_allocated_section && total_bss_size == bss_size;
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
    if (buffer_.size() < kHeaderV1Size) {
        return std::unexpected(Error::truncated(std::format(
            "rel: file smaller than v1 header ({} < {})",
            buffer_.size(), kHeaderV1Size)));
    }

    const ByteReader reader(buffer_);
    auto word = [&](std::size_t offset) -> u32 {
        return read_be_at<u32>(buffer_.data() + offset);
    };

    module_id_ = word(0x00);
    const u32 next = word(0x04);
    const u32 prev = word(0x08);
    const u32 section_count = word(0x0c);
    const u32 section_table_offset = word(0x10);
    version_ = word(0x1c);
    const u32 bss_size = word(0x20);
    const u32 rel_offset = word(0x24);
    const u32 imp_offset = word(0x28);
    const u32 imp_size = word(0x2c);
    const u8 prolog_section = static_cast<u8>(buffer_[0x30]);
    const u8 epilog_section = static_cast<u8>(buffer_[0x31]);
    const u8 unresolved_section = static_cast<u8>(buffer_[0x32]);
    const u8 bss_section = static_cast<u8>(buffer_[0x33]);
    const u32 prolog_offset = word(0x34);
    const u32 epilog_offset = word(0x38);
    const u32 unresolved_offset = word(0x3c);

    if (version_ < 1 || version_ > 3) {
        return std::unexpected(Error::unsupported(std::format(
            "rel: unsupported format version {}", version_)));
    }
    const std::size_t header_size = version_ == 1
        ? kHeaderV1Size : (version_ == 2 ? kHeaderV2Size : kHeaderV3Size);
    if (buffer_.size() < header_size) {
        return std::unexpected(Error::truncated(std::format(
            "rel: v{} header extends past file", version_)));
    }
    if (next != 0 || prev != 0 || bss_section != 0) {
        return std::unexpected(Error::invalid_format(
            "rel: runtime next/prev/bss-section fields must be zero on disk"));
    }
    if (section_count == 0 || section_count > 255) {
        return std::unexpected(Error::invalid_format(std::format(
            "rel: invalid section count {}", section_count)));
    }
    const u64 section_table_size = static_cast<u64>(section_count) * kSectionEntrySize;
    if (section_table_offset > buffer_.size() ||
        section_table_size > buffer_.size() - section_table_offset) {
        return std::unexpected(Error::out_of_bounds(
            "rel: section table extends past end of file"));
    }

    const u32 section_align = version_ >= 2 ? word(0x40) : 4;
    const u32 bss_align = version_ >= 2 ? word(0x44) : 4;
    const u32 fix_size = version_ >= 3 ? word(0x48) : 0;
    if (section_align == 0 || bss_align == 0) {
        return std::unexpected(Error::invalid_format(
            "rel: section and BSS alignments must be non-zero"));
    }

    section_bases_.assign(section_count, 0);
    section_offsets_.assign(section_count, 0);
    section_sizes_.assign(section_count, 0);
    section_executable_.assign(section_count, false);
    sections_.reserve(section_count);

    addr_t cursor = synthetic_base_;
    u64 total_bss_size = 0;
    bool saw_bss = false;
    bool named_text = false;
    std::vector<std::pair<u64, u64>> file_ranges;
    for (u32 index = 0; index < section_count; ++index) {
        const std::size_t header_offset =
            static_cast<std::size_t>(section_table_offset) + index * kSectionEntrySize;
        const u32 offset_and_flags = read_be_at<u32>(buffer_.data() + header_offset);
        const u32 file_offset = offset_and_flags & ~1u;
        const u32 size = read_be_at<u32>(buffer_.data() + header_offset + 4);
        const bool executable = (offset_and_flags & 1u) != 0;
        section_offsets_[index] = file_offset;
        section_sizes_[index] = size;
        section_executable_[index] = executable;
        if (size == 0) continue;

        const bool is_bss = file_offset == 0;
        if (is_bss && saw_bss) {
            return std::unexpected(Error::invalid_format(
                "rel: multiple non-empty BSS sections"));
        }
        if (!is_bss &&
            (file_offset > buffer_.size() || size > buffer_.size() - file_offset)) {
            return std::unexpected(Error::out_of_bounds(std::format(
                "rel: section {} [{:#x}, +{:#x}) extends past file",
                index, file_offset, size)));
        }
        if (!is_bss) {
            file_ranges.emplace_back(file_offset,
                                     static_cast<u64>(file_offset) + size);
        }

        const addr_t alignment = is_bss ? bss_align : section_align;
        const addr_t base = align_up(cursor, alignment);
        if (base < cursor || base > kPpc32Max || size > kPpc32Max - base) {
            return std::unexpected(Error::invalid_format(
                "rel: synthetic section layout exceeds PPC32 address space"));
        }
        cursor = base + size;
        section_bases_[index] = base;

        Section section;
        if (is_bss) {
            section.name = ".bss";
            saw_bss = true;
            total_bss_size += size;
        } else if (executable && !named_text) {
            section.name = ".text";
            named_text = true;
        } else if (section_count >= 7 && index == 2) {
            section.name = ".ctors";
        } else if (section_count >= 7 && index == 3) {
            section.name = ".dtors";
        } else if (section_count >= 7 && index == 4) {
            section.name = ".rodata";
        } else if (section_count >= 7 && index == 5) {
            section.name = ".data";
        } else {
            section.name = std::format(".section{}", index);
        }
        section.vaddr = base;
        section.file_offset = file_offset;
        section.size = size;
        section.flags.readable = true;
        section.flags.writable = !executable;
        section.flags.executable = executable;
        section.flags.allocated = true;
        if (!is_bss) {
            section.data = *reader.slice(file_offset, size);
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

    std::ranges::sort(file_ranges);
    for (std::size_t index = 1; index < file_ranges.size(); ++index) {
        if (file_ranges[index].first < file_ranges[index - 1].second) {
            return std::unexpected(Error::invalid_format(
                "rel: overlapping file-backed sections"));
        }
    }

    if (total_bss_size != bss_size) {
        return std::unexpected(Error::invalid_format(std::format(
            "rel: BSS size mismatch ({:#x} in sections, {:#x} in header)",
            total_bss_size, bss_size)));
    }
    if (sections_.empty()) {
        return std::unexpected(Error::invalid_format("rel: no allocated sections"));
    }

    load_base_ = sections_.front().vaddr;
    addr_t high = load_base_;
    for (const auto& section : sections_) {
        load_base_ = std::min(load_base_, section.vaddr);
        high = std::max(high, section.vaddr + section.size);
    }
    mapped_size_ = high - load_base_;

    add_known_function("_prolog", prolog_section, prolog_offset);
    add_known_function("_epilog", epilog_section, epilog_offset);
    add_known_function("_unresolved", unresolved_section, unresolved_offset);
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

    if (auto result = parse_relocations(rel_offset, imp_offset, imp_size, fix_size); !result) {
        return result;
    }
    sort_and_dedupe_symbols();
    return {};
}

Result<void> RelBinary::parse_relocations(u32 rel_offset, u32 imp_offset,
                                          u32 imp_size, u32 fix_size) {
    if (imp_size == 0) return {};
    if (imp_size % kImportEntrySize != 0 || imp_offset > buffer_.size() ||
        imp_size > buffer_.size() - imp_offset) {
        return std::unexpected(Error::out_of_bounds(
            "rel: invalid import table range or entry count"));
    }

    const std::size_t import_count = imp_size / kImportEntrySize;
    for (std::size_t import_index = 0; import_index < import_count; ++import_index) {
        const std::size_t import_at = imp_offset + import_index * kImportEntrySize;
        const u32 target_module = read_be_at<u32>(buffer_.data() + import_at);
        const u32 stream_offset = read_be_at<u32>(buffer_.data() + import_at + 4);
        if (import_index == 0 && stream_offset != rel_offset) {
            return std::unexpected(Error::invalid_format(std::format(
                "rel: first import stream {:#x} does not match rel offset {:#x}",
                stream_offset, rel_offset)));
        }
        if (version_ >= 3 && target_module == module_id_ && stream_offset != fix_size) {
            return std::unexpected(Error::invalid_format(std::format(
                "rel: self relocation stream {:#x} does not match fix_size {:#x}",
                stream_offset, fix_size)));
        }
        if (stream_offset > buffer_.size() ||
            buffer_.size() - stream_offset < kRelocEntrySize) {
            return std::unexpected(Error::out_of_bounds(std::format(
                "rel: import {} relocation stream starts outside file", import_index)));
        }

        u64 source_offset = 0;
        u8 source_section = 0xff;
        bool found_end = false;
        for (std::size_t stream_at = stream_offset;
             stream_at <= buffer_.size() - kRelocEntrySize;
             stream_at += kRelocEntrySize) {
            const u16 delta = read_be_at<u16>(buffer_.data() + stream_at);
            const u8 type = static_cast<u8>(buffer_[stream_at + 2]);
            const u8 target_section = static_cast<u8>(buffer_[stream_at + 3]);
            const u32 addend = read_be_at<u32>(buffer_.data() + stream_at + 4);

            if (type == rppc::NONE) continue;
            if (type == rppc::DOLPHIN_NOP) {
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
            const u32 word_offset = static_cast<u32>(source_offset) & ~3u;
            const u8 width = relocation_width(type);
            const bool halfword = width == 2;
            const u32 field_offset = word_offset + (halfword ? 2u : 0u);
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
                    symbol.kind = is_branch_relocation(type)
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
                symbol.kind = is_branch_relocation(type)
                    ? SymbolKind::Function : SymbolKind::Object;
                symbol.is_import = true;
                symbols_.push_back(std::move(symbol));
            } else {
                target_name = std::format("rel{}_s{}_{:08x}",
                                          target_module, target_section, addend);
                Symbol symbol;
                symbol.name = target_name;
                symbol.kind = is_branch_relocation(type)
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
            relocation.pc_relative = type == rppc::REL24 || type == rppc::REL14 ||
                type == rppc::REL14_BRTAKEN || type == rppc::REL14_BRNTAKEN;
            relocation.type_name = std::string(relocation_name(type));
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
                "rel: import {} relocation stream has no R_DOLPHIN_END",
                import_index)));
        }
    }
    return {};
}

Result<bool> RelBinary::apply_relocation(Relocation& relocation,
                                         addr_t target) {
    const u32 source_section = relocation.source_section;
    if (relocation.width == 0 || source_section >= section_bases_.size() ||
        section_bases_[source_section] == 0 ||
        section_offsets_[source_section] == 0 || target > kPpc32Max) {
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
    bool applied = true;
    switch (relocation.type) {
        case rppc::ADDR32:
        case rppc::UADDR32:
            write_be<u32>(patch, static_cast<u32>(target));
            break;
        case rppc::ADDR16:
        case rppc::ADDR16_LO:
            write_be<u16>(patch, static_cast<u16>(target));
            break;
        case rppc::ADDR16_HI:
            write_be<u16>(patch, static_cast<u16>(target >> 16));
            break;
        case rppc::ADDR16_HA:
            write_be<u16>(patch, static_cast<u16>((target + 0x8000u) >> 16));
            break;
        case rppc::ADDR24: {
            applied = (target & 3u) == 0 && target <= 0x03fffffcu;
            if (applied) {
                const u32 word_value = read_be_at<u32>(patch);
                write_be<u32>(patch, (word_value & ~0x03fffffcu) |
                    (static_cast<u32>(target) & 0x03fffffcu));
            }
            break;
        }
        case rppc::REL24: {
            const addr_t instruction_site = relocation.site & ~addr_t{3};
            const i64 delta_value = static_cast<i64>(target) -
                                    static_cast<i64>(instruction_site);
            applied = (delta_value & 3) == 0 &&
                delta_value >= -0x02000000LL && delta_value <= 0x01fffffcLL;
            if (applied) {
                const u32 word_value = read_be_at<u32>(patch);
                write_be<u32>(patch, (word_value & ~0x03fffffcu) |
                    (static_cast<u32>(delta_value) & 0x03fffffcu));
            }
            break;
        }
        case rppc::REL14:
        case rppc::REL14_BRTAKEN:
        case rppc::REL14_BRNTAKEN: {
            const addr_t instruction_site = relocation.site & ~addr_t{3};
            const i64 delta_value = static_cast<i64>(target) -
                                    static_cast<i64>(instruction_site);
            applied = (delta_value & 3) == 0 &&
                delta_value >= -0x8000LL && delta_value <= 0x7ffcLL;
            if (applied) {
                const u32 word_value = read_be_at<u32>(patch);
                write_be<u32>(patch, (word_value & ~0x0000fffcu) |
                    (static_cast<u32>(delta_value) & 0x0000fffcu));
            }
            break;
        }
        default:
            applied = false;
            break;
    }
    relocation.target = target;
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
        if (*relative_offset >= section->size) {
            return std::unexpected(Error::out_of_bounds(std::format(
                "dtk REL symbols: {}:{}: offset {:#x} exceeds {}",
                path.string(), line_number, *relative_offset, section_name)));
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
                    symbol.kind = is_branch_relocation(
                        static_cast<u8>(relocation.type))
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
