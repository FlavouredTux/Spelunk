#include <spelunk/binary/elf.hpp>

#include <algorithm>
#include <bit>
#include <cstddef>
#include <expected>
#include <format>
#include <limits>
#include <span>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <spelunk/binary/section.hpp>
#include <spelunk/binary/symbol.hpp>
#include <spelunk/common/bytes.hpp>
#include <spelunk/common/error.hpp>
#include <spelunk/common/types.hpp>

#include "elf_internal.hpp"

namespace spelunk {
namespace {

using elf::align_up_bounded;
using elf::Shdr;
using elf::shdr_at;
namespace shn = elf::shn;
namespace sht = elf::sht;

struct ExtendedIndexTable {
    u32 section_index = 0;
    std::span<const std::byte> bytes;
};

using ExtendedIndexTables = std::unordered_map<u32, ExtendedIndexTable>;

[[nodiscard]] Result<ExtendedIndexTables>
discover_extended_index_tables(Endian endian, const ByteReader& reader,
                               const std::byte* section_table, u32 section_count,
                               bool is_64bit) {
    ExtendedIndexTables tables;
    for (u32 i = 0; i < section_count; ++i) {
        const Shdr sh = shdr_at(endian, section_table, i, is_64bit);
        if (sh.type != sht::SYMTAB_SHNDX) continue;
        if (sh.link >= section_count) {
            return std::unexpected(Error::invalid_format(std::format(
                "elf: SYMTAB_SHNDX {} has invalid symbol-table link {}",
                i, sh.link)));
        }
        const Shdr linked = shdr_at(endian, section_table, sh.link, is_64bit);
        if (linked.type != sht::SYMTAB && linked.type != sht::DYNSYM) {
            return std::unexpected(Error::invalid_format(std::format(
                "elf: SYMTAB_SHNDX {} links to section type {}",
                i, linked.type)));
        }
        if (sh.entsize != sizeof(u32) || sh.size % sizeof(u32) != 0) {
            return std::unexpected(Error::invalid_format(std::format(
                "elf: SYMTAB_SHNDX {} has entry size {} and total size {}",
                i, sh.entsize, sh.size)));
        }
        auto bytes = reader.slice(sh.offset, sh.size);
        if (!bytes) return std::unexpected(std::move(bytes).error());
        const auto [unused, inserted] = tables.emplace(
            sh.link, ExtendedIndexTable{i, *bytes});
        (void)unused;
        if (!inserted) {
            return std::unexpected(Error::invalid_format(std::format(
                "elf: multiple SYMTAB_SHNDX sections link to symbol table {}",
                sh.link)));
        }
    }
    return tables;
}

struct ResolvedSectionIndex {
    u32 value = 0;
    bool extended = false;
};

[[nodiscard]] Result<ResolvedSectionIndex>
resolve_section_index(Endian endian, u16 raw_index, std::size_t symbol_index,
                      u32 symbol_table_index, u32 section_count,
                      const ExtendedIndexTable* extended_table) {
    const bool extended = raw_index == shn::XINDEX;
    if (!extended_table) {
        if (extended) {
            return std::unexpected(Error::invalid_format(std::format(
                "elf: symbol {}:{} uses SHN_XINDEX without SYMTAB_SHNDX",
                symbol_table_index, symbol_index)));
        }
        return ResolvedSectionIndex{raw_index, false};
    }

    const u32 extended_index = elf::read_at<u32>(
        endian, extended_table->bytes.data() + symbol_index * sizeof(u32));
    if (!extended) {
        if (extended_index != shn::UNDEF) {
            return std::unexpected(Error::invalid_format(std::format(
                "elf: symbol {}:{} has unexpected extended section index {}",
                symbol_table_index, symbol_index, extended_index)));
        }
        return ResolvedSectionIndex{raw_index, false};
    }
    if (extended_index == shn::UNDEF || extended_index >= section_count) {
        return std::unexpected(Error::invalid_format(std::format(
            "elf: symbol {}:{} has invalid extended section index {}",
            symbol_table_index, symbol_index, extended_index)));
    }
    return ResolvedSectionIndex{extended_index, true};
}

struct CommonLayout {
    bool set = false;
    addr_t base = 0;
    addr_t end = 0;
};

[[nodiscard]] Result<addr_t>
allocate_common_symbol(u64 alignment_value, u64 size, addr_t& cursor,
                       CommonLayout& layout, u32 table_index,
                       std::size_t symbol_index) {
    if (alignment_value > 1 && !std::has_single_bit(alignment_value)) {
        return std::unexpected(Error::invalid_format(std::format(
            "elf: COMMON symbol {}:{} has invalid alignment {}",
            table_index, symbol_index, alignment_value)));
    }

    constexpr addr_t kPpc32AddressMax = std::numeric_limits<u32>::max();
    const addr_t alignment = std::max<addr_t>(alignment_value, 1);
    const auto address = align_up_bounded(cursor, alignment, kPpc32AddressMax);
    if (!address ||
        (size != 0 && size - 1 > kPpc32AddressMax - *address)) {
        return std::unexpected(Error::invalid_format(std::format(
            "elf: COMMON symbol {}:{} exceeds the PPC32 address space",
            table_index, symbol_index)));
    }

    if (!layout.set) {
        layout.base = *address;
        layout.set = true;
    }
    layout.end = *address + size;
    cursor = layout.end;
    return *address;
}

}  // namespace

Result<void>
ElfBinary::parse_symbols(const ParsedEhdr& h,
                         std::vector<std::string>& dynsym_names,
                         u32& dynsym_section,
                         bool& dynsym_section_seen) {
    if (h.e_shnum == 0) return {};

    const ByteReader reader(buffer_);
    const std::size_t section_table_size =
        static_cast<std::size_t>(h.e_shentsize) * h.e_shnum;
    auto section_table = reader.slice(h.e_shoff, section_table_size);
    if (!section_table) {
        return std::unexpected(std::move(section_table).error());
    }

    auto discovered = discover_extended_index_tables(
        endian_, reader, section_table->data(), h.e_shnum, h.is_64bit);
    if (!discovered) return std::unexpected(std::move(discovered).error());
    const ExtendedIndexTables& extended_indices = *discovered;

    std::unordered_map<u32, std::string> cafe_imports;
    std::unordered_map<u32, u32> cafe_import_counts;
    if (is_cafe_) {
        for (u32 i = 0; i < h.e_shnum; ++i) {
            const Shdr sh = shdr_at(endian_, section_table->data(), i, false);
            if (sh.type != sht::CAFE_IMPORTS) continue;
            auto bytes = reader.slice(sh.offset, sh.size);
            if (!bytes) return std::unexpected(bytes.error());
            if (bytes->size() < 9 || (sh.flags & 2u) == 0)
                return std::unexpected(Error::invalid_format("cafe: invalid import section"));
            const ByteReader imports(*bytes);
            auto module = imports.read_cstr(8);
            if (!module || module->empty() ||
                read_be_at<u32>(bytes->data()) > (sh.size - 8) / 8)
                return std::unexpected(Error::invalid_format("cafe: invalid import module or count"));
            cafe_imports.emplace(i, std::string(*module));
            cafe_import_counts.emplace(i, read_be_at<u32>(bytes->data()));
        }
    }

    const std::size_t symbol_size =
        h.is_64bit ? elf::kSym64Size : elf::kSym32Size;
    const std::size_t absolute_max_symbols = buffer_.size() / symbol_size;
    std::size_t total_symbols = 0;
    for (u32 i = 0; i < h.e_shnum; ++i) {
        const Shdr sh = shdr_at(endian_, section_table->data(), i, h.is_64bit);
        if (sh.type != sht::SYMTAB && sh.type != sht::DYNSYM) continue;
        if (sh.entsize == symbol_size) total_symbols += sh.size / symbol_size;
    }
    if (total_symbols > absolute_max_symbols) {
        total_symbols = absolute_max_symbols;
    }
    symbols_.reserve(total_symbols);

    CommonLayout common_layout;
    for (u32 i = 0; i < h.e_shnum; ++i) {
        const Shdr sh = shdr_at(endian_, section_table->data(), i, h.is_64bit);
        if (sh.type != sht::SYMTAB && sh.type != sht::DYNSYM) continue;
        if (sh.entsize != symbol_size || sh.size % symbol_size != 0) {
            return std::unexpected(Error::invalid_format(std::format(
                "elf: symbol table {} has entry size {} and total size {} "
                "(entry size must be {})",
                i, sh.entsize, sh.size, symbol_size)));
        }
        if (sh.link >= h.e_shnum) {
            return std::unexpected(Error::invalid_format(std::format(
                "elf: symtab {} has bad strtab link {}", i, sh.link)));
        }

        const Shdr string_header = shdr_at(
            endian_, section_table->data(), sh.link, h.is_64bit);
        if (string_header.type != sht::STRTAB) {
            return std::unexpected(Error::invalid_format(std::format(
                "elf: symtab {} links to section type {} (want STRTAB)",
                i, string_header.type)));
        }
        auto string_bytes = reader.slice(string_header.offset, string_header.size);
        if (!string_bytes) {
            return std::unexpected(std::move(string_bytes).error());
        }
        const ByteReader string_reader(*string_bytes);

        auto symbol_bytes = reader.slice(sh.offset, sh.size);
        if (!symbol_bytes) {
            return std::unexpected(std::move(symbol_bytes).error());
        }

        const bool is_dynsym = sh.type == sht::DYNSYM;
        const std::size_t count = sh.size / symbol_size;
        const auto extended_it = extended_indices.find(i);
        const ExtendedIndexTable* extended_table =
            extended_it == extended_indices.end() ? nullptr : &extended_it->second;
        if (extended_table &&
            extended_table->bytes.size() / sizeof(u32) != count) {
            return std::unexpected(Error::invalid_format(std::format(
                "elf: SYMTAB_SHNDX {} has {} entries for {} symbols in table {}",
                extended_table->section_index,
                extended_table->bytes.size() / sizeof(u32), count, i)));
        }

        auto& parsed_table = symbol_tables_[i];
        parsed_table.resize(count);
        if (is_dynsym) {
            dynsym_names.resize(count);
            dynsym_section = i;
            dynsym_section_seen = true;
        }

        const std::byte* const base = symbol_bytes->data();
        for (std::size_t k = 0; k < count; ++k) {
            const std::byte* const p = base + k * symbol_size;
            const u32 st_name = elf::read_at<u32>(endian_, p);
            const u8 st_info = h.is_64bit
                ? elf::read_at<u8>(endian_, p + 4)
                : elf::read_at<u8>(endian_, p + 12);
            const u16 raw_section_index = h.is_64bit
                ? elf::read_at<u16>(endian_, p + 6)
                : elf::read_at<u16>(endian_, p + 14);
            const u64 st_value = h.is_64bit
                ? elf::read_at<u64>(endian_, p + 8)
                : elf::read_at<u32>(endian_, p + 4);
            const u64 st_size = h.is_64bit
                ? elf::read_at<u64>(endian_, p + 16)
                : elf::read_at<u32>(endian_, p + 8);

            std::string name;
            if (auto parsed_name = string_reader.read_cstr(st_name); parsed_name) {
                name = std::string(*parsed_name);
            }
            if (is_dynsym) dynsym_names[k] = name;

            auto section_index = resolve_section_index(
                endian_, raw_section_index, k, i, h.e_shnum, extended_table);
            if (!section_index) {
                return std::unexpected(std::move(section_index).error());
            }

            addr_t resolved_address = st_value;
            const bool ordinary_section_index = section_index->extended ||
                (raw_section_index != shn::UNDEF &&
                 raw_section_index < shn::LORESERVE);
            if (is_cafe_ && ordinary_section_index && section_index->value >= h.e_shnum)
                return std::unexpected(Error::invalid_format("cafe: invalid symbol section index"));
            const auto cafe_module = cafe_imports.find(section_index->value);
            const bool cafe_import = cafe_module != cafe_imports.end() &&
                (st_info & 0xf) != elf::stt::SECTION;
            if (cafe_import) {
                const Shdr defining = shdr_at(endian_, section_table->data(), section_index->value, false);
                if (name.empty() || st_value < defining.addr + 8 ||
                    st_value - defining.addr > defining.size - 8 ||
                    (st_value - defining.addr - 8) % 8 != 0 ||
                    (st_value - defining.addr - 8) / 8 >= cafe_import_counts.at(section_index->value))
                    return std::unexpected(Error::invalid_format("cafe: invalid imported symbol slot"));
                name = cafe_module->second + "!" + name;
            }
            if (is_relocatable_ && ordinary_section_index) {
                if (section_index->value >= h.e_shnum ||
                    section_index->value >= section_bases_.size()) {
                    return std::unexpected(Error::invalid_format(std::format(
                        "elf: symbol {}:{} has invalid section index {}",
                        i, k, section_index->value)));
                }
                const Shdr defining = shdr_at(
                    endian_, section_table->data(), section_index->value,
                    h.is_64bit);
                if (st_value > defining.size ||
                    st_size > defining.size - st_value) {
                    return std::unexpected(Error::invalid_format(std::format(
                        "elf: symbol {}:{} value {:#x} and size {:#x} exceed "
                        "section {} size {:#x}",
                        i, k, st_value, st_size,
                        section_index->value, defining.size)));
                }
                const addr_t section_base = section_bases_[section_index->value];
                if (st_value > std::numeric_limits<addr_t>::max() - section_base) {
                    return std::unexpected(Error::invalid_format(std::format(
                        "elf: symbol {}:{} address overflows", i, k)));
                }
                resolved_address = section_base + st_value;
            } else if (is_relocatable_ && raw_section_index == shn::COMMON) {
                auto common_address = allocate_common_symbol(
                    st_value, st_size, next_external_addr_, common_layout, i, k);
                if (!common_address) {
                    return std::unexpected(std::move(common_address).error());
                }
                resolved_address = *common_address;
            }

            ParsedSymbol parsed;
            parsed.name = name;
            parsed.addr = resolved_address;
            parsed.kind = elf::symbol_kind_from_info(st_info);
            parsed.undefined = raw_section_index == shn::UNDEF;
            parsed.imported = cafe_import;
            parsed.tls = (st_info & 0xf) == 6;
            parsed_table[k] = parsed;

            if (name.empty()) continue;
            Symbol symbol;
            symbol.name = std::move(name);
            symbol.addr = resolved_address;
            symbol.size = st_size;
            symbol.kind = elf::symbol_kind_from_info(st_info);
            symbol.is_import = raw_section_index == shn::UNDEF || cafe_import;
            if (cafe_import) {
                const Shdr defining = shdr_at(endian_, section_table->data(), section_index->value, false);
                symbol.kind = (defining.flags & 4u) != 0 ? SymbolKind::Function : SymbolKind::Object;
                parsed_table[k].kind = symbol.kind;
                symbol.size = 8;
            }
            symbol.is_export = !symbol.is_import &&
                (is_dynsym || (is_relocatable_ && (st_info >> 4) != 0));
            symbols_.push_back(std::move(symbol));
        }
    }

    if (common_layout.set && common_layout.end > common_layout.base) {
        Section common;
        common.name = ".common";
        common.vaddr = common_layout.base;
        common.size = common_layout.end - common_layout.base;
        common.flags.allocated = true;
        common.flags.readable = true;
        common.flags.writable = true;
        sections_.push_back(std::move(common));
    }

    if (is_relocatable_ && entry_ == 0) {
        for (const auto& symbol : symbols_) {
            if (!symbol.is_import && symbol.kind == SymbolKind::Function &&
                symbol.addr != 0) {
                entry_ = symbol.addr;
                break;
            }
        }
    }
    return {};
}

}  // namespace spelunk
