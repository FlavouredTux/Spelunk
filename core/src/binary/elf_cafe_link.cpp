// Static Cafe linkage. Import slots are symbolic addresses, not OS exports.
#include <spelunk/binary/elf.hpp>

#include <algorithm>
#include <array>
#include <format>
#include <limits>
#include <map>
#include <optional>
#include <utility>

#include "elf_internal.hpp"
#include "ppc32_relocation.hpp"

namespace spelunk {
namespace {
void put32(std::span<std::byte> bytes, u32 value) {
    for (unsigned i = 0; i < 4; ++i)
        bytes[i] = static_cast<std::byte>((value >> ((3 - i) * 8)) & 0xffu);
}
}

Result<void> ElfBinary::link_cafe_sections(const ParsedEhdr& h) {
    if (!is_cafe_ || h.e_shnum == 0) return {};
    if (sections_.size() != h.e_shnum)
        return std::unexpected(Error::invalid_format("cafe: truncated section data"));
    const ByteReader reader(buffer_);
    auto table = reader.slice(h.e_shoff, static_cast<u64>(h.e_shnum) * h.e_shentsize);
    if (!table) return std::unexpected(table.error());
    std::vector<elf::Shdr> headers;
    headers.reserve(h.e_shnum);
    for (u32 i = 0; i < h.e_shnum; ++i)
        headers.push_back(elf::shdr_at(Endian::Big, table->data(), i, false));
    // EXECINSTR distinguishes function imports/exports from data, but the
    // tables themselves contain metadata rather than PowerPC instructions.
    for (u32 i = 0; i < h.e_shnum; ++i) {
        if (headers[i].type == elf::sht::CAFE_IMPORTS || headers[i].type == elf::sht::CAFE_EXPORTS)
            sections_[i].flags.executable = false;
        // On disk these bytes hold the module name, not the imported object's
        // runtime contents. Do not let constant propagation read that name as
        // the value of an external global at its symbolic slot address.
        if (headers[i].type == elf::sht::CAFE_IMPORTS) sections_[i].data = {};
    }


    struct Stub { u32 target; std::string name; };
    std::map<addr_t, Stub> stubs;
    std::map<u32, std::vector<addr_t>> stubs_by_target;
    const auto reachable = [](addr_t site, addr_t destination, u32 type) {
        std::array<std::byte, 4> instruction{};
        return destination <= std::numeric_limits<u32>::max() &&
            ppc32::encode(instruction, type, Endian::Big, static_cast<u32>(destination), site);
    };
    const auto free_range = [&](addr_t address) {
        if (address == 0 || address > 0xfffffff0ULL || (address & 3u) != 0) return false;
        for (const auto& section : sections_) {
            if (!section.flags.allocated || section.size == 0) continue;
            if (address < section.vaddr + section.size && section.vaddr < address + 16) return false;
        }
        return true;
    };
    const auto make_stub = [&](addr_t site, u32 word, u32 target, const std::string& name,
                                const elf::Shdr& source) -> std::optional<addr_t> {
        // Reuse a previously assigned reachable veneer for this import.
        for (addr_t address : stubs_by_target[target])
            if (stubs.at(address).name == name && reachable(site, address, ppc32::type::REL24)) return address;
        // Linkers can leave branches aimed at reserved, non-file-backed
        // trampoline space. Prefer that address only if it is free.
        std::optional<addr_t> chosen;
        const u32 bits = word & 0x03fffffcu;
        const i64 displacement = (bits & 0x02000000u) != 0
            ? static_cast<i64>(bits) - 0x04000000LL : static_cast<i64>(bits);
        const addr_t encoded = static_cast<u32>(static_cast<u32>(site) + static_cast<u32>(displacement));
        if (free_range(encoded) && reachable(site, encoded, ppc32::type::REL24)) chosen = encoded;
        if (!chosen) {
            addr_t candidate = (source.addr + source.size + 15) & ~addr_t{15};
            // One veneer per import normally suffices. Keep malformed or huge
            // images from turning gap selection into an unbounded search.
            for (std::size_t attempt = 0; attempt <= stubs.size() + headers.size(); ++attempt) {
                if (free_range(candidate) && reachable(site, candidate, ppc32::type::REL24)) {
                    chosen = candidate;
                    break;
                }
                addr_t next = candidate + 16;
                for (const auto& section : sections_) {
                    if (section.flags.allocated && candidate < section.vaddr + section.size &&
                        section.vaddr < candidate + 16)
                        next = std::max(next, (section.vaddr + section.size + 15) & ~addr_t{15});
                }
                candidate = next;
                if (candidate > 0xfffffff0ULL) break;
            }
        }
        if (!chosen || stubs.size() >= 65536) return std::nullopt;
        auto& bytes = cafe_storage_[*chosen];
        bytes.resize(16);
        put32(std::span{bytes}.subspan(0, 4), 0x3d600000u | (target >> 16)); // lis r11,hi
        put32(std::span{bytes}.subspan(4, 4), 0x616b0000u | (target & 0xffff)); // ori r11,r11,lo
        put32(std::span{bytes}.subspan(8, 4), 0x7d6903a6u); // mtctr r11
        put32(std::span{bytes}.subspan(12, 4), 0x4e800420u); // bctr
        Section section;
        section.name = ".cafe.import_stub." + name;
        section.vaddr = *chosen; section.size = 16; section.data = bytes;
        section.file_offset = buffer_.size(); // no file-backed bytes
        section.flags.allocated = true; section.flags.readable = true; section.flags.executable = true;
        sections_.push_back(std::move(section));
        Symbol symbol;
        symbol.name = name; symbol.addr = *chosen; symbol.size = 16;
        symbol.kind = SymbolKind::Function; symbol.is_import = true;
        symbols_.push_back(std::move(symbol));
        stubs.emplace(*chosen, Stub{target, name});
        stubs_by_target[target].push_back(*chosen);
        return chosen;
    };

    std::size_t total = 0;
    std::size_t zero_fill = 0;
    for (u32 i = 0; i < h.e_shnum; ++i) {
        const auto& sh = headers[i];
        if (sh.type != elf::sht::RELA && sh.type != elf::sht::REL) continue;
        if (sh.type == elf::sht::REL)
            return std::unexpected(Error::unsupported("cafe: implicit-addend relocations are not supported"));
        if (sh.entsize != 12 || sh.size % 12 != 0 || sh.link >= h.e_shnum || sh.info >= h.e_shnum)
            return std::unexpected(Error::invalid_format("cafe: invalid relocation table header"));
        const auto symbols = symbol_tables_.find(sh.link);
        if (symbols == symbol_tables_.end())
            return std::unexpected(Error::invalid_format("cafe: relocation table must link to a symbol table"));
        const auto& destination = headers[sh.info];
        if ((destination.flags & 2u) == 0) continue; // non-runtime/debug relocations
        if (destination.type != 1 && destination.type != elf::sht::NOBITS &&
            destination.type != elf::sht::CAFE_EXPORTS && destination.type != 14 && destination.type != 15)
            return std::unexpected(Error::invalid_format("cafe: invalid relocation destination section"));
        auto entries = reader.slice(sh.offset, sh.size);
        if (!entries) return std::unexpected(entries.error());
        const std::size_t count = static_cast<std::size_t>(sh.size / 12);
        constexpr std::size_t max_relocations = 4u * 1024u * 1024u;
        if (count > max_relocations - total)
            return std::unexpected(Error::invalid_format("cafe: too many relocations"));
        total += count;
        relocations_.reserve(total);
        for (std::size_t j = 0; j < count; ++j) {
            const auto* entry = entries->data() + j * 12;
            const u32 site = read_be_at<u32>(entry);
            const u32 info = read_be_at<u32>(entry + 4);
            const u32 type = info & 0xff;
            const u32 index = info >> 8;
            if (index >= symbols->second.size())
                return std::unexpected(Error::invalid_format("cafe: relocation symbol index out of range"));
            const auto& symbol = symbols->second[index];
            auto description = ppc32::info(type);
            if (type == 68) description = {.name="R_PPC_DTPMOD32", .width=4, .alignment=4};
            if (type == 78) description = {.name="R_PPC_DTPREL32", .width=4, .alignment=4};
            Relocation relocation;
            relocation.site = site; relocation.type = type;
            relocation.addend = read_be_at<i32>(entry + 8);
            relocation.target = type == 68 ? 0 : ppc32::resolve(symbol.addr, relocation.addend);
            relocation.symbol_name = symbol.name;
            relocation.section_name = sections_[sh.info].name;
            relocation.width = description.width; relocation.pc_relative = description.pc_relative;
            relocation.type_name = description.name;
            if (type != ppc32::type::NONE) {
                const u64 width = std::max<u64>(description.width, 1);
                if (site < destination.addr || site - destination.addr > destination.size ||
                    width > destination.size - (site - destination.addr) || site % description.alignment != 0)
                    return std::unexpected(Error::invalid_format("cafe: relocation field outside section or misaligned"));
                if ((type == 68 || type == 78) && !symbol.tls)
                    return std::unexpected(Error::invalid_format("cafe: TLS relocation refers to a non-TLS symbol"));
                const auto offset = static_cast<std::size_t>(site - destination.addr);
                std::span<std::byte> field;
                if (destination.type == elf::sht::NOBITS) {
                    if (!cafe_storage_.contains(destination.addr)) {
                        constexpr std::size_t max_bss = 64u * 1024u * 1024u;
                        if (destination.size > max_bss - zero_fill)
                            return std::unexpected(Error::invalid_format("cafe: relocated BSS exceeds 64 MiB"));
                        zero_fill += static_cast<std::size_t>(destination.size);
                        auto& bytes = cafe_storage_[destination.addr];
                        bytes.resize(static_cast<std::size_t>(destination.size));
                        sections_[sh.info].data = bytes;
                        sections_[sh.info].file_offset = buffer_.size();
                    }
                    field = std::span{cafe_storage_.at(destination.addr)}.subspan(offset, static_cast<std::size_t>(width));
                } else {
                    auto backing = reader.slice(destination.offset, destination.size);
                    if (!backing) return std::unexpected(backing.error());
                    field = std::span{buffer_}.subspan(static_cast<std::size_t>(destination.offset) + offset,
                                                      static_cast<std::size_t>(width));
                }
                const bool available = !symbol.undefined || index == 0;
                if (type == 78 && available && !symbol.imported) {
                    put32(field, static_cast<u32>(relocation.target));
                    relocation.applied = true;
                } else if (type != 68 && type != 78 && available && description.elf_supported) {
                    if (description.branch) {
                        const u32 word = read_be_at<u32>(field.data());
                        const bool branch24 = type == ppc32::type::REL24 || type == ppc32::type::ADDR24;
                        const bool valid_opcode = (word >> 26) == (branch24 ? 18u : 16u) &&
                            ((word & 2u) == 0) == description.pc_relative;
                        if (!valid_opcode)
                            return std::unexpected(Error::invalid_format("cafe: branch relocation has invalid opcode"));
                    }
                    relocation.applied = ppc32::encode(field, type, Endian::Big,
                        static_cast<u32>(relocation.target), site);
                    if (!relocation.applied && type == ppc32::type::REL24 &&
                        symbol.imported && symbol.kind == SymbolKind::Function && relocation.addend == 0) {
                        if (auto stub = make_stub(site, read_be_at<u32>(field.data()),
                                                   static_cast<u32>(relocation.target), symbol.name, destination)) {
                            relocation.applied = ppc32::encode(field, type, Endian::Big, static_cast<u32>(*stub), site);
                        }
                    }
                }
            } else relocation.applied = true;
            relocations_.push_back(std::move(relocation));
        }
    }
    // Export names are carried separately from the ELF symbol table.
    for (u32 i = 0; i < h.e_shnum; ++i) {
        const auto& sh = headers[i];
        if (sh.type != elf::sht::CAFE_EXPORTS) continue;
        auto bytes = reader.slice(sh.offset, sh.size);
        if (!bytes) return std::unexpected(bytes.error());
        if (sh.size < 8)
            return std::unexpected(Error::invalid_format("cafe: truncated export header"));
        const u32 count = read_be_at<u32>(bytes->data());
        if (count > (sh.size - 8) / 8)
            return std::unexpected(Error::invalid_format("cafe: export count exceeds section"));
        const ByteReader exports(*bytes);
        for (u32 j = 0; j < count; ++j) {
            const auto* entry = bytes->data() + 8 + static_cast<std::size_t>(j) * 8;
            const u32 name_offset = read_be_at<u32>(entry + 4) & 0x7fffffff;
            auto name = exports.read_cstr(name_offset);
            if (name_offset < 8 + static_cast<u64>(count) * 8 || !name || name->empty())
                return std::unexpected(Error::invalid_format("cafe: invalid export name"));
            Symbol symbol;
            symbol.name = std::string(*name);
            symbol.addr = read_be_at<u32>(entry);
            symbol.kind = (sh.flags & 4u) != 0 ? SymbolKind::Function : SymbolKind::Object;
            symbol.is_export = true;
            symbols_.push_back(std::move(symbol));
        }
    }

    return {};
}
} // namespace spelunk
