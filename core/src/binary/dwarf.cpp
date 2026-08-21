#include <ember/binary/dwarf.hpp>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstring>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/common/bytes.hpp>

namespace ember {

namespace {

constexpr u64 DW_TAG_formal_parameter = 0x05;
constexpr u64 DW_TAG_pointer_type = 0x0f;
constexpr u64 DW_TAG_reference_type = 0x10;
constexpr u64 DW_TAG_compile_unit = 0x11;
constexpr u64 DW_TAG_structure_type = 0x13;
constexpr u64 DW_TAG_subroutine_type = 0x15;
constexpr u64 DW_TAG_typedef = 0x16;
constexpr u64 DW_TAG_union_type = 0x17;
constexpr u64 DW_TAG_unspecified_parameters = 0x18;
constexpr u64 DW_TAG_base_type = 0x24;
constexpr u64 DW_TAG_const_type = 0x26;
constexpr u64 DW_TAG_subprogram = 0x2e;
constexpr u64 DW_TAG_unspecified_type = 0x3b;
constexpr u64 DW_TAG_volatile_type = 0x35;
constexpr u64 DW_TAG_restrict_type = 0x37;
constexpr u64 DW_TAG_rvalue_reference_type = 0x42;

constexpr u64 DW_AT_name = 0x03;
constexpr u64 DW_AT_byte_size = 0x0b;
constexpr u64 DW_AT_low_pc = 0x11;
constexpr u64 DW_AT_high_pc = 0x12;
constexpr u64 DW_AT_declaration = 0x3c;
constexpr u64 DW_AT_type = 0x49;
constexpr u64 DW_AT_abstract_origin = 0x31;
constexpr u64 DW_AT_specification = 0x47;
constexpr u64 DW_AT_linkage_name = 0x6e;
constexpr u64 DW_AT_MIPS_linkage_name = 0x2007;

constexpr u64 DW_FORM_addr = 0x01;
constexpr u64 DW_FORM_block2 = 0x03;
constexpr u64 DW_FORM_block4 = 0x04;
constexpr u64 DW_FORM_data2 = 0x05;
constexpr u64 DW_FORM_data4 = 0x06;
constexpr u64 DW_FORM_data8 = 0x07;
constexpr u64 DW_FORM_string = 0x08;
constexpr u64 DW_FORM_block = 0x09;
constexpr u64 DW_FORM_block1 = 0x0a;
constexpr u64 DW_FORM_data1 = 0x0b;
constexpr u64 DW_FORM_flag = 0x0c;
constexpr u64 DW_FORM_sdata = 0x0d;
constexpr u64 DW_FORM_strp = 0x0e;
constexpr u64 DW_FORM_udata = 0x0f;
constexpr u64 DW_FORM_ref_addr = 0x10;
constexpr u64 DW_FORM_ref1 = 0x11;
constexpr u64 DW_FORM_ref2 = 0x12;
constexpr u64 DW_FORM_ref4 = 0x13;
constexpr u64 DW_FORM_ref8 = 0x14;
constexpr u64 DW_FORM_ref_udata = 0x15;
constexpr u64 DW_FORM_indirect = 0x16;
constexpr u64 DW_FORM_sec_offset = 0x17;
constexpr u64 DW_FORM_exprloc = 0x18;
constexpr u64 DW_FORM_flag_present = 0x19;
constexpr u64 DW_FORM_strx = 0x1a;
constexpr u64 DW_FORM_addrx = 0x1b;
constexpr u64 DW_FORM_ref_sup4 = 0x1c;
constexpr u64 DW_FORM_strp_sup = 0x1d;
constexpr u64 DW_FORM_data16 = 0x1e;
constexpr u64 DW_FORM_line_strp = 0x1f;
constexpr u64 DW_FORM_ref_sig8 = 0x20;
constexpr u64 DW_FORM_implicit_const = 0x21;
constexpr u64 DW_FORM_loclistx = 0x22;
constexpr u64 DW_FORM_rnglistx = 0x23;
constexpr u64 DW_FORM_ref_sup8 = 0x24;
constexpr u64 DW_FORM_strx1 = 0x25;
constexpr u64 DW_FORM_strx2 = 0x26;
constexpr u64 DW_FORM_strx3 = 0x27;
constexpr u64 DW_FORM_strx4 = 0x28;
constexpr u64 DW_FORM_addrx1 = 0x29;
constexpr u64 DW_FORM_addrx2 = 0x2a;
constexpr u64 DW_FORM_addrx3 = 0x2b;
constexpr u64 DW_FORM_addrx4 = 0x2c;

struct Reader {
    std::span<const std::byte> bytes;
    std::size_t pos = 0;
    std::size_t end = 0;
    bool little = true;

    [[nodiscard]] bool can(std::size_t count) const noexcept {
        return pos <= end && count <= end - pos && end <= bytes.size();
    }
    [[nodiscard]] std::optional<u8> u8v() {
        if (!can(1)) return std::nullopt;
        return static_cast<u8>(bytes[pos++]);
    }
    template <typename T>
    [[nodiscard]] std::optional<T> fixed() {
        if (!can(sizeof(T))) return std::nullopt;
        T value = little ? read_le_at<T>(bytes.data() + pos)
                         : read_be_at<T>(bytes.data() + pos);
        pos += sizeof(T);
        return value;
    }
    [[nodiscard]] std::optional<u64> uint_n(unsigned size) {
        switch (size) {
            case 1: if (auto v = u8v()) return *v; break;
            case 2: if (auto v = fixed<u16>()) return *v; break;
            case 3: {
                if (!can(3)) break;
                u64 value = 0;
                for (unsigned i = 0; i < 3; ++i) {
                    const unsigned at = little ? i : 2u - i;
                    value |= static_cast<u64>(static_cast<u8>(bytes[pos + at])) << (i * 8);
                }
                pos += 3;
                return value;
            }
            case 4: if (auto v = fixed<u32>()) return *v; break;
            case 8: if (auto v = fixed<u64>()) return *v; break;
            default: break;
        }
        return std::nullopt;
    }
    [[nodiscard]] std::optional<u64> uleb() {
        u64 value = 0;
        unsigned shift = 0;
        for (unsigned i = 0; i < 10; ++i) {
            auto byte = u8v();
            if (!byte) return std::nullopt;
            value |= static_cast<u64>(*byte & 0x7fu) << shift;
            if ((*byte & 0x80u) == 0) return value;
            shift += 7;
        }
        return std::nullopt;
    }
    [[nodiscard]] std::optional<i64> sleb() {
        i64 value = 0;
        unsigned shift = 0;
        u8 byte = 0;
        for (unsigned i = 0; i < 10; ++i) {
            auto next = u8v();
            if (!next) return std::nullopt;
            byte = *next;
            value |= static_cast<i64>(byte & 0x7fu) << shift;
            shift += 7;
            if ((byte & 0x80u) == 0) {
                if (shift < 64 && (byte & 0x40u)) value |= -(i64{1} << shift);
                return value;
            }
        }
        return std::nullopt;
    }
    [[nodiscard]] std::optional<std::string> cstr() {
        const std::size_t start = pos;
        while (pos < end && bytes[pos] != std::byte{0}) ++pos;
        if (pos >= end) return std::nullopt;
        std::string value(reinterpret_cast<const char*>(bytes.data() + start),
                          pos - start);
        ++pos;
        return value;
    }
    bool skip(u64 count) {
        if (count > static_cast<u64>(end - std::min(pos, end))) return false;
        pos += static_cast<std::size_t>(count);
        return true;
    }
};

struct AbbrevAttr { u64 name = 0; u64 form = 0; i64 implicit = 0; };
struct Abbrev { u64 tag = 0; bool children = false; std::vector<AbbrevAttr> attrs; };

struct Die {
    u64 offset = 0;
    u64 tag = 0;
    std::string name;
    std::string linkage;
    u64 type = 0;
    u64 specification = 0;
    u64 origin = 0;
    u64 low_pc = 0;
    u64 high_pc = 0;
    u64 byte_size = 0;
    bool high_is_offset = false;
    bool declaration = false;
    bool variadic = false;
    std::vector<std::pair<std::string, u64>> params;
};

[[nodiscard]] std::span<const std::byte>
section_bytes(const Binary& binary, std::string_view name) {
    for (const Section& section : binary.sections()) {
        if (section.name == name) return section.data;
    }
    return {};
}

[[nodiscard]] std::string string_at(std::span<const std::byte> bytes, u64 offset) {
    if (offset >= bytes.size()) return {};
    const char* start = reinterpret_cast<const char*>(bytes.data() + offset);
    std::size_t length = 0;
    while (offset + length < bytes.size() && start[length] != '\0') ++length;
    if (offset + length >= bytes.size() || length > 4096) return {};
    return std::string(start, length);
}

[[nodiscard]] std::map<u64, Abbrev>
parse_abbrevs(std::span<const std::byte> bytes, u64 offset, bool little) {
    std::map<u64, Abbrev> result;
    if (offset >= bytes.size()) return result;
    Reader reader{bytes, static_cast<std::size_t>(offset), bytes.size(), little};
    while (reader.pos < reader.end && result.size() < 65536) {
        auto code = reader.uleb();
        if (!code || *code == 0) break;
        auto tag = reader.uleb();
        auto children = reader.u8v();
        if (!tag || !children) break;
        Abbrev abbrev{*tag, *children != 0, {}};
        for (;;) {
            auto name = reader.uleb();
            auto form = reader.uleb();
            if (!name || !form) return {};
            if (*name == 0 && *form == 0) break;
            i64 implicit = 0;
            if (*form == DW_FORM_implicit_const) {
                auto value = reader.sleb();
                if (!value) return {};
                implicit = *value;
            }
            abbrev.attrs.push_back({*name, *form, implicit});
        }
        result.emplace(*code, std::move(abbrev));
    }
    return result;
}

struct FormValue {
    u64 number = 0;
    std::string text;
    bool present = false;
    bool reference = false;
};

[[nodiscard]] std::optional<FormValue> read_form(
    Reader& reader, u64 form, i64 implicit, unsigned address_size,
    unsigned offset_size, u64 unit_start, std::span<const std::byte> debug_str,
    std::span<const std::byte> line_str) {
    if (form == DW_FORM_indirect) {
        auto actual = reader.uleb();
        if (!actual) return std::nullopt;
        return read_form(reader, *actual, implicit, address_size, offset_size,
                         unit_start, debug_str, line_str);
    }
    FormValue value;
    value.present = true;
    switch (form) {
        case DW_FORM_addr: {
            auto v = reader.uint_n(address_size); if (!v) return std::nullopt;
            value.number = *v; break;
        }
        case DW_FORM_data1: case DW_FORM_flag: case DW_FORM_strx1:
        case DW_FORM_addrx1: {
            auto v = reader.uint_n(1); if (!v) return std::nullopt;
            value.number = *v; break;
        }
        case DW_FORM_data2: case DW_FORM_ref_sup4: case DW_FORM_strx2:
        case DW_FORM_addrx2: {
            auto v = reader.uint_n(2); if (!v) return std::nullopt;
            value.number = *v; break;
        }
        case DW_FORM_strx3: case DW_FORM_addrx3: {
            auto v = reader.uint_n(3); if (!v) return std::nullopt;
            value.number = *v; break;
        }
        case DW_FORM_data4: case DW_FORM_ref_sup8: case DW_FORM_strx4:
        case DW_FORM_addrx4: {
            auto v = reader.uint_n(4); if (!v) return std::nullopt;
            value.number = *v; break;
        }
        case DW_FORM_data8: case DW_FORM_ref_sig8: {
            auto v = reader.uint_n(8); if (!v) return std::nullopt;
            value.number = *v; break;
        }
        case DW_FORM_udata: case DW_FORM_strx: case DW_FORM_addrx:
        case DW_FORM_loclistx: case DW_FORM_rnglistx: {
            auto v = reader.uleb(); if (!v) return std::nullopt;
            value.number = *v; break;
        }
        case DW_FORM_sdata: {
            auto v = reader.sleb(); if (!v) return std::nullopt;
            value.number = static_cast<u64>(*v); break;
        }
        case DW_FORM_string: {
            auto v = reader.cstr(); if (!v) return std::nullopt;
            value.text = std::move(*v); break;
        }
        case DW_FORM_strp: case DW_FORM_strp_sup: case DW_FORM_line_strp: {
            auto v = reader.uint_n(offset_size); if (!v) return std::nullopt;
            value.number = *v;
            value.text = string_at(form == DW_FORM_line_strp ? line_str : debug_str, *v);
            break;
        }
        case DW_FORM_ref1: case DW_FORM_ref2: case DW_FORM_ref4:
        case DW_FORM_ref8: {
            const unsigned size = form == DW_FORM_ref1 ? 1u :
                (form == DW_FORM_ref2 ? 2u : (form == DW_FORM_ref4 ? 4u : 8u));
            auto v = reader.uint_n(size); if (!v) return std::nullopt;
            value.number = unit_start + *v; value.reference = true; break;
        }
        case DW_FORM_ref_udata: {
            auto v = reader.uleb(); if (!v) return std::nullopt;
            value.number = unit_start + *v; value.reference = true; break;
        }
        case DW_FORM_ref_addr: case DW_FORM_sec_offset: {
            auto v = reader.uint_n(offset_size); if (!v) return std::nullopt;
            value.number = *v; value.reference = form == DW_FORM_ref_addr; break;
        }
        case DW_FORM_block1: case DW_FORM_block2: case DW_FORM_block4:
        case DW_FORM_block: case DW_FORM_exprloc: {
            std::optional<u64> length;
            if (form == DW_FORM_block1) length = reader.uint_n(1);
            else if (form == DW_FORM_block2) length = reader.uint_n(2);
            else if (form == DW_FORM_block4) length = reader.uint_n(4);
            else length = reader.uleb();
            if (!length || !reader.skip(*length)) return std::nullopt;
            break;
        }
        case DW_FORM_flag_present: value.number = 1; break;
        case DW_FORM_implicit_const: value.number = static_cast<u64>(implicit); break;
        case DW_FORM_data16:
            if (!reader.skip(16)) return std::nullopt;
            break;
        default:
            return std::nullopt;
    }
    return value;
}

[[nodiscard]] std::string normalize_base_type(std::string name, u64 size) {
    if (!name.empty()) return name;
    if (size == 1) return "uint8_t";
    if (size == 2) return "uint16_t";
    if (size == 4) return "uint32_t";
    if (size == 8) return "uint64_t";
    return "void";
}

}  // namespace

std::map<addr_t, DwarfFunctionInfo>
parse_dwarf_functions(const Binary& binary) {
    std::map<addr_t, DwarfFunctionInfo> output;
    auto info = section_bytes(binary, ".debug_info");
    auto abbrev_bytes = section_bytes(binary, ".debug_abbrev");
    if (info.empty() || abbrev_bytes.empty()) return output;
    const auto debug_str = section_bytes(binary, ".debug_str");
    const auto line_str = section_bytes(binary, ".debug_line_str");
    const bool little = binary.endian() != Endian::Big;
    Reader units{info, 0, info.size(), little};
    std::vector<Die> dies;
    std::map<u64, std::size_t> die_by_offset;

    while (units.pos + 4 <= units.end) {
        const u64 unit_start = units.pos;
        auto initial_length = units.fixed<u32>();
        if (!initial_length || *initial_length == 0) break;
        bool dwarf64 = *initial_length == 0xffffffffu;
        u64 unit_length = *initial_length;
        if (dwarf64) {
            auto extended = units.fixed<u64>();
            if (!extended) break;
            unit_length = *extended;
        }
        const std::size_t payload_start = units.pos;
        if (unit_length > units.end - payload_start) break;
        const std::size_t unit_end = payload_start + static_cast<std::size_t>(unit_length);
        Reader reader{info, units.pos, unit_end, little};
        auto version = reader.fixed<u16>();
        if (!version || (*version < 2 || *version > 5)) {
            units.pos = unit_end;
            continue;
        }
        unsigned address_size = 0;
        u64 abbrev_offset = 0;
        const unsigned offset_size = dwarf64 ? 8u : 4u;
        if (*version >= 5) {
            auto unit_type = reader.u8v();
            auto addr = reader.u8v();
            auto abbrev = reader.uint_n(offset_size);
            if (!unit_type || !addr || !abbrev) { units.pos = unit_end; continue; }
            address_size = *addr;
            abbrev_offset = *abbrev;
        } else {
            auto abbrev = reader.uint_n(offset_size);
            auto addr = reader.u8v();
            if (!abbrev || !addr) { units.pos = unit_end; continue; }
            abbrev_offset = *abbrev;
            address_size = *addr;
        }
        auto abbrevs = parse_abbrevs(abbrev_bytes, abbrev_offset, little);
        if (abbrevs.empty()) { units.pos = unit_end; continue; }
        std::vector<std::size_t> parents;

        while (reader.pos < unit_end) {
            const u64 die_offset = reader.pos;
            auto code = reader.uleb();
            if (!code) break;
            if (*code == 0) {
                if (!parents.empty()) parents.pop_back();
                continue;
            }
            auto abbreviation = abbrevs.find(*code);
            if (abbreviation == abbrevs.end()) break;
            Die die;
            die.offset = die_offset;
            die.tag = abbreviation->second.tag;
            bool failed = false;
            for (const AbbrevAttr& attribute : abbreviation->second.attrs) {
                auto value = read_form(reader, attribute.form, attribute.implicit,
                    address_size, offset_size, unit_start, debug_str, line_str);
                if (!value) { failed = true; break; }
                switch (attribute.name) {
                    case DW_AT_name: die.name = value->text; break;
                    case DW_AT_linkage_name:
                    case DW_AT_MIPS_linkage_name: die.linkage = value->text; break;
                    case DW_AT_type: die.type = value->number; break;
                    case DW_AT_specification: die.specification = value->number; break;
                    case DW_AT_abstract_origin: die.origin = value->number; break;
                    case DW_AT_low_pc: die.low_pc = value->number; break;
                    case DW_AT_high_pc:
                        die.high_pc = value->number;
                        die.high_is_offset = attribute.form != DW_FORM_addr;
                        break;
                    case DW_AT_byte_size: die.byte_size = value->number; break;
                    case DW_AT_declaration: die.declaration = value->number != 0; break;
                    default: break;
                }
            }
            if (failed) break;
            const std::size_t index = dies.size();
            dies.push_back(std::move(die));
            die_by_offset[die_offset] = index;
            if (!parents.empty()) {
                Die& parent = dies[parents.back()];
                if (dies[index].tag == DW_TAG_formal_parameter) {
                    parent.params.emplace_back(dies[index].name, dies[index].type);
                    if (dies[index].origin != 0) {
                        parent.params.back().second = dies[index].origin;
                        parent.params.back().first = "@origin";
                    }
                } else if (dies[index].tag == DW_TAG_unspecified_parameters) {
                    parent.variadic = true;
                }
            }
            if (abbreviation->second.children) parents.push_back(index);
        }
        units.pos = unit_end;
    }

    const auto find_die = [&](u64 offset) -> const Die* {
        auto found = die_by_offset.find(offset);
        return found == die_by_offset.end() ? nullptr : &dies[found->second];
    };
    const auto resolve_type = [&](const auto& self, u64 offset,
                                  std::set<u64>& seen, int depth) -> std::string {
        if (offset == 0) return "void";
        if (depth > 24 || !seen.insert(offset).second) return "void*";
        const Die* die = find_die(offset);
        if (!die) return "void*";
        switch (die->tag) {
            case DW_TAG_base_type:
            case DW_TAG_unspecified_type:
                return normalize_base_type(die->name, die->byte_size);
            case DW_TAG_pointer_type:
                return self(self, die->type, seen, depth + 1) + "*";
            case DW_TAG_reference_type:
                return self(self, die->type, seen, depth + 1) + "&";
            case DW_TAG_rvalue_reference_type:
                return self(self, die->type, seen, depth + 1) + "&&";
            case DW_TAG_const_type:
                return "const " + self(self, die->type, seen, depth + 1);
            case DW_TAG_volatile_type:
                return "volatile " + self(self, die->type, seen, depth + 1);
            case DW_TAG_restrict_type:
                return self(self, die->type, seen, depth + 1);
            case DW_TAG_typedef:
                return die->name.empty()
                    ? self(self, die->type, seen, depth + 1) : die->name;
            case DW_TAG_structure_type:
            case DW_TAG_union_type:
                return die->name.empty() ? "void*" : die->name;
            case DW_TAG_subroutine_type:
                return "void*";
            default:
                return die->type != 0
                    ? self(self, die->type, seen, depth + 1) : "void*";
        }
    };

    for (const Die& definition : dies) {
        if (definition.tag != DW_TAG_subprogram || definition.low_pc == 0 ||
            definition.declaration) continue;
        const Die* specification = definition.specification != 0
            ? find_die(definition.specification) : nullptr;
        const Die* origin = definition.origin != 0
            ? find_die(definition.origin) : nullptr;
        if (specification && specification->tag != DW_TAG_subprogram) {
            specification = nullptr;
        }
        if (origin && origin->tag != DW_TAG_subprogram) origin = nullptr;
        const Die* source = specification ? specification : (origin ? origin : &definition);
        std::string name = !definition.linkage.empty() ? definition.linkage
            : (!source->linkage.empty() ? source->linkage
               : (!definition.name.empty() ? definition.name : source->name));
        // Namespace DIEs referenced by a partially supported specification
        // chain are not callable function names. Keep the address under its
        // synthetic name rather than producing a misleading `std(...)` call.
        if (name == "std" || name == "__gnu_cxx") name.clear();
        if (name.empty()) continue;
        FunctionSig signature;
        const u64 return_ref = definition.type != 0 ? definition.type : source->type;
        std::set<u64> return_seen;
        signature.return_type = resolve_type(
            resolve_type, return_ref, return_seen, 0);
        const auto& parameters = !definition.params.empty()
            ? definition.params : source->params;
        for (std::size_t index = 0; index < parameters.size(); ++index) {
            std::string param_name = parameters[index].first;
            u64 type_ref = parameters[index].second;
            if (param_name == "@origin") {
                if (const Die* parameter = find_die(type_ref); parameter) {
                    param_name = parameter->name;
                    type_ref = parameter->type;
                }
            }
            std::set<u64> param_seen;
            signature.params.push_back({
                resolve_type(resolve_type, type_ref, param_seen, 0),
                param_name.empty() ? "arg" + std::to_string(index) : param_name});
        }
        signature.variadic = definition.variadic || source->variadic;
        const u64 high_pc = definition.high_pc;
        const u64 size = high_pc == 0 ? 0 :
            (definition.high_is_offset ? high_pc
             : (high_pc > definition.low_pc ? high_pc - definition.low_pc : 0));
        output.try_emplace(static_cast<addr_t>(definition.low_pc),
            DwarfFunctionInfo{std::move(name), std::move(signature), size});
    }
    return output;
}

}  // namespace ember
