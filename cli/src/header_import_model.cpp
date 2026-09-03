#include "header_import_internal.hpp"

#include <cctype>
#include <charconv>
#include <cmath>
#include <cstring>
#include <expected>
#include <format>
#include <limits>
#include <set>
#include <system_error>
#include <utility>

#include <ember/binary/binary.hpp>
#include <ember/binary/relocation.hpp>
#include <ember/binary/symbol.hpp>

namespace ember::cli::header_import_model {
namespace {

std::size_t scalar_size(std::string name) {
    name = base_type_name(std::move(name));
    if (name == "u8" || name == "s8" || name == "char" || name == "bool" || name == "uint8_t" || name == "int8_t") return 1;
    if (name == "u16" || name == "s16" || name == "short" || name == "uint16_t" || name == "int16_t") return 2;
    if (name == "u64" || name == "s64" || name == "double" || name == "uint64_t" || name == "int64_t") return 8;
    return 4;
}

std::string c_string_at(const Binary& b, addr_t at) {
    auto bytes = b.bytes_at(at);
    if (bytes.empty()) return {};
    std::string out;
    for (std::size_t i = 0; i < bytes.size() && i < 512; ++i) {
        const unsigned char c = std::to_integer<unsigned char>(bytes[i]);
        if (c == 0) return out.empty() ? std::string{} : out;
        if (c < 0x20 || c >= 0x7f) return {};
        if (c == '\\' || c == '"') out.push_back('\\');
        out.push_back(static_cast<char>(c));
    }
    return {};
}

addr_t relocated_pointer(const Binary& b, addr_t site, std::size_t size) {
    for (const auto& r : b.relocations())
        if (r.site == site && r.target != 0 && (r.width == 0 || r.width == size)) return r.target;
    return read_uint(b, site, size);
}

const Symbol* exact_symbol_at(const Binary& b, addr_t at) {
    for (const auto& s : b.symbols()) if (!s.is_import && s.addr == at && !s.name.empty()) return &s;
    return nullptr;
}

}  // namespace

std::string trim(std::string s) {
    auto ws = [](unsigned char c) { return std::isspace(c) != 0; };
    while (!s.empty() && ws(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
    while (!s.empty() && ws(static_cast<unsigned char>(s.back()))) s.pop_back();
    return s;
}

std::string unqualified(std::string_view s) {
    const auto p = s.rfind("::");
    return std::string(p == std::string_view::npos ? s : s.substr(p + 2));
}

std::string base_type_name(std::string s) {
    s = trim(std::move(s));
    for (std::string_view q : {"const ", "volatile ", "struct ", "class ", "union ", "enum "}) {
        while (s.starts_with(q)) s = trim(s.substr(q.size()));
    }
    const auto bracket = s.find('[');
    if (bracket != std::string::npos) s.resize(bracket);
    const auto star = s.find('*');
    if (star != std::string::npos) s.resize(star);
    while (!s.empty() && (s.back() == '&' || std::isspace(static_cast<unsigned char>(s.back()))))
        s.pop_back();
    return unqualified(trim(std::move(s)));
}

const HeaderRecord* record_for(const HeaderDatabase& db, std::string type) {
    std::string base = base_type_name(std::move(type));
    if (auto it = db.records.find(base); it != db.records.end()) return &it->second;
    if (auto it = db.aliases.find(base); it != db.aliases.end()) {
        base = base_type_name(it->second);
        if (auto rit = db.records.find(base); rit != db.records.end()) return &rit->second;
    }
    return nullptr;
}

std::unique_ptr<TypeNode> parse_type(const HeaderDatabase& db, std::string text) {
    text = trim(std::move(text));
    std::vector<std::size_t> dims;
    while (!text.empty() && text.back() == ']') {
        const auto open = text.rfind('[');
        if (open == std::string::npos) break;
        std::size_t n = 0;
        const std::string num = text.substr(open + 1, text.size() - open - 2);
        try { n = static_cast<std::size_t>(std::stoull(num, nullptr, 0)); } catch (...) { return {}; }
        dims.push_back(n);
        text = trim(text.substr(0, open));
    }
    const bool function_ptr = text.find("(*)") != std::string::npos || text.find("(*") != std::string::npos;
    unsigned pointers = function_ptr ? 1u : 0u;
    if (!function_ptr) {
        while (!text.empty()) {
            auto pos = text.find_last_not_of(" \t");
            if (pos == std::string::npos || text[pos] != '*') break;
            ++pointers;
            text = trim(text.substr(0, pos));
        }
    }
    auto node = std::make_unique<TypeNode>();
    node->name = trim(text);
    if (const auto* rec = record_for(db, node->name)) {
        node->kind = TypeNode::Kind::Record;
        node->record = rec;
    } else {
        // Canonicalize scalar typedefs (not records) so Wii aliases such as
        // f32/u32 inherit the correct primitive rendering.
        for (unsigned i = 0; i < 8; ++i) {
            const std::string base = base_type_name(node->name);
            auto alias = db.aliases.find(base);
            if (alias == db.aliases.end()) break;
            node->name = alias->second;
        }
    }
    for (unsigned i = 0; i < pointers; ++i) {
        auto p = std::make_unique<TypeNode>();
        p->kind = TypeNode::Kind::Pointer;
        p->name = node->name + " *";
        p->child = std::move(node);
        node = std::move(p);
    }
    for (std::size_t n : dims) {
        auto a = std::make_unique<TypeNode>();
        a->kind = TypeNode::Kind::Array;
        a->count = n;
        a->name = node->name;
        a->child = std::move(node);
        node = std::move(a);
    }
    return node;
}

std::size_t type_size(const TypeNode& t, std::size_t pointer_size) {
    switch (t.kind) {
        case TypeNode::Kind::Pointer: return pointer_size;
        case TypeNode::Kind::Array: return t.count * type_size(*t.child, pointer_size);
        case TypeNode::Kind::Record: return t.record ? t.record->size : 0;
        case TypeNode::Kind::Scalar: return scalar_size(t.name);
    }
    return 0;
}

u64 read_uint(const Binary& b, addr_t at, std::size_t size) {
    auto bytes = b.bytes_at(at);
    if (bytes.size() < size || size > 8) return 0;
    u64 v = 0;
    if (b.endian() == Endian::Big) {
        for (std::size_t i = 0; i < size; ++i) v = (v << 8) | std::to_integer<u8>(bytes[i]);
    } else {
        for (std::size_t i = 0; i < size; ++i) v |= static_cast<u64>(std::to_integer<u8>(bytes[i])) << (i * 8);
    }
    return v;
}

void write_uint(std::span<std::byte> out, std::size_t offset, std::size_t size, u64 value,
                Endian endian) {
    if (offset > out.size() || size > out.size() - offset)
        return;
    for (std::size_t i = 0; i < size; ++i) {
        const std::size_t shift_index = endian == Endian::Big ? size - i - 1 : i;
        out[offset + i] = static_cast<std::byte>((value >> (shift_index * 8)) & 0xffu);
    }
}

const Relocation* relocation_at(const Binary& b, addr_t site, std::size_t size) {
    for (const auto& relocation : b.relocations()) {
        if (relocation.site == site && (relocation.width == 0 || relocation.width == size)) {
            return &relocation;
        }
    }
    return nullptr;
}

std::string render_value(const HeaderDatabase& db, const Binary& b, const TypeNode& type,
                         addr_t at, unsigned depth, std::size_t pointer_size) {
    if (depth > 12) return "/* recursion limit */ 0";
    const std::string ind(depth * 2, ' '), child_ind((depth + 1) * 2, ' ');
    if (type.kind == TypeNode::Kind::Pointer) {
        const addr_t value = relocated_pointer(b, at, pointer_size);
        if (value == 0) return "NULL";
        const std::string pointee = base_type_name(type.child ? type.child->name : "");
        if (pointee == "char" || pointee == "s8" || pointee == "u8") {
            if (auto s = c_string_at(b, value); !s.empty()) return std::format("\"{}\"", s);
        }
        // Pointer tables of records are the common shape for Wii descriptor
        // data.  Follow them by default and emit typed compound literals so
        // `MapData *[468]` becomes actual MapData initializers rather than a
        // wall of `&lbl_*` entries that each require another command.
        if (type.child && type.child->kind == TypeNode::Kind::Record) {
            const std::size_t needed = type_size(*type.child, pointer_size);
            if (needed != 0 && b.bytes_at(value).size() >= needed) {
                return std::format("&({}){}", type.child->name,
                    render_value(db, b, *type.child, value, depth + 1, pointer_size));
            }
        }
        if (const Symbol* sym = exact_symbol_at(b, value)) return "&" + sym->name;
        if (const Symbol* sym = b.defined_object_at(value)) {
            if (value == sym->addr) return "&" + sym->name;
            return std::format("(void *)(&{} + {:#x})", sym->name, value - sym->addr);
        }
        return std::format("(void *){:#x}", value);
    }
    if (type.kind == TypeNode::Kind::Array) {
        const std::size_t stride = type_size(*type.child, pointer_size);
        std::string out = "{";
        for (std::size_t i = 0; i < type.count; ++i) {
            out += std::format("\n{}[{}] = {}", child_ind, i,
                render_value(db, b, *type.child, at + i * stride, depth + 1, pointer_size));
            if (i + 1 != type.count) out += ',';
        }
        return out + "\n" + ind + "}";
    }
    if (type.kind == TypeNode::Kind::Record && type.record) {
        std::string out = "{";
        for (std::size_t i = 0; i < type.record->fields.size(); ++i) {
            const auto& f = type.record->fields[i];
            auto ft = parse_type(db, f.type);
            out += std::format("\n{}.{} = {}", child_ind, f.name,
                ft ? render_value(db, b, *ft, at + f.offset, depth + 1, pointer_size) : "0");
            if (i + 1 != type.record->fields.size()) out += ',';
        }
        return out + "\n" + ind + "}";
    }
    const std::size_t n = scalar_size(type.name);
    const u64 raw = read_uint(b, at, n);
    const std::string base = base_type_name(type.name);
    if (base == "float" && n == 4) {
        const u32 bits = static_cast<u32>(raw); float f; std::memcpy(&f, &bits, sizeof(f));
        if (std::isfinite(f)) {
            std::string lit = std::format("{:.9g}", f);
            if (lit.find_first_of(".eE") == std::string::npos) lit += ".0";
            return lit + "f";
        }
    }
    if (base == "double" && n == 8) {
        double d; std::memcpy(&d, &raw, sizeof(d));
        if (std::isfinite(d)) return std::format("{:.17g}", d);
    }
    const std::string enum_type = base_type_name(type.name);
    if (auto eit = db.enums.find(enum_type); eit != db.enums.end())
        if (auto it = eit->second.find(static_cast<i64>(raw)); it != eit->second.end()) return it->second;
    return raw < 10 ? std::to_string(raw) : std::format("{:#x}", raw);
}

Result<RoundtripStats> verify_typed_roundtrip(const HeaderDatabase& db, const Binary& b,
                                              const TypeNode& root, addr_t root_at,
                                              std::size_t pointer_size) {
    RoundtripStats stats;
    std::set<std::pair<addr_t, std::string>> visited;
    const auto verify_object = [&](auto&& self, const TypeNode& type, addr_t at,
                                   unsigned depth) -> Result<void> {
        if (depth > 12)
            return {};
        const std::size_t size = type_size(type, pointer_size);
        if (size == 0 || b.bytes_at(at).size() < size) {
            return std::unexpected(Error::invalid_format(
                std::format("round-trip object {} at {:#x} is incomplete", type.name, at)));
        }
        const auto key = std::pair{at, type.name};
        if (!visited.insert(key).second)
            return {};
        ++stats.objects;
        stats.bytes += size;
        std::vector<std::byte> encoded(size, std::byte{0});

        const auto encode = [&](auto&& encode_self, const TypeNode& node, addr_t node_at,
                                std::size_t out_offset, unsigned node_depth) -> Result<void> {
            if (node_depth > 12)
                return {};
            if (node.kind == TypeNode::Kind::Pointer) {
                const u64 raw = read_uint(b, node_at, pointer_size);
                write_uint(encoded, out_offset, pointer_size, raw, b.endian());
                ++stats.pointers;
                if (relocation_at(b, node_at, pointer_size))
                    ++stats.relocations;
                const addr_t target = relocated_pointer(b, node_at, pointer_size);
                if (target != 0 && node.child && node.child->kind == TypeNode::Kind::Record) {
                    auto nested = self(self, *node.child, target, node_depth + 1);
                    if (!nested)
                        return nested;
                }
                return {};
            }
            if (node.kind == TypeNode::Kind::Array) {
                const std::size_t stride = type_size(*node.child, pointer_size);
                for (std::size_t i = 0; i < node.count; ++i) {
                    auto item = encode_self(encode_self, *node.child, node_at + i * stride,
                                            out_offset + i * stride, node_depth + 1);
                    if (!item)
                        return item;
                }
                return {};
            }
            if (node.kind == TypeNode::Kind::Record && node.record) {
                for (const auto& field : node.record->fields) {
                    auto field_type = parse_type(db, field.type);
                    if (!field_type) {
                        return std::unexpected(Error::invalid_format(
                            std::format("round-trip cannot parse field type {}.{} ({})",
                                        node.record->name, field.name, field.type)));
                    }
                    auto field_result =
                        encode_self(encode_self, *field_type, node_at + field.offset,
                                    out_offset + field.offset, node_depth + 1);
                    if (!field_result)
                        return field_result;
                }
                return {};
            }
            const std::size_t scalar_bytes = scalar_size(node.name);
            const std::string rendered =
                render_value(db, b, node, node_at, node_depth, pointer_size);
            u64 roundtrip = 0;
            const std::string base = base_type_name(node.name);
            try {
                if (base == "float" && scalar_bytes == 4) {
                    std::string literal = rendered;
                    if (!literal.empty() && literal.back() == 'f')
                        literal.pop_back();
                    const float value = std::stof(literal);
                    u32 bits = 0;
                    std::memcpy(&bits, &value, sizeof(bits));
                    roundtrip = bits;
                } else if (base == "double" && scalar_bytes == 8) {
                    const double value = std::stod(rendered);
                    std::memcpy(&roundtrip, &value, sizeof(value));
                } else if (auto enum_it = db.enums.find(base); enum_it != db.enums.end()) {
                    bool found = false;
                    for (const auto& [value, name] : enum_it->second) {
                        if (name == rendered) {
                            roundtrip = static_cast<u64>(value);
                            found = true;
                            break;
                        }
                    }
                    if (!found)
                        roundtrip = std::stoull(rendered, nullptr, 0);
                } else {
                    roundtrip = std::stoull(rendered, nullptr, 0);
                }
            } catch (...) {
                return std::unexpected(Error::invalid_format(
                    std::format("round-trip cannot parse scalar '{}' for {} at {:#x}", rendered,
                                node.name, node_at)));
            }
            write_uint(encoded, out_offset, scalar_bytes, roundtrip, b.endian());
            return {};
        };

        auto encoded_result = encode(encode, type, at, 0, depth);
        if (!encoded_result)
            return encoded_result;
        const auto original = b.bytes_at(at).first(size);
        for (std::size_t i = 0; i < size; ++i) {
            if (encoded[i] == original[i])
                continue;
            return std::unexpected(Error::invalid_format(
                std::format("round-trip mismatch for {} at {:#x}+{:#x}: source "
                            "{:#04x}, encoded {:#04x}",
                            type.name, at, i, std::to_integer<unsigned>(original[i]),
                            std::to_integer<unsigned>(encoded[i]))));
        }
        return {};
    };
    auto result = verify_object(verify_object, root, root_at, 0);
    if (!result)
        return std::unexpected(std::move(result).error());
    return stats;
}

const std::array<std::string_view, kEvtOpcodeCount> kEvtNames = {
    "NEXT","END_SCRIPT","RETURN","LBL","GOTO","DO","WHILE","DO_BREAK","DO_CONTINUE",
    "WAIT_FRM","WAIT_MSEC","HALT","IF_STR_EQUAL","IF_STR_NOT_EQUAL","IF_STR_SMALL","IF_STR_LARGE",
    "IF_STR_SMALL_EQUAL","IF_STR_LARGE_EQUAL","IFF_EQUAL","IFF_NOT_EQUAL","IFF_SMALL","IFF_LARGE",
    "IFF_SMALL_EQUAL","IFF_LARGE_EQUAL","IF_EQUAL","IF_NOT_EQUAL","IF_SMALL","IF_LARGE",
    "IF_SMALL_EQUAL","IF_LARGE_EQUAL","IF_FLAG","IF_NOT_FLAG","ELSE","END_IF","SWITCH","SWITCHI",
    "CASE_EQUAL","CASE_NOT_EQUAL","CASE_SMALL","CASE_LARGE","CASE_SMALL_EQUAL","CASE_LARGE_EQUAL",
    "CASE_ETC","CASE_OR","CASE_AND","CASE_FLAG","CASE_END","EVT_CASE_BETWEEN","SWITCH_BREAK","END_SWITCH",
    "SET","SETI","SETF","ADD","SUB","MUL","DIV","MOD","ADDF","SUBF","MULF","DIVF","SET_READ",
    "READ","READ2","READ3","READ4","READ_N","SET_READF","READF","READF2","READF3","READF4","READF_N",
    "CLAMP_INT","SET_USER_WRK","SET_USER_FLG","ALLOC_USER_WRK","AND","ANDI","OR","ORI","SET_FRAME_FROM_MSEC",
    "SET_MSEC_FROM_FRAMES","SET_RAM","SET_RAMF","GET_RAM","GET_RAMF","SETR","SETRF","GETR","GETRF","USER_FUNC",
    "RUN_EVT","RUN_EVT_ID","RUN_CHILD_EVT","DELETE_EVT","RESTART_EVT","SET_PRI","SET_SPD","SET_TYPE","STOP_ALL",
    "START_ALL","STOP_OTHER","START_OTHER","STOP_ID","START_ID","CHK_EVT","INLINE_EVT","INLINE_EVT_ID","END_INLINE",
    "BROTHER_EVT","BROTHER_EVT_ID","END_BROTHER","DEBUG_PUT_MSG","DEBUG_MSG_CLEAR","DEBUG_PUT_REG","DEBUG_NAME","DEBUG_REM","DEBUG_BP"
};

std::string evt_arg(const Binary& b, addr_t site, i32 v, bool pointer_hint) {
    for (const auto& relocation : b.relocations()) {
        if (relocation.site == site && !relocation.symbol_name.empty()) {
            return relocation.symbol_name;
        }
    }
    const addr_t relocated = relocated_pointer(b, site, 4);
    const bool mapped_pointer = relocated != 0 && !b.bytes_at(relocated).empty();
    const bool relocation_changed_value = relocated != static_cast<u32>(v);
    // A pointer-position hint alone is not enough: event variables are signed
    // sentinel encodings and can legally occupy pointer-like opcode slots.
    // For example 0xfe363c81 is LW(1), not an unmapped address.
    if ((mapped_pointer || relocation_changed_value) && relocated != 0) {
        if (!pointer_hint)
            if (auto s = c_string_at(b, relocated); !s.empty()) return std::format("PTR(\"{}\")", s);
        if (const auto* sym = exact_symbol_at(b, relocated)) return sym->name;
        if (auto s = c_string_at(b, relocated); !s.empty()) return std::format("PTR(\"{}\")", s);
        return std::format("PTR({:#x})", relocated);
    }
    struct Enc { i32 low, base; const char* macro; };
    constexpr Enc enc[] = {{-290000000,-270000000,"PTR"},{-220000000,-240000000,"FLOAT"},
        {-200000000,-210000000,"UF"},{-180000000,-190000000,"UW"},{-160000000,-170000000,"GSW"},
        {-140000000,-150000000,"LSW"},{-120000000,-130000000,"GSWF"},{-100000000,-110000000,"LSWF"},
        {-80000000,-90000000,"GF"},{-60000000,-70000000,"LF"},{-40000000,-50000000,"GW"},{-20000000,-30000000,"LW"}};
    for (const auto& e : enc) if (v <= e.low) {
        if (std::string_view(e.macro) == "FLOAT") return std::format("FLOAT({:.6g})", static_cast<double>(v - e.base) / 1024.0);
        return std::format("{}({})", e.macro, v - e.base);
    }
    return std::to_string(v);
}

std::optional<i32> evt_scalar_from_rendered(std::string_view rendered) {
    if (rendered.empty())
        return std::nullopt;
    i64 plain = 0;
    const auto plain_result =
        std::from_chars(rendered.data(), rendered.data() + rendered.size(), plain, 10);
    if (plain_result.ec == std::errc{} && plain_result.ptr == rendered.data() + rendered.size() &&
        plain >= std::numeric_limits<i32>::min() && plain <= std::numeric_limits<i32>::max()) {
        return static_cast<i32>(plain);
    }
    struct Enc {
        std::string_view macro;
        i32 base;
    };
    constexpr Enc enc[] = {{"PTR", -270000000},  {"FLOAT", -240000000}, {"UF", -210000000},
                           {"UW", -190000000},   {"GSW", -170000000},   {"LSW", -150000000},
                           {"GSWF", -130000000}, {"LSWF", -110000000},  {"GF", -90000000},
                           {"LF", -70000000},    {"GW", -50000000},     {"LW", -30000000}};
    for (const auto& item : enc) {
        const std::string prefix = std::string(item.macro) + "(";
        if (!rendered.starts_with(prefix) || !rendered.ends_with(')'))
            continue;
        const std::string_view inner =
            rendered.substr(prefix.size(), rendered.size() - prefix.size() - 1);
        if (item.macro == "FLOAT") {
            try {
                const double value = std::stod(std::string(inner));
                const i64 encoded = item.base + std::llround(value * 1024.0);
                if (encoded < std::numeric_limits<i32>::min() ||
                    encoded > std::numeric_limits<i32>::max())
                    return std::nullopt;
                return static_cast<i32>(encoded);
            } catch (...) {
                return std::nullopt;
            }
        }
        i64 value = 0;
        const auto parsed = std::from_chars(inner.data(), inner.data() + inner.size(), value, 10);
        if (parsed.ec != std::errc{} || parsed.ptr != inner.data() + inner.size())
            return std::nullopt;
        const i64 encoded = item.base + value;
        if (encoded < std::numeric_limits<i32>::min() || encoded > std::numeric_limits<i32>::max())
            return std::nullopt;
        return static_cast<i32>(encoded);
    }
    return std::nullopt;
}

}  // namespace ember::cli::header_import_model
