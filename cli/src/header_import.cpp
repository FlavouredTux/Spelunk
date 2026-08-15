#include "header_import.hpp"

#include <algorithm>
#include <bit>
#include <cctype>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <map>
#include <optional>
#include <print>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/binary/symbol.hpp>
#include <ember/common/error.hpp>

#include "args.hpp"
#include "subcommands.hpp"
#include "util.hpp"

#ifdef EMBER_HAVE_LIBCLANG
#include <clang-c/Index.h>
#endif

namespace ember::cli {
namespace {

struct HeaderField {
    std::string name;
    std::string type;
    std::size_t offset = 0;
    std::size_t size = 0;
};
struct HeaderRecord {
    std::string name;
    std::size_t size = 0;
    std::vector<HeaderField> fields;
};
struct HeaderDatabase {
    std::map<std::string, FunctionSig, std::less<>> functions;
    std::map<std::string, HeaderRecord, std::less<>> records;
    std::map<std::string, std::string, std::less<>> globals;
    std::map<std::string, std::string, std::less<>> aliases;
    std::map<i64, std::string> enum_values;
    std::map<std::string, std::map<i64, std::string>, std::less<>> enums;
    std::size_t diagnostics = 0;
    std::vector<std::string> diagnostic_text;
};

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

#ifdef EMBER_HAVE_LIBCLANG
std::string cx_string(CXString s) {
    const char* p = clang_getCString(s);
    std::string out = p ? p : "";
    clang_disposeString(s);
    return out;
}

std::optional<HeaderRecord> read_record(CXCursor cursor, std::string name) {
    CXType ty = clang_getCursorType(cursor);
    const auto size = clang_Type_getSizeOf(ty);
    if (size < 0) return std::nullopt;
    HeaderRecord rec{.name = std::move(name), .size = static_cast<std::size_t>(size), .fields = {}};
    struct State { HeaderRecord* rec; } state{&rec};
    clang_visitChildren(cursor, [](CXCursor c, CXCursor, CXClientData raw) {
        if (clang_getCursorKind(c) != CXCursor_FieldDecl) return CXChildVisit_Continue;
        auto& target = *static_cast<State*>(raw)->rec;
        CXType ft = clang_getCursorType(c);
        const auto bits = clang_Cursor_getOffsetOfField(c);
        const auto bytes = clang_Type_getSizeOf(ft);
        if (bits < 0) return CXChildVisit_Continue;
        target.fields.push_back(HeaderField{
            .name = cx_string(clang_getCursorSpelling(c)),
            .type = cx_string(clang_getTypeSpelling(ft)),
            .offset = static_cast<std::size_t>(bits / 8),
            .size = bytes > 0 ? static_cast<std::size_t>(bytes) : 0,
        });
        return CXChildVisit_Continue;
    }, &state);
    return rec;
}

CXChildVisitResult visit_decl(CXCursor c, CXCursor, CXClientData raw) {
    auto& db = *static_cast<HeaderDatabase*>(raw);
    const auto kind = clang_getCursorKind(c);
    const std::string name = cx_string(clang_getCursorSpelling(c));
    if (kind == CXCursor_FunctionDecl && !name.empty()) {
        FunctionSig sig;
        CXType ft = clang_getCursorType(c);
        sig.variadic = clang_isFunctionTypeVariadic(ft) != 0;
        sig.return_type = cx_string(clang_getTypeSpelling(clang_getResultType(ft)));
        const int n = clang_Cursor_getNumArguments(c);
        for (int i = 0; i < n; ++i) {
            CXCursor arg = clang_Cursor_getArgument(c, static_cast<unsigned>(i));
            sig.params.push_back({cx_string(clang_getTypeSpelling(clang_getCursorType(arg))),
                                  cx_string(clang_getCursorSpelling(arg))});
        }
        db.functions.try_emplace(name, std::move(sig));
    } else if ((kind == CXCursor_StructDecl || kind == CXCursor_UnionDecl ||
                kind == CXCursor_ClassDecl) && !name.empty() && clang_isCursorDefinition(c)) {
        if (auto rec = read_record(c, unqualified(name))) db.records[rec->name] = std::move(*rec);
    } else if (kind == CXCursor_TypedefDecl && !name.empty()) {
        CXType underlying = clang_getTypedefDeclUnderlyingType(c);
        db.aliases[name] = cx_string(clang_getTypeSpelling(underlying));
        CXCursor decl = clang_getTypeDeclaration(underlying);
        const auto dk = clang_getCursorKind(decl);
        if ((dk == CXCursor_StructDecl || dk == CXCursor_UnionDecl || dk == CXCursor_ClassDecl) &&
            clang_isCursorDefinition(decl)) {
            if (auto rec = read_record(decl, name)) db.records[name] = std::move(*rec);
        }
    } else if (kind == CXCursor_VarDecl && !name.empty()) {
        const auto parent_kind = clang_getCursorKind(clang_getCursorSemanticParent(c));
        if (parent_kind == CXCursor_TranslationUnit || parent_kind == CXCursor_Namespace)
            db.globals.try_emplace(name, cx_string(clang_getTypeSpelling(clang_getCursorType(c))));
    } else if (kind == CXCursor_EnumConstantDecl && !name.empty()) {
        const i64 value = clang_getEnumConstantDeclValue(c);
        db.enum_values.try_emplace(value, name);
        const std::string enum_name = unqualified(cx_string(clang_getCursorSpelling(
            clang_getCursorSemanticParent(c))));
        if (!enum_name.empty()) db.enums[enum_name].try_emplace(value, name);
    }
    return CXChildVisit_Recurse;
}

Result<HeaderDatabase> import_headers(const Args& args) {
    HeaderDatabase db;
    if (args.header_paths.empty()) return db;
    std::vector<std::filesystem::path> files;
    std::set<std::filesystem::path> roots;
    std::error_code ec;
    for (const std::string& raw : args.header_paths) {
        std::filesystem::path p = std::filesystem::absolute(raw, ec);
        if (ec || !std::filesystem::exists(p))
            return std::unexpected(Error::io("header path does not exist: " + raw));
        if (std::filesystem::is_directory(p)) {
            roots.insert(p);
            for (std::filesystem::recursive_directory_iterator it(p, ec), end; it != end && !ec; it.increment(ec)) {
                if (!it->is_regular_file()) continue;
                const auto ext = it->path().extension().string();
                if (ext == ".h" || ext == ".hh" || ext == ".hpp" || ext == ".hxx") files.push_back(it->path());
            }
        } else {
            files.push_back(p);
            roots.insert(p.parent_path());
        }
    }
    if (files.empty()) return std::unexpected(Error::invalid_format("--headers found no header files"));
    std::sort(files.begin(), files.end());
    files.erase(std::unique(files.begin(), files.end()), files.end());

    std::string source;
    for (const auto& f : files) source += std::format("#include \"{}\"\n", f.string());
    std::vector<std::string> owned_args{"-x", "c++", "-std=c++20", "-target", "powerpc-unknown-eabi",
                                        "-DM2C=1", "-DRELAX_NAMESPACING=1", "-Wno-everything"};
    for (const auto& root : roots) owned_args.push_back("-I" + root.string());
    for (const auto& a : args.header_args) owned_args.push_back(a);
    std::vector<const char*> clang_args;
    for (const auto& a : owned_args) clang_args.push_back(a.c_str());

    CXIndex index = clang_createIndex(0, 0);
    CXUnsavedFile unsaved{"ember_headers.cpp", source.c_str(), static_cast<unsigned long>(source.size())};
    CXTranslationUnit tu = nullptr;
    const auto err = clang_parseTranslationUnit2(index, "ember_headers.cpp",
        clang_args.data(), static_cast<int>(clang_args.size()), &unsaved, 1,
        CXTranslationUnit_SkipFunctionBodies | CXTranslationUnit_KeepGoing, &tu);
    if (err != CXError_Success || tu == nullptr) {
        clang_disposeIndex(index);
        return std::unexpected(Error::invalid_format("libclang could not parse the requested headers"));
    }
    const unsigned diagnostics = clang_getNumDiagnostics(tu);
    for (unsigned i = 0; i < diagnostics; ++i) {
        CXDiagnostic d = clang_getDiagnostic(tu, i);
        const auto severity = clang_getDiagnosticSeverity(d);
        if (severity >= CXDiagnostic_Error) {
            ++db.diagnostics;
            db.diagnostic_text.push_back(cx_string(clang_formatDiagnostic(
                d, clang_defaultDiagnosticDisplayOptions())));
        }
        clang_disposeDiagnostic(d);
    }
    clang_visitChildren(clang_getTranslationUnitCursor(tu), visit_decl, &db);
    // UNKNOWN_FUNCTION deliberately erases the real prototype in decomp
    // headers.  Keep those declarations useful without claiming a false
    // zero-argument `void f(void)`: mark them incomplete/variadic so ABI
    // recovery may still supply observed arguments and return values.
    const std::regex unknown_function(
        R"(UNKNOWN_FUNCTION\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\))");
    const std::regex pointer_global(
        R"((?:extern\s+|DECOMP_STATIC\s*\(\s*)([A-Za-z_][A-Za-z0-9_:]*)\s*\*\s*([A-Za-z_][A-Za-z0-9_]*))");
    for (const auto& file : files) {
        std::ifstream in(file);
        if (!in) continue;
        const std::string contents((std::istreambuf_iterator<char>(in)),
                                   std::istreambuf_iterator<char>());
        for (std::sregex_iterator it(contents.begin(), contents.end(), unknown_function), end;
             it != end; ++it) {
            const std::string function_name = (*it)[1].str();
            if (function_name == "name") continue;  // macro definition itself
            db.functions[function_name] = FunctionSig{
                .return_type = "", .params = {}, .variadic = true};
        }
        for (std::sregex_iterator it(contents.begin(), contents.end(), pointer_global), end;
             it != end; ++it) {
            db.globals.insert_or_assign((*it)[2].str(), (*it)[1].str() + " *");
        }
    }
    clang_disposeTranslationUnit(tu);
    clang_disposeIndex(index);
    return db;
}
#else
Result<HeaderDatabase> import_headers(const Args& args) {
    if (!args.header_paths.empty())
        return std::unexpected(Error::unsupported("this Ember build has no libclang header importer"));
    return HeaderDatabase{};
}
#endif

const HeaderRecord* record_for(const HeaderDatabase& db, std::string type) {
    std::string base = base_type_name(std::move(type));
    if (auto it = db.records.find(base); it != db.records.end()) return &it->second;
    if (auto it = db.aliases.find(base); it != db.aliases.end()) {
        base = base_type_name(it->second);
        if (auto rit = db.records.find(base); rit != db.records.end()) return &rit->second;
    }
    return nullptr;
}

std::optional<addr_t> resolve_data_address(const Binary& b, std::string_view token) {
    if (auto a = parse_cli_addr(token)) return *a;
    if (const Symbol* s = b.find_by_name(token)) return s->addr;
    return std::nullopt;
}

struct TypeNode {
    enum class Kind { Scalar, Pointer, Array, Record } kind = Kind::Scalar;
    std::string name;
    std::size_t count = 0;
    const HeaderRecord* record = nullptr;
    std::unique_ptr<TypeNode> child;
};

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

std::size_t scalar_size(std::string name) {
    name = base_type_name(std::move(name));
    if (name == "u8" || name == "s8" || name == "char" || name == "bool" || name == "uint8_t" || name == "int8_t") return 1;
    if (name == "u16" || name == "s16" || name == "short" || name == "uint16_t" || name == "int16_t") return 2;
    if (name == "u64" || name == "s64" || name == "double" || name == "uint64_t" || name == "int64_t") return 8;
    return 4;
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

constexpr std::string_view kEvtNames[] = {
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

}  // namespace

int apply_header_annotations(const Args& args, const Binary& b,
                             Annotations& annotations, bool& loaded) {
    if (args.header_paths.empty()) return EXIT_SUCCESS;
    auto imported = import_headers(args);
    if (!imported) {
        std::println(stderr, "ember: --headers: {}: {}", imported.error().kind_name(), imported.error().message);
        return EXIT_FAILURE;
    }
    std::size_t sigs = 0, fields = 0;
    for (const auto& [name, rec] : imported->records)
        annotations.type_sizes.try_emplace(name, rec.size);
    for (const auto& [name, rec] : imported->records) {
        ImportedRecordLayout layout;
        layout.size = rec.size;
        for (const auto& field : rec.fields) {
            layout.fields.emplace(static_cast<i64>(field.offset), ImportedRecordField{
                .name = field.name, .type = field.type,
                .offset = field.offset, .size = field.size});
        }
        annotations.imported_records.try_emplace(name, std::move(layout));
    }
    annotations.imported_enums = imported->enums;
    annotations.imported_global_types_by_name = imported->globals;
    for (const auto& [name, type] : imported->globals) {
        const std::string base = base_type_name(type);
        if (!imported->records.contains(base)) continue;
        auto [it, inserted] = annotations.type_global_names.try_emplace(base, name);
        if (!inserted && it->second != name) it->second.clear();
    }
    // DTK maps may expose aliases for the same SDA slot. Resolve the header's
    // own spelling directly first so a preceding `lbl_*` alias cannot prevent
    // the real pointer type from reaching that address.
    for (const auto& [name, type] : imported->globals) {
        if (const Symbol* symbol = b.find_by_name(name);
            symbol && symbol->kind == SymbolKind::Object && !symbol->is_import) {
            annotations.global_types.insert_or_assign(symbol->addr, type);
        }
    }
    for (const auto& sym : b.symbols()) {
        if (sym.kind != SymbolKind::Object || sym.is_import || sym.name.empty()) continue;
        if (auto it = imported->globals.find(sym.name); it != imported->globals.end())
            annotations.global_types.try_emplace(sym.addr, it->second);
    }
    for (const auto& sym : b.symbols()) {
        if (sym.kind != SymbolKind::Function || sym.is_import || sym.name.empty()) continue;
        auto it = imported->functions.find(sym.name);
        if (it == imported->functions.end()) it = imported->functions.find(unqualified(sym.name));
        if (it == imported->functions.end()) continue;
        if (annotations.signatures.try_emplace(sym.addr, it->second).second) ++sigs;
        for (std::size_t p = 0; p < it->second.params.size(); ++p) {
            if (const auto* rec = record_for(*imported, it->second.params[p].type)) {
                for (const auto& f : rec->fields)
                    if (annotations.field_names.try_emplace(FieldKey{sym.addr, p, static_cast<i64>(f.offset)}, f.name).second) ++fields;
            }
        }
    }
    // Enum declarations stay typed in the header database. Flattening every
    // enum into the annotation constant map would make common values such as
    // zero acquire an arbitrary unrelated name throughout pseudo-C.
    loaded |= sigs != 0 || fields != 0;
    if (!args.quiet) std::println(stderr,
        "ember: headers: {} prototype(s), {} field(s), {} enum value(s), {} record(s){}",
        sigs, fields, imported->enum_values.size(), imported->records.size(),
        imported->diagnostics ? std::format(", {} parse diagnostic(s)", imported->diagnostics) : "");
    if (args.verbose) {
        for (const auto& diagnostic : imported->diagnostic_text)
            std::println(stderr, "ember: headers: {}", diagnostic);
    }
    return EXIT_SUCCESS;
}

int run_decompile_data(const Args& args, const Binary& b) {
    if (args.data_type.empty()) {
        std::println(stderr, "ember: --decompile-data requires --type TYPE");
        return EXIT_FAILURE;
    }
    auto imported = import_headers(args);
    if (!imported) {
        std::println(stderr, "ember: --headers: {}: {}", imported.error().kind_name(), imported.error().message);
        return EXIT_FAILURE;
    }
    const auto at = resolve_data_address(b, args.decompile_data);
    if (!at) {
        std::println(stderr, "ember: --decompile-data: unknown symbol/address '{}'", args.decompile_data);
        return EXIT_FAILURE;
    }
    auto type = parse_type(*imported, args.data_type);
    if (!type || type_size(*type, b.arch() == Arch::Ppc32 ? 4 : 8) == 0) {
        std::println(stderr, "ember: --type: unknown or incomplete type '{}'", args.data_type);
        return EXIT_FAILURE;
    }
    const std::size_t pointer_size = b.arch() == Arch::Ppc32 ? 4 : 8;
    const std::size_t bytes = type_size(*type, pointer_size);
    if (b.bytes_at(*at).size() < bytes) {
        std::println(stderr, "ember: --decompile-data: {} needs {:#x} bytes, only {:#x} mapped",
                     args.data_type, bytes, b.bytes_at(*at).size());
        return EXIT_FAILURE;
    }
    std::string declaration = args.data_type;
    const std::string var = unqualified(args.decompile_data);
    if (const auto bracket = declaration.find('['); bracket != std::string::npos)
        declaration.insert(bracket, " " + var);
    else
        declaration += " " + var;
    std::println("{} = {};", declaration,
                 render_value(*imported, b, *type, *at, 0, pointer_size));
    return EXIT_SUCCESS;
}

int run_evt_script(const Args& args, const Binary& b) {
    const auto at = resolve_data_address(b, args.evt_script);
    if (!at) {
        std::println(stderr, "ember: --evt-script: unknown symbol/address '{}'", args.evt_script);
        return EXIT_FAILURE;
    }
    std::println("EVT_BEGIN({})", unqualified(args.evt_script));
    addr_t pc = *at;
    unsigned indent = 1;
    for (std::size_t inst_no = 0; inst_no < 65536; ++inst_no) {
        if (b.bytes_at(pc).size() < 4) {
            std::println(stderr, "ember: --evt-script: truncated instruction at {:#x}", pc);
            return EXIT_FAILURE;
        }
        const u32 word = static_cast<u32>(read_uint(b, pc, 4));
        const u16 opcode = static_cast<u16>(word & 0xffffu);
        const u16 argc = static_cast<u16>(word >> 16);
        if (opcode >= std::size(kEvtNames) || argc > 64) {
            std::println(stderr, "ember: --evt-script: invalid opcode/count {:#x}/{} at {:#x}", opcode, argc, pc);
            return EXIT_FAILURE;
        }
        const std::string_view name = kEvtNames[opcode];
        if (name == "END_IF" || name == "END_SWITCH" || name == "WHILE" ||
            name == "END_INLINE" || name == "END_BROTHER" || name == "ELSE") {
            if (indent > 1) --indent;
        }
        std::string line(indent * 2, ' ');
        line += name;
        line += '(';
        for (u16 i = 0; i < argc; ++i) {
            if (i) line += ", ";
            const addr_t arg_site = pc + 4 + i * 4;
            const i32 value = static_cast<i32>(read_uint(b, arg_site, 4));
            const bool pointer_hint = (name == "USER_FUNC" && i == 0) ||
                ((name == "RUN_EVT" || name == "RUN_CHILD_EVT" || name == "INLINE_EVT" || name == "BROTHER_EVT") && i == 0);
            line += evt_arg(b, arg_site, value, pointer_hint);
        }
        line += ')';
        std::println("{}", line);
        pc += 4 + static_cast<addr_t>(argc) * 4;
        if (name == "END_SCRIPT") { std::println("EVT_END()"); return EXIT_SUCCESS; }
        if (name.starts_with("IF_") || name.starts_with("IFF_") || name == "SWITCH" || name == "SWITCHI" ||
            name == "DO" || name == "INLINE_EVT" || name == "INLINE_EVT_ID" || name == "BROTHER_EVT" ||
            name == "BROTHER_EVT_ID" || name == "ELSE") ++indent;
    }
    std::println(stderr, "ember: --evt-script: instruction limit reached");
    return EXIT_FAILURE;
}

}  // namespace ember::cli
