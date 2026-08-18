#include "header_import.hpp"

#include <algorithm>
#include <bit>
#include <cctype>
#include <charconv>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <limits>
#include <map>
#include <optional>
#include <print>
#include <regex>
#include <set>
#include <span>
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
    std::set<std::filesystem::path> include_roots;
    std::error_code ec;
    for (const std::string& raw : args.header_paths) {
        std::filesystem::path p = std::filesystem::absolute(raw, ec);
        if (ec || !std::filesystem::exists(p))
            return std::unexpected(Error::io("header path does not exist: " + raw));
        if (std::filesystem::is_directory(p)) {
            include_roots.insert(p);
            if (p.filename() == "include") {
                for (std::string_view sibling : {"decomp", "mod"}) {
                    const auto candidate = p.parent_path() / sibling;
                    if (std::filesystem::is_directory(candidate)) {
                        include_roots.insert(candidate);
                    }
                }
            }
            for (std::filesystem::recursive_directory_iterator it(p, ec), end; it != end && !ec; it.increment(ec)) {
                if (!it->is_regular_file()) continue;
                const auto ext = it->path().extension().string();
                if (ext == ".h" || ext == ".hh" || ext == ".hpp" || ext == ".hxx") files.push_back(it->path());
            }
        } else {
            files.push_back(p);
            include_roots.insert(p.parent_path());
        }
    }
    if (files.empty()) return std::unexpected(Error::invalid_format("--headers found no header files"));
    std::sort(files.begin(), files.end());
    files.erase(std::unique(files.begin(), files.end()), files.end());

    std::string source;
    for (const auto& f : files) source += std::format("#include \"{}\"\n", f.string());
    std::vector<std::string> owned_args{"-x", "c++", "-std=c++20", "-target", "powerpc-unknown-eabi",
                                        "-DM2C=1", "-DRELAX_NAMESPACING=1", "-Wno-everything"};
    for (const auto& root : include_roots) owned_args.push_back("-I" + root.string());
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
    const std::regex decomp_static(R"(DECOMP_STATIC\s*\(\s*([^()\r\n]+)\s*\))");
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
        for (std::sregex_iterator it(contents.begin(), contents.end(), decomp_static), end;
             it != end; ++it) {
            std::string declaration = (*it)[1].str();
            if (declaration.find('(') != std::string::npos) continue;
            while (!declaration.empty() && std::isspace(
                       static_cast<unsigned char>(declaration.back()))) {
                declaration.pop_back();
            }
            const std::regex object_decl(
                R"(^\s*(.+?[\s*])([A-Za-z_][A-Za-z0-9_]*)(\s*(?:\[[^\]]*\])*)\s*$)");
            std::smatch match;
            if (!std::regex_match(declaration, match, object_decl)) continue;
            std::string type = match[1].str();
            while (!type.empty() && std::isspace(
                       static_cast<unsigned char>(type.back()))) {
                type.pop_back();
            }
            std::string arrays = match[3].str();
            arrays.erase(std::remove_if(arrays.begin(), arrays.end(),
                [](unsigned char c) { return std::isspace(c) != 0; }), arrays.end());
            db.globals.insert_or_assign(match[2].str(), type + arrays);
        }
    }
    // Decomp projects often keep still-unknown prototypes beside the source
    // unit rather than in the public header set. Import simple C declarations
    // and definitions as lower-priority project evidence so sibling callers
    // can share their return/parameter layout without parsing function bodies.
    if (!args.dtk_project_path.empty()) {
        std::filesystem::path project = std::filesystem::absolute(
            args.dtk_project_path, ec);
        std::filesystem::path source_root = project / "src";
        if (!ec && std::filesystem::is_directory(source_root)) {
            std::vector<std::filesystem::path> source_files;
            for (std::filesystem::recursive_directory_iterator it(source_root, ec), end;
                 it != end && !ec; it.increment(ec)) {
                if (!it->is_regular_file()) continue;
                const auto ext = it->path().extension().string();
                if (ext == ".c" || ext == ".cc" || ext == ".cpp" || ext == ".cxx") {
                    source_files.push_back(it->path());
                }
            }
            std::sort(source_files.begin(), source_files.end());
            const std::regex function_decl(
                R"((?:^|\n)\s*(?:(?:extern|static|inline)\s+)*([A-Za-z_][A-Za-z0-9_:]*(?:\s*\*)?)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^;{}\n]*)\)\s*(?:;|\{))");
            for (const auto& file : source_files) {
                std::ifstream in(file);
                if (!in) continue;
                const std::string contents((std::istreambuf_iterator<char>(in)),
                                           std::istreambuf_iterator<char>());
                for (std::sregex_iterator it(contents.begin(), contents.end(), function_decl), end;
                     it != end; ++it) {
                    const std::string name = (*it)[2].str();
                    if (db.functions.contains(name)) continue;
                    FunctionSig signature;
                    signature.return_type = (*it)[1].str();
                    std::string params = (*it)[3].str();
                    std::size_t start = 0;
                    std::size_t param_index = 0;
                    while (start <= params.size()) {
                        std::size_t comma = params.find(',', start);
                        if (comma == std::string::npos) comma = params.size();
                        std::string param = params.substr(start, comma - start);
                        while (!param.empty() && std::isspace(
                                   static_cast<unsigned char>(param.front()))) {
                            param.erase(param.begin());
                        }
                        while (!param.empty() && std::isspace(
                                   static_cast<unsigned char>(param.back()))) {
                            param.pop_back();
                        }
                        if (param == "...") {
                            signature.variadic = true;
                        } else if (!param.empty() && param != "void") {
                            const std::regex named_param(
                                R"(^(.+?[\s*])([A-Za-z_][A-Za-z0-9_]*)\s*$)");
                            std::smatch match;
                            if (std::regex_match(param, match, named_param)) {
                                std::string type = match[1].str();
                                while (!type.empty() && std::isspace(
                                           static_cast<unsigned char>(type.back()))) {
                                    type.pop_back();
                                }
                                signature.params.push_back({type, match[2].str()});
                            } else {
                                signature.params.push_back(
                                    {param, std::format("param_{}", param_index + 1)});
                            }
                            ++param_index;
                        }
                        if (comma == params.size()) break;
                        start = comma + 1;
                    }
                    db.functions.try_emplace(name, std::move(signature));
                }
            }
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

struct RoundtripStats {
    std::size_t objects = 0;
    std::size_t bytes = 0;
    std::size_t pointers = 0;
    std::size_t relocations = 0;
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
    const std::string var = parse_cli_addr(args.decompile_data)
                                ? std::format("data_{:x}", *at)
                                : unqualified(args.decompile_data);
    if (const auto bracket = declaration.find('['); bracket != std::string::npos)
        declaration.insert(bracket, " " + var);
    else
        declaration += " " + var;
    const std::string initializer =
        render_value(*imported, b, *type, *at, 0, pointer_size);
    if (args.verify_roundtrip) {
        auto verified = verify_typed_roundtrip(*imported, b, *type, *at, pointer_size);
        if (!verified) {
            std::println(stderr, "ember: --verify-roundtrip: {}: {}", verified.error().kind_name(),
                         verified.error().message);
            return EXIT_FAILURE;
        }
        std::println(stderr,
                     "ember: round-trip verified: {} object(s), {:#x} bytes, {} "
                     "pointer(s), {} relocation(s)",
                     verified->objects, verified->bytes, verified->pointers, verified->relocations);
    }
    std::println("{} = {};", declaration, initializer);
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
    std::vector<std::byte> encoded;
    std::size_t relocation_args = 0;
    std::size_t symbolic_args = 0;
    const auto append_word = [&](u32 value) {
        const std::size_t offset = encoded.size();
        encoded.resize(offset + 4);
        write_uint(encoded, offset, 4, value, b.endian());
    };
    const auto verify_encoded = [&]() -> bool {
        if (!args.verify_roundtrip)
            return true;
        const auto original = b.bytes_at(*at);
        if (original.size() < encoded.size())
            return false;
        for (std::size_t i = 0; i < encoded.size(); ++i) {
            if (original[i] == encoded[i])
                continue;
            std::println(stderr,
                         "ember: --verify-roundtrip: event mismatch at {:#x}: "
                         "source {:#04x}, encoded {:#04x}",
                         *at + i, std::to_integer<unsigned>(original[i]),
                         std::to_integer<unsigned>(encoded[i]));
            return false;
        }
        std::println(stderr,
                     "ember: round-trip verified: {} event bytes, {} symbolic "
                     "argument(s), {} relocation(s)",
                     encoded.size(), symbolic_args, relocation_args);
        return true;
    };
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
        append_word(word);
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
            const std::string rendered =
                evt_arg(b, arg_site, value, pointer_hint);
            line += rendered;
            if (args.verify_roundtrip) {
                const bool relocated = relocation_at(b, arg_site, 4) != nullptr;
                if (relocated)
                    ++relocation_args;
                if (auto roundtrip = evt_scalar_from_rendered(rendered); roundtrip && !relocated) {
                    if (*roundtrip != value) {
                        std::println(stderr,
                                     "ember: --verify-roundtrip: '{}' re-encodes as "
                                     "{}, expected {} at {:#x}",
                                     rendered, *roundtrip, value, arg_site);
                        return EXIT_FAILURE;
                    }
                    append_word(static_cast<u32>(*roundtrip));
                } else {
                    ++symbolic_args;
                    append_word(static_cast<u32>(value));
                }
            }
        }
        line += ')';
        std::println("{}", line);
        pc += 4 + static_cast<addr_t>(argc) * 4;
        if (name == "END_SCRIPT") {
            std::println("EVT_END()");
            return verify_encoded() ? EXIT_SUCCESS : EXIT_FAILURE;
        }
        if (name.starts_with("IF_") || name.starts_with("IFF_") || name == "SWITCH" || name == "SWITCHI" ||
            name == "DO" || name == "INLINE_EVT" || name == "INLINE_EVT_ID" || name == "BROTHER_EVT" ||
            name == "BROTHER_EVT_ID" || name == "ELSE") ++indent;
    }
    std::println(stderr, "ember: --evt-script: instruction limit reached");
    return EXIT_FAILURE;
}

}  // namespace ember::cli
