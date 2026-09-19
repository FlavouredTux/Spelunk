#include <spelunk/common/diagnostic.hpp>
#include "header_import.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <cstdlib>
#include <expected>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <map>
#include <optional>
#include <print>
#include <regex>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <spelunk/binary/arch.hpp>
#include <spelunk/binary/binary.hpp>
#include <spelunk/binary/symbol.hpp>
#include <spelunk/common/annotations.hpp>
#include <spelunk/common/error.hpp>
#include <spelunk/common/types.hpp>

#include "args.hpp"
#include "header_import_internal.hpp"
#include "subcommands.hpp"
#include "util.hpp"

#ifdef SPELUNK_HAVE_LIBCLANG
#include <clang-c/CXDiagnostic.h>
#include <clang-c/CXErrorCode.h>
#include <clang-c/CXString.h>
#include <clang-c/Index.h>
#endif

namespace spelunk::cli {
namespace model = header_import_model;
namespace {

#ifdef SPELUNK_HAVE_LIBCLANG
std::string cx_string(CXString s) {
    const char* p = clang_getCString(s);
    std::string out = p ? p : "";
    clang_disposeString(s);
    return out;
}

std::optional<model::HeaderRecord> read_record(CXCursor cursor, std::string name) {
    CXType ty = clang_getCursorType(cursor);
    const auto size = clang_Type_getSizeOf(ty);
    if (size < 0) return std::nullopt;
    model::HeaderRecord rec{
        .name = std::move(name),
        .size = static_cast<std::size_t>(size),
        .is_union = clang_getCursorKind(cursor) == CXCursor_UnionDecl,
        .fields = {}};
    struct State { model::HeaderRecord* rec; } state{&rec};
    clang_visitChildren(cursor, [](CXCursor c, CXCursor, CXClientData raw) {
        if (clang_getCursorKind(c) != CXCursor_FieldDecl) return CXChildVisit_Continue;
        auto& target = *static_cast<State*>(raw)->rec;
        CXType ft = clang_getCursorType(c);
        const auto bits = clang_Cursor_getOffsetOfField(c);
        const auto bytes = clang_Type_getSizeOf(ft);
        if (bits < 0) return CXChildVisit_Continue;
        target.fields.push_back(model::HeaderField{
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
    auto& db = *static_cast<model::HeaderDatabase*>(raw);
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
        if (auto rec = read_record(c, model::unqualified(name))) db.records[rec->name] = std::move(*rec);
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
        const std::string enum_name = model::unqualified(cx_string(clang_getCursorSpelling(
            clang_getCursorSemanticParent(c))));
        if (!enum_name.empty()) db.enums[enum_name].try_emplace(value, name);
    }
    return CXChildVisit_Recurse;
}

Result<model::HeaderDatabase> import_headers(const Args& args) {
    model::HeaderDatabase db;
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
    CXUnsavedFile unsaved{"spelunk_headers.cpp", source.c_str(), static_cast<unsigned long>(source.size())};
    CXTranslationUnit tu = nullptr;
    const auto err = clang_parseTranslationUnit2(index, "spelunk_headers.cpp",
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
Result<model::HeaderDatabase> import_headers(const Args& args) {
    if (!args.header_paths.empty())
        return std::unexpected(Error::unsupported("this Spelunk build has no libclang header importer"));
    return model::HeaderDatabase{};
}
#endif

std::optional<addr_t> resolve_data_address(const Binary& b, std::string_view token) {
    if (auto a = parse_cli_addr(token)) return *a;
    if (const Symbol* s = b.find_by_name(token)) return s->addr;
    return std::nullopt;
}

std::map<addr_t, std::string> load_dtk_linker_aliases(const Args& args) {
    std::map<addr_t, std::string> aliases;
    if (args.dtk_version.empty()) return aliases;
    std::string version = args.dtk_version;
    std::ranges::transform(version, version.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    std::set<std::filesystem::path> candidates;
    std::error_code ec;
    for (const std::string& raw : args.header_paths) {
        auto path = std::filesystem::absolute(raw, ec);
        if (ec) { ec.clear(); continue; }
        const auto directory = std::filesystem::is_directory(path)
            ? path : path.parent_path();
        if (directory.filename() == "include") {
            candidates.insert(directory.parent_path() / "linker" /
                              std::format("spm.{}.lst", version));
        }
    }
    if (!args.dtk_project_path.empty()) {
        auto project = std::filesystem::absolute(args.dtk_project_path, ec);
        if (!ec) {
            candidates.insert(project / "spm-headers" / "linker" /
                              std::format("spm.{}.lst", version));
        }
    }

    for (const auto& path : candidates) {
        std::ifstream input(path);
        if (!input) continue;
        std::string line;
        while (std::getline(input, line)) {
            const auto colon = line.find(':');
            if (colon == std::string::npos || colon == 0) continue;
            addr_t address = 0;
            const std::string_view raw_address(line.data(), colon);
            const auto parsed = std::from_chars(
                raw_address.data(), raw_address.data() + raw_address.size(),
                address, 16);
            if (parsed.ec != std::errc{} ||
                parsed.ptr != raw_address.data() + raw_address.size()) continue;
            std::string name = model::trim(line.substr(colon + 1));
            if (name.empty() ||
                (!std::isalpha(static_cast<unsigned char>(name.front())) &&
                 name.front() != '_')) continue;
            if (!std::ranges::all_of(name, [](unsigned char c) {
                    return std::isalnum(c) != 0 || c == '_';
                })) continue;
            aliases.try_emplace(address, std::move(name));
        }
        if (!aliases.empty()) break;
    }
    return aliases;
}

}  // namespace

int apply_header_annotations(const Args& args, const Binary& b,
                             Annotations& annotations, bool& loaded) {
    if (args.header_paths.empty()) return EXIT_SUCCESS;
    auto imported = import_headers(args);
    if (!imported) {
        spelunk::diagnostic::print("spelunk: --headers: {}: {}", imported.error().kind_name(), imported.error().message);
        return EXIT_FAILURE;
    }
    std::size_t sigs = 0, fields = 0;
    for (const auto& [name, rec] : imported->records)
        annotations.type_sizes.try_emplace(name, rec.size);
    for (const auto& [name, rec] : imported->records) {
        ImportedRecordLayout layout;
        layout.size = rec.size;
        layout.is_union = rec.is_union;
        for (const auto& field : rec.fields) {
            layout.fields.emplace(static_cast<i64>(field.offset), ImportedRecordField{
                .name = field.name, .type = field.type,
                .offset = field.offset, .size = field.size});
        }
        annotations.imported_records.try_emplace(name, std::move(layout));
    }
    annotations.imported_enums = imported->enums;
    annotations.imported_global_types_by_name = imported->globals;
    annotations.imported_aliases = imported->aliases;
    const auto linker_aliases = load_dtk_linker_aliases(args);
    for (const auto& [address, name] : linker_aliases) {
        auto type = imported->globals.find(name);
        if (type == imported->globals.end()) continue;
        const Symbol* object = b.defined_object_at(address);
        if (!object || object->kind != SymbolKind::Object ||
            object->addr != address) continue;
        annotations.global_types.insert_or_assign(address, type->second);
        annotations.preferred_global_names.insert_or_assign(address, name);
    }
    for (const auto& [name, type] : imported->globals) {
        const std::string base = model::base_type_name(type);
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
        if (it == imported->functions.end())
            it = imported->functions.find(model::unqualified(sym.name));
        if (it == imported->functions.end()) continue;
        if (annotations.signatures.try_emplace(sym.addr, it->second).second) ++sigs;
        for (std::size_t p = 0; p < it->second.params.size(); ++p) {
            if (const auto* rec = model::record_for(*imported, it->second.params[p].type)) {
                for (const auto& f : rec->fields)
                    if (annotations.field_names.try_emplace(FieldKey{sym.addr, p, static_cast<i64>(f.offset)}, f.name).second) ++fields;
            }
        }
    }
    // Enum declarations stay typed in the header database. Flattening every
    // enum into the annotation constant map would make common values such as
    // zero acquire an arbitrary unrelated name throughout pseudo-C.
    loaded |= sigs != 0 || fields != 0;
    if (!args.quiet) spelunk::diagnostic::print("spelunk: headers: {} prototype(s), {} field(s), {} enum value(s), {} record(s){}",
        sigs, fields, imported->enum_values.size(), imported->records.size(),
        imported->diagnostics ? std::format(", {} parse diagnostic(s)", imported->diagnostics) : "");
    if (args.verbose) {
        for (const auto& diagnostic : imported->diagnostic_text)
            spelunk::diagnostic::print("spelunk: headers: {}", diagnostic);
    }
    return EXIT_SUCCESS;
}

int run_decompile_data(const Args& args, const Binary& b) {
    if (args.data_type.empty()) {
        spelunk::diagnostic::print("spelunk: --decompile-data requires --type TYPE");
        return EXIT_FAILURE;
    }
    auto imported = import_headers(args);
    if (!imported) {
        spelunk::diagnostic::print("spelunk: --headers: {}: {}", imported.error().kind_name(), imported.error().message);
        return EXIT_FAILURE;
    }
    const auto at = resolve_data_address(b, args.decompile_data);
    if (!at) {
        spelunk::diagnostic::print("spelunk: --decompile-data: unknown symbol/address '{}'", args.decompile_data);
        return EXIT_FAILURE;
    }
    auto type = model::parse_type(*imported, args.data_type);
    if (!type || model::type_size(*type, b.arch() == Arch::Ppc32 ? 4 : 8) == 0) {
        spelunk::diagnostic::print("spelunk: --type: unknown or incomplete type '{}'", args.data_type);
        return EXIT_FAILURE;
    }
    const std::size_t pointer_size = b.arch() == Arch::Ppc32 ? 4 : 8;
    const std::size_t bytes = model::type_size(*type, pointer_size);
    if (b.bytes_at(*at).size() < bytes) {
        spelunk::diagnostic::print("spelunk: --decompile-data: {} needs {:#x} bytes, only {:#x} mapped",
                     args.data_type, bytes, b.bytes_at(*at).size());
        return EXIT_FAILURE;
    }
    std::string declaration = args.data_type;
    const std::string var = parse_cli_addr(args.decompile_data)
                                ? std::format("data_{:x}", *at)
                                : model::unqualified(args.decompile_data);
    if (const auto bracket = declaration.find('['); bracket != std::string::npos)
        declaration.insert(bracket, " " + var);
    else
        declaration += " " + var;
    const std::string initializer =
        model::render_value(*imported, b, *type, *at, 0, pointer_size);
    if (args.verify_roundtrip) {
        auto verified =
            model::verify_typed_roundtrip(*imported, b, *type, *at, pointer_size);
        if (!verified) {
            spelunk::diagnostic::print("spelunk: --verify-roundtrip: {}: {}", verified.error().kind_name(),
                         verified.error().message);
            return EXIT_FAILURE;
        }
        spelunk::diagnostic::print("spelunk: round-trip verified: {} object(s), {:#x} bytes, {} "
                     "pointer(s), {} relocation(s)",
                     verified->objects, verified->bytes, verified->pointers, verified->relocations);
    }
    std::println("{} = {};", declaration, initializer);
    return EXIT_SUCCESS;
}

int run_evt_script(const Args& args, const Binary& b) {
    const auto at = resolve_data_address(b, args.evt_script);
    if (!at) {
        spelunk::diagnostic::print("spelunk: --evt-script: unknown symbol/address '{}'", args.evt_script);
        return EXIT_FAILURE;
    }
    // The manual advertises "--json where supported"; this writer has
    // no machine form, so announce the downgrade instead of silently
    // emitting plain text under a --json-expecting script.
    if (args.json) {
        spelunk::diagnostic::print("spelunk: --evt-script has no --json output; emitting plain text");
    }
    // Decode and validate the whole script before anything reaches
    // stdout. Emitting while parsing used to leave a partial EVT_BEGIN
    // body trailing the error line - and because stdout block-buffers
    // under a pipe while stderr does not, the already-written header
    // even appeared AFTER the diagnostic. Nothing is printed unless the
    // last opcode validates.
    std::vector<std::string> lines;
    addr_t pc = *at;
    unsigned indent = 1;
    std::vector<std::byte> encoded;
    std::size_t relocation_args = 0;
    std::size_t symbolic_args = 0;
    bool reached_end = false;
    const auto append_word = [&](u32 value) {
        const std::size_t offset = encoded.size();
        encoded.resize(offset + 4);
        model::write_uint(encoded, offset, 4, value, b.endian());
    };
    for (std::size_t inst_no = 0; inst_no < 65536; ++inst_no) {
        if (b.bytes_at(pc).size() < 4) {
            spelunk::diagnostic::print("spelunk: --evt-script: truncated instruction at {:#x}", pc);
            return EXIT_FAILURE;
        }
        const u32 word = static_cast<u32>(model::read_uint(b, pc, 4));
        const u16 opcode = static_cast<u16>(word & 0xffffu);
        const u16 argc = static_cast<u16>(word >> 16);
        if (opcode >= std::size(model::kEvtNames) || argc > 64) {
            spelunk::diagnostic::print("spelunk: --evt-script: invalid opcode/count {:#x}/{} at {:#x}", opcode, argc, pc);
            return EXIT_FAILURE;
        }
        const std::string_view name = model::kEvtNames[opcode];
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
            const i32 value = static_cast<i32>(model::read_uint(b, arg_site, 4));
            const bool pointer_hint = (name == "USER_FUNC" && i == 0) ||
                ((name == "RUN_EVT" || name == "RUN_CHILD_EVT" || name == "INLINE_EVT" || name == "BROTHER_EVT") && i == 0);
            const std::string rendered =
                model::evt_arg(b, arg_site, value, pointer_hint);
            line += rendered;
            if (args.verify_roundtrip) {
                const bool relocated = model::relocation_at(b, arg_site, 4) != nullptr;
                if (relocated)
                    ++relocation_args;
                if (auto roundtrip = model::evt_scalar_from_rendered(rendered);
                    roundtrip && !relocated) {
                    if (*roundtrip != value) {
                        spelunk::diagnostic::print("spelunk: --verify-roundtrip: '{}' re-encodes as "
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
        lines.push_back(std::move(line));
        pc += 4 + static_cast<addr_t>(argc) * 4;
        if (name == "END_SCRIPT") {
            reached_end = true;
            break;
        }
        if (name.starts_with("IF_") || name.starts_with("IFF_") || name == "SWITCH" || name == "SWITCHI" ||
            name == "DO" || name == "INLINE_EVT" || name == "INLINE_EVT_ID" || name == "BROTHER_EVT" ||
            name == "BROTHER_EVT_ID" || name == "ELSE") ++indent;
    }
    if (!reached_end) {
        spelunk::diagnostic::print("spelunk: --evt-script: instruction limit reached");
        return EXIT_FAILURE;
    }
    // Byte-level round-trip check runs before the dump too, so a
    // mismatch aborts with a reason and no partial body.
    if (args.verify_roundtrip) {
        const auto original = b.bytes_at(*at);
        if (original.size() < encoded.size()) {
            spelunk::diagnostic::print("spelunk: --verify-roundtrip: re-encoded {} bytes but only "
                         "{} source bytes mapped at {:#x}",
                         encoded.size(), original.size(), *at);
            return EXIT_FAILURE;
        }
        for (std::size_t i = 0; i < encoded.size(); ++i) {
            if (original[i] == encoded[i])
                continue;
            spelunk::diagnostic::print("spelunk: --verify-roundtrip: event mismatch at {:#x}: "
                         "source {:#04x}, encoded {:#04x}",
                         *at + i, std::to_integer<unsigned>(original[i]),
                         std::to_integer<unsigned>(encoded[i]));
            return EXIT_FAILURE;
        }
    }
    std::println("EVT_BEGIN({})", model::unqualified(args.evt_script));
    for (const auto& line : lines) std::println("{}", line);
    std::println("EVT_END()");
    if (args.verify_roundtrip) {
        spelunk::diagnostic::print("spelunk: round-trip verified: {} event bytes, {} symbolic "
                     "argument(s), {} relocation(s)",
                     encoded.size(), symbolic_args, relocation_args);
    }
    return EXIT_SUCCESS;
}

}  // namespace spelunk::cli
