// Declarations and explicit memory accesses for C exports.
#include "emitter_internal.hpp"
#include "emitter_text.hpp"

#include <ember/disasm/register.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <format>
#include <regex>

namespace ember::emit {
namespace {

// Words that already name a type (or can never begin one). A candidate that
// survives the "only ever used as `NAME *`" test still has to clear this
// list before we invent a record for it.
[[nodiscard]] bool known_c_type_word(std::string_view word) noexcept {
    static const std::set<std::string_view> known{
        "void", "char", "short", "int", "long", "float", "double", "signed",
        "unsigned", "bool", "_Bool", "const", "volatile", "restrict",
        "struct", "union", "enum", "typedef", "static", "extern", "inline",
        "return", "sizeof", "if", "else", "while", "for", "do", "switch",
        "case", "default", "break", "continue", "goto", "register", "auto",
        "int8_t", "int16_t", "int32_t", "int64_t",
        "uint8_t", "uint16_t", "uint32_t", "uint64_t",
        "intptr_t", "uintptr_t", "size_t", "ssize_t", "ptrdiff_t",
        "wchar_t", "FILE", "va_list",
        "__m128", "__m128i", "__m128d", "__m256", "__m256i", "__m256d",
        "__m512", "__m512i", "__m512d",
    };
    return known.contains(word);
}

// C type for a register that is read without a reaching definition.
[[nodiscard]] std::string_view register_c_type(unsigned bytes) noexcept {
    switch (bytes) {
        case 1:  return "uint8_t";
        case 2:  return "uint16_t";
        case 4:  return "uint32_t";
        case 8:  return "uint64_t";
        case 16: return "__m128i";
        case 32: return "__m256i";
        case 64: return "__m512i";
        default: return {};
    }
}

// Flag predicates, conversions, rotates and string operations print as plain
// calls. Each one that survives into a body gets its exact definition in the
// preamble, so an export stays self-contained instead of leaning on a
// preamble the caller has to supply.
struct CHelper { std::string_view name; std::string_view definition; };
constexpr std::array kCHelpers{
    CHelper{"cvtsd2ss", "static inline float cvtsd2ss(double x) { return (float)x; }"},
    CHelper{"cvtss2sd", "static inline double cvtss2sd(float x) { return (double)x; }"},
    CHelper{"cvtsi2sd", "static inline double cvtsi2sd(int64_t x) { return (double)x; }"},
    CHelper{"cvtsi2ss", "static inline float cvtsi2ss(int64_t x) { return (float)x; }"},
    CHelper{"cvttsd2si", "static inline int64_t cvttsd2si(double x) { return (int64_t)x; }"},
    CHelper{"cvttss2si", "static inline int64_t cvttss2si(float x) { return (int64_t)x; }"},
    CHelper{"carry_add",
            "static inline int carry_add(uint64_t a, uint64_t b) "
            "{ uint64_t r; return __builtin_add_overflow(a, b, &r); }"},
    CHelper{"borrow_sub",
            "static inline int borrow_sub(uint64_t a, uint64_t b) "
            "{ uint64_t r; return __builtin_sub_overflow(a, b, &r); }"},
    CHelper{"overflow_add",
            "static inline int overflow_add(int64_t a, int64_t b) "
            "{ int64_t r; return __builtin_add_overflow(a, b, &r); }"},
    CHelper{"overflow_sub",
            "static inline int overflow_sub(int64_t a, int64_t b) "
            "{ int64_t r; return __builtin_sub_overflow(a, b, &r); }"},
    CHelper{"__unreachable",
            "static inline void __unreachable(void) { __builtin_unreachable(); }"},
    CHelper{"ember_bswap16",
            "static inline uint16_t ember_bswap16(uint16_t v) { return __builtin_bswap16(v); }"},
    CHelper{"ember_bswap32",
            "static inline uint32_t ember_bswap32(uint32_t v) { return __builtin_bswap32(v); }"},
    CHelper{"ember_bswap64",
            "static inline uint64_t ember_bswap64(uint64_t v) { return __builtin_bswap64(v); }"},
    CHelper{"ember_popcnt64",
            "static inline uint64_t ember_popcnt64(uint64_t v) "
            "{ return (uint64_t)__builtin_popcountll(v); }"},
    CHelper{"rotl8",  "EMBER_C_ROTL(8, uint8_t)"},
    CHelper{"rotl16", "EMBER_C_ROTL(16, uint16_t)"},
    CHelper{"rotl32", "EMBER_C_ROTL(32, uint32_t)"},
    CHelper{"rotl64", "EMBER_C_ROTL(64, uint64_t)"},
    CHelper{"rotr8",  "EMBER_C_ROTR(8, uint8_t)"},
    CHelper{"rotr16", "EMBER_C_ROTR(16, uint16_t)"},
    CHelper{"rotr32", "EMBER_C_ROTR(32, uint32_t)"},
    CHelper{"rotr64", "EMBER_C_ROTR(64, uint64_t)"},
    // REP MOVS / STOS with a known count are a forward copy and a fill.
    // The element width is in the name; the count is in RCX.
    CHelper{"ember_rep_movsb", "EMBER_C_REP_MOVS(b, uint8_t)"},
    CHelper{"ember_rep_movsd", "EMBER_C_REP_MOVS(d, uint32_t)"},
    CHelper{"ember_rep_movsq", "EMBER_C_REP_MOVS(q, uint64_t)"},
    CHelper{"ember_rep_stosb", "EMBER_C_REP_STOS(b, uint8_t)"},
    CHelper{"ember_rep_stosd", "EMBER_C_REP_STOS(d, uint32_t)"},
    CHelper{"ember_rep_stosq", "EMBER_C_REP_STOS(q, uint64_t)"},
};

// Names the standard headers already declare. Redeclaring one from observed
// machine arguments conflicts with the real prototype, so leave them alone.
[[nodiscard]] bool standard_c_library_name(std::string_view name) noexcept {
    static const std::set<std::string_view> standard{
        "memcpy", "memmove", "memset", "memcmp", "memchr", "strlen", "strcmp", "strncmp",
        "strcpy", "strncpy", "strcat", "strncat", "strchr", "strrchr", "strstr", "strspn",
        "strcspn", "strpbrk", "strtok", "malloc", "calloc", "realloc", "free", "abort", "exit",
        "atoi", "atol", "atoll", "atof", "strtol", "strtoul", "strtoll", "strtoull", "strtod", "strtof",
        "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf", "vsprintf", "vsnprintf",
        "scanf", "fscanf", "sscanf", "puts", "putchar", "getchar", "fopen", "fclose", "fread", "fwrite",
        "fgets", "fputs", "fflush", "fseek", "ftell", "feof", "ferror", "perror", "remove", "rename",
        "sqrt", "sqrtf", "sin", "sinf", "cos", "cosf", "tan", "tanf", "fabs", "fabsf",
        "floor", "floorf", "ceil", "ceilf", "pow", "powf", "exp", "expf", "log", "logf", "fmod", "fmodf",
    };
    return standard.contains(name);
}

// The identifier a C type spelling is built on: `const packet*` -> `packet`,
// `uint8_t[8]` -> `uint8_t`. Empty when the spelling has no plain base (a
// function-pointer declarator, say).
[[nodiscard]] std::string_view c_type_base_name(std::string_view type) noexcept {
    if (const auto declarator = type.find_first_of("*&[("); declarator != std::string_view::npos) {
        type = type.substr(0, declarator);
    }
    while (!type.empty() && std::isspace(static_cast<unsigned char>(type.back()))) {
        type.remove_suffix(1);
    }
    if (const auto space = type.find_last_of(" \t"); space != std::string_view::npos) {
        type = type.substr(space + 1);
    }
    if (type.empty() || std::isdigit(static_cast<unsigned char>(type.front())) != 0) return {};
    for (const char c : type) {
        if (!c_ident_char(c)) return {};
    }
    return type;
}

[[nodiscard]] bool defined_c_helper(std::string_view name) noexcept {
    for (const auto& helper : kCHelpers) {
        if (helper.name == name) return true;
    }
    return false;
}

}  // namespace

std::string_view Emitter::c_memory_suffix(IrType type) {
    switch (type) {
        case IrType::I1: case IrType::I8: return "u8";
        case IrType::I16: return "u16";
        case IrType::I32: return "u32";
        case IrType::I64: return "u64";
        case IrType::F32: return "f32";
        case IrType::F64: return "f64";
        default: return "unsupported";
    }
}

std::string Emitter::c_address(const IrValue& value) const {
    if (binary) {
        if (auto address = try_resolve_imm_addr(value)) {
            const auto va = static_cast<addr_t>(*address);
            if (const auto* symbol = binary->defined_object_at(va);
                symbol && symbol->kind == SymbolKind::Object) {
                note_global_decl(*symbol, "uint8_t[]");
                return std::format("(uintptr_t)&{} + {:#x}", global_display_name(*symbol), va - symbol->addr);
            }
        }
    }
    if (auto base = try_base_plus_offset(value)) {
        return std::format("(uintptr_t)({}) + (uintptr_t)({})", expr(base->first), base->second);
    }
    return std::format("(uintptr_t)({})", expr(value));
}

void Emitter::note_c_call(const IrInst& inst, std::string_view name,
                         const std::vector<IrValue>& args) const {
    // Use the standard headers' qualifiers and variadic prototypes instead
    // of redeclaring libc functions from their observed machine arguments.
    if (standard_c_library_name(name)) return;

    std::string parameters;
    if (const auto* signature = call_annotation_signature(inst)) {
        for (const auto& parameter : signature->params) {
            if (!parameters.empty()) parameters += ", ";
            parameters += normalize_c_type_alias(parameter.type);
            note_c_type_name(parameters);
        }
        if (signature->variadic) parameters += parameters.empty() ? "..." : ", ...";
    } else {
        for (const auto& value : args) {
            if (!parameters.empty()) parameters += ", ";
            const std::string rendered = expr(value);
            parameters += rendered.starts_with('&') ? "void*"
                : rendered.starts_with('"') ? "const char*" : c_type_name_for(value);
        }
    }
    if (parameters.empty()) parameters = "void";
    const std::string returned = known_call_return_c_type(inst).value_or("uint64_t");
    note_c_type_name(returned);
    const std::string declaration = std::format("extern {} {}({});\n", returned, name, parameters);
    auto [it, inserted] = c_call_declarations.emplace(std::string(name), declaration);
    if (inserted || it->second == declaration) return;

    // Two call sites disagree about this signature. Emitting both declarations
    // guarantees the export will not compile, which buries the disagreement
    // instead of reporting it. Keep the arguments every site agrees on and
    // make the rest variadic, so each call still type-checks, then mark the
    // declaration so the checker names the gap.
    const auto parameters_of = [](std::string_view text) -> std::string_view {
        const auto open = text.find('(');
        const auto close = text.find_last_of(')');
        if (open == std::string_view::npos || close <= open) return {};
        return text.substr(open + 1, close - open - 1);
    };
    const auto arity = [&](std::string_view text) -> std::ptrdiff_t {
        const std::string_view p = parameters_of(text);
        if (p.empty() || p == "void") return 0;
        return std::ranges::count(p, ',') + 1;
    };
    if (arity(declaration) < arity(it->second)) it->second = declaration;
    static constexpr std::string_view kMark = " /* unresolved call signature */";
    if (it->second.find(kMark) != std::string::npos) return;
    if (const std::string_view agreed = parameters_of(it->second);
        agreed != "..." && !agreed.ends_with(", ...")) {
        const auto close = it->second.find_last_of(')');
        // C11 has no `(...)`: an empty parameter list already accepts any
        // argument, so use that when no argument is agreed on at all.
        it->second.replace(it->second.find('(') + 1, close - it->second.find('(') - 1,
                           agreed.empty() || agreed == "void"
                               ? std::string{}
                               : std::format("{}, ...", agreed));
    }
    const auto semicolon = it->second.find_last_of(';');
    if (semicolon != std::string::npos) it->second.insert(semicolon + 1, kMark);
}

std::string Emitter::c_preamble(std::string_view body,
                                std::string_view scope_decls) const {
    std::string out = "#include <stdint.h>\n#include <stdbool.h>\n#include <stddef.h>\n#include <string.h>\n#include <stdlib.h>\n#include <stdio.h>\n#include <math.h>\n";
    if (body.find("ember_read_unsupported") != std::string_view::npos ||
        body.find("ember_write_unsupported") != std::string_view::npos) {
        out += "#error Unsupported memory width in C export\n";
    }
    if (body.find("__m128") != std::string_view::npos || body.find("_mm_") != std::string_view::npos) {
        out += "#include <immintrin.h>\n";
    }
    struct Scalar { std::string_view suffix; std::string_view type; };
    constexpr std::array scalars{
        Scalar{"u8", "uint8_t"}, Scalar{"u16", "uint16_t"}, Scalar{"u32", "uint32_t"},
        Scalar{"u64", "uint64_t"}, Scalar{"f32", "float"}, Scalar{"f64", "double"},
    };
    for (const auto& scalar : scalars) {
        const auto read = std::format("ember_read_{}", scalar.suffix);
        const auto write = std::format("ember_write_{}", scalar.suffix);
        if (!text_contains_identifier(body, read) && !text_contains_identifier(body, write)) continue;
        out += std::format(
            "#ifndef EMBER_C_MEMORY_{0}\n#define EMBER_C_MEMORY_{0}\n"
            "static inline {1} {2}(uintptr_t p) {{ {1} v; memcpy(&v, (const void*)p, sizeof(v)); return v; }}\n"
            "static inline void {3}(uintptr_t p, {1} v) {{ memcpy((void*)p, &v, sizeof(v)); }}\n#endif\n",
            scalar.suffix, scalar.type, read, write);
    }
    std::string helper_text;
    bool need_rep_macros = false;
    bool need_rot_macros = false;
    for (const auto& helper : kCHelpers) {
        if (!text_contains_identifier(body, helper.name)) continue;
        need_rep_macros |= helper.definition.starts_with("EMBER_C_REP_");
        need_rot_macros |= helper.definition.starts_with("EMBER_C_ROT");
        helper_text += std::format(
            "#ifndef EMBER_C_HELPER_{0}\n#define EMBER_C_HELPER_{0}\n{1}\n#endif\n",
            helper.name, helper.definition);
    }
    if (need_rot_macros) {
        out += "#ifndef EMBER_C_ROT\n#define EMBER_C_ROT\n"
               "#define EMBER_C_ROTL(w, T) static inline T rotl##w(T v, uint64_t n) "
               "{ n &= (w - 1); return n ? (T)((T)(v << n) | (T)(v >> (w - n))) : v; }\n"
               "#define EMBER_C_ROTR(w, T) static inline T rotr##w(T v, uint64_t n) "
               "{ n &= (w - 1); return n ? (T)((T)(v >> n) | (T)(v << (w - n))) : v; }\n"
               "#endif\n";
    }
    if (need_rep_macros) {
        out += "#ifndef EMBER_C_REP\n#define EMBER_C_REP\n"
               "#define EMBER_C_REP_MOVS(w, T) static inline void ember_rep_movs##w("
               "uintptr_t d, uintptr_t s, uint64_t n) "
               "{ memmove((void*)d, (const void*)s, n * sizeof(T)); }\n"
               "#define EMBER_C_REP_STOS(w, T) static inline void ember_rep_stos##w("
               "uintptr_t d, uint64_t v, uint64_t n) "
               "{ for (uint64_t i = 0; i < n; ++i) { T e = (T)v; "
               "memcpy((void*)(d + i * sizeof(T)), &e, sizeof(T)); } }\n#endif\n";
    }
    out += helper_text;

    // Intrinsics the lifter names but this export cannot define - REP
    // CMPS / SCAS / LODS, and every architecture-tagged operation the IR
    // kept as an opaque call. Declaring them keeps the export parseable;
    // the marker keeps the checker honest about what was not modelled.
    for (const auto& [name, declaration] : c_intrinsic_declarations) {
        if (text_contains_identifier(body, name)) out += declaration;
    }

    std::string declarations;
    for (const auto& [name, declaration] : c_call_declarations) {
        if (text_contains_identifier(body, name)) declarations += declaration;
    }
    // Record names reach the export through signatures and casts only. Scan
    // everything that will be emitted, including the declarations just built.
    std::string context(body);
    context += '\n';
    context += scope_decls;
    context += '\n';
    context += declarations;
    return out + c_forward_type_declarations(context) + declarations + "\n";
}

void Emitter::note_c_type_name(std::string_view type) const {
    // `parameters` accumulates a comma-separated list; the type just appended
    // is whatever follows the last separator.
    if (const auto last = type.find_last_of(','); last != std::string_view::npos) {
        type = type.substr(last + 1);
    }
    while (!type.empty() && std::isspace(static_cast<unsigned char>(type.front()))) {
        type.remove_prefix(1);
    }
    const std::string_view base = c_type_base_name(type);
    if (base.empty() || known_c_type_word(base)) return;
    c_signature_type_names.emplace(base);
}

std::string Emitter::c_forward_type_declarations(std::string_view context) const {
    // A name is a record only if every one of its occurrences is a pointer
    // declarator (`NAME *`). Anything declared, called, indexed or used as a
    // value fails that test, which keeps locals and globals out - and keeps
    // types that something else already defines out too, since a definition
    // spells the name followed by `{`, `;` or `[`.
    const std::string code = code_only_text(context);
    std::map<std::string_view, bool> record_shaped;
    for (std::size_t i = 0; i < code.size();) {
        if (!c_ident_char(code[i]) ||
            std::isdigit(static_cast<unsigned char>(code[i])) != 0) { ++i; continue; }
        const std::size_t begin = i;
        while (i < code.size() && c_ident_char(code[i])) ++i;
        const std::string_view word(code.data() + begin, i - begin);
        std::size_t after = i;
        while (after < code.size() &&
               std::isspace(static_cast<unsigned char>(code[after])) != 0) ++after;
        const bool pointer_use = after < code.size() && code[after] == '*';
        auto [it, inserted] = record_shaped.try_emplace(word, pointer_use);
        if (!inserted) it->second = it->second && pointer_use;
    }
    // Anything the context already defines needs nothing from us.
    // TODO: replace the std::regex scan below with a manual scan (perf,
    // exceptions, and the <regex> sanitizer workaround noted in CMakeLists).
    std::set<std::string> defined;
    for (const std::regex& pattern : {
             std::regex(R"(\btypedef\b[^;{]*?([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])?\s*;)"),
             std::regex(R"(\}\s*([A-Za-z_][A-Za-z0-9_]*)\s*;)")}) {
        for (std::sregex_iterator it(code.begin(), code.end(), pattern), end;
             it != end; ++it) {
            defined.insert((*it)[1].str());
        }
    }

    std::string out;
    std::set<std::string_view> forward_declared;
    for (const auto& [name, pointer_use] : record_shaped) {
        if (!pointer_use || known_c_type_word(name) || defined.contains(std::string(name))) {
            continue;
        }
        // Only ever `NAME *`: an opaque record is exactly right, and keeps
        // the recovered name in the export.
        out += std::format("typedef struct {0} {0};\n", name);
        forward_declared.insert(name);
    }
    for (const std::string& name : c_signature_type_names) {
        if (forward_declared.contains(name) || defined.contains(name) ||
            !text_contains_identifier(context, name)) continue;
        // A signature names this type but the export only ever uses it by
        // value, so there is no layout to recover and no pointer spelling to
        // lean on. Pointer width is the one shape that still accepts the
        // arguments actually being passed - say so rather than imply more.
        out += std::format("typedef void* {}; /* unresolved record type */\n", name);
    }
    if (!out.empty()) out += "\n";
    return out;
}

std::string Emitter::c_intrinsic_name(const IrInst& inst) {
    // `bswap` and `popcnt` carry their width in the destination type, not in
    // the name; every helper is width-specific, so resolve it here.
    if (inst.name == "bswap") {
        const unsigned bits = std::max(16u, type_bits(inst.dst.type));
        return std::format("ember_bswap{}", bits > 32 ? 64 : (bits > 16 ? 32 : 16));
    }
    if (inst.name == "popcnt") return "ember_popcnt64";
    // `rep.movsq`, `ppc.ps_lane0`, `arm64.crc32` and friends are not C
    // identifiers. Give them a stable prefixed spelling.
    if (inst.name.find('.') == std::string::npos) return inst.name;
    std::string out = std::format("ember_{}", inst.name);
    std::ranges::replace(out, '.', '_');
    return out;
}

std::string Emitter::render_intrinsic_call(const IrInst& inst, int depth) const {
    // REP string operands are RDI / RSI / RAX / RCX: two addresses, or an
    // address and a fill value, plus a count. The helpers take them as
    // uintptr_t / uint64_t, so cast at the call site rather than relying on
    // the rendered operand types lining up.
    const bool rep = options.c_source && inst.name.starts_with("rep.");
    const bool fill = rep && inst.name.find("stos") != std::string::npos;
    std::string args;
    for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
        if (i > 0) args += ", ";
        std::string rendered = expr(inst.srcs[i], depth, 0);
        if (!rep) { args += std::move(rendered); continue; }
        const bool address = i == 0 || (i == 1 && !fill);
        args += std::format("({})({})",
                            address ? "uintptr_t" : "uint64_t", rendered);
    }
    if (!options.c_source) return std::format("{}({})", inst.name, args);
    std::string name = c_intrinsic_name(inst);
    note_c_intrinsic(name, inst.src_count);
    return std::format("{}({})", name, args);
}

void Emitter::note_c_intrinsic(std::string_view name, u8 arity) const {
    // Compiler intrinsics come from <immintrin.h>, libc from its own headers,
    // and helpers define themselves.
    if (name.starts_with("_mm") || defined_c_helper(name) ||
        standard_c_library_name(name)) return;
    std::string parameters;
    for (u8 i = 0; i < arity; ++i) {
        parameters += parameters.empty() ? "uint64_t" : ", uint64_t";
    }
    if (parameters.empty()) parameters = "void";
    c_intrinsic_declarations.insert_or_assign(
        std::string(name),
        std::format("extern uint64_t {}({}); /* unresolved intrinsic */\n",
                    name, parameters));
}

std::string
Emitter::c_undefined_register_declarations(std::string_view body) const {
    // A machine register with no reaching definition renders under its own
    // name (`rax_2`, `xmm0`). Nothing declares those, so the export would not
    // compile; declare them zeroed and say what they are.
    std::string out;
    const std::string code = code_only_text(body);
    std::set<std::string> declared;
    for (unsigned r = 1; r < static_cast<unsigned>(Reg::Count); ++r) {
        const auto reg = static_cast<Reg>(r);
        const std::string_view type = register_c_type(reg_size(reg));
        if (type.empty()) continue;
        const std::string_view base = reg_name(reg);
        if (base.empty()) continue;
        // The bare name and every SSA-versioned spelling of it.
        for (std::size_t at = code.find(base); at != std::string::npos;
             at = code.find(base, at + 1)) {
            if (at != 0 && c_ident_char(code[at - 1])) continue;
            std::size_t end = at + base.size();
            if (end < code.size() && code[end] == '_') {
                std::size_t digits = end + 1;
                while (digits < code.size() &&
                       std::isdigit(static_cast<unsigned char>(code[digits])) != 0) ++digits;
                if (digits > end + 1) end = digits;
            }
            if (end < code.size() && c_ident_char(code[end])) continue;
            std::string name(code, at, end - at);
            if (text_declares_identifier(body, name)) continue;
            declared.insert(std::move(name));
        }
    }
    for (const std::string& name : declared) {
        const auto underscore = name.rfind('_');
        const std::string_view base = underscore == std::string::npos
            ? std::string_view(name)
            : std::string_view(name).substr(0, underscore);
        for (unsigned r = 1; r < static_cast<unsigned>(Reg::Count); ++r) {
            const auto reg = static_cast<Reg>(r);
            if (reg_name(reg) != base) continue;
            out += std::format("  {} {} = {{0}}; /* unresolved register read */\n",
                               register_c_type(reg_size(reg)), name);
            break;
        }
    }
    return out;
}

}  // namespace ember::emit
