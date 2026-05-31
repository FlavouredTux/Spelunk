#include "builders.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <format>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include <ember/analysis/app_surface.hpp>
#include <ember/analysis/arity.hpp>
#include <ember/analysis/data_xrefs.hpp>
#include <ember/analysis/demangle.hpp>
#include <ember/analysis/graphics.hpp>
#include <ember/analysis/msvc_rtti.hpp>
#include <ember/analysis/objc.hpp>
#include <ember/analysis/pipeline.hpp>
#include <ember/analysis/rtti.hpp>
#include <ember/analysis/strings.hpp>
#include <ember/analysis/int3_resolver.hpp>
#include <ember/analysis/vtables.hpp>
#include <ember/binary/binary.hpp>
#include <ember/binary/symbol.hpp>
#include <ember/common/timing.hpp>
#include <ember/disasm/register.hpp>

#include "util.hpp"

namespace ember::cli {

namespace {

[[nodiscard]] std::string lower_ascii(std::string_view text) {
    std::string out(text);
    for (char& c : out) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

[[nodiscard]] bool contains_ci(std::string_view haystack, std::string_view needle) {
    if (needle.empty()) return true;
    return lower_ascii(haystack).find(lower_ascii(needle)) != std::string::npos;
}

[[nodiscard]] bool equals_ci(std::string_view lhs, std::string_view rhs) {
    return lower_ascii(lhs) == lower_ascii(rhs);
}

[[nodiscard]] bool vector_contains_ci(const std::vector<std::string>& values,
                                      std::string_view needle) {
    if (needle.empty()) return true;
    return std::ranges::any_of(values, [&](const std::string& value) {
        return equals_ci(value, needle);
    });
}

[[nodiscard]] bool vector_contains_substring_ci(const std::vector<std::string>& values,
                                                std::string_view needle) {
    if (needle.empty()) return true;
    return std::ranges::any_of(values, [&](const std::string& value) {
        return contains_ci(value, needle);
    });
}

[[nodiscard]] bool vector_contains_addr(const std::vector<addr_t>& values, addr_t needle) {
    return std::ranges::find(values, needle) != values.end();
}

[[nodiscard]] bool row_in_role_scope(const std::vector<addr_t>& functions,
                                     GraphicsBackend backend,
                                     bool role_active,
                                     const std::map<GraphicsBackend, std::set<addr_t>>& role_functions) {
    if (!role_active) return true;
    const auto it = role_functions.find(backend);
    if (it == role_functions.end() || it->second.empty()) return false;
    return std::ranges::any_of(functions, [&](addr_t fn) {
        return it->second.contains(fn);
    });
}

[[nodiscard]] bool backend_matches(GraphicsBackend backend,
                                   const GraphicsOutputFilter& filter) {
    return filter.backend.empty() ||
           equals_ci(graphics_backend_name(backend), filter.backend);
}

[[nodiscard]] bool row_type_matches(const GraphicsOutputFilter& filter,
                                    std::string_view row_type) {
    return filter.row_type.empty() || equals_ci(filter.row_type, row_type);
}

[[nodiscard]] bool surface_summary_wanted(const SurfaceOutputFilter& filter) {
    return filter.row_type.empty() || equals_ci(filter.row_type, "summary") ||
           equals_ci(filter.row_type, "all");
}

[[nodiscard]] bool surface_function_wanted(const SurfaceOutputFilter& filter) {
    return equals_ci(filter.row_type, "function") || equals_ci(filter.row_type, "all");
}

[[nodiscard]] bool surface_evidence_wanted(const SurfaceOutputFilter& filter) {
    return equals_ci(filter.row_type, "evidence") || equals_ci(filter.row_type, "all");
}

[[nodiscard]] bool surface_category_wanted(const SurfaceOutputFilter& filter) {
    return equals_ci(filter.row_type, "category") || equals_ci(filter.row_type, "all");
}

[[nodiscard]] bool surface_artifact_wanted(const SurfaceOutputFilter& filter) {
    return equals_ci(filter.row_type, "artifact") || equals_ci(filter.row_type, "all");
}

[[nodiscard]] bool surface_owner_wanted(const SurfaceOutputFilter& filter) {
    return equals_ci(filter.row_type, "owner") || equals_ci(filter.row_type, "all");
}

[[nodiscard]] bool surface_descriptor_wanted(const SurfaceOutputFilter& filter) {
    return equals_ci(filter.row_type, "descriptor") || equals_ci(filter.row_type, "all");
}

[[nodiscard]] bool surface_name_matches(std::string_view subsystem,
                                        const SurfaceOutputFilter& filter) {
    return filter.subsystem.empty() || equals_ci(subsystem, filter.subsystem);
}

[[nodiscard]] bool surface_category_matches(const std::vector<std::string>& categories,
                                            const SurfaceOutputFilter& filter) {
    return filter.category.empty() || vector_contains_ci(categories, filter.category);
}

[[nodiscard]] bool matches_surface_summary(const AppSurfaceSummary& s,
                                           const SurfaceOutputFilter& filter) {
    if (!surface_summary_wanted(filter)) return false;
    if (!filter.owner.empty()) return false;
    if (!surface_name_matches(s.subsystem, filter)) return false;
    if (!surface_category_matches(s.categories, filter)) return false;
    return filter.kind.empty() && !filter.function;
}

[[nodiscard]] bool matches_surface_function(const AppSurfaceFunction& f,
                                            const SurfaceOutputFilter& filter) {
    if (!surface_function_wanted(filter)) return false;
    if (!filter.owner.empty()) return false;
    if (!surface_name_matches(f.subsystem, filter)) return false;
    if (!surface_category_matches(f.categories, filter)) return false;
    if (filter.function && f.function != *filter.function) return false;
    return filter.kind.empty();
}

[[nodiscard]] bool matches_surface_evidence(const AppSurfaceEvidence& e,
                                            const SurfaceOutputFilter& filter) {
    if (!surface_evidence_wanted(filter)) return false;
    if (!surface_name_matches(e.subsystem, filter)) return false;
    if (!filter.kind.empty() && !equals_ci(e.kind, filter.kind)) return false;
    if (!filter.category.empty() && !equals_ci(e.category, filter.category)) return false;
    if (filter.function && !vector_contains_addr(e.functions, *filter.function)) return false;
    return true;
}

[[nodiscard]] bool matches_surface_evidence_scope(const AppSurfaceEvidence& e,
                                                  const SurfaceOutputFilter& filter) {
    if (!surface_name_matches(e.subsystem, filter)) return false;
    if (!filter.kind.empty() && !equals_ci(e.kind, filter.kind)) return false;
    if (!filter.category.empty() && !equals_ci(e.category, filter.category)) return false;
    if (filter.function && !vector_contains_addr(e.functions, *filter.function)) return false;
    return true;
}

[[nodiscard]] bool matches_graphics_summary(const GraphicsBackendSummary& s,
                                            const GraphicsOutputFilter& filter) {
    if (!backend_matches(s.backend, filter)) return false;
    // Domain/API filters narrow per-row evidence. Keeping backend totals in
    // that mode reads like filtered counts, so omit summaries instead.
    return filter.domain.empty() && filter.api.empty() &&
           filter.extension.empty() && filter.category.empty() &&
           filter.role.empty() && !filter.function;
}

[[nodiscard]] bool matches_graphics_api(const GraphicsApiFact& a,
                                        const GraphicsOutputFilter& filter) {
    if (!backend_matches(a.backend, filter)) return false;
    if (!vector_contains_ci(a.domains, filter.domain)) return false;
    if (!vector_contains_ci(a.extensions, filter.extension)) return false;
    if (!vector_contains_ci(a.categories, filter.category)) return false;
    if (filter.function && !vector_contains_addr(a.functions, *filter.function)) return false;
    return filter.api.empty() || contains_ci(a.api_name, filter.api) ||
           vector_contains_substring_ci(a.variants, filter.api);
}

[[nodiscard]] bool matches_graphics_extension(const GraphicsExtensionFact& e,
                                              const GraphicsOutputFilter& filter) {
    if (!backend_matches(e.backend, filter)) return false;
    if (!filter.extension.empty() && !equals_ci(e.extension, filter.extension)) return false;
    if (!vector_contains_ci(e.domains, filter.domain)) return false;
    if (!vector_contains_ci(e.categories, filter.category)) return false;
    if (filter.function && !vector_contains_addr(e.functions, *filter.function)) return false;
    if (filter.api.empty()) return true;
    return vector_contains_substring_ci(e.apis, filter.api) ||
           vector_contains_substring_ci(e.variants, filter.api);
}

[[nodiscard]] bool matches_graphics_function(const GraphicsFunctionFact& f,
                                             const GraphicsOutputFilter& filter) {
    if (!backend_matches(f.backend, filter)) return false;
    if (!vector_contains_ci(f.domains, filter.domain)) return false;
    if (!vector_contains_ci(f.extensions, filter.extension)) return false;
    if (!filter.category.empty() &&
        !vector_contains_ci(f.categories, filter.category) &&
        !equals_ci(f.role, filter.category)) return false;
    if (!filter.role.empty() && !equals_ci(f.role, filter.role)) return false;
    if (filter.function && f.function != *filter.function) return false;
    if (filter.api.empty()) return true;
    return std::ranges::any_of(f.evidence, [&](const std::string& e) {
        return contains_ci(e, filter.api);
    });
}

[[nodiscard]] bool matches_graphics_symbol(const GraphicsSymbolFact& s,
                                           const GraphicsOutputFilter& filter) {
    if (!backend_matches(s.backend, filter)) return false;
    if (!filter.domain.empty() && !equals_ci(s.domain, filter.domain)) return false;
    if (!filter.extension.empty() && !equals_ci(s.api_extension, filter.extension)) return false;
    if (!filter.category.empty() && !equals_ci(s.category, filter.category)) return false;
    if (filter.function && s.addr != *filter.function) return false;
    if (filter.api.empty()) return true;
    return contains_ci(s.api_name, filter.api) ||
           contains_ci(s.canonical_api_name, filter.api) ||
           contains_ci(s.name, filter.api);
}

[[nodiscard]] bool matches_graphics_string(const GraphicsStringFact& s,
                                           const GraphicsOutputFilter& filter) {
    if (!backend_matches(s.backend, filter)) return false;
    if (!filter.domain.empty() && !equals_ci(s.domain, filter.domain)) return false;
    if (!filter.extension.empty() && !equals_ci(s.api_extension, filter.extension)) return false;
    if (!filter.category.empty() && !equals_ci(s.category, filter.category)) return false;
    if (filter.function && !vector_contains_addr(s.functions, *filter.function)) return false;
    if (filter.api.empty()) return true;
    return contains_ci(s.api_name, filter.api) ||
           contains_ci(s.canonical_api_name, filter.api) ||
           contains_ci(s.text, filter.api);
}

template <class T, class Pred>
[[nodiscard]] std::vector<const T*> filtered_ptrs(const std::vector<T>& rows, Pred pred) {
    std::vector<const T*> out;
    out.reserve(rows.size());
    for (const auto& row : rows) {
        if (pred(row)) out.push_back(&row);
    }
    return out;
}

struct SurfaceCategoryRow {
    std::string subsystem;
    std::string category;
    std::size_t evidence_count = 0;
    std::size_t string_count = 0;
    std::size_t artifact_count = 0;
    std::size_t symbol_count = 0;
    std::size_t objc_method_count = 0;
    std::size_t rtti_class_count = 0;
    std::size_t log_category_count = 0;
    std::size_t function_count = 0;
    std::vector<std::string> kinds;
    std::vector<std::string> examples;
};

struct SurfaceArtifactRow {
    std::string path;
    std::size_t match_count = 0;
    std::vector<std::string> subsystems;
    std::vector<std::string> categories;
};

struct SurfaceOwnerRow {
    std::string subsystem;
    std::string owner;
    std::size_t descriptor_count = 0;
    std::size_t bound_function_count = 0;
    std::size_t yield_function_count = 0;
    std::size_t property_count = 0;
    std::size_t event_count = 0;
    std::size_t remote_event_count = 0;
    std::size_t enum_count = 0;
    std::size_t type_count = 0;
    std::size_t other_count = 0;
    std::size_t function_count = 0;
    std::vector<std::string> categories;
    std::vector<std::string> arities;
    std::vector<std::string> examples;
};

struct SurfaceDescriptorRow {
    std::string subsystem;
    std::string owner;
    std::string descriptor_kind;
    std::string category;
    std::string arity;
    std::string signature;
    addr_t addr = 0;
    std::vector<addr_t> xrefs;
    std::vector<addr_t> functions;
    std::string type;
};

struct ReflectionDescriptorFields {
    std::string kind;
    std::string owner;
    std::string arity;
    std::string type;
};

[[nodiscard]] std::optional<std::string_view>
field_after(std::string_view text, std::string_view marker,
            std::string_view next_marker) {
    const auto start = text.find(marker);
    if (start == std::string_view::npos) return std::nullopt;
    const auto value_start = start + marker.size();
    const auto end = text.find(next_marker, value_start);
    if (end == std::string_view::npos || end <= value_start) return std::nullopt;
    return text.substr(value_start, end - value_start);
}

[[nodiscard]] std::optional<ReflectionDescriptorFields>
parse_reflection_descriptor_fields(std::string_view text) {
    const auto owner = field_after(text, " owner=", " argc=");
    const auto arity = field_after(text, " argc=", " type=");
    const auto type_start = text.find(" type=");
    const auto kind_end = text.find(" owner=");
    if (!owner || !arity || type_start == std::string_view::npos ||
        kind_end == std::string_view::npos || kind_end == 0) {
        return std::nullopt;
    }
    return ReflectionDescriptorFields{
        .kind = std::string{text.substr(0, kind_end)},
        .owner = std::string{*owner},
        .arity = std::string{*arity},
        .type = std::string{text.substr(type_start + std::string_view{" type="}.size())},
    };
}

[[nodiscard]] bool surface_owner_matches(const AppSurfaceEvidence& evidence,
                                         const SurfaceOutputFilter& filter) {
    if (filter.owner.empty()) return true;
    if (!equals_ci(evidence.kind, "reflection_descriptor")) return false;
    const auto fields = parse_reflection_descriptor_fields(evidence.text);
    return fields && equals_ci(fields->owner, filter.owner);
}

[[nodiscard]] std::optional<std::string_view>
outer_template_args(std::string_view text) {
    const auto start = text.find('<');
    if (start == std::string_view::npos) return std::nullopt;
    int angle = 0;
    for (std::size_t i = start; i < text.size(); ++i) {
        if (text[i] == '<') ++angle;
        else if (text[i] == '>') {
            --angle;
            if (angle == 0) return text.substr(start + 1, i - start - 1);
        }
    }
    return std::nullopt;
}

[[nodiscard]] std::vector<std::string>
split_top_level_template_args(std::string_view text) {
    std::vector<std::string> out;
    int angle = 0;
    int paren = 0;
    std::size_t start = 0;
    for (std::size_t i = 0; i <= text.size(); ++i) {
        const bool at_end = i == text.size();
        const char c = at_end ? '\0' : text[i];
        if (at_end || (c == ',' && angle == 0 && paren == 0)) {
            std::size_t a = start;
            std::size_t b = i;
            while (a < b && std::isspace(static_cast<unsigned char>(text[a]))) ++a;
            while (b > a && std::isspace(static_cast<unsigned char>(text[b - 1]))) --b;
            out.emplace_back(text.substr(a, b - a));
            start = i + 1;
        } else if (c == '<') ++angle;
        else if (c == '>') --angle;
        else if (c == '(') ++paren;
        else if (c == ')') --paren;
    }
    return out;
}

[[nodiscard]] std::string compact_signature(std::string sig) {
    auto replace_all = [&](std::string_view from, std::string_view to) {
        std::size_t p = 0;
        while ((p = sig.find(from, p)) != std::string::npos) {
            sig.replace(p, from.size(), to);
            p += to.size();
        }
    };
    replace_all("std::__1::", "std::");
    replace_all("std::basic_string<char,std::char_traits<char>,std::allocator<char>>",
                "std::string");
    sig = simplify_stdlib_templates(std::move(sig));
    replace_all(", ", ",");
    replace_all("> >", ">>");
    replace_all(" (", "(");
    return sig;
}

[[nodiscard]] std::string_view trim_to_reflection_mangle(std::string_view type) {
    std::size_t start = std::string_view::npos;
    for (const auto prefix : {
        std::string_view{"N6Engine10Reflection"},
        std::string_view{"N6Engine10Reflection"},
    }) {
        const auto p = type.find(prefix);
        if (p != std::string_view::npos && (start == std::string_view::npos || p < start)) {
            start = p;
        }
    }
    return start == std::string_view::npos ? type : type.substr(start);
}

[[nodiscard]] std::optional<std::string>
demangled_descriptor_signature(std::string_view type) {
    type = trim_to_reflection_mangle(type);
    std::string synthetic = "_Z";
    synthetic += type;
    const auto demangled = demangle_itanium(synthetic);
    if (!demangled) return std::nullopt;

    const auto args_text = outer_template_args(*demangled);
    if (!args_text) return std::nullopt;
    const auto args = split_top_level_template_args(*args_text);
    if (args.size() >= 2 && args[1].find('(') != std::string::npos) {
        auto sig = compact_signature(args[1]);
        if (type.find("EKF") != std::string_view::npos && sig.starts_with("const ")) {
            sig.erase(0, std::string_view{"const "}.size());
            sig += " const";
        }
        if (sig.ends_with("(void)")) {
            sig.replace(sig.size() - std::string_view{"(void)"}.size(),
                        std::string_view{"(void)"}.size(), "()");
        }
        if (sig.ends_with("(void) const")) {
            sig.replace(sig.size() - std::string_view{"(void) const"}.size(),
                        std::string_view{"(void) const"}.size(), "() const");
        }
        return sig;
    }
    if ((type.find("PropDescriptorI") != std::string_view::npos ||
         type.find("EnumPropDescriptorI") != std::string_view::npos ||
         type.find("RefPropDescriptorI") != std::string_view::npos) &&
        args.size() >= 2) {
        return "value=" + compact_signature(args[1]);
    }
    if ((type.find("EnumDescI") != std::string_view::npos ||
         type.find("TypedPropertyDescriptorI") != std::string_view::npos ||
         type.find("TTypeI") != std::string_view::npos) &&
        !args.empty()) {
        return "type=" + compact_signature(args[0]);
    }
    return std::nullopt;
}

[[nodiscard]] bool looks_like_bad_descriptor_signature(std::string_view sig) {
    return sig.find("Engine<") != std::string_view::npos ||
           sig.find("Engine::basic_string") != std::string_view::npos ||
           sig.find("Engine::allocator") != std::string_view::npos ||
           sig.find("Engine::hash") != std::string_view::npos ||
           sig.find("Engine::equal_to") != std::string_view::npos ||
           sig.find("Engine::pair") != std::string_view::npos;
}

struct DescriptorTypeParser {
    std::string_view in;
    std::size_t pos = 0;
    std::string primary_namespace;
    bool failed = false;

    [[nodiscard]] char peek() const {
        return pos < in.size() ? in[pos] : '\0';
    }

    [[nodiscard]] bool starts_with(std::string_view text) const {
        return in.substr(pos).starts_with(text);
    }

    [[nodiscard]] bool consume_if(char c) {
        if (peek() != c) return false;
        ++pos;
        return true;
    }

    [[nodiscard]] std::optional<std::size_t> parse_number() {
        if (!std::isdigit(static_cast<unsigned char>(peek()))) return std::nullopt;
        std::size_t n = 0;
        while (std::isdigit(static_cast<unsigned char>(peek()))) {
            n = n * 10 + static_cast<std::size_t>(peek() - '0');
            ++pos;
            if (n > 4096) {
                failed = true;
                return std::nullopt;
            }
        }
        return n;
    }

    [[nodiscard]] std::string parse_source_name() {
        const auto n = parse_number();
        if (!n || pos + *n > in.size()) {
            failed = true;
            return {};
        }
        std::string name{in.substr(pos, *n)};
        pos += *n;
        return name;
    }

    [[nodiscard]] std::string parse_substitution() {
        if (!consume_if('S')) return {};
        if (consume_if('t')) return "std";
        while (std::isalnum(static_cast<unsigned char>(peek()))) ++pos;
        if (consume_if('_')) {
            return primary_namespace.empty() ? "sub" : primary_namespace;
        }
        failed = true;
        return {};
    }

    [[nodiscard]] std::string parse_template_args() {
        if (!consume_if('I')) return {};
        std::vector<std::string> args;
        while (pos < in.size() && peek() != 'E' && !failed) {
            auto arg = parse_type();
            if (arg.empty()) break;
            args.push_back(std::move(arg));
        }
        if (!consume_if('E')) {
            failed = true;
            return {};
        }
        std::string out = "<";
        for (std::size_t i = 0; i < args.size(); ++i) {
            if (i > 0) out += ",";
            out += args[i];
        }
        out += ">";
        return out;
    }

    [[nodiscard]] std::string parse_name_component() {
        std::string name;
        if (peek() == 'S') {
            name = parse_substitution();
        } else {
            name = parse_source_name();
        }
        if (failed || name.empty()) return {};
        if (peek() == 'I') name += parse_template_args();
        return name;
    }

    [[nodiscard]] std::string simplify_known(std::string name) const {
        auto replace_all = [&](std::string_view from, std::string_view to) {
            std::size_t p = 0;
            while ((p = name.find(from, p)) != std::string::npos) {
                name.replace(p, from.size(), to);
                p += to.size();
            }
        };
        replace_all("std::__1::", "std::");
        if (!primary_namespace.empty()) {
            replace_all("sub::", primary_namespace + "::");
            replace_all("<sub>", "<" + primary_namespace + ">");
            replace_all(",sub>", "," + primary_namespace + ">");
            replace_all("(sub)", "(" + primary_namespace + ")");
            replace_all(",sub)", "," + primary_namespace + ")");
        }
        if (name.starts_with("std::basic_string<char")) return "std::string";
        return name;
    }

    [[nodiscard]] std::string parse_nested_name() {
        if (!consume_if('N')) return {};
        std::vector<std::string> parts;
        while (pos < in.size() && peek() != 'E' && !failed) {
            auto part = parse_name_component();
            if (part.empty()) break;
            parts.push_back(std::move(part));
        }
        if (!consume_if('E')) {
            failed = true;
            return {};
        }
        std::string out;
        for (const auto& part : parts) {
            if (out.empty()) out = part;
            else out += "::" + part;
        }
        if (primary_namespace.empty() && !parts.empty() && parts.front() != "std") {
            primary_namespace = parts.front();
        }
        return simplify_known(out);
    }

    [[nodiscard]] std::string parse_type() {
        if (failed || pos >= in.size()) return {};

        if (consume_if('K')) {
            auto inner = parse_type();
            return inner.empty() ? inner : "const " + inner;
        }
        if (consume_if('R')) {
            auto inner = parse_type();
            return inner.empty() ? inner : inner + "&";
        }
        if (consume_if('O')) {
            auto inner = parse_type();
            return inner.empty() ? inner : inner + "&&";
        }
        if (consume_if('P')) {
            auto inner = parse_type();
            return inner.empty() ? inner : inner + "*";
        }

        struct Builtin { char code; std::string_view name; };
        static constexpr Builtin builtins[] = {
            {'v', "void"}, {'b', "bool"}, {'c', "char"}, {'a', "signed_char"},
            {'h', "unsigned_char"}, {'s', "short"}, {'t', "unsigned_short"},
            {'i', "int"}, {'j', "unsigned_int"}, {'l', "long"},
            {'m', "unsigned_long"}, {'x', "long_long"},
            {'y', "unsigned_long_long"}, {'f', "float"}, {'d', "double"},
            {'e', "long_double"},
        };
        for (const auto& b : builtins) {
            if (consume_if(b.code)) return std::string{b.name};
        }

        if (peek() == 'N') return parse_nested_name();
        if (peek() == 'S') return parse_substitution();
        if (std::isdigit(static_cast<unsigned char>(peek()))) {
            auto name = parse_source_name();
            if (peek() == 'I') name += parse_template_args();
            return name;
        }

        failed = true;
        return {};
    }
};

[[nodiscard]] std::string reflection_descriptor_signature(std::string_view type) {
    if (auto demangled = demangled_descriptor_signature(type)) return *demangled;

    static constexpr std::string_view markers[] = {
        "BoundYieldFuncDescI",
        "BoundFuncDescI",
        "RemoteEventDescI",
        "EventDescI",
    };
    std::size_t start = std::string_view::npos;
    for (const auto marker : markers) {
        const auto p = type.find(marker);
        if (p != std::string_view::npos) {
            start = p + marker.size();
            break;
        }
    }
    if (start == std::string_view::npos) return "-";

    DescriptorTypeParser parser;
    parser.in = type;
    parser.pos = start;
    if (type.find("N6Engine") != std::string_view::npos) {
        parser.primary_namespace = "Engine";
    } else if (type.find("N6Engine") != std::string_view::npos) {
        parser.primary_namespace = "Engine";
    }
    const auto owner = parser.parse_type();
    if (owner.empty() || parser.failed) return "-";

    std::string fn_qualifier;
    while (true) {
        if (parser.consume_if('K')) {
            fn_qualifier += " const";
        } else if (parser.consume_if('V')) {
            fn_qualifier += " volatile";
        } else if (parser.consume_if('r')) {
            fn_qualifier += " restrict";
        } else {
            break;
        }
    }
    if (!parser.consume_if('F')) return "-";

    const auto ret = parser.parse_type();
    if (ret.empty() || parser.failed) return "-";

    std::vector<std::string> args;
    while (parser.pos < type.size() && parser.peek() != 'E' && !parser.failed) {
        auto arg = parser.parse_type();
        if (arg.empty()) break;
        args.push_back(std::move(arg));
    }
    if (!parser.consume_if('E') || parser.failed) return "-";

    std::string out = ret + "(";
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (i > 0) out += ",";
        out += args[i];
    }
    out += ")";
    if (out.ends_with("(void)")) {
        out.replace(out.size() - std::string_view{"(void)"}.size(),
                    std::string_view{"(void)"}.size(), "()");
    }
    out += fn_qualifier;
    out = compact_signature(std::move(out));
    if (looks_like_bad_descriptor_signature(out)) return "-";
    return out;
}

[[nodiscard]] std::vector<const AppSurfaceEvidence*>
filter_surface_owner_evidence(std::vector<const AppSurfaceEvidence*> evidence,
                              const SurfaceOutputFilter& filter) {
    if (filter.owner.empty()) return evidence;
    std::erase_if(evidence, [&](const AppSurfaceEvidence* row) {
        return row == nullptr || !surface_owner_matches(*row, filter);
    });
    return evidence;
}

[[nodiscard]] std::vector<SurfaceCategoryRow>
build_surface_category_rows(const std::vector<const AppSurfaceEvidence*>& evidence) {
    struct Acc {
        SurfaceCategoryRow row;
        std::set<addr_t> functions;
        std::set<std::string> log_categories;
    };

    std::map<std::pair<std::string, std::string>, Acc> accs;
    for (const auto* ep : evidence) {
        const auto& e = *ep;
        auto& acc = accs[{e.subsystem, e.category}];
        acc.row.subsystem = e.subsystem;
        acc.row.category = e.category;
        ++acc.row.evidence_count;
        if (std::ranges::find(acc.row.kinds, e.kind) == acc.row.kinds.end()) {
            acc.row.kinds.push_back(e.kind);
        }
        if (acc.row.examples.size() < 6 &&
            std::ranges::find(acc.row.examples, e.text) == acc.row.examples.end()) {
            acc.row.examples.push_back(e.text);
        }
        for (addr_t fn : e.functions) {
            if (fn != 0) acc.functions.insert(fn);
        }
        if (e.kind == "string") ++acc.row.string_count;
        else if (e.kind == "image_string" || e.kind == "bundle_file") ++acc.row.artifact_count;
        else if (e.kind == "symbol") ++acc.row.symbol_count;
        else if (e.kind == "objc_method") ++acc.row.objc_method_count;
        else if (e.kind == "rtti_class") ++acc.row.rtti_class_count;
        else if (e.kind == "log_category") {
            acc.log_categories.insert(e.text);
            acc.row.log_category_count = acc.log_categories.size();
        }
    }

    std::vector<SurfaceCategoryRow> out;
    out.reserve(accs.size());
    for (auto& [_, acc] : accs) {
        acc.row.function_count = acc.functions.size();
        std::ranges::sort(acc.row.kinds);
        std::ranges::sort(acc.row.examples);
        out.push_back(std::move(acc.row));
    }
    std::ranges::sort(out, [](const auto& lhs, const auto& rhs) {
        if (lhs.evidence_count != rhs.evidence_count) {
            return lhs.evidence_count > rhs.evidence_count;
        }
        if (lhs.subsystem != rhs.subsystem) return lhs.subsystem < rhs.subsystem;
        return lhs.category < rhs.category;
    });
    return out;
}

[[nodiscard]] std::vector<SurfaceOwnerRow>
build_surface_owner_rows(const std::vector<const AppSurfaceEvidence*>& evidence) {
    struct Acc {
        SurfaceOwnerRow row;
        std::set<addr_t> functions;
    };

    std::map<std::pair<std::string, std::string>, Acc> accs;
    for (const auto* ep : evidence) {
        const auto& e = *ep;
        if (!equals_ci(e.kind, "reflection_descriptor")) continue;
        const auto fields = parse_reflection_descriptor_fields(e.text);
        if (!fields) continue;

        auto& acc = accs[{e.subsystem, fields->owner}];
        acc.row.subsystem = e.subsystem;
        acc.row.owner = fields->owner;
        ++acc.row.descriptor_count;
        if (e.category == "reflection_bound_function") ++acc.row.bound_function_count;
        else if (e.category == "reflection_yield_function") ++acc.row.yield_function_count;
        else if (e.category == "reflection_property") ++acc.row.property_count;
        else if (e.category == "reflection_event") ++acc.row.event_count;
        else if (e.category == "reflection_remote_event") ++acc.row.remote_event_count;
        else if (e.category == "reflection_enum") ++acc.row.enum_count;
        else if (e.category == "reflection_type") ++acc.row.type_count;
        else ++acc.row.other_count;

        if (std::ranges::find(acc.row.categories, e.category) == acc.row.categories.end()) {
            acc.row.categories.push_back(e.category);
        }
        if (fields->arity != "-" &&
            std::ranges::find(acc.row.arities, fields->arity) == acc.row.arities.end()) {
            acc.row.arities.push_back(fields->arity);
        }
        if (acc.row.examples.size() < 6 &&
            std::ranges::find(acc.row.examples, e.text) == acc.row.examples.end()) {
            acc.row.examples.push_back(e.text);
        }
        for (addr_t fn : e.functions) {
            if (fn != 0) acc.functions.insert(fn);
        }
    }

    std::vector<SurfaceOwnerRow> out;
    out.reserve(accs.size());
    for (auto& [_, acc] : accs) {
        acc.row.function_count = acc.functions.size();
        std::ranges::sort(acc.row.categories);
        std::ranges::sort(acc.row.arities);
        std::ranges::sort(acc.row.examples);
        out.push_back(std::move(acc.row));
    }
    std::ranges::sort(out, [](const auto& lhs, const auto& rhs) {
        if (lhs.descriptor_count != rhs.descriptor_count) {
            return lhs.descriptor_count > rhs.descriptor_count;
        }
        if (lhs.subsystem != rhs.subsystem) return lhs.subsystem < rhs.subsystem;
        return lhs.owner < rhs.owner;
    });
    return out;
}

[[nodiscard]] std::vector<SurfaceDescriptorRow>
build_surface_descriptor_rows(const std::vector<const AppSurfaceEvidence*>& evidence) {
    std::vector<SurfaceDescriptorRow> out;
    for (const auto* ep : evidence) {
        const auto& e = *ep;
        if (!equals_ci(e.kind, "reflection_descriptor")) continue;
        const auto fields = parse_reflection_descriptor_fields(e.text);
        if (!fields) continue;
        out.push_back(SurfaceDescriptorRow{
            .subsystem = e.subsystem,
            .owner = fields->owner,
            .descriptor_kind = fields->kind,
            .category = e.category,
            .arity = fields->arity,
            .signature = reflection_descriptor_signature(fields->type),
            .addr = e.addr,
            .xrefs = e.xrefs,
            .functions = e.functions,
            .type = fields->type,
        });
    }
    std::ranges::sort(out, [](const auto& lhs, const auto& rhs) {
        if (lhs.subsystem != rhs.subsystem) return lhs.subsystem < rhs.subsystem;
        if (lhs.owner != rhs.owner) return lhs.owner < rhs.owner;
        if (lhs.category != rhs.category) return lhs.category < rhs.category;
        if (lhs.descriptor_kind != rhs.descriptor_kind) {
            return lhs.descriptor_kind < rhs.descriptor_kind;
        }
        return lhs.addr < rhs.addr;
    });
    return out;
}

[[nodiscard]] std::vector<SurfaceArtifactRow>
build_surface_artifact_rows(const std::vector<const AppSurfaceEvidence*>& evidence) {
    std::map<std::string, SurfaceArtifactRow> rows;
    for (const auto* ep : evidence) {
        const auto& e = *ep;
        if (!equals_ci(e.kind, "bundle_file")) continue;
        auto& row = rows[e.text];
        row.path = e.text;
        ++row.match_count;
        if (std::ranges::find(row.subsystems, e.subsystem) == row.subsystems.end()) {
            row.subsystems.push_back(e.subsystem);
        }
        if (std::ranges::find(row.categories, e.category) == row.categories.end()) {
            row.categories.push_back(e.category);
        }
    }

    std::vector<SurfaceArtifactRow> out;
    out.reserve(rows.size());
    for (auto& [_, row] : rows) {
        std::ranges::sort(row.subsystems);
        std::ranges::sort(row.categories);
        out.push_back(std::move(row));
    }
    std::ranges::sort(out, [](const auto& lhs, const auto& rhs) {
        if (lhs.match_count != rhs.match_count) return lhs.match_count > rhs.match_count;
        return lhs.path < rhs.path;
    });
    return out;
}

}  // namespace

std::string build_strings_output(const Binary& b) {
    // Format: "addr|escaped-text|xref1,xref2,..."  (addrs in hex, no 0x prefix)
    std::string out;
    for (const auto& e : scan_strings(b)) {
        std::string xrefs;
        for (std::size_t i = 0; i < e.xrefs.size(); ++i) {
            if (i > 0) xrefs += ",";
            xrefs += std::format("{:x}", e.xrefs[i]);
        }
        out += std::format("{:x}|{}|{}\n", e.addr, escape_for_line(e.text), xrefs);
    }
    return out;
}

std::string build_graphics_output(const Binary& b, bool json,
                                  const GraphicsOutputFilter& filter) {
    const auto g = analyze_graphics_surface(b);
    std::string out;
    std::map<GraphicsBackend, std::set<addr_t>> role_functions;
    const bool role_active = !filter.role.empty();
    if (role_active) {
        for (const auto& f : g.functions) {
            if (equals_ci(f.role, filter.role)) role_functions[f.backend].insert(f.function);
        }
    }
    const auto summaries = filtered_ptrs(g.summaries, [&](const auto& row) {
        return row_type_matches(filter, "summary") &&
               matches_graphics_summary(row, filter);
    });
    const auto apis = filtered_ptrs(g.apis, [&](const auto& row) {
        return row_type_matches(filter, "api") &&
               matches_graphics_api(row, filter) &&
               row_in_role_scope(row.functions, row.backend, role_active, role_functions);
    });
    const auto extensions = filtered_ptrs(g.extensions, [&](const auto& row) {
        return row_type_matches(filter, "extension") &&
               matches_graphics_extension(row, filter) &&
               row_in_role_scope(row.functions, row.backend, role_active, role_functions);
    });
    const auto functions = filtered_ptrs(g.functions, [&](const auto& row) {
        return row_type_matches(filter, "function") &&
               matches_graphics_function(row, filter);
    });
    const auto symbols = filtered_ptrs(g.symbols, [&](const auto& row) {
        std::vector<addr_t> symbol_functions;
        if (row.addr != 0) symbol_functions.push_back(row.addr);
        return row_type_matches(filter, "symbol") &&
               matches_graphics_symbol(row, filter) &&
               row_in_role_scope(symbol_functions, row.backend, role_active, role_functions);
    });
    const auto strings = filtered_ptrs(g.strings, [&](const auto& row) {
        return row_type_matches(filter, "string") &&
               matches_graphics_string(row, filter) &&
               row_in_role_scope(row.functions, row.backend, role_active, role_functions);
    });

    auto join_plain = [](const std::vector<std::string>& values) {
        std::string joined;
        for (std::size_t i = 0; i < values.size(); ++i) {
            if (i > 0) joined += ",";
            joined += escape_for_line(values[i]);
        }
        return joined;
    };
    auto join_evidence = [](const std::vector<std::string>& evidence) {
        std::string joined;
        for (std::size_t i = 0; i < evidence.size(); ++i) {
            if (i > 0) joined += " || ";
            joined += escape_for_line(evidence[i]);
        }
        return joined;
    };
    auto join_xrefs = [](const std::vector<addr_t>& xrefs) {
        std::string joined;
        for (std::size_t i = 0; i < xrefs.size(); ++i) {
            if (i > 0) joined += ",";
            joined += std::format("{:#x}", xrefs[i]);
        }
        return joined;
    };
    auto json_string_array = [](const std::vector<std::string>& values) {
        std::string joined = "[";
        for (std::size_t i = 0; i < values.size(); ++i) {
            if (i > 0) joined += ",";
            joined += std::format("\"{}\"", json_escape(values[i]));
        }
        joined += "]";
        return joined;
    };
    auto json_addr_array = [](const std::vector<addr_t>& values) {
        std::string joined = "[";
        for (std::size_t i = 0; i < values.size(); ++i) {
            if (i > 0) joined += ",";
            joined += std::format("\"{:#x}\"", values[i]);
        }
        joined += "]";
        return joined;
    };

    if (json) {
        out += "{\"summaries\":[";
        for (std::size_t i = 0; i < summaries.size(); ++i) {
            if (i > 0) out += ",";
            const auto& s = *summaries[i];
            out += std::format(
                "{{\"backend\":\"{}\",\"strings\":{},\"symbols\":{},\"functions\":{},"
                "\"api_names\":{},\"domains\":{},\"evidence\":{}}}",
                graphics_backend_name(s.backend), s.string_count, s.symbol_count,
                s.function_count, s.api_name_count, json_string_array(s.domains),
                json_string_array(s.evidence));
        }
        out += "],\"apis\":[";
        for (std::size_t i = 0; i < apis.size(); ++i) {
            if (i > 0) out += ",";
            const auto& a = *apis[i];
            out += std::format(
                "{{\"backend\":\"{}\",\"api\":\"{}\",\"variants\":{},"
                "\"extensions\":{},\"domains\":{},\"categories\":{},"
                "\"strings\":{},\"symbols\":{},\"xrefs\":{},"
                "\"functions\":{},\"string_addrs\":{},\"xref_addrs\":{},"
                "\"function_addrs\":{},\"symbol_names\":{}}}",
                graphics_backend_name(a.backend), json_escape(a.api_name),
                json_string_array(a.variants), json_string_array(a.extensions),
                json_string_array(a.domains), json_string_array(a.categories),
                a.string_count, a.symbol_count, a.xref_count, a.function_count,
                json_addr_array(a.strings), json_addr_array(a.xrefs),
                json_addr_array(a.functions), json_string_array(a.symbols));
        }
        out += "],\"extensions\":[";
        for (std::size_t i = 0; i < extensions.size(); ++i) {
            if (i > 0) out += ",";
            const auto& e = *extensions[i];
            out += std::format(
                "{{\"backend\":\"{}\",\"extension\":\"{}\",\"apis\":{},"
                "\"variants\":{},\"domains\":{},\"categories\":{},"
                "\"api_count\":{},\"variant_count\":{},\"strings\":{},"
                "\"symbols\":{},\"xrefs\":{},\"functions\":{},"
                "\"string_addrs\":{},\"xref_addrs\":{},\"function_addrs\":{},"
                "\"symbol_names\":{}}}",
                graphics_backend_name(e.backend), json_escape(e.extension),
                json_string_array(e.apis), json_string_array(e.variants),
                json_string_array(e.domains), json_string_array(e.categories),
                e.api_count, e.variant_count, e.string_count, e.symbol_count,
                e.xref_count, e.function_count, json_addr_array(e.strings),
                json_addr_array(e.xrefs), json_addr_array(e.functions),
                json_string_array(e.symbols));
        }
        out += "],\"functions\":[";
        for (std::size_t i = 0; i < functions.size(); ++i) {
            if (i > 0) out += ",";
            const auto& f = *functions[i];
            out += std::format(
                "{{\"backend\":\"{}\",\"role\":\"{}\",\"addr\":\"{:#x}\","
                "\"strings\":{},\"symbols\":{},\"api_names\":{},"
                "\"extensions\":{},\"categories\":{},\"domains\":{},\"evidence\":{}}}",
                graphics_backend_name(f.backend), json_escape(f.role), f.function,
                f.string_count, f.symbol_count, f.api_name_count,
                json_string_array(f.extensions), json_string_array(f.categories),
                json_string_array(f.domains), json_string_array(f.evidence));
        }
        out += "],\"symbols\":[";
        for (std::size_t i = 0; i < symbols.size(); ++i) {
            if (i > 0) out += ",";
            const auto& s = *symbols[i];
            out += std::format(
                "{{\"backend\":\"{}\",\"category\":\"{}\",\"domain\":\"{}\","
                "\"addr\":\"{:#x}\",\"got\":\"{:#x}\",\"api\":\"{}\","
                "\"canonical_api\":\"{}\",\"extension\":\"{}\","
                "\"linkage\":\"{}\",\"name\":\"{}\"}}",
                graphics_backend_name(s.backend), json_escape(s.category),
                json_escape(s.domain), s.addr, s.got_addr, json_escape(s.api_name),
                json_escape(s.canonical_api_name), json_escape(s.api_extension),
                json_escape(s.linkage), json_escape(s.name));
        }
        out += "],\"strings\":[";
        for (std::size_t i = 0; i < strings.size(); ++i) {
            if (i > 0) out += ",";
            const auto& s = *strings[i];
            out += std::format(
                "{{\"backend\":\"{}\",\"category\":\"{}\",\"domain\":\"{}\","
                "\"addr\":\"{:#x}\",\"api\":\"{}\",\"canonical_api\":\"{}\","
                "\"extension\":\"{}\",\"xrefs\":{},\"functions\":{},\"text\":\"{}\"}}",
                graphics_backend_name(s.backend), json_escape(s.category),
                json_escape(s.domain), s.addr, json_escape(s.api_name),
                json_escape(s.canonical_api_name), json_escape(s.api_extension),
                json_addr_array(s.xrefs), json_addr_array(s.functions),
                json_escape(s.text));
        }
        out += "]}\n";
        return out;
    }

    for (const auto* sp : summaries) {
        const auto& s = *sp;
        out += std::format("summary\t{}\tstrings={}\tsymbols={}\tfunctions={}\tapi_names={}\tdomains={}\t{}\n",
                           graphics_backend_name(s.backend), s.string_count,
                           s.symbol_count, s.function_count, s.api_name_count,
                           join_plain(s.domains),
                           join_evidence(s.evidence));
    }
    for (const auto* ap : apis) {
        const auto& a = *ap;
        out += std::format(
            "api\t{}\t{}\tvariants={}\textensions={}\tdomains={}\tcategories={}\tstrings={}\tsymbols={}\txrefs={}\tfunctions={}\tstring_addrs={}\txref_addrs={}\tfunction_addrs={}\tsymbol_names={}\n",
            graphics_backend_name(a.backend), escape_for_line(a.api_name),
            join_plain(a.variants), join_plain(a.extensions),
            join_plain(a.domains), join_plain(a.categories), a.string_count,
            a.symbol_count, a.xref_count, a.function_count, join_xrefs(a.strings),
            join_xrefs(a.xrefs), join_xrefs(a.functions), join_plain(a.symbols));
    }
    for (const auto* ep : extensions) {
        const auto& e = *ep;
        out += std::format(
            "extension\t{}\t{}\tapis={}\tvariants={}\tstrings={}\tsymbols={}\txrefs={}\tfunctions={}\tdomains={}\tcategories={}\tapi_names={}\tvariant_names={}\tstring_addrs={}\txref_addrs={}\tfunction_addrs={}\tsymbol_names={}\n",
            graphics_backend_name(e.backend), escape_for_line(e.extension),
            e.api_count, e.variant_count, e.string_count, e.symbol_count,
            e.xref_count, e.function_count, join_plain(e.domains),
            join_plain(e.categories), join_plain(e.apis), join_plain(e.variants),
            join_xrefs(e.strings), join_xrefs(e.xrefs), join_xrefs(e.functions),
            join_plain(e.symbols));
    }
    for (const auto* fp : functions) {
        const auto& f = *fp;
        out += std::format("function\t{}\t{}\t{:#x}\tstrings={}\tsymbols={}\tapi_names={}\textensions={}\tcategories={}\tdomains={}\t{}\n",
                           graphics_backend_name(f.backend), f.role, f.function,
                           f.string_count, f.symbol_count, f.api_name_count,
                           join_plain(f.extensions), join_plain(f.categories),
                           join_plain(f.domains),
                           join_evidence(f.evidence));
    }
    for (const auto* sp : symbols) {
        const auto& s = *sp;
        out += std::format("symbol\t{}\t{}\t{}\t{:#x}\tgot={:#x}\tapi={}\tlinkage={}\t{}\n",
                           graphics_backend_name(s.backend), s.category, s.domain,
                           s.addr, s.got_addr,
                           s.api_name.empty() ? "-" : escape_for_line(s.api_name),
                           escape_for_line(s.linkage),
                           s.canonical_api_name.empty()
                               ? escape_for_line(s.name)
                               : std::format("{}\tcanonical={}\text={}",
                                             escape_for_line(s.name),
                                             escape_for_line(s.canonical_api_name),
                                             s.api_extension.empty() ? "-" : escape_for_line(s.api_extension)));
    }
    for (const auto* sp : strings) {
        const auto& s = *sp;
        out += std::format("string\t{}\t{}\t{}\t{:#x}\tapi={}\txrefs={}\tfunctions={}\t{}\n",
                           graphics_backend_name(s.backend), s.category, s.domain, s.addr,
                           s.api_name.empty() ? "-" : escape_for_line(s.api_name),
                           join_xrefs(s.xrefs), join_xrefs(s.functions),
                           s.canonical_api_name.empty()
                               ? escape_for_line(s.text)
                               : std::format("canonical={}\text={}\t{}",
                                             escape_for_line(s.canonical_api_name),
                                             s.api_extension.empty() ? "-" : escape_for_line(s.api_extension),
                                             escape_for_line(s.text)));
    }
    return out;
}

[[nodiscard]] std::string format_surfaces_output(const AppSurfaceAnalysis& analysis,
                                                 bool json,
                                                 const SurfaceOutputFilter& filter) {
    const auto summaries = filtered_ptrs(analysis.summaries, [&](const auto& row) {
        return matches_surface_summary(row, filter);
    });
    const auto functions = filtered_ptrs(analysis.functions, [&](const auto& row) {
        return matches_surface_function(row, filter);
    });
    auto category_evidence = filtered_ptrs(analysis.evidence, [&](const auto& row) {
        return matches_surface_evidence_scope(row, filter);
    });
    category_evidence = filter_surface_owner_evidence(std::move(category_evidence), filter);
    const auto categories = surface_category_wanted(filter)
        ? build_surface_category_rows(category_evidence)
        : std::vector<SurfaceCategoryRow>{};
    const auto owners = surface_owner_wanted(filter)
        ? build_surface_owner_rows(category_evidence)
        : std::vector<SurfaceOwnerRow>{};
    const auto descriptors = surface_descriptor_wanted(filter)
        ? build_surface_descriptor_rows(category_evidence)
        : std::vector<SurfaceDescriptorRow>{};
    const auto artifacts = surface_artifact_wanted(filter)
        ? build_surface_artifact_rows(category_evidence)
        : std::vector<SurfaceArtifactRow>{};
    auto evidence = filtered_ptrs(analysis.evidence, [&](const auto& row) {
        return matches_surface_evidence(row, filter);
    });
    evidence = filter_surface_owner_evidence(std::move(evidence), filter);

    auto join_plain = [](const std::vector<std::string>& values) {
        std::string joined;
        for (std::size_t i = 0; i < values.size(); ++i) {
            if (i > 0) joined += ",";
            joined += escape_for_line(values[i]);
        }
        return joined;
    };
    auto join_evidence = [](const std::vector<std::string>& values) {
        std::string joined;
        for (std::size_t i = 0; i < values.size(); ++i) {
            if (i > 0) joined += " || ";
            joined += escape_for_line(values[i]);
        }
        return joined;
    };
    auto join_xrefs = [](const std::vector<addr_t>& xrefs) {
        std::string joined;
        for (std::size_t i = 0; i < xrefs.size(); ++i) {
            if (i > 0) joined += ",";
            joined += std::format("{:#x}", xrefs[i]);
        }
        return joined;
    };
    auto json_string_array = [](const std::vector<std::string>& values) {
        std::string joined = "[";
        for (std::size_t i = 0; i < values.size(); ++i) {
            if (i > 0) joined += ",";
            joined += std::format("\"{}\"", json_escape(values[i]));
        }
        joined += "]";
        return joined;
    };
    auto json_addr_array = [](const std::vector<addr_t>& values) {
        std::string joined = "[";
        for (std::size_t i = 0; i < values.size(); ++i) {
            if (i > 0) joined += ",";
            joined += std::format("\"{:#x}\"", values[i]);
        }
        joined += "]";
        return joined;
    };

    std::string out;
    if (json) {
        out += "{\"summaries\":[";
        for (std::size_t i = 0; i < summaries.size(); ++i) {
            if (i > 0) out += ",";
            const auto& s = *summaries[i];
            out += std::format(
                "{{\"subsystem\":\"{}\",\"strings\":{},\"symbols\":{},"
                "\"artifacts\":{},\"objc_methods\":{},\"rtti_classes\":{},\"log_categories\":{},"
                "\"functions\":{},\"categories\":{},\"evidence\":{}}}",
                json_escape(s.subsystem), s.string_count, s.symbol_count, s.artifact_count,
                s.objc_method_count, s.rtti_class_count, s.log_category_count,
                s.function_count, json_string_array(s.categories),
                json_string_array(s.evidence));
        }
        out += "],\"functions\":[";
        for (std::size_t i = 0; i < functions.size(); ++i) {
            if (i > 0) out += ",";
            const auto& f = *functions[i];
            out += std::format(
                "{{\"subsystem\":\"{}\",\"addr\":\"{:#x}\",\"evidence\":{},"
                "\"categories\":{},\"examples\":{}}}",
                json_escape(f.subsystem), f.function, f.evidence_count,
                json_string_array(f.categories), json_string_array(f.evidence));
        }
        out += "],\"categories\":[";
        for (std::size_t i = 0; i < categories.size(); ++i) {
            if (i > 0) out += ",";
            const auto& c = categories[i];
            out += std::format(
                "{{\"subsystem\":\"{}\",\"category\":\"{}\",\"evidence\":{},"
                "\"strings\":{},\"artifacts\":{},\"symbols\":{},\"objc_methods\":{},"
                "\"rtti_classes\":{},\"log_categories\":{},\"functions\":{},"
                "\"kinds\":{},\"examples\":{}}}",
                json_escape(c.subsystem), json_escape(c.category), c.evidence_count,
                c.string_count, c.artifact_count, c.symbol_count,
                c.objc_method_count, c.rtti_class_count, c.log_category_count,
                c.function_count, json_string_array(c.kinds),
                json_string_array(c.examples));
        }
        out += "],\"owners\":[";
        for (std::size_t i = 0; i < owners.size(); ++i) {
            if (i > 0) out += ",";
            const auto& o = owners[i];
            out += std::format(
                "{{\"subsystem\":\"{}\",\"owner\":\"{}\",\"descriptors\":{},"
                "\"bound_functions\":{},\"yield_functions\":{},\"properties\":{},"
                "\"events\":{},\"remote_events\":{},\"enums\":{},\"types\":{},"
                "\"other\":{},\"functions\":{},\"categories\":{},\"arities\":{},"
                "\"examples\":{}}}",
                json_escape(o.subsystem), json_escape(o.owner), o.descriptor_count,
                o.bound_function_count, o.yield_function_count, o.property_count,
                o.event_count, o.remote_event_count, o.enum_count, o.type_count,
                o.other_count, o.function_count, json_string_array(o.categories),
                json_string_array(o.arities), json_string_array(o.examples));
        }
        out += "],\"descriptors\":[";
        for (std::size_t i = 0; i < descriptors.size(); ++i) {
            if (i > 0) out += ",";
            const auto& d = descriptors[i];
            out += std::format(
                "{{\"subsystem\":\"{}\",\"owner\":\"{}\",\"kind\":\"{}\","
                "\"category\":\"{}\",\"arity\":\"{}\",\"addr\":\"{:#x}\","
                "\"signature\":\"{}\",\"xrefs\":{},\"functions\":{},\"type\":\"{}\"}}",
                json_escape(d.subsystem), json_escape(d.owner),
                json_escape(d.descriptor_kind), json_escape(d.category),
                json_escape(d.arity), d.addr, json_escape(d.signature),
                json_addr_array(d.xrefs), json_addr_array(d.functions),
                json_escape(d.type));
        }
        out += "],\"artifacts\":[";
        for (std::size_t i = 0; i < artifacts.size(); ++i) {
            if (i > 0) out += ",";
            const auto& a = artifacts[i];
            out += std::format(
                "{{\"path\":\"{}\",\"matches\":{},\"subsystems\":{},\"categories\":{}}}",
                json_escape(a.path), a.match_count, json_string_array(a.subsystems),
                json_string_array(a.categories));
        }
        out += "],\"evidence\":[";
        for (std::size_t i = 0; i < evidence.size(); ++i) {
            if (i > 0) out += ",";
            const auto& e = *evidence[i];
            out += std::format(
                "{{\"subsystem\":\"{}\",\"kind\":\"{}\",\"category\":\"{}\","
                "\"addr\":\"{:#x}\",\"xrefs\":{},\"functions\":{},\"text\":\"{}\"}}",
                json_escape(e.subsystem), json_escape(e.kind),
                json_escape(e.category), e.addr, json_addr_array(e.xrefs),
                json_addr_array(e.functions), json_escape(e.text));
        }
        out += "]}\n";
        return out;
    }

    for (const auto* sp : summaries) {
        const auto& s = *sp;
        out += std::format(
            "summary\t{}\tstrings={}\tartifacts={}\tsymbols={}\tobjc_methods={}\trtti_classes={}\tlog_categories={}\tfunctions={}\tcategories={}\t{}\n",
            escape_for_line(s.subsystem), s.string_count, s.artifact_count, s.symbol_count,
            s.objc_method_count, s.rtti_class_count, s.log_category_count,
            s.function_count, join_plain(s.categories), join_evidence(s.evidence));
    }
    for (const auto* fp : functions) {
        const auto& f = *fp;
        out += std::format(
            "function\t{}\t{:#x}\tevidence={}\tcategories={}\t{}\n",
            escape_for_line(f.subsystem), f.function, f.evidence_count,
            join_plain(f.categories), join_evidence(f.evidence));
    }
    for (const auto& c : categories) {
        out += std::format(
            "category\t{}\t{}\tevidence={}\tstrings={}\tartifacts={}\tsymbols={}\tobjc_methods={}\trtti_classes={}\tlog_categories={}\tfunctions={}\tkinds={}\t{}\n",
            escape_for_line(c.subsystem), escape_for_line(c.category),
            c.evidence_count, c.string_count, c.artifact_count, c.symbol_count,
            c.objc_method_count, c.rtti_class_count, c.log_category_count,
            c.function_count, join_plain(c.kinds), join_evidence(c.examples));
    }
    for (const auto& o : owners) {
        out += std::format(
            "owner\t{}\t{}\tdescriptors={}\tbound_functions={}\tyield_functions={}\tproperties={}\tevents={}\tremote_events={}\tenums={}\ttypes={}\tother={}\tfunctions={}\tarities={}\tcategories={}\t{}\n",
            escape_for_line(o.subsystem), escape_for_line(o.owner),
            o.descriptor_count, o.bound_function_count, o.yield_function_count,
            o.property_count, o.event_count, o.remote_event_count, o.enum_count,
            o.type_count, o.other_count, o.function_count, join_plain(o.arities),
            join_plain(o.categories), join_evidence(o.examples));
    }
    for (const auto& d : descriptors) {
        out += std::format(
            "descriptor\t{}\t{}\t{}\t{}\t{:#x}\targc={}\tsig={}\txrefs={}\tfunctions={}\t{}\n",
            escape_for_line(d.subsystem), escape_for_line(d.owner),
            escape_for_line(d.descriptor_kind), escape_for_line(d.category),
            d.addr, escape_for_line(d.arity), escape_for_line(d.signature),
            join_xrefs(d.xrefs), join_xrefs(d.functions), escape_for_line(d.type));
    }
    for (const auto& a : artifacts) {
        out += std::format(
            "artifact\t{}\tmatches={}\tsubsystems={}\tcategories={}\n",
            escape_for_line(a.path), a.match_count,
            join_plain(a.subsystems), join_plain(a.categories));
    }
    for (const auto* ep : evidence) {
        const auto& e = *ep;
        out += std::format(
            "evidence\t{}\t{}\t{}\t{:#x}\txrefs={}\tfunctions={}\t{}\n",
            escape_for_line(e.subsystem), escape_for_line(e.kind),
            escape_for_line(e.category), e.addr, join_xrefs(e.xrefs),
            join_xrefs(e.functions), escape_for_line(e.text));
    }
    return out;
}

std::string build_surfaces_output(const Binary& b, bool json,
                                  const SurfaceOutputFilter& filter) {
    const bool reflection_only =
        equals_ci(filter.subsystem, "reflection_metadata") &&
        (filter.kind.empty() || equals_ci(filter.kind, "reflection_descriptor"));
    const bool artifact_rows_only =
        equals_ci(filter.row_type, "artifact") &&
        filter.owner.empty() &&
        (filter.kind.empty() || equals_ci(filter.kind, "bundle_file"));
    const bool artifacts_only = !filter.function &&
                                filter.owner.empty() &&
                                (artifact_rows_only ||
                                 (equals_ci(filter.kind, "bundle_file") &&
                                  (equals_ci(filter.row_type, "evidence") ||
                                   equals_ci(filter.row_type, "category") ||
                                   equals_ci(filter.row_type, "all"))));
    if (artifacts_only) {
        return build_surface_artifacts_output(filter.artifacts, json, filter);
    }

    AppSurfaceOptions options;
    options.artifact_strings = filter.artifacts;
    options.reflection_only = reflection_only;
    const auto analysis = analyze_app_surfaces(b, options);
    return format_surfaces_output(analysis, json, filter);
}

std::string build_surface_artifacts_output(const std::vector<std::string>& artifacts,
                                           bool json,
                                           const SurfaceOutputFilter& filter) {
    const auto analysis = analyze_app_surface_artifacts(artifacts);
    return format_surfaces_output(analysis, json, filter);
}

std::string build_log_categories_output(const Binary& b) {
    std::string out;
    for (const auto& c : mine_log_categories(b)) {
        std::string fns;
        for (std::size_t i = 0; i < c.functions.size(); ++i) {
            if (i > 0) fns += ",";
            fns += std::format("{:x}", c.functions[i]);
        }
        std::string examples;
        for (std::size_t i = 0; i < c.examples.size(); ++i) {
            if (i > 0) examples += " || ";
            examples += escape_for_line(c.examples[i]);
        }
        out += std::format("{}\t{}\t{}\t{}\n",
                           c.category, c.functions.size(), fns, examples);
    }
    return out;
}

std::string build_xrefs_output(const Binary& b) {
    ScopedTimer total_timer("xrefs.total");
    std::vector<CallEdge> edges;
    {
        ScopedTimer t("xrefs.call_graph");
        edges = compute_call_graph(b, {}, CallGraphMode::Fast);
    }
    if (timing_enabled()) {
        std::fprintf(stderr, "[timing] xrefs.edges: %zu\n", edges.size());
    }

    // Keep --xrefs cheap: callers mostly need a stable edge list, not a
    // graph-layout pass. The old topo-ish formatter built several maps and
    // sets over the whole edge list after the scan had already done the
    // useful work. Sorting pairs directly is dramatically lighter on large
    // binaries and daemon/agent loops.
    {
        ScopedTimer t("xrefs.sort_dedupe");
        std::ranges::sort(edges, {}, [](const CallEdge& e) {
            return std::pair{e.caller, e.callee};
        });
        edges.erase(std::unique(edges.begin(), edges.end(),
            [](const CallEdge& lhs, const CallEdge& rhs) {
                return lhs.caller == rhs.caller && lhs.callee == rhs.callee;
            }), edges.end());
    }

    std::string out;
    {
        ScopedTimer t("xrefs.format");
        out.reserve(edges.size() * 32);
        for (const auto& e : edges) {
            out += std::format("{:#x} -> {:#x}\n", e.caller, e.callee);
        }
    }
    return out;
}

std::string build_data_xrefs_output(const Binary& b, bool json) {
    const auto xrefs = compute_data_xrefs(b);
    std::string out;
    if (!json) {
        for (const auto& [target, refs] : xrefs) {
            for (const auto& r : refs) {
                out += std::format("{:x}\t{:x}\t{}\n",
                                   target, r.from_pc, data_xref_kind_name(r.kind));
            }
        }
        return out;
    }
    out = "[";
    bool first_t = true;
    for (const auto& [target, refs] : xrefs) {
        if (!first_t) out += ',';
        first_t = false;
        out += std::format("{{\"target\":\"{:#x}\",\"refs\":[", target);
        bool first_r = true;
        for (const auto& r : refs) {
            if (!first_r) out += ',';
            first_r = false;
            out += std::format("{{\"site\":\"{:#x}\",\"kind\":\"{}\"}}",
                               r.from_pc, data_xref_kind_name(r.kind));
        }
        out += "]}";
    }
    out += "]\n";
    return out;
}

std::string build_arities_output(const Binary& b) {
    std::string out;
    for (const auto& fn : enumerate_functions(b, EnumerateMode::Auto)) {
        if (b.import_at_plt(fn.addr)) continue;
        out += std::format("{:#x} {}\n", fn.addr, infer_arity(b, fn.addr));
    }
    return out;
}

// TSV: <addr_hex>\t<size_hex>\t<kind>\t<name>. `kind` is "symbol" for a
// defined function symbol or "sub" for a CFG-discovered entry. Missing sizes
// are estimated from the gap to the next function (or section boundary) so
// downstream tools still work with sparse or stripped symbol metadata.
std::string build_functions_output(const Binary& b, bool full_analysis) {
    ScopedTimer timer("functions.build_output");
    std::string out;
    const auto mode = full_analysis ? EnumerateMode::Full : EnumerateMode::Auto;
    std::vector<DiscoveredFunction> fns;
    {
        ScopedTimer phase("functions.enumerate");
        fns = enumerate_functions(b, mode);
    }
    {
        ScopedTimer phase("functions.format");
        for (const auto& fn : fns) {
            out += std::format("{:#018x}\t{:#x}\t{}\t{}\n", fn.addr, fn.size,
                               discovered_kind_name(fn.kind), fn.name);
        }
    }
    return out;
}

// TSV: <imp-hex>\t<[+-]>\t<class>\t<selector>\t<decoded-signature>
std::string build_objc_names_output(const Binary& b) {
    std::string out;
    for (const auto& m : parse_objc_methods(b)) {
        out += std::format("{:x}\t{}\t{}\t{}\t{}\n",
                           m.imp, m.is_class ? '+' : '-',
                           m.cls, m.selector, decode_objc_type(m.type_encoding));
    }
    return out;
}

// One block per protocol, each line: `protocol\t[+-][!?]\tselector\tsignature`.
// `!` marks required, `?` marks optional.
std::string build_objc_protocols_output(const Binary& b) {
    std::string out;
    auto emit = [&](const ObjcProtocol& p, const std::vector<ObjcMethod>& ml,
                    char tag, char req) {
        for (const auto& m : ml) {
            out += std::format("{}\t{}{}\t{}\t{}\n",
                               p.name, tag, req, m.selector,
                               decode_objc_type(m.type_encoding));
        }
    };
    for (const auto& p : parse_objc_protocols(b)) {
        emit(p, p.required_instance, '-', '!');
        emit(p, p.required_class,    '+', '!');
        emit(p, p.optional_instance, '-', '?');
        emit(p, p.optional_class,    '+', '?');
    }
    return out;
}

namespace {

[[nodiscard]] std::string objc_method_key(const ObjcMethod& m) {
    return std::format("{}\t{}", m.is_class ? '+' : '-', m.selector);
}

[[nodiscard]] bool objc_class_matches_surface(std::string_view method_cls,
                                              std::string_view surface_cls) {
    if (method_cls == surface_cls) return true;
    if (method_cls.starts_with(surface_cls) &&
        method_cls.size() > surface_cls.size() &&
        method_cls[surface_cls.size()] == '(') {
        return true;
    }
    return false;
}

}  // namespace

// TSV: <class>\t<source>\t<protocol>\t<required|optional>\t<[+-]>\t
//      <selector>\t<implemented|missing>\t<decoded-signature>.
std::string build_objc_surfaces_output(const Binary& b) {
    std::string out;
    const auto methods = parse_objc_methods(b);
    const auto protocols = parse_objc_protocols(b);

    std::unordered_map<std::string, const ObjcProtocol*> protocol_by_name;
    for (const auto& p : protocols) protocol_by_name.emplace(p.name, &p);

    for (const auto& c : parse_objc_protocol_conformances(b)) {
        std::set<std::string> implemented;
        for (const auto& m : methods) {
            if (!objc_class_matches_surface(m.cls, c.cls)) continue;
            implemented.insert(objc_method_key(m));
        }

        auto emit = [&](const ObjcProtocol& p, const std::vector<ObjcMethod>& ml,
                        std::string_view requirement) {
            for (const auto& m : ml) {
                const std::string key = objc_method_key(m);
                out += std::format("{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                                   c.cls, c.source, p.name, requirement,
                                   m.is_class ? '+' : '-', m.selector,
                                   implemented.contains(key) ? "implemented" : "missing",
                                   decode_objc_type(m.type_encoding));
            }
        };

        for (const auto& proto_name : c.protocols) {
            const auto it = protocol_by_name.find(proto_name);
            if (it == protocol_by_name.end()) {
                out += std::format("{}\t{}\t{}\tunknown\t?\t\tdeclared\t\n",
                                   c.cls, c.source, proto_name);
                continue;
            }
            const ObjcProtocol& p = *it->second;
            emit(p, p.required_instance, "required");
            emit(p, p.required_class, "required");
            emit(p, p.optional_instance, "optional");
            emit(p, p.optional_class, "optional");
        }
    }
    return out;
}

// C++ RTTI: one row per (class, vfn_idx, imp_addr); meta row per class
// with vtable address + method count. Mach-O/ELF use Itanium ABI RTTI;
// PE uses MSVC RTTI.
std::string build_rtti_output(const Binary& b) {
    std::string out;
    if (b.format() == Format::Pe) {
        const auto classes = parse_msvc_rtti(b);
        const auto method_names = rtti_method_names(classes);
        for (const auto& c : classes) {
            out += std::format("class\t{:x}\t{:x}\t{}\t{}\t{}\n",
                               c.type_descriptor, c.vtable, c.methods.size(),
                               c.pretty_name, c.decorated_name);
            for (const auto& base : c.bases) {
                out += std::format("base\t{:x}\t{:x}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                                   base.type_descriptor, base.descriptor,
                                   base.pretty_name, base.decorated_name,
                                   base.mdisp, base.pdisp, base.vdisp,
                                   base.attributes);
            }
            for (std::size_t i = 0; i < c.methods.size(); ++i) {
                auto it = method_names.find(c.methods[i]);
                const std::string name = it != method_names.end()
                    ? it->second
                    : std::format("{}::vfn_{}", c.pretty_name, i);
                out += std::format("vfn\t{:x}\t{}\t{}\n",
                                   c.methods[i], i, name);
            }
        }
        return out;
    }

    const auto classes = parse_itanium_rtti(b);
    const auto method_names = rtti_method_names(classes);
    for (const auto& c : classes) {
        out += std::format("class\t{:x}\t{:x}\t{}\t{}\t{}\n",
                           c.typeinfo, c.vtable, c.methods.size(),
                           c.demangled_name, c.mangled_name);
        for (std::size_t i = 0; i < c.methods.size(); ++i) {
            auto it = method_names.find(c.methods[i]);
            const std::string name = it != method_names.end()
                ? it->second
                : std::format("{}::vfn_{}", c.demangled_name, i);
            out += std::format("vfn\t{:x}\t{}\t{}\n",
                               c.methods[i], i, name);
        }
    }
    return out;
}

std::string build_vtables_output(const Binary& b) {
    std::string out;
    const addr_t width = arch_pointer_bits(b.arch()) == 32 ? 4 : 8;
    for (const auto& vt : discover_runtime_vtables(b)) {
        out += std::format("vtable\t{:#x}\t{}\n", vt.vaddr, vt.methods.size());
        for (std::size_t i = 0; i < vt.methods.size(); ++i) {
            out += std::format("slot\t{:#x}\t{:#x}\t{}\n",
                               vt.vaddr + static_cast<addr_t>(i) * width,
                               vt.methods[i], i);
        }
    }
    return out;
}

std::string build_vtable_at_output(const Binary& b, addr_t va, u64 limit) {
    const addr_t width = arch_pointer_bits(b.arch()) == 32 ? 4 : 8;
    const auto vtables = discover_runtime_vtables(b);

    const RuntimeVtable* best = nullptr;
    std::size_t best_index = 0;
    addr_t best_distance = std::numeric_limits<addr_t>::max();

    for (const auto& vt : vtables) {
        if (vt.methods.empty()) continue;
        const addr_t begin = vt.vaddr;
        const addr_t end = vt.vaddr + static_cast<addr_t>(vt.methods.size()) * width;

        std::size_t index = 0;
        addr_t distance = 0;
        if (va >= begin && va < end) {
            index = static_cast<std::size_t>((va - begin) / width);
        } else {
            const addr_t before = begin >= 2 * width ? begin - 2 * width : begin;
            const addr_t after = end + 2 * width;
            if (va < before || va > after) continue;
            if (va < begin) {
                distance = begin - va;
                index = 0;
            } else {
                distance = va - end;
                index = vt.methods.size() - 1;
            }
        }

        if (!best || distance < best_distance) {
            best = &vt;
            best_index = index;
            best_distance = distance;
        }
    }

    if (!best) {
        return std::format("(no runtime vtable containing/near {:#x})\n", va);
    }

    std::size_t first = 0;
    std::size_t last = best->methods.size();
    if (limit != 0 && best->methods.size() > limit) {
        const std::size_t cap = static_cast<std::size_t>(limit);
        const std::size_t half = cap / 2;
        first = best_index > half ? best_index - half : 0;
        last = std::min(best->methods.size(), first + cap);
        if (last - first < cap && last == best->methods.size()) {
            first = best->methods.size() > cap ? best->methods.size() - cap : 0;
        }
    }

    std::string out;
    out += std::format("vtable\t{:#x}\t{}\tquery={:#x}\tindex={}\n",
                       best->vaddr, best->methods.size(), va, best_index);
    if (first != 0) {
        out += std::format("...\t{} slots before\n", first);
    }
    for (std::size_t i = first; i < last; ++i) {
        out += std::format("slot\t{:#x}\t{:#x}\t{}\n",
                           best->vaddr + static_cast<addr_t>(i) * width,
                           best->methods[i], i);
    }
    if (last != best->methods.size()) {
        out += std::format("...\t{} slots after\n", best->methods.size() - last);
    }
    return out;
}

std::string build_int3_resolve_output(const Binary& b) {
    auto fn_label = [&](addr_t va) -> std::string {
        for (const auto& s : b.symbols()) {
            if (s.is_import) continue;
            if (s.kind != SymbolKind::Function) continue;
            if (s.addr == va && !s.name.empty()) return s.name;
        }
        return std::format("sub_{:x}", va);
    };

    std::string out;
    auto results = resolve_embedded_int3s(b);
    if (results.empty()) {
        out = "(no embedded int3 bytes found)\n";
        return out;
    }

    out += std::format("embedded int3 sites: {}\n", results.size());
    out += "\n";

    // Group by kind for a summary header.
    std::unordered_map<Int3Kind, std::size_t> by_kind;
    for (const auto& r : results) ++by_kind[r.kind];
    out += "summary by kind:\n";
    for (auto [kind, count] : by_kind) {
        out += std::format("  {:12s} {}\n", int3_kind_name(kind), count);
    }
    out += "\n";

    // Per-site detail.
    for (const auto& r : results) {
        out += std::format("{:#x}  {:14s}", r.addr, int3_kind_name(r.kind));
        if (r.kind == Int3Kind::StubbedBranch && r.predicate) {
            out += std::format("[{}] ", branch_predicate_name(*r.predicate));
        }
        if (r.containing_fn != 0) {
            out += std::format("  in {}+{:#x}",
                               fn_label(r.containing_fn), r.fn_offset);
        } else {
            out += "  (outside any function)";
        }
        if (!r.note.empty()) {
            out += std::format("  - {}", r.note);
        }
        out += "\n";
    }
    return out;
}

}  // namespace ember::cli
