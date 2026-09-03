// App-surface reports: category, owner, descriptor and artifact rows.

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <format>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <ember/analysis/app_surface.hpp>
#include <ember/analysis/demangle.hpp>
#include <ember/analysis/graphics.hpp>
#include <ember/binary/binary.hpp>
#include <ember/common/types.hpp>

#include "builders.hpp"
#include "builders_internal.hpp"
#include "util.hpp"

namespace ember::cli::builders {

namespace {

[[nodiscard]] std::string lower_ascii(std::string_view text) {
    std::string out(text);
    for (char& c : out) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
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

bool contains_ci(std::string_view haystack, std::string_view needle) {
    if (needle.empty()) return true;
    return lower_ascii(haystack).find(lower_ascii(needle)) != std::string::npos;
}

bool equals_ci(std::string_view lhs, std::string_view rhs) {
    return lower_ascii(lhs) == lower_ascii(rhs);
}

bool vector_contains_ci(const std::vector<std::string>& values,
                                      std::string_view needle) {
    if (needle.empty()) return true;
    return std::ranges::any_of(values, [&](const std::string& value) {
        return equals_ci(value, needle);
    });
}

bool vector_contains_substring_ci(const std::vector<std::string>& values,
                                                std::string_view needle) {
    if (needle.empty()) return true;
    return std::ranges::any_of(values, [&](const std::string& value) {
        return contains_ci(value, needle);
    });
}

bool vector_contains_addr(const std::vector<addr_t>& values, addr_t needle) {
    return std::ranges::find(values, needle) != values.end();
}

bool row_in_role_scope(const std::vector<addr_t>& functions,
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

bool backend_matches(GraphicsBackend backend,
                                   const GraphicsOutputFilter& filter) {
    return filter.backend.empty() ||
           equals_ci(graphics_backend_name(backend), filter.backend);
}

bool row_type_matches(const GraphicsOutputFilter& filter,
                                    std::string_view row_type) {
    return filter.row_type.empty() || equals_ci(filter.row_type, row_type);
}

}  // namespace ember::cli::builders

namespace ember::cli {

using namespace builders;

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

}  // namespace ember::cli
