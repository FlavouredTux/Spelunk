// App-surface report row assembly and reflection descriptor decoding.

#include <algorithm>
#include <cctype>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <ember/analysis/app_surface.hpp>
#include <ember/analysis/demangle.hpp>
#include <ember/common/types.hpp>

#include "builders_internal.hpp"
#include "builders_surfaces_internal.hpp"

namespace ember::cli::builders {

namespace {

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

}  // namespace

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

namespace {

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

}  // namespace

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

}  // namespace ember::cli::builders
