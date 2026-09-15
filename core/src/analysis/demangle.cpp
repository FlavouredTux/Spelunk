#include <spelunk/analysis/demangle.hpp>

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <spelunk/analysis/msvc_demangle.hpp>

namespace spelunk {

std::string pretty_symbol(std::string_view name) {
    if (auto r = demangle_itanium(name); r) {
        return simplify_stdlib_templates(std::move(*r));
    }
    if (auto r = demangle_msvc_full(name); r) {
        return simplify_stdlib_templates(std::move(*r));
    }
    return std::string(name);
}

std::string strip_signature_suffix(std::string_view s) {
    // Trailing CV/ref-qualifier suffix on member functions.
    while (!s.empty()) {
        if (s.ends_with(" const"))     s.remove_suffix(6);
        else if (s.ends_with(" volatile")) s.remove_suffix(9);
        else if (s.ends_with(" &"))     s.remove_suffix(2);
        else if (s.ends_with(" &&"))    s.remove_suffix(3);
        else break;
    }
    // Trailing arg list. Match the `(` that pairs with the final `)`.
    if (s.empty() || s.back() != ')') return std::string(s);
    int depth = 1;
    std::size_t i = s.size() - 1;
    while (i > 0) {
        --i;
        const char c = s[i];
        if (c == ')') ++depth;
        else if (c == '(') {
            --depth;
            if (depth == 0) {
                // If what remains ends in `operator` (with no trailing char),
                // the `()` we'd strip is actually part of the call-operator's
                // own name - e.g. `operator()`. Restore.
                std::string_view head = s.substr(0, i);
                if (head.ends_with("operator")) return std::string(s);
                return std::string(head);
            }
        }
    }
    return std::string(s);
}

std::string pretty_symbol_base(std::string_view name) {
    if (auto r = demangle_msvc(name); r) {
        return *r;
    }
    return strip_signature_suffix(pretty_symbol(name));
}

std::optional<unsigned char>
arity_from_mangled(std::string_view mangled) {
    auto demangled_opt = demangle_itanium(mangled);
    if (!demangled_opt) return std::nullopt;
    const std::string& s = *demangled_opt;

    // Strip CV/ref-qualifier suffix in place to land the trailing `)`
    // adjacent to the args parens.
    std::string_view sv{s};
    while (!sv.empty()) {
        if (sv.ends_with(" const"))      sv.remove_suffix(6);
        else if (sv.ends_with(" volatile")) sv.remove_suffix(9);
        else if (sv.ends_with(" &"))      sv.remove_suffix(2);
        else if (sv.ends_with(" &&"))     sv.remove_suffix(3);
        else break;
    }
    if (sv.empty() || sv.back() != ')') return std::nullopt;

    // Find the matching `(` for the trailing `)`. Bail if we'd cross an
    // `operator()` boundary (the parens there belong to the operator name).
    int depth = 1;
    std::size_t i = sv.size() - 1;
    while (i > 0) {
        --i;
        const char c = sv[i];
        if (c == ')') ++depth;
        else if (c == '(') {
            --depth;
            if (depth == 0) {
                std::string_view head = sv.substr(0, i);
                if (head.ends_with("operator")) return std::nullopt;
                std::string_view args = sv.substr(i + 1, sv.size() - i - 2);

                // Count comma-separated entries, ignoring commas nested
                // inside <…> template args or further (…) inside arg types.
                unsigned char arg_count = 0;
                if (!args.empty()) {
                    auto trimmed = [&](std::string_view t) {
                        std::size_t a = 0;
                        while (a < t.size() && t[a] == ' ') ++a;
                        return a < t.size();
                    };
                    int d = 0;
                    std::size_t start = 0;
                    for (std::size_t j = 0; j < args.size(); ++j) {
                        const char ac = args[j];
                        if (ac == '<' || ac == '(' || ac == '[') ++d;
                        else if (ac == '>' || ac == ')' || ac == ']') --d;
                        else if (ac == ',' && d == 0) {
                            if (trimmed(args.substr(start, j - start))) ++arg_count;
                            start = j + 1;
                        }
                    }
                    if (trimmed(args.substr(start))) ++arg_count;
                    // `(void)` decays to zero args.
                    if (arg_count == 1 && args == "void") arg_count = 0;
                }

                // Member-function `this` adjustment: if `head` ends in
                // `Class::name` (a `::` separator before the leaf
                // identifier) AND the leaf isn't `operator new` /
                // `operator delete` (which are treated as free functions
                // even when found via class scope), bump by 1.
                bool is_member = false;
                {
                    auto last_colon = head.rfind("::");
                    if (last_colon != std::string_view::npos) {
                        std::string_view leaf = head.substr(last_colon + 2);
                        if (leaf != "operator new" &&
                            leaf != "operator new[]" &&
                            leaf != "operator delete" &&
                            leaf != "operator delete[]" &&
                            !head.starts_with("operator ")) {
                            is_member = true;
                        }
                    }
                }
                if (is_member && arg_count < 255) ++arg_count;
                return arg_count;
            }
        }
    }
    return std::nullopt;
}

}  // namespace spelunk
