#include <spelunk/analysis/demangle.hpp>

#include <cctype>
#include <cstddef>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace spelunk {

namespace {

[[nodiscard]] std::string trim_copy(std::string_view s) {
    while (!s.empty() && s.front() == ' ') s.remove_prefix(1);
    while (!s.empty() && s.back() == ' ') s.remove_suffix(1);
    std::string out(s);
    for (std::size_t i = 1; i < out.size();) {
        if (out[i - 1] == ' ' && out[i] == '>') {
            out.erase(i - 1, 1);
            continue;
        }
        ++i;
    }
    return out;
}

[[nodiscard]] std::vector<std::string> split_template_args(std::string_view s) {
    std::vector<std::string> out;
    int angle = 0;
    int paren = 0;
    std::size_t start = 0;
    for (std::size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (c == '<') ++angle;
        else if (c == '>') --angle;
        else if (c == '(') ++paren;
        else if (c == ')') --paren;
        else if (c == ',' && angle == 0 && paren == 0) {
            out.push_back(trim_copy(s.substr(start, i - start)));
            start = i + 1;
        }
    }
    out.push_back(trim_copy(s.substr(start)));
    return out;
}

[[nodiscard]] bool default_allocator_for(std::string_view alloc,
                                         std::string_view type) {
    return trim_copy(alloc) == std::format("std::allocator<{}>", trim_copy(type));
}

[[nodiscard]] bool default_less_for(std::string_view cmp,
                                    std::string_view type) {
    return trim_copy(cmp) == std::format("std::less<{}>", trim_copy(type));
}

[[nodiscard]] bool default_hash_for(std::string_view h,
                                    std::string_view type) {
    return trim_copy(h) == std::format("std::hash<{}>", trim_copy(type));
}

[[nodiscard]] bool default_equal_for(std::string_view eq,
                                     std::string_view type) {
    return trim_copy(eq) == std::format("std::equal_to<{}>", trim_copy(type));
}

[[nodiscard]] bool default_pair_allocator_for(std::string_view alloc,
                                              std::string_view key,
                                              std::string_view value) {
    const std::string a = trim_copy(alloc);
    const std::string k = trim_copy(key);
    const std::string v = trim_copy(value);
    const std::string pair_const_key = std::format("std::pair<const {}, {}>", k, v);
    const std::string pair_key_const = std::format("std::pair<{} const, {}>", k, v);
    return a == std::format("std::allocator<{}>", pair_const_key) ||
           a == std::format("std::allocator<{}>", pair_key_const);
}

[[nodiscard]] std::string strip_std_cxx11(std::string name) {
    constexpr std::string_view ns = "std::__cxx11::";
    if (name.starts_with(ns)) name.replace(0, ns.size(), "std::");
    return name;
}

[[nodiscard]] std::optional<std::string>
stdlib_alias(const std::string& name, const std::vector<std::string>& args) {
    const bool dtor = name.starts_with("~");
    std::string base = dtor ? name.substr(1) : name;
    base = strip_std_cxx11(std::move(base));

    const bool std_qualified = base.starts_with("std::");
    std::string leaf = std_qualified ? base.substr(5) : base;
    auto qualify = [&](std::string_view alias) {
        std::string out = std_qualified ? "std::" + std::string(alias)
                                        : std::string(alias);
        if (dtor) out.insert(0, "~");
        return out;
    };

    auto char_alias = [&](std::string_view alias) -> std::optional<std::string> {
        if (args.empty()) return std::nullopt;
        const std::string ch = trim_copy(args[0]);
        if (ch == "char") return qualify(alias);
        if (ch == "wchar_t") return qualify(std::string("w") + std::string(alias));
        return std::nullopt;
    };

    if ((leaf == "__new_allocator" || leaf == "allocator") && args.size() == 1) {
        return qualify(std::format("allocator<{}>", args[0]));
    }

    if (leaf == "basic_string" && args.size() >= 3 &&
        trim_copy(args[1]) == std::format("std::char_traits<{}>", args[0]) &&
        default_allocator_for(args[2], args[0])) {
        const std::string ch = trim_copy(args[0]);
        if (ch == "char") return qualify("string");
        if (ch == "wchar_t") return qualify("wstring");
        if (ch == "char8_t") return qualify("u8string");
        if (ch == "char16_t") return qualify("u16string");
        if (ch == "char32_t") return qualify("u32string");
    }
    if (leaf == "basic_string_view" && args.size() >= 2 &&
        trim_copy(args[1]) == std::format("std::char_traits<{}>", args[0])) {
        const std::string ch = trim_copy(args[0]);
        if (ch == "char") return qualify("string_view");
        if (ch == "wchar_t") return qualify("wstring_view");
        if (ch == "char8_t") return qualify("u8string_view");
        if (ch == "char16_t") return qualify("u16string_view");
        if (ch == "char32_t") return qualify("u32string_view");
    }

    if (args.size() >= 2 &&
        trim_copy(args[1]) == std::format("std::char_traits<{}>", args[0])) {
        if (leaf == "basic_ifstream") return char_alias("ifstream");
        if (leaf == "basic_ofstream") return char_alias("ofstream");
        if (leaf == "basic_fstream") return char_alias("fstream");
        if (leaf == "basic_istream") return char_alias("istream");
        if (leaf == "basic_ostream") return char_alias("ostream");
        if (leaf == "basic_iostream") return char_alias("iostream");
        if (leaf == "basic_streambuf") return char_alias("streambuf");
        if (leaf == "basic_ios") return char_alias("ios");
    }
    if (leaf == "basic_stringstream" && args.size() >= 3 &&
        trim_copy(args[1]) == std::format("std::char_traits<{}>", args[0]) &&
        default_allocator_for(args[2], args[0])) {
        return char_alias("stringstream");
    }
    if (leaf == "basic_istringstream" && args.size() >= 3 &&
        trim_copy(args[1]) == std::format("std::char_traits<{}>", args[0]) &&
        default_allocator_for(args[2], args[0])) {
        return char_alias("istringstream");
    }
    if (leaf == "basic_ostringstream" && args.size() >= 3 &&
        trim_copy(args[1]) == std::format("std::char_traits<{}>", args[0]) &&
        default_allocator_for(args[2], args[0])) {
        return char_alias("ostringstream");
    }

    if ((leaf == "vector" || leaf == "deque" || leaf == "list" ||
         leaf == "forward_list") &&
        args.size() == 2 && default_allocator_for(args[1], args[0])) {
        return qualify(std::format("{}<{}>", leaf, args[0]));
    }
    if ((leaf == "set" || leaf == "multiset") &&
        args.size() == 3 && default_less_for(args[1], args[0]) &&
        default_allocator_for(args[2], args[0])) {
        return qualify(std::format("{}<{}>", leaf, args[0]));
    }
    if ((leaf == "unordered_set" || leaf == "unordered_multiset") &&
        args.size() == 4 && default_hash_for(args[1], args[0]) &&
        default_equal_for(args[2], args[0]) &&
        default_allocator_for(args[3], args[0])) {
        return qualify(std::format("{}<{}>", leaf, args[0]));
    }
    if ((leaf == "map" || leaf == "multimap") &&
        args.size() == 4 && default_less_for(args[2], args[0]) &&
        default_pair_allocator_for(args[3], args[0], args[1])) {
        return qualify(std::format("{}<{}, {}>", leaf, args[0], args[1]));
    }
    if ((leaf == "unordered_map" || leaf == "unordered_multimap") &&
        args.size() == 5 && default_hash_for(args[2], args[0]) &&
        default_equal_for(args[3], args[0]) &&
        default_pair_allocator_for(args[4], args[0], args[1])) {
        return qualify(std::format("{}<{}, {}>", leaf, args[0], args[1]));
    }
    if (leaf == "unique_ptr" && args.size() == 2 &&
        trim_copy(args[1]) == std::format("std::default_delete<{}>", args[0])) {
        return qualify(std::format("unique_ptr<{}>", args[0]));
    }
    return std::nullopt;
}

[[nodiscard]] std::string simplify_stdlib_templates_balanced(std::string_view s) {
    std::string out;
    for (std::size_t i = 0; i < s.size();) {
        const char c = s[i];
        if (!(std::isalpha(static_cast<unsigned char>(c)) || c == '_' || c == '~')) {
            out += c;
            ++i;
            continue;
        }

        const std::size_t name_start = i;
        ++i;
        while (i < s.size()) {
            const char ch = s[i];
            if (std::isalnum(static_cast<unsigned char>(ch)) ||
                ch == '_' || ch == ':') {
                ++i;
            } else {
                break;
            }
        }
        std::string name{s.substr(name_start, i - name_start)};
        if (i >= s.size() || s[i] != '<' || name.ends_with("operator")) {
            out += name;
            continue;
        }

        int depth = 1;
        std::size_t j = i + 1;
        for (; j < s.size(); ++j) {
            if (s[j] == '<') ++depth;
            else if (s[j] == '>') {
                --depth;
                if (depth == 0) break;
            }
        }
        if (j >= s.size() || depth != 0) {
            out += name;
            continue;
        }

        const std::string inner =
            simplify_stdlib_templates_balanced(s.substr(i + 1, j - i - 1));
        auto args = split_template_args(inner);
        if (auto alias = stdlib_alias(name, args); alias) {
            out += *alias;
        } else {
            out += name;
            out += '<';
            out += inner;
            out += '>';
        }
        i = j + 1;
    }
    return out;
}

}  // namespace

// Collapse the verbose libstdc++ template forms into their canonical
// typedef names. Hex-Rays does the same - without this, every C++ string
// or stream operation in a decompile drowns the reader in
// `std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>`
// where the source code only ever wrote `std::string`. A small fixed
// spelling pass handles historical libstdc++ quirks, then a balanced
// template pass drops default allocators / comparators while preserving
// custom policy types.
std::string simplify_stdlib_templates(std::string s) {
    struct Sub { std::string_view from, to; };
    static constexpr Sub subs[] = {
        // String types.
        {"std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >",     "std::string"},
        {"std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>",      "std::string"},
        {"std::__cxx11::basic_string<wchar_t, std::char_traits<wchar_t>, std::allocator<wchar_t> >", "std::wstring"},
        {"std::__cxx11::basic_string<wchar_t, std::char_traits<wchar_t>, std::allocator<wchar_t>>",  "std::wstring"},
        {"std::basic_string<char, std::char_traits<char>, std::allocator<char> >",              "std::string"},
        {"std::basic_string<char, std::char_traits<char>, std::allocator<char>>",               "std::string"},
        {"std::basic_string_view<char, std::char_traits<char> >",                                "std::string_view"},
        {"std::basic_string_view<char, std::char_traits<char>>",                                 "std::string_view"},
        // I/O streams.
        {"std::basic_ifstream<char, std::char_traits<char> >", "std::ifstream"},
        {"std::basic_ifstream<char, std::char_traits<char>>",  "std::ifstream"},
        {"std::basic_ofstream<char, std::char_traits<char> >", "std::ofstream"},
        {"std::basic_ofstream<char, std::char_traits<char>>",  "std::ofstream"},
        {"std::basic_fstream<char, std::char_traits<char> >",  "std::fstream"},
        {"std::basic_fstream<char, std::char_traits<char>>",   "std::fstream"},
        {"std::basic_istream<char, std::char_traits<char> >",  "std::istream"},
        {"std::basic_istream<char, std::char_traits<char>>",   "std::istream"},
        {"std::basic_ostream<char, std::char_traits<char> >",  "std::ostream"},
        {"std::basic_ostream<char, std::char_traits<char>>",   "std::ostream"},
        {"std::basic_iostream<char, std::char_traits<char> >", "std::iostream"},
        {"std::basic_iostream<char, std::char_traits<char>>",  "std::iostream"},
        {"std::basic_streambuf<char, std::char_traits<char> >", "std::streambuf"},
        {"std::basic_streambuf<char, std::char_traits<char>>",  "std::streambuf"},
        {"std::basic_ios<char, std::char_traits<char> >", "std::ios"},
        {"std::basic_ios<char, std::char_traits<char>>",  "std::ios"},
        // Destructor / leaf-class-name variants (no `std::` prefix) -
        // the demangler renders ctor / dtor names as `~basic_X<…>` with
        // template args of the parent class, and those don't pass the
        // `std::`-prefixed alias above. Matching the bare leaf form
        // collapses `…::~basic_string<char, std::char_traits<char>>`
        // to `…::~string` for clean RAII tail rendering.
        {"basic_string<char, std::char_traits<char>, std::allocator<char> >", "string"},
        {"basic_string<char, std::char_traits<char>, std::allocator<char>>",  "string"},
        {"basic_ifstream<char, std::char_traits<char> >",  "ifstream"},
        {"basic_ifstream<char, std::char_traits<char>>",   "ifstream"},
        {"basic_ofstream<char, std::char_traits<char> >",  "ofstream"},
        {"basic_ofstream<char, std::char_traits<char>>",   "ofstream"},
        {"basic_istream<char, std::char_traits<char> >",   "istream"},
        {"basic_istream<char, std::char_traits<char>>",    "istream"},
        {"basic_ostream<char, std::char_traits<char> >",   "ostream"},
        {"basic_ostream<char, std::char_traits<char>>",    "ostream"},
        {"basic_iostream<char, std::char_traits<char> >",  "iostream"},
        {"basic_iostream<char, std::char_traits<char>>",   "iostream"},
        {"basic_ios<char, std::char_traits<char> >",       "ios"},
        {"basic_ios<char, std::char_traits<char>>",        "ios"},
        // libstdc++-internal allocator wrapper that the spec exposes
        // as a raw template argument (`std::__new_allocator<char>`).
        // Almost every C++ stdlib decompile drops uses of this; the
        // class itself is plumbing the user never wrote, so collapse
        // it to its visible cousin `std::allocator<char>`.
        {"std::__new_allocator<char>", "std::allocator<char>"},
        {"__new_allocator<char>",      "allocator<char>"},
        // Bare-class form for ctor/dtor names - `~__new_allocator` /
        // `__new_allocator()` shows up after our strip-template-args
        // step on dtors of templated allocator classes.
        {"__new_allocator", "allocator"},
        {"std::basic_stringstream<char, std::char_traits<char>, std::allocator<char> >", "std::stringstream"},
        {"std::basic_stringstream<char, std::char_traits<char>, std::allocator<char>>",  "std::stringstream"},
        // Container default-allocator collapse - `vector<T, allocator<T>>`
        // → `vector<T>` when the allocator's parameter literally matches.
        // We do this generically below, but pin a couple of common ones for
        // shorter chains the generic pass would also handle.
        {", std::allocator<char> >", ">"},
        {", std::allocator<char>>", ">"},
    };
    for (const auto& [from, to] : subs) {
        for (std::size_t pos = 0;;) {
            pos = s.find(from, pos);
            if (pos == std::string::npos) break;
            s.replace(pos, from.size(), to);
            pos += to.size();
        }
    }
    return simplify_stdlib_templates_balanced(s);
}

}  // namespace spelunk
