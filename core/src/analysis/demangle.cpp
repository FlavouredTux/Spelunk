#include <ember/analysis/demangle.hpp>

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace ember {

namespace {

// Recursive-descent parser for a conservative subset of the Itanium ABI
// mangling grammar. We build output strings in place and maintain the
// substitution list as the spec requires. On any construct we don't
// understand we set `failed` and unwind — the top-level returns nullopt
// and the display path falls back to the mangled name unchanged.
struct Dem {
    std::string_view in;
    std::size_t      pos = 0;
    // Substitution table — each entry is a previously-parsed type or nested
    // name, in encounter order. S_ = subs[0], S0_ = subs[1], ...
    std::vector<std::string> subs;
    // Active template-argument list, if we're currently inside one.
    // T_ references this; persists for the duration of a function signature
    // if the symbol is a template instance.
    std::vector<std::string> tmpl_args;
    bool failed = false;

    [[nodiscard]] bool eof() const { return pos >= in.size(); }
    char peek(std::size_t off = 0) const {
        return pos + off < in.size() ? in[pos + off] : '\0';
    }
    char consume() {
        if (eof()) { failed = true; return '\0'; }
        return in[pos++];
    }
    bool match(char c) {
        if (peek() != c) return false;
        ++pos;
        return true;
    }
    bool match_pref(std::string_view p) {
        if (in.size() - pos < p.size()) return false;
        if (in.substr(pos, p.size()) != p) return false;
        pos += p.size();
        return true;
    }
    void fail() { failed = true; }
};

void parse_type(Dem& d, std::string& out);
void parse_name(Dem& d, std::string& out, std::string* cv_suffix = nullptr);
void parse_template_args(Dem& d, std::string& out);
void parse_nested(Dem& d, std::string& out, std::string* cv_suffix);
void parse_expression_or_literal(Dem& d, std::string& out);

// Split a freshly-parsed `<A, B, C>` string back into its top-level
// template-arg components so T_/T0_ references inside the function body
// resolve correctly. Depth-aware so nested `<…>` don't get chopped.
void capture_tmpl_args(Dem& d, std::string_view args) {
    if (!d.tmpl_args.empty()) return;  // keep only the outermost set
    if (args.size() < 2 || args.front() != '<' || args.back() != '>') return;
    const auto inner = args.substr(1, args.size() - 2);
    std::size_t pstart = 0;
    int depth = 0;
    for (std::size_t i = 0; i <= inner.size(); ++i) {
        if (i == inner.size() || (inner[i] == ',' && depth == 0)) {
            std::size_t a = pstart, b = i;
            while (a < b && inner[a] == ' ') ++a;
            while (b > a && inner[b - 1] == ' ') --b;
            if (b > a) d.tmpl_args.emplace_back(inner.substr(a, b - a));
            pstart = i + 1;
        } else if (inner[i] == '<') ++depth;
        else if (inner[i] == '>') --depth;
    }
}

// <number> ::= <positive decimal> ; leading '0' not allowed
int parse_number(Dem& d) {
    int v = 0;
    if (d.peek() < '1' || d.peek() > '9') { d.fail(); return 0; }
    while (d.peek() >= '0' && d.peek() <= '9') {
        v = v * 10 + (d.consume() - '0');
        if (v > 1'000'000) { d.fail(); return 0; }  // runaway guard
    }
    return v;
}

// <source-name> ::= <number> <identifier>
std::string parse_source_name(Dem& d) {
    const int n = parse_number(d);
    if (d.failed || n <= 0 || d.in.size() - d.pos < static_cast<std::size_t>(n)) {
        d.fail();
        return {};
    }
    std::string s(d.in.substr(d.pos, static_cast<std::size_t>(n)));
    d.pos += static_cast<std::size_t>(n);
    return s;
}

// <operator-name> ::= two letters (or in some cases with cv suffix). We cover
// the ones that actually appear in real-world C++ code.
std::string parse_operator_name(Dem& d) {
    if (d.in.size() - d.pos < 2) { d.fail(); return {}; }
    const std::string_view op = d.in.substr(d.pos, 2);
    struct E { std::string_view code, pretty; };
    static constexpr E kOps[] = {
        {"nw", "operator new"},     {"na", "operator new[]"},
        {"dl", "operator delete"},  {"da", "operator delete[]"},
        {"ps", "operator+"},        {"ng", "operator-"},
        {"ad", "operator&"},        {"de", "operator*"},
        {"co", "operator~"},
        {"pl", "operator+"},        {"mi", "operator-"},
        {"ml", "operator*"},        {"dv", "operator/"},
        {"rm", "operator%"},
        {"an", "operator&"},        {"or", "operator|"},
        {"eo", "operator^"},
        {"aS", "operator="},        {"pL", "operator+="},
        {"mI", "operator-="},       {"mL", "operator*="},
        {"dV", "operator/="},       {"rM", "operator%="},
        {"aN", "operator&="},       {"oR", "operator|="},
        {"eO", "operator^="},
        {"ls", "operator<<"},       {"rs", "operator>>"},
        {"lS", "operator<<="},      {"rS", "operator>>="},
        {"eq", "operator=="},       {"ne", "operator!="},
        {"lt", "operator<"},        {"gt", "operator>"},
        {"le", "operator<="},       {"ge", "operator>="},
        {"nt", "operator!"},
        {"aa", "operator&&"},       {"oo", "operator||"},
        {"pp", "operator++"},       {"mm", "operator--"},
        {"cm", "operator,"},        {"pm", "operator->*"},
        {"pt", "operator->"},       {"cl", "operator()"},
        {"ix", "operator[]"},       {"qu", "operator?"},
        {"sz", "sizeof"},
    };
    for (const auto& e : kOps) {
        if (op == e.code) { d.pos += 2; return std::string(e.pretty); }
    }
    d.fail();
    return {};
}

// <ctor-dtor-name> ::= C1 | C2 | C3 | CI{1,2,3} | D0 | D1 | D2
// We need the enclosing class name to render these, which the caller
// tracks. Returned string is the unqualified part (e.g. "Foo()" for C1
// inside class Foo). Here we just emit a placeholder that the caller
// replaces with the last seen class name.
std::string parse_ctor_dtor(Dem& d, std::string_view enclosing) {
    if (d.in.size() - d.pos < 2) { d.fail(); return {}; }
    const char a = d.in[d.pos];
    const char b = d.in[d.pos + 1];
    d.pos += 2;
    if (a == 'C' && (b == '1' || b == '2' || b == '3')) return std::string(enclosing);
    if (a == 'D' && (b == '0' || b == '1' || b == '2')) return "~" + std::string(enclosing);
    d.fail();
    return {};
}

// Last component of a nested-name — pulls the "this" class for ctor/dtor.
std::string last_component(std::string_view nested) {
    const auto p = nested.rfind("::");
    if (p == std::string_view::npos) return std::string(nested);
    return std::string(nested.substr(p + 2));
}

// <builtin-type> — one letter (or 'D' + one letter for a few cases).
std::optional<std::string> parse_builtin(Dem& d) {
    if (d.eof()) return std::nullopt;
    const char c = d.peek();
    struct B { char code; std::string_view name; };
    static constexpr B kB[] = {
        {'v', "void"}, {'w', "wchar_t"}, {'b', "bool"},
        {'c', "char"}, {'a', "signed char"}, {'h', "unsigned char"},
        {'s', "short"}, {'t', "unsigned short"},
        {'i', "int"}, {'j', "unsigned int"},
        {'l', "long"}, {'m', "unsigned long"},
        {'x', "long long"}, {'y', "unsigned long long"},
        {'n', "__int128"}, {'o', "unsigned __int128"},
        {'f', "float"}, {'d', "double"}, {'e', "long double"},
        {'g', "__float128"}, {'z', "..."},
    };
    for (const auto& e : kB) if (e.code == c) { d.pos += 1; return std::string(e.name); }
    // 'D' introduces a few extras.
    if (c == 'D' && d.pos + 1 < d.in.size()) {
        const char c2 = d.in[d.pos + 1];
        switch (c2) {
            case 'i': d.pos += 2; return std::string("char32_t");
            case 's': d.pos += 2; return std::string("char16_t");
            case 'u': d.pos += 2; return std::string("char8_t");
            case 'a': d.pos += 2; return std::string("auto");
            case 'c': d.pos += 2; return std::string("decltype(auto)");
            case 'n': d.pos += 2; return std::string("std::nullptr_t");
            default: break;
        }
    }
    return std::nullopt;
}

// <substitution> ::= S_ | S<seq-id>_ | St | Sa | Ss | Si | So | Sd
std::optional<std::string> parse_substitution(Dem& d) {
    if (d.peek() != 'S') return std::nullopt;
    const char n = d.peek(1);
    switch (n) {
        case 't': d.pos += 2; return std::string("std");
        case 'a': d.pos += 2; return std::string("std::allocator");
        case 's': d.pos += 2; return std::string("std::string");
        case 'i': d.pos += 2; return std::string("std::istream");
        case 'o': d.pos += 2; return std::string("std::ostream");
        case 'd': d.pos += 2; return std::string("std::iostream");
        case 'b': d.pos += 2; return std::string("std::basic_string");
        case '_': {
            d.pos += 2;
            if (d.subs.empty()) { d.fail(); return std::nullopt; }
            return d.subs.front();
        }
        default: break;
    }
    // S<seq_id>_ with seq_id base 36 starting at 0 (so S0_ = subs[1]).
    if ((n >= '0' && n <= '9') || (n >= 'A' && n <= 'Z')) {
        std::size_t p = d.pos + 1;
        std::size_t seq = 0;
        while (p < d.in.size() &&
               ((d.in[p] >= '0' && d.in[p] <= '9') ||
                (d.in[p] >= 'A' && d.in[p] <= 'Z'))) {
            const int digit = (d.in[p] >= 'A') ? (d.in[p] - 'A' + 10)
                                               : (d.in[p] - '0');
            seq = seq * 36 + static_cast<std::size_t>(digit);
            if (seq > 1'000'000) { d.fail(); return std::nullopt; }
            ++p;
        }
        if (p >= d.in.size() || d.in[p] != '_') return std::nullopt;
        const std::size_t idx = seq + 1;
        if (idx >= d.subs.size()) { d.fail(); return std::nullopt; }
        d.pos = p + 1;
        return d.subs[idx];
    }
    return std::nullopt;
}

// <template-param> ::= T_ | T<seq>_
std::optional<std::string> parse_template_param(Dem& d) {
    if (d.peek() != 'T') return std::nullopt;
    std::size_t p = d.pos + 1;
    std::size_t idx = 0;
    if (p < d.in.size() && d.in[p] == '_') {
        if (d.tmpl_args.empty()) { d.fail(); return std::nullopt; }
        d.pos = p + 1;
        return d.tmpl_args.front();
    }
    std::size_t seq = 0;
    bool any = false;
    while (p < d.in.size() &&
           ((d.in[p] >= '0' && d.in[p] <= '9') ||
            (d.in[p] >= 'A' && d.in[p] <= 'Z'))) {
        const int digit = (d.in[p] >= 'A') ? (d.in[p] - 'A' + 10)
                                           : (d.in[p] - '0');
        seq = seq * 36 + static_cast<std::size_t>(digit);
        any = true;
        ++p;
    }
    if (!any || p >= d.in.size() || d.in[p] != '_') return std::nullopt;
    idx = seq + 1;
    if (idx >= d.tmpl_args.size()) { d.fail(); return std::nullopt; }
    d.pos = p + 1;
    return d.tmpl_args[idx];
}

// <template-args> ::= I <template-arg>+ E
// <template-arg>  ::= <type> | X <expression> E | <expr-primary> | J <arg>* E
void parse_template_args(Dem& d, std::string& out) {
    if (!d.match('I')) { d.fail(); return; }
    out += '<';
    bool first = true;
    while (!d.eof() && d.peek() != 'E') {
        if (!first) out += ", ";
        first = false;
        if (d.peek() == 'X') {
            ++d.pos;
            parse_expression_or_literal(d, out);
            if (d.failed) return;
            if (!d.match('E')) { d.fail(); return; }
        } else if (d.peek() == 'L') {
            // <expr-primary> ::= L <type> <value number> E
            ++d.pos;
            std::string t;
            parse_type(d, t);
            if (d.failed) return;
            // Read number (possibly negative).
            std::string num;
            if (d.match('n')) num += '-';
            while (!d.eof() && d.peek() != 'E') num += d.consume();
            if (!d.match('E')) { d.fail(); return; }
            out += num.empty() ? t : num;
        } else if (d.peek() == 'J') {
            // Pack: J args E — just join the inner types comma-separated.
            ++d.pos;
            bool first_pack = true;
            while (!d.eof() && d.peek() != 'E') {
                if (!first_pack) out += ", ";
                first_pack = false;
                std::string t;
                parse_type(d, t);
                if (d.failed) return;
                out += t;
            }
            if (!d.match('E')) { d.fail(); return; }
        } else {
            std::string t;
            parse_type(d, t);
            if (d.failed) return;
            out += t;
        }
    }
    if (!d.match('E')) { d.fail(); return; }
    out += '>';
}

// Trivial expression / literal handling — just enough for X ... E within
// template args. A lot of real-world templates use simple integer literals.
void parse_expression_or_literal(Dem& d, std::string& out) {
    // Most common: L<type><value>E — integer literal.
    if (d.peek() == 'L') {
        ++d.pos;
        std::string t;
        parse_type(d, t);
        if (d.failed) return;
        std::string num;
        if (d.match('n')) num += '-';
        while (!d.eof() && d.peek() != 'E') num += d.consume();
        if (!d.match('E')) { d.fail(); return; }
        out += num.empty() ? t : num;
        return;
    }
    d.fail();
}

// <unqualified-name> ::= <operator-name> | <ctor-dtor-name> | <source-name>
// Called within a nested-name or as a top-level unqualified function name.
// `enclosing` is the most recently seen class name, used to render ctor/dtor.
void parse_unqualified_into(Dem& d, std::string& out,
                            std::string_view enclosing) {
    if (d.eof()) { d.fail(); return; }
    const char c = d.peek();
    if (c >= '0' && c <= '9') {
        out += parse_source_name(d);
        return;
    }
    if (c == 'C' || c == 'D') {
        out += parse_ctor_dtor(d, enclosing);
        return;
    }
    // Operator name: two lowercase/upper-case letters.
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
        out += parse_operator_name(d);
        return;
    }
    d.fail();
}

// <nested-name> ::= N [<CV-qualifiers>] <prefix> <unqualified-name> E
//                 | N [<CV-qualifiers>] <template-prefix> <template-args> E
// Prefixes cascade; each added component is pushed onto the substitution
// table.
void parse_nested(Dem& d, std::string& out, std::string* cv_suffix) {
    if (!d.match('N')) { d.fail(); return; }
    // CV qualifiers on the implicit `this` — 'r' restrict, 'V' volatile,
    // 'K' const. They apply to the function type, rendered as a suffix on
    // the complete declaration (`foo() const`, not `foo const()`).
    std::string cv;
    while (true) {
        if (d.peek() == 'r') { ++d.pos; cv += " restrict"; }
        else if (d.peek() == 'V') { ++d.pos; cv += " volatile"; }
        else if (d.peek() == 'K') { ++d.pos; cv += " const"; }
        else break;
    }
    // Also 'R'/'O' for ref-qualifiers on the this ptr (member fns).
    std::string ref_qual;
    if (d.peek() == 'R') { ++d.pos; ref_qual = " &"; }
    else if (d.peek() == 'O') { ++d.pos; ref_qual = " &&"; }

    std::string assembled;
    while (!d.eof() && d.peek() != 'E') {
        // Snapshot enclosing-class BEFORE appending the `::` separator, so a
        // ctor/dtor component resolves against the parent's last name.
        const std::string enclosing = last_component(assembled);
        if (!assembled.empty()) assembled += "::";

        // A prefix slot may also be a substitution or template parameter
        // reference; if so, plug it in and remember for later cascades.
        if (d.peek() == 'S') {
            auto sub = parse_substitution(d);
            if (d.failed || !sub) { d.fail(); return; }
            assembled += *sub;
            continue;
        }
        if (d.peek() == 'T') {
            auto tp = parse_template_param(d);
            if (d.failed || !tp) { d.fail(); return; }
            assembled += *tp;
            d.subs.push_back(assembled);
            continue;
        }
        parse_unqualified_into(d, assembled, enclosing);
        if (d.failed) return;
        // Template args attach to the just-added component.
        if (d.peek() == 'I') {
            std::string args;
            parse_template_args(d, args);
            if (d.failed) return;
            // Grab the component we just appended + its args and stash as a
            // substitution for future S_ references.
            assembled += args;
            capture_tmpl_args(d, args);
        }
        d.subs.push_back(assembled);
    }
    if (!d.match('E')) { d.fail(); return; }
    out += assembled;
    if (cv_suffix) {
        *cv_suffix += cv;
        *cv_suffix += ref_qual;
    } else {
        out += cv;
        out += ref_qual;
    }
}

// <type> ::= <builtin> | <qualified> | P<type> | R<type> | O<type>
//          | K<type> | V<type> | A <number> _ <type>
//          | <class-enum-type> | <substitution> | <template-param>
//          | M <class> <type>      (pointer-to-member, partial support)
//          | F ... E               (function type — rare in params; skip)
void parse_type(Dem& d, std::string& out) {
    if (d.eof()) { d.fail(); return; }
    // Record position of the "unmodified" root so we can add the full type
    // (with modifiers) to the substitution table at the end.
    const std::size_t root_start = out.size();
    const std::size_t sub_pos_before = d.subs.size();
    (void)sub_pos_before;

    const char c = d.peek();
    // Pointer
    if (c == 'P') {
        ++d.pos;
        std::string inner;
        parse_type(d, inner);
        if (d.failed) return;
        out += inner + "*";
        d.subs.push_back(out.substr(root_start));
        return;
    }
    if (c == 'R') {
        ++d.pos;
        std::string inner;
        parse_type(d, inner);
        if (d.failed) return;
        out += inner + "&";
        d.subs.push_back(out.substr(root_start));
        return;
    }
    if (c == 'O') {
        ++d.pos;
        std::string inner;
        parse_type(d, inner);
        if (d.failed) return;
        out += inner + "&&";
        d.subs.push_back(out.substr(root_start));
        return;
    }
    if (c == 'K' || c == 'V' || c == 'r') {
        // const / volatile / restrict prefix.
        const char q = d.consume();
        std::string inner;
        parse_type(d, inner);
        if (d.failed) return;
        std::string_view word = (q == 'K') ? "const" : (q == 'V') ? "volatile" : "restrict";
        out += std::string(word) + " " + inner;
        d.subs.push_back(out.substr(root_start));
        return;
    }
    if (c == 'A') {
        // Array: A <number> _ <type>
        ++d.pos;
        int n = parse_number(d);
        if (d.failed) return;
        if (!d.match('_')) { d.fail(); return; }
        std::string inner;
        parse_type(d, inner);
        if (d.failed) return;
        out += inner;
        out += "[";
        out += std::to_string(n);
        out += "]";
        return;
    }
    if (c == 'F') {
        // Function type: F <return> <args>* E — render as ret(args) for
        // function-pointer params. Common enough to support minimally.
        ++d.pos;
        std::string ret_t;
        parse_type(d, ret_t);
        if (d.failed) return;
        std::string args;
        bool first = true;
        while (!d.eof() && d.peek() != 'E') {
            if (!first) args += ", ";
            first = false;
            std::string t;
            parse_type(d, t);
            if (d.failed) return;
            args += t;
        }
        if (!d.match('E')) { d.fail(); return; }
        out += ret_t + " (" + args + ")";
        d.subs.push_back(out.substr(root_start));
        return;
    }
    if (c == 'S') {
        auto s = parse_substitution(d);
        if (d.failed || !s) { d.fail(); return; }
        // Substitution refs may have template args attached, OR (for the
        // St/Sa/Ss… namespace abbreviations) a further source-name cascade
        // like `St6vector` = std::vector.
        out += *s;
        if (d.peek() >= '0' && d.peek() <= '9') {
            out += "::";
            parse_unqualified_into(d, out, *s);
            if (d.failed) return;
            d.subs.push_back(out.substr(root_start));
        }
        if (d.peek() == 'I') {
            std::string args;
            parse_template_args(d, args);
            if (d.failed) return;
            out += args;
            d.subs.push_back(out.substr(root_start));
        }
        return;
    }
    if (c == 'T') {
        auto tp = parse_template_param(d);
        if (d.failed || !tp) { d.fail(); return; }
        out += *tp;
        d.subs.push_back(out.substr(root_start));
        return;
    }
    if (c == 'N') {
        std::string nested;
        parse_nested(d, nested, nullptr);
        if (d.failed) return;
        out += nested;
        return;
    }
    // Unnamed class-enum-type = <source-name> [<template-args>]
    if (c >= '0' && c <= '9') {
        std::string name = parse_source_name(d);
        if (d.failed) return;
        out += name;
        if (d.peek() == 'I') {
            std::string args;
            parse_template_args(d, args);
            if (d.failed) return;
            out += args;
        }
        d.subs.push_back(out.substr(root_start));
        return;
    }
    // Pointer-to-member: M <class> <type>. We emit "type class::*" which is
    // canonical C++ syntax.
    if (c == 'M') {
        ++d.pos;
        std::string cls;
        parse_type(d, cls);
        if (d.failed) return;
        std::string pointee;
        parse_type(d, pointee);
        if (d.failed) return;
        out += pointee + " " + cls + "::*";
        d.subs.push_back(out.substr(root_start));
        return;
    }
    if (auto b = parse_builtin(d); b) {
        out += *b;
        return;  // builtin types are NOT added to substitutions per ABI.
    }
    d.fail();
}

// <name> ::= <nested-name> | <unscoped-name> | <local-name> | <substitution>
void parse_name(Dem& d, std::string& out, std::string* cv_suffix) {
    if (d.peek() == 'N') { parse_nested(d, out, cv_suffix); return; }
    if (d.peek() == 'Z') { d.fail(); return; }  // local-name — not supported
    if (d.peek() == 'S') {
        auto s = parse_substitution(d);
        if (d.failed || !s) { d.fail(); return; }
        out += *s;
        // Special-case: the `St`/`Sa`/`Ss` etc. prefixes are also valid
        // namespace prefixes for an unqualified name that follows directly.
        // `_ZSt3mini` → `std::min(int)`.
        if (d.peek() >= '0' && d.peek() <= '9') {
            out += "::";
            parse_unqualified_into(d, out, *s);
            if (d.failed) return;
            d.subs.push_back(out);
        }
        if (d.peek() == 'I') {
            std::string args;
            parse_template_args(d, args);
            if (d.failed) return;
            out += args;
            capture_tmpl_args(d, args);
        }
        return;
    }
    // <unscoped-name> ::= <unqualified-name> [<template-args>]
    parse_unqualified_into(d, out, {});
    if (d.failed) return;
    if (d.peek() == 'I') {
        std::string args;
        parse_template_args(d, args);
        if (d.failed) return;
        out += args;
        capture_tmpl_args(d, args);
    }
}

// Top-level encoding: <name> [<bare-function-type>]
std::string parse_encoding(Dem& d) {
    std::string name;
    std::string cv_suffix;
    parse_name(d, name, &cv_suffix);
    if (d.failed) return {};
    if (d.eof()) return name + cv_suffix;
    if (d.peek() == 'E') return name + cv_suffix;

    // When the name is a template specialization, the first type in the
    // bare-function-type is the RETURN type (ABI 5.1.5). Skip it for display.
    const bool template_instance = !d.tmpl_args.empty();

    std::vector<std::string> types;
    const std::size_t save = d.pos;
    while (!d.eof()) {
        std::string t;
        const std::size_t before = d.pos;
        parse_type(d, t);
        if (d.failed) {
            if (d.pos == save && types.empty()) { d.failed = false; return name + cv_suffix; }
            d.failed = false;
            d.pos = before;
            break;
        }
        types.push_back(std::move(t));
    }
    std::size_t first_arg = 0;
    if (template_instance && !types.empty()) first_arg = 1;  // drop return type

    std::string args;
    for (std::size_t i = first_arg; i < types.size(); ++i) {
        if (i > first_arg) args += ", ";
        args += types[i];
    }
    if (args == "void") args.clear();
    return name + "(" + args + ")" + cv_suffix;
}

}  // namespace

std::optional<std::string> demangle_itanium(std::string_view mangled) {
    if (mangled.size() < 2) return std::nullopt;
    std::size_t start = 0;
    if (mangled.substr(0, 2) == "_Z") start = 2;
    else if (mangled.size() >= 3 && mangled.substr(0, 3) == "__Z") start = 3;
    else return std::nullopt;

    Dem d;
    d.in  = mangled;
    d.pos = start;

    std::string result = parse_encoding(d);
    if (d.failed || result.empty()) return std::nullopt;
    return result;
}

std::string pretty_symbol(std::string_view name) {
    if (auto r = demangle_itanium(name); r) return *r;
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
                // own name — e.g. `operator()`. Restore.
                std::string_view head = s.substr(0, i);
                if (head.ends_with("operator")) return std::string(s);
                return std::string(head);
            }
        }
    }
    return std::string(s);
}

std::string pretty_symbol_base(std::string_view name) {
    return strip_signature_suffix(pretty_symbol(name));
}

}  // namespace ember
