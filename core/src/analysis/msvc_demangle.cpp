#include <ember/analysis/msvc_demangle.hpp>

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ember {

namespace {

// Operator codes after `??`. Indexed table beats a switch for the
// dense `?A`..`?Z` range and a small fallthrough handles `?_X` two-char
// operators below.
[[nodiscard]] std::string_view operator_for(char c) noexcept {
    switch (c) {
        case '2': return "operator new";
        case '3': return "operator delete";
        case '4': return "operator=";
        case '5': return "operator>>";
        case '6': return "operator<<";
        case '7': return "operator!";
        case '8': return "operator==";
        case '9': return "operator!=";
        case 'A': return "operator[]";
        case 'B': return "operator cast";
        case 'C': return "operator->";
        case 'D': return "operator*";
        case 'E': return "operator++";
        case 'F': return "operator--";
        case 'G': return "operator-";
        case 'H': return "operator+";
        case 'I': return "operator&";
        case 'J': return "operator->*";
        case 'K': return "operator/";
        case 'L': return "operator%";
        case 'M': return "operator<";
        case 'N': return "operator<=";
        case 'O': return "operator>";
        case 'P': return "operator>=";
        case 'Q': return "operator,";
        case 'R': return "operator()";
        case 'S': return "operator~";
        case 'T': return "operator^";
        case 'U': return "operator|";
        case 'V': return "operator&&";
        case 'W': return "operator||";
        case 'X': return "operator*=";
        case 'Y': return "operator+=";
        case 'Z': return "operator-=";
        default:  return {};
    }
}

[[nodiscard]] std::string_view operator2_for(char c) noexcept {
    // `?_<c>` two-character operators. Subset that shows up in real code.
    switch (c) {
        case '0': return "operator/=";
        case '1': return "operator%=";
        case '2': return "operator>>=";
        case '3': return "operator<<=";
        case '4': return "operator&=";
        case '5': return "operator|=";
        case '6': return "operator^=";
        case '7': return "`vftable'";
        case '8': return "`vbtable'";
        case '9': return "`vcall'";
        case 'A': return "`typeof'";
        case 'B': return "`local static guard'";
        case 'C': return "`string'";
        case 'D': return "`vbase destructor'";
        case 'E': return "<dtor>";   // vector deleting destructor
        case 'F': return "`default constructor closure'";
        case 'G': return "<dtor>";   // scalar deleting destructor
        case 'H': return "`vector constructor iterator'";
        case 'I': return "`vector destructor iterator'";
        case 'L': return "`eh vector constructor iterator'";
        case 'M': return "`eh vector destructor iterator'";
        case 'N': return "`copy constructor closure'";
        case 'P': return "`udt returning'";
        case 'R': return "`RTTI'";
        case 'S': return "`local vftable'";
        case 'T': return "`local vftable constructor closure'";
        case 'U': return "operator new[]";
        case 'V': return "operator delete[]";
        case 'X': return "`placement delete closure'";
        case 'Y': return "`placement delete[] closure'";
        default:  return {};
    }
}

[[nodiscard]] std::string_view builtin_type(char c) noexcept {
    switch (c) {
        case 'C': return "signed char";
        case 'D': return "char";
        case 'E': return "unsigned char";
        case 'F': return "short";
        case 'G': return "unsigned short";
        case 'H': return "int";
        case 'I': return "unsigned int";
        case 'J': return "long";
        case 'K': return "unsigned long";
        case 'M': return "float";
        case 'N': return "double";
        case 'O': return "long double";
        case 'X': return "void";
        case 'Z': return "...";
        default:  return {};
    }
}

[[nodiscard]] std::string_view builtin_type2(char c) noexcept {
    // `_<c>` extended primitives.
    switch (c) {
        case 'D': return "__int8";
        case 'E': return "unsigned __int8";
        case 'F': return "__int16";
        case 'G': return "unsigned __int16";
        case 'H': return "__int32";
        case 'I': return "unsigned __int32";
        case 'J': return "__int64";
        case 'K': return "unsigned __int64";
        case 'L': return "__int128";
        case 'M': return "unsigned __int128";
        case 'N': return "bool";
        case 'S': return "char16_t";
        case 'U': return "char32_t";
        case 'W': return "wchar_t";
        default:  return {};
    }
}

class MsvcDemangler {
public:
    explicit MsvcDemangler(std::string_view in) noexcept : in_(in) {}

    std::optional<std::string> run();

private:
    static constexpr int kMaxDepth = 32;

    [[nodiscard]] char peek() const noexcept {
        return pos_ < in_.size() ? in_[pos_] : '\0';
    }
    char eat() noexcept {
        return pos_ < in_.size() ? in_[pos_++] : '\0';
    }
    bool consume(char c) noexcept {
        if (peek() == c) { ++pos_; return true; } return false;
    }
    [[nodiscard]] bool eof() const noexcept { return pos_ >= in_.size(); }
    [[nodiscard]] bool starts_with(std::string_view s) const noexcept {
        return pos_ + s.size() <= in_.size() &&
               in_.compare(pos_, s.size(), s) == 0;
    }

    // Parses the qualified name list starting at the current position
    // and ending at `@@`. Joins fragments with `::` after reversing
    // (innermost-first → outermost-first).
    std::optional<std::string> parse_qualified_name();
    // One fragment of a qualified name: literal, backref, template, or
    // (at top level) a special-name marker.
    std::optional<std::string> parse_unqualified_name();
    // After the `?$` template marker has been consumed: read the template
    // name, then `<args...>`, then `@@`. Returns "Name<arg1,arg2>".
    std::optional<std::string> parse_template_after_marker();
    // One template / function argument. Recursive.
    std::optional<std::string> parse_type();
    // After a `V`/`U`/`W`/`T` named-type marker — reads the qualified
    // class name terminator.
    std::optional<std::string> parse_named_type();

    std::string_view              in_;
    std::size_t                   pos_   = 0;
    int                           depth_ = 0;
    std::vector<std::string>      name_backrefs_;
    std::vector<std::string>      type_backrefs_;
};

std::optional<std::string> MsvcDemangler::run() {
    if (in_.empty()) return std::nullopt;

    // RTTI type descriptor: ".?AV<name>@@" or ".?AU<name>@@". Anything
    // else with a leading dot isn't ours.
    if (starts_with(".?AV") || starts_with(".?AU")) {
        pos_ += 4;
        return parse_qualified_name();
    }
    if (peek() == '.') return std::nullopt;

    // Public mangled symbols start with `?`.
    if (!consume('?')) return std::nullopt;

    // `??` introduces a special form: operator, ctor, dtor, etc.
    if (consume('?')) {
        std::string op_marker;
        const char c = eat();
        if (c == '0') op_marker = "<ctor>";
        else if (c == '1') op_marker = "<dtor>";
        else if (c == '_') {
            const char c2 = eat();
            const std::string_view sv = operator2_for(c2);
            if (sv.empty()) return std::nullopt;
            op_marker = std::string(sv);
        } else {
            const std::string_view sv = operator_for(c);
            if (sv.empty()) return std::nullopt;
            op_marker = std::string(sv);
        }

        // Now parse the qualified scope. The class name (innermost) is
        // needed to render ctor/dtor; for plain operators, the scope is
        // appended in front and the operator name is the basename.
        auto qual = parse_qualified_name();
        if (!qual) return std::nullopt;

        // qual is already joined `Outer::Inner::Class`. For ctor/dtor we
        // need the *last* component as the class name to substitute in.
        const std::string& q = *qual;
        if (op_marker == "<ctor>" || op_marker == "<dtor>") {
            const auto last_sep = q.rfind("::");
            const std::string_view class_name =
                (last_sep == std::string::npos) ? std::string_view(q)
                                                : std::string_view(q).substr(last_sep + 2);
            std::string out = q;
            out += "::";
            if (op_marker == "<dtor>") out += "~";
            out.append(class_name.data(), class_name.size());
            return out;
        }
        // Plain operator: scope::operatorName.
        std::string out = q;
        if (!out.empty()) out += "::";
        out += op_marker;
        return out;
    }

    // Non-special mangled name. The first fragment is the basename;
    // subsequent ones are scopes.
    return parse_qualified_name();
}

std::optional<std::string> MsvcDemangler::parse_qualified_name() {
    if (++depth_ > kMaxDepth) { --depth_; return std::nullopt; }

    std::vector<std::string> parts;
    while (!eof()) {
        if (peek() == '@') { eat(); break; }   // first '@' of '@@' terminator
        auto frag = parse_unqualified_name();
        if (!frag) { --depth_; return std::nullopt; }
        parts.push_back(std::move(*frag));
    }

    --depth_;
    std::string out;
    for (auto it = parts.rbegin(); it != parts.rend(); ++it) {
        if (!out.empty()) out += "::";
        out += *it;
    }
    return out;
}

std::optional<std::string> MsvcDemangler::parse_unqualified_name() {
    const char c = peek();
    if (c == '\0') return std::nullopt;

    // Backreference into the name table.
    if (c >= '0' && c <= '9') {
        eat();
        const std::size_t idx = static_cast<std::size_t>(c - '0');
        if (idx >= name_backrefs_.size()) return std::nullopt;
        return name_backrefs_[idx];
    }

    // Template fragment: `?$<name>@<args...>@@`.
    if (c == '?') {
        eat();
        if (!consume('$')) return std::nullopt;
        return parse_template_after_marker();
    }

    // Literal C identifier terminated by '@'.
    std::string name;
    while (!eof() && peek() != '@') name.push_back(eat());
    if (eof()) return std::nullopt;
    eat();  // consume terminating '@'

    if (name_backrefs_.size() < 10) name_backrefs_.push_back(name);
    return name;
}

std::optional<std::string> MsvcDemangler::parse_template_after_marker() {
    if (++depth_ > kMaxDepth) { --depth_; return std::nullopt; }

    // The template's bookkeeping uses a *fresh* backref table — template
    // arg parsing must not leak names into the outer name table, and the
    // outer name backrefs must not satisfy `0`-`9` references inside the
    // template body. Save and restore on exit.
    std::vector<std::string> saved_names; saved_names.swap(name_backrefs_);
    std::vector<std::string> saved_types; saved_types.swap(type_backrefs_);

    auto restore = [&] {
        saved_names.swap(name_backrefs_);
        saved_types.swap(type_backrefs_);
        --depth_;
    };

    // Template name (a literal identifier).
    std::string name;
    while (!eof() && peek() != '@') name.push_back(eat());
    if (eof() || name.empty()) { restore(); return std::nullopt; }
    eat();  // consume '@' after template name

    // Argument list: each arg is a type, terminated by `@`.
    std::vector<std::string> args;
    while (!eof()) {
        if (peek() == '@') { eat(); break; }
        auto arg = parse_type();
        if (!arg) { restore(); return std::nullopt; }
        args.push_back(std::move(*arg));
    }

    restore();

    std::string out = std::move(name);
    out += '<';
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (i) out += ", ";
        out += args[i];
    }
    if (!out.empty() && out.back() == '>') out += ' ';  // avoid `>>` digraph
    out += '>';

    if (name_backrefs_.size() < 10) name_backrefs_.push_back(out);
    return out;
}

std::optional<std::string> MsvcDemangler::parse_type() {
    if (++depth_ > kMaxDepth) { --depth_; return std::nullopt; }

    auto pop_depth = [&] { --depth_; };

    const char c = eat();
    if (c == '\0') { pop_depth(); return std::nullopt; }

    // Type backreference: digit refers to an earlier-parsed compound type.
    if (c >= '0' && c <= '9') {
        const std::size_t idx = static_cast<std::size_t>(c - '0');
        pop_depth();
        if (idx >= type_backrefs_.size()) return std::nullopt;
        return type_backrefs_[idx];
    }

    // Single-char primitive types.
    if (auto sv = builtin_type(c); !sv.empty()) {
        pop_depth();
        return std::string(sv);
    }

    // Pointer / reference family. Modifier byte structure on x64:
    //   <P/Q/R/S> <E?> <A/B/C/D> <type>
    // P=ptr, Q=const ptr, R=volatile ptr, S=const-volatile ptr,
    // A=ref, B=const ref. The optional E marks ptr64 (always present
    // on x64). The third byte is the CV qualifier of the *target*:
    // A=none, B=const, C=volatile, D=const-volatile.
    if (c == 'P' || c == 'Q' || c == 'R' || c == 'S' ||
        c == 'A' || c == 'B') {
        const bool is_ref = (c == 'A' || c == 'B');
        const bool ptr_const    = (c == 'Q' || c == 'S' || c == 'B');
        const bool ptr_volatile = (c == 'R' || c == 'S');
        consume('E');                          // ptr64 marker (optional)
        const char tgt_cv = eat();
        const bool tgt_const    = (tgt_cv == 'B' || tgt_cv == 'D');
        const bool tgt_volatile = (tgt_cv == 'C' || tgt_cv == 'D');
        auto inner = parse_type();
        pop_depth();
        if (!inner) return std::nullopt;

        std::string out;
        if (tgt_const)    out += "const ";
        if (tgt_volatile) out += "volatile ";
        out += *inner;
        out += is_ref ? '&' : '*';
        if (ptr_const)    out += " const";
        if (ptr_volatile) out += " volatile";

        if (type_backrefs_.size() < 10) type_backrefs_.push_back(out);
        return out;
    }

    // Named user types: T (union), U (struct), V (class), W (enum).
    if (c == 'T' || c == 'U' || c == 'V') {
        auto qn = parse_qualified_name();
        pop_depth();
        if (!qn) return std::nullopt;
        if (type_backrefs_.size() < 10) type_backrefs_.push_back(*qn);
        return qn;
    }
    if (c == 'W') {
        // Enum: one byte indicating underlying type follows, then the
        // qualified name. We don't render the underlying type — caller
        // gets `EnumName`.
        if (eof()) return std::nullopt;
        eat();   // underlying-type code (e.g. '4' = int)
        auto qn = parse_qualified_name();
        pop_depth();
        if (!qn) return std::nullopt;
        if (type_backrefs_.size() < 10) type_backrefs_.push_back(*qn);
        return qn;
    }

    // Two-character primitive (`_<c>`) or extension marker.
    if (c == '_') {
        const char c2 = eat();
        if (auto sv = builtin_type2(c2); !sv.empty()) {
            pop_depth();
            return std::string(sv);
        }
        pop_depth();
        return std::nullopt;
    }

    // Anything else we don't model — bail so the caller falls back to
    // the raw mangled string.
    pop_depth();
    return std::nullopt;
}

}  // namespace

std::optional<std::string> demangle_msvc(std::string_view mangled) {
    MsvcDemangler d(mangled);
    auto out = d.run();
    if (!out) return std::nullopt;
    if (out->empty()) return std::nullopt;
    return out;
}

}  // namespace ember
