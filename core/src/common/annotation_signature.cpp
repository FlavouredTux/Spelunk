#include <spelunk/common/annotations.hpp>

#include <cctype>

namespace spelunk {
namespace {

[[nodiscard]] std::string_view ltrim(std::string_view s) noexcept {
    std::size_t i = 0;
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
    return s.substr(i);
}

[[nodiscard]] std::string_view rtrim(std::string_view s) noexcept {
    std::size_t i = s.size();
    while (i > 0 && (s[i - 1] == ' ' || s[i - 1] == '\t' || s[i - 1] == '\r')) --i;
    return s.substr(0, i);
}

[[nodiscard]] std::string_view trim(std::string_view s) noexcept {
    return rtrim(ltrim(s));
}

[[nodiscard]] bool is_type_keyword(std::string_view s) noexcept {
    return s == "void" || s == "char" || s == "short" || s == "int" ||
           s == "long" || s == "float" || s == "double" ||
           s == "signed" || s == "unsigned" || s == "bool" ||
           s == "size_t" || s == "ssize_t";
}

// Split a parameter `<type> <name>` into the two halves. If the param
// is a single token (or all tokens are type keywords), the name is empty
// and the whole thing is the type.
[[nodiscard]] ParamSig parse_param(std::string_view raw) {
    ParamSig p;
    auto v = trim(raw);
    if (v.empty() || v == "void") return p;
    // Find the last whitespace-separated identifier; if it's a type
    // keyword, treat the whole thing as type.
    std::size_t last_space = v.find_last_of(" \t");
    if (last_space == std::string_view::npos) {
        p.type = std::string(v);
        return p;
    }
    auto candidate = trim(v.substr(last_space + 1));
    if (candidate.empty() || is_type_keyword(candidate)) {
        p.type = std::string(v);
        return p;
    }
    // Identifier check: must start with [_A-Za-z], rest [_A-Za-z0-9].
    auto is_id = [](std::string_view s) {
        if (s.empty()) return false;
        const auto c0 = static_cast<unsigned char>(s[0]);
        if (!(std::isalpha(c0) || c0 == '_')) return false;
        for (std::size_t i = 1; i < s.size(); ++i) {
            const auto c = static_cast<unsigned char>(s[i]);
            if (!(std::isalnum(c) || c == '_')) return false;
        }
        return true;
    };
    if (!is_id(candidate)) {
        p.type = std::string(v);
        return p;
    }
    p.type = std::string(trim(v.substr(0, last_space)));
    p.name = std::string(candidate);
    return p;
}

}  // namespace

[[nodiscard]] std::optional<FunctionSig>
parse_signature(std::string_view src) {
    auto v = trim(src);
    const std::size_t lp = v.find('(');
    const std::size_t rp = v.rfind(')');
    if (lp == std::string_view::npos || rp == std::string_view::npos || rp <= lp) {
        return std::nullopt;
    }
    FunctionSig sig;
    // Header: everything before `(`. Drop the function name (last
    // identifier before the paren) - keep everything else as the return
    // type. `int foo` → return=`int`, `void` → return=`void`.
    std::string_view header = trim(v.substr(0, lp));
    std::size_t hsp = header.find_last_of(" \t");
    if (hsp == std::string_view::npos) {
        // `void(...)` or `int(...)` - just a return type, no fn name.
        sig.return_type = std::string(header);
    } else {
        sig.return_type = std::string(trim(header.substr(0, hsp)));
        if (sig.return_type.empty()) sig.return_type = std::string(header);
    }
    // Params: top-level comma-split; strip outer paren contents.
    std::string_view body = v.substr(lp + 1, rp - lp - 1);
    if (trim(body) == "void") return sig;
    std::size_t depth = 0, prev = 0;
    for (std::size_t i = 0; i <= body.size(); ++i) {
        const char c = (i < body.size()) ? body[i] : ',';
        if      (c == '<' || c == '(') ++depth;
        else if (c == '>' || c == ')') { if (depth) --depth; }
        else if (c == ',' && depth == 0) {
            auto p = trim(body.substr(prev, i - prev));
            if (!p.empty()) sig.params.push_back(parse_param(p));
            prev = i + 1;
        }
    }
    return sig;
}

}  // namespace spelunk
