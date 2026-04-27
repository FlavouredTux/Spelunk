#include <ember/script/declarative.hpp>

#include <cctype>
#include <charconv>
#include <cstddef>
#include <format>
#include <fstream>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <ember/analysis/pipeline.hpp>
#include <ember/analysis/strings.hpp>
#include <ember/binary/binary.hpp>

namespace ember::script {

namespace {

// ---------------------------------------------------------------------------
// String helpers (case-insensitive compare, trim, glob)
// ---------------------------------------------------------------------------

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

// Strip a trailing ` # comment`. The `#` must be preceded by whitespace
// AND not be inside a `"..."` quoted span — so values like `note = see
// ticket #42` keep the literal `#42` while `name = foo  # alias` drops
// the comment.
[[nodiscard]] std::string_view strip_trailing_comment(std::string_view line) noexcept {
    bool in_str = false;
    for (std::size_t i = 0; i < line.size(); ++i) {
        const char c = line[i];
        if (c == '"' && (i == 0 || line[i - 1] != '\\')) {
            in_str = !in_str;
        } else if (!in_str && c == '#' && i > 0 &&
                   (line[i - 1] == ' ' || line[i - 1] == '\t')) {
            return line.substr(0, i);
        }
    }
    return line;
}

[[nodiscard]] bool iequals(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        const auto ac = static_cast<unsigned char>(a[i]);
        const auto bc = static_cast<unsigned char>(b[i]);
        if (std::tolower(ac) != std::tolower(bc)) return false;
    }
    return true;
}

[[nodiscard]] bool parse_hex_addr(std::string_view s, addr_t& out) noexcept {
    if (s.starts_with("sub_"))                            s.remove_prefix(4);
    else if (s.starts_with("0x") || s.starts_with("0X"))  s.remove_prefix(2);
    if (s.empty()) return false;
    u64 v = 0;
    auto r = std::from_chars(s.data(), s.data() + s.size(), v, 16);
    if (r.ec != std::errc{} || r.ptr != s.data() + s.size()) return false;
    out = static_cast<addr_t>(v);
    return true;
}

// `*` in `pat` matches any (possibly empty) run of characters; everything
// else is literal. Captures whatever each `*` matched into `caps`.
[[nodiscard]] bool glob_match(std::string_view pat, std::string_view s,
                              std::vector<std::string>& caps) {
    caps.clear();
    std::size_t pi = 0, si = 0;
    std::size_t star_pi = std::string_view::npos;
    std::size_t star_si = 0;
    std::size_t cap_start = 0;
    while (si < s.size()) {
        if (pi < pat.size() && pat[pi] == '*') {
            star_pi = pi++;
            star_si = si;
            cap_start = si;
            caps.emplace_back();
            continue;
        }
        if (pi < pat.size() && pat[pi] == s[si]) {
            ++pi;
            ++si;
            continue;
        }
        if (star_pi != std::string_view::npos) {
            pi = star_pi + 1;
            ++star_si;
            si = star_si;
            caps.back() = std::string(s.substr(cap_start, si - cap_start));
            continue;
        }
        return false;
    }
    while (pi < pat.size() && pat[pi] == '*') {
        if (caps.empty() || caps.back() != std::string(s.substr(cap_start)))
            caps.emplace_back();
        ++pi;
    }
    if (pi != pat.size()) return false;
    if (!caps.empty()) caps.back() = std::string(s.substr(cap_start));
    return true;
}

// `%s`, `%d`, `%x`, `%*` in `pat` capture a non-empty greedy run of
// non-format characters (any %-token treated as a wildcard); other
// characters match literally. Returns the captured groups in order.
// The returned value is nullopt when the pattern doesn't match.
[[nodiscard]] std::optional<std::vector<std::string>>
fmt_capture(std::string_view pat, std::string_view s) {
    std::vector<std::string> caps;
    std::size_t pi = 0, si = 0;
    while (pi < pat.size()) {
        if (pat[pi] == '%' && pi + 1 < pat.size()) {
            const char tok = pat[pi + 1];
            if (tok == 's' || tok == 'd' || tok == 'x' || tok == '*') {
                // Greedy capture up to the next literal pattern character
                // (or end of pattern). We re-scan literals after the %X
                // so multi-token templates like "[HttpClient] %s ok" work.
                pi += 2;
                std::size_t next_lit = pi;
                while (next_lit < pat.size() && pat[next_lit] != '%') ++next_lit;
                std::string_view trailer = pat.substr(pi, next_lit - pi);
                std::size_t end = std::string_view::npos;
                if (trailer.empty()) {
                    end = s.size();
                } else {
                    end = s.find(trailer, si);
                    if (end == std::string_view::npos) return std::nullopt;
                }
                if (end <= si) return std::nullopt;  // empty capture
                caps.emplace_back(s.substr(si, end - si));
                si = end;
                continue;
            }
        }
        if (si >= s.size()) return std::nullopt;
        if (pat[pi] != s[si])  return std::nullopt;
        ++pi;
        ++si;
    }
    if (si != s.size()) return std::nullopt;
    return caps;
}

// Substitute `*` (in glob templates) or `$1..$9` (in string-rename
// templates) with the corresponding capture. `*` consumes captures
// in order; `$N` indexes 1-based.
[[nodiscard]] std::string
expand_template(std::string_view tmpl, std::span<const std::string> caps) {
    std::string out;
    out.reserve(tmpl.size());
    std::size_t star_idx = 0;
    for (std::size_t i = 0; i < tmpl.size(); ++i) {
        const char c = tmpl[i];
        if (c == '*') {
            if (star_idx < caps.size()) out += caps[star_idx++];
            continue;
        }
        if (c == '$' && i + 1 < tmpl.size()
                     && tmpl[i + 1] >= '1' && tmpl[i + 1] <= '9') {
            const std::size_t idx = static_cast<std::size_t>(tmpl[i + 1] - '1');
            if (idx < caps.size()) out += caps[idx];
            ++i;
            continue;
        }
        out += c;
    }
    return out;
}

// ---------------------------------------------------------------------------
// Lexer / parser
// ---------------------------------------------------------------------------

[[nodiscard]] Result<std::string>
unquote(std::string_view s, std::size_t line) {
    if (s.size() < 2 || s.front() != '"' || s.back() != '"') {
        return std::unexpected(Error::invalid_format(std::format(
            "ember: line {}: expected quoted string, got `{}`", line, s)));
    }
    std::string out;
    out.reserve(s.size() - 2);
    for (std::size_t i = 1; i + 1 < s.size(); ++i) {
        if (s[i] == '\\' && i + 2 < s.size()) {
            const char n = s[++i];
            switch (n) {
                case 'n':  out += '\n'; break;
                case 'r':  out += '\r'; break;
                case 't':  out += '\t'; break;
                case '\\': out += '\\'; break;
                case '"':  out += '"';  break;
                default:
                    return std::unexpected(Error::invalid_format(std::format(
                        "ember: line {}: unknown escape `\\{}`", line, n)));
            }
        } else {
            out += s[i];
        }
    }
    return out;
}

// Split `key <sep> value` where sep is `=` or `->`. Quoted strings on
// either side are preserved verbatim (caller decides how to interpret).
struct KvPair {
    std::string lhs;
    std::string rhs;
    bool        arrow = false;  // `->` if true, `=` if false
};

[[nodiscard]] Result<KvPair>
split_kv(std::string_view line, std::size_t lineno) {
    // Skip a leading quoted span so an `=` or `->` inside doesn't
    // confuse the splitter.
    std::size_t i = 0;
    if (line[0] == '"') {
        ++i;
        while (i < line.size() && line[i] != '"') {
            if (line[i] == '\\' && i + 1 < line.size()) i += 2;
            else                                       ++i;
        }
        if (i >= line.size()) {
            return std::unexpected(Error::invalid_format(std::format(
                "ember: line {}: unterminated quoted string", lineno)));
        }
        ++i;  // skip the closing quote
    } else {
        while (i < line.size() && line[i] != '=' && !(i + 1 < line.size() && line[i] == '-' && line[i + 1] == '>')) {
            ++i;
        }
    }

    // Now find the separator from position i onward (allowing whitespace).
    std::size_t sep = i;
    while (sep < line.size() && (line[sep] == ' ' || line[sep] == '\t')) ++sep;
    if (sep >= line.size()) {
        return std::unexpected(Error::invalid_format(std::format(
            "ember: line {}: missing `=` or `->` separator", lineno)));
    }
    bool arrow = false;
    std::size_t after = sep;
    if (line[sep] == '=') {
        after = sep + 1;
    } else if (sep + 1 < line.size() && line[sep] == '-' && line[sep + 1] == '>') {
        arrow = true;
        after = sep + 2;
    } else {
        return std::unexpected(Error::invalid_format(std::format(
            "ember: line {}: missing `=` or `->` separator", lineno)));
    }

    KvPair kv;
    std::string_view lhs_view = trim(line.substr(0, sep));
    std::string_view rhs_view = trim(line.substr(after));
    kv.arrow = arrow;

    if (!lhs_view.empty() && lhs_view.front() == '"') {
        auto u = unquote(lhs_view, lineno);
        if (!u) return std::unexpected(u.error());
        kv.lhs = std::move(*u);
    } else {
        kv.lhs = std::string(lhs_view);
    }
    if (!rhs_view.empty() && rhs_view.front() == '"') {
        auto u = unquote(rhs_view, lineno);
        if (!u) return std::unexpected(u.error());
        kv.rhs = std::move(*u);
    } else {
        kv.rhs = std::string(rhs_view);
    }
    return kv;
}

// ---------------------------------------------------------------------------
// Signature parsing — `<ret> <name>(<params>)` or just `(<params>) -> <ret>`
// ---------------------------------------------------------------------------

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
    // identifier before the paren) — keep everything else as the return
    // type. `int foo` → return=`int`, `void` → return=`void`.
    std::string_view header = trim(v.substr(0, lp));
    std::size_t hsp = header.find_last_of(" \t");
    if (hsp == std::string_view::npos) {
        // `void(...)` or `int(...)` — just a return type, no fn name.
        sig.return_type = std::string(header);
    } else {
        sig.return_type = std::string(trim(header.substr(0, hsp)));
        if (sig.return_type.empty()) sig.return_type = std::string(header);
    }
    // Params: top-level comma-split; strip outer paren contents.
    std::string_view body = v.substr(lp + 1, rp - lp - 1);
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

// ---------------------------------------------------------------------------
// Resolver: name → addr via symbols ∪ existing renames
// ---------------------------------------------------------------------------

[[nodiscard]] std::optional<addr_t>
resolve_to_addr(const Binary& b, const Annotations& ann, std::string_view s) {
    if (addr_t a = 0; parse_hex_addr(s, a)) return a;
    for (const auto& sym : b.symbols()) {
        if (sym.is_import) continue;
        if (sym.name == s) return sym.addr;
    }
    for (const auto& [addr, name] : ann.renames) {
        if (name == s) return addr;
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Apply each directive kind
// ---------------------------------------------------------------------------

void apply_rename(const Directive& d, const Binary& b,
                  Annotations& ann, ApplyStats& st) {
    auto a = resolve_to_addr(b, ann, d.lhs);
    if (!a) {
        st.warnings.push_back(std::format(
            "line {}: [rename] cannot resolve `{}` to an address", d.line, d.lhs));
        return;
    }
    if (d.rhs.empty()) {
        st.warnings.push_back(std::format(
            "line {}: [rename] empty target name", d.line));
        return;
    }
    auto [it, inserted] = ann.renames.try_emplace(*a, d.rhs);
    if (!inserted && it->second != d.rhs) {
        st.warnings.push_back(std::format(
            "line {}: [rename] {:#x} already renamed to `{}`, keeping",
            d.line, *a, it->second));
        return;
    }
    if (inserted) ++st.renames_added;
}

void apply_note(const Directive& d, const Binary& b,
                Annotations& ann, ApplyStats& st) {
    auto a = resolve_to_addr(b, ann, d.lhs);
    if (!a) {
        st.warnings.push_back(std::format(
            "line {}: [note] cannot resolve `{}` to an address", d.line, d.lhs));
        return;
    }
    auto [_, inserted] = ann.notes.try_emplace(*a, d.rhs);
    if (inserted) ++st.notes_added;
}

void apply_signature(const Directive& d, const Binary& b,
                     Annotations& ann, ApplyStats& st) {
    auto a = resolve_to_addr(b, ann, d.lhs);
    if (!a) {
        st.warnings.push_back(std::format(
            "line {}: [signature] cannot resolve `{}` to an address", d.line, d.lhs));
        return;
    }
    auto sig = parse_signature(d.rhs);
    if (!sig) {
        st.warnings.push_back(std::format(
            "line {}: [signature] cannot parse `{}`", d.line, d.rhs));
        return;
    }
    auto [_, inserted] = ann.signatures.try_emplace(*a, std::move(*sig));
    if (inserted) ++st.signatures_added;
}

void apply_pattern_rename(const Directive& d, const Binary& b,
                          Annotations& ann, ApplyStats& st) {
    const auto fns = enumerate_functions(b);
    std::vector<std::string> caps;
    for (const auto& fn : fns) {
        const std::string current = ann.renames.contains(fn.addr)
            ? ann.renames[fn.addr]
            : fn.name;
        if (!glob_match(d.lhs, current, caps)) continue;
        const std::string new_name = expand_template(d.rhs, caps);
        if (new_name.empty()) {
            st.warnings.push_back(std::format(
                "line {}: [pattern-rename] empty rename for `{}`", d.line, current));
            continue;
        }
        if (ann.renames.contains(fn.addr)) continue;     // user/explicit wins
        ann.renames.try_emplace(fn.addr, new_name);
        ++st.pattern_renames_applied;
    }
}

void apply_from_strings(const Directive& d, const Binary& b,
                        Annotations& ann, ApplyStats& st) {
    const auto strings = scan_strings(b);
    for (const auto& s : strings) {
        auto caps = fmt_capture(d.lhs, s.text);
        if (!caps) continue;
        const std::string new_name = expand_template(d.rhs, *caps);
        if (new_name.empty()) {
            st.warnings.push_back(std::format(
                "line {}: [from-strings] empty rename for `{}`", d.line, s.text));
            continue;
        }
        // Each xref instruction is in some function — collect the
        // distinct enclosing entries.
        std::set<addr_t> targets;
        for (addr_t xr : s.xrefs) {
            if (auto cf = containing_function(b, xr)) targets.insert(cf->entry);
        }
        for (addr_t fn : targets) {
            if (ann.renames.contains(fn)) continue;
            ann.renames.try_emplace(fn, new_name);
            ++st.string_renames_applied;
        }
    }
}

}  // namespace

// ===========================================================================
// Public API
// ===========================================================================

Result<std::vector<Directive>> parse(std::string_view text) {
    std::vector<Directive> out;
    std::string_view section;
    std::size_t lineno = 0;
    std::size_t cursor = 0;
    while (cursor <= text.size()) {
        const std::size_t nl = text.find('\n', cursor);
        const std::size_t end = (nl == std::string_view::npos) ? text.size() : nl;
        std::string_view raw = text.substr(cursor, end - cursor);
        cursor = (nl == std::string_view::npos) ? text.size() + 1 : (nl + 1);
        ++lineno;

        std::string_view line = trim(strip_trailing_comment(raw));
        if (line.empty() || line.front() == '#') continue;

        if (line.front() == '[') {
            const auto rb = line.find(']');
            if (rb == std::string_view::npos) {
                return std::unexpected(Error::invalid_format(std::format(
                    "ember: line {}: unterminated section header", lineno)));
            }
            section = trim(line.substr(1, rb - 1));
            continue;
        }
        if (section.empty()) {
            return std::unexpected(Error::invalid_format(std::format(
                "ember: line {}: directive outside any section", lineno)));
        }

        auto kv = split_kv(line, lineno);
        if (!kv) return std::unexpected(kv.error());

        Directive d;
        d.lhs  = std::move(kv->lhs);
        d.rhs  = std::move(kv->rhs);
        d.line = lineno;

        if      (iequals(section, "rename"))         d.kind = Directive::Kind::Rename;
        else if (iequals(section, "note"))           d.kind = Directive::Kind::Note;
        else if (iequals(section, "signature"))      d.kind = Directive::Kind::Signature;
        else if (iequals(section, "pattern-rename")) d.kind = Directive::Kind::PatternRename;
        else if (iequals(section, "from-strings"))   d.kind = Directive::Kind::FromStrings;
        else {
            return std::unexpected(Error::invalid_format(std::format(
                "ember: line {}: unknown section `[{}]`", lineno, section)));
        }

        // Section-specific separator validation: `=` for direct sections,
        // `->` for the two pattern sections.
        const bool wants_arrow =
            d.kind == Directive::Kind::PatternRename ||
            d.kind == Directive::Kind::FromStrings;
        if (kv->arrow && !wants_arrow) {
            return std::unexpected(Error::invalid_format(std::format(
                "ember: line {}: [{}] uses `=`, not `->`", lineno, section)));
        }
        if (!kv->arrow && wants_arrow) {
            return std::unexpected(Error::invalid_format(std::format(
                "ember: line {}: [{}] uses `->`, not `=`", lineno, section)));
        }
        out.push_back(std::move(d));
    }
    return out;
}

Result<std::vector<Directive>>
parse_file(const std::filesystem::path& path) {
    std::ifstream f(path);
    if (!f) {
        return std::unexpected(Error::io(std::format(
            "ember: cannot open '{}'", path.string())));
    }
    std::stringstream buf;
    buf << f.rdbuf();
    return parse(buf.str());
}

ApplyStats apply(std::span<const Directive> directives,
                 const Binary& b, Annotations& ann) {
    ApplyStats st;
    // First pass: direct sections (Rename, Note, Signature). User intent
    // beats anything inferred.
    for (const auto& d : directives) {
        switch (d.kind) {
            case Directive::Kind::Rename:    apply_rename   (d, b, ann, st); break;
            case Directive::Kind::Note:      apply_note     (d, b, ann, st); break;
            case Directive::Kind::Signature: apply_signature(d, b, ann, st); break;
            default: break;
        }
    }
    // Second pass: pattern + from-strings. Only fill addresses without
    // an existing user rename.
    for (const auto& d : directives) {
        switch (d.kind) {
            case Directive::Kind::PatternRename: apply_pattern_rename(d, b, ann, st); break;
            case Directive::Kind::FromStrings:   apply_from_strings  (d, b, ann, st); break;
            default: break;
        }
    }
    return st;
}

Result<ApplyStats> apply_file(const std::filesystem::path& path,
                              const Binary& b, Annotations& ann) {
    auto directives = parse_file(path);
    if (!directives) return std::unexpected(directives.error());
    return apply(*directives, b, ann);
}

}  // namespace ember::script
