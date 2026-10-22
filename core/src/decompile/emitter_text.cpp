// Post-processing passes over rendered pseudo-C text.
#include <cctype>
#include <cstddef>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include <spelunk/common/types.hpp>

#include "emitter_text.hpp"

namespace spelunk::emit {

namespace {

struct CodeSpan {
    std::size_t begin;
    std::size_t end;
};

// The emitter produces ordinary C literals (including wide and ObjC strings).
// Keep their escape handling and comment boundaries in one scanner.
std::optional<std::size_t> non_code_end(std::string_view text,
                                        std::size_t start) noexcept {
    if (text.substr(start, 2) == "//") {
        std::size_t end = start + 2;
        while (end < text.size()) {
            if (text[end] == '\n' &&
                (end == 0 || text[end - 1] != '\\')) break;
            ++end;
        }
        return end;
    }
    if (text.substr(start, 2) == "/*") {
        const auto end = text.find("*/", start + 2);
        return end == std::string_view::npos ? text.size() : end + 2;
    }
    std::size_t quote_at = start;
    if (start == 0 || !c_ident_char(text[start - 1])) {
        const auto tail = text.substr(start);
        if (tail.starts_with("u8\"") || tail.starts_with("u8'")) {
            quote_at += 2;
        } else if (tail.size() >= 2 &&
                   (tail[0] == 'L' || tail[0] == 'u' ||
                    tail[0] == 'U' || tail[0] == '@') &&
                   (tail[1] == '"' || tail[1] == '\'')) {
            ++quote_at;
        }
    }
    const char quote = text[quote_at];
    if (quote != '"' && quote != '\'') return std::nullopt;
    std::size_t end = quote_at + 1;
    while (end < text.size()) {
        if (text[end] == '\\') {
            end += end + 1 < text.size() ? 2u : 1u;
        } else if (text[end++] == quote) {
            break;
        }
    }
    return end;
}

std::optional<CodeSpan> next_code_span(std::string_view text,
                                      std::size_t& cursor) noexcept {
    std::size_t begin = cursor;
    while (cursor < text.size()) {
        if (auto end = non_code_end(text, cursor)) {
            const CodeSpan span{begin, cursor};
            cursor = *end;
            if (span.begin != span.end) return span;
            begin = cursor;
        } else {
            ++cursor;
        }
    }
    if (begin != cursor) return CodeSpan{begin, cursor};
    return std::nullopt;
}

}  // namespace

std::optional<std::string_view> incomplete_c_export_reason(std::string_view text) {
    for (std::size_t at = 0; at < text.size();) {
        if (auto end = non_code_end(text, at)) {
            if (text.substr(at, 2) == "//" || text.substr(at, 2) == "/*") {
                const auto comment = text.substr(at, *end - at);
                for (std::string_view marker : {
                         "STRUCTURER_FAIL", "unresolved expression materialization",
                         "unresolved SSA merge", "stray call.args", "unresolved register read",
                         "unresolved record type", "unresolved intrinsic",
                         "unresolved string operation", "unresolved call signature"}) {
                    if (comment.find(marker) != std::string_view::npos) return marker;
                }
            }
            at = *end;
        } else {
            if (text.substr(at).starts_with("#error")) return "unsupported C export operation";
            ++at;
        }
    }
    return std::nullopt;
}

std::string code_only_text(std::string_view text) {
    std::string code(text.size(), ' ');
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '\n' || text[i] == '\r') code[i] = text[i];
    }
    std::size_t cursor = 0;
    while (auto span = next_code_span(text, cursor)) {
        code.replace(span->begin, span->end - span->begin,
                     text.substr(span->begin, span->end - span->begin));
    }
    return code;
}


std::string_view trim_line_view(std::string_view line) noexcept {
    while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) {
        line.remove_prefix(1);
    }
    while (!line.empty() && (line.back() == ' ' || line.back() == '\t' ||
                             line.back() == '\r')) {
        line.remove_suffix(1);
    }
    return line;
}

bool is_bb_label_line(std::string_view line) noexcept {
    line = trim_line_view(line);
    if (!line.starts_with("// bb_")) return false;
    auto rest = line.substr(6);
    if (rest.empty()) return false;
    for (char c : rest) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

bool line_semantically_empty(std::string_view line) noexcept {
    line = trim_line_view(line);
    return line.empty() || is_bb_label_line(line);
}

bool c_ident_char(char c) noexcept {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
}

bool text_contains_identifier(std::string_view text,
                                            std::string_view name) noexcept {
    if (name.empty()) return false;
    std::size_t pos = 0;
    while ((pos = text.find(name, pos)) != std::string_view::npos) {
        const bool left_ok = pos == 0 || !c_ident_char(text[pos - 1]);
        const std::size_t end = pos + name.size();
        const bool right_ok = end >= text.size() || !c_ident_char(text[end]);
        if (left_ok && right_ok) return true;
        pos = end;
    }
    return false;
}

bool text_contains_identifier_in_code(std::string_view text,
                                      std::string_view name) noexcept {
    if (name.empty()) return false;
    std::size_t cursor = 0;
    while (auto span = next_code_span(text, cursor)) {
        if (text_contains_identifier(
                text.substr(span->begin, span->end - span->begin), name)) {
            return true;
        }
    }
    return false;
}

namespace {

bool code_line_declares_identifier(std::string_view line,
                                   std::string_view name) noexcept {
    if (name.empty()) return false;
    line = trim_line_view(line);
    if (line.starts_with("return ") || line.starts_with("goto ")) return false;
    std::size_t pos = line.find(name);
    while (pos != std::string_view::npos) {
        const std::size_t end = pos + name.size();
        const bool boundary =
            pos > 0 && std::isspace(static_cast<unsigned char>(line[pos - 1])) &&
            (end == line.size() || !c_ident_char(line[end]));
        if (boundary) {
            std::string_view before = trim_line_view(line.substr(0, pos));
            std::string_view after = trim_line_view(line.substr(end));
            const bool declarator_tail = after.empty() || after.front() == '=' ||
                after.front() == ';' || after.front() == '[';
            if (!before.empty() && declarator_tail &&
                before.find('(') == std::string_view::npos &&
                before.find("->") == std::string_view::npos) {
                return true;
            }
        }
        pos = line.find(name, end);
    }
    return false;
}

}  // namespace

bool line_declares_identifier(std::string_view line, std::string_view name) {
    return code_line_declares_identifier(code_only_text(line), name);
}

bool text_declares_identifier(std::string_view text,
                              std::string_view name) {
    const std::string code = code_only_text(text);
    std::size_t start = 0;
    while (start <= text.size()) {
        std::size_t end = text.find('\n', start);
        if (end == std::string_view::npos) end = text.size();
        if (code_line_declares_identifier(
                std::string_view(code).substr(start, end - start), name)) {
            return true;
        }
        if (end == text.size()) break;
        start = end + 1;
    }
    return false;
}

std::unordered_set<std::string> declared_identifiers(std::string_view text) {
    // One pass of code_line_declares_identifier's rule over every token: an
    // identifier after whitespace and a type, before `=`, `;`, `[` or the end.
    std::unordered_set<std::string> declared;
    const std::string code = code_only_text(text);
    std::size_t start = 0;
    while (start <= code.size()) {
        std::size_t end = code.find('\n', start);
        if (end == std::string::npos) end = code.size();
        const std::string_view line = trim_line_view(std::string_view(code).substr(start, end - start));
        if (!line.starts_with("return ") && !line.starts_with("goto ")) {
            for (std::size_t pos = 1; pos < line.size(); ++pos) {
                if (!c_ident_char(line[pos]) ||
                    !std::isspace(static_cast<unsigned char>(line[pos - 1]))) continue;
                std::size_t token_end = pos;
                while (token_end < line.size() && c_ident_char(line[token_end])) ++token_end;
                const std::string_view before = trim_line_view(line.substr(0, pos));
                const std::string_view after = trim_line_view(line.substr(token_end));
                if (!before.empty() &&
                    (after.empty() || after.front() == '=' || after.front() == ';' ||
                     after.front() == '[') &&
                    before.find('(') == std::string_view::npos &&
                    before.find("->") == std::string_view::npos) {
                    declared.emplace(line.substr(pos, token_end - pos));
                }
                pos = token_end;
            }
        }
        if (end == code.size()) break;
        start = end + 1;
    }
    return declared;
}

std::string replace_identifier(std::string_view text,
                               std::string_view old_name,
                               std::string_view new_name) {
    if (old_name.empty()) return std::string(text);
    std::string out;
    out.reserve(text.size());
    std::size_t cursor = 0;
    std::size_t copied = 0;
    while (auto span = next_code_span(text, cursor)) {
        std::size_t pos = span->begin;
        while ((pos = text.find(old_name, pos)) != std::string_view::npos &&
               pos < span->end) {
            const std::size_t end = pos + old_name.size();
            const bool left_ok = pos == span->begin || !c_ident_char(text[pos - 1]);
            const bool right_ok = end == span->end ||
                (end < span->end && !c_ident_char(text[end]));
            if (left_ok && right_ok) {
                out.append(text.substr(copied, pos - copied));
                out.append(new_name);
                copied = end;
            }
            pos = end;
        }
    }
    out.append(text.substr(copied));
    return out;
}

std::size_t count_untyped_pointer_index_sites(
    const std::string& source) {
    const std::string text = code_only_text(source);
    std::vector<std::string> untyped_names;
    const auto is_ident_char = [](char c) {
        const auto uc = static_cast<unsigned char>(c);
        return std::isalnum(uc) || c == '_';
    };
    const auto scan_line = [&](std::string_view line) {
        std::size_t pos = 0;
        while ((pos = line.find("void*", pos)) != std::string_view::npos) {
            pos += 5;
            if (pos < line.size() && line[pos] == '*') continue;  // void**: indexable
            while (pos < line.size() && line[pos] == ' ') ++pos;
            const std::size_t start = pos;
            while (pos < line.size() && is_ident_char(line[pos])) ++pos;
            if (pos > start) {
                untyped_names.emplace_back(line.substr(start, pos - start));
            }
        }
    };

    std::size_t sites = 0;
    std::size_t start = 0;
    while (start <= text.size()) {
        std::size_t end = text.find('\n', start);
        if (end == std::string::npos) end = text.size();
        const std::string_view line(text.data() + start, end - start);
        const std::string_view trimmed = trim_line_view(line);
        if (trimmed.starts_with("//")) {
            if (end == text.size()) break;
            start = end + 1;
            continue;
        }
        scan_line(trimmed);
        for (const std::string& name : untyped_names) {
            std::size_t hit = 0;
            while ((hit = trimmed.find(name, hit)) != std::string_view::npos) {
                const std::size_t after = hit + name.size();
                const bool whole = (hit == 0 || !is_ident_char(trimmed[hit - 1])) &&
                                   (after >= trimmed.size() ||
                                    !is_ident_char(trimmed[after]));
                if (whole && after < trimmed.size()) {
                    std::size_t bracket = after;
                    while (bracket < trimmed.size() &&
                           trimmed[bracket] == ' ') ++bracket;
                    // Skip the name's own declarator (`void* name[N];` is
                    // a valid array of void*); anything else indexing
                    // through the untyped pointer counts once per line.
                    const bool own_declarator =
                        bracket != after && hit >= 6 &&
                        trimmed.substr(0, 5) == "void*" &&
                        trimmed.substr(5, hit - 5).find_first_not_of(' ') ==
                            std::string_view::npos;
                    if (bracket < trimmed.size() && trimmed[bracket] == '[' &&
                        !own_declarator) {
                        ++sites;
                        break;
                    }
                }
                hit = after;
            }
        }
        if (end == text.size()) break;
        start = end + 1;
    }
    return sites;
}

bool line_starts_empty_if(std::string_view line) noexcept {
    line = trim_line_view(line);
    return line.starts_with("if (") && line.ends_with("{");
}

std::string lower_first_ascii(std::string s) {
    if (!s.empty()) {
        s.front() = static_cast<char>(
            std::tolower(static_cast<unsigned char>(s.front())));
    }
    return s;
}

std::string sanitize_ident(std::string_view s,
                                         std::string_view fallback) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        const bool ok = (c >= 'A' && c <= 'Z') ||
                        (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') ||
                        c == '_';
        if (ok) out.push_back(c);
    }
    if (out.empty() || (out.front() >= '0' && out.front() <= '9')) {
        out = std::string(fallback);
    }
    return out;
}

std::vector<std::string>
objc_selector_arg_names(std::string_view selector) {
    std::vector<std::string> names;
    std::size_t start = 0;
    while (start < selector.size()) {
        const std::size_t colon = selector.find(':', start);
        if (colon == std::string_view::npos) break;
        std::string piece(selector.substr(start, colon - start));
        if (names.empty()) {
            if (piece.starts_with("set") && piece.size() > 3) {
                piece = lower_first_ascii(piece.substr(3));
            } else if (piece.starts_with("with") && piece.size() > 4) {
                piece = lower_first_ascii(piece.substr(4));
            } else if (auto with = piece.rfind("With");
                       with != std::string::npos && with + 4 < piece.size()) {
                piece = lower_first_ascii(piece.substr(with + 4));
            }
        }
        if (piece.empty()) piece = std::format("arg{}", names.size());
        names.push_back(sanitize_ident(piece, std::format("arg{}", names.size())));
        start = colon + 1;
    }
    return names;
}

std::string objc_block_literal_name(addr_t literal) {
    return std::format("__block_literal_{:x}", static_cast<u64>(literal));
}

std::string objc_block_invoke_name(addr_t invoke) {
    return std::format("__block_invoke_{:x}", static_cast<u64>(invoke));
}

std::string block_param_type(std::string_view ty) {
    if (ty == "block") return "void*";
    return std::string(ty);
}

bool line_is_close_brace(std::string_view line) noexcept {
    return trim_line_view(line) == "}";
}

bool line_is_else_open(std::string_view line) noexcept {
    return trim_line_view(line) == "} else {";
}

std::string strip_outer_parens(std::string_view s) {
    s = trim_line_view(s);
    if (s.size() < 2 || s.front() != '(' || s.back() != ')') {
        return std::string(s);
    }
    int depth = 0;
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '(') {
            ++depth;
        } else if (s[i] == ')') {
            --depth;
            if (depth == 0 && i + 1 != s.size()) return std::string(s);
        }
        if (depth < 0) return std::string(s);
    }
    return std::string(trim_line_view(s.substr(1, s.size() - 2)));
}

std::string invert_condition_text(std::string_view cond) {
    cond = trim_line_view(cond);
    if (cond.starts_with("!") &&
        (cond.size() == 1 || cond[1] != '=')) {
        return strip_outer_parens(cond.substr(1));
    }
    return std::format("!({})", cond);
}

std::optional<std::string>
inverted_if_line(std::string_view line) {
    const std::string_view trimmed = trim_line_view(line);
    if (!trimmed.starts_with("if (") || !trimmed.ends_with("{")) {
        return std::nullopt;
    }
    const std::size_t open = line.find("if (");
    if (open == std::string_view::npos) return std::nullopt;
    const std::size_t close = line.rfind(") {");
    if (close == std::string_view::npos || close < open + 4) {
        return std::nullopt;
    }
    const std::string_view indent = line.substr(0, open);
    const std::string cond = invert_condition_text(
        line.substr(open + 4, close - (open + 4)));
    return std::format("{}if ({}) {{", indent, cond);
}

std::string collapse_empty_then_else_blocks(std::string_view text) {
    std::vector<std::string_view> lines;
    std::size_t start = 0;
    while (start <= text.size()) {
        std::size_t end = text.find('\n', start);
        if (end == std::string_view::npos) end = text.size();
        lines.push_back(text.substr(start, end - start));
        if (end == text.size()) break;
        start = end + 1;
    }

    std::string out;
    out.reserve(text.size());
    for (std::size_t i = 0; i < lines.size(); ++i) {
        if (auto inverted = inverted_if_line(lines[i]); inverted) {
            std::size_t j = i + 1;
            while (j < lines.size() && line_semantically_empty(lines[j])) {
                ++j;
            }
            if (j < lines.size() && line_is_else_open(lines[j])) {
                out += *inverted;
                out += '\n';
                i = j;
                continue;
            }
            if (j + 1 < lines.size() &&
                line_is_close_brace(lines[j]) &&
                line_is_else_open(lines[j + 1])) {
                out += *inverted;
                out += '\n';
                i = j + 1;
                continue;
            }
        }
        if (!lines[i].empty() || i + 1 < lines.size()) {
            out += lines[i];
            out += '\n';
        }
    }
    return out;
}

std::string strip_label_only_if_blocks(std::string_view text) {
    std::vector<std::string_view> lines;
    std::size_t start = 0;
    while (start <= text.size()) {
        std::size_t end = text.find('\n', start);
        if (end == std::string_view::npos) end = text.size();
        lines.push_back(text.substr(start, end - start));
        if (end == text.size()) break;
        start = end + 1;
    }

    std::string out;
    out.reserve(text.size());
    for (std::size_t i = 0; i < lines.size(); ++i) {
        if (line_starts_empty_if(lines[i])) {
            std::size_t j = i + 1;
            while (j < lines.size() && line_semantically_empty(lines[j])) {
                ++j;
            }
            if (j < lines.size() && line_is_close_brace(lines[j])) {
                i = j;
                continue;
            }
        }
        if (!lines[i].empty() || i + 1 < lines.size()) {
            out += lines[i];
            out += '\n';
        }
    }
    return out;
}

}  // namespace spelunk::emit
