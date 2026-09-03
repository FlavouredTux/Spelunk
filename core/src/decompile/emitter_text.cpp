// Post-processing passes over rendered pseudo-C text.
#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <format>
#include <map>
#include <optional>
#include <regex>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <ember/common/types.hpp>

#include "emitter_internal.hpp"

namespace ember::emit {

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
    bool in_block_comment = false;
    std::size_t start = 0;
    while (start <= text.size()) {
        std::size_t end = text.find('\n', start);
        if (end == std::string_view::npos) end = text.size();
        std::string_view line = text.substr(start, end - start);
        if (const std::size_t comment = line.find("//");
            comment != std::string_view::npos) {
            line = line.substr(0, comment);
        }
        std::string code;
        code.reserve(line.size());
        for (std::size_t i = 0; i < line.size(); ) {
            if (in_block_comment) {
                const std::size_t close = line.find("*/", i);
                if (close == std::string_view::npos) break;
                in_block_comment = false;
                i = close + 2;
                continue;
            }
            const std::size_t open = line.find("/*", i);
            if (open == std::string_view::npos) {
                code.append(line.substr(i));
                break;
            }
            code.append(line.substr(i, open - i));
            in_block_comment = true;
            i = open + 2;
        }
        if (text_contains_identifier(code, name)) return true;
        if (end == text.size()) break;
        start = end + 1;
    }
    return false;
}

bool line_declares_identifier(std::string_view line,
                                            std::string_view name) noexcept {
    line = trim_line_view(line);
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

bool text_declares_identifier(std::string_view text,
                                            std::string_view name) noexcept {
    std::size_t start = 0;
    while (start <= text.size()) {
        std::size_t end = text.find('\n', start);
        if (end == std::string_view::npos) end = text.size();
        if (line_declares_identifier(text.substr(start, end - start), name)) {
            return true;
        }
        if (end == text.size()) break;
        start = end + 1;
    }
    return false;
}

std::string replace_identifier(std::string_view text,
                                             std::string_view old_name,
                                             std::string_view new_name) {
    std::string out;
    out.reserve(text.size());
    std::size_t cursor = 0;
    while (cursor < text.size()) {
        const std::size_t pos = text.find(old_name, cursor);
        if (pos == std::string_view::npos) {
            out.append(text.substr(cursor));
            break;
        }
        const std::size_t end = pos + old_name.size();
        const bool left_ok = pos == 0 || !c_ident_char(text[pos - 1]);
        const bool right_ok = end == text.size() || !c_ident_char(text[end]);
        out.append(text.substr(cursor, pos - cursor));
        if (left_ok && right_ok) {
            out.append(new_name);
        } else {
            out.append(old_name);
        }
        cursor = end;
    }
    return out;
}

std::string rename_ppc_temporaries(std::string text) {
    struct Rename {
        std::string old_name;
        std::string new_name;
    };
    std::vector<Rename> renames;
    std::map<std::string, u32> next_suffix;
    std::vector<std::string> temporary_names;
    std::set<std::string> seen_temporaries;
    for (std::size_t i = 0; i + 1 < text.size(); ++i) {
        if (text[i] != 't' ||
            !std::isdigit(static_cast<unsigned char>(text[i + 1])) ||
            (i != 0 && c_ident_char(text[i - 1]))) {
            continue;
        }
        std::size_t name_end = i + 2;
        while (name_end < text.size() && std::isdigit(
                   static_cast<unsigned char>(text[name_end]))) {
            ++name_end;
        }
        if (name_end < text.size() && c_ident_char(text[name_end])) continue;
        std::string name = text.substr(i, name_end - i);
        if (seen_temporaries.insert(name).second) {
            temporary_names.push_back(std::move(name));
        }
        i = name_end - 1;
    }

    for (const std::string& old_name : temporary_names) {
        std::string_view declared_type;
        std::size_t start = 0;
        while (start <= text.size()) {
            std::size_t end = text.find('\n', start);
            if (end == std::string::npos) end = text.size();
            const std::string_view line = std::string_view(text).substr(
                start, end - start);
            if (line_declares_identifier(line, old_name)) {
                const std::size_t declared_at = line.find(old_name);
                declared_type = trim_line_view(line.substr(0, declared_at));
                break;
            }
            if (end == text.size()) break;
            start = end + 1;
        }

        const auto used_on_line_with = [&](std::string_view needle) {
            std::size_t line_start = 0;
            while (line_start <= text.size()) {
                std::size_t line_end = text.find('\n', line_start);
                if (line_end == std::string::npos) line_end = text.size();
                const std::string_view line = std::string_view(text).substr(
                    line_start, line_end - line_start);
                if (!line_declares_identifier(line, old_name) &&
                    text_contains_identifier(line, old_name) &&
                    line.find(needle) != std::string_view::npos) {
                    return true;
                }
                if (line_end == text.size()) break;
                line_start = line_end + 1;
            }
            return false;
        };

        std::string base = "value";
        if (declared_type.find("PpcState") != std::string_view::npos) {
            base = "state";
        } else if (declared_type.find("PpcObject") != std::string_view::npos) {
            base = "object";
        } else if (declared_type.find('*') != std::string_view::npos) {
            base = "data";
        } else if (declared_type.find("bool") != std::string_view::npos) {
            base = "flag";
        } else if (declared_type.find("float") != std::string_view::npos ||
                   declared_type.find("double") != std::string_view::npos) {
            base = used_on_line_with(" * ") ? "scale" : "scalar";
        } else if (declared_type.find("uint8_t") != std::string_view::npos ||
                   declared_type.find("int8_t") != std::string_view::npos) {
            base = "byte_value";
        } else if (declared_type.find("uint16_t") != std::string_view::npos ||
                   declared_type.find("int16_t") != std::string_view::npos) {
            base = "halfword";
        } else if (used_on_line_with("SetMessage") ||
                   used_on_line_with("Msg(")) {
            base = "message_id";
        } else if (used_on_line_with(" & ")) {
            base = "flags";
        }

        u32& suffix = next_suffix[base];
        std::string candidate;
        do {
            ++suffix;
            candidate = suffix == 1
                ? base
                : std::format("{}_{}", base, suffix);
        } while (text_contains_identifier(text, candidate));
        renames.push_back({old_name, std::move(candidate)});
    }

    for (const Rename& rename : renames) {
        text = replace_identifier(text, rename.old_name, rename.new_name);
    }
    return text;
}

std::string fix_ppc_offset_pointer_declarations(std::string text) {
    std::size_t start = 0;
    while (start < text.size()) {
        std::size_t end = text.find('\n', start);
        if (end == std::string::npos) end = text.size();
        std::string_view line(text.data() + start, end - start);
        const std::size_t type = line.find("void* ");
        const std::size_t equals = line.find(" = ");
        if (type != std::string_view::npos && equals != std::string_view::npos &&
            type < equals) {
            const std::string_view initializer = line.substr(equals + 3);
            const bool scaled_integer =
                (initializer.find(" << ") != std::string_view::npos ||
                 initializer.find(" >> ") != std::string_view::npos) &&
                (initializer.find(" & ") != std::string_view::npos ||
                 initializer.find(" | ") != std::string_view::npos);
            if (scaled_integer) {
                text.replace(start + type, 5, "uint32_t");
                const std::size_t growth = std::string_view("uint32_t").size() - 5;
                end += growth;
            }
        }
        if (end == text.size()) break;
        start = end + 1;
    }
    return text;
}

std::size_t count_untyped_pointer_index_sites(
    const std::string& text) {
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

std::string compact_ppc_type_names(std::string text) {
    static constexpr std::array<std::string_view, 3> families{
        "PpcGlobalState", "PpcObject", "PpcState"
    };
    std::map<std::string, std::vector<std::pair<u32, std::string>>> declarations;
    std::vector<std::pair<std::string, std::string>> renames;
    std::size_t start = 0;
    while (start <= text.size()) {
        std::size_t end = text.find('\n', start);
        if (end == std::string::npos) end = text.size();
        const std::string_view line = std::string_view(text).substr(
            start, end - start);
        constexpr std::string_view prefix = "typedef union ";
        if (line.starts_with(prefix)) {
            const std::string_view declared = line.substr(prefix.size());
            for (std::string_view family : families) {
                if (!declared.starts_with(family)) continue;
                std::size_t name_size = family.size();
                while (name_size < declared.size() && std::isdigit(
                           static_cast<unsigned char>(declared[name_size]))) {
                    ++name_size;
                }
                const std::string old_name(declared.substr(0, name_size));
                u32 suffix = 0;
                if (name_size > family.size()) {
                    const std::string_view raw = declared.substr(
                        family.size(), name_size - family.size());
                    (void)std::from_chars(raw.data(), raw.data() + raw.size(), suffix);
                }
                auto& names = declarations[std::string(family)];
                if (std::ranges::none_of(names, [&](const auto& item) {
                        return item.second == old_name;
                    })) names.emplace_back(suffix, old_name);
                break;
            }
        }
        if (end == text.size()) break;
        start = end + 1;
    }
    for (auto& [family, names] : declarations) {
        std::ranges::sort(names, [](const auto& lhs, const auto& rhs) {
            return lhs.first < rhs.first ||
                   (lhs.first == rhs.first && lhs.second < rhs.second);
        });
        for (std::size_t i = 0; i < names.size(); ++i) {
            const std::string new_name = i == 0
                ? family : std::format("{}{}", family, i + 1);
            if (names[i].second != new_name) {
                renames.emplace_back(names[i].second, new_name);
            }
        }
    }
    std::vector<std::pair<std::string, std::string>> staged;
    staged.reserve(renames.size());
    for (std::size_t i = 0; i < renames.size(); ++i) {
        std::string temporary = std::format("__ember_ppc_type_{}__", i);
        text = replace_identifier(text, renames[i].first, temporary);
        staged.emplace_back(std::move(temporary), renames[i].second);
    }
    for (const auto& [temporary, new_name] : staged) {
        text = replace_identifier(text, temporary, new_name);
    }
    return text;
}

std::string collapse_ppc_field_copy_runs(const std::string& text) {
    struct CopyLine {
        std::string indent;
        std::string destination;
        std::string source;
        i64 destination_offset = 0;
        i64 source_offset = 0;
        i64 width = 0;
    };
    const std::regex copy_pattern(
        R"(^(\s*)(?:\*\([^)]*\)&)?([A-Za-z_][A-Za-z0-9_]*)->(byte|half|word|qword|float|double)_([0-9a-fA-F]+) = (?:\*\([^)]*\)&)?([A-Za-z_][A-Za-z0-9_]*)->(byte|half|word|qword|float|double)_([0-9a-fA-F]+);$)");
    const auto width_for = [](std::string_view prefix) -> i64 {
        if (prefix == "byte") return 1;
        if (prefix == "half") return 2;
        if (prefix == "qword" || prefix == "double") return 8;
        return 4;
    };
    const auto parse = [&](const std::string& line) -> std::optional<CopyLine> {
        std::smatch match;
        if (!std::regex_match(line, match, copy_pattern)) return std::nullopt;
        CopyLine copy;
        copy.indent = match[1].str();
        copy.destination = match[2].str();
        copy.source = match[5].str();
        copy.width = width_for(match[3].str());
        const std::string destination_offset = match[4].str();
        const std::string source_offset = match[7].str();
        auto destination_result = std::from_chars(
            destination_offset.data(),
            destination_offset.data() + destination_offset.size(),
            copy.destination_offset, 16);
        auto source_result = std::from_chars(
            source_offset.data(), source_offset.data() + source_offset.size(),
            copy.source_offset, 16);
        if (destination_result.ec != std::errc{} ||
            source_result.ec != std::errc{}) return std::nullopt;
        return copy;
    };

    std::vector<std::string> lines;
    std::size_t start = 0;
    while (start < text.size()) {
        std::size_t end = text.find('\n', start);
        if (end == std::string::npos) end = text.size();
        lines.push_back(text.substr(start, end - start));
        if (end == text.size()) break;
        start = end + 1;
    }
    std::vector<std::string> output;
    for (std::size_t i = 0; i < lines.size();) {
        auto first = parse(lines[i]);
        if (!first) {
            output.push_back(std::move(lines[i++]));
            continue;
        }
        std::size_t end = i + 1;
        i64 destination_end = first->destination_offset + first->width;
        i64 source_end = first->source_offset + first->width;
        while (end < lines.size()) {
            auto next = parse(lines[end]);
            if (!next || next->indent != first->indent ||
                next->destination != first->destination ||
                next->source != first->source ||
                next->destination_offset != destination_end ||
                next->source_offset != source_end) break;
            destination_end += next->width;
            source_end += next->width;
            ++end;
        }
        if (end - i < 4) {
            output.push_back(std::move(lines[i++]));
            continue;
        }
        const i64 bytes = destination_end - first->destination_offset;
        std::string destination = first->destination;
        std::string source = first->source;
        if (first->destination_offset > 0) {
            destination = std::format("(uint8_t*){} + {:#x}", destination,
                                      static_cast<u64>(first->destination_offset));
        }
        if (first->source_offset > 0) {
            source = std::format("(uint8_t*){} + {:#x}", source,
                                 static_cast<u64>(first->source_offset));
        }
        output.push_back(std::format("{}memcpy({}, {}, {:#x});",
                                     first->indent, destination,
                                     source, static_cast<u64>(bytes)));
        i = end;
    }
    std::string collapsed;
    for (std::size_t i = 0; i < output.size(); ++i) {
        collapsed += output[i];
        if (i + 1 < output.size() || text.ends_with('\n')) collapsed += '\n';
    }
    return collapsed;
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

}  // namespace ember::emit
