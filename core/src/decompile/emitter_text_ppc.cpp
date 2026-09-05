// PowerPC naming and field-copy presentation passes.
#include "emitter_text.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <format>
#include <map>
#include <regex>
#include <set>
#include <system_error>
#include <utility>

namespace ember::emit {

std::string rename_ppc_temporaries(std::string text) {
    const std::string code = code_only_text(text);
    struct Rename {
        std::string old_name;
        std::string new_name;
    };
    std::vector<Rename> renames;
    std::map<std::string, u32> next_suffix;
    std::vector<std::string> temporary_names;
    std::set<std::string> seen_temporaries;
    for (std::size_t i = 0; i + 1 < code.size(); ++i) {
        if (code[i] != 't' ||
            !std::isdigit(static_cast<unsigned char>(code[i + 1])) ||
            (i != 0 && c_ident_char(code[i - 1]))) {
            continue;
        }
        std::size_t name_end = i + 2;
        while (name_end < code.size() && std::isdigit(
                   static_cast<unsigned char>(code[name_end]))) {
            ++name_end;
        }
        if (name_end < code.size() && c_ident_char(code[name_end])) continue;
        std::string name = code.substr(i, name_end - i);
        if (seen_temporaries.insert(name).second) {
            temporary_names.push_back(std::move(name));
        }
        i = name_end - 1;
    }

    for (const std::string& old_name : temporary_names) {
        std::string_view declared_type;
        std::size_t start = 0;
        while (start <= code.size()) {
            std::size_t end = code.find('\n', start);
            if (end == std::string::npos) end = code.size();
            const std::string_view line = std::string_view(code).substr(
                start, end - start);
            if (line_declares_identifier(line, old_name)) {
                const std::size_t declared_at = line.find(old_name);
                declared_type = trim_line_view(line.substr(0, declared_at));
                break;
            }
            if (end == code.size()) break;
            start = end + 1;
        }

        const auto used_on_line_with = [&](std::string_view needle) {
            std::size_t line_start = 0;
            while (line_start <= code.size()) {
                std::size_t line_end = code.find('\n', line_start);
                if (line_end == std::string::npos) line_end = code.size();
                const std::string_view line = std::string_view(code).substr(
                    line_start, line_end - line_start);
                if (!line_declares_identifier(line, old_name) &&
                    text_contains_identifier(line, old_name) &&
                    line.find(needle) != std::string_view::npos) {
                    return true;
                }
                if (line_end == code.size()) break;
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
        } while (text_contains_identifier(code, candidate));
        renames.push_back({old_name, std::move(candidate)});
    }

    for (const Rename& rename : renames) {
        text = replace_identifier(text, rename.old_name, rename.new_name);
    }
    return text;
}

std::string fix_ppc_offset_pointer_declarations(std::string text) {
    std::string code = code_only_text(text);
    std::size_t start = 0;
    while (start < text.size()) {
        std::size_t end = text.find('\n', start);
        if (end == std::string::npos) end = text.size();
        std::string_view line(code.data() + start, end - start);
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
                code.replace(start + type, 5, "uint32_t");
                const std::size_t growth = std::string_view("uint32_t").size() - 5;
                end += growth;
            }
        }
        if (end == text.size()) break;
        start = end + 1;
    }
    return text;
}

std::string compact_ppc_type_names(std::string text) {
    const std::string code = code_only_text(text);
    static constexpr std::array<std::string_view, 3> families{
        "PpcGlobalState", "PpcObject", "PpcState"
    };
    std::map<std::string, std::vector<std::pair<u32, std::string>>> declarations;
    std::vector<std::pair<std::string, std::string>> renames;
    std::size_t start = 0;
    while (start <= text.size()) {
        std::size_t end = text.find('\n', start);
        if (end == std::string::npos) end = text.size();
        const std::string_view line = std::string_view(code).substr(
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

}  // namespace ember::emit
