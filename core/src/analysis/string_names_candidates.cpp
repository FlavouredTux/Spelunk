// Pure function-name candidate parsing and sanitization helpers.

#include <cctype>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <ember/analysis/demangle.hpp>

#include "string_names_internal.hpp"

namespace ember::string_names {

namespace {

[[nodiscard]] bool good_name(std::string_view s) noexcept {
    if (s.size() < 4 || s.size() > 192) return false;
    if (s.starts_with("sub_")) return false;
    bool has_alpha = false;
    for (char c : s) {
        const auto u = static_cast<unsigned char>(c);
        if (std::isalpha(u)) has_alpha = true;
        if (!(std::isalnum(u) || c == '_' || c == ':' || c == '[' || c == ']' ||
              c == '-' || c == '+' || c == ' ')) {
            return false;
        }
    }
    return has_alpha;
}

[[nodiscard]] bool
demangled_name_needs_itanium_special_fallback(std::string_view name) noexcept {
    if (name.find("::~") != std::string_view::npos) return true;
    const auto last = name.rfind("::");
    if (last == std::string_view::npos || last + 2 >= name.size()) return false;
    const auto prev = name.rfind("::", last == 0 ? 0 : last - 1);
    const auto owner_start = prev == std::string_view::npos ? 0 : prev + 2;
    const auto owner = name.substr(owner_start, last - owner_start);
    const auto leaf = name.substr(last + 2);
    return !owner.empty() && owner == leaf;
}

[[nodiscard]] bool is_known_c_type_token(std::string_view tok) noexcept {
    return tok == "void" || tok == "bool" || tok == "char" ||
           tok == "short" || tok == "int" || tok == "long" ||
           tok == "float" || tok == "double" || tok == "size_t" ||
           tok == "ssize_t" || tok == "auto" || tok == "static" ||
           tok == "const" || tok == "volatile" || tok == "signed" ||
           tok == "unsigned" || tok == "struct" || tok == "class" ||
           tok == "enum" || tok == "BOOL" || tok == "id" ||
           tok.starts_with("uint") || tok.starts_with("int");
}

[[nodiscard]] std::optional<std::string>
reflection_owner_component(std::string_view enc) {
    std::vector<std::string> parts;
    if (!enc.empty() && enc.front() == 'N') {
        std::size_t pos = 1;
        while (pos < enc.size() && enc[pos] != 'E') {
            if (enc.substr(pos).starts_with("S_")) {
                pos += 2;
                continue;
            }
            if (!std::isdigit(static_cast<unsigned char>(enc[pos]))) break;
            std::size_t len = 0;
            while (pos < enc.size() && std::isdigit(static_cast<unsigned char>(enc[pos]))) {
                len = len * 10 + static_cast<std::size_t>(enc[pos] - '0');
                ++pos;
                if (len > 256) return std::nullopt;
            }
            if (len == 0 || pos + len > enc.size()) return std::nullopt;
            parts.emplace_back(enc.substr(pos, len));
            pos += len;
        }
    } else if (!enc.empty() &&
               std::isdigit(static_cast<unsigned char>(enc.front()))) {
        std::size_t pos = 0;
        std::size_t len = 0;
        while (pos < enc.size() && std::isdigit(static_cast<unsigned char>(enc[pos]))) {
            len = len * 10 + static_cast<std::size_t>(enc[pos] - '0');
            ++pos;
            if (len > 256) return std::nullopt;
        }
        if (len == 0 || pos + len > enc.size()) return std::nullopt;
        parts.emplace_back(enc.substr(pos, len));
    }
    if (parts.empty()) return std::nullopt;
    auto owner = sanitize_name(parts.back());
    if (owner.empty()) return std::nullopt;
    return owner;
}

[[nodiscard]] std::string reflection_descriptor_arity(std::string_view text) {
    if (const auto a = text.rfind("ELi"); a != std::string_view::npos) {
        std::size_t pos = a + 3;
        std::size_t end = pos;
        while (end < text.size() &&
               std::isdigit(static_cast<unsigned char>(text[end]))) {
            ++end;
        }
        if (end > pos && end < text.size() && text[end] == 'E') {
            return std::string{text.substr(pos, end - pos)};
        }
    }
    return "n";
}

}  // namespace

std::optional<ReflectionDescriptorNameParts>
parse_reflection_descriptor_name_parts(std::string_view text) {
    struct Marker {
        std::string_view token;
        std::string_view tag;
        bool include_arity;
    };
    for (const auto& marker : {
        Marker{"BoundYieldFuncDescI", "yield_func", true},
        Marker{"CustomBoundFuncDescI", "bound_func", true},
        Marker{"BoundFuncDescI", "bound_func", true},
        Marker{"RemoteEventDescI", "remote_event", false},
        Marker{"EventDescI", "event", false},
        Marker{"EnumPropDescriptorI", "enum_property", false},
        Marker{"RefPropDescriptorI", "ref_property", false},
        Marker{"PropDescriptorI", "property", false},
        Marker{"TypedPropertyDescriptorI", "typed_property", false},
        Marker{"EnumDescI", "enum", false},
        Marker{"TTypeI", "type", false},
    }) {
        const auto p = text.find(marker.token);
        if (p == std::string_view::npos) continue;
        auto owner = reflection_owner_component(text.substr(p + marker.token.size()));
        if (!owner) continue;
        return ReflectionDescriptorNameParts{
            .owner = std::move(*owner),
            .marker = marker.token,
            .tag = marker.tag,
            .arity = marker.include_arity ? reflection_descriptor_arity(text) : "",
            .include_arity = marker.include_arity,
        };
    }
    return std::nullopt;
}

std::optional<std::string>
reflection_descriptor_candidate_name(const ReflectionDescriptorNameParts& parts,
                                     std::optional<std::string_view> member) {
    std::string name = "reflection_" + parts.owner + "_";
    if (member && !member->empty()) {
        name += std::string{*member} + "_";
    }
    name += std::string{parts.tag};
    if (parts.include_arity) {
        name += "_argc_" + parts.arity;
    }
    if (auto n = sanitize_name(name); !n.empty()) return n;
    return std::nullopt;
}

namespace {

[[nodiscard]] std::optional<std::string>
reflection_bound_descriptor_name(std::string_view text) {
    auto parts = parse_reflection_descriptor_name_parts(text);
    if (!parts) return std::nullopt;
    if (!parts->include_arity) return std::nullopt;
    return reflection_descriptor_candidate_name(*parts, std::nullopt);
}

}  // namespace

bool looks_like_reflection_member_name(std::string_view text) noexcept {
    if (text.size() < 2 || text.size() > 96) return false;
    if (!(std::isalpha(static_cast<unsigned char>(text.front())) ||
          text.front() == '_')) {
        return false;
    }
    if (text.starts_with("__")) return false;
    if (text.find("DescI") != std::string_view::npos ||
        text.find("Reflection") != std::string_view::npos ||
        text.find("::") != std::string_view::npos) {
        return false;
    }

    bool alpha = false;
    for (char c : text) {
        const auto u = static_cast<unsigned char>(c);
        if (std::isalpha(u)) alpha = true;
        if (!(std::isalnum(u) || c == '_')) return false;
    }
    return alpha;
}

std::optional<std::string>
candidate_name_from_string(std::string_view text) {
    // Source-level block names often survive as strings even when the invoke
    // function itself is anonymous, e.g. "-[Cls doIt:]_block_invoke" or
    // "void Ns::Type::method(...)_block_invoke". Keep the suffix so these do
    // not collapse onto the enclosing method's name.
    if (const auto block_pos = text.find("_block_invoke");
        block_pos != std::string_view::npos) {
        std::string_view head = text.substr(0, block_pos);
        if (const auto objc_start = head.rfind("-[");
            objc_start != std::string_view::npos) {
            if (auto n = sanitize_name(head.substr(objc_start)); !n.empty()) {
                n += "_block_invoke";
                return n;
            }
        }
        if (const auto objc_start = head.rfind("+[");
            objc_start != std::string_view::npos) {
            if (auto n = sanitize_name(head.substr(objc_start)); !n.empty()) {
                n += "_block_invoke";
                return n;
            }
        }
        if (const auto scope = head.rfind("::");
            scope != std::string_view::npos) {
            std::size_t start = scope;
            while (start > 0) {
                const char c = head[start - 1];
                if (!(is_ident_char(c) || c == ':')) break;
                --start;
            }
            if (auto n = sanitize_name(head.substr(start)); !n.empty()) {
                n += "_block_invoke";
                return n;
            }
        }
    }

    // ObjC bracket form inside logs: "-[Class selector:]" or "+[Class sel]".
    for (std::size_t i = 0; i + 3 < text.size(); ++i) {
        if ((text[i] != '-' && text[i] != '+') || text[i + 1] != '[') continue;
        const auto end = text.find(']', i + 2);
        if (end == std::string_view::npos || end <= i + 3) continue;
        if (auto n = sanitize_name(text.substr(i, end - i + 1)); !n.empty()) return n;
    }

    if (auto n = reflection_bound_descriptor_name(text)) return n;
    if (auto n = graphics_api_name_from_string(text)) return n;
    if (auto n = graphics_phrase_name_from_string(text)) return n;

    // Itanium encodings embedded inside RTTI / std::function / lambda
    // metadata strings often carry a source function name even after the
    // symbol table is stripped. The common shape is a larger type encoding
    // containing `Z<function-encoding>`, for example
    // `...IZN7Example6Worker3runEvE...`.
    for (std::size_t i = 0; i + 2 < text.size(); ++i) {
        if (text[i] != 'Z') continue;
        if (text[i + 1] != 'N' &&
            text[i + 1] != 'L' &&
            !(i + 2 < text.size() && text[i + 1] == 'Z' && text[i + 2] == 'N') &&
            !(i + 2 < text.size() && text[i + 1] == 'Z' && text[i + 2] == 'L') &&
            !(i + 2 < text.size() && text[i + 1] == 'Z' &&
              std::isdigit(static_cast<unsigned char>(text[i + 2]))) &&
            !std::isdigit(static_cast<unsigned char>(text[i + 1]))) {
            continue;
        }
        std::string mangled = "_";
        mangled += text.substr(i);
        auto demangled = demangle_itanium(mangled);
        if (!demangled) {
            if (auto n = itanium_embedded_function_name_prefix(text.substr(i))) return n;
            continue;
        }
        auto base = strip_signature_suffix(*demangled);
        if (!base.contains("::")) {
            if (auto n = itanium_embedded_function_name_prefix(text.substr(i))) return n;
            continue;
        }
        if (base.starts_with("std::") || base.starts_with("__cxxabiv1::")) {
            if (auto n = itanium_embedded_function_name_prefix(text.substr(i))) return n;
            continue;
        }
        base = normalize_operator_name(base);
        if (demangled_name_needs_itanium_special_fallback(base)) {
            if (auto n = itanium_embedded_function_name_prefix(text.substr(i))) return n;
        }
        if (auto n = sanitize_name(base); !n.empty()) return n;
        if (auto n = itanium_embedded_function_name_prefix(text.substr(i))) return n;
    }

    // C++/namespace-ish tokens from logs: "Core::Player::step failed".
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (!is_ident_char(text[i])) continue;
        std::size_t j = i;
        while (j < text.size() &&
               (is_ident_char(text[j]) ||
                (j + 1 < text.size() && text[j] == ':' &&
                 text[j + 1] == ':'))) {
            if (text[j] == ':') j += 2;
            else ++j;
        }
        const auto tok = text.substr(i, j - i);
        if (tok.find("::") != std::string_view::npos) {
            if (i > 0 && text[i - 1] == '[' &&
                j < text.size() && text[j] == ']') {
                i = j;
                continue;
            }
            if (tok.ends_with("::operator")) {
                if (auto suffix = operator_suffix_token(text, j)) {
                    if (auto n = sanitize_name(std::string(tok) + "_" + *suffix);
                        !n.empty()) {
                        return n;
                    }
                }
            }
            if (tok.ends_with("::") && j < text.size() && text[j] == '~') {
                const std::size_t name_start = j + 1;
                std::size_t name_end = name_start;
                while (name_end < text.size() && is_ident_char(text[name_end])) {
                    ++name_end;
                }
                if (name_end > name_start) {
                    std::string dtor = std::string(tok) + "dtor_" +
                                       std::string(text.substr(name_start,
                                                              name_end - name_start));
                    if (auto n = sanitize_name(dtor); !n.empty()) return n;
                }
            }
            if (auto n = sanitize_name(tok); !n.empty()) return n;
        }
        i = j;
    }

    // C/C++ compiler-provided function strings: `__PRETTY_FUNCTION__`,
    // assertion runtimes, and some logging macros preserve signatures such as
    // "static int recoverCachedValue(int)" even after symbols are stripped.
    if (auto n = c_pretty_function_name(text)) return n;

    // Prefix form: "recover_player_name: bad state" / "recover_player_name failed".
    const auto stop = text.find_first_of(":(");
    if (stop != std::string_view::npos && stop >= 4 && stop <= 80) {
        const auto prefix = text.substr(0, stop);
        bool all_ident = true;
        for (char c : prefix) {
            if (!is_ident_char(c)) { all_ident = false; break; }
        }
        if (all_ident) {
            if (auto n = sanitize_name(prefix); !n.empty()) return n;
        }
    }
    return std::nullopt;
}

bool is_ident_char(char c) noexcept {
    const auto u = static_cast<unsigned char>(c);
    return std::isalnum(u) || c == '_';
}

std::string sanitize_name(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_') {
            out.push_back(c);
        } else if (c == ':' && i + 1 < s.size() && s[i + 1] == ':') {
            out += "::";
            ++i;
        } else if (c == '-' || c == '+' || c == '[' || c == ']' || c == ' ') {
            if (out.empty() || out.back() != '_') out.push_back('_');
        }
    }
    while (!out.empty() && out.front() == '_' &&
           !out.starts_with("_GLOBAL__N_")) {
        out.erase(out.begin());
    }
    while (!out.empty() && out.back() == '_') out.pop_back();
    return good_name(out) ? out : std::string{};
}

std::string_view trim_ascii(std::string_view s) noexcept {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) {
        s.remove_prefix(1);
    }
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) {
        s.remove_suffix(1);
    }
    return s;
}

bool has_c_signature_type_cue(std::string_view prefix) noexcept {
    prefix = trim_ascii(prefix);
    if (prefix.empty()) return false;
    if (prefix.find('*') != std::string_view::npos ||
        prefix.find('&') != std::string_view::npos) {
        return true;
    }
    for (std::size_t i = 0; i < prefix.size();) {
        while (i < prefix.size() && !is_ident_char(prefix[i])) ++i;
        const std::size_t start = i;
        while (i < prefix.size() && is_ident_char(prefix[i])) ++i;
        const std::string_view token{prefix.data() + start, i - start};
        if (!token.empty() && is_known_c_type_token(token)) {
            return true;
        }
    }
    return false;
}

bool is_bad_plain_function_name(std::string_view name) noexcept {
    return name == "if" || name == "for" || name == "while" ||
           name == "switch" || name == "return" || name == "sizeof" ||
           name == "alignof" || name == "static_cast" ||
           name == "reinterpret_cast" || name == "const_cast" ||
           name == "dynamic_cast";
}

}  // namespace ember::string_names
