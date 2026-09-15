// Function-name extraction from demangled Itanium and operator spellings.

#include <cctype>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "string_names_internal.hpp"

namespace spelunk::string_names {

namespace {

struct OperatorSuffixMatch {
    std::string_view token;
    std::size_t length = 0;
};

[[nodiscard]] std::optional<OperatorSuffixMatch>
operator_suffix_match(std::string_view text, std::size_t pos) {
    struct OpName {
        std::string_view spelling;
        std::string_view token;
    };
    for (const auto& op : {
        OpName{"()", "call"},
        OpName{"[]", "index"},
        OpName{"<=>", "cmp"},
        OpName{"==", "eq"},
        OpName{"!=", "ne"},
        OpName{"<=", "le"},
        OpName{">=", "ge"},
        OpName{"->*", "ptr_member"},
        OpName{"->", "arrow"},
        OpName{"&&", "logical_and"},
        OpName{"||", "logical_or"},
        OpName{"++", "inc"},
        OpName{"--", "dec"},
        OpName{"+=", "plus_assign"},
        OpName{"-=", "minus_assign"},
        OpName{"*=", "mul_assign"},
        OpName{"/=", "div_assign"},
        OpName{"%=", "mod_assign"},
        OpName{"&=", "and_assign"},
        OpName{"|=", "or_assign"},
        OpName{"^=", "xor_assign"},
        OpName{"<<=", "shl_assign"},
        OpName{">>=", "shr_assign"},
        OpName{"<<", "shl"},
        OpName{">>", "shr"},
        OpName{"+", "plus"},
        OpName{"-", "minus"},
        OpName{"*", "mul"},
        OpName{"/", "div"},
        OpName{"%", "mod"},
        OpName{"&", "and"},
        OpName{"|", "or"},
        OpName{"^", "xor"},
        OpName{"~", "bit_not"},
        OpName{"!", "not"},
        OpName{"=", "assign"},
        OpName{"<", "lt"},
        OpName{">", "gt"},
        OpName{",", "comma"},
    }) {
        if (text.substr(pos).starts_with(op.spelling)) {
            return OperatorSuffixMatch{op.token, op.spelling.size()};
        }
    }
    if (text.substr(pos).starts_with(" new[]")) {
        return OperatorSuffixMatch{"new_array", 6};
    }
    if (text.substr(pos).starts_with(" delete[]")) {
        return OperatorSuffixMatch{"delete_array", 9};
    }
    if (text.substr(pos).starts_with(" new")) {
        return OperatorSuffixMatch{"new", 4};
    }
    if (text.substr(pos).starts_with(" delete")) {
        return OperatorSuffixMatch{"delete", 7};
    }
    return std::nullopt;
}

[[nodiscard]] std::string flat_demangled_type_token(std::string_view type) {
    type = trim_ascii(type);
    std::string out;
    out.reserve(type.size() + 8);
    auto underscore = [&] {
        if (!out.empty() && out.back() != '_')
            out.push_back('_');
    };
    auto append_word = [&](std::string_view word) {
        if (word.empty())
            return;
        if (!out.empty() && out.back() != '_')
            out.push_back('_');
        out.append(word);
    };
    for (std::size_t i = 0; i < type.size(); ++i) {
        const char c = type[i];
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_') {
            out.push_back(c);
        } else if (c == ':' && i + 1 < type.size() && type[i + 1] == ':') {
            underscore();
            ++i;
        } else if (c == '*') {
            append_word("ptr");
        } else if (c == '&') {
            if (i + 1 < type.size() && type[i + 1] == '&') {
                append_word("rref");
                ++i;
            } else {
                append_word("ref");
            }
        } else if (c == '[') {
            append_word("array");
            while (i + 1 < type.size() && type[i + 1] != ']')
                ++i;
        } else {
            underscore();
        }
    }
    while (!out.empty() && out.front() == '_')
        out.erase(out.begin());
    while (!out.empty() && out.back() == '_')
        out.pop_back();
    return out;
}

struct ItaniumNameComponent {
    std::string token;
    std::size_t length = 0;
};

[[nodiscard]] std::optional<ItaniumNameComponent> itanium_type_token(std::string_view text);

[[nodiscard]] std::optional<ItaniumNameComponent> itanium_source_name_token(std::string_view text) {
    std::size_t pos = 0;
    if (pos >= text.size() || !std::isdigit(static_cast<unsigned char>(text[pos]))) {
        return std::nullopt;
    }
    std::size_t len = 0;
    while (pos < text.size() && std::isdigit(static_cast<unsigned char>(text[pos]))) {
        len = len * 10 + static_cast<std::size_t>(text[pos] - '0');
        ++pos;
        if (len > 256)
            return std::nullopt;
    }
    if (len == 0 || pos + len > text.size())
        return std::nullopt;
    auto name = text.substr(pos, len);
    for (char c : name) {
        if (!is_ident_char(c))
            return std::nullopt;
    }
    return ItaniumNameComponent{std::string{name}, pos + len};
}

[[nodiscard]] std::optional<ItaniumNameComponent> itanium_nested_type_token(std::string_view text) {
    if (text.empty() || text.front() != 'N')
        return std::nullopt;
    std::size_t pos = 1;
    while (pos < text.size() && (text[pos] == 'K' || text[pos] == 'V' || text[pos] == 'r' ||
                                 text[pos] == 'R' || text[pos] == 'O')) {
        ++pos;
    }
    std::vector<std::string> parts;
    while (pos < text.size() && text[pos] != 'E') {
        auto part = itanium_source_name_token(text.substr(pos));
        if (!part)
            return std::nullopt;
        parts.push_back(std::move(part->token));
        pos += part->length;
        if (pos < text.size() && text[pos] == 'I') {
            int depth = 1;
            ++pos;
            while (pos < text.size() && depth > 0) {
                if (text[pos] == 'I')
                    ++depth;
                else if (text[pos] == 'E')
                    --depth;
                ++pos;
            }
            if (depth != 0)
                return std::nullopt;
        }
    }
    if (pos >= text.size() || text[pos] != 'E' || parts.empty()) {
        return std::nullopt;
    }
    std::string token;
    for (const auto &part : parts) {
        if (!token.empty())
            token += '_';
        token += part;
    }
    return ItaniumNameComponent{std::move(token), pos + 1};
}

[[nodiscard]] std::optional<ItaniumNameComponent> itanium_type_token(std::string_view text) {
    if (text.empty())
        return std::nullopt;
    const char c = text.front();
    if (c == 'K' || c == 'V' || c == 'r') {
        auto inner = itanium_type_token(text.substr(1));
        if (!inner)
            return std::nullopt;
        if (c == 'K')
            inner->token = "const_" + inner->token;
        else if (c == 'V')
            inner->token = "volatile_" + inner->token;
        else
            inner->token = "restrict_" + inner->token;
        ++inner->length;
        return inner;
    }
    if (c == 'P' || c == 'R' || c == 'O') {
        auto inner = itanium_type_token(text.substr(1));
        if (!inner)
            return std::nullopt;
        inner->token += c == 'P' ? "_ptr" : c == 'R' ? "_ref" : "_rref";
        ++inner->length;
        return inner;
    }
    if (c == 'N')
        return itanium_nested_type_token(text);
    if (std::isdigit(static_cast<unsigned char>(c))) {
        return itanium_source_name_token(text);
    }
    struct Builtin {
        char code;
        std::string_view token;
    };
    for (const auto &b : {
             Builtin{'v', "void"},
             Builtin{'b', "bool"},
             Builtin{'c', "char"},
             Builtin{'a', "schar"},
             Builtin{'h', "uchar"},
             Builtin{'s', "short"},
             Builtin{'t', "ushort"},
             Builtin{'i', "int"},
             Builtin{'j', "uint"},
             Builtin{'l', "long"},
             Builtin{'m', "ulong"},
             Builtin{'x', "long_long"},
             Builtin{'y', "ulong_long"},
             Builtin{'f', "float"},
             Builtin{'d', "double"},
             Builtin{'e', "long_double"},
             Builtin{'g', "float128"},
             Builtin{'z', "ellipsis"},
         }) {
        if (c == b.code)
            return ItaniumNameComponent{std::string{b.token}, 1};
    }
    if (text.starts_with("S_"))
        return ItaniumNameComponent{"subst", 2};
    return std::nullopt;
}

[[nodiscard]] std::optional<ItaniumNameComponent>
itanium_operator_component(std::string_view text) {
    struct OpCode {
        std::string_view code;
        std::string_view token;
    };
    if (text.starts_with("cv")) {
        auto target = itanium_type_token(text.substr(2));
        if (!target)
            return std::nullopt;
        return ItaniumNameComponent{"operator_" + std::move(target->token), target->length + 2};
    }
    for (const auto &op : {
             OpCode{"nw", "operator_new"},         OpCode{"na", "operator_new_array"},
             OpCode{"dl", "operator_delete"},      OpCode{"da", "operator_delete_array"},
             OpCode{"ps", "operator_plus"},        OpCode{"ng", "operator_minus"},
             OpCode{"ad", "operator_and"},         OpCode{"de", "operator_mul"},
             OpCode{"co", "operator_bit_not"},     OpCode{"pl", "operator_plus"},
             OpCode{"mi", "operator_minus"},       OpCode{"ml", "operator_mul"},
             OpCode{"dv", "operator_div"},         OpCode{"rm", "operator_mod"},
             OpCode{"an", "operator_and"},         OpCode{"or", "operator_or"},
             OpCode{"eo", "operator_xor"},         OpCode{"aS", "operator_assign"},
             OpCode{"pL", "operator_plus_assign"}, OpCode{"mI", "operator_minus_assign"},
             OpCode{"mL", "operator_mul_assign"},  OpCode{"dV", "operator_div_assign"},
             OpCode{"rM", "operator_mod_assign"},  OpCode{"aN", "operator_and_assign"},
             OpCode{"oR", "operator_or_assign"},   OpCode{"eO", "operator_xor_assign"},
             OpCode{"ls", "operator_shl"},         OpCode{"rs", "operator_shr"},
             OpCode{"lS", "operator_shl_assign"},  OpCode{"rS", "operator_shr_assign"},
             OpCode{"eq", "operator_eq"},          OpCode{"ne", "operator_ne"},
             OpCode{"lt", "operator_lt"},          OpCode{"gt", "operator_gt"},
             OpCode{"le", "operator_le"},          OpCode{"ge", "operator_ge"},
             OpCode{"nt", "operator_not"},         OpCode{"aa", "operator_logical_and"},
             OpCode{"oo", "operator_logical_or"},  OpCode{"pp", "operator_inc"},
             OpCode{"mm", "operator_dec"},         OpCode{"cm", "operator_comma"},
             OpCode{"pm", "operator_ptr_member"},  OpCode{"pt", "operator_arrow"},
             OpCode{"cl", "operator_call"},        OpCode{"ix", "operator_index"},
         }) {
        if (text.starts_with(op.code)) {
            return ItaniumNameComponent{std::string(op.token), op.code.size()};
        }
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::string>
itanium_nested_name_prefix(std::string_view text) {
    std::size_t start = 0;
    if (text.starts_with("ZZN") || text.starts_with("ZZNK")) start = 1;
    if (!text.substr(start).starts_with("ZN")) return std::nullopt;
    std::size_t pos = start + 2;
    while (pos < text.size() &&
           (text[pos] == 'K' || text[pos] == 'V' ||
            text[pos] == 'r' || text[pos] == 'R' || text[pos] == 'O')) {
        ++pos;
    }
    std::vector<std::string> parts;
    while (pos < text.size() && text[pos] != 'E') {
        if (pos + 1 < text.size() && text[pos] == 'C' &&
            (text[pos + 1] == '1' || text[pos + 1] == '2' ||
             text[pos + 1] == '3')) {
            if (!parts.empty()) parts.push_back("ctor_" + parts.back());
            pos += 2;
            continue;
        }
        if (pos + 1 < text.size() && text[pos] == 'D' &&
            (text[pos + 1] == '0' || text[pos + 1] == '1' ||
             text[pos + 1] == '2')) {
            if (!parts.empty()) parts.push_back("dtor_" + parts.back());
            pos += 2;
            continue;
        }
            if (auto op = itanium_operator_component(text.substr(pos))) {
                parts.push_back(std::move(op->token));
                pos += op->length;
                continue;
            }
        if (!std::isdigit(static_cast<unsigned char>(text[pos]))) return std::nullopt;
        std::size_t len = 0;
        while (pos < text.size() && std::isdigit(static_cast<unsigned char>(text[pos]))) {
            len = len * 10 + static_cast<std::size_t>(text[pos] - '0');
            ++pos;
            if (len > 256) return std::nullopt;
        }
        if (len == 0 || pos + len > text.size()) return std::nullopt;
        auto comp = text.substr(pos, len);
        pos += len;
        if (comp.empty() || comp.front() == '$') continue;
        bool ok = true;
        for (char c : comp) {
            if (!(is_ident_char(c) || c == '$')) {
                ok = false;
                break;
            }
        }
        if (!ok) return std::nullopt;
        parts.emplace_back(comp);
    }
    if (pos >= text.size() || text[pos] != 'E') return std::nullopt;
    if (parts.size() < 2) return std::nullopt;
    if (parts.front() == "std" || parts.front() == "__cxxabiv1") return std::nullopt;

    std::string out;
    for (const auto& p : parts) {
        if (out.empty()) out = p;
        else out += "::" + p;
    }
    if (auto n = sanitize_name(out); !n.empty()) return n;
    return std::nullopt;
}

[[nodiscard]] std::optional<std::string>
itanium_local_function_name_prefix(std::string_view text) {
    std::size_t pos = 0;
    if (text.starts_with("ZZL")) pos = 1;
    if (!text.substr(pos).starts_with("ZL")) return std::nullopt;
    pos += 2;
    if (pos >= text.size() ||
        !std::isdigit(static_cast<unsigned char>(text[pos]))) {
        return std::nullopt;
    }
    std::size_t len = 0;
    while (pos < text.size() && std::isdigit(static_cast<unsigned char>(text[pos]))) {
        len = len * 10 + static_cast<std::size_t>(text[pos] - '0');
        ++pos;
        if (len > 256) return std::nullopt;
    }
    if (len == 0 || pos + len > text.size()) return std::nullopt;
    const auto name = text.substr(pos, len);
    for (char c : name) {
        if (!is_ident_char(c)) return std::nullopt;
    }
    if (auto n = sanitize_name(name); !n.empty()) return n;
    return std::nullopt;
}

[[nodiscard]] bool is_itanium_type_start(char c) noexcept {
    switch (c) {
    case 'v': case 'w': case 'b': case 'c': case 'a': case 'h':
    case 's': case 't': case 'i': case 'j': case 'l': case 'm':
    case 'x': case 'y': case 'n': case 'o': case 'f': case 'd':
    case 'e': case 'g': case 'z': case 'P': case 'R': case 'O':
    case 'C': case 'G': case 'U': case 'N': case 'S': case 'I':
    case 'K': case 'V': case 'r': case 'E':
        return true;
    default:
        return false;
    }
}

[[nodiscard]] std::optional<std::string>
itanium_free_function_name_prefix(std::string_view text) {
    std::size_t pos = 0;
    if (text.starts_with("ZZ") && text.size() > 2 &&
        std::isdigit(static_cast<unsigned char>(text[2]))) {
        pos = 1;
    }
    if (pos >= text.size() || text[pos] != 'Z') return std::nullopt;
    ++pos;
    if (pos >= text.size() ||
        !std::isdigit(static_cast<unsigned char>(text[pos]))) {
        return std::nullopt;
    }
    std::size_t len = 0;
    while (pos < text.size() && std::isdigit(static_cast<unsigned char>(text[pos]))) {
        len = len * 10 + static_cast<std::size_t>(text[pos] - '0');
        ++pos;
        if (len > 256) return std::nullopt;
    }
    if (len == 0 || pos + len > text.size()) return std::nullopt;
    const auto name = text.substr(pos, len);
    for (char c : name) {
        if (!is_ident_char(c)) return std::nullopt;
    }
    pos += len;
    if (pos < text.size() && !is_itanium_type_start(text[pos])) {
        return std::nullopt;
    }
    if (auto n = sanitize_name(name); !n.empty()) return n;
    return std::nullopt;
}

}  // namespace

std::optional<std::string> operator_suffix_token(std::string_view text,
                                                               std::size_t pos) {
    auto match = operator_suffix_match(text, pos);
    if (!match)
        return std::nullopt;
    return std::string(match->token);
}

std::string normalize_operator_name(std::string_view name) {
    constexpr std::string_view needle = "operator";
    for (std::size_t pos = name.find(needle); pos != std::string_view::npos;
         pos = name.find(needle, pos + needle.size())) {
        const bool boundary_before =
            pos == 0 || (pos >= 2 && name[pos - 1] == ':' && name[pos - 2] == ':');
        if (!boundary_before)
            continue;
        auto match = operator_suffix_match(name, pos + needle.size());
        std::string out{name.substr(0, pos)};
        out += "operator_";
        if (match) {
            out += match->token;
            out += name.substr(pos + needle.size() + match->length);
            return out;
        }
        const auto target = trim_ascii(name.substr(pos + needle.size()));
        if (target.empty())
            continue;
        auto token = flat_demangled_type_token(target);
        if (token.empty())
            continue;
        out += token;
        return out;
    }
    return std::string{name};
}

std::optional<std::string>
c_pretty_function_name(std::string_view text) {
    for (std::size_t paren = text.find('(');
         paren != std::string_view::npos;
         paren = text.find('(', paren + 1)) {
        auto head = trim_ascii(text.substr(0, paren));
        if (head.empty()) continue;

        std::size_t end = head.size();
        while (end > 0 &&
               std::isspace(static_cast<unsigned char>(head[end - 1]))) {
            --end;
        }
        std::size_t start = end;
        while (start > 0 && is_ident_char(head[start - 1])) --start;
        if (start == end) continue;

        const auto raw_name = head.substr(start, end - start);
        if (is_bad_plain_function_name(raw_name)) continue;
        if (!has_c_signature_type_cue(head.substr(0, start))) continue;
        if (auto n = sanitize_name(raw_name); !n.empty()) return n;
    }
    return std::nullopt;
}

std::optional<std::string>
itanium_embedded_function_name_prefix(std::string_view text) {
    if (auto n = itanium_nested_name_prefix(text)) return n;
    if (auto n = itanium_local_function_name_prefix(text)) return n;
    if (auto n = itanium_free_function_name_prefix(text)) return n;
    return std::nullopt;
}

}  // namespace spelunk::string_names
