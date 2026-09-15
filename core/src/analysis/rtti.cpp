#include <spelunk/analysis/rtti.hpp>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstring>
#include <format>
#include <iterator>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <spelunk/analysis/demangle.hpp>
#include <spelunk/analysis/discovery.hpp>
#include <spelunk/binary/binary.hpp>
#include <spelunk/binary/symbol.hpp>
#include <spelunk/common/types.hpp>

namespace spelunk {

namespace {

// A typeinfo's name pointer targets a C string like "3Foo", "N3Foo3BarE",
// "Pi" (pointer to int), "Sa" etc. We detect validity by trying to route
// the name through the Itanium demangler as the "encoding" part of a
// `_Z` symbol - if the demangler accepts it, it's RTTI.
[[nodiscard]] std::string read_cstring(const Binary& b, addr_t va,
                                       std::size_t max = 512) {
    auto span = b.bytes_at(va);
    if (span.empty()) return {};
    std::string out;
    out.reserve(32);
    const std::size_t lim = std::min(span.size(), max);
    for (std::size_t i = 0; i < lim; ++i) {
        const auto c = static_cast<unsigned char>(span[i]);
        if (c == 0) return out;
        // Typeinfo names never contain whitespace / control; early-reject
        // keeps us from accepting log messages and such as typeinfo names.
        if (c < 0x21 || c > 0x7e) return {};
        out.push_back(static_cast<char>(c));
    }
    return {};
}

[[nodiscard]] bool looks_like_typeinfo_name(std::string_view s) {
    if (s.size() < 2 || s.size() > 512) return false;
    // Itanium RTTI name payloads start with: a digit (source-name length),
    // 'N' (nested), 'P' (pointer), 'K' (const), 'R' (ref), 'S' (standard
    // abbrev), 'T' (template), or the two-letter names used by builtin
    // primitive types. The demangler below is the authoritative filter;
    // this is a pre-filter to skip unrelated strings cheaply.
    const char c = s.front();
    if (c >= '0' && c <= '9') return true;
    switch (c) {
        case 'N': case 'P': case 'K': case 'R': case 'O':
        case 'S': case 'U': case 'V': return true;
        default: return false;
    }
}

[[nodiscard]] bool useful_embedded_function_name(std::string_view name) noexcept {
    if (name.size() < 4 || name.size() > 192) return false;
    if (name.starts_with("std::") || name.starts_with("__cxxabiv1::")) return false;
    if (name.contains("::") || name.starts_with("-[") || name.starts_with("+[")) {
        return true;
    }
    bool has_alpha = false;
    for (char c : name) {
        const auto u = static_cast<unsigned char>(c);
        if (std::isalpha(u)) has_alpha = true;
        if (!(std::isalnum(u) || c == '_' || c == '-' || c == '+' ||
              c == ' ' || c == '[' || c == ']')) {
            return false;
        }
    }
    return has_alpha;
}

struct OperatorSuffixMatch {
    std::string_view token;
    std::size_t length = 0;
};

[[nodiscard]] std::optional<OperatorSuffixMatch> operator_suffix_match(std::string_view text,
                                                                       std::size_t pos) {
    struct OpName {
        std::string_view spelling;
        std::string_view token;
    };
    for (const auto &op : {
             OpName{"()", "call"},        OpName{"[]", "index"},       OpName{"<=>", "cmp"},
             OpName{"==", "eq"},          OpName{"!=", "ne"},          OpName{"<=", "le"},
             OpName{">=", "ge"},          OpName{"->*", "ptr_member"}, OpName{"->", "arrow"},
             OpName{"&&", "logical_and"}, OpName{"||", "logical_or"},  OpName{"++", "inc"},
             OpName{"--", "dec"},         OpName{"+=", "plus_assign"}, OpName{"-=", "minus_assign"},
             OpName{"*=", "mul_assign"},  OpName{"/=", "div_assign"},  OpName{"%=", "mod_assign"},
             OpName{"&=", "and_assign"},  OpName{"|=", "or_assign"},   OpName{"^=", "xor_assign"},
             OpName{"<<=", "shl_assign"}, OpName{">>=", "shr_assign"}, OpName{"<<", "shl"},
             OpName{">>", "shr"},         OpName{"+", "plus"},         OpName{"-", "minus"},
             OpName{"*", "mul"},          OpName{"/", "div"},          OpName{"%", "mod"},
             OpName{"&", "and"},          OpName{"|", "or"},           OpName{"^", "xor"},
             OpName{"~", "bit_not"},      OpName{"!", "not"},          OpName{"=", "assign"},
             OpName{"<", "lt"},           OpName{">", "gt"},           OpName{",", "comma"},
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

[[nodiscard]] std::string_view trim_ascii(std::string_view s) noexcept {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) {
        s.remove_prefix(1);
    }
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) {
        s.remove_suffix(1);
    }
    return s;
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

[[nodiscard]] std::string normalize_operator_name(std::string_view name) {
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

[[nodiscard]] std::string normalize_embedded_function_name(std::string name) {
    name = normalize_operator_name(name);
    const auto dtor = name.rfind("::~");
    if (dtor == std::string::npos) return name;
    const std::string_view leaf{name.data() + dtor + 3,
                                name.size() - dtor - 3};
    if (dtor == 0 || leaf.empty()) return name;
    return std::string{name.substr(0, dtor)} + "::dtor_" +
           std::string{leaf};
}

[[nodiscard]] std::optional<std::string>
itanium_nested_special_function_prefix(std::string_view text) {
    std::size_t start = 0;
    if (text.starts_with("ZZN") || text.starts_with("ZZNK")) start = 1;
    if (!text.substr(start).starts_with("ZN")) return std::nullopt;
    std::size_t pos = start + 2;
    while (pos < text.size() &&
           (text[pos] == 'K' || text[pos] == 'V' ||
            text[pos] == 'r' || text[pos] == 'R' || text[pos] == 'O')) {
        ++pos;
    }

    bool saw_special = false;
    std::vector<std::string> parts;
    while (pos < text.size() && text[pos] != 'E') {
        if (pos + 1 < text.size() && text[pos] == 'C' &&
            (text[pos + 1] == '1' || text[pos + 1] == '2' ||
             text[pos + 1] == '3')) {
            if (!parts.empty()) {
                parts.push_back("ctor_" + parts.back());
                saw_special = true;
            }
            pos += 2;
            continue;
        }
        if (pos + 1 < text.size() && text[pos] == 'D' &&
            (text[pos + 1] == '0' || text[pos + 1] == '1' ||
             text[pos + 1] == '2')) {
            if (!parts.empty()) {
                parts.push_back("dtor_" + parts.back());
                saw_special = true;
            }
            pos += 2;
            continue;
        }
        if (!std::isdigit(static_cast<unsigned char>(text[pos]))) return std::nullopt;
        std::size_t len = 0;
        while (pos < text.size() &&
               std::isdigit(static_cast<unsigned char>(text[pos]))) {
            len = len * 10 + static_cast<std::size_t>(text[pos] - '0');
            ++pos;
            if (len > 256) return std::nullopt;
        }
        if (len == 0 || pos + len > text.size()) return std::nullopt;
        auto comp = text.substr(pos, len);
        pos += len;
        if (comp.empty() || comp.front() == '$') continue;
        for (char c : comp) {
            if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_')) {
                return std::nullopt;
            }
        }
        parts.emplace_back(comp);
    }
    if (!saw_special || pos >= text.size() || text[pos] != 'E') return std::nullopt;
    if (parts.size() < 2 || parts.front() == "std" ||
        parts.front() == "__cxxabiv1") {
        return std::nullopt;
    }

    std::string out;
    for (const auto& p : parts) {
        if (out.empty()) out = p;
        else out += "::" + p;
    }
    if (!useful_embedded_function_name(out)) return std::nullopt;
    return out;
}

[[nodiscard]] bool is_itanium_type_start(char c) noexcept {
    const auto u = static_cast<unsigned char>(c);
    return std::isalpha(u) || c == 'P' || c == 'R' || c == 'O' ||
           c == 'K' || c == 'V' || c == 'N' || c == 'S' ||
           c == 'I' || c == 'E';
}

[[nodiscard]] std::optional<std::string>
itanium_local_or_free_function_prefix(std::string_view text) {
    std::size_t pos = std::string_view::npos;
    if (text.starts_with("ZL")) {
        pos = 2;
    } else if (text.starts_with("ZZL")) {
        pos = 3;
    } else if (text.size() >= 2 &&
               text[0] == 'Z' &&
               std::isdigit(static_cast<unsigned char>(text[1]))) {
        pos = 1;
    } else if (text.size() >= 3 &&
               text[0] == 'Z' && text[1] == 'Z' &&
               std::isdigit(static_cast<unsigned char>(text[2]))) {
        pos = 2;
    }
    if (pos == std::string_view::npos) return std::nullopt;

    std::size_t len = 0;
    while (pos < text.size() &&
           std::isdigit(static_cast<unsigned char>(text[pos]))) {
        len = len * 10 + static_cast<std::size_t>(text[pos] - '0');
        ++pos;
        if (len > 256) return std::nullopt;
    }
    if (len == 0 || pos + len > text.size()) return std::nullopt;
    std::string name{text.substr(pos, len)};
    pos += len;

    // After the source name comes the bare function type (`v`, `i`, `P...`,
    // etc.) or the local-name delimiter `E`.
    if (pos < text.size() && text[pos] != 'E' && !is_itanium_type_start(text[pos])) {
        return std::nullopt;
    }
    if (!useful_embedded_function_name(name)) return std::nullopt;
    return name;
}

struct EmbeddedCallableName {
    std::string function;
    std::optional<unsigned> lambda_ordinal;
};

[[nodiscard]] bool is_libcxx_function_func_type(std::string_view text) noexcept {
    return text.starts_with("NSt3__110__function6__funcI");
}

[[nodiscard]] std::optional<unsigned>
lambda_ordinal_from_type_encoding(std::string_view text) {
    for (std::size_t i = 0; i + 2 < text.size(); ++i) {
        if (text[i] != '$' || text[i + 1] != '_') continue;
        std::size_t j = i + 2;
        unsigned value = 0;
        bool any = false;
        while (j < text.size() &&
               std::isdigit(static_cast<unsigned char>(text[j]))) {
            any = true;
            value = value * 10u + static_cast<unsigned>(text[j] - '0');
            ++j;
        }
        if (any) return value;
    }
    return std::nullopt;
}

[[nodiscard]] std::string_view libcxx_function_slot_name(std::size_t slot) noexcept {
    // libc++ std::__1::__function::__func vtable, after the Itanium
    // offset/typeinfo header: complete dtor, deleting dtor, two clone
    // forms, two destroy forms, operator(), target_type(), target().
    switch (slot) {
        case 0: return "dtor";
        case 1: return "deleting_dtor";
        case 2: return "clone";
        case 3: return "clone_into";
        case 4: return "destroy";
        case 5: return "destroy_deallocate";
        case 6: return "invoke";
        case 7: return "target_type";
        case 8: return "target";
        default: return {};
    }
}

[[nodiscard]] std::string_view
libcxx_shared_ptr_pointer_slot_name(std::size_t slot) noexcept {
    // libc++ `std::__1::__shared_ptr_pointer<T, D, A>` control blocks sit
    // behind shared_ptr/weak_ptr instances. Their vtable slots are stable
    // enough to name from the ABI/library layout: destructors, shared-count
    // disposal, weak-count disposal, then deleter lookup.
    switch (slot) {
        case 0: return "dtor";
        case 1: return "deleting_dtor";
        case 2: return "on_zero_shared";
        case 3: return "on_zero_shared_weak";
        case 4: return "get_deleter";
        default: return {};
    }
}

[[nodiscard]] std::optional<std::string>
embedded_function_name_from_type_encoding(std::string_view text);

[[nodiscard]] std::optional<EmbeddedCallableName>
embedded_callable_from_type_encoding(std::string_view text) {
    for (std::size_t i = 0; i + 2 < text.size(); ++i) {
        if (text[i] != 'Z') continue;
        const char next = text[i + 1];
        const bool nested = next == 'N';
        const bool local = next == 'L';
        const bool free_function = next >= '0' && next <= '9';
        const bool local_nested =
            next == 'Z' && i + 2 < text.size() &&
            (text[i + 2] == 'N' || text[i + 2] == 'L' ||
             std::isdigit(static_cast<unsigned char>(text[i + 2])));
        if (!nested && !local && !free_function && !local_nested) continue;

        std::string mangled = "_";
        mangled += text.substr(i);
        auto demangled = demangle_itanium(mangled);
        if (!demangled) {
            if (auto fallback = itanium_local_or_free_function_prefix(text.substr(i))) {
                EmbeddedCallableName out;
                out.function = std::move(*fallback);
                out.lambda_ordinal = lambda_ordinal_from_type_encoding(text);
                return out;
            }
            continue;
        }
        auto base = strip_signature_suffix(*demangled);
        if (auto special = itanium_nested_special_function_prefix(text.substr(i))) {
            base = std::move(*special);
        } else {
            base = normalize_embedded_function_name(std::move(base));
        }
        if (!useful_embedded_function_name(base)) {
            if (auto fallback = itanium_local_or_free_function_prefix(text.substr(i))) {
                EmbeddedCallableName out;
                out.function = std::move(*fallback);
                out.lambda_ordinal = lambda_ordinal_from_type_encoding(text);
                return out;
            }
            continue;
        }
        EmbeddedCallableName out;
        out.function = std::move(base);
        out.lambda_ordinal = lambda_ordinal_from_type_encoding(text);
        return out;
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::string>
embedded_function_name_from_type_encoding(std::string_view text) {
    auto c = embedded_callable_from_type_encoding(text);
    if (!c) return std::nullopt;
    return c->function;
}

[[nodiscard]] std::optional<std::string>
try_demangle_typeinfo(std::string_view name) {
    if (!looks_like_typeinfo_name(name)) return std::nullopt;
    // Prepend `_Z` so the demangler sees a legal mangled symbol. RTTI
    // names are exactly the `<encoding>` portion of a top-level mangling
    // without the function-parameter list.
    std::string mangled = "_Z";
    mangled.append(name);
    auto r = demangle_itanium(mangled);
    if (!r) return embedded_function_name_from_type_encoding(name);
    // Strip the parenthesized arg list the demangler inserts - RTTI names
    // aren't functions, they're types.
    std::string s = *r;
    const auto lp = s.find('(');
    if (lp != std::string::npos) s = s.substr(0, lp);
    // Conservative sanity: empty / exactly the input back = no real parse.
    if (s.empty() || s == name) return std::nullopt;
    return s;
}

[[nodiscard]] std::optional<std::string_view>
vtable_typeinfo_payload(std::string_view symbol) {
    if (symbol.starts_with("__Z")) {
        symbol.remove_prefix(1); // Mach-O's C symbol prefix before `_Z...`.
    }
    if (!symbol.starts_with("_ZTV")) return std::nullopt;
    return symbol.substr(4);
}

[[nodiscard]] std::optional<std::string>
try_demangle_vtable_symbol(std::string_view symbol) {
    const auto payload = vtable_typeinfo_payload(symbol);
    if (!payload) return std::nullopt;
    return try_demangle_typeinfo(*payload);
}

// `code_sections` holds [start, end) ranges of canonical code sections so a
// pointer check can answer "is this a code address?" without losing protected
// text sections whose executable bit is restored only at runtime.
struct CodeRanges {
    std::vector<std::pair<addr_t, addr_t>> ranges;

    [[nodiscard]] bool contains(addr_t a) const {
        for (const auto& r : ranges) {
            if (a >= r.first && a < r.second) return true;
        }
        return false;
    }
};

[[nodiscard]] CodeRanges collect_code_ranges(const Binary& b) {
    CodeRanges r;
    for (const auto& s : b.sections()) {
        if (s.size == 0) continue;
        if (!addr_in_code_section(b, s.vaddr)) continue;
        // Mach-O segment protections bleed into section flags, so `__TEXT`
        // data sections (`__cstring`, `__const`, `__literal*`, `__unwind_info`,
        // `__eh_frame`, `__gcc_except_tab`) all show up as "executable" even
        // though they aren't real code. If the walker accepts pointers into
        // them as vtable entries, we end up labelling the addresses of
        // typeinfo-name C strings as methods - the exact Bug C failure.
        const std::string_view n = s.name;
        auto contains = [&](std::string_view needle) {
            return n.find(needle) != std::string_view::npos;
        };
        if (contains("__cstring") || contains("__const") ||
            contains("__literal") || contains("__eh_frame") ||
            contains("__unwind_info") || contains("__gcc_except_tab") ||
            contains("__objc_methname") || contains("__objc_classname") ||
            contains("__objc_methtype") || contains("__swift5") ||
            contains("__TEXT,__init") || contains("__TEXT,__oslogstring") ||
            contains(",__info_plist") || contains(",__ustring")) {
            continue;
        }
        r.ranges.emplace_back(static_cast<addr_t>(s.vaddr),
                              static_cast<addr_t>(s.vaddr + s.size));
    }
    return r;
}

struct ConstSection {
    std::span<const std::byte> bytes;
    addr_t                     vaddr;
};

struct AddressRanges {
    std::vector<std::pair<addr_t, addr_t>> ranges;

    void add(addr_t lo, addr_t hi) {
        if (hi > lo) ranges.emplace_back(lo, hi);
    }

    void finish() {
        std::ranges::sort(ranges);
        std::vector<std::pair<addr_t, addr_t>> merged;
        for (auto [lo, hi] : ranges) {
            if (merged.empty() || lo > merged.back().second) {
                merged.emplace_back(lo, hi);
            } else if (hi > merged.back().second) {
                merged.back().second = hi;
            }
        }
        ranges = std::move(merged);
    }

    [[nodiscard]] bool contains(addr_t a) const {
        const auto it = std::ranges::upper_bound(
            ranges, a, {}, [](const auto& r) { return r.first; });
        if (it == ranges.begin()) return false;
        const auto& r = *std::prev(it);
        return a >= r.first && a < r.second;
    }
};

[[nodiscard]] std::vector<ConstSection>
collect_const_sections(const Binary& b) {
    std::vector<ConstSection> out;
    for (const auto& s : b.sections()) {
        const std::string_view n = s.name;
        if (n == "__const" ||
            n.ends_with(",__const") ||
            n == ".data.rel.ro" ||
            n == ".rodata") {
            if (!s.data.empty()) {
                out.push_back({s.data, static_cast<addr_t>(s.vaddr)});
            }
        }
    }
    return out;
}

[[nodiscard]] bool section_name_contains(std::string_view name,
                                         std::string_view needle) noexcept {
    return name.find(needle) != std::string_view::npos;
}

[[nodiscard]] AddressRanges collect_typeinfo_name_ranges(const Binary& b) {
    AddressRanges out;
    for (const auto& s : b.sections()) {
        if (s.data.empty()) continue;
        const std::string_view n = s.name;
        const bool string_like =
            section_name_contains(n, "__cstring") ||
            section_name_contains(n, ".rodata") ||
            section_name_contains(n, ".rdata") ||
            section_name_contains(n, "__const") ||
            section_name_contains(n, ".data.rel.ro");
        if (!string_like) continue;
        out.add(static_cast<addr_t>(s.vaddr),
                static_cast<addr_t>(s.vaddr + s.data.size()));
    }
    out.finish();
    return out;
}

[[nodiscard]] std::vector<addr_t>
read_vtable_methods_from_symbol(const Binary& b, const CodeRanges& code,
                                addr_t vtable_object) {
    std::vector<addr_t> out;
    if (vtable_object == 0) return out;

    addr_t slot_va = vtable_object + 16;
    constexpr std::size_t kMaxVtableSlots   = 4096;
    constexpr std::size_t kMaxTrailingZeros = 8;
    std::size_t trailing_zeros = 0;
    for (std::size_t i = 0; i < kMaxVtableSlots; ++i, slot_va += 8) {
        auto span = b.bytes_at(slot_va);
        if (span.size() < 8) break;
        u64 raw = 0;
        std::memcpy(&raw, span.data(), 8);
        const addr_t target = static_cast<addr_t>(raw);
        if (target == 0 || !code.contains(target)) {
            out.push_back(0);
            if (++trailing_zeros >= kMaxTrailingZeros) break;
            continue;
        }
        trailing_zeros = 0;
        out.push_back(target);
    }
    while (!out.empty() && out.back() == 0) out.pop_back();
    return out;
}

}  // namespace

std::vector<RttiClass> parse_itanium_rtti(const Binary& b) {
    std::vector<RttiClass> out;
    const auto consts = collect_const_sections(b);
    if (consts.empty()) return out;
    const auto code = collect_code_ranges(b);
    const auto name_ranges = collect_typeinfo_name_ranges(b);

    // Pass 1: find typeinfo structs. A typeinfo is a u64 pair
    // (vptr, name_ptr) at 8-byte alignment where the second u64 points
    // at a cstring the demangler accepts as an Itanium type-encoding.
    std::map<addr_t, std::size_t> ti_by_addr;  // typeinfo_vaddr → index into out
    for (const auto& sec : consts) {
        const std::size_t n = sec.bytes.size() / 8;
        for (std::size_t i = 0; i + 1 < n; ++i) {
            u64 vptr = 0, name_p = 0;
            std::memcpy(&vptr,   sec.bytes.data() + i * 8,       8);
            std::memcpy(&name_p, sec.bytes.data() + (i + 1) * 8, 8);
            if (vptr == 0 || name_p == 0) continue;
            if (!name_ranges.contains(static_cast<addr_t>(name_p))) continue;
            std::string name = read_cstring(b, static_cast<addr_t>(name_p));
            if (name.empty()) continue;
            auto demangled = try_demangle_typeinfo(name);
            if (!demangled) continue;
            RttiClass c;
            c.typeinfo       = static_cast<addr_t>(sec.vaddr + i * 8);
            c.mangled_name   = std::move(name);
            c.demangled_name = std::move(*demangled);
            ti_by_addr.emplace(c.typeinfo, out.size());
            out.push_back(std::move(c));
        }
    }

    // Pass 2: find vtables. A primary vtable begins with (i64 offset_to_top
    // == 0, u64 typeinfo_ptr → one of our recorded typeinfos). Subsequent
    // u64s are method IMPs; walk until we hit the start of the next
    // vtable, the next typeinfo struct, or a clearly non-vtable slot.
    //
    // Key subtlety: a pure-virtual slot points at `__cxa_pure_virtual`,
    // which on Mach-O binaries that link against the dyld shared cache
    // is an *imported* symbol - its address lives outside our __TEXT
    // ranges, and on chained-fixups images it may read as 0 or a fixup
    // descriptor. Bailing on the first such slot under-counts abstract
    // interfaces (HttpClient, RakPeerInterface, NetworkStream etc.) and
    // cascades into every subclass's pseudo-C losing its vfn_N labels.
    // We record those slots as 0 placeholders and keep walking; callers
    // that build (imp → name) maps simply skip zeros.
    for (const auto& sec : consts) {
        const std::size_t n = sec.bytes.size() / 8;
        for (std::size_t i = 0; i + 1 < n; ++i) {
            i64 offset_to_top = 0;
            u64 ti = 0;
            std::memcpy(&offset_to_top, sec.bytes.data() + i * 8,       8);
            std::memcpy(&ti,            sec.bytes.data() + (i + 1) * 8, 8);
            if (offset_to_top != 0) continue;
            auto it = ti_by_addr.find(static_cast<addr_t>(ti));
            if (it == ti_by_addr.end()) continue;

            // vtable base is (i+1)*8 - the typeinfo slot; primary IMPs
            // start one u64 later.
            RttiClass& cls = out[it->second];
            if (cls.vtable != 0) continue;  // already recorded the primary
            cls.vtable = static_cast<addr_t>(sec.vaddr + (i + 1) * 8);
            constexpr std::size_t kMaxVtableSlots    = 4096;
            constexpr std::size_t kMaxTrailingZeros  = 8;
            std::size_t trailing_zeros = 0;
            for (std::size_t k = i + 2; k < n; ++k) {
                if (cls.methods.size() >= kMaxVtableSlots) break;
                u64 m = 0;
                std::memcpy(&m, sec.bytes.data() + k * 8, 8);
                // Structural boundary #1: current slot IS a typeinfo vptr
                // - we've walked straight into the next RTTI struct.
                if (ti_by_addr.count(static_cast<addr_t>(m))) break;
                // Structural boundary #2: the NEXT slot is a known
                // typeinfo, so this slot is the offset_to_top of a
                // new (primary or secondary) vtable.
                if (k + 1 < n) {
                    u64 next = 0;
                    std::memcpy(&next, sec.bytes.data() + (k + 1) * 8, 8);
                    if (ti_by_addr.count(static_cast<addr_t>(next))) {
                        const i64 oot = static_cast<i64>(m);
                        if (oot == 0 ||
                            (oot > -(i64{1} << 20) && oot < (i64{1} << 20))) {
                            break;
                        }
                    }
                }
                if (m == 0 || !code.contains(static_cast<addr_t>(m))) {
                    // Pure-virtual / imported / padding - placeholder so
                    // downstream slot indices stay aligned with the real
                    // vtable layout.
                    cls.methods.push_back(0);
                    if (++trailing_zeros >= kMaxTrailingZeros) break;
                    continue;
                }
                trailing_zeros = 0;
                cls.methods.push_back(static_cast<addr_t>(m));
            }
            // Trim trailing zero placeholders only when there's real
            // content before them - an all-zero method list means the
            // class is purely abstract (every slot is __cxa_pure_virtual
            // routed through chained-fixups), and we still want the
            // class registered so the resolver can report it exists.
            bool has_nonzero = false;
            for (addr_t a : cls.methods) if (a != 0) { has_nonzero = true; break; }
            if (has_nonzero) {
                while (!cls.methods.empty() && cls.methods.back() == 0) {
                    cls.methods.pop_back();
                }
            }
            // Don't skip ahead here: the vtable-header pattern
            // `(offset_to_top, known_ti)` is unambiguous enough that
            // re-scanning the method slots as outer-loop positions is
            // cheap, and skipping risks stepping over a back-to-back
            // vtable whose offset_to_top landed inside what we just
            // recorded as a method. `cls.vtable != 0` prevents any
            // duplicate re-entry for the same class.
        }
    }

    // Pass 3: named Itanium vtable symbols (`_ZTV*`). These may arrive from
    // an unstripped Mach-O, export info, or an external dSYM. They still give
    // us strong virtual-method names when the raw typeinfo walk cannot tie
    // the vtable back to a class.
    for (const auto& sym : b.symbols()) {
        if (sym.is_import || sym.addr == 0) continue;
        if (sym.kind != SymbolKind::Object && sym.kind != SymbolKind::Unknown) continue;
        auto payload = vtable_typeinfo_payload(sym.name);
        if (!payload) continue;
        auto demangled = try_demangle_vtable_symbol(sym.name);
        if (!demangled) continue;

        const addr_t typeinfo_slot = sym.addr + 8;
        auto methods = read_vtable_methods_from_symbol(b, code, sym.addr);
        if (methods.empty()) continue;

        RttiClass* cls = nullptr;
        for (auto& candidate : out) {
            if (candidate.vtable == typeinfo_slot ||
                (candidate.vtable == 0 && candidate.demangled_name == *demangled)) {
                cls = &candidate;
                break;
            }
        }
        if (!cls) {
            RttiClass c;
            c.mangled_name = std::string(*payload);
            c.demangled_name = std::move(*demangled);
            c.vtable = typeinfo_slot;
            c.methods = std::move(methods);
            out.push_back(std::move(c));
            continue;
        }
        if (cls->vtable == 0) cls->vtable = typeinfo_slot;
        if (cls->methods.empty()) cls->methods = std::move(methods);
    }

    return out;
}

std::map<addr_t, std::string>
rtti_method_names(std::span<const RttiClass> classes) {
    // Count how many vtable slots each IMP appears in. Addresses that show
    // up across many classes are almost always shared thunks - most
    // commonly `__cxa_pure_virtual`, but also deleting-destructor stubs
    // and ICF-folded methods. Labelling call sites `SomeRandomClass::vfn_3`
    // when the target is really the pure-virtual trampoline is worse than
    // leaving them as `sub_<hex>`, so we drop addresses with a wide fan-in.
    std::map<addr_t, std::size_t> fanin;
    for (const auto& c : classes) {
        for (addr_t a : c.methods) if (a != 0) ++fanin[a];
    }
    constexpr std::size_t kMaxFanin = 3;
    std::map<addr_t, std::string> out;
    for (const auto& c : classes) {
        if (c.demangled_name.empty()) continue;
        const auto embedded = embedded_callable_from_type_encoding(c.mangled_name);
        std::string label_base = embedded ? embedded->function : c.demangled_name;
        const bool libcxx_func = is_libcxx_function_func_type(c.mangled_name) &&
                                 c.methods.size() >= 9;
        const bool libcxx_shared_ptr_pointer =
            c.mangled_name.find("__shared_ptr_pointer") != std::string_view::npos ||
            label_base.find("__shared_ptr_pointer<") != std::string::npos;
        std::string slot_prefix = "vfn";
        if (embedded && embedded->lambda_ordinal) {
            label_base += std::format("::lambda_{}", *embedded->lambda_ordinal);
        } else if (embedded) {
            slot_prefix = "metadata_vfn";
        }
        for (std::size_t i = 0; i < c.methods.size(); ++i) {
            const addr_t a = c.methods[i];
            if (a == 0) continue;
            if (libcxx_func) {
                std::string_view slot = libcxx_function_slot_name(i);
                if (!slot.empty()) {
                    out[a] = std::format("{}::{}", label_base, slot);
                    continue;
                }
            }
            if (libcxx_shared_ptr_pointer) {
                std::string_view slot = libcxx_shared_ptr_pointer_slot_name(i);
                if (!slot.empty()) {
                    out[a] = std::format("{}::{}", label_base, slot);
                    continue;
                }
            }
            if (fanin[a] > kMaxFanin) continue;
            out.emplace(a, std::format("{}::{}_{:d}", label_base, slot_prefix, i));
        }
    }
    return out;
}

}  // namespace spelunk
