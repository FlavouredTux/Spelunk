#include <ember/analysis/rtti.hpp>

#include <cstddef>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <ember/analysis/demangle.hpp>
#include <ember/binary/binary.hpp>
#include <ember/common/types.hpp>

namespace ember {

namespace {

// A typeinfo's name pointer targets a C string like "3Foo", "N3Foo3BarE",
// "Pi" (pointer to int), "Sa" etc. We detect validity by trying to route
// the name through the Itanium demangler as the "encoding" part of a
// `_Z` symbol — if the demangler accepts it, it's RTTI.
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

[[nodiscard]] std::optional<std::string>
try_demangle_typeinfo(std::string_view name) {
    if (!looks_like_typeinfo_name(name)) return std::nullopt;
    // Prepend `_Z` so the demangler sees a legal mangled symbol. RTTI
    // names are exactly the `<encoding>` portion of a top-level mangling
    // without the function-parameter list.
    std::string mangled = "_Z";
    mangled.append(name);
    auto r = demangle_itanium(mangled);
    if (!r) return std::nullopt;
    // Strip the parenthesized arg list the demangler inserts — RTTI names
    // aren't functions, they're types.
    std::string s = *r;
    const auto lp = s.find('(');
    if (lp != std::string::npos) s = s.substr(0, lp);
    // Conservative sanity: empty / exactly the input back = no real parse.
    if (s.empty() || s == name) return std::nullopt;
    return s;
}

// `code_sections` holds [start, end) ranges of executable sections so a
// pointer check can answer "is this in __TEXT?" in O(log n).
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
        if (!s.flags.executable) continue;
        if (s.size == 0) continue;
        r.ranges.emplace_back(static_cast<addr_t>(s.vaddr),
                              static_cast<addr_t>(s.vaddr + s.size));
    }
    return r;
}

struct ConstSection {
    std::span<const std::byte> bytes;
    addr_t                     vaddr;
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

}  // namespace

std::vector<RttiClass> parse_itanium_rtti(const Binary& b) {
    std::vector<RttiClass> out;
    const auto consts = collect_const_sections(b);
    if (consts.empty()) return out;
    const auto code = collect_code_ranges(b);

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
    // u64s are method IMPs; stop on the first pointer outside __TEXT (that
    // boundary is where the next vtable / padding / data starts).
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

            // vtable base is (i+1)*8 — the typeinfo slot; primary IMPs
            // start one u64 later.
            RttiClass& cls = out[it->second];
            if (cls.vtable != 0) continue;  // already recorded the primary
            cls.vtable = static_cast<addr_t>(sec.vaddr + (i + 1) * 8);
            for (std::size_t k = i + 2; k < n; ++k) {
                u64 m = 0;
                std::memcpy(&m, sec.bytes.data() + k * 8, 8);
                if (!code.contains(static_cast<addr_t>(m))) break;
                cls.methods.push_back(static_cast<addr_t>(m));
            }
            i += cls.methods.size() + 1;  // skip past this vtable
        }
    }

    return out;
}

std::map<addr_t, std::string>
rtti_method_names(const std::vector<RttiClass>& classes) {
    std::map<addr_t, std::string> out;
    for (const auto& c : classes) {
        if (c.demangled_name.empty()) continue;
        for (std::size_t i = 0; i < c.methods.size(); ++i) {
            out.emplace(c.methods[i],
                        std::format("{}::vfn_{}", c.demangled_name, i));
        }
    }
    return out;
}

}  // namespace ember
