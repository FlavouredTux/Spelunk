#include <ember/analysis/rtti.hpp>

#include <cstddef>
#include <cstring>
#include <format>
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
        // Mach-O segment protections bleed into section flags, so `__TEXT`
        // data sections (`__cstring`, `__const`, `__literal*`, `__unwind_info`,
        // `__eh_frame`, `__gcc_except_tab`) all show up as "executable" even
        // though they aren't real code. If the walker accepts pointers into
        // them as vtable entries, we end up labelling the addresses of
        // typeinfo-name C strings as methods — the exact Bug C failure.
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
    // u64s are method IMPs; walk until we hit the start of the next
    // vtable, the next typeinfo struct, or a clearly non-vtable slot.
    //
    // Key subtlety: a pure-virtual slot points at `__cxa_pure_virtual`,
    // which on Mach-O binaries that link against the dyld shared cache
    // is an *imported* symbol — its address lives outside our __TEXT
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

            // vtable base is (i+1)*8 — the typeinfo slot; primary IMPs
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
                // — we've walked straight into the next RTTI struct.
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
                    // Pure-virtual / imported / padding — placeholder so
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
            // content before them — an all-zero method list means the
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

    return out;
}

std::map<addr_t, std::string>
rtti_method_names(const std::vector<RttiClass>& classes) {
    // Count how many vtable slots each IMP appears in. Addresses that show
    // up across many classes are almost always shared thunks — most
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
        for (std::size_t i = 0; i < c.methods.size(); ++i) {
            const addr_t a = c.methods[i];
            if (a == 0) continue;
            if (fanin[a] > kMaxFanin) continue;
            out.emplace(a, std::format("{}::vfn_{}", c.demangled_name, i));
        }
    }
    return out;
}

}  // namespace ember
