#include <ember/analysis/msvc_rtti.hpp>

#include <algorithm>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <ember/analysis/msvc_demangle.hpp>
#include <ember/binary/pe.hpp>
#include <ember/common/bytes.hpp>

namespace ember {

namespace {

constexpr std::size_t kColSize = 24;
constexpr u32         kColSignatureX64 = 1;

struct CodeRanges {
    std::vector<std::pair<addr_t, addr_t>> ranges;
    [[nodiscard]] bool contains(addr_t a) const noexcept {
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

struct RdataSection {
    std::span<const std::byte> bytes;
    addr_t                     vaddr;
};

// MSVC RTTI metadata and vtables live in read-only, non-executable
// sections — classically `.rdata`. We accept any R-only section to be
// resilient to linker renames ("const", "xdata" variants).
[[nodiscard]] std::vector<RdataSection>
collect_rdata_sections(const Binary& b) {
    std::vector<RdataSection> out;
    for (const auto& s : b.sections()) {
        if (s.flags.executable) continue;
        if (s.flags.writable)   continue;
        if (!s.flags.readable)  continue;
        if (s.data.empty())     continue;
        out.push_back({s.data, static_cast<addr_t>(s.vaddr)});
    }
    return out;
}

// Hand the decorated name straight to the MSVC demangler; on parse
// failure (templates we don't model, exotic operator codes, etc.), fall
// back to a minimum-viable cleanup that strips the kind prefix and
// reverses simple `@`-separated scope chains. The fallback exists so a
// demangler bug can never *hide* a class from the emitter — at worst
// the user sees a slightly mangled name.
[[nodiscard]] std::string pretty_from_decorated(std::string_view s) {
    if (auto d = demangle_msvc(s); d && !d->empty()) return *d;

    std::string_view body = s;
    if (body.starts_with(".?AV") || body.starts_with(".?AU")) body.remove_prefix(4);
    if (body.ends_with("@@")) body.remove_suffix(2);
    if (body.empty()) return std::string(s);

    std::vector<std::string_view> parts;
    parts.reserve(4);
    std::size_t start = 0;
    for (std::size_t i = 0; i < body.size(); ++i) {
        if (body[i] == '@') {
            parts.emplace_back(body.substr(start, i - start));
            start = i + 1;
        }
    }
    parts.emplace_back(body.substr(start));

    std::string out;
    for (auto it = parts.rbegin(); it != parts.rend(); ++it) {
        if (it->empty()) continue;
        if (!out.empty()) out += "::";
        out.append(it->data(), it->size());
    }
    return out.empty() ? std::string(s) : out;
}

// Read a C string at the given VA, capped. Rejects non-printable bytes —
// real TypeDescriptor names are ASCII with an optional leading dot.
[[nodiscard]] std::string read_decorated_name(const Binary& b, addr_t va) {
    auto span = b.bytes_at(va);
    if (span.empty()) return {};
    std::string out;
    out.reserve(64);
    const std::size_t lim = std::min<std::size_t>(span.size(), 512);
    for (std::size_t i = 0; i < lim; ++i) {
        const auto c = static_cast<unsigned char>(span[i]);
        if (c == 0) return out;
        if (c < 0x20 || c > 0x7e) return {};
        out.push_back(static_cast<char>(c));
    }
    return {};
}

// Validate a COL candidate at the given VA on a PE image. Returns the
// type-descriptor VA on success (non-zero) or 0 if the candidate doesn't
// look like a real COL.
[[nodiscard]] addr_t
validate_col(const PeBinary& pe, addr_t col_va) {
    auto span = pe.bytes_at(col_va);
    if (span.size() < kColSize) return 0;

    const u32 signature   = read_le_at<u32>(span.data() + 0);
    const u32 p_td_rva    = read_le_at<u32>(span.data() + 12);
    const u32 p_chd_rva   = read_le_at<u32>(span.data() + 16);
    const u32 p_self_rva  = read_le_at<u32>(span.data() + 20);

    if (signature != kColSignatureX64) return 0;
    if (p_td_rva == 0 || p_chd_rva == 0 || p_self_rva == 0) return 0;

    // pSelf on x64 is the RVA of this COL itself. Use it as a strong
    // integrity check: a randomly-aligned byte run won't carry the
    // right self-reference. Tolerate the RVA being off by the image
    // base quirk — the recorded value is *always* an RVA.
    const addr_t self_abs = pe.image_base() + static_cast<addr_t>(p_self_rva);
    if (self_abs != col_va) return 0;

    return pe.image_base() + static_cast<addr_t>(p_td_rva);
}

}  // namespace

std::vector<MsvcRttiClass> parse_msvc_rtti(const Binary& b) {
    const auto* pe = dynamic_cast<const PeBinary*>(&b);
    if (!pe) return {};
    // ARM64 PE uses MSVC RTTI too, but the COL layout differs
    // (different signature value, sometimes an IMAGE_BASE field).
    // Restricting to x86_64 keeps the validator tight until that
    // divergence is modelled.
    if (pe->arch() != Arch::X86_64) return {};

    std::vector<MsvcRttiClass> out;
    const auto rdata_sections = collect_rdata_sections(*pe);
    if (rdata_sections.empty()) return out;
    const auto code = collect_code_ranges(*pe);

    // Walk 8-byte slots in rdata-like sections. Pattern for an MSVC x64
    // vtable header is:
    //
    //   rdata[k  ] = u64 absolute VA of COL  (≥ image_base, COL lives in rdata)
    //   rdata[k+1] = u64 first virtual-method IMP (must land in a code range)
    //
    // The vtable VA is `&rdata[k+1]`. We emit one class per unique
    // (decorated_name, vtable) pair; method walking stops at the first
    // slot whose target is not a code address.
    for (const auto& sec : rdata_sections) {
        const std::size_t n = sec.bytes.size() / 8;
        for (std::size_t k = 0; k + 1 < n; ++k) {
            u64 col_ptr = 0, first_imp = 0;
            std::memcpy(&col_ptr,   sec.bytes.data() + k * 8,       8);
            std::memcpy(&first_imp, sec.bytes.data() + (k + 1) * 8, 8);
            if (col_ptr == 0 || first_imp == 0) continue;
            if (!code.contains(static_cast<addr_t>(first_imp))) continue;

            const addr_t td_va = validate_col(*pe, static_cast<addr_t>(col_ptr));
            if (td_va == 0) continue;

            // TypeDescriptor: { u64 pVFTable; u64 spare; char name[]; }
            // The decorated name begins at offset 16.
            const std::string decorated = read_decorated_name(*pe, td_va + 16);
            if (decorated.empty()) continue;
            // Every real MSVC type descriptor name starts with ".?" —
            // filter out random ASCII C strings that happen to sit
            // where a TD would be.
            if (decorated.size() < 4 || decorated[0] != '.' || decorated[1] != '?') {
                continue;
            }

            MsvcRttiClass cls;
            cls.col             = static_cast<addr_t>(col_ptr);
            cls.type_descriptor = td_va;
            cls.vtable          = static_cast<addr_t>(sec.vaddr + (k + 1) * 8);
            cls.decorated_name  = decorated;
            cls.pretty_name     = pretty_from_decorated(decorated);

            // Walk IMP slots starting at k+1. Stop when a slot stops
            // pointing into code, mirroring the Itanium walker's
            // structural-boundary logic.
            constexpr std::size_t kMaxVtableSlots   = 4096;
            constexpr std::size_t kMaxTrailingZeros = 8;
            std::size_t trailing_zeros = 0;
            for (std::size_t m = k + 1; m < n; ++m) {
                if (cls.methods.size() >= kMaxVtableSlots) break;
                u64 slot = 0;
                std::memcpy(&slot, sec.bytes.data() + m * 8, 8);
                if (slot == 0) {
                    cls.methods.push_back(0);
                    if (++trailing_zeros >= kMaxTrailingZeros) break;
                    continue;
                }
                if (!code.contains(static_cast<addr_t>(slot))) break;
                trailing_zeros = 0;
                cls.methods.push_back(static_cast<addr_t>(slot));
            }
            while (!cls.methods.empty() && cls.methods.back() == 0) {
                cls.methods.pop_back();
            }
            if (cls.methods.empty()) continue;

            out.push_back(std::move(cls));

            // Skip past the methods we just consumed so we don't re-enter
            // the same vtable as a method of itself on the next iteration.
            k += out.back().methods.size();
        }
    }
    return out;
}

std::map<addr_t, std::string>
rtti_method_names(std::span<const MsvcRttiClass> classes) {
    // Count how often each IMP shows up across vtables. Shared thunks
    // (pure-virtual, deleting-destructor) appear in many slots and should
    // not get per-class labels — mirrors the Itanium helper.
    std::map<addr_t, unsigned> imp_count;
    for (const auto& c : classes) {
        for (addr_t m : c.methods) if (m) imp_count[m]++;
    }

    std::map<addr_t, std::string> out;
    for (const auto& c : classes) {
        for (std::size_t i = 0; i < c.methods.size(); ++i) {
            const addr_t m = c.methods[i];
            if (m == 0) continue;
            if (imp_count[m] > 1) continue;
            const std::string& cls = c.pretty_name.empty()
                ? c.decorated_name : c.pretty_name;
            out.emplace(m, cls + "::vfn_" + std::to_string(i));
        }
    }
    return out;
}

}  // namespace ember
