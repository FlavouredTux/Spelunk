#include <ember/analysis/objc.hpp>

#include <cstddef>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>

#include <ember/common/types.hpp>

namespace ember {

namespace {

// On-disk layouts are 64-bit little-endian. We read through bytes_at() so
// absolute VAs in the image map back to file bytes naturally.

constexpr u32 kRelativeMethodListFlag = 0x80000000u;
constexpr u32 kPreoptSelFlag          = 0x40000000u;  // clang emits this
constexpr u32 kRwMeta                 = 0x1u;  // class_ro_t flags bit: is metaclass

[[nodiscard]] std::optional<u64> load_u64(const Binary& b, addr_t va) {
    auto bytes = b.bytes_at(va);
    if (bytes.size() < 8) return std::nullopt;
    u64 v = 0;
    std::memcpy(&v, bytes.data(), 8);
    return v;
}

[[nodiscard]] std::optional<u32> load_u32(const Binary& b, addr_t va) {
    auto bytes = b.bytes_at(va);
    if (bytes.size() < 4) return std::nullopt;
    u32 v = 0;
    std::memcpy(&v, bytes.data(), 4);
    return v;
}

[[nodiscard]] std::optional<i32> load_i32(const Binary& b, addr_t va) {
    auto v = load_u32(b, va);
    if (!v) return std::nullopt;
    return static_cast<i32>(*v);
}

[[nodiscard]] std::string read_cstring(const Binary& b, addr_t va) {
    auto bytes = b.bytes_at(va);
    std::string out;
    out.reserve(64);
    const std::size_t kMax = 4096;
    const std::size_t lim = std::min(bytes.size(), kMax);
    for (std::size_t i = 0; i < lim; ++i) {
        const auto c = static_cast<unsigned char>(bytes[i]);
        if (c == 0) return out;
        if (c < 0x20 && c != '\t') return {};
        out.push_back(static_cast<char>(c));
    }
    return {};
}

// Locate a Mach-O section by suffix ("__objc_classlist", "__objc_selrefs",
// etc.). Mach-O section names are stored as __SEGMENT,__sect; Ember's loader
// strips the segment prefix in most cases but some builds preserve it.
[[nodiscard]] std::span<const std::byte>
find_section(const Binary& b, std::string_view name, u64& out_vaddr) {
    for (const auto& s : b.sections()) {
        const std::string_view sn = s.name;
        if (sn == name ||
            sn.ends_with(std::string{","} + std::string{name}) ||
            sn.ends_with(std::string{"__"} + std::string{name.substr(2)})) {
            out_vaddr = s.vaddr;
            return s.data;
        }
    }
    // Case-insensitive trailing match for names like "__DATA,__objc_classlist".
    for (const auto& s : b.sections()) {
        const std::string_view sn = s.name;
        if (sn.size() >= name.size() &&
            sn.substr(sn.size() - name.size()) == name) {
            out_vaddr = s.vaddr;
            return s.data;
        }
    }
    out_vaddr = 0;
    return {};
}

// method_t in absolute-pointer form (24 bytes):
//     u64 name  (points at a C-string selector)
//     u64 types (type encoding — we ignore)
//     u64 imp   (function pointer)
[[nodiscard]] std::optional<ObjcMethod>
read_abs_method(const Binary& b, addr_t entry_va, std::string_view cls) {
    auto sel_p  = load_u64(b, entry_va + 0);
    auto imp_p  = load_u64(b, entry_va + 16);
    if (!sel_p || !imp_p) return std::nullopt;
    ObjcMethod m;
    m.cls      = std::string(cls);
    m.selector = read_cstring(b, static_cast<addr_t>(*sel_p));
    m.imp      = static_cast<addr_t>(*imp_p);
    if (m.selector.empty() || m.imp == 0) return std::nullopt;
    return m;
}

// Relative method_t (12 bytes): three i32 offsets from each field's address.
//     i32 name_off  → selector string (or @selector() indirection)
//     i32 types_off
//     i32 imp_off
// When the method list header's entsize has the preopt flag set, name_off
// is the offset to a selref slot instead of the selector string directly.
[[nodiscard]] std::optional<ObjcMethod>
read_rel_method(const Binary& b, addr_t entry_va,
                std::string_view cls, bool preopt_sel) {
    auto name_d = load_i32(b, entry_va + 0);
    auto imp_d  = load_i32(b, entry_va + 8);
    if (!name_d || !imp_d) return std::nullopt;

    ObjcMethod m;
    m.cls = std::string(cls);
    const addr_t sel_or_ref = static_cast<addr_t>(
        static_cast<i64>(entry_va) + static_cast<i64>(*name_d));
    if (preopt_sel) {
        // Indirection: the offset points to a pointer to the selector.
        auto ptr = load_u64(b, sel_or_ref);
        if (!ptr) return std::nullopt;
        m.selector = read_cstring(b, static_cast<addr_t>(*ptr));
    } else {
        m.selector = read_cstring(b, sel_or_ref);
    }
    m.imp = static_cast<addr_t>(
        static_cast<i64>(entry_va + 8) + static_cast<i64>(*imp_d));
    if (m.selector.empty() || m.imp == 0) return std::nullopt;
    return m;
}

// Walk one method_list_t at `ml_va`. Adds entries into `out` tagged with
// `cls` and `is_class`. Returns false on malformed data; we still keep any
// methods already parsed.
bool read_method_list(const Binary& b, addr_t ml_va,
                      std::string_view cls, bool is_class,
                      std::vector<ObjcMethod>& out) {
    if (ml_va == 0) return true;
    auto entsize_raw = load_u32(b, ml_va + 0);
    auto count       = load_u32(b, ml_va + 4);
    if (!entsize_raw || !count) return false;
    const bool relative  = (*entsize_raw & kRelativeMethodListFlag) != 0;
    const bool preopt    = (*entsize_raw & kPreoptSelFlag) != 0;
    const u32  entsize   = *entsize_raw & 0x3FFFFFFFu;
    if (entsize == 0) return false;
    if (*count > 100'000) return false;   // runaway guard

    for (u32 i = 0; i < *count; ++i) {
        const addr_t entry_va = ml_va + 8 + static_cast<addr_t>(i) * entsize;
        std::optional<ObjcMethod> m;
        if (relative) m = read_rel_method(b, entry_va, cls, preopt);
        else          m = read_abs_method(b, entry_va, cls);
        if (!m) continue;
        m->is_class = is_class;
        out.push_back(std::move(*m));
    }
    return true;
}

// class_ro_t layout (64-bit):
//   u32 flags; u32 instanceStart; u32 instanceSize; u32 reserved;
//   u64 ivarLayout; u64 name; u64 baseMethods; u64 baseProtocols;
//   u64 ivars; u64 weakIvarLayout; u64 baseProperties;
struct ClassRo {
    u32    flags;
    addr_t name_va;
    addr_t methods_va;
};

[[nodiscard]] std::optional<ClassRo>
read_class_ro(const Binary& b, addr_t ro_va) {
    auto flags    = load_u32(b, ro_va + 0);
    auto name_p   = load_u64(b, ro_va + 24);
    auto methods  = load_u64(b, ro_va + 32);
    if (!flags || !name_p || !methods) return std::nullopt;
    ClassRo r;
    r.flags      = *flags;
    r.name_va    = static_cast<addr_t>(*name_p);
    r.methods_va = static_cast<addr_t>(*methods);
    return r;
}

// class_t: isa, superclass, cache, vtable, data
[[nodiscard]] std::optional<addr_t>
read_class_data_ptr(const Binary& b, addr_t cls_va) {
    auto data_p = load_u64(b, cls_va + 32);
    if (!data_p) return std::nullopt;
    // The low bits of `data` hold flags (RW_REALIZED, etc.); mask them.
    return static_cast<addr_t>(*data_p & ~u64{0x7});
}

[[nodiscard]] std::optional<ClassRo>
read_class_ro_from_class(const Binary& b, addr_t cls_va) {
    auto data_ptr = read_class_data_ptr(b, cls_va);
    if (!data_ptr) return std::nullopt;
    return read_class_ro(b, *data_ptr);
}

void walk_class(const Binary& b, addr_t cls_va,
                std::vector<ObjcMethod>& out) {
    auto ro = read_class_ro_from_class(b, cls_va);
    if (!ro) return;
    const std::string name = read_cstring(b, ro->name_va);
    if (name.empty()) return;
    const bool is_meta = (ro->flags & kRwMeta) != 0;
    read_method_list(b, ro->methods_va, name, is_meta, out);
    // Metaclass walk: class methods live on the metaclass (isa pointer).
    if (!is_meta) {
        auto meta_p = load_u64(b, cls_va + 0);  // isa → metaclass
        if (meta_p) {
            auto meta_ro = read_class_ro_from_class(b, static_cast<addr_t>(*meta_p));
            if (meta_ro) {
                read_method_list(b, meta_ro->methods_va, name, true, out);
            }
        }
    }
}

}  // namespace

std::vector<ObjcMethod> parse_objc_methods(const Binary& b) {
    std::vector<ObjcMethod> out;
    u64 vaddr = 0;
    auto cls_list = find_section(b, "__objc_classlist", vaddr);
    if (cls_list.empty()) return out;
    // Each entry is a pointer to a class_t.
    const std::size_t n = cls_list.size() / 8;
    for (std::size_t i = 0; i < n; ++i) {
        u64 cls_p = 0;
        std::memcpy(&cls_p, cls_list.data() + i * 8, 8);
        if (cls_p == 0) continue;
        walk_class(b, static_cast<addr_t>(cls_p), out);
    }
    return out;
}

std::map<addr_t, std::string> parse_objc_selrefs(const Binary& b) {
    std::map<addr_t, std::string> out;
    u64 vaddr = 0;
    auto sel_refs = find_section(b, "__objc_selrefs", vaddr);
    if (sel_refs.empty()) return out;
    const std::size_t n = sel_refs.size() / 8;
    for (std::size_t i = 0; i < n; ++i) {
        u64 sel_p = 0;
        std::memcpy(&sel_p, sel_refs.data() + i * 8, 8);
        if (sel_p == 0) continue;
        std::string s = read_cstring(b, static_cast<addr_t>(sel_p));
        if (s.empty()) continue;
        out.emplace(static_cast<addr_t>(vaddr + i * 8), std::move(s));
    }
    return out;
}

}  // namespace ember
