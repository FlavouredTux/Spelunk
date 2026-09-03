#include <ember/analysis/objc.hpp>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <initializer_list>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/binary/symbol.hpp>
#include <ember/common/types.hpp>

namespace ember {

namespace {

// On-disk layouts are 64-bit little-endian. We read through bytes_at() so
// absolute VAs in the image map back to file bytes naturally.

constexpr u32 kRelativeMethodListFlag = 0x80000000u;
constexpr u32 kSelectorOffsetsFlag    = 0x40000000u;
constexpr u32 kRwMeta                 = 0x1u;  // class_ro_t flags bit: is metaclass
constexpr u32 kBlockHasCopyDispose    = 1u << 25;
constexpr u32 kBlockHasSignature      = 1u << 30;

constexpr addr_t kCategoryNameOffset               = 0;
constexpr addr_t kCategoryClassOffset              = 8;
constexpr addr_t kCategoryInstanceMethodsOffset    = 16;
constexpr addr_t kCategoryClassMethodsOffset       = 24;
constexpr addr_t kCategoryProtocolsOffset          = 32;
constexpr addr_t kCategoryInstancePropertiesOffset = 40;
constexpr addr_t kCategoryClassPropertiesOffset    = 48;

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

[[nodiscard]] std::string read_cstring(std::span<const std::byte> bytes) {
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

[[nodiscard]] std::string read_cstring(const Binary& b, addr_t va) {
    return read_cstring(b.bytes_at(va));
}

// Locate a Mach-O section by suffix ("__objc_classlist", "__objc_selrefs",
// etc.). Mach-O section names are stored as __SEGMENT,__sect; Ember's loader
// strips the segment prefix in most cases but some builds preserve it.
[[nodiscard]] bool section_name_matches(std::string_view actual,
                                        std::string_view wanted) noexcept {
    return actual == wanted || actual.ends_with(wanted);
}

[[nodiscard]] std::span<const std::byte>
find_section(const Binary& b, std::string_view name, u64& out_vaddr) {
    for (const auto& s : b.sections()) {
        if (section_name_matches(s.name, name)) {
            out_vaddr = s.vaddr;
            return s.data;
        }
    }
    out_vaddr = 0;
    return {};
}

[[nodiscard]] std::span<const std::byte>
find_section(const Binary& b, std::string_view name) {
    u64 unused_vaddr = 0;
    return find_section(b, name, unused_vaddr);
}

template <typename Fn>
void for_each_ptr_in_section(const Binary& b, std::string_view name, Fn&& fn) {
    u64 vaddr = 0;
    auto data = find_section(b, name, vaddr);
    if (data.empty()) return;
    const std::size_t n = data.size() / 8;
    for (std::size_t i = 0; i < n; ++i) {
        u64 p = 0;
        std::memcpy(&p, data.data() + i * 8, 8);
        fn(static_cast<addr_t>(vaddr + i * 8), static_cast<addr_t>(p));
    }
}

template <typename Fn>
void for_each_unique_ptr_in_sections(const Binary& b,
                                     std::initializer_list<std::string_view> names,
                                     Fn&& fn) {
    std::set<std::pair<std::string_view, addr_t>> seen_slots;
    std::set<addr_t> seen_ptrs;
    for (std::string_view name : names) {
        for_each_ptr_in_section(b, name, [&](addr_t slot, addr_t p) {
            if (!seen_slots.emplace(name, slot).second) return;
            if (p == 0) return;
            if (!seen_ptrs.insert(p).second) return;
            fn(slot, p);
        });
    }
}

// method_t in absolute-pointer form (24 bytes):
//     u64 name  (points at a C-string selector)
//     u64 types (type encoding C-string)
//     u64 imp   (function pointer; 0 for protocol signatures)
[[nodiscard]] std::optional<ObjcMethod>
read_abs_method(const Binary& b, addr_t entry_va, std::string_view cls,
                bool allow_zero_imp) {
    auto sel_p   = load_u64(b, entry_va + 0);
    auto types_p = load_u64(b, entry_va + 8);
    auto imp_p   = load_u64(b, entry_va + 16);
    if (!sel_p) return std::nullopt;
    ObjcMethod m;
    m.cls      = std::string(cls);
    m.selector = read_cstring(b, static_cast<addr_t>(*sel_p));
    if (types_p) m.type_encoding = read_cstring(b, static_cast<addr_t>(*types_p));
    m.imp      = imp_p ? static_cast<addr_t>(*imp_p) : addr_t{0};
    if (m.selector.empty()) return std::nullopt;
    if (!allow_zero_imp && m.imp == 0) return std::nullopt;
    return m;
}

// Relative method_t (12 bytes): three i32 offsets from each field's address.
//     i32 name_off  → selector string (or @selector() indirection)
//     i32 types_off
//     i32 imp_off
// With the selector-offset flag, name_off is an unsigned offset from the
// __objc_methname string buffer. Without it, name_off is a signed
// field-relative offset to a selref slot that contains the string pointer.
[[nodiscard]] std::optional<ObjcMethod>
read_rel_method(const Binary& b, addr_t entry_va,
                std::string_view cls, bool selector_uses_buffer_offset,
                bool allow_zero_imp) {
    auto name_d  = load_i32(b, entry_va + 0);
    auto types_d = load_i32(b, entry_va + 4);
    auto imp_d   = load_i32(b, entry_va + 8);
    if (!name_d || !types_d || !imp_d) return std::nullopt;

    ObjcMethod m;
    m.cls = std::string(cls);
    if (selector_uses_buffer_offset) {
        // Binary has no shared-cache header to supply a global base. Only use
        // an embedded methname section, and never let the offset escape it.
        const auto selector_buffer = find_section(b, "__objc_methname");
        const u32 selector_offset = static_cast<u32>(*name_d);
        if (selector_offset >= selector_buffer.size()) {
            return std::nullopt;
        }
        m.selector = read_cstring(selector_buffer.subspan(selector_offset));
    } else {
        const addr_t selref = static_cast<addr_t>(
            static_cast<i64>(entry_va) + static_cast<i64>(*name_d));
        auto ptr = load_u64(b, selref);
        if (!ptr) return std::nullopt;
        m.selector = read_cstring(b, static_cast<addr_t>(*ptr));
    }
    // Types are always a direct (non-indirect) relative offset to a C string.
    const addr_t types_va = static_cast<addr_t>(
        static_cast<i64>(entry_va + 4) + static_cast<i64>(*types_d));
    m.type_encoding = read_cstring(b, types_va);

    m.imp = static_cast<addr_t>(
        static_cast<i64>(entry_va + 8) + static_cast<i64>(*imp_d));
    if (m.selector.empty()) return std::nullopt;
    if (!allow_zero_imp && m.imp == 0) return std::nullopt;
    return m;
}

// Walk one method_list_t at `ml_va`. Adds entries into `out` tagged with
// `cls` and `is_class`. `allow_zero_imp` accepts entries whose IMP is zero
// - required for protocol method lists, which carry signatures without
// implementations.
bool read_method_list(const Binary& b, addr_t ml_va,
                      std::string_view cls, bool is_class,
                      std::vector<ObjcMethod>& out,
                      bool allow_zero_imp = false) {
    if (ml_va == 0) return true;
    auto entsize_raw = load_u32(b, ml_va + 0);
    auto count       = load_u32(b, ml_va + 4);
    if (!entsize_raw || !count) return false;
    const bool relative  = (*entsize_raw & kRelativeMethodListFlag) != 0;
    const bool selectors_use_buffer_offsets =
        (*entsize_raw & kSelectorOffsetsFlag) != 0;
    const u32  entsize   = *entsize_raw & 0x3FFFFFFFu;
    if (entsize == 0) return false;
    if (*count > 100'000) return false;   // runaway guard

    for (u32 i = 0; i < *count; ++i) {
        const addr_t entry_va = ml_va + 8 + static_cast<addr_t>(i) * entsize;
        std::optional<ObjcMethod> m;
        if (relative) {
            m = read_rel_method(b, entry_va, cls,
                                selectors_use_buffer_offsets,
                                allow_zero_imp);
        } else {
            m = read_abs_method(b, entry_va, cls, allow_zero_imp);
        }
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
    addr_t protocols_va;
    addr_t ivars_va;
    addr_t properties_va;
};

[[nodiscard]] std::optional<ClassRo>
read_class_ro(const Binary& b, addr_t ro_va) {
    auto flags    = load_u32(b, ro_va + 0);
    auto name_p   = load_u64(b, ro_va + 24);
    auto methods  = load_u64(b, ro_va + 32);
    auto protos   = load_u64(b, ro_va + 40);
    auto ivars    = load_u64(b, ro_va + 48);
    auto props    = load_u64(b, ro_va + 64);
    if (!flags || !name_p) return std::nullopt;
    ClassRo r;
    r.flags      = *flags;
    r.name_va    = static_cast<addr_t>(*name_p);
    r.methods_va = methods ? static_cast<addr_t>(*methods) : addr_t{0};
    r.protocols_va = protos ? static_cast<addr_t>(*protos) : addr_t{0};
    r.ivars_va   = ivars ? static_cast<addr_t>(*ivars) : addr_t{0};
    r.properties_va = props ? static_cast<addr_t>(*props) : addr_t{0};
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

void read_ivar_list(const Binary& b, addr_t ivars_va,
                    std::string_view cls,
                    std::vector<ObjcIvar>& out) {
    if (ivars_va == 0 || cls.empty()) return;
    auto entsize_raw = load_u32(b, ivars_va + 0);
    auto count       = load_u32(b, ivars_va + 4);
    if (!entsize_raw || !count) return;
    const u32 entsize = *entsize_raw & 0xFFFFu;
    if (entsize < 32 || *count > 100'000) return;

    for (u32 i = 0; i < *count; ++i) {
        const addr_t entry_va = ivars_va + 8 + static_cast<addr_t>(i) * entsize;
        auto off_slot_p = load_u64(b, entry_va + 0);
        auto name_p     = load_u64(b, entry_va + 8);
        auto type_p     = load_u64(b, entry_va + 16);
        if (!off_slot_p || !*off_slot_p || !name_p || !*name_p) continue;
        ObjcIvar iv;
        iv.cls = std::string(cls);
        iv.offset_slot = static_cast<addr_t>(*off_slot_p);
        if (auto off_v = load_u64(b, iv.offset_slot); off_v) iv.offset = *off_v;
        iv.name = read_cstring(b, static_cast<addr_t>(*name_p));
        if (type_p && *type_p) {
            iv.type_encoding = read_cstring(b, static_cast<addr_t>(*type_p));
        }
        if (iv.name.empty()) continue;
        out.push_back(std::move(iv));
    }
}

[[nodiscard]] std::string property_ivar_from_attrs(std::string_view attrs) {
    std::size_t start = 0;
    while (start < attrs.size()) {
        std::size_t end = attrs.find(',', start);
        if (end == std::string_view::npos) end = attrs.size();
        std::string_view part = attrs.substr(start, end - start);
        if (part.starts_with("V") && part.size() > 1) {
            return std::string(part.substr(1));
        }
        if (end == attrs.size()) break;
        start = end + 1;
    }
    return {};
}

void read_property_list(const Binary& b, addr_t props_va,
                        std::string_view cls,
                        std::vector<ObjcProperty>& out) {
    if (props_va == 0 || cls.empty()) return;
    auto entsize_raw = load_u32(b, props_va + 0);
    auto count       = load_u32(b, props_va + 4);
    if (!entsize_raw || !count) return;
    const u32 entsize = *entsize_raw & 0xFFFFu;
    if (entsize < 16 || *count > 100'000) return;

    for (u32 i = 0; i < *count; ++i) {
        const addr_t entry_va = props_va + 8 + static_cast<addr_t>(i) * entsize;
        auto name_p  = load_u64(b, entry_va + 0);
        auto attrs_p = load_u64(b, entry_va + 8);
        if (!name_p || !*name_p || !attrs_p || !*attrs_p) continue;
        ObjcProperty p;
        p.cls = std::string(cls);
        p.name = read_cstring(b, static_cast<addr_t>(*name_p));
        p.attributes = read_cstring(b, static_cast<addr_t>(*attrs_p));
        p.ivar_name = property_ivar_from_attrs(p.attributes);
        if (p.name.empty()) continue;
        out.push_back(std::move(p));
    }
}

[[nodiscard]] bool is_executable_addr(const Binary& b, addr_t va) {
    for (const auto& s : b.sections()) {
        if (!s.flags.executable) continue;
        if (va >= s.vaddr && va < s.vaddr + s.size) return true;
    }
    return false;
}

[[nodiscard]] bool is_readable_addr(const Binary& b, addr_t va) {
    for (const auto& s : b.sections()) {
        if (!s.flags.readable) continue;
        if (va >= s.vaddr && va < s.vaddr + s.size) return true;
    }
    return false;
}

[[nodiscard]] std::optional<ObjcBlock>
read_block_literal(const Binary& b, addr_t literal_va) {
    auto flags = load_u32(b, literal_va + 8);
    auto reserved = load_u32(b, literal_va + 12);
    auto invoke = load_u64(b, literal_va + 16);
    auto descriptor = load_u64(b, literal_va + 24);
    if (!flags || !reserved || !invoke || !descriptor) return std::nullopt;
    if (*reserved != 0) return std::nullopt;
    if ((*flags & kBlockHasSignature) == 0) return std::nullopt;
    if (!is_executable_addr(b, static_cast<addr_t>(*invoke))) return std::nullopt;
    if (!is_readable_addr(b, static_cast<addr_t>(*descriptor))) return std::nullopt;

    auto reserved_desc = load_u64(b, static_cast<addr_t>(*descriptor) + 0);
    auto size = load_u64(b, static_cast<addr_t>(*descriptor) + 8);
    if (!reserved_desc || !size || *reserved_desc != 0) return std::nullopt;
    if (*size < 0x20 || *size > 0x1000) return std::nullopt;

    addr_t sig_slot = static_cast<addr_t>(*descriptor) + 16;
    if ((*flags & kBlockHasCopyDispose) != 0) sig_slot += 16;
    auto sig_p = load_u64(b, sig_slot);
    if (!sig_p || !*sig_p) return std::nullopt;
    std::string sig = read_cstring(b, static_cast<addr_t>(*sig_p));
    if (sig.empty() || sig.find("@?") == std::string::npos) return std::nullopt;

    ObjcBlock blk;
    blk.literal = literal_va;
    blk.invoke = static_cast<addr_t>(*invoke);
    blk.descriptor = static_cast<addr_t>(*descriptor);
    blk.flags = *flags;
    blk.size = *size;
    blk.signature = std::move(sig);
    return blk;
}

[[nodiscard]] std::string objc_class_name_from_symbol(std::string_view sym) {
    constexpr std::string_view kNeedle = "OBJC_CLASS_$_";
    const std::size_t pos = sym.find(kNeedle);
    if (pos == std::string_view::npos) return {};
    std::string name(sym.substr(pos + kNeedle.size()));
    if (name.empty()) return {};
    if (!name.empty() && name.front() == '_') name.erase(name.begin());
    return name;
}

[[nodiscard]] std::string
class_name_from_class_pointer(const Binary& b, addr_t cls_p) {
    if (cls_p == 0) return {};
    if (auto ro = read_class_ro_from_class(b, cls_p); ro) {
        return read_cstring(b, ro->name_va);
    }
    for (const auto& sym : b.symbols()) {
        if (sym.addr != cls_p) continue;
        std::string name = objc_class_name_from_symbol(sym.name);
        if (!name.empty()) return name;
    }
    return {};
}

[[nodiscard]] std::string
class_name_from_import_slot(const Binary& b, addr_t slot) {
    if (const Symbol* imp = b.import_at_got(slot); imp) {
        std::string name = objc_class_name_from_symbol(imp->name);
        if (!name.empty()) return name;
    }
    for (const auto& sym : b.symbols()) {
        if (sym.is_import && sym.got_addr == slot) {
            std::string name = objc_class_name_from_symbol(sym.name);
            if (!name.empty()) return name;
        }
        if (sym.addr == slot) {
            std::string name = objc_class_name_from_symbol(sym.name);
            if (!name.empty()) return name;
        }
    }
    return {};
}

[[nodiscard]] std::string
category_target_class_name(const Binary& b, addr_t cls_slot, addr_t cls_p) {
    if (std::string name = class_name_from_class_pointer(b, cls_p); !name.empty()) {
        return name;
    }
    return class_name_from_import_slot(b, cls_slot);
}

struct ObjcCategory {
    addr_t va = 0;
    addr_t name_va = 0;
    addr_t class_va = 0;
    addr_t instance_methods_va = 0;
    addr_t class_methods_va = 0;
    addr_t protocols_va = 0;
    addr_t instance_properties_va = 0;
    addr_t class_properties_va = 0;
};

[[nodiscard]] std::optional<ObjcCategory>
read_category(const Binary& b, addr_t cat_va) {
    auto name_p   = load_u64(b, cat_va + kCategoryNameOffset);
    auto cls_p    = load_u64(b, cat_va + kCategoryClassOffset);
    auto imeth_p  = load_u64(b, cat_va + kCategoryInstanceMethodsOffset);
    auto cmeth_p  = load_u64(b, cat_va + kCategoryClassMethodsOffset);
    auto protos_p = load_u64(b, cat_va + kCategoryProtocolsOffset);
    auto iprops_p = load_u64(b, cat_va + kCategoryInstancePropertiesOffset);
    auto cprops_p = load_u64(b, cat_va + kCategoryClassPropertiesOffset);
    if (!name_p) return std::nullopt;

    ObjcCategory cat;
    cat.va = cat_va;
    cat.name_va = static_cast<addr_t>(*name_p);
    cat.class_va = cls_p ? static_cast<addr_t>(*cls_p) : addr_t{0};
    cat.instance_methods_va = imeth_p ? static_cast<addr_t>(*imeth_p) : addr_t{0};
    cat.class_methods_va = cmeth_p ? static_cast<addr_t>(*cmeth_p) : addr_t{0};
    cat.protocols_va = protos_p ? static_cast<addr_t>(*protos_p) : addr_t{0};
    cat.instance_properties_va = iprops_p ? static_cast<addr_t>(*iprops_p) : addr_t{0};
    cat.class_properties_va = cprops_p ? static_cast<addr_t>(*cprops_p) : addr_t{0};
    return cat;
}

[[nodiscard]] std::string
category_display_class_name(const Binary& b, const ObjcCategory& cat) {
    std::string cat_name = read_cstring(b, cat.name_va);
    std::string target_cls = category_target_class_name(
        b, cat.va + kCategoryClassOffset, cat.class_va);
    if (target_cls.empty()) target_cls = "?";
    return cat_name.empty() ? target_cls : target_cls + "(" + cat_name + ")";
}

// ---- ObjC type encoding decoder --------------------------------------------

// Spec reference: Apple's "Type Encodings" documentation. Input is a
// return type immediately followed by the sum of arg sizes (decimal),
// then `<argtype><argoffset>` for each argument. self (id at 0) and _cmd
// (SEL at 8) are always the first two args; we hide them from the output
// signature since every ObjC method has them.

struct EncCursor {
    std::string_view s;
    std::size_t pos = 0;
    char peek(std::size_t k = 0) const {
        return pos + k < s.size() ? s[pos + k] : '\0';
    }
    char take() { return pos < s.size() ? s[pos++] : '\0'; }
    bool eat(char c) { if (peek() == c) { ++pos; return true; } return false; }
};

std::string decode_one(EncCursor& st);

void skip_digits(EncCursor& st) {
    while (st.peek() >= '0' && st.peek() <= '9') ++st.pos;
}

std::string decode_one(EncCursor& st) {
    // Discard leading qualifier prefixes.
    while (true) {
        const char c = st.peek();
        if (c == 'r' || c == 'R' || c == 'n' || c == 'N' ||
            c == 'o' || c == 'O' || c == 'V' || c == '!') {
            ++st.pos;
            continue;
        }
        break;
    }
    const char c = st.take();
    switch (c) {
        case 'v': return "void";
        case 'c': return "char";
        case 'C': return "unsigned char";
        case 's': return "short";
        case 'S': return "unsigned short";
        case 'i': return "int";
        case 'I': return "unsigned int";
        case 'l': return "long";
        case 'L': return "unsigned long";
        case 'q': return "long long";
        case 'Q': return "unsigned long long";
        case 'f': return "float";
        case 'd': return "double";
        case 'D': return "long double";
        case 'B': return "bool";
        case '*': return "char*";
        case '#': return "Class";
        case ':': return "SEL";
        case '?': return "unknown";
        case '@': {
            // @"ClassName" → named object type
            // @?            → block
            if (st.eat('"')) {
                std::string name;
                while (st.peek() != '"' && st.pos < st.s.size())
                    name.push_back(st.take());
                st.eat('"');
                if (name.empty()) return "id";
                // Protocol conformance: @"<ProtoName>" shows up as "<Proto>".
                if (!name.empty() && name.front() == '<') return "id " + name;
                return name + "*";
            }
            if (st.eat('?')) return "block";
            return "id";
        }
        case '^': {
            std::string inner = decode_one(st);
            return inner + "*";
        }
        case '{': {
            std::string name;
            while (st.peek() != '=' && st.peek() != '}' && st.pos < st.s.size())
                name.push_back(st.take());
            if (st.eat('=')) {
                while (st.peek() != '}' && st.pos < st.s.size())
                    (void)decode_one(st);
            }
            st.eat('}');
            return name.empty() ? "struct" : ("struct " + name);
        }
        case '(': {
            std::string name;
            while (st.peek() != '=' && st.peek() != ')' && st.pos < st.s.size())
                name.push_back(st.take());
            if (st.eat('=')) {
                while (st.peek() != ')' && st.pos < st.s.size())
                    (void)decode_one(st);
            }
            st.eat(')');
            return name.empty() ? "union" : ("union " + name);
        }
        case '[': {
            std::string count;
            while (st.peek() >= '0' && st.peek() <= '9')
                count.push_back(st.take());
            std::string inner = decode_one(st);
            st.eat(']');
            return inner + "[" + count + "]";
        }
        case 'b': {
            std::string count;
            while (st.peek() >= '0' && st.peek() <= '9')
                count.push_back(st.take());
            return "bitfield:" + count;
        }
        default:
            return std::string{};
    }
}

std::vector<std::string> decode_objc_type_parts_impl(std::string_view enc) {
    std::vector<std::string> parts;
    if (enc.empty()) return parts;
    EncCursor st{enc, 0};
    std::string ret = decode_one(st);
    if (ret.empty()) return {};
    skip_digits(st);
    parts.push_back(std::move(ret));
    while (st.pos < st.s.size()) {
        std::string t = decode_one(st);
        skip_digits(st);
        if (!t.empty()) parts.push_back(std::move(t));
    }
    return parts;
}

std::string decode_objc_type_impl(std::string_view enc) {
    auto parts = decode_objc_type_parts_impl(enc);
    if (parts.empty()) return {};
    std::string out = parts[0];
    out += " (";
    // Hide self (arg 0, always id) and _cmd (arg 1, always SEL).
    for (std::size_t i = 3; i < parts.size(); ++i) {
        if (i > 3) out += ", ";
        out += parts[i];
    }
    // When there are exactly self + _cmd (parts.size() == 3) or only return
    // type, the loop is empty - close the parens.
    out += ")";
    return out;
}

// ---- Protocol parser -------------------------------------------------------

std::string read_protocol_name_from_ptr(const Binary& b, addr_t proto_p) {
    auto name_p = load_u64(b, proto_p + 8);
    if (!name_p) return {};
    return read_cstring(b, static_cast<addr_t>(*name_p));
}

std::optional<ObjcProtocol>
read_protocol(const Binary& b, addr_t proto_va) {
    ObjcProtocol p;
    p.name = read_protocol_name_from_ptr(b, proto_va);
    if (p.name.empty()) return std::nullopt;

    auto conforms_p = load_u64(b, proto_va + 16);
    auto inst_req_p = load_u64(b, proto_va + 24);
    auto cls_req_p  = load_u64(b, proto_va + 32);
    auto inst_opt_p = load_u64(b, proto_va + 40);
    auto cls_opt_p  = load_u64(b, proto_va + 48);

    if (inst_req_p && *inst_req_p)
        read_method_list(b, static_cast<addr_t>(*inst_req_p),
                         p.name, false, p.required_instance, true);
    if (cls_req_p && *cls_req_p)
        read_method_list(b, static_cast<addr_t>(*cls_req_p),
                         p.name, true,  p.required_class,    true);
    if (inst_opt_p && *inst_opt_p)
        read_method_list(b, static_cast<addr_t>(*inst_opt_p),
                         p.name, false, p.optional_instance, true);
    if (cls_opt_p && *cls_opt_p)
        read_method_list(b, static_cast<addr_t>(*cls_opt_p),
                         p.name, true,  p.optional_class,    true);

    if (conforms_p && *conforms_p) {
        // protocol_list_t: u64 count, followed by count u64 pointers.
        auto cnt = load_u64(b, static_cast<addr_t>(*conforms_p));
        if (cnt && *cnt <= 256) {
            for (u64 j = 0; j < *cnt; ++j) {
                auto ptr = load_u64(b, static_cast<addr_t>(*conforms_p + 8 + j * 8));
                if (!ptr || !*ptr) continue;
                std::string cn = read_protocol_name_from_ptr(b, static_cast<addr_t>(*ptr));
                if (!cn.empty()) p.conforms_to.push_back(std::move(cn));
            }
        }
    }
    return p;
}

std::vector<std::string> read_protocol_list_names(const Binary& b,
                                                  addr_t list_va) {
    std::vector<std::string> out;
    if (list_va == 0) return out;
    auto cnt = load_u64(b, list_va);
    if (!cnt || *cnt > 100'000) return out;
    std::set<std::string> seen;
    for (u64 i = 0; i < *cnt; ++i) {
        auto proto_p = load_u64(b, list_va + 8 + i * 8);
        if (!proto_p || !*proto_p) continue;
        std::string name = read_protocol_name_from_ptr(
            b, static_cast<addr_t>(*proto_p));
        if (name.empty()) continue;
        if (seen.insert(name).second) out.push_back(std::move(name));
    }
    return out;
}

}  // namespace

std::string decode_objc_type(std::string_view encoding) {
    return decode_objc_type_impl(encoding);
}

std::vector<std::string> decode_objc_type_parts(std::string_view encoding) {
    return decode_objc_type_parts_impl(encoding);
}

std::vector<ObjcProtocol> parse_objc_protocols(const Binary& b) {
    std::vector<ObjcProtocol> out;
    u64 vaddr = 0;
    auto proto_list = find_section(b, "__objc_protolist", vaddr);
    if (proto_list.empty()) return out;
    const std::size_t n = proto_list.size() / 8;
    for (std::size_t i = 0; i < n; ++i) {
        u64 proto_p = 0;
        std::memcpy(&proto_p, proto_list.data() + i * 8, 8);
        if (proto_p == 0) continue;
        if (auto p = read_protocol(b, static_cast<addr_t>(proto_p)); p) {
            out.push_back(std::move(*p));
        }
    }
    return out;
}

std::vector<ObjcProtocolConformance>
parse_objc_protocol_conformances(const Binary& b) {
    std::vector<ObjcProtocolConformance> out;
    for_each_unique_ptr_in_sections(
        b, {"__objc_classlist", "__objc_nlclslist"},
        [&](addr_t, addr_t cls_p) {
            auto ro = read_class_ro_from_class(b, cls_p);
            if (!ro) return;
            std::string cls_name = read_cstring(b, ro->name_va);
            if (cls_name.empty()) return;
            auto protos = read_protocol_list_names(b, ro->protocols_va);
            if (protos.empty()) return;
            ObjcProtocolConformance c;
            c.cls = std::move(cls_name);
            c.source = "class";
            c.protocols = std::move(protos);
            out.push_back(std::move(c));
        });

    for_each_unique_ptr_in_sections(
        b, {"__objc_catlist", "__objc_nlcatlist"},
        [&](addr_t, addr_t cat_p) {
            auto cat = read_category(b, cat_p);
            if (!cat) return;
            auto protos = read_protocol_list_names(b, cat->protocols_va);
            if (protos.empty()) return;
            std::string display = category_display_class_name(b, *cat);
            if (display.empty()) return;
            std::string cls = display;
            if (const std::size_t p = cls.find('('); p != std::string::npos) {
                cls.resize(p);
            }
            ObjcProtocolConformance c;
            c.cls = std::move(cls);
            c.source = "category:" + display;
            c.protocols = std::move(protos);
            out.push_back(std::move(c));
        });
    return out;
}

std::vector<ObjcMethod> parse_objc_methods(const Binary& b) {
    std::vector<ObjcMethod> out;
    for_each_unique_ptr_in_sections(
        b, {"__objc_classlist", "__objc_nlclslist"},
        [&](addr_t, addr_t cls_p) { walk_class(b, cls_p, out); });

    // __objc_catlist holds category_t pointers. A category adds
    // (instance_methods, class_methods, protocols) to an existing class
    // post-hoc. The category_t layout (64-bit):
    //   u64 name              // C-string, e.g. "Extensions"
    //   u64 cls               // class_t* the category extends
    //   u64 instance_methods
    //   u64 class_methods
    //   u64 protocols
    //   u64 instance_properties
    //   u64 class_properties
    for_each_unique_ptr_in_sections(
        b, {"__objc_catlist", "__objc_nlcatlist"},
        [&](addr_t, addr_t cat_p) {
            auto cat = read_category(b, cat_p);
            if (!cat) return;
            // Category target class name - the method list belongs to it,
            // tagged with `(CategoryName)` so the reader can tell it apart
            // from the base class's own methods.
            const std::string tagged = category_display_class_name(b, *cat);
            if (tagged.empty()) return;
            read_method_list(b, cat->instance_methods_va, tagged, false, out);
            read_method_list(b, cat->class_methods_va, tagged, true, out);
        });
    return out;
}

std::vector<ObjcIvar> parse_objc_ivars(const Binary& b) {
    std::vector<ObjcIvar> out;
    for_each_unique_ptr_in_sections(
        b, {"__objc_classlist", "__objc_nlclslist"},
        [&](addr_t, addr_t cls_p) {
            auto ro = read_class_ro_from_class(b, cls_p);
            if (!ro) return;
            std::string cls_name = read_cstring(b, ro->name_va);
            if (cls_name.empty()) return;
            read_ivar_list(b, ro->ivars_va, cls_name, out);
        });
    return out;
}

std::vector<ObjcProperty> parse_objc_properties(const Binary& b) {
    std::vector<ObjcProperty> out;
    for_each_unique_ptr_in_sections(
        b, {"__objc_classlist", "__objc_nlclslist"},
        [&](addr_t, addr_t cls_p) {
            auto ro = read_class_ro_from_class(b, cls_p);
            if (!ro) return;
            std::string cls_name = read_cstring(b, ro->name_va);
            if (cls_name.empty()) return;
            read_property_list(b, ro->properties_va, cls_name, out);
        });

    for_each_unique_ptr_in_sections(
        b, {"__objc_catlist", "__objc_nlcatlist"},
        [&](addr_t, addr_t cat_p) {
            auto cat = read_category(b, cat_p);
            if (!cat) return;
            const std::string tagged = category_display_class_name(b, *cat);
            if (tagged.empty()) return;
            read_property_list(b, cat->instance_properties_va, tagged, out);
            read_property_list(b, cat->class_properties_va, tagged, out);
        });
    return out;
}

std::vector<ObjcBlock> parse_objc_blocks(const Binary& b) {
    std::vector<ObjcBlock> out;
    for (const auto& s : b.sections()) {
        if (!s.flags.readable || s.flags.executable || s.data.size() < 32) {
            continue;
        }
        const std::string_view name = s.name;
        const bool likely_block_section =
            name.find("__const") != std::string_view::npos ||
            name.find("__data") != std::string_view::npos ||
            name.find("__objc") != std::string_view::npos;
        if (!likely_block_section) continue;

        const std::size_t limit = s.data.size() - 32;
        for (std::size_t off = 0; off <= limit; off += 8) {
            const addr_t va = static_cast<addr_t>(s.vaddr + off);
            auto blk = read_block_literal(b, va);
            if (!blk) continue;
            out.push_back(std::move(*blk));
        }
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

std::map<addr_t, std::string> parse_objc_classrefs(const Binary& b) {
    std::map<addr_t, std::string> out;
    auto read_ref_section = [&](std::string_view name) {
        for_each_ptr_in_section(b, name, [&](addr_t slot, addr_t cls_p) {
            if (out.contains(slot)) return;
            if (cls_p == 0) {
                // External classrefs are often zero on disk and populated by
                // dyld bind/chained-fixup metadata at load time. The Mach-O
                // loader can expose an import symbol at the classref slot;
                // use that so class messages render as `[NSString class]`
                // instead of a raw `*(u64*)(slot)`.
                if (std::string cls_name = class_name_from_import_slot(b, slot);
                    !cls_name.empty()) {
                    out.emplace(slot, std::move(cls_name));
                }
                return;
            }
            // classref → class_t → class_ro_t → name. Follow the same chain
            // the method walker uses.
            std::string cls_name = class_name_from_class_pointer(b, cls_p);
            if (cls_name.empty()) return;
            out.emplace(slot, std::move(cls_name));
        });
    };
    read_ref_section("__objc_classrefs");
    // `super` sends use the same pointer-slot shape but live in their own
    // section on modern ObjC2 Mach-O files. Returning them through the same
    // map lets emitter-side RIP-relative loads render a class name instead
    // of an opaque slot.
    read_ref_section("__objc_superrefs");
    return out;
}

}  // namespace ember
