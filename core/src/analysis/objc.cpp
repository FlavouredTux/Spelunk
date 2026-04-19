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
// When the method list header's entsize has the preopt flag set, name_off
// is the offset to a selref slot instead of the selector string directly.
[[nodiscard]] std::optional<ObjcMethod>
read_rel_method(const Binary& b, addr_t entry_va,
                std::string_view cls, bool preopt_sel, bool allow_zero_imp) {
    auto name_d  = load_i32(b, entry_va + 0);
    auto types_d = load_i32(b, entry_va + 4);
    auto imp_d   = load_i32(b, entry_va + 8);
    if (!name_d || !types_d || !imp_d) return std::nullopt;

    ObjcMethod m;
    m.cls = std::string(cls);
    const addr_t sel_or_ref = static_cast<addr_t>(
        static_cast<i64>(entry_va) + static_cast<i64>(*name_d));
    if (preopt_sel) {
        auto ptr = load_u64(b, sel_or_ref);
        if (!ptr) return std::nullopt;
        m.selector = read_cstring(b, static_cast<addr_t>(*ptr));
    } else {
        m.selector = read_cstring(b, sel_or_ref);
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
// — required for protocol method lists, which carry signatures without
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
    const bool preopt    = (*entsize_raw & kPreoptSelFlag) != 0;
    const u32  entsize   = *entsize_raw & 0x3FFFFFFFu;
    if (entsize == 0) return false;
    if (*count > 100'000) return false;   // runaway guard

    for (u32 i = 0; i < *count; ++i) {
        const addr_t entry_va = ml_va + 8 + static_cast<addr_t>(i) * entsize;
        std::optional<ObjcMethod> m;
        if (relative) m = read_rel_method(b, entry_va, cls, preopt, allow_zero_imp);
        else          m = read_abs_method(b, entry_va, cls, allow_zero_imp);
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

std::string decode_objc_type_impl(std::string_view enc) {
    if (enc.empty()) return {};
    EncCursor st{enc, 0};
    std::string ret = decode_one(st);
    if (ret.empty()) return {};
    skip_digits(st);  // total arg size

    std::vector<std::string> args;
    while (st.pos < st.s.size()) {
        std::string t = decode_one(st);
        skip_digits(st);
        if (!t.empty()) args.push_back(std::move(t));
    }

    // Hide self (arg 0, always id) and _cmd (arg 1, always SEL).
    std::string out = ret;
    out += " (";
    if (args.size() <= 2) {
        out += ")";
        return out;
    }
    for (std::size_t i = 2; i < args.size(); ++i) {
        if (i > 2) out += ", ";
        out += args[i];
    }
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

}  // namespace

std::string decode_objc_type(std::string_view encoding) {
    return decode_objc_type_impl(encoding);
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
