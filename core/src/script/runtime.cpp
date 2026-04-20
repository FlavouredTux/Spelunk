#include <ember/script/runtime.hpp>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <format>
#include <fstream>
#include <memory>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

#include <ember/analysis/fingerprint.hpp>
#include <ember/analysis/libcxx_string.hpp>
#include <ember/analysis/objc.hpp>
#include <ember/analysis/pipeline.hpp>
#include <ember/analysis/strings.hpp>
#include <ember/binary/binary.hpp>
#include <ember/binary/symbol.hpp>

extern "C" {
#include <quickjs.h>
}

namespace ember {

namespace {

struct PendingAnnotations {
    std::map<addr_t, std::string> renames;
    std::map<addr_t, FunctionSig> signatures;
    std::map<addr_t, std::string> notes;

    bool empty() const noexcept {
        return renames.empty() && signatures.empty() && notes.empty();
    }
    void clear() noexcept { renames.clear(); signatures.clear(); notes.clear(); }
};

// Lazy call graph, built once per ScriptRuntime. The first xrefs.callers /
// xrefs.callees / xrefs.to call pays the cost of building a CFG per
// function; subsequent queries are hash lookups.
struct CallGraphCache {
    std::unordered_map<addr_t, std::vector<addr_t>> callers_by_callee;
    std::unordered_map<addr_t, std::vector<addr_t>> callees_by_caller;
};

struct ScriptCtx {
    const Binary*                   binary  = nullptr;
    ProjectContext*                 project = nullptr;   // null: mutation API raises
    PendingAnnotations              pending{};
    std::vector<std::string>        argv{};
    std::unique_ptr<CallGraphCache> call_graph{};        // lazy
    std::vector<addr_t>             function_starts{};   // lazy, sorted
};

const CallGraphCache& ensure_call_graph(ScriptCtx& hc) {
    if (hc.call_graph) return *hc.call_graph;
    hc.call_graph = std::make_unique<CallGraphCache>();
    for (const auto& e : compute_call_graph(*hc.binary)) {
        hc.call_graph->callers_by_callee[e.callee].push_back(e.caller);
        hc.call_graph->callees_by_caller[e.caller].push_back(e.callee);
    }
    auto dedup = [](std::vector<addr_t>& v) {
        std::sort(v.begin(), v.end());
        v.erase(std::unique(v.begin(), v.end()), v.end());
    };
    for (auto& [_, v] : hc.call_graph->callers_by_callee) dedup(v);
    for (auto& [_, v] : hc.call_graph->callees_by_caller) dedup(v);
    return *hc.call_graph;
}

ScriptCtx* ctx_of(JSContext* ctx) noexcept {
    return static_cast<ScriptCtx*>(JS_GetContextOpaque(ctx));
}

JSValue make_str(JSContext* ctx, std::string_view s) {
    return JS_NewStringLen(ctx, s.data(), s.size());
}

JSValue throw_err(JSContext* ctx, std::string_view msg) {
    return JS_ThrowTypeError(ctx, "%.*s",
        static_cast<int>(msg.size()), msg.data());
}

// RAII wrapper around JS_ToCString / JS_FreeCString. `valid()` is false when
// the target value can't be stringified (exception pending on `ctx`).
class ScopedCString {
public:
    ScopedCString(JSContext* ctx, JSValueConst v) noexcept
        : ctx_(ctx), s_(JS_ToCString(ctx, v)) {}
    ~ScopedCString() { if (s_) JS_FreeCString(ctx_, s_); }
    ScopedCString(const ScopedCString&)            = delete;
    ScopedCString& operator=(const ScopedCString&) = delete;

    [[nodiscard]] bool             valid() const noexcept { return s_ != nullptr; }
    [[nodiscard]] const char*      c_str() const noexcept { return s_; }
    [[nodiscard]] std::string_view view() const noexcept {
        return s_ ? std::string_view{s_} : std::string_view{};
    }

private:
    JSContext*  ctx_;
    const char* s_;
};

std::string join_args(JSContext* ctx, int argc, JSValueConst* argv) {
    std::string out;
    for (int i = 0; i < argc; ++i) {
        if (i > 0) out += ' ';
        ScopedCString s(ctx, argv[i]);
        if (s.valid()) out += s.c_str();
    }
    return out;
}

JSValue js_print(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    std::fputs(join_args(ctx, argc, argv).c_str(), stdout);
    std::fputc('\n', stdout);
    return JS_UNDEFINED;
}
JSValue js_log_info(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    std::fprintf(stdout, "[info] %s\n", join_args(ctx, argc, argv).c_str());
    return JS_UNDEFINED;
}
JSValue js_log_warn(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    std::fprintf(stderr, "[warn] %s\n", join_args(ctx, argc, argv).c_str());
    return JS_UNDEFINED;
}
JSValue js_log_error(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    std::fprintf(stderr, "[err]  %s\n", join_args(ctx, argc, argv).c_str());
    return JS_UNDEFINED;
}

std::string_view symbol_kind_str(SymbolKind k) noexcept {
    switch (k) {
        case SymbolKind::Function: return "function";
        case SymbolKind::Object:   return "object";
        case SymbolKind::Section:  return "section";
        case SymbolKind::File:     return "file";
        case SymbolKind::Unknown:  return "unknown";
    }
    return "unknown";
}

JSValue make_symbol_obj(JSContext* ctx, const Symbol& s) {
    JSValue obj = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, obj, "name",     make_str(ctx, s.name));
    JS_SetPropertyStr(ctx, obj, "addr",     JS_NewBigUint64(ctx, s.addr));
    JS_SetPropertyStr(ctx, obj, "size",     JS_NewBigUint64(ctx, s.size));
    JS_SetPropertyStr(ctx, obj, "kind",     make_str(ctx, symbol_kind_str(s.kind)));
    JS_SetPropertyStr(ctx, obj, "isImport", JS_NewBool(ctx, s.is_import));
    JS_SetPropertyStr(ctx, obj, "isExport", JS_NewBool(ctx, s.is_export));
    if (s.got_addr) {
        JS_SetPropertyStr(ctx, obj, "gotAddr", JS_NewBigUint64(ctx, s.got_addr));
    }
    return obj;
}

// Accept either Number or BigInt for addresses.
[[nodiscard]] bool to_u64(JSContext* ctx, JSValueConst v, u64* out) {
    if (JS_IsBigInt(ctx, v)) {
        int64_t tmp = 0;
        if (JS_ToBigInt64(ctx, &tmp, v) < 0) return false;
        *out = static_cast<u64>(tmp);
        return true;
    }
    double d = 0;
    if (JS_ToFloat64(ctx, &d, v) < 0) return false;
    *out = static_cast<u64>(d);
    return true;
}

// Look up a defined function symbol at `addr`. Returns nullptr if none.
[[nodiscard]] const Symbol* defined_fn_at(const Binary& b, addr_t addr) noexcept {
    for (const auto& s : b.symbols()) {
        if (s.is_import) continue;
        if (s.addr == addr && !s.name.empty()) return &s;
    }
    return nullptr;
}

// String → symbol name, number/bigint → address.
std::optional<FuncWindow>
resolve_js_target(JSContext* ctx, const Binary& b, JSValueConst v) {
    if (JS_IsString(v)) {
        ScopedCString s(ctx, v);
        if (!s.valid()) return std::nullopt;
        return resolve_function(b, s.view());
    }
    u64 addr = 0;
    if (!to_u64(ctx, v, &addr)) return std::nullopt;
    return resolve_function_at(b, static_cast<addr_t>(addr));
}

JSValue js_symbols(JSContext* ctx, JSValueConst, int, JSValueConst*) {
    const Binary* b = ctx_of(ctx)->binary;
    JSValue arr = JS_NewArray(ctx);
    u32 i = 0;
    for (const auto& s : b->symbols()) {
        JS_SetPropertyUint32(ctx, arr, i++, make_symbol_obj(ctx, s));
    }
    return arr;
}

JSValue js_sections(JSContext* ctx, JSValueConst, int, JSValueConst*) {
    const Binary* b = ctx_of(ctx)->binary;
    JSValue arr = JS_NewArray(ctx);
    u32 i = 0;
    for (const auto& s : b->sections()) {
        JSValue obj = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, obj, "name",       make_str(ctx, s.name));
        JS_SetPropertyStr(ctx, obj, "addr",       JS_NewBigUint64(ctx, s.vaddr));
        JS_SetPropertyStr(ctx, obj, "size",       JS_NewBigUint64(ctx, s.size));
        JS_SetPropertyStr(ctx, obj, "readable",   JS_NewBool(ctx, s.flags.readable));
        JS_SetPropertyStr(ctx, obj, "writable",   JS_NewBool(ctx, s.flags.writable));
        JS_SetPropertyStr(ctx, obj, "executable", JS_NewBool(ctx, s.flags.executable));
        JS_SetPropertyUint32(ctx, arr, i++, obj);
    }
    return arr;
}

JSValue js_find_symbol(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NULL;
    ScopedCString n(ctx, argv[0]);
    if (!n.valid()) return JS_NULL;
    const Binary* b = ctx_of(ctx)->binary;
    if (const Symbol* s = b->find_by_name(n.view()); s) return make_symbol_obj(ctx, *s);
    return JS_NULL;
}

JSValue js_symbol_at(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NULL;
    u64 addr = 0;
    if (!to_u64(ctx, argv[0], &addr)) return JS_NULL;
    const Binary* b = ctx_of(ctx)->binary;
    for (const auto& s : b->symbols()) {
        if (!s.is_import && s.addr == addr && !s.name.empty())
            return make_symbol_obj(ctx, s);
    }
    if (const Symbol* s = b->defined_object_at(static_cast<addr_t>(addr)); s) {
        return make_symbol_obj(ctx, *s);
    }
    return JS_NULL;
}

// Parse a hex pattern of the form "b8 ?? ?? c3" into (nibble-pair, mask) bytes.
// Spaces, tabs, and commas are skipped. `??` matches any byte; every other
// pair is an exact hex byte. Returns false on any odd/invalid input.
[[nodiscard]] bool parse_hex_pattern(std::string_view pat,
                                     std::vector<u8>& bytes,
                                     std::vector<u8>& mask) {
    auto is_ws = [](char c) { return c == ' ' || c == '\t' || c == ',' || c == '\n'; };
    auto hex_val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + c - 'a';
        if (c >= 'A' && c <= 'F') return 10 + c - 'A';
        return -1;
    };
    std::size_t i = 0;
    while (i < pat.size()) {
        while (i < pat.size() && is_ws(pat[i])) ++i;
        if (i >= pat.size()) break;
        if (i + 1 >= pat.size()) return false;
        const char c0 = pat[i], c1 = pat[i + 1];
        if (c0 == '?' && c1 == '?') {
            bytes.push_back(0);
            mask.push_back(0);
        } else {
            const int hi = hex_val(c0);
            const int lo = hex_val(c1);
            if (hi < 0 || lo < 0) return false;
            bytes.push_back(static_cast<u8>((hi << 4) | lo));
            mask.push_back(0xff);
        }
        i += 2;
    }
    return !bytes.empty();
}

JSValue js_find_bytes(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return throw_err(ctx, "findBytes: missing pattern");
    ScopedCString pattern(ctx, argv[0]);
    if (!pattern.valid()) return throw_err(ctx, "findBytes: bad pattern");

    std::vector<u8> needle;
    std::vector<u8> mask;
    if (!parse_hex_pattern(pattern.view(), needle, mask)) {
        return throw_err(ctx, "findBytes: bad hex pattern");
    }
    // findBytes scans executable sections only; data matches are usually
    // coincidental. Callers wanting data search should use a different API.

    u64 cap = 1024;
    if (argc >= 2 && !JS_IsUndefined(argv[1]) && !JS_IsNull(argv[1])) {
        if (!to_u64(ctx, argv[1], &cap)) return throw_err(ctx, "findBytes: bad max");
    }

    const Binary* b = ctx_of(ctx)->binary;
    JSValue arr = JS_NewArray(ctx);
    u32 n_out = 0;
    for (const auto& s : b->sections()) {
        // Executable sections only; data matches are usually coincidental.
        if (!s.flags.executable) continue;
        if (s.data.empty() || s.data.size() < needle.size()) continue;
        const auto* raw = reinterpret_cast<const u8*>(s.data.data());
        const std::size_t end = s.data.size() - needle.size() + 1;
        for (std::size_t i = 0; i < end; ++i) {
            bool hit = true;
            for (std::size_t j = 0; j < needle.size(); ++j) {
                if ((raw[i + j] & mask[j]) != (needle[j] & mask[j])) { hit = false; break; }
            }
            if (!hit) continue;
            JS_SetPropertyUint32(ctx, arr, n_out++,
                JS_NewBigUint64(ctx, s.vaddr + static_cast<addr_t>(i)));
            if (n_out >= cap) return arr;
        }
    }
    return arr;
}

JSValue js_string_at(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NULL;
    u64 addr = 0;
    if (!to_u64(ctx, argv[0], &addr)) return JS_NULL;
    u64 max = 1024;
    if (argc >= 2 && !JS_IsUndefined(argv[1]) && !JS_IsNull(argv[1])) {
        if (!to_u64(ctx, argv[1], &max)) return JS_NULL;
    }

    const Binary* b = ctx_of(ctx)->binary;
    auto span = b->bytes_at(static_cast<addr_t>(addr));
    if (span.empty()) return JS_NULL;

    const auto* raw = reinterpret_cast<const unsigned char*>(span.data());
    const std::size_t cap = std::min<std::size_t>(span.size(), static_cast<std::size_t>(max));
    std::string out;
    for (std::size_t i = 0; i < cap; ++i) {
        const unsigned char c = raw[i];
        if (c == 0) return make_str(ctx, out);
        // Accept printable ASCII + common whitespace; bail on anything else
        // so we don't return garbage from mid-code reads.
        if (c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c <= 0x7e)) {
            out.push_back(static_cast<char>(c));
        } else {
            return out.empty() ? JS_NULL : make_str(ctx, out);
        }
    }
    return make_str(ctx, out);
}

JSValue js_bytes_at(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NULL;
    u64 addr = 0;
    if (!to_u64(ctx, argv[0], &addr)) return JS_NULL;
    u64 n = 16;
    if (argc >= 2) { if (!to_u64(ctx, argv[1], &n)) return JS_NULL; }
    if (n > 1024 * 1024) n = 1024 * 1024;

    const Binary* b = ctx_of(ctx)->binary;
    auto span = b->bytes_at(static_cast<addr_t>(addr));
    if (span.empty()) return JS_NewArrayBufferCopy(ctx, nullptr, 0);
    const std::size_t take = std::min<std::size_t>(span.size(), static_cast<std::size_t>(n));
    return JS_NewArrayBufferCopy(ctx,
        reinterpret_cast<const uint8_t*>(span.data()), take);
}

JSValue js_bin_decompile(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return throw_err(ctx, "decompile: missing addr");
    const Binary* b = ctx_of(ctx)->binary;
    auto win = resolve_js_target(ctx, *b, argv[0]);
    if (!win) return throw_err(ctx, "decompile: address/symbol not found");
    auto rv = format_struct(*b, *win, /*pseudo=*/true, nullptr);
    if (!rv) return throw_err(ctx, rv.error().message);
    return make_str(ctx, *rv);
}

JSValue js_bin_disasm(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return throw_err(ctx, "disasm: missing addr");
    const Binary* b = ctx_of(ctx)->binary;
    auto win = resolve_js_target(ctx, *b, argv[0]);
    if (!win) return throw_err(ctx, "disasm: address/symbol not found");

    if (argc >= 2 && !JS_IsUndefined(argv[1]) && !JS_IsNull(argv[1])) {
        u64 n_bytes = 0;
        if (!to_u64(ctx, argv[1], &n_bytes))
            return throw_err(ctx, "disasm: invalid byte count");
        win->size = n_bytes;
    }

    auto rv = format_disasm(*b, *win);
    if (!rv) return throw_err(ctx, rv.error().message);
    return make_str(ctx, *rv);
}

JSValue js_bin_disasm_range(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 2) return throw_err(ctx, "disasmRange: need (start, end)");
    const Binary* b = ctx_of(ctx)->binary;
    u64 start = 0, end = 0;
    if (!to_u64(ctx, argv[0], &start)) return throw_err(ctx, "disasmRange: bad start");
    if (!to_u64(ctx, argv[1], &end))   return throw_err(ctx, "disasmRange: bad end");
    auto rv = format_disasm_range(*b, start, end);
    if (!rv) return throw_err(ctx, rv.error().message);
    return make_str(ctx, *rv);
}

JSValue js_bin_cfg(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return throw_err(ctx, "cfg: missing addr");
    const Binary* b = ctx_of(ctx)->binary;
    auto win = resolve_js_target(ctx, *b, argv[0]);
    if (!win) return throw_err(ctx, "cfg: address/symbol not found");
    auto rv = format_cfg(*b, *win);
    if (!rv) return throw_err(ctx, rv.error().message);
    return make_str(ctx, *rv);
}

// Decode a libc++ std::string object at `addr`. Returns the string
// contents or null when the bytes don't look like a valid string object.
// Useful when a local is constructed via std::string's ctor and you want
// to see what literal / runtime value it holds in memory.
JSValue js_bin_std_string(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return throw_err(ctx, "stdString: missing addr");
    const Binary* b = ctx_of(ctx)->binary;
    u64 addr = 0;
    if (!to_u64(ctx, argv[0], &addr)) return throw_err(ctx, "stdString: bad addr");
    auto s = decode_libcxx_string(*b, static_cast<addr_t>(addr));
    if (!s) return JS_NULL;
    return make_str(ctx, *s);
}

// Every Objective-C method the runtime parser could recover from
// __objc_classlist. Each entry is
//   {addr, class, selector, isClass, types, signature}
JSValue js_bin_objc_methods(JSContext* ctx, JSValueConst, int, JSValueConst*) {
    const Binary* b = ctx_of(ctx)->binary;
    JSValue arr = JS_NewArray(ctx);
    u32 i = 0;
    for (const auto& m : parse_objc_methods(*b)) {
        JSValue o = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, o, "addr",      JS_NewBigUint64(ctx, m.imp));
        JS_SetPropertyStr(ctx, o, "class",     make_str(ctx, m.cls));
        JS_SetPropertyStr(ctx, o, "selector",  make_str(ctx, m.selector));
        JS_SetPropertyStr(ctx, o, "isClass",   JS_NewBool(ctx, m.is_class));
        JS_SetPropertyStr(ctx, o, "types",     make_str(ctx, m.type_encoding));
        JS_SetPropertyStr(ctx, o, "signature", make_str(ctx, decode_objc_type(m.type_encoding)));
        JS_SetPropertyUint32(ctx, arr, i++, o);
    }
    return arr;
}

// Every formal Obj-C protocol with its method signatures. Protocols
// carry signatures only (no IMPs). Each entry:
//   { name, conformsTo: [], required: {instance: [], class: []},
//     optional: {instance: [], class: []} }
JSValue js_bin_objc_protocols(JSContext* ctx, JSValueConst, int, JSValueConst*) {
    const Binary* b = ctx_of(ctx)->binary;
    JSValue arr = JS_NewArray(ctx);
    u32 i = 0;
    auto method_arr = [&](const std::vector<ObjcMethod>& methods) {
        JSValue a = JS_NewArray(ctx);
        u32 j = 0;
        for (const auto& m : methods) {
            JSValue mv = JS_NewObject(ctx);
            JS_SetPropertyStr(ctx, mv, "selector",  make_str(ctx, m.selector));
            JS_SetPropertyStr(ctx, mv, "types",     make_str(ctx, m.type_encoding));
            JS_SetPropertyStr(ctx, mv, "signature", make_str(ctx, decode_objc_type(m.type_encoding)));
            JS_SetPropertyUint32(ctx, a, j++, mv);
        }
        return a;
    };
    for (const auto& p : parse_objc_protocols(*b)) {
        JSValue o = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, o, "name", make_str(ctx, p.name));
        JSValue c = JS_NewArray(ctx);
        for (u32 j = 0; j < p.conforms_to.size(); ++j) {
            JS_SetPropertyUint32(ctx, c, j, make_str(ctx, p.conforms_to[j]));
        }
        JS_SetPropertyStr(ctx, o, "conformsTo", c);
        JSValue req = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, req, "instance", method_arr(p.required_instance));
        JS_SetPropertyStr(ctx, req, "class",    method_arr(p.required_class));
        JS_SetPropertyStr(ctx, o, "required", req);
        JSValue opt = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, opt, "instance", method_arr(p.optional_instance));
        JS_SetPropertyStr(ctx, opt, "class",    method_arr(p.optional_class));
        JS_SetPropertyStr(ctx, o, "optional", opt);
        JS_SetPropertyUint32(ctx, arr, i++, o);
    }
    return arr;
}

// Address-independent content hash of the function at `addr`. Scripts use
// this to move names forward across binary versions — see
// scripts/apply-names.js.
JSValue js_bin_fingerprint(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return throw_err(ctx, "fingerprint: missing addr");
    const Binary* b = ctx_of(ctx)->binary;
    auto win = resolve_js_target(ctx, *b, argv[0]);
    if (!win) return throw_err(ctx, "fingerprint: address/symbol not found");
    const auto fp = compute_fingerprint(*b, win->start);
    if (fp.hash == 0) return JS_NULL;
    JSValue o = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, o, "hash",
        make_str(ctx, std::format("{:016x}", fp.hash)));
    JS_SetPropertyStr(ctx, o, "blocks", JS_NewUint32(ctx, fp.blocks));
    JS_SetPropertyStr(ctx, o, "insts",  JS_NewUint32(ctx, fp.insts));
    JS_SetPropertyStr(ctx, o, "calls",  JS_NewUint32(ctx, fp.calls));
    return o;
}

JSValue js_bin_functions(JSContext* ctx, JSValueConst, int, JSValueConst*);

JSValue addr_name_obj(JSContext* ctx, const Binary& b, addr_t a) {
    JSValue o = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, o, "addr", JS_NewBigUint64(ctx, a));
    std::string name;
    if (const Symbol* s = defined_fn_at(b, a); s) {
        name = s->name;
    } else if (const Symbol* p = b.import_at_plt(a); p) {
        name = p->name;
    } else {
        name = std::format("sub_{:x}", a);
    }
    JS_SetPropertyStr(ctx, o, "name", make_str(ctx, name));
    return o;
}

// Every function entry the CFG builder can walk from. Union of named
// function symbols and direct call targets, deduplicated. Lets scripts
// iterate the binary without re-discovering entry points themselves.
JSValue js_bin_functions(JSContext* ctx, JSValueConst, int, JSValueConst*) {
    const Binary* b = ctx_of(ctx)->binary;
    std::set<addr_t> fns;
    for (const auto& s : b->symbols()) {
        if (s.is_import) continue;
        if (s.kind != SymbolKind::Function) continue;
        if (s.addr == 0 || s.name.empty()) continue;
        fns.insert(s.addr);
    }
    for (const auto& e : compute_call_graph(*b)) {
        // Call targets that aren't import stubs land here — the `sub_*`
        // functions the user actually wants to name.
        if (!b->import_at_plt(e.callee)) fns.insert(e.callee);
    }
    JSValue arr = JS_NewArray(ctx);
    u32 i = 0;
    for (addr_t a : fns) {
        JS_SetPropertyUint32(ctx, arr, i++, addr_name_obj(ctx, *b, a));
    }
    return arr;
}

// Return the entry address of the function whose extent contains `addr`,
// or null when no containing function is known. Uses the discovered set
// from binary.functions() — O(log n) per query after a one-shot sort
// cached on the ScriptCtx.
JSValue js_bin_function_at(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NULL;
    u64 addr = 0;
    if (!to_u64(ctx, argv[0], &addr)) return JS_NULL;
    auto& hc = *ctx_of(ctx);
    if (hc.function_starts.empty()) {
        std::set<addr_t> fns;
        for (const auto& s : hc.binary->symbols()) {
            if (s.is_import) continue;
            if (s.kind != SymbolKind::Function) continue;
            if (s.addr == 0 || s.name.empty()) continue;
            fns.insert(s.addr);
        }
        for (const auto& e : compute_call_graph(*hc.binary)) {
            if (!hc.binary->import_at_plt(e.callee)) fns.insert(e.callee);
        }
        hc.function_starts.assign(fns.begin(), fns.end());
    }
    // upper_bound - 1 gives the largest start <= addr.
    auto it = std::upper_bound(hc.function_starts.begin(),
                               hc.function_starts.end(),
                               static_cast<addr_t>(addr));
    if (it == hc.function_starts.begin()) return JS_NULL;
    --it;
    return addr_name_obj(ctx, *hc.binary, *it);
}

JSValue js_xrefs_callees(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewArray(ctx);
    u64 addr = 0;
    if (!to_u64(ctx, argv[0], &addr)) return JS_NewArray(ctx);
    auto& hc = *ctx_of(ctx);
    const auto& g = ensure_call_graph(hc);
    JSValue arr = JS_NewArray(ctx);
    u32 i = 0;
    auto it = g.callees_by_caller.find(static_cast<addr_t>(addr));
    if (it != g.callees_by_caller.end()) {
        for (addr_t t : it->second) {
            JS_SetPropertyUint32(ctx, arr, i++, addr_name_obj(ctx, *hc.binary, t));
        }
    }
    return arr;
}

JSValue js_xrefs_callers(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewArray(ctx);
    u64 addr = 0;
    if (!to_u64(ctx, argv[0], &addr)) return JS_NewArray(ctx);
    auto& hc = *ctx_of(ctx);
    const auto& g = ensure_call_graph(hc);
    JSValue arr = JS_NewArray(ctx);
    u32 i = 0;
    auto it = g.callers_by_callee.find(static_cast<addr_t>(addr));
    if (it != g.callers_by_callee.end()) {
        for (addr_t c : it->second) {
            JS_SetPropertyUint32(ctx, arr, i++, addr_name_obj(ctx, *hc.binary, c));
        }
    }
    return arr;
}

// Aliased to callers for now; data xrefs live on strings.*.
JSValue js_xrefs_to(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    return js_xrefs_callers(ctx, this_val, argc, argv);
}

void install_xrefs_global(JSContext* ctx) {
    JSValue global = JS_GetGlobalObject(ctx);
    JSValue obj = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, obj, "to",      JS_NewCFunction(ctx, js_xrefs_to,      "to",      1));
    JS_SetPropertyStr(ctx, obj, "callers", JS_NewCFunction(ctx, js_xrefs_callers, "callers", 1));
    JS_SetPropertyStr(ctx, obj, "callees", JS_NewCFunction(ctx, js_xrefs_callees, "callees", 1));
    JS_SetPropertyStr(ctx, global, "xrefs", obj);
    JS_FreeValue(ctx, global);
}

// Accept a JS string (raw pattern) or a RegExp (read .source + .flags).
bool build_regex(JSContext* ctx, JSValueConst v,
                 std::regex& out, std::string& err) {
    std::string pattern;
    bool icase = false;

    if (JS_IsString(v)) {
        ScopedCString s(ctx, v);
        if (!s.valid()) { err = "strings: invalid pattern"; return false; }
        pattern.assign(s.view());
    } else if (JS_IsObject(v)) {
        JSValue src = JS_GetPropertyStr(ctx, v, "source");
        JSValue flg = JS_GetPropertyStr(ctx, v, "flags");
        if (ScopedCString p(ctx, src); p.valid()) pattern.assign(p.view());
        if (ScopedCString f(ctx, flg); f.valid()) icase = f.view().find('i') != std::string_view::npos;
        JS_FreeValue(ctx, src);
        JS_FreeValue(ctx, flg);
        if (pattern.empty()) { err = "strings: RegExp missing source"; return false; }
    } else {
        err = "strings: pattern must be string or RegExp";
        return false;
    }

    try {
        auto flags = std::regex::ECMAScript;
        if (icase) flags |= std::regex::icase;
        out = std::regex(pattern, flags);
    } catch (const std::regex_error& e) {
        err = std::format("strings: bad regex: {}", e.what());
        return false;
    }
    return true;
}

[[nodiscard]] JSValue string_entry_obj(JSContext* ctx, const StringEntry& e) {
    JSValue o = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, o, "addr", JS_NewBigUint64(ctx, e.addr));
    JS_SetPropertyStr(ctx, o, "text", make_str(ctx, e.text));
    JSValue xarr = JS_NewArray(ctx);
    u32 i = 0;
    for (addr_t x : e.xrefs) {
        JS_SetPropertyUint32(ctx, xarr, i++, JS_NewBigUint64(ctx, x));
    }
    JS_SetPropertyStr(ctx, o, "xrefs", xarr);
    return o;
}

JSValue js_strings_search(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return throw_err(ctx, "strings.search: missing pattern");
    std::regex re;
    std::string err;
    if (!build_regex(ctx, argv[0], re, err)) return throw_err(ctx, err);

    const Binary* b = ctx_of(ctx)->binary;
    auto all = scan_strings(*b);
    JSValue arr = JS_NewArray(ctx);
    u32 i = 0;
    for (const auto& e : all) {
        if (std::regex_search(e.text, re)) {
            JS_SetPropertyUint32(ctx, arr, i++, string_entry_obj(ctx, e));
        }
    }
    return arr;
}

// Same as search, but drops strings with no xrefs.
JSValue js_strings_xrefs(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return throw_err(ctx, "strings.xrefs: missing pattern");
    std::regex re;
    std::string err;
    if (!build_regex(ctx, argv[0], re, err)) return throw_err(ctx, err);

    const Binary* b = ctx_of(ctx)->binary;
    auto all = scan_strings(*b);
    JSValue arr = JS_NewArray(ctx);
    u32 i = 0;
    for (const auto& e : all) {
        if (e.xrefs.empty()) continue;
        if (std::regex_search(e.text, re)) {
            JS_SetPropertyUint32(ctx, arr, i++, string_entry_obj(ctx, e));
        }
    }
    return arr;
}

void install_strings_global(JSContext* ctx) {
    JSValue global = JS_GetGlobalObject(ctx);
    JSValue obj = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, obj, "search", JS_NewCFunction(ctx, js_strings_search, "search", 1));
    JS_SetPropertyStr(ctx, obj, "xrefs",  JS_NewCFunction(ctx, js_strings_xrefs,  "xrefs",  1));
    JS_SetPropertyStr(ctx, global, "strings", obj);
    JS_FreeValue(ctx, global);
}

bool parse_addr_arg(JSContext* ctx, JSValueConst v, addr_t* out) {
    u64 a = 0;
    if (!to_u64(ctx, v, &a)) return false;
    *out = static_cast<addr_t>(a);
    return true;
}

bool is_dry_run(JSContext* ctx, JSValueConst opts) {
    if (!JS_IsObject(opts)) return false;
    JSValue v = JS_GetPropertyStr(ctx, opts, "dryRun");
    const bool dry = JS_ToBool(ctx, v) > 0;
    JS_FreeValue(ctx, v);
    return dry;
}

JSValue make_diff_entry(JSContext* ctx, std::string_view kind,
                                      addr_t a, std::string_view detail) {
    JSValue o = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, o, "kind",   make_str(ctx, kind));
    JS_SetPropertyStr(ctx, o, "addr",   JS_NewBigUint64(ctx, a));
    JS_SetPropertyStr(ctx, o, "detail", make_str(ctx, detail));
    return o;
}

JSValue require_project(JSContext* ctx) {
    auto* hc = ctx_of(ctx);
    if (!hc->project) {
        return throw_err(ctx,
            "project.*: no --project passed; mutations are read-only");
    }
    return JS_UNDEFINED;
}

JSValue js_project_rename(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (JSValue err = require_project(ctx); !JS_IsUndefined(err)) return err;
    if (argc < 2) return throw_err(ctx, "rename: (addr, name[, opts])");
    addr_t a = 0;
    if (!parse_addr_arg(ctx, argv[0], &a)) return throw_err(ctx, "rename: bad addr");
    ScopedCString n(ctx, argv[1]);
    if (!n.valid()) return throw_err(ctx, "rename: bad name");
    std::string name{n.view()};

    auto* hc = ctx_of(ctx);
    const bool dry = argc >= 3 && is_dry_run(ctx, argv[2]);
    JSValue diff = make_diff_entry(ctx, "rename", a, name);
    if (!dry) hc->pending.renames[a] = std::move(name);
    return diff;
}

JSValue js_project_set_signature(JSContext* ctx, JSValueConst,
                                 int argc, JSValueConst* argv) {
    if (JSValue err = require_project(ctx); !JS_IsUndefined(err)) return err;
    if (argc < 2) return throw_err(ctx, "setSignature: (addr, sig[, opts])");
    addr_t a = 0;
    if (!parse_addr_arg(ctx, argv[0], &a)) return throw_err(ctx, "setSignature: bad addr");
    if (!JS_IsObject(argv[1]))
        return throw_err(ctx, "setSignature: sig must be {returnType, params:[{type,name}]}");

    FunctionSig sig;
    {
        JSValue rt = JS_GetPropertyStr(ctx, argv[1], "returnType");
        if (ScopedCString s(ctx, rt); s.valid()) sig.return_type = s.view();
        JS_FreeValue(ctx, rt);
    }
    {
        JSValue params = JS_GetPropertyStr(ctx, argv[1], "params");
        if (JS_IsArray(params)) {
            JSValue lenv = JS_GetPropertyStr(ctx, params, "length");
            uint32_t len = 0;
            JS_ToUint32(ctx, &len, lenv);
            JS_FreeValue(ctx, lenv);
            for (uint32_t i = 0; i < len; ++i) {
                JSValue p = JS_GetPropertyUint32(ctx, params, i);
                ParamSig ps;
                JSValue t = JS_GetPropertyStr(ctx, p, "type");
                JSValue nm = JS_GetPropertyStr(ctx, p, "name");
                if (ScopedCString s(ctx, t);  s.valid()) ps.type = s.view();
                if (ScopedCString s(ctx, nm); s.valid()) ps.name = s.view();
                JS_FreeValue(ctx, t);
                JS_FreeValue(ctx, nm);
                JS_FreeValue(ctx, p);
                if (!ps.type.empty()) sig.params.push_back(std::move(ps));
            }
        }
        JS_FreeValue(ctx, params);
    }

    std::string detail = sig.return_type + "(";
    for (std::size_t i = 0; i < sig.params.size(); ++i) {
        if (i) detail += ", ";
        detail += sig.params[i].type + " " + sig.params[i].name;
    }
    detail += ")";

    auto* hc = ctx_of(ctx);
    const bool dry = argc >= 3 && is_dry_run(ctx, argv[2]);
    JSValue diff = make_diff_entry(ctx, "sig", a, detail);
    if (!dry) hc->pending.signatures[a] = std::move(sig);
    return diff;
}

JSValue js_project_note(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (JSValue err = require_project(ctx); !JS_IsUndefined(err)) return err;
    if (argc < 2) return throw_err(ctx, "note: (addr, text[, opts])");
    addr_t a = 0;
    if (!parse_addr_arg(ctx, argv[0], &a)) return throw_err(ctx, "note: bad addr");
    ScopedCString n(ctx, argv[1]);
    if (!n.valid()) return throw_err(ctx, "note: bad text");
    std::string text{n.view()};

    auto* hc = ctx_of(ctx);
    const bool dry = argc >= 3 && is_dry_run(ctx, argv[2]);
    JSValue diff = make_diff_entry(ctx, "note", a, text);
    if (!dry) hc->pending.notes[a] = std::move(text);
    return diff;
}

JSValue js_project_diff(JSContext* ctx, JSValueConst, int, JSValueConst*) {
    if (JSValue err = require_project(ctx); !JS_IsUndefined(err)) return err;
    auto* hc = ctx_of(ctx);
    JSValue arr = JS_NewArray(ctx);
    u32 i = 0;
    for (const auto& [a, n] : hc->pending.renames) {
        JS_SetPropertyUint32(ctx, arr, i++, make_diff_entry(ctx, "rename", a, n));
    }
    for (const auto& [a, s] : hc->pending.signatures) {
        std::string detail = s.return_type + "(";
        for (std::size_t k = 0; k < s.params.size(); ++k) {
            if (k) detail += ", ";
            detail += s.params[k].type + " " + s.params[k].name;
        }
        detail += ")";
        JS_SetPropertyUint32(ctx, arr, i++, make_diff_entry(ctx, "sig", a, detail));
    }
    for (const auto& [a, t] : hc->pending.notes) {
        JS_SetPropertyUint32(ctx, arr, i++, make_diff_entry(ctx, "note", a, t));
    }
    return arr;
}

JSValue js_project_commit(JSContext* ctx, JSValueConst, int, JSValueConst*) {
    if (JSValue err = require_project(ctx); !JS_IsUndefined(err)) return err;
    auto* hc = ctx_of(ctx);
    if (hc->pending.empty()) return JS_NewInt32(ctx, 0);

    for (auto& [a, n] : hc->pending.renames)    hc->project->loaded.renames[a]    = n;
    for (auto& [a, s] : hc->pending.signatures) hc->project->loaded.signatures[a] = s;
    for (auto& [a, t] : hc->pending.notes)      hc->project->loaded.notes[a]      = t;

    const std::size_t n = hc->pending.renames.size()
                        + hc->pending.signatures.size()
                        + hc->pending.notes.size();

    auto rv = hc->project->loaded.save(hc->project->path);
    if (!rv) return throw_err(ctx, rv.error().message);
    hc->pending.clear();
    return JS_NewInt32(ctx, static_cast<int32_t>(n));
}

JSValue js_project_revert(JSContext* ctx, JSValueConst, int, JSValueConst*) {
    if (JSValue err = require_project(ctx); !JS_IsUndefined(err)) return err;
    auto* hc = ctx_of(ctx);
    const std::size_t n = hc->pending.renames.size()
                        + hc->pending.signatures.size()
                        + hc->pending.notes.size();
    hc->pending.clear();
    return JS_NewInt32(ctx, static_cast<int32_t>(n));
}

void install_project_global(JSContext* ctx) {
    JSValue global = JS_GetGlobalObject(ctx);
    JSValue obj = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, obj, "rename",
        JS_NewCFunction(ctx, js_project_rename,        "rename",       3));
    JS_SetPropertyStr(ctx, obj, "setSignature",
        JS_NewCFunction(ctx, js_project_set_signature, "setSignature", 3));
    JS_SetPropertyStr(ctx, obj, "note",
        JS_NewCFunction(ctx, js_project_note,          "note",         3));
    JS_SetPropertyStr(ctx, obj, "diff",
        JS_NewCFunction(ctx, js_project_diff,          "diff",         0));
    JS_SetPropertyStr(ctx, obj, "commit",
        JS_NewCFunction(ctx, js_project_commit,        "commit",       0));
    JS_SetPropertyStr(ctx, obj, "revert",
        JS_NewCFunction(ctx, js_project_revert,        "revert",       0));
    JS_SetPropertyStr(ctx, global, "project", obj);
    JS_FreeValue(ctx, global);
}

void install_binary_global(JSContext* ctx) {
    const Binary* b = ctx_of(ctx)->binary;
    JSValue global = JS_GetGlobalObject(ctx);
    JSValue bin = JS_NewObject(ctx);

    const char* arch = [&]() {
        switch (b->arch()) {
            case Arch::X86_64:  return "x86_64";
            case Arch::X86:     return "x86";
            case Arch::Arm64:   return "arm64";
            case Arch::Arm:     return "arm";
            case Arch::Riscv32: return "riscv32";
            case Arch::Riscv64: return "riscv64";
            default:            return "unknown";
        }
    }();
    const char* fmt = [&]() {
        switch (b->format()) {
            case Format::Elf:   return "elf";
            case Format::MachO: return "mach-o";
            case Format::Pe:    return "pe";
            default:            return "unknown";
        }
    }();
    JS_SetPropertyStr(ctx, bin, "arch",   make_str(ctx, arch));
    JS_SetPropertyStr(ctx, bin, "format", make_str(ctx, fmt));
    JS_SetPropertyStr(ctx, bin, "entry",  JS_NewBigUint64(ctx, b->entry_point()));

    JS_SetPropertyStr(ctx, bin, "symbols",
        JS_NewCFunction(ctx, js_symbols,      "symbols",     0));
    JS_SetPropertyStr(ctx, bin, "sections",
        JS_NewCFunction(ctx, js_sections,     "sections",    0));
    JS_SetPropertyStr(ctx, bin, "findSymbol",
        JS_NewCFunction(ctx, js_find_symbol,  "findSymbol",  1));
    JS_SetPropertyStr(ctx, bin, "symbolAt",
        JS_NewCFunction(ctx, js_symbol_at,    "symbolAt",    1));
    JS_SetPropertyStr(ctx, bin, "bytesAt",
        JS_NewCFunction(ctx, js_bytes_at,     "bytesAt",     2));
    JS_SetPropertyStr(ctx, bin, "findBytes",
        JS_NewCFunction(ctx, js_find_bytes,   "findBytes",   2));
    JS_SetPropertyStr(ctx, bin, "stringAt",
        JS_NewCFunction(ctx, js_string_at,    "stringAt",    2));
    JS_SetPropertyStr(ctx, bin, "decompile",
        JS_NewCFunction(ctx, js_bin_decompile, "decompile",  1));
    JS_SetPropertyStr(ctx, bin, "disasm",
        JS_NewCFunction(ctx, js_bin_disasm,   "disasm",      2));
    JS_SetPropertyStr(ctx, bin, "disasmRange",
        JS_NewCFunction(ctx, js_bin_disasm_range, "disasmRange", 2));
    JS_SetPropertyStr(ctx, bin, "cfg",
        JS_NewCFunction(ctx, js_bin_cfg,      "cfg",         1));
    JS_SetPropertyStr(ctx, bin, "fingerprint",
        JS_NewCFunction(ctx, js_bin_fingerprint, "fingerprint", 1));
    JS_SetPropertyStr(ctx, bin, "functions",
        JS_NewCFunction(ctx, js_bin_functions,   "functions",   0));
    JS_SetPropertyStr(ctx, bin, "functionAt",
        JS_NewCFunction(ctx, js_bin_function_at,  "functionAt",  1));
    JS_SetPropertyStr(ctx, bin, "stdString",
        JS_NewCFunction(ctx, js_bin_std_string,  "stdString",   1));
    JS_SetPropertyStr(ctx, bin, "objcMethods",
        JS_NewCFunction(ctx, js_bin_objc_methods, "objcMethods", 0));
    JS_SetPropertyStr(ctx, bin, "objcProtocols",
        JS_NewCFunction(ctx, js_bin_objc_protocols, "objcProtocols", 0));

    JS_SetPropertyStr(ctx, global, "binary", bin);
    JS_FreeValue(ctx, global);
}

void install_argv_global(JSContext* ctx) {
    const auto& args = ctx_of(ctx)->argv;
    JSValue global = JS_GetGlobalObject(ctx);
    JSValue arr = JS_NewArray(ctx);
    u32 i = 0;
    for (const auto& a : args) {
        JS_SetPropertyUint32(ctx, arr, i++, make_str(ctx, a));
    }
    JS_SetPropertyStr(ctx, global, "argv", arr);
    JS_FreeValue(ctx, global);
}

void install_log_global(JSContext* ctx) {
    JSValue global = JS_GetGlobalObject(ctx);
    JSValue log = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, log, "info",  JS_NewCFunction(ctx, js_log_info,  "info",  1));
    JS_SetPropertyStr(ctx, log, "warn",  JS_NewCFunction(ctx, js_log_warn,  "warn",  1));
    JS_SetPropertyStr(ctx, log, "error", JS_NewCFunction(ctx, js_log_error, "error", 1));
    JS_SetPropertyStr(ctx, global, "log", log);
    JS_SetPropertyStr(ctx, global, "print", JS_NewCFunction(ctx, js_print, "print", 1));
    JS_FreeValue(ctx, global);
}

// Minimal text file I/O — enough for scripts to manage their own sidecar
// databases (fingerprint tables, custom signature packs, etc.). Path is
// whatever the host resolves; no chroot. Scripts run with the same
// privileges as the `ember` process invoking them.
JSValue js_io_read(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return throw_err(ctx, "io.read: missing path");
    ScopedCString p(ctx, argv[0]);
    if (!p.valid()) return throw_err(ctx, "io.read: bad path");
    std::ifstream f(std::string{p.view()});
    if (!f) return throw_err(ctx, std::format("io.read: cannot open '{}'", p.view()));
    std::stringstream ss;
    ss << f.rdbuf();
    return make_str(ctx, ss.str());
}

JSValue js_io_write(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 2) return throw_err(ctx, "io.write: (path, content)");
    ScopedCString p(ctx, argv[0]);
    ScopedCString c(ctx, argv[1]);
    if (!p.valid() || !c.valid()) return throw_err(ctx, "io.write: bad args");
    std::ofstream f(std::string{p.view()}, std::ios::trunc);
    if (!f) return throw_err(ctx, std::format("io.write: cannot open '{}'", p.view()));
    const auto sv = c.view();
    f.write(sv.data(), static_cast<std::streamsize>(sv.size()));
    if (!f) return throw_err(ctx, std::format("io.write: short write to '{}'", p.view()));
    return JS_UNDEFINED;
}

void install_io_global(JSContext* ctx) {
    JSValue global = JS_GetGlobalObject(ctx);
    JSValue io = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, io, "read",  JS_NewCFunction(ctx, js_io_read,  "read",  1));
    JS_SetPropertyStr(ctx, io, "write", JS_NewCFunction(ctx, js_io_write, "write", 2));
    JS_SetPropertyStr(ctx, global, "io", io);
    JS_FreeValue(ctx, global);
}

void dump_exception(JSContext* ctx) {
    JSValue exc = JS_GetException(ctx);
    const bool is_err = JS_IsError(ctx, exc);
    {
        ScopedCString msg(ctx, exc);
        std::fprintf(stderr, "ember: script error: %s\n",
                     msg.valid() ? msg.c_str() : "(no message)");
    }
    if (is_err) {
        JSValue stack = JS_GetPropertyStr(ctx, exc, "stack");
        if (!JS_IsUndefined(stack)) {
            if (ScopedCString s(ctx, stack); s.valid()) {
                std::fprintf(stderr, "%s", s.c_str());
            }
        }
        JS_FreeValue(ctx, stack);
    }
    JS_FreeValue(ctx, exc);
}

}  // namespace

struct ScriptRuntime::Impl {
    JSRuntime* rt  = nullptr;
    JSContext* ctx = nullptr;
    ScriptCtx  host{};
};

ScriptRuntime::ScriptRuntime(const Binary& binary, ProjectContext* project) noexcept
    : impl_(std::make_unique<Impl>()) {
    impl_->host.binary  = &binary;
    impl_->host.project = project;
    impl_->rt  = JS_NewRuntime();
    if (!impl_->rt) {
        std::fprintf(stderr, "ember: JS_NewRuntime failed (out of memory)\n");
        std::abort();
    }
    impl_->ctx = JS_NewContext(impl_->rt);
    if (!impl_->ctx) {
        std::fprintf(stderr, "ember: JS_NewContext failed (out of memory)\n");
        std::abort();
    }
    JS_SetContextOpaque(impl_->ctx, &impl_->host);
    install_log_global(impl_->ctx);
    install_binary_global(impl_->ctx);
    install_io_global(impl_->ctx);
    install_xrefs_global(impl_->ctx);
    install_strings_global(impl_->ctx);
    install_project_global(impl_->ctx);
    install_argv_global(impl_->ctx);
}

void ScriptRuntime::set_argv(std::vector<std::string> argv) {
    impl_->host.argv = std::move(argv);
    install_argv_global(impl_->ctx);
}

ScriptRuntime::~ScriptRuntime() {
    if (impl_->ctx) JS_FreeContext(impl_->ctx);
    if (impl_->rt)  JS_FreeRuntime(impl_->rt);
}

Result<void>
ScriptRuntime::run_file(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        return std::unexpected(Error::io(std::format(
            "cannot open script '{}'", path.string())));
    }
    std::stringstream ss;
    ss << f.rdbuf();
    return eval(ss.str(), path.filename().string());
}

Result<void>
ScriptRuntime::eval(std::string source, std::string name) {
    JSValue rv = JS_Eval(impl_->ctx, source.data(), source.size(),
                         name.c_str(), JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(rv)) {
        JS_FreeValue(impl_->ctx, rv);
        dump_exception(impl_->ctx);
        return std::unexpected(Error::invalid_format("script raised an exception"));
    }
    JS_FreeValue(impl_->ctx, rv);
    return {};
}

}  // namespace ember
