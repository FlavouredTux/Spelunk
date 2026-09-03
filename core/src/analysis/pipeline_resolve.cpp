// Resolving a symbol or address to a function window.

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <ember/analysis/discovery.hpp>
#include <ember/analysis/objc.hpp>
#include <ember/analysis/pipeline.hpp>
#include <ember/binary/binary.hpp>
#include <ember/binary/symbol.hpp>
#include <ember/common/annotations.hpp>
#include <ember/common/types.hpp>

#include "pipeline_internal.hpp"

namespace ember::pipeline {

namespace {

// Try to parse `s` as a hex VA. Accepts `0x...`, `0X...`, or `sub_...`
// only - bare hex strings collide with legitimate symbol names like
// `add32`, so we require an explicit prefix.
[[nodiscard]] std::optional<addr_t> try_parse_va(std::string_view s) {
    if (s.starts_with("sub_"))          s.remove_prefix(4);
    else if (s.starts_with("0x") || s.starts_with("0X")) s.remove_prefix(2);
    else return std::nullopt;
    if (s.empty() || s.size() > 16) return std::nullopt;
    u64 v = 0;
    const auto r = std::from_chars(s.data(), s.data() + s.size(), v, 16);
    if (r.ec != std::errc{} || r.ptr != s.data() + s.size()) return std::nullopt;
    return static_cast<addr_t>(v);
}

// Find the Obj-C IMP matching a `-[Class sel]` / `+[Class sel]` string.
[[nodiscard]] std::optional<addr_t>
try_parse_objc_bracket(const Binary& b, std::string_view s) {
    if (s.size() < 4) return std::nullopt;
    const char sign = s.front();
    if (sign != '-' && sign != '+') return std::nullopt;
    if (s[1] != '[' || s.back() != ']') return std::nullopt;
    const auto inner = s.substr(2, s.size() - 3);
    const auto sp = inner.find(' ');
    if (sp == std::string_view::npos) return std::nullopt;
    const auto cls_name = inner.substr(0, sp);
    const auto sel      = inner.substr(sp + 1);
    const bool want_class = (sign == '+');
    for (const auto& m : parse_objc_methods(b)) {
        if (m.cls == cls_name && m.selector == sel &&
            m.is_class == want_class && m.imp != 0) {
            return m.imp;
        }
    }
    return std::nullopt;
}

// True when EMBER_QUIET=1 - the CLI sets this for --quiet, and we honour
// it for one-shot diagnostics too so a `--quiet` invocation produces no
// stderr noise even when -s lands mid-function.
[[nodiscard]] bool diagnostics_silenced() noexcept {
    const char* q = std::getenv("EMBER_QUIET");
    return q && q[0] == '1';
}

void note_mid_function(addr_t addr, std::string_view name, u64 off) {
    if (diagnostics_silenced()) return;
    std::fprintf(stderr,
        "ember: note: %#llx is inside %.*s at +%#llx\n",
        static_cast<unsigned long long>(addr),
        static_cast<int>(name.size()), name.data(),
        static_cast<unsigned long long>(off));
}

[[nodiscard]] std::optional<FuncWindow>
exact_discovered_function(const Binary& b, addr_t addr, EnumerateMode mode) {
    for (const auto& fn : enumerate_functions(b, mode)) {
        if (fn.addr != addr) continue;
        if (b.bytes_at(addr).empty()) return std::nullopt;
        return window_from_addr(fn.addr, fn.size, fn.name);
    }
    return std::nullopt;
}

}  // namespace

// Resolve `addr` to the nearest containing function entry. Uses the
// defined-objects cache for an O(log n) lookup. Returns a FuncWindow
// whose `start` is the function entry (NOT `addr` itself) when `addr`
// lies inside a known function's extent; the label carries the offset
// so the caller can annotate the output. Nullopt when nothing contains
// `addr` and `addr` itself has no bytes mapped.
std::optional<FuncWindow>
resolve_containing_function(const Binary& b, addr_t addr) {
    // Exact-addr Function symbol wins outright before the containing-
    // function logic kicks in. Covers two cases that defined_object_at
    // misses because it filters size==0 entries:
    //   - synthesized sub_<hex> stubs (no size known)
    //   - --force-fn-start overrides (user says "this VA is a function
    //     entry" so don't rebind to the closest-below symbol)
    for (const auto& s : b.symbols()) {
        if (s.addr == addr && s.kind == SymbolKind::Function && !s.is_import) {
            if (b.bytes_at(addr).empty()) return std::nullopt;
            return window_from_addr(addr, s.size, s.name);
        }
    }
    if (auto exact = exact_discovered_function(b, addr, EnumerateMode::Cheap); exact) {
        return exact;
    }
    const Symbol* c = b.defined_object_at(addr);
    if (c && c->kind == SymbolKind::Function && c->addr != 0) {
        if (b.bytes_at(c->addr).empty()) return std::nullopt;
        if (c->addr == addr) {
            return window_from_addr(c->addr, c->size, c->name);
        }
        const u64 off = addr - c->addr;
        if (c->size == 0 || off < c->size) {
            note_mid_function(addr, c->name, off);
            return window_from_addr(c->addr, c->size,
                                    std::format("{}+{:#x}", c->name, off));
        }
    }
    if (b.bytes_at(addr).empty()) return std::nullopt;
    // Fall back to the broader function index (CFG-discovered `sub_*`
    // entries that aren't in the symbol table). When the literal VA
    // lands mid-`sub_*` we still want the same offset note + entry-
    // anchored window the named branch produces - otherwise `-s 0xVA`
    // on a hex literal in the middle of a discovered function silently
    // disasms from the wrong instruction boundary.
    if (auto exact = exact_discovered_function(b, addr, EnumerateMode::Auto); exact) {
        return exact;
    }
    if (auto cf = containing_function(b, addr); cf && cf->entry != addr) {
        note_mid_function(addr, cf->name, cf->offset_within);
        return window_from_addr(cf->entry, cf->size,
            std::format("{}+{:#x}", cf->name, cf->offset_within));
    }
    if (!addr_in_code_section(b, addr)) return std::nullopt;
    return window_from_addr(addr, 0, std::format("sub_{:x}", addr));
}

}  // namespace ember::pipeline

namespace ember {

using namespace pipeline;

std::optional<FuncWindow>
resolve_function(const Binary& b, std::string_view symbol,
                 const Annotations* ann) {
    // Obj-C bracket form: -[Class sel] / +[Class sel] - look up the IMP
    // in the classlist, then resolve by VA.
    if (!symbol.empty() && (symbol.front() == '-' || symbol.front() == '+') &&
        symbol.size() > 1 && symbol[1] == '[') {
        if (auto addr = try_parse_objc_bracket(b, symbol); addr) {
            return resolve_containing_function(b, *addr);
        }
    }
    // Hex VA / sub_<hex> form: jump straight to VA-driven resolution so a
    // mid-function address gets resolved to its container rather than
    // silently failing.
    if (auto va = try_parse_va(symbol); va) {
        // `sub_<hex>` is the canonical name for a discovered function
        // entry. When the user types it explicitly, treat the address
        // as its own entry - even if a separate `sub_*` candidate's
        // closest-below container also covers it. Without this guard,
        // call targets that the prologue scan misses (because they
        // sit inside a larger prologue-detected blob) get rebound to
        // the container and rendered at offset +N, when the user
        // clearly meant the call target itself.
        const bool explicit_entry = symbol.starts_with("sub_");
        if (explicit_entry) {
            if (b.bytes_at(*va).empty() || !addr_in_code_section(b, *va)) {
                std::fprintf(stderr,
                    "ember: address %#llx is not in any code section "
                    "(or the bytes there are not mapped)\n",
                    static_cast<unsigned long long>(*va));
                return std::nullopt;
            }
            if (auto cf = containing_function(b, *va); cf && cf->entry == *va) {
                return window_from_addr(cf->entry, cf->size, cf->name);
            }
            return window_from_addr(*va, 0, std::format("sub_{:x}", *va));
        }
        auto win = resolve_containing_function(b, *va);
        if (!win) {
            // Common when --functions / call-graph discovery surfaces a
            // garbage indirect-jmp target on obfuscated binaries; the
            // address isn't in any mapped section so nothing decodes.
            std::fprintf(stderr,
                "ember: address %#llx is not in any mapped section "
                "(or the bytes there don't decode as code)\n",
                static_cast<unsigned long long>(*va));
        }
        return win;
    }

    const std::string_view lookup = symbol.empty() ? "main" : symbol;
    const Symbol* chosen = b.find_by_name(lookup);
    if (chosen && chosen->is_import) chosen = nullptr;
    if (!symbol.empty() && chosen && chosen->is_import) chosen = nullptr;

    if (chosen) {
        // Fingerprint import and user renames can silently bind the same
        // name to multiple addresses. Refuse the lookup rather than
        // picking the first - a wrong-address answer presents as phantom
        // bugs downstream.
        const auto all = b.find_all_by_name(lookup);
        if (all.size() > 1) {
            std::fprintf(stderr,
                "ember: name '%.*s' is ambiguous - matches %zu addresses:",
                static_cast<int>(lookup.size()), lookup.data(), all.size());
            const std::size_t shown = std::min<std::size_t>(all.size(), 5);
            for (std::size_t i = 0; i < shown; ++i) {
                std::fprintf(stderr, " %#llx",
                    static_cast<unsigned long long>(all[i]->addr));
            }
            if (all.size() > shown) {
                std::fprintf(stderr, " ... (+%zu more)",
                    all.size() - shown);
            }
            std::fprintf(stderr,
                "; pass the VA (0x…) to pick one\n");
            return std::nullopt;
        }
        if (b.bytes_at(chosen->addr).empty()) {
            std::fprintf(stderr,
                "ember: symbol '%.*s' at %#llx has no mapped bytes\n",
                static_cast<int>(lookup.size()), lookup.data(),
                static_cast<unsigned long long>(chosen->addr));
            return std::nullopt;
        }
        return window_from_addr(chosen->addr, chosen->size, chosen->name);
    }

    // Annotation-rename fallback: a name typed by the user that doesn't
    // match the binary symbol table may match a `rename` record in the
    // resolved annotations file. Without this, freshly-named functions
    // (`ember annotate ADDR --set-name X`) wouldn't be reachable via
    // `-s X` until the user remembered the original `sub_<hex>` form.
    if (ann && !symbol.empty()) {
        std::vector<addr_t> hits;
        hits.reserve(2);
        for (const auto& [addr, name] : ann->renames) {
            if (name == lookup) hits.push_back(addr);
        }
        if (hits.size() > 1) {
            std::fprintf(stderr,
                "ember: rename '%.*s' is ambiguous - bound to %zu addresses:",
                static_cast<int>(lookup.size()), lookup.data(), hits.size());
            const std::size_t shown = std::min<std::size_t>(hits.size(), 5);
            for (std::size_t i = 0; i < shown; ++i) {
                std::fprintf(stderr, " %#llx",
                    static_cast<unsigned long long>(hits[i]));
            }
            if (hits.size() > shown) {
                std::fprintf(stderr, " ... (+%zu more)",
                    hits.size() - shown);
            }
            std::fprintf(stderr,
                "; pass the VA (0x…) to pick one\n");
            return std::nullopt;
        }
        if (hits.size() == 1) {
            const addr_t a = hits.front();
            if (b.bytes_at(a).empty()) {
                std::fprintf(stderr,
                    "ember: rename '%.*s' resolves to %#llx but no bytes are mapped there\n",
                    static_cast<int>(lookup.size()), lookup.data(),
                    static_cast<unsigned long long>(a));
                return std::nullopt;
            }
            // Width unknown without lifting; window_from_addr's 0-size
            // fallback uses the terminator scan, same shape as the
            // sub_<hex> case.
            return window_from_addr(a, 0, std::string(lookup));
        }
    }

    if (!symbol.empty()) {
        std::vector<DiscoveredFunction> hits;
        for (const auto& fn : enumerate_functions(b, EnumerateMode::Cheap)) {
            if (fn.name == lookup) hits.push_back(fn);
            if (hits.size() > 5) break;
        }
        if (hits.size() > 1) {
            std::fprintf(stderr,
                "ember: discovered name '%.*s' is ambiguous - matches %zu addresses:",
                static_cast<int>(lookup.size()), lookup.data(), hits.size());
            const std::size_t shown = std::min<std::size_t>(hits.size(), 5);
            for (std::size_t i = 0; i < shown; ++i) {
                std::fprintf(stderr, " %#llx",
                    static_cast<unsigned long long>(hits[i].addr));
            }
            if (hits.size() > shown) {
                std::fprintf(stderr, " ... (+%zu more)",
                    hits.size() - shown);
            }
            std::fprintf(stderr, "; pass the VA (0x…) to pick one\n");
            return std::nullopt;
        }
        if (hits.size() == 1) {
            return window_from_addr(hits.front().addr, hits.front().size,
                                    hits.front().name);
        }
    }

    if (!symbol.empty()) {
        std::fprintf(stderr,
            "ember: no symbol named '%.*s'\n",
            static_cast<int>(lookup.size()), lookup.data());
        return std::nullopt;
    }

    const addr_t entry = b.entry_point();
    if (b.bytes_at(entry).empty()) return std::nullopt;
    return window_from_addr(entry, 0, "<entry>");
}

std::optional<FuncWindow>
resolve_function_at(const Binary& b, addr_t addr) {
    return resolve_containing_function(b, addr);
}

}  // namespace ember
