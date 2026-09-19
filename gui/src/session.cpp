#include "session.hpp"

#include <algorithm>
#include <expected>
#include <utility>

#include <spelunk/analysis/demangle.hpp>
#include <spelunk/common/cache.hpp>

namespace spelunk::gui {

const Section* Session::section_at(addr_t va) const noexcept {
    for (const auto& s : binary->sections()) {
        if (s.size == 0) continue;
        if (va >= s.vaddr && va < s.vaddr + s.size) return &s;
    }
    return nullptr;
}

std::string Session::segment_name(addr_t va) const {
    if (const auto* s = section_at(va); s && !s->name.empty()) return s->name;
    return "MEMORY";
}

const DiscoveredFunction* Session::function_at(addr_t va) const noexcept {
    auto it = std::upper_bound(functions.begin(), functions.end(), va,
        [](addr_t v, const DiscoveredFunction& f) { return v < f.addr; });
    if (it == functions.begin()) return nullptr;
    --it;
    if (it->size != 0 && va >= it->addr + it->size) return nullptr;
    return &*it;
}

const DiscoveredFunction* Session::function_after(addr_t va) const noexcept {
    auto it = std::lower_bound(functions.begin(), functions.end(), va,
        [](const DiscoveredFunction& f, addr_t v) { return f.addr < v; });
    return it == functions.end() ? nullptr : &*it;
}

std::optional<FuncWindow> Session::window_for(const DiscoveredFunction& fn) const {
    if (auto w = resolve_function_at(*binary, fn.addr)) {
        w->label = fn.name;
        return w;
    }
    return FuncWindow{fn.addr, fn.size, fn.name};
}

std::span<const addr_t> Session::callers_of(addr_t fn) const noexcept {
    const auto it = callers.find(fn);
    if (it == callers.end()) return {};
    return it->second;
}

Result<std::string> Session::disassembly(const FuncWindow& w) const {
    // Always pass a span: before the graph lands this is empty and the
    // header is simply omitted, instead of the renderer walking the whole
    // binary on the GUI thread.
    DisasmOptions opts;
    opts.callers = callers_of(w.start);
    return format_disasm(*binary, w, opts);
}

Result<std::string> Session::pseudocode(const FuncWindow& w, LineMap* map) const {
    EmitOptions opts;
    opts.known_function_entries = &entries;
    opts.line_map               = map;
    return format_struct(*binary, w, /*pseudo=*/true, &annotations, opts);
}

const std::vector<StringEntry>& Session::string_table() {
    if (!strings) strings = scan_strings(*binary);
    return *strings;
}

Result<std::unique_ptr<Session>> open_session(const std::filesystem::path& path) {
    auto bin = load_binary(path);
    if (!bin) return std::unexpected(bin.error());

    auto s    = std::make_unique<Session>();
    s->path   = path;
    s->binary = std::move(*bin);
    const auto location = resolve_annotation_location(path, {}, cache::default_dir());
    std::error_code ec;
    if (std::filesystem::exists(location.path, ec) && !ec) {
        auto annotations = Annotations::load(location.path);
        if (!annotations) return std::unexpected(annotations.error());
        s->annotations = std::move(*annotations);
    }
    s->functions = enumerate_functions(*s->binary, EnumerateMode::Auto);
    for (auto& function : s->functions)
        if (const auto* name = s->annotations.name_for(function.addr)) function.name = *name;
    std::sort(s->functions.begin(), s->functions.end(),
              [](const DiscoveredFunction& a, const DiscoveredFunction& b) {
                  return a.addr < b.addr;
              });
    s->entries.reserve(s->functions.size());
    for (const auto& f : s->functions) s->entries.insert(f.addr);
    // Force the Binary's lazy lookup caches to exist now, on this thread,
    // so the GUI thread and the xref worker only ever read them.
    (void)s->binary->find_by_name("main");
    return s;
}

}  // namespace spelunk::gui

namespace spelunk::gui {

namespace {

// Rust's legacy mangling is `_ZN` + (<len><ident>)* + `E` with punctuation
// escaped as `$LT$`, `$u20$`, `..` and a trailing `17h<hash>` component.
// The Itanium demangler treats those escapes as ordinary identifier
// characters, so decode this shape here and only fall back to it for
// everything else.
std::string unescape_rust(std::string_view part) {
    static constexpr std::pair<std::string_view, std::string_view> kNamed[] = {
        {"$SP$", "@"}, {"$BP$", "*"}, {"$RF$", "&"}, {"$LT$", "<"}, {"$GT$", ">"},
        {"$LP$", "("}, {"$RP$", ")"}, {"$C$", ","},
    };
    std::string out;
    out.reserve(part.size());
    std::size_t i = 0;
    while (i < part.size()) {
        if (part[i] == '.' && i + 1 < part.size() && part[i + 1] == '.') {
            out += "::";
            i += 2;
            continue;
        }
        if (part[i] == '$') {
            bool hit = false;
            for (const auto& [from, to] : kNamed) {
                if (part.substr(i).starts_with(from)) {
                    out += to;
                    i += from.size();
                    hit = true;
                    break;
                }
            }
            if (hit) continue;
            if (part.substr(i).starts_with("$u")) {
                const auto end = part.find('$', i + 2);
                if (end != std::string_view::npos && end > i + 2) {
                    unsigned code = 0;
                    bool ok = true;
                    for (std::size_t k = i + 2; k < end; ++k) {
                        const char ch = part[k];
                        unsigned v = 0;
                        if (ch >= '0' && ch <= '9') v = static_cast<unsigned>(ch - '0');
                        else if (ch >= 'a' && ch <= 'f') v = static_cast<unsigned>(ch - 'a' + 10);
                        else { ok = false; break; }
                        code = code * 16 + v;
                    }
                    if (ok && code < 0x80) {
                        out += static_cast<char>(code);
                        i = end + 1;
                        continue;
                    }
                }
            }
        }
        out += part[i];
        ++i;
    }
    return out;
}

std::optional<std::string> demangle_rust_legacy(std::string_view s) {
    if (!s.starts_with("_ZN")) return std::nullopt;
    std::size_t pos = 3;
    std::string out;
    bool any_part = false;
    while (pos < s.size() && s[pos] != 'E') {
        std::size_t len = 0;
        bool digits = false;
        while (pos < s.size() && s[pos] >= '0' && s[pos] <= '9') {
            len = len * 10 + static_cast<std::size_t>(s[pos] - '0');
            ++pos;
            digits = true;
        }
        if (!digits || len == 0 || pos + len > s.size()) return std::nullopt;
        if (any_part) out += "::";
        out += unescape_rust(s.substr(pos, len));
        pos += len;
        any_part = true;
    }
    // Must consume the whole string: a C++ function would continue with
    // parameter types after the `E`, which the Itanium path handles.
    if (!any_part || pos + 1 != s.size() || s[pos] != 'E') return std::nullopt;
    return out;
}

}  // namespace

std::string display_name(std::string_view raw) {
    if (!raw.starts_with("_Z")) return std::string(raw);

    // Rust first: its `..` escape means a '.' is part of the name, so only
    // the unambiguous `.llvm.<n>` LTO suffix may be cut before parsing.
    if (auto rust = demangle_rust_legacy(raw)) return *rust;
    if (const auto lto = raw.find(".llvm."); lto != std::string_view::npos)
        if (auto rust = demangle_rust_legacy(raw.substr(0, lto))) return *rust;

    // Itanium C++ names never contain '.', so anything from the first one
    // on is a linker suffix (`.cold`, `.constprop.0`, `.isra.0`, ...).
    std::string_view base = raw;
    if (const auto dot = base.find('.'); dot != std::string_view::npos) base = base.substr(0, dot);
    std::string pretty = pretty_symbol(base);
    if (pretty == base) return std::string(raw);
    return pretty;
}

}  // namespace spelunk::gui
