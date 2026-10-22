#include <algorithm>
#include <cstddef>
#include <format>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <spelunk/binary/binary.hpp>

namespace spelunk {

const Binary::LookupCaches& Binary::caches() const {
    if (const auto* ready = caches_ready_.load(std::memory_order_acquire)) return *ready;
    const std::lock_guard lock(caches_mutex_);
    if (caches_) return *caches_;
    auto built = std::make_unique<LookupCaches>();
    auto& c = *built;

    const auto syms = symbols();
    c.imports_by_addr.reserve(syms.size());
    c.defined_objects_by_addr.reserve(syms.size());

    for (const auto& s : syms) {
        // Prefer defined symbols on name collision (imports have stub addrs
        // that callers expect to resolve to imports via import_at_plt, not
        // via find_by_name; find_by_name is for user intent like "resolve
        // this source-level name").
        auto [it, inserted] = c.by_name.try_emplace(s.name, &s);
        if (!inserted && it->second->is_import && !s.is_import) it->second = &s;

        if (s.is_import) {
            if (s.got_addr != 0) c.import_by_got.emplace(s.got_addr, &s);
            if (s.addr != 0 && s.kind != SymbolKind::Object) c.imports_by_addr.push_back(&s);
        } else if (s.kind == SymbolKind::Function || s.kind == SymbolKind::Object) {
            c.defined_objects_by_addr.push_back(&s);
        }
    }

    // Sort both vectors by (addr, name, size) to match the loader's
    // symbols() sort order. defined_object_at must return the same alias the
    // original linear scan did when multiple symbols share a vaddr (e.g.
    // `stdout` + `stdout@GLIBC_2.2.5` on a copy-relocated import).
    auto by_addr_name_size = [](const Symbol* a, const Symbol* b) noexcept {
        if (a->addr != b->addr) return a->addr < b->addr;
        if (a->name != b->name) return a->name < b->name;
        return a->size < b->size;
    };
    std::ranges::sort(c.imports_by_addr, by_addr_name_size);
    // A linker section marker (`__data_start__`, `__bss_start__`) shares its
    // address with the first real object there; that object's own name wins.
    const auto section_marker = [](const Symbol* s) noexcept {
        return s->name.size() > 4 && s->name.starts_with("__") && s->name.ends_with("__");
    };
    std::ranges::sort(c.defined_objects_by_addr, [&](const Symbol* a, const Symbol* b) noexcept {
        if (a->addr != b->addr) return a->addr < b->addr;
        if (section_marker(a) != section_marker(b)) return !section_marker(a);
        return by_addr_name_size(a, b);
    });
    caches_ = std::move(built);
    caches_ready_.store(caches_.get(), std::memory_order_release);
    return *caches_;
}

const Symbol* Binary::import_at_plt(addr_t plt_addr, unsigned slot_size) const noexcept {
    if (plt_addr == 0) return nullptr;
    const auto& c = caches();
    // Stubs are fixed-width slots - upper_bound on addr gives the slot whose
    // base is > plt_addr; step one back to get the slot that could contain it.
    auto it = std::upper_bound(
        c.imports_by_addr.begin(), c.imports_by_addr.end(), plt_addr,
        [](addr_t a, const Symbol* s) noexcept { return a < s->addr; });
    if (it == c.imports_by_addr.begin()) return nullptr;
    --it;
    // Rewind to the first entry with this addr so ties break the same way
    // the original linear scan did.
    while (it != c.imports_by_addr.begin() && (*(it - 1))->addr == (*it)->addr) --it;
    const Symbol* s = *it;
    const u64 extent = s->size == 0 ? slot_size : std::min<u64>(slot_size, s->size);
    if (plt_addr >= s->addr && plt_addr - s->addr < extent) return s;
    return nullptr;
}

const Symbol* Binary::import_at_got(addr_t got_addr) const noexcept {
    if (got_addr == 0) return nullptr;
    const auto& c = caches();
    auto it = c.import_by_got.find(got_addr);
    return it == c.import_by_got.end() ? nullptr : it->second;
}

const Symbol* Binary::defined_object_at(addr_t vaddr) const noexcept {
    const auto& c = caches();
    auto it = std::upper_bound(
        c.defined_objects_by_addr.begin(), c.defined_objects_by_addr.end(), vaddr,
        [](addr_t a, const Symbol* s) noexcept { return a < s->addr; });
    if (it == c.defined_objects_by_addr.begin()) return nullptr;
    --it;
    while (it != c.defined_objects_by_addr.begin() && (*(it - 1))->addr == (*it)->addr) --it;
    // Among aliases at the same addr, return the first that contains vaddr -
    // this preserves the (name, size)-sorted preference of the original
    // linear scan over symbols().
    const addr_t group_addr = (*it)->addr;
    auto group_end = it;
    while (group_end != c.defined_objects_by_addr.end() && (*group_end)->addr == group_addr) {
        ++group_end;
    }

    for (auto cur = it; cur != group_end; ++cur) {
        const Symbol* s = *cur;
        if (s->size != 0 && vaddr >= s->addr && vaddr < s->addr + s->size) return s;
    }

    // Zero-sized symbols still carry useful names. Treat exact matches as
    // authoritative, and for unsized data objects infer a conservative extent
    // up to the next symbol or the end of the containing non-exec section.
    for (auto cur = it; cur != group_end; ++cur) {
        const Symbol* s = *cur;
        if (s->size == 0 && vaddr == s->addr) return s;
    }

    auto containing_data_section = [this](addr_t a) -> const Section* {
        for (const auto& sec : sections()) {
            if (sec.flags.executable) continue;
            if (a >= sec.vaddr && a < sec.vaddr + sec.size) return &sec;
        }
        return nullptr;
    };

    const Section* sec = containing_data_section(group_addr);
    if (!sec || vaddr < sec->vaddr || vaddr >= sec->vaddr + sec->size) return nullptr;

    addr_t upper = sec->vaddr + sec->size;
    if (group_end != c.defined_objects_by_addr.end()) {
        const addr_t next_addr = (*group_end)->addr;
        if (next_addr > group_addr && next_addr < upper) upper = next_addr;
    }

    if (vaddr < upper) {
        for (auto cur = it; cur != group_end; ++cur) {
            const Symbol* s = *cur;
            if (s->kind == SymbolKind::Object && s->size == 0) return s;
        }
    }
    return nullptr;
}

const Symbol* Binary::find_by_name(std::string_view name) const noexcept {
    const auto& c = caches();
    auto it = c.by_name.find(name);
    return it == c.by_name.end() ? nullptr : it->second;
}

void Binary::add_synthetic_function_start(addr_t va) {
    if (va == 0) return;
    auto& syms = mutable_symbols();
    for (const auto& s : syms) {
        if (s.addr == va && s.kind == SymbolKind::Function && !s.is_import) {
            return;     // already a Function symbol at this VA
        }
    }
    Symbol s;
    s.name = std::format("sub_{:x}", va);
    s.addr = va;
    s.kind = SymbolKind::Function;
    syms.push_back(std::move(s));
    invalidate_caches();
}

bool Binary::add_inferred_function_name(addr_t va, std::string_view name) {
    if (va == 0 || name.empty()) return false;
    if (bytes_at(va).empty()) return false;
    auto is_placeholder = [](std::string_view n) noexcept {
        return n.empty() || n.starts_with("sub_");
    };
    auto& syms = mutable_symbols();
    for (auto& s : syms) {
        if (s.is_import || s.addr != va || s.kind != SymbolKind::Function) continue;
        if (!is_placeholder(s.name)) return false;
        s.name = std::string{name};
        invalidate_caches();
        return true;
    }
    Symbol s;
    s.name = std::string{name};
    s.addr = va;
    s.kind = SymbolKind::Function;
    syms.push_back(std::move(s));
    invalidate_caches();
    return true;
}

std::size_t Binary::overlay_symbols_from(const Binary& overlay) {
    const addr_t dst_base = preferred_load_base();
    const addr_t src_base = overlay.preferred_load_base();
    if (dst_base == 0 && src_base != 0) return 0;

    auto& syms = mutable_symbols();
    std::size_t added = 0;
    auto is_placeholder = [](std::string_view name) noexcept {
        return name.starts_with("sub_");
    };

    for (const auto& src : overlay.symbols()) {
        if (src.is_import || src.addr == 0 || src.name.empty()) continue;
        if (src.kind != SymbolKind::Function && src.kind != SymbolKind::Object) continue;
        if (src_base != 0 && src.addr < src_base) continue;
        const addr_t offset = src_base == 0 ? src.addr : src.addr - src_base;
        const addr_t dst_addr = dst_base + offset;
        if (dst_addr == 0 || bytes_at(dst_addr).empty()) continue;

        bool inserted = false;
        for (auto& dst : syms) {
            if (dst.is_import || dst.addr != dst_addr || dst.kind != src.kind) continue;
            if (dst.name.empty() || is_placeholder(dst.name)) {
                dst.name = src.name;
                if (dst.size == 0) dst.size = src.size;
                ++added;
            }
            inserted = true;
            break;
        }
        if (inserted) continue;

        Symbol s = src;
        s.addr = dst_addr;
        s.is_import = false;
        syms.push_back(std::move(s));
        ++added;
    }

    if (added != 0) invalidate_caches();
    return added;
}

std::vector<const Symbol*>
Binary::find_all_by_name(std::string_view name) const {
    // Linear scan rather than a cached multimap: collision checks are
    // low-frequency (once per CLI invocation, once per project.rename)
    // and the single-winner cache still satisfies the hot path.
    std::vector<const Symbol*> out;
    for (const auto& s : symbols()) {
        if (s.is_import) continue;
        if (s.name == name) out.push_back(&s);
    }
    return out;
}

void Binary::record_indirect_edge(addr_t from, addr_t to) const {
    auto& vec = indirect_edges_[from];
    // Linear-scan dedupe - N is tiny per call site (a handful of
    // observed targets on real traces), and keeping the order means
    // downstream sees edges in the order they were learned.
    for (addr_t existing : vec) if (existing == to) return;
    vec.push_back(to);
}

std::span<const addr_t>
Binary::indirect_edges_from(addr_t from) const noexcept {
    auto it = indirect_edges_.find(from);
    if (it == indirect_edges_.end()) return {};
    return it->second;
}

std::size_t Binary::indirect_edge_count() const noexcept {
    std::size_t n = 0;
    for (const auto& [from, vec] : indirect_edges_) n += vec.size();
    return n;
}

void Binary::record_runtime_qword(addr_t at, u64 value) const {
    runtime_qwords_[at] = value;
}

std::optional<u64> Binary::runtime_qword_at(addr_t at) const noexcept {
    auto it = runtime_qwords_.find(at);
    if (it == runtime_qwords_.end()) return std::nullopt;
    return it->second;
}

std::size_t Binary::runtime_qword_count() const noexcept {
    return runtime_qwords_.size();
}

}  // namespace spelunk
