#include <ember/analysis/recover_imports.hpp>

#include <algorithm>
#include <cstddef>
#include <limits>
#include <set>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/common/bytes.hpp>
#include <ember/common/types.hpp>

namespace ember {

ReferenceExports
reference_exports_from(const Binary& dll, std::string module_name) {
    ReferenceExports out;
    out.module = std::move(module_name);
    const addr_t base = dll.preferred_load_base();
    for (const auto& sym : dll.symbols()) {
        if (!sym.is_export || sym.name.empty()) continue;
        if (sym.addr < base) continue;
        const u64 rva = sym.addr - base;
        if (rva > 0xFFFFFFFFull) continue;
        // Alias collision (two names at one RVA): keep the
        // lexicographically smaller name so the result is deterministic
        // regardless of symbol-table order.
        auto [it, inserted] = out.by_rva.try_emplace(static_cast<u32>(rva), sym.name);
        if (!inserted && sym.name < it->second) it->second = sym.name;
    }
    return out;
}

namespace {

// Pull every 8-aligned qword in the dump's readable sections that looks
// like a module pointer (in-band, and not itself mapped inside the dump -
// an import points at a DLL whose pages the capture doesn't contain).
std::vector<std::pair<addr_t, addr_t>>
harvest_slots(const Binary& dump, const ImportRecoveryOptions& opts) {
    std::vector<std::pair<addr_t, addr_t>> slots;
    for (const auto& sec : dump.sections()) {
        if (!sec.flags.readable) continue;
        if (sec.flags.executable && !opts.scan_executable) continue;
        const auto data = sec.data;
        if (data.size() < 8) continue;

        // Align the scan start to an 8-byte VA boundary.
        const addr_t va0 = sec.vaddr;
        std::size_t off = static_cast<std::size_t>((8 - (va0 & 7)) & 7);
        for (; off + 8 <= data.size(); off += 8) {
            const u64 v = read_le_at<u64>(data.data() + off);
            if (v < opts.band_low || v >= opts.band_high) continue;
            if (!dump.bytes_at(static_cast<addr_t>(v)).empty()) continue;  // own / captured
            slots.emplace_back(va0 + static_cast<addr_t>(off),
                               static_cast<addr_t>(v));
        }
    }
    return slots;
}

// Best (reference module, load base) for one cluster of target pointers.
struct BaseSolution {
    const ReferenceExports* ref   = nullptr;
    addr_t                  base  = 0;
    std::size_t             hits  = 0;
    std::size_t             distinct_hits = 0;
    bool                    ambiguous = false;
};

BaseSolution solve_base(std::span<const addr_t> targets,
                        std::span<const ReferenceExports> refs,
                        const ImportRecoveryOptions& opts) {
    const addr_t cluster_low = targets.front();   // sorted ascending
    const addr_t aligned     = cluster_low & ~addr_t{0xFFFF};

    BaseSolution best;
    for (const auto& ref : refs) {
        for (unsigned step = 0; step <= opts.base_search_steps; ++step) {
            const addr_t B = aligned - static_cast<addr_t>(step) * 0x10000;
            if (B > cluster_low) continue;
            std::size_t hits = 0;
            std::set<addr_t> distinct;
            for (addr_t v : targets) {
                const u64 rva = v - B;
                if (rva <= 0xFFFFFFFFull &&
                    ref.by_rva.contains(static_cast<u32>(rva))) {
                    ++hits;
                    distinct.insert(v);
                }
            }
            // Prefer more hits; tie-break on the base closest to the
            // cluster (largest B = smallest first-export RVA), then on
            // module name for determinism.
            const std::size_t distinct_hits = distinct.size();
            if (distinct_hits == best.distinct_hits && hits == best.hits &&
                hits > 0 && best.ref &&
                (&ref != best.ref || B != best.base)) {
                bool same_matches = true;
                for (addr_t v : targets) {
                    const u64 old_rva = v - best.base;
                    const u64 new_rva = v - B;
                    const bool old_hit = old_rva <= 0xFFFFFFFFull &&
                        best.ref->by_rva.contains(static_cast<u32>(old_rva));
                    const bool new_hit = new_rva <= 0xFFFFFFFFull &&
                        ref.by_rva.contains(static_cast<u32>(new_rva));
                    if (old_hit != new_hit) { same_matches = false; break; }
                }
                if (same_matches) best.ambiguous = true;
            }
            const bool strictly_better =
                distinct_hits > best.distinct_hits ||
                (distinct_hits == best.distinct_hits && hits > best.hits);
            const bool deterministic_tie =
                distinct_hits == best.distinct_hits && hits == best.hits && hits > 0 &&
                (B > best.base ||
                 (B == best.base && best.ref && ref.module < best.ref->module));
            const bool better = strictly_better || deterministic_tie;
            if (better) {
                const bool keep_ambiguity = !strictly_better && best.ambiguous;
                best.ref  = &ref;
                best.base = B;
                best.hits = hits;
                best.distinct_hits = distinct_hits;
                best.ambiguous = keep_ambiguity;
            }
        }
    }
    return best;
}

}  // namespace

ImportRecoveryResult
recover_imports(const Binary& dump,
                std::span<const ReferenceExports> refs,
                const ImportRecoveryOptions& opts) {
    ImportRecoveryResult result;

    auto slots = harvest_slots(dump, opts);
    result.harvested = slots.size();
    if (slots.empty()) return result;

    // Cluster by target value. Sort a parallel (target, slot) view so each
    // cluster's pointers are contiguous; the gap split separates modules.
    std::sort(slots.begin(), slots.end(),
              [](const auto& a, const auto& b) { return a.second < b.second; });

    std::size_t i = 0;
    while (i < slots.size()) {
        std::size_t j = i + 1;
        while (j < slots.size() &&
               slots[j].second - slots[j - 1].second <= opts.cluster_gap) {
            ++j;
        }

        const auto first = slots.begin() + static_cast<std::ptrdiff_t>(i);
        const auto last  = slots.begin() + static_cast<std::ptrdiff_t>(j);
        std::vector<std::pair<addr_t, addr_t>> remaining(first, last);
        while (!remaining.empty()) {
            std::vector<addr_t> targets;
            targets.reserve(remaining.size());
            for (const auto& slot : remaining) targets.push_back(slot.second);
            const BaseSolution sol = solve_base(targets, refs, opts);
            // One pointer is not enough evidence: common export RVAs make a
            // singleton compatible with many (module, base) pairs.
            if (!sol.ref || sol.distinct_hits < 2 || sol.ambiguous) break;

            ImportCluster cluster;
            cluster.low = std::numeric_limits<addr_t>::max();
            cluster.module = sol.ref->module;
            cluster.base = sol.base;

            std::vector<std::pair<addr_t, addr_t>> unmatched;
            unmatched.reserve(remaining.size() - sol.hits);
            for (const auto& [slot_va, target] : remaining) {
                const u64 rva = target - sol.base;
                auto it = rva <= 0xFFFFFFFFull
                    ? sol.ref->by_rva.find(static_cast<u32>(rva))
                    : sol.ref->by_rva.end();
                if (it == sol.ref->by_rva.end()) {
                    unmatched.emplace_back(slot_va, target);
                    continue;
                }
                cluster.low = std::min(cluster.low, target);
                cluster.high = std::max(cluster.high, target);
                ++cluster.slots;
                ++cluster.hits;
                RecoveredImport imp;
                imp.slot   = slot_va;
                imp.target = target;
                imp.rva    = opts.own_base ? (slot_va - opts.own_base) : slot_va;
                imp.module = sol.ref->module;
                imp.name   = it->second;
                result.imports.push_back(std::move(imp));
            }
            result.clusters.push_back(std::move(cluster));
            remaining = std::move(unmatched);
        }
        if (!remaining.empty()) {
            ImportCluster unresolved;
            unresolved.low = remaining.front().second;
            unresolved.high = remaining.back().second;
            unresolved.slots = remaining.size();
            result.clusters.push_back(std::move(unresolved));
        }
        i = j;
    }

    std::sort(result.imports.begin(), result.imports.end(),
              [](const RecoveredImport& a, const RecoveredImport& b) {
                  return a.slot < b.slot;
              });
    std::sort(result.clusters.begin(), result.clusters.end(),
              [](const ImportCluster& a, const ImportCluster& b) {
                  return a.low < b.low;
              });
    return result;
}

}  // namespace ember
