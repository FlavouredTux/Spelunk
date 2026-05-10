#include <ember/analysis/symresolve.hpp>

#include <algorithm>
#include <cstddef>
#include <map>
#include <optional>
#include <set>
#include <vector>

#include <ember/analysis/data_xrefs.hpp>
#include <ember/analysis/fn_table.hpp>
#include <ember/binary/section.hpp>

namespace ember::analysis {

namespace {

constexpr addr_t       kSlotSize    = 8;     // 64-bit fnptr table
constexpr std::size_t  kMinSlotRun  = 3;     // ignore noise from 1-2 globals

struct WritableTable {
    struct Row { addr_t beg, end; };
    std::vector<Row> rows;

    explicit WritableTable(const Binary& b) {
        const auto secs = b.sections();
        rows.reserve(secs.size());
        for (const auto& s : secs) {
            if (s.size == 0) continue;
            if (!s.flags.allocated || !s.flags.writable) continue;
            if (s.flags.executable) continue;
            rows.push_back({s.vaddr, s.vaddr + s.size});
        }
        std::ranges::sort(rows, [](const Row& l, const Row& r) noexcept {
            return l.beg < r.beg;
        });
    }

    [[nodiscard]] bool contains(addr_t a) const noexcept {
        auto it = std::ranges::upper_bound(rows, a,
            {}, [](const Row& r) noexcept { return r.beg; });
        if (it == rows.begin()) return false;
        --it;
        return a < it->end;
    }
};

// Iterative resolver detection. Each pass picks the longest stride-8
// run across all functions, claims its slots, and removes the claimed
// VAs from the work set so the next pass can find the next longest
// run. Stops when no remaining run reaches the kMinSlotRun floor.
// This handles the multi-resolver case (one resolver fills weak-symbol
// stubs, another fills the bulk of the table) without mis-attributing
// either's coverage.
std::vector<ResolverCandidate>
detect_resolvers(const Binary& b,
                 const std::map<addr_t, std::vector<DataXref>>& xrefs,
                 const FnTable& fns) {
    std::vector<ResolverCandidate> out;
    if (b.arch() != Arch::X86_64) return out;

    WritableTable wsects(b);

    std::map<addr_t, std::vector<addr_t>> writes_by_fn;
    for (const auto& [target, bucket] : xrefs) {
        if (!wsects.contains(target)) continue;
        for (const auto& x : bucket) {
            if (x.kind != DataXrefKind::Write) continue;
            const auto* fn = fns.containing(x.from_pc);
            if (!fn) continue;
            writes_by_fn[fn->entry].push_back(target);
        }
    }
    for (auto& [_, v] : writes_by_fn) {
        std::ranges::sort(v);
        v.erase(std::unique(v.begin(), v.end()), v.end());
    }

    std::set<addr_t> claimed;
    while (true) {
        std::size_t best_len  = 0;
        addr_t      best_base = 0;
        addr_t      best_fn   = 0;

        for (const auto& [fn_entry, all_targets] : writes_by_fn) {
            std::vector<addr_t> targets;
            targets.reserve(all_targets.size());
            for (auto t : all_targets) {
                if (!claimed.contains(t)) targets.push_back(t);
            }
            if (targets.size() < kMinSlotRun) continue;

            std::size_t local_best_len  = 1;
            addr_t      local_best_base = targets.front();
            std::size_t cur_len   = 1;
            addr_t      cur_base  = targets.front();
            for (std::size_t i = 1; i < targets.size(); ++i) {
                if (targets[i] == targets[i - 1] + kSlotSize) {
                    ++cur_len;
                } else {
                    if (cur_len > local_best_len) {
                        local_best_len  = cur_len;
                        local_best_base = cur_base;
                    }
                    cur_base = targets[i];
                    cur_len  = 1;
                }
            }
            if (cur_len > local_best_len) {
                local_best_len  = cur_len;
                local_best_base = cur_base;
            }
            if (local_best_len < kMinSlotRun) continue;

            if (local_best_len > best_len ||
                (local_best_len == best_len && fn_entry < best_fn)) {
                best_len  = local_best_len;
                best_base = local_best_base;
                best_fn   = fn_entry;
            }
        }

        if (best_len == 0) break;

        const auto* fn_row = fns.containing(best_fn);
        ResolverCandidate rc;
        rc.fn_addr = best_fn;
        rc.fn_name = fn_row ? fn_row->name : std::string{};
        rc.base_va = best_base;
        rc.slots   = best_len;
        out.push_back(std::move(rc));

        for (std::size_t i = 0; i < best_len; ++i) {
            claimed.insert(best_base + i * kSlotSize);
        }
    }
    return out;
}

// Find the resolver covering `slot_va`, if any. Resolvers don't
// overlap (the iterative detector claims one slot for at most one
// resolver), so the first match is authoritative.
[[nodiscard]] const ResolverCandidate*
resolver_covering(std::span<const ResolverCandidate> resolvers, addr_t slot_va) {
    for (const auto& r : resolvers) {
        if (slot_va >= r.base_va &&
            slot_va < r.base_va + r.slots * kSlotSize) {
            return &r;
        }
    }
    return nullptr;
}

}  // namespace

Result<SymResolution> resolve_symtable(const Binary& b, addr_t table_va) {
    auto walk = walk_symtable(b, table_va);
    if (!walk) return std::unexpected(walk.error());

    SymResolution out;
    out.walk = std::move(*walk);

    const auto    xrefs = compute_data_xrefs(b);
    const FnTable fns(b);

    out.resolvers = detect_resolvers(b, xrefs, fns);
    std::ranges::sort(out.resolvers, [](const auto& l, const auto& r) noexcept {
        return l.base_va < r.base_va;
    });

    // Merged table base = lowest claimed slot VA across all resolvers.
    // String index i maps to slot VA = merged_base + i*kSlotSize, and
    // we look up which resolver (if any) covers that slot.
    const std::optional<addr_t> merged_base = out.resolvers.empty()
        ? std::optional<addr_t>{}
        : std::optional<addr_t>{out.resolvers.front().base_va};

    std::size_t idx = 0;
    for (const auto& e : out.walk.entries) {
        if (e.text.empty()) continue;
        ResolvedSymbol r;
        r.index     = idx;
        r.string_va = e.va;
        r.name      = e.text;
        if (merged_base) {
            const addr_t slot_va = *merged_base + idx * kSlotSize;
            if (const auto* cov = resolver_covering(out.resolvers, slot_va)) {
                r.fnptr_va    = slot_va;
                r.resolver_fn = cov->fn_addr;
                ++out.resolved_count;
                if (auto it = xrefs.find(slot_va); it != xrefs.end()) {
                    for (const auto& x : it->second) {
                        if (x.kind == DataXrefKind::Read) {
                            r.callsites.push_back(x.from_pc);
                        }
                    }
                }
            }
        }
        out.rows.push_back(std::move(r));
        ++idx;
    }
    out.non_empty_count = idx;
    return out;
}

}  // namespace ember::analysis
