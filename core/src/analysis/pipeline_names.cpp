// Name validation and collision reports.

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <ember/analysis/fingerprint.hpp>
#include <ember/analysis/pipeline.hpp>
#include <ember/binary/binary.hpp>
#include <ember/binary/symbol.hpp>
#include <ember/common/types.hpp>

namespace ember::pipeline {

}  // namespace ember::pipeline

namespace ember {

using namespace pipeline;

NameValidation
validate_name(const Binary& b, std::string_view name,
              std::span<const FingerprintRow> precomputed) {
    NameValidation out;
    if (name.empty()) return out;

    const auto matches = b.find_all_by_name(name);

    // The bound-address path always needs an "enclosing function entry"
    // lookup - a wrong rename can pin a name mid-function, and the
    // fingerprint we report has to be the enclosing fn's, not 0. That
    // table comes from enumerate_functions regardless of caching.
    const auto fns = enumerate_functions(b);
    std::vector<addr_t> bound_addrs;
    bound_addrs.reserve(matches.size() + 1);
    for (const Symbol* s : matches) bound_addrs.push_back(s->addr);
    for (const auto& fn : fns) {
        if (fn.name == name &&
            std::find(bound_addrs.begin(), bound_addrs.end(), fn.addr) == bound_addrs.end()) {
            bound_addrs.push_back(fn.addr);
        }
    }
    out.bound.reserve(bound_addrs.size());
    out.fps.reserve(bound_addrs.size());
    out.offsets.reserve(bound_addrs.size());

    auto enclosing_entry = [&](addr_t addr) -> std::optional<addr_t> {
        auto it = std::upper_bound(fns.begin(), fns.end(), addr,
            [](addr_t a, const DiscoveredFunction& d) { return a < d.addr; });
        if (it == fns.begin()) return std::nullopt;
        --it;
        if (it->size != 0 && addr >= it->addr + it->size) return std::nullopt;
        return it->addr;
    };

    // Index the precomputed table by addr for O(1) fingerprint lookup.
    // When empty, `fingerprint_at` falls through to the slow path so the
    // function still works on a fresh binary with no cache.
    std::unordered_map<addr_t, std::size_t> fp_by_addr;
    if (!precomputed.empty()) {
        fp_by_addr.reserve(precomputed.size());
        for (std::size_t i = 0; i < precomputed.size(); ++i) {
            fp_by_addr.emplace(precomputed[i].addr, i);
        }
    }
    auto fingerprint_at = [&](addr_t a) -> FunctionFingerprint {
        if (auto it = fp_by_addr.find(a); it != fp_by_addr.end()) {
            return precomputed[it->second].fp;
        }
        if (!precomputed.empty()) return {};
        return compute_fingerprint(b, a);
    };

    FunctionFingerprint anchor{};
    bool anchor_set = false;
    for (addr_t bound_addr : bound_addrs) {
        out.bound.push_back(bound_addr);
        u64 off = 0;
        FunctionFingerprint fp{};
        if (auto entry = enclosing_entry(bound_addr); entry) {
            off = bound_addr - *entry;
            fp = fingerprint_at(*entry);
        }
        out.fps.push_back(fp);
        out.offsets.push_back(off);
        if (!anchor_set && fp.hash != 0) {
            anchor = fp;
            anchor_set = true;
        }
    }

    // Near-match scan: every other function whose (blocks, insts, calls)
    // tuple matches the anchor. Hash equality is *kept* (same content,
    // different addr is the strongest name-DB confusion signal); callers
    // grep for hash=<anchor> when they want to single out exact twins.
    if (anchor_set) {
        std::unordered_set<addr_t> bound_entries;
        for (addr_t a : out.bound) {
            if (auto e = enclosing_entry(a); e) bound_entries.insert(*e);
        }

        auto consider = [&](addr_t addr, const FunctionFingerprint& fp,
                            std::string_view fname) {
            if (bound_entries.contains(addr)) return;
            if (fp.hash == 0) return;
            if (fp.blocks != anchor.blocks) return;
            if (fp.insts  != anchor.insts)  return;
            if (fp.calls  != anchor.calls)  return;
            NameValidation::NearMatch nm;
            nm.addr = addr;
            nm.fp   = fp;
            nm.name = std::string{fname};
            out.near_matches.push_back(std::move(nm));
        };

        if (!precomputed.empty()) {
            for (const auto& row : precomputed) {
                consider(row.addr, row.fp, row.name);
            }
        } else {
            for (const auto& d : fns) {
                const auto fp = compute_fingerprint(b, d.addr);
                consider(d.addr, fp, d.name);
            }
        }
        std::sort(out.near_matches.begin(), out.near_matches.end(),
            [](const auto& a, const auto& bb) { return a.addr < bb.addr; });
    }

    if (out.bound.empty())          out.verdict = NameValidation::Verdict::Unknown;
    else if (out.bound.size() > 1)  out.verdict = NameValidation::Verdict::Ambiguous;
    else if (out.near_matches.empty()) out.verdict = NameValidation::Verdict::Strong;
    else                            out.verdict = NameValidation::Verdict::Weak;
    return out;
}

Collisions
collect_collisions(const Binary& b,
                   std::span<const FingerprintRow> precomputed) {
    Collisions out;

    // Name collisions come straight from the symbol table - find_all_by_name
    // already does the per-name filter, but here we want every duplicate
    // in one pass. Skip imports (PLT stubs share names with their defined
    // counterparts and that's not a collision worth flagging).
    {
        std::unordered_map<std::string_view, std::vector<addr_t>> by_name;
        for (const auto& s : b.symbols()) {
            if (s.is_import) continue;
            if (s.name.empty()) continue;
            by_name[s.name].push_back(s.addr);
        }
        for (auto& [name, addrs] : by_name) {
            if (addrs.size() < 2) continue;
            std::sort(addrs.begin(), addrs.end());
            addrs.erase(std::unique(addrs.begin(), addrs.end()), addrs.end());
            if (addrs.size() < 2) continue;
            NameCollision nc;
            nc.name  = std::string{name};
            nc.addrs = std::move(addrs);
            out.by_name.push_back(std::move(nc));
        }
        std::sort(out.by_name.begin(), out.by_name.end(),
            [](const NameCollision& a, const NameCollision& bb) {
                return a.name < bb.name;
            });
    }

    // Fingerprint collisions: bucket every function's hash, emit groups
    // with size > 1. The fingerprint source is `precomputed` when
    // supplied (the cache-fed fast path) or compute-on-the-fly otherwise.
    {
        std::unordered_map<u64, std::vector<addr_t>> by_fp;
        if (!precomputed.empty()) {
            by_fp.reserve(precomputed.size());
            for (const auto& row : precomputed) {
                if (row.fp.hash == 0) continue;
                by_fp[row.fp.hash].push_back(row.addr);
            }
        } else {
            for (const auto& d : enumerate_functions(b)) {
                const auto fp = compute_fingerprint(b, d.addr);
                if (fp.hash == 0) continue;
                by_fp[fp.hash].push_back(d.addr);
            }
        }
        out.by_fingerprint.reserve(by_fp.size());
        for (auto& [hash, addrs] : by_fp) {
            if (addrs.size() < 2) continue;
            std::sort(addrs.begin(), addrs.end());
            FingerprintCollision fc;
            fc.hash  = hash;
            fc.addrs = std::move(addrs);
            out.by_fingerprint.push_back(std::move(fc));
        }
        std::sort(out.by_fingerprint.begin(), out.by_fingerprint.end(),
            [](const FingerprintCollision& a, const FingerprintCollision& bb) {
                return a.addrs.front() < bb.addrs.front();
            });
    }

    return out;
}

}  // namespace ember
