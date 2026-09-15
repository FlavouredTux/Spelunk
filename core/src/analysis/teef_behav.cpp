#include <spelunk/analysis/teef_behav.hpp>

#include "teef_behav_interpreter_internal.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <optional>
#include <vector>

#include <spelunk/common/types.hpp>
#include <spelunk/disasm/register.hpp>

#include <spelunk/analysis/cfg_builder.hpp>
#include <spelunk/binary/binary.hpp>
#include <spelunk/common/hash.hpp>
#include <spelunk/disasm/decoder.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/ir/lifter.hpp>
#include <spelunk/ir/passes.hpp>
#include <spelunk/ir/ssa.hpp>

namespace spelunk {

namespace {

using teef_behav_detail::step;
using teef_behav_detail::Trace;
using teef_behav_detail::value_key;

// ---- Block walker --------------------------------------------------------
//
// Walks block-by-block in execution order, evaluating phi-nodes against
// the previous block's identity, then non-terminator insts via step(),
// then resolves the terminator to pick the next block. Returns the
// per-trace outcome hash on success, or 0 on abort.

// Seed the argument registers into the trace's value map.
// Called once per trace after reset().
void seed_trace(Trace& t, const std::array<u64, 6>& argv) {
    // SysV ABI argument registers (seven incoming integer slots: rdi rsi
    // rdx rcx r8 r9 + return rax pre-init to 0). The lifter exposes
    // these as Reg::* with version=0.
    static constexpr std::array<Reg, 6> kArgRegs = {
        Reg::Rdi, Reg::Rsi, Reg::Rdx, Reg::Rcx, Reg::R8, Reg::R9,
    };
    for (std::size_t i = 0; i < kArgRegs.size(); ++i) {
        IrValue v = IrValue::make_reg(kArgRegs[i], IrType::I64);
        v.version = 0;
        t.values[value_key(v)] = argv[i];
    }
    {
        IrValue rax0 = IrValue::make_reg(Reg::Rax, IrType::I64);
        rax0.version = 0;
        t.values[value_key(rax0)] = 0;
    }
}

// Execute the block-walking interpreter loop on an already-seeded
// Trace. Returns the outcome hash, or 0 on abort.
[[nodiscard]] u64 run_trace_body(Trace& t, u64 input_seed,
                                 std::size_t max_blocks_visited) {
    static const bool dbg = std::getenv("SPELUNK_BEHAV_DEBUG") != nullptr;
    auto bail = [&](const char* why) -> u64 {
        if (dbg) {
            std::fprintf(stderr, "behav abort: %s @insns=%zu fn=0x%lx\n",
                         why, t.insns_done, static_cast<unsigned long>(t.fn.start));
        }
        return 0;
    };

    addr_t cur = t.fn.start;
    addr_t prev = 0;
    u64 ret_value = 0;
    bool returned = false;
    std::size_t blocks_visited = 0;

    while (!returned) {
        if (++blocks_visited > max_blocks_visited) return bail("max-blocks");
        auto it = t.fn.block_at.find(cur);
        if (it == t.fn.block_at.end()) return bail("block-not-found");
        const IrBlock& bb = t.fn.blocks[it->second];

        // Resolve phi nodes against `prev`. Phi nodes appear at the
        // block's start; a single pass.
        for (const auto& inst : bb.insts) {
            if (inst.op != IrOp::Phi) break;
            std::optional<u64> picked;
            for (std::size_t i = 0; i < inst.phi_preds.size(); ++i) {
                if (inst.phi_preds[i] == prev) {
                    picked = t.get(inst.phi_operands[i]);
                    break;
                }
            }
            if (!picked) {
                // Entry block phi from the synthetic predecessor (prev=0)
                // - fall back to the first operand. If still nothing,
                // give up.
                if (!inst.phi_operands.empty()) picked = t.get(inst.phi_operands[0]);
            }
            if (!picked) return bail("phi-no-pick");
            t.set(inst.dst, *picked);
        }

        // Walk non-phi insts.
        const IrInst* terminator = nullptr;
        for (const auto& inst : bb.insts) {
            if (inst.op == IrOp::Phi) continue;
            if (is_terminator(inst.op)) { terminator = &inst; break; }
            if (!step(t, inst)) return bail("step-false");
            if (t.aborted) {
                // Soft abort (trace budget hit). Instead of killing the
                // trace entirely, exit via the synthetic budget marker
                // that step() already pushed onto side_effects. The
                // signature still contributes a hash that's stable across
                // compilations whose interpreters bottom out the same way.
                returned = true;
                break;
            }
        }
        if (returned) break;
        if (!terminator) {
            // Fallthrough: take the first listed successor.
            if (bb.successors.empty()) return bail("no-fallthrough");
            prev = cur;
            cur  = bb.successors.front();
            continue;
        }

        // Resolve the terminator.
        switch (terminator->op) {
            case IrOp::Return: {
                // Capture the return value (first src, by SysV ABI rax).
                if (terminator->src_count >= 1) {
                    const auto v = t.get(terminator->srcs[0]);
                    ret_value = v.value_or(0);
                }
                returned = true;
                break;
            }
            case IrOp::Branch: {
                if (bb.successors.empty()) return bail("br-no-succ");
                prev = cur;
                cur  = bb.successors.front();
                break;
            }
            case IrOp::CondBranch: {
                if (terminator->src_count < 1) return bail("cbr-no-cond");
                const auto c = t.get(terminator->srcs[0]);
                if (!c) return bail("cbr-cond-none");
                const bool taken = (*c & 1);
                // x64 lifter convention: target1 = taken, target2 = fall-through.
                const addr_t nxt = taken ? terminator->target1 : terminator->target2;
                if (nxt == 0) {
                    // Some encodings stash both successors in bb.successors;
                    // index 0 = taken, index 1 = fall-through (or first/second
                    // in IR-builder order).
                    if (bb.successors.size() < 2) return bail("cbr-no-succ");
                    prev = cur;
                    cur  = bb.successors[taken ? 0 : 1];
                } else {
                    prev = cur;
                    cur  = nxt;
                }
                break;
            }
            case IrOp::BranchIndirect: {
                // Switch dispatch. If the IR records case values + a
                // switch-index reg, resolve by looking up the value of
                // that reg and picking the matching successor; if no
                // case matches and there's a default, take it; else
                // bail to successor[0] as a degraded-but-deterministic
                // fall-through. If the block has no metadata at all,
                // record an "ind-br" side-effect and exit cleanly so
                // the trace still contributes a hash.
                if (!bb.case_values.empty() && bb.switch_index != Reg::None) {
                    IrValue probe = IrValue::make_reg(bb.switch_index, IrType::I64);
                    // We don't know the exact version; scan recent
                    // versions in the values map, picking the highest
                    // version that's bound. (Cheap heuristic - better
                    // would be tracking last def per reg in the trace.)
                    std::optional<u64> idx;
                    for (u32 ver = 0; ver <= 8 && !idx; ++ver) {
                        probe.version = ver;
                        idx = t.get(probe);
                    }
                    if (idx) {
                        std::size_t hit = bb.case_values.size();   // sentinel "miss"
                        for (std::size_t i = 0; i < bb.case_values.size(); ++i) {
                            if (static_cast<i64>(*idx) == bb.case_values[i]) {
                                hit = i; break;
                            }
                        }
                        addr_t nxt = 0;
                        if (hit < bb.case_values.size() && hit < bb.successors.size()) {
                            nxt = bb.successors[hit];
                        } else if (bb.has_default && !bb.successors.empty()) {
                            nxt = bb.successors.back();
                        }
                        if (nxt != 0) { prev = cur; cur = nxt; break; }
                    }
                }
                // No metadata or unresolved: emit a side-effect and exit.
                t.side_effects.push_back(mix64(fnv1a_64("ind-br"), cur));
                returned = true;
                break;
            }
            case IrOp::Unreachable: {
                // Trap intrinsic / unreachable - record as a side-effect
                // and exit cleanly so the trace contributes a hash.
                t.side_effects.push_back(fnv1a_64("unreachable"));
                returned = true;
                break;
            }
            default:
                return bail("default-terminator");
        }
    }

    // Sort and dedupe side effects for a stable per-trace hash.
    std::sort(t.side_effects.begin(), t.side_effects.end());
    t.side_effects.erase(
        std::unique(t.side_effects.begin(), t.side_effects.end()),
        t.side_effects.end());
    u64 sx = fnv1a_64("se");
    for (u64 e : t.side_effects) sx = mix64(sx, e);

    u64 outcome = mix64(fnv1a_64(kBehavSchema), input_seed);
    outcome = mix64(outcome, ret_value);
    outcome = mix64(outcome, sx);
    return outcome;
}

// ---- Input vector generator ---------------------------------------------
//
// K=64 vectors per fn, drawn from a fixed-seed mix of distributions so
// runs are reproducible. The distribution is intentionally diverse:
// behavior under (0, 0, 0, ..., 0) and (1, 0, 0, ...) and large-pointer
// arguments differs, and we want each function to produce a multiset
// that captures that variation.

[[nodiscard]] std::array<u64, 6> mk_inputs(std::size_t k) noexcept {
    // Per-slot derived from (k, slot) so vectors are deterministic.
    std::array<u64, 6> v{};
    auto derive = [&](std::size_t slot, u64 base) -> u64 {
        u64 h = mix64(0xA5A5A5A5A5A5A5A5ULL ^ k, slot);
        // Pick a flavor: small int / zero / one / big random / pointer.
        switch (k % 8) {
            case 0: return 0;
            case 1: return 1;
            case 2: return 0xffffffffffffffffULL;
            case 3: return static_cast<u64>(slot + 1);
            case 4: return base;                          // big random
            case 5: return base & u64{0xffff};            // medium-small
            case 6: return u64{0x100000} + base;          // pointer-shaped
            case 7: return base & u64{0xff};              // byte
        }
        return h;
    };
    for (std::size_t i = 0; i < 6; ++i) v[i] = derive(i, mix64(k, i * 0x9e3779b97f4a7c15ULL));
    return v;
}

// ---- MinHash -------------------------------------------------------------

[[nodiscard]] std::array<u64, 8>
minhash8(const std::vector<u64>& xs) noexcept {
    std::array<u64, 8> mh;
    mh.fill(std::numeric_limits<u64>::max());
    if (xs.empty()) return mh;
    const u64 schemaSalt = fnv1a_64(kBehavSchema);
    for (u64 x : xs) {
        for (std::size_t k = 0; k < 8; ++k) {
            const u64 hk = mix64(x, schemaSalt + k * 0x9e3779b97f4a7c15ULL);
            if (hk < mh[k]) mh[k] = hk;
        }
    }
    return mh;
}

[[nodiscard]] u64 multiset_hash(const std::vector<u64>& xs) noexcept {
    u64 h = fnv1a_64(kBehavSchema);
    for (u64 x : xs) h = mix64(h, x);
    return h;
}

}  // namespace

BehavSig compute_behav_sig_from_ir(const IrFunction& fn, const Binary& bin) {
    BehavSig out;

    // Cap the number of blocks visited per trace so loops don't run
    // forever on unfortunate inputs (we still bound by insn count
    // separately). 4× kBehavMaxInsnsTrace tolerates up to that many
    // single-insn blocks.
    const std::size_t max_blocks_visited = 4 * kBehavMaxInsnsTrace;

    // Reuse a single Trace across all K traces to avoid 64×
    // construct/destroy of the value map, side-effects vector, and
    // memory model. reset() clears all mutable state while preserving
    // allocated capacity; seed_trace() re-populates arg registers
    // with the new trace's inputs.
    Trace t(fn, bin, /*mem_salt=*/0);

    std::vector<u64> outcomes;
    outcomes.reserve(kBehavTraces);
    u8 done = 0;
    u8 aborted = 0;
    for (std::size_t k = 0; k < kBehavTraces; ++k) {
        const auto argv = mk_inputs(k);
        const u64 seed = mix64(0xDEADBEEFCAFEULL, k);
        t.reset(mix64(0xC0FFEEULL, seed));
        seed_trace(t, argv);
        const u64 outcome = run_trace_body(t, seed, max_blocks_visited);
        if (outcome != 0) { outcomes.push_back(outcome); ++done; }
        else               { ++aborted; }
    }
    out.traces_done    = done;
    out.traces_aborted = aborted;
    if (outcomes.empty()) return out;
    std::sort(outcomes.begin(), outcomes.end());
    outcomes.erase(std::unique(outcomes.begin(), outcomes.end()),
                   outcomes.end());
    out.exact_hash = multiset_hash(outcomes);
    out.minhash    = minhash8(outcomes);
    return out;
}

BehavSig compute_behav_sig(const Binary& bin, addr_t fn_start) {
    auto dec_r = make_decoder(bin);
    if (!dec_r) return {};
    const CfgBuilder cfg(bin, **dec_r);
    auto fn_r = cfg.build(fn_start, {});
    if (!fn_r) return {};
    auto lifter_r = make_lifter(bin);
    if (!lifter_r) return {};
    auto ir_r = (*lifter_r)->lift(*fn_r);
    if (!ir_r) return {};
    const SsaBuilder ssa;
    if (auto rv = ssa.convert(*ir_r); !rv) return {};
    if (auto rv = run_cleanup(*ir_r); !rv) return {};
    return compute_behav_sig_from_ir(*ir_r, bin);
}

}  // namespace spelunk
