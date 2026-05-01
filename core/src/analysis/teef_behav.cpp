#include <ember/analysis/teef_behav.hpp>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <ember/analysis/cfg_builder.hpp>
#include <ember/analysis/pipeline.hpp>
#include <ember/binary/binary.hpp>
#include <ember/disasm/decoder.hpp>
#include <ember/ir/ir.hpp>
#include <ember/ir/lifter.hpp>
#include <ember/ir/passes.hpp>
#include <ember/ir/ssa.hpp>

namespace ember {

namespace {

// ---- Hash helpers --------------------------------------------------------

constexpr u64 kFnvOffset = 0xcbf29ce484222325ULL;
constexpr u64 kFnvPrime  = 0x100000001b3ULL;

[[nodiscard]] constexpr u64 fnv1a(std::string_view s) noexcept {
    u64 h = kFnvOffset;
    for (char c : s) { h ^= static_cast<u8>(c); h *= kFnvPrime; }
    return h;
}

[[nodiscard]] constexpr u64 mix64(u64 a, u64 b) noexcept {
    u64 x = a ^ (b + 0x9e3779b97f4a7c15ULL + (a << 6) + (a >> 2));
    x ^= x >> 30;  x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;  x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return x;
}

[[nodiscard]] constexpr u64 mask_to(u64 v, unsigned bits) noexcept {
    if (bits >= 64) return v;
    return v & ((1ULL << bits) - 1);
}

[[nodiscard]] constexpr i64 sign_extend(u64 v, unsigned bits) noexcept {
    if (bits >= 64) return static_cast<i64>(v);
    const u64 m = 1ULL << (bits - 1);
    return static_cast<i64>((v ^ m) - m);
}

[[nodiscard]] u64 value_key(const IrValue& v) noexcept {
    switch (v.kind) {
        case IrValueKind::Reg:
            return mix64(fnv1a("reg"),
                         (static_cast<u64>(v.reg) << 16) | v.version);
        case IrValueKind::Temp:
            return mix64(fnv1a("temp"),
                         (static_cast<u64>(v.temp) << 8) | v.version);
        case IrValueKind::Flag:
            return mix64(fnv1a("flag"),
                         (static_cast<u64>(v.flag) << 8) | v.version);
        default:
            return 0;
    }
}

[[nodiscard]] u64 addr_class_hash(const Binary& bin, addr_t a) noexcept {
    if (const auto* imp = bin.import_at_plt(a); imp && !imp->name.empty())
        return mix64(fnv1a("plt"), fnv1a(imp->name));
    if (const auto* imp = bin.import_at_got(a); imp && !imp->name.empty())
        return mix64(fnv1a("got"), fnv1a(imp->name));
    if (const auto* sym = bin.defined_object_at(a); sym && !sym->name.empty())
        return mix64(fnv1a("sym"), fnv1a(sym->name));
    return fnv1a("addr");
}

// ---- Memory model --------------------------------------------------------

struct Memory {
    std::unordered_map<u64, u64> cells;
    u64 salt;

    [[nodiscard]] u64 load(u64 addr, unsigned width_bytes) {
        auto it = cells.find(addr);
        u64 v;
        if (it != cells.end()) {
            v = it->second;
        } else {
            v = mix64(addr, salt);
            cells[addr] = v;
        }
        return mask_to(v, width_bytes * 8);
    }

    void store(u64 addr, u64 val, unsigned width_bytes) {
        cells[addr] = mask_to(val, width_bytes * 8);
    }
};

// ---- Per-trace interpreter state -----------------------------------------

struct Trace {
    const IrFunction& fn;
    const Binary&     bin;

    std::unordered_map<u64, u64> values;
    std::vector<u64>             side_effects;
    Memory                       mem;
    std::size_t                  insns_done = 0;
    std::size_t                  loads_done = 0;
    bool                         aborted = false;
    addr_t                       prev_block = 0;

    Trace(const IrFunction& f, const Binary& b, u64 mem_salt)
        : fn(f), bin(b) { mem.salt = mem_salt; }

    [[nodiscard]] std::optional<u64> get(const IrValue& v) noexcept {
        if (v.kind == IrValueKind::Imm) return static_cast<u64>(v.imm);
        if (v.kind == IrValueKind::None) return std::nullopt;
        const u64 k = value_key(v);
        if (k == 0) return std::nullopt;
        auto it = values.find(k);
        if (it == values.end()) {
            // Unbound SSA read. Real binaries hit this when the lifter's
            // SSA renumbering or cleanup renames a value to a version we
            // didn't pre-seed (e.g. rdi_v1 used before any insn defines
            // it because the entry-block live-in was renamed). Bail
            // would abort 95% of traces on stripped fns; synthesize a
            // deterministic-by-identity value instead and cache it so
            // subsequent reads of the same key see the same value.
            const u64 synth = mix64(fnv1a("synth"), k);
            values[k] = synth;
            return synth;
        }
        return it->second;
    }

    void set(const IrValue& dst, u64 val) {
        if (dst.kind == IrValueKind::None) return;
        const u64 k = value_key(dst);
        if (k == 0) return;
        values[k] = mask_to(val, type_bits(dst.type));
    }
};

// ---- Per-instruction step -----------------------------------------------
//
// Returns:
//   true  → step succeeded, continue
//   false → trace aborted (sets t.aborted)

[[nodiscard]] bool step(Trace& t, const IrInst& inst);

// Synth a deterministic placeholder dst from (op, src values) so an
// instruction shape we don't precisely model can't kill the trace.
// Used by step_arith/step_unop/step_cmp/step_cast/step_select on
// src-count or operand-kind mismatches.
[[nodiscard]] inline bool synth_dst(Trace& t, const IrInst& inst) {
    if (inst.dst.kind == IrValueKind::None) return true;
    u64 h = mix64(fnv1a("synth-dst"), static_cast<u64>(inst.op));
    for (u8 i = 0; i < inst.src_count; ++i) {
        const auto v = t.get(inst.srcs[i]);
        if (v) h = mix64(h, *v);
    }
    t.set(inst.dst, h);
    return true;
}

[[nodiscard]] bool step_arith(Trace& t, const IrInst& inst) {
    if (inst.src_count != 2) return synth_dst(t, inst);
    const auto a = t.get(inst.srcs[0]);
    const auto b = t.get(inst.srcs[1]);
    if (!a || !b) return synth_dst(t, inst);
    const unsigned bits = type_bits(inst.dst.type);
    u64 r = 0;
    switch (inst.op) {
        case IrOp::Add: r = *a + *b; break;
        case IrOp::Sub: r = *a - *b; break;
        case IrOp::Mul: r = *a * *b; break;
        case IrOp::Div:
        case IrOp::Mod: {
            // Without signedness in IR, fall back to unsigned. Divide-by-zero
            // is undefined per the IR (lifter omits explicit zero check); we
            // pretend it returns 0 to keep the trace alive deterministically.
            if (*b == 0) { r = 0; break; }
            r = (inst.op == IrOp::Div) ? (*a / *b) : (*a % *b);
            break;
        }
        case IrOp::And: r = *a & *b; break;
        case IrOp::Or:  r = *a | *b; break;
        case IrOp::Xor: r = *a ^ *b; break;
        case IrOp::Shl: r = *a << (*b & 63); break;
        case IrOp::Lshr:r = *a >> (*b & 63); break;
        case IrOp::Ashr: {
            const i64 s = sign_extend(*a, bits);
            r = static_cast<u64>(s >> (*b & 63));
            break;
        }
        default: return synth_dst(t, inst);
    }
    t.set(inst.dst, r);
    return true;
}

[[nodiscard]] bool step_unop(Trace& t, const IrInst& inst) {
    if (inst.src_count != 1) return synth_dst(t, inst);
    const auto a = t.get(inst.srcs[0]);
    if (!a) return synth_dst(t, inst);
    u64 r = 0;
    switch (inst.op) {
        case IrOp::Neg: r = static_cast<u64>(-static_cast<i64>(*a)); break;
        case IrOp::Not: r = ~*a; break;
        default: return synth_dst(t, inst);
    }
    t.set(inst.dst, r);
    return true;
}

[[nodiscard]] bool step_cmp(Trace& t, const IrInst& inst) {
    if (inst.src_count != 2) return synth_dst(t, inst);
    const auto a = t.get(inst.srcs[0]);
    const auto b = t.get(inst.srcs[1]);
    if (!a || !b) return synth_dst(t, inst);
    const unsigned bits = type_bits(inst.srcs[0].type);
    const i64 sa = sign_extend(*a, bits);
    const i64 sb = sign_extend(*b, bits);
    u64 r = 0;
    switch (inst.op) {
        case IrOp::CmpEq:  r = (*a == *b); break;
        case IrOp::CmpNe:  r = (*a != *b); break;
        case IrOp::CmpUlt: r = (*a <  *b); break;
        case IrOp::CmpUle: r = (*a <= *b); break;
        case IrOp::CmpUgt: r = (*a >  *b); break;
        case IrOp::CmpUge: r = (*a >= *b); break;
        case IrOp::CmpSlt: r = (sa <  sb); break;
        case IrOp::CmpSle: r = (sa <= sb); break;
        case IrOp::CmpSgt: r = (sa >  sb); break;
        case IrOp::CmpSge: r = (sa >= sb); break;
        default: return synth_dst(t, inst);
    }
    t.set(inst.dst, r);
    return true;
}

[[nodiscard]] bool step_cast(Trace& t, const IrInst& inst) {
    if (inst.src_count != 1) return synth_dst(t, inst);
    const auto a = t.get(inst.srcs[0]);
    if (!a) return synth_dst(t, inst);
    const unsigned dst_bits = type_bits(inst.dst.type);
    const unsigned src_bits = type_bits(inst.srcs[0].type);
    u64 r = 0;
    switch (inst.op) {
        case IrOp::ZExt:  r = mask_to(*a, src_bits); break;
        case IrOp::SExt:  r = static_cast<u64>(sign_extend(*a, src_bits)); break;
        case IrOp::Trunc: r = *a; break;
        default: return false;
    }
    r = mask_to(r, dst_bits);
    t.set(inst.dst, r);
    return true;
}

[[nodiscard]] bool step_select(Trace& t, const IrInst& inst) {
    if (inst.src_count != 3) return synth_dst(t, inst);
    const auto c = t.get(inst.srcs[0]);
    const auto a = t.get(inst.srcs[1]);
    const auto b = t.get(inst.srcs[2]);
    if (!c || !a || !b) return synth_dst(t, inst);
    t.set(inst.dst, (*c & 1) ? *a : *b);
    return true;
}

[[nodiscard]] bool step_load(Trace& t, const IrInst& inst) {
    if (++t.loads_done > kBehavMaxLoadsTrace) return synth_dst(t, inst);
    if (inst.src_count < 1) return synth_dst(t, inst);
    const auto addr = t.get(inst.srcs[0]);
    if (!addr) return synth_dst(t, inst);
    const unsigned w = (type_bits(inst.dst.type) + 7) / 8;
    const u64 v = t.mem.load(*addr, w == 0 ? 8 : w);
    t.set(inst.dst, v);
    return true;
}

[[nodiscard]] bool step_store(Trace& t, const IrInst& inst) {
    if (inst.src_count < 2) return true;     // malformed; ignore but continue
    const auto addr = t.get(inst.srcs[0]);
    const auto val  = t.get(inst.srcs[1]);
    if (!addr || !val) return true;
    const unsigned w = (type_bits(inst.srcs[1].type) + 7) / 8;
    t.mem.store(*addr, *val, w == 0 ? 8 : w);
    // Side effect: hash (kind="store", addr_class, value).
    u64 h = mix64(fnv1a("store"), *addr);
    h = mix64(h, *val);
    t.side_effects.push_back(h);
    return true;
}

[[nodiscard]] bool step_call(Trace& t, const IrInst& inst) {
    // Direct calls: target1 holds the called address; we bake its
    // address-class into the side-effect hash and use it as part of
    // the synthetic return value.
    u64 tgt = 0;
    if (inst.op == IrOp::CallIndirect) {
        // Indirect: target is in srcs[0]. Get its concrete value if we can.
        if (inst.src_count < 1) return synth_dst(t, inst);
        const auto t0 = t.get(inst.srcs[0]);
        if (!t0) return synth_dst(t, inst);
        tgt = mix64(fnv1a("ind-call"), *t0);
    } else {
        tgt = addr_class_hash(t.bin, inst.target1);
    }
    // Hash sorted argument values. GCC -Werror=array-bounds gives a false
    // positive on std::sort with a small std::array bound; switching to
    // a small std::vector defeats the bogus range analysis without any
    // runtime cost (vector stays size <= 2 in the inst.src_count==3 cap).
    std::vector<u64> args;
    args.reserve(3);
    const std::size_t first_arg = (inst.op == IrOp::CallIndirect) ? 1u : 0u;
    for (std::size_t i = first_arg; i < inst.src_count; ++i) {
        if (args.size() >= 3) break;
        const auto v = t.get(inst.srcs[i]);
        if (v) args.push_back(*v);
    }
    std::sort(args.begin(), args.end());
    u64 h = mix64(fnv1a("call"), tgt);
    for (u64 a : args) h = mix64(h, a);
    t.side_effects.push_back(h);
    // Synthetic return value: deterministic hash of the call signature.
    if (inst.dst.kind != IrValueKind::None) {
        t.set(inst.dst, h);
    }
    return true;
}

// Semantic intrinsic modeling. Without this, intrinsics get hashed as
// `mix64("intr", name, srcs...)` — opaque-by-name. That's fine for two
// compilations that both emit the same intrinsic, but breaks down when
// one compiler lowers a computation to a single intrinsic (e.g. clang
// emitting `bswap` for a recognized byte-swap idiom) while the other
// keeps the open-coded shifts (gcc -Os). Both compute the same value;
// only one looks like an intrinsic.
//
// For known intrinsics with well-defined source-language semantics, we
// compute the actual result here. The trace then sees the *value* of
// the computation, not its IR encoding. Cross-compiler matches that
// turn on intrinsic recognition (bswap, divq/divr, mulh, bsr/bsf)
// collapse correctly. Unknown intrinsics fall through to the opaque
// hash path (caller's responsibility).
//
// Returns true iff the intrinsic was modeled and t.set has been called
// for inst.dst.
[[nodiscard]] bool try_semantic_intrinsic(Trace& t, const IrInst& inst) {
    if (inst.name.empty()) return false;
    if (inst.dst.kind == IrValueKind::None) return false;
    const std::string_view n = inst.name;

    // ---- bsr: position of MSB (x86 BSR) ---------------------------------
    // Undefined for input==0 in hardware; we return 0 deterministically.
    if (n == "bsr") {
        if (inst.src_count < 1) return false;
        const auto x = t.get(inst.srcs[0]);
        if (!x) return false;
        const unsigned bits = type_bits(inst.srcs[0].type);
        const u64 v = mask_to(*x, bits);
        u64 r = 0;
        if (v != 0) {
            r = bits - 1;
            while (r > 0 && ((v >> r) & 1ULL) == 0) --r;
        }
        t.set(inst.dst, r);
        return true;
    }

    // ---- bsf: position of LSB (x86 BSF) ---------------------------------
    if (n == "bsf") {
        if (inst.src_count < 1) return false;
        const auto x = t.get(inst.srcs[0]);
        if (!x) return false;
        const unsigned bits = type_bits(inst.srcs[0].type);
        const u64 v = mask_to(*x, bits);
        u64 r = 0;
        if (v != 0) {
            while (r < bits && ((v >> r) & 1ULL) == 0) ++r;
        }
        t.set(inst.dst, r);
        return true;
    }

    // ---- bswap: byte reversal (16/32/64) --------------------------------
    if (n == "bswap") {
        if (inst.src_count < 1) return false;
        const auto x = t.get(inst.srcs[0]);
        if (!x) return false;
        const unsigned bits = type_bits(inst.srcs[0].type);
        u64 r = 0;
        if (bits <= 16) {
            const u32 v = static_cast<u32>(*x) & 0xffffu;
            r = ((v & 0xffu) << 8) | ((v >> 8) & 0xffu);
        } else if (bits <= 32) {
            const u32 v = static_cast<u32>(*x);
            r = (static_cast<u64>(v & 0xff000000u) >> 24) |
                (static_cast<u64>(v & 0x00ff0000u) >>  8) |
                (static_cast<u64>(v & 0x0000ff00u) <<  8) |
                (static_cast<u64>(v & 0x000000ffu) << 24);
        } else {
            const u64 v = *x;
            r = ((v & 0xff00000000000000ULL) >> 56) |
                ((v & 0x00ff000000000000ULL) >> 40) |
                ((v & 0x0000ff0000000000ULL) >> 24) |
                ((v & 0x000000ff00000000ULL) >>  8) |
                ((v & 0x00000000ff000000ULL) <<  8) |
                ((v & 0x0000000000ff0000ULL) << 24) |
                ((v & 0x000000000000ff00ULL) << 40) |
                ((v & 0x00000000000000ffULL) << 56);
        }
        t.set(inst.dst, r);
        return true;
    }

    // ---- mulh.{u,s}.64: high half of 64x64 multiply ---------------------
    // ---- divq.{u,s}.64 / divr.{u,s}.64: 128/64 div quotient/remainder ---
    // srcs for div: (rdx, rax, divisor). x86 DIV/IDIV semantics. Divide-
    // by-zero is hardware-trapping; we substitute 0 to keep the trace
    // alive deterministically. Both families use __int128 — non-ISO but
    // GCC and clang both accept it; pedantic warning suppressed locally.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
    using u128 = unsigned __int128;
    using i128 =          __int128;

    if (n == "mulh.u.64") {
        if (inst.src_count < 2) return false;
        const auto a = t.get(inst.srcs[0]);
        const auto b = t.get(inst.srcs[1]);
        if (!a || !b) return false;
        const u128 prod = static_cast<u128>(*a) * static_cast<u128>(*b);
        t.set(inst.dst, static_cast<u64>(prod >> 64));
        return true;
    }
    if (n == "mulh.s.64") {
        if (inst.src_count < 2) return false;
        const auto a = t.get(inst.srcs[0]);
        const auto b = t.get(inst.srcs[1]);
        if (!a || !b) return false;
        const i128 prod = static_cast<i128>(static_cast<i64>(*a)) *
                          static_cast<i128>(static_cast<i64>(*b));
        t.set(inst.dst, static_cast<u64>(static_cast<u128>(prod) >> 64));
        return true;
    }

    auto do_div = [&](bool quotient, bool sgn) -> bool {
        if (inst.src_count < 3) return false;
        const auto rdx = t.get(inst.srcs[0]);
        const auto rax = t.get(inst.srcs[1]);
        const auto div = t.get(inst.srcs[2]);
        if (!rdx || !rax || !div) return false;
        if (*div == 0) { t.set(inst.dst, 0); return true; }
        if (sgn) {
            const i128 num = (static_cast<i128>(static_cast<i64>(*rdx)) << 64)
                           |  static_cast<i128>(*rax);
            const i64 d = static_cast<i64>(*div);
            const i128 r = quotient ? (num / d) : (num % d);
            t.set(inst.dst, static_cast<u64>(static_cast<i64>(r)));
        } else {
            const u128 num = (static_cast<u128>(*rdx) << 64)
                           |  static_cast<u128>(*rax);
            const u128 r = quotient ? (num / *div) : (num % *div);
            t.set(inst.dst, static_cast<u64>(r));
        }
        return true;
    };
    if (n == "divq.u.64") return do_div(/*quotient=*/true,  /*sgn=*/false);
    if (n == "divq.s.64") return do_div(/*quotient=*/true,  /*sgn=*/true);
    if (n == "divr.u.64") return do_div(/*quotient=*/false, /*sgn=*/false);
    if (n == "divr.s.64") return do_div(/*quotient=*/false, /*sgn=*/true);
#pragma GCC diagnostic pop

    // ---- parity / not_parity: even-parity of low byte -------------------
    // x86 PF — set when low byte has even number of set bits. The lifter
    // emits these as the cond for Jp/Jnp jumps.
    if (n == "parity" || n == "not_parity") {
        if (inst.src_count < 1) return false;
        const auto x = t.get(inst.srcs[0]);
        if (!x) return false;
        u64 v = *x & 0xffULL;
        u64 c = 0;
        for (u64 b = 0; b < 8; ++b) c += (v >> b) & 1ULL;
        const u64 even = (c & 1ULL) ? 0u : 1u;
        t.set(inst.dst, n == "parity" ? even : (even ^ 1ULL));
        return true;
    }

    // ---- unordered_fp_compare: NaN check on FP operands -----------------
    // Our abstract value model doesn't track NaN-ness; concrete inputs
    // are always "ordered" (not NaN). Return 0 — the FP-compare path is
    // a fallback the lifter only emits after ucomi when the parity flag
    // matters; on synthetic concrete inputs no FP NaN appears.
    if (n == "unordered_fp_compare") {
        t.set(inst.dst, 0);
        return true;
    }

    // Other intrinsics (`_mm_movemask_epi8`, `arm64.*` family, anything
    // we don't recognize) fall back to the opaque-by-name hash in the
    // caller. Modeling SSE / NEON precisely would require widening the
    // abstract value to 128+ bits, which isn't worth the engineering
    // tax for the matches it would unlock.
    return false;
}

[[nodiscard]] bool step(Trace& t, const IrInst& inst) {
    if (++t.insns_done > kBehavMaxInsnsTrace) {
        // Trace ran past the per-trace insn budget — most likely an
        // input that hits a deep / infinite loop. Don't kill the trace
        // outright; signal the budget cap into a side-effect so two
        // traces that bottomed out at the same place still produce a
        // stable hash, and stop processing this insn.
        t.side_effects.push_back(fnv1a("trace-budget"));
        t.aborted = true;     // forces the block walker to exit
        return true;
    }
    switch (inst.op) {
        case IrOp::Nop:
            return true;
        case IrOp::Assign: {
            if (inst.src_count != 1) return synth_dst(t, inst);
            const auto v = t.get(inst.srcs[0]);
            if (!v) return synth_dst(t, inst);
            t.set(inst.dst, *v);
            return true;
        }
        case IrOp::Add: case IrOp::Sub: case IrOp::Mul:
        case IrOp::Div: case IrOp::Mod:
        case IrOp::And: case IrOp::Or:  case IrOp::Xor:
        case IrOp::Shl: case IrOp::Lshr: case IrOp::Ashr:
            return step_arith(t, inst);
        case IrOp::Neg: case IrOp::Not:
            return step_unop(t, inst);
        case IrOp::CmpEq: case IrOp::CmpNe:
        case IrOp::CmpUlt: case IrOp::CmpUle:
        case IrOp::CmpUgt: case IrOp::CmpUge:
        case IrOp::CmpSlt: case IrOp::CmpSle:
        case IrOp::CmpSgt: case IrOp::CmpSge:
            return step_cmp(t, inst);
        case IrOp::ZExt: case IrOp::SExt: case IrOp::Trunc:
            return step_cast(t, inst);
        case IrOp::Select:
            return step_select(t, inst);
        case IrOp::Load:
            return step_load(t, inst);
        case IrOp::Store:
            return step_store(t, inst);
        case IrOp::Call:
        case IrOp::CallIndirect:
            return step_call(t, inst);
        // Carry / overflow ops: we don't model flags precisely; treat
        // as plain arithmetic on the dst, leave flag bits undefined.
        case IrOp::AddCarry:    case IrOp::SubBorrow:
        case IrOp::AddOverflow: case IrOp::SubOverflow:
            return step_arith(t, inst);
        case IrOp::Clobber:
            // Models caller-saved-reg loss across calls. Re-bind dst
            // to a deterministic-but-distinct value derived from the
            // dst key, so subsequent reads get a stable u64 instead of
            // aborting on missing-bind.
            if (inst.dst.kind != IrValueKind::None) {
                const u64 k = value_key(inst.dst);
                t.set(inst.dst, mix64(fnv1a("clobber"), k));
            }
            return true;
        case IrOp::Intrinsic:
            // First try to compute the intrinsic semantically — bswap,
            // bsr/bsf, divq/divr/mulh, etc. all have well-defined values
            // we can compute precisely so two compilations that disagree
            // on whether to emit an intrinsic vs. open-coded shifts still
            // produce the same trace value. Falls back to opaque-by-name
            // hashing for unmodeled intrinsics. Side-effecting intrinsics
            // with no dst (the `call.args.*` placeholders the lifter
            // emits to stash arg regs before a call) just no-op here.
            if (inst.dst.kind != IrValueKind::None) {
                if (try_semantic_intrinsic(t, inst)) return true;
                u64 h = mix64(fnv1a("intr"),
                              inst.name.empty() ? 0 : fnv1a(inst.name));
                for (u8 i = 0; i < inst.src_count; ++i) {
                    const auto v = t.get(inst.srcs[i]);
                    if (v) h = mix64(h, *v);
                }
                t.set(inst.dst, h);
            }
            return true;
        // Phi handled by the block-entry walker, not here.
        case IrOp::Phi:
            return true;
        // Terminators handled by the block walker.
        case IrOp::Branch:
        case IrOp::CondBranch:
        case IrOp::BranchIndirect:
        case IrOp::Return:
        case IrOp::Unreachable:
            return true;
    }
    // Unknown op: bind dst to a deterministic placeholder so the trace
    // can keep running. Real binaries throw lifter-specific ops at us
    // (e.g. AddCarry on i128) that we don't model precisely; aborting
    // each one would kill behavioural fingerprinting on most fns.
    if (inst.dst.kind != IrValueKind::None) {
        u64 h = mix64(fnv1a("unk-op"), static_cast<u64>(inst.op));
        for (u8 i = 0; i < inst.src_count; ++i) {
            const auto v = t.get(inst.srcs[i]);
            if (v) h = mix64(h, *v);
        }
        t.set(inst.dst, h);
    }
    return true;
}

// ---- Block walker --------------------------------------------------------
//
// Walks block-by-block in execution order, evaluating phi-nodes against
// the previous block's identity, then non-terminator insts via step(),
// then resolves the terminator to pick the next block. Returns the
// per-trace outcome hash on success, or 0 on abort.

[[nodiscard]] u64 run_trace(const IrFunction& fn, const Binary& bin,
                            const std::array<u64, 6>& argv,
                            u64 input_seed,
                            std::size_t max_blocks_visited) {
    Trace t(fn, bin, /*mem_salt=*/mix64(0xC0FFEEULL, input_seed));
    // EMBER_BEHAV_DEBUG=1 logs every trace abort with its reason; useful
    // when inspecting why a particular fn produces no traces. Off by
    // default — the tally in BehavSig.traces_aborted is enough for
    // routine telemetry.
    const bool dbg = std::getenv("EMBER_BEHAV_DEBUG") != nullptr;
    auto bail = [&](const char* why) -> u64 {
        if (dbg) {
            std::fprintf(stderr, "behav abort: %s @insns=%zu fn=0x%lx\n",
                         why, t.insns_done, static_cast<unsigned long>(fn.start));
        }
        return 0;
    };

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

    addr_t cur = fn.start;
    addr_t prev = 0;
    u64 ret_value = 0;
    bool returned = false;
    std::size_t blocks_visited = 0;

    while (!returned) {
        if (++blocks_visited > max_blocks_visited) return bail("max-blocks");
        auto it = fn.block_at.find(cur);
        if (it == fn.block_at.end()) return bail("block-not-found");
        const IrBlock& bb = fn.blocks[it->second];

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
                // — fall back to the first operand. If still nothing,
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
                    // version that's bound. (Cheap heuristic — better
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
                t.side_effects.push_back(mix64(fnv1a("ind-br"), cur));
                returned = true;
                break;
            }
            case IrOp::Unreachable: {
                // Trap intrinsic / unreachable — record as a side-effect
                // and exit cleanly so the trace contributes a hash.
                t.side_effects.push_back(fnv1a("unreachable"));
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
    u64 sx = fnv1a("se");
    for (u64 e : t.side_effects) sx = mix64(sx, e);

    u64 outcome = mix64(fnv1a(kBehavSchema), input_seed);
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
    const u64 schemaSalt = fnv1a(kBehavSchema);
    for (u64 x : xs) {
        for (std::size_t k = 0; k < 8; ++k) {
            const u64 hk = mix64(x, schemaSalt + k * 0x9e3779b97f4a7c15ULL);
            if (hk < mh[k]) mh[k] = hk;
        }
    }
    return mh;
}

[[nodiscard]] u64 multiset_hash(const std::vector<u64>& xs) noexcept {
    u64 h = fnv1a(kBehavSchema);
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

    std::vector<u64> outcomes;
    outcomes.reserve(kBehavTraces);
    u8 done = 0;
    u8 aborted = 0;
    for (std::size_t k = 0; k < kBehavTraces; ++k) {
        const auto argv = mk_inputs(k);
        const u64 seed = mix64(0xDEADBEEFCAFEULL, k);
        const u64 outcome = run_trace(fn, bin, argv, seed, max_blocks_visited);
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

float behav_jaccard(const BehavSig& a, const BehavSig& b) noexcept {
    if (a.exact_hash == 0 || b.exact_hash == 0) return 0.0f;
    if (a.exact_hash == b.exact_hash) return 1.0f;
    int eq = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        if (a.minhash[i] == b.minhash[i]) ++eq;
    }
    return static_cast<float>(eq) / 8.0f;
}

}  // namespace ember
