#include <spelunk/analysis/teef.hpp>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <spelunk/analysis/cfg_builder.hpp>
#include <spelunk/analysis/function.hpp>
#include <spelunk/analysis/teef_behav.hpp>
#include <spelunk/binary/binary.hpp>
#include <spelunk/common/hash.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/disasm/decoder.hpp>
#include <spelunk/disasm/instruction.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/ir/lifter.hpp>
#include <spelunk/ir/passes.hpp>
#include <spelunk/ir/ssa.hpp>
#include <spelunk/structure/region.hpp>
#include <spelunk/structure/structurer.hpp>

namespace spelunk {

namespace {

// Bigram hash over the canonical token stream.
[[nodiscard]] u64 bigram_hash(u64 a, u64 b) noexcept { return mix64(a, b); }

// Token class for literals too large to be anything but an address.
constexpr u64 kClassAddr = fnv1a_64("ADDR");

// Classify a hex / decimal literal. Two principles:
//   1. Small literals (<= 0x10000) keep their literal value - these are
//      bit masks, struct offsets, flag bits, syscall numbers, TLS slot
//      offsets, etc., and they're the dominant identifying signal that
//      distinguishes otherwise shape-equivalent functions
//      (e.g. isalpha vs isdigit only differ in the bit they mask).
//   2. Anything bigger goes to ADDR - those are rip-relative addresses
//      that ASLR/relocation perturbs across builds.
[[nodiscard]] u64 literal_class(u64 v) noexcept {
    if (v <= 0x10000u) {
        // Literal verbatim, but distinguish positive from sign-extended
        // negatives so `-1` vs `0xffffffff` still match.
        char buf[24];
        const int n = std::snprintf(buf, sizeof buf, "%lx", static_cast<unsigned long>(v));
        return fnv1a_64(std::string_view(buf, static_cast<std::size_t>(n)));
    }
    // Negative i64 immediates land here too (high bits set). For those
    // we still want a stable class - emit a sign-extended-class token.
    const i64 s = static_cast<i64>(v);
    if (s < 0 && s >= -0x10000) {
        char buf[24];
        const int n = std::snprintf(buf, sizeof buf, "-%lx", static_cast<unsigned long>(-s));
        return fnv1a_64(std::string_view(buf, static_cast<std::size_t>(n)));
    }
    return kClassAddr;
}

// MinHash sketch over the bigram set. Standard construction: for each
// of K hash functions, store the minimum hash value across the bigram
// set. Two sketches' Jaccard ≈ fraction of positions where minimums
// match. K=8 is at the lower end of useful (precision ~12% on Jaccard
// estimate) but compact enough to fit in the existing fingerprint
// row; matchers wanting tighter precision can use the exact_hash for
// the high-confidence path.
constexpr std::size_t kMinHashSlots = 8;

[[nodiscard]] std::array<u64, kMinHashSlots>
minhash_bigrams(const std::vector<u64>& tokens) noexcept {
    std::array<u64, kMinHashSlots> mh;
    mh.fill(std::numeric_limits<u64>::max());
    if (tokens.size() < 2) return mh;
    for (std::size_t i = 0; i + 1 < tokens.size(); ++i) {
        const u64 b = bigram_hash(tokens[i], tokens[i + 1]);
        for (std::size_t k = 0; k < kMinHashSlots; ++k) {
            // Per-slot deterministic hash perturbation. mix64 with a
            // slot-specific salt gives K independent hash families.
            const u64 hk = mix64(b, fnv1a_64(kTeefSchema) + k * 0x9e3779b97f4a7c15ULL);
            if (hk < mh[k]) mh[k] = hk;
        }
    }
    return mh;
}

[[nodiscard]] u64 exact_token_stream_hash(const std::vector<u64>& tokens) noexcept {
    u64 h = fnv1a_64(kTeefSchema);
    for (u64 t : tokens) h = mix64(h, t);
    return h;
}

}  // namespace

// ---- Direct IR-walking TEEF ----------------------------------------
//
// The canonical hash never needs the pseudo-C text, so the structured IR
// is hashed directly instead of emitting and re-tokenizing it (the
// emitter dominated the old profile).
//
// Token alphabet (one u64 each):
//   - region kinds and structural delimiters
//   - IR opcode names from op_name(IrOp)
//   - operands: Reg -> alpha-renamed (canonical_reg, version),
//     Temp -> alpha-renamed id, Imm -> literal_class, Flag -> its name
//   - anchor names (callees, intrinsics, imports): fnv1a of the string

namespace {

constexpr std::array<u64, 14> kRegionKindHashes = {
    fnv1a_64("R/Empty"),       fnv1a_64("R/Block"),       fnv1a_64("R/Seq"),
    fnv1a_64("R/IfThen"),      fnv1a_64("R/IfElse"),      fnv1a_64("R/While"),
    fnv1a_64("R/DoWhile"),     fnv1a_64("R/For"),         fnv1a_64("R/Loop"),
    fnv1a_64("R/Switch"),      fnv1a_64("R/Return"),      fnv1a_64("R/Unreachable"),
    fnv1a_64("R/Break"),       fnv1a_64("R/Continue"),
};
constexpr u64 kRegionGoto      = fnv1a_64("R/Goto");
constexpr u64 kRegionOpen      = fnv1a_64("{");
constexpr u64 kRegionClose     = fnv1a_64("}");
constexpr u64 kCondTok         = fnv1a_64("?");
constexpr u64 kInvertTok       = fnv1a_64("!");
constexpr u64 kIntrinsicTok    = fnv1a_64("INTRINSIC");
constexpr u64 kFlagTok         = fnv1a_64("FLAG");

struct IrTokenizer {
    std::vector<u64>& out;
    const Binary&     bin;
    std::unordered_map<u64, u64> reg_alpha;   // (reg<<32 | version) → ID hash
    std::unordered_map<u32, u64> temp_alpha;  // temp_id → ID hash
    std::size_t next_alpha = 0;

    IrTokenizer(std::vector<u64>& o, const Binary& b) : out(o), bin(b) {}

    // Resolve an absolute VA to a stable name token. Try in order:
    //   PLT slot → import name (call sites)
    //   GOT slot → import name (the per-instance global pointer family
    //     - __ctype_b_loc, __errno_location, __h_errno_location all
    //     read distinct GOT slots that resolve to distinct symbols)
    //   defined object → its symbol name (rip-rel global accesses)
    //   nothing matches → ADDR class
    [[nodiscard]] u64 resolve_addr_token(addr_t a) const noexcept {
        if (const auto* imp = bin.import_at_plt(a); imp && !imp->name.empty()) {
            return fnv1a_64(imp->name);
        }
        if (const auto* imp = bin.import_at_got(a); imp && !imp->name.empty()) {
            return fnv1a_64(imp->name);
        }
        if (const auto* sym = bin.defined_object_at(a); sym && !sym->name.empty()) {
            return fnv1a_64(sym->name);
        }
        return kClassAddr;
    }

    [[nodiscard]] u64 alpha(u64 key, std::unordered_map<u64, u64>& map) {
        auto it = map.find(key);
        if (it != map.end()) return it->second;
        const u64 h = fnv1a_64("ID") ^ (next_alpha++ * 0x9e3779b97f4a7c15ULL);
        map.emplace(key, h);
        return h;
    }

    void emit_value(const IrValue& v) {
        // Type tag: i1, i8, ..., i64, f32/f64. Distinguishes operand
        // shapes - `Add i32` (likely an int) hashes differently from
        // `Add i64` (likely a pointer offset).
        out.push_back(fnv1a_64(type_name(v.type)));
        switch (v.kind) {
            case IrValueKind::None:
                out.push_back(fnv1a_64("none"));
                return;
            case IrValueKind::Reg: {
                const u64 key = (static_cast<u64>(v.reg) << 32)
                              | static_cast<u64>(v.version);
                out.push_back(alpha(key, reg_alpha));
                return;
            }
            case IrValueKind::Temp: {
                u64 key = 0;
                auto it = temp_alpha.find(v.temp);
                if (it == temp_alpha.end()) {
                    key = fnv1a_64("ID") ^ (next_alpha++ * 0x9e3779b97f4a7c15ULL);
                    temp_alpha.emplace(v.temp, key);
                } else {
                    key = it->second;
                }
                out.push_back(key);
                return;
            }
            case IrValueKind::Imm: {
                const u64 u = static_cast<u64>(v.imm);
                if (u > 0x10000u) {
                    out.push_back(resolve_addr_token(static_cast<addr_t>(u)));
                } else {
                    out.push_back(literal_class(u));
                }
                return;
            }
            case IrValueKind::Flag:
                out.push_back(kFlagTok);
                out.push_back(fnv1a_64(flag_name(v.flag)));
                return;
        }
    }

    void emit_inst(const IrInst& inst) {
        if (inst.op == IrOp::Nop) return;
        out.push_back(fnv1a_64(op_name(inst.op)));
        // Segment-prefixed loads/stores (fs:[..] for TLS, gs:[..] for
        // PEB) are distinguishing signal - `read TLS canary` vs `read
        // ordinary global` look the same opcode-wise but the segment
        // tags them apart.
        if (inst.segment != Reg::None) {
            out.push_back(fnv1a_64("seg"));
            out.push_back(fnv1a_64(reg_name(inst.segment)));
        }
        if (inst.op == IrOp::Call) {
            // A named callee is far stronger evidence than the alpha-
            // renamed arithmetic around it, so its token is repeated 3x
            // to weight both the exact hash and the MinHash. Unresolved
            // (kClassAddr) calls stay single.
            const u64 t = resolve_addr_token(inst.target1);
            out.push_back(t);
            if (t != kClassAddr) {
                out.push_back(t);
                out.push_back(t);
            }
        } else if (inst.op == IrOp::Intrinsic && !inst.name.empty()) {
            // Intrinsic names (cpuid, rdtsc, syscall, x64.lock, etc) are
            // also strong anchors - same 3x weighting.
            const u64 nameTok = fnv1a_64(inst.name);
            out.push_back(kIntrinsicTok);
            out.push_back(nameTok);
            out.push_back(nameTok);
            out.push_back(nameTok);
        }
        if (inst.dst.kind != IrValueKind::None) emit_value(inst.dst);
        for (u8 i = 0; i < inst.src_count; ++i) emit_value(inst.srcs[i]);
    }
};

void emit_block_tokens(IrTokenizer& t, const IrFunction& fn, addr_t block_addr) {
    auto it = fn.block_at.find(block_addr);
    if (it == fn.block_at.end()) return;
    const IrBlock& bb = fn.blocks[it->second];
    for (const auto& inst : bb.insts) t.emit_inst(inst);
}

// (kept for future use; emit_region_tokens references it)

void emit_region_tokens(IrTokenizer& t, const IrFunction& fn, const Region& r) {
    if (r.kind == RegionKind::Goto) {
        t.out.push_back(kRegionGoto);
        return;
    }
    const std::size_t k = static_cast<std::size_t>(r.kind);
    if (k < kRegionKindHashes.size()) {
        t.out.push_back(kRegionKindHashes[k]);
    } else {
        t.out.push_back(fnv1a_64("R/?"));
    }
    if (r.kind == RegionKind::Block) {
        emit_block_tokens(t, fn, r.block_start);
        return;
    }
    if (r.kind == RegionKind::IfThen   || r.kind == RegionKind::IfElse ||
        r.kind == RegionKind::While    || r.kind == RegionKind::DoWhile ||
        r.kind == RegionKind::For) {
        t.out.push_back(kCondTok);
        if (r.invert) t.out.push_back(kInvertTok);
        t.emit_value(r.condition);
    }
    t.out.push_back(kRegionOpen);
    for (const auto& child : r.children) {
        if (child) emit_region_tokens(t, fn, *child);
    }
    t.out.push_back(kRegionClose);
}

}  // namespace

namespace {

// Sum the IR instructions in a region's subtree (excluding Nops). Used
// to threshold which chunks are worth fingerprinting; tiny regions are
// not identifying.
[[nodiscard]] u32 subtree_insts(const IrFunction& fn, const Region& r) {
    u32 total = 0;
    if (r.kind == RegionKind::Block) {
        if (auto it = fn.block_at.find(r.block_start); it != fn.block_at.end()) {
            for (const auto& ins : fn.blocks[it->second].insts) {
                if (ins.op != IrOp::Nop) ++total;
            }
        }
    }
    for (const auto& c : r.children) {
        if (c) total += subtree_insts(fn, *c);
    }
    return total;
}

// Compute a fresh TeefSig over just `r`'s subtree. Each call uses its
// own IrTokenizer, so the alpha-rename map is independent - this is
// the whole point: a chunk hashes the same regardless of where in
// its parent it sits.
[[nodiscard]] TeefSig sig_for_region(const Binary& b, const IrFunction& fn,
                                     const Region& r) {
    std::vector<u64> tokens;
    IrTokenizer t(tokens, b);
    emit_region_tokens(t, fn, r);
    TeefSig s;
    if (!tokens.empty()) {
        s.exact_hash = exact_token_stream_hash(tokens);
        s.minhash    = minhash_bigrams(tokens);
    }
    return s;
}

// Region kinds worth fingerprinting as standalone chunks. The big-fn
// recovery case (huge bucket on glibc 2.35→2.39) requires more than
// just nested control-flow regions: long state-machine arms are flat
// Seq / Block regions, but if they're big enough they're highly
// identifying. So we accept Seq / Block too, with the size threshold
// (collect_chunks's min_insts gate) doing the actual filtering. Goto
// / Return / Continue / Break / Empty stay excluded - they're
// terminators with no meaningful body.
[[nodiscard]] bool is_chunkable_kind(RegionKind k) noexcept {
    switch (k) {
        case RegionKind::IfThen:
        case RegionKind::IfElse:
        case RegionKind::While:
        case RegionKind::DoWhile:
        case RegionKind::For:
        case RegionKind::Loop:
        case RegionKind::Switch:
        case RegionKind::Seq:
        case RegionKind::Block:
            return true;
        default:
            return false;
    }
}

void collect_chunks(const Binary& b, const IrFunction& fn, const Region& r,
                    u32 min_insts, bool is_root,
                    std::vector<TeefChunk>& out) {
    const u32 sz = subtree_insts(fn, r);
    if (!is_root && is_chunkable_kind(r.kind) && sz >= min_insts) {
        TeefChunk ch;
        ch.sig        = sig_for_region(b, fn, r);
        ch.inst_count = sz;
        ch.kind       = static_cast<u8>(r.kind);
        if (ch.sig.exact_hash != 0) out.push_back(ch);
    }
    for (const auto& c : r.children) {
        if (c) collect_chunks(b, fn, *c, min_insts, false, out);
    }
}

}  // namespace

namespace {

// Per-fn IR insn cap. Bails the L2 path on huge VMP / Themida / Enigma
// fns whose region-tree walk is O(insns × region_depth) and would
// dominate a parallel sweep for 30+ minutes per fn. SPELUNK_TEEF_MAX_INSNS
// overrides the default of 4096; at that limit a normal 50–500 insn
// fn isn't affected and aggressive inlining still fits.
[[nodiscard]] std::size_t teef_max_insns_per_fn() noexcept {
    static const std::size_t v = []() -> std::size_t {
        if (const char* s = std::getenv("SPELUNK_TEEF_MAX_INSNS")) {
            try { return static_cast<std::size_t>(std::stoull(s)); }
            catch (...) { /* malformed → fall through to default */ }
        }
        return 4096;
    }();
    return v;
}

[[nodiscard]] bool cfg_over_budget(const Function& fn,
                                   const TeefComputeOptions& opts) noexcept {
    if (opts.max_cfg_blocks > 0 && fn.blocks.size() > opts.max_cfg_blocks) {
        return true;
    }
    std::size_t edges = 0;
    std::size_t insts = 0;
    for (const auto& bb : fn.blocks) {
        edges += bb.successors.size();
        insts += bb.instructions.size();
    }
    if (opts.max_cfg_edges > 0 && edges > opts.max_cfg_edges) return true;
    if (opts.max_cfg_insts > 0 && insts > opts.max_cfg_insts) return true;
    return false;
}

[[nodiscard]] bool ir_over_budget(const IrFunction& fn,
                                  const TeefComputeOptions& opts) noexcept {
    std::size_t total = 0;
    for (const auto& bb : fn.blocks) total += bb.insts.size();
    const u64 cap = opts.max_ir_insts > 0
        ? opts.max_ir_insts
        : static_cast<u64>(teef_max_insns_per_fn());
    return total > cap;
}

// L0 topology hash from the pre-lift CFG, so it can gate the lift when
// --l0-prefilter is on. Features: block count, edge count, max in/out
// degree, blocks with more than one predecessor (loop proxy), return
// blocks. Corpus and query both hash the CFG, so lift-time block
// splits do not matter.
[[nodiscard]] u64 compute_topo_hash_from_cfg(const Function& fn) noexcept {
    u32 num_blocks       = static_cast<u32>(fn.blocks.size());
    u32 num_edges        = 0;
    u32 max_in_degree    = 0;
    u32 max_out_degree   = 0;
    u32 num_loop_headers = 0;
    u32 num_returns      = 0;
    for (const auto& bb : fn.blocks) {
        num_edges      += static_cast<u32>(bb.successors.size());
        max_in_degree   = std::max<u32>(max_in_degree,
                                        static_cast<u32>(bb.predecessors.size()));
        max_out_degree  = std::max<u32>(max_out_degree,
                                        static_cast<u32>(bb.successors.size()));
        if (bb.predecessors.size() > 1) ++num_loop_headers;
        if (bb.kind == BlockKind::Return) ++num_returns;
    }
    u64 h = fnv1a_64("topo");
    h = mix64(h, num_blocks);
    h = mix64(h, num_edges);
    h = mix64(h, max_in_degree);
    h = mix64(h, max_out_degree);
    h = mix64(h, num_loop_headers);
    h = mix64(h, num_returns);
    return h;
}

// L1 byte-prefix hash for tiny functions (<= 64 bytes, <= 16 insns):
// (mnemonic, operand shape, register identity, classed immediate) per
// instruction in address order, folded into one u64. Returns 0 for
// anything larger; L2/L4 serve those. Register identity is literal
// (`mov rax, [rdi]` != `mov rcx, [rsi]`) and immediates > 0x10000 are
// classed to ADDR, the same trade-off FLIRT makes.
[[nodiscard]] u64 compute_prefix_hash(const Function& fn) noexcept {
    constexpr u32 kMaxInsns = 16;
    constexpr u32 kMaxBytes = 64;
    constexpr u32 kMinInsns = 3;

    std::vector<const BasicBlock*> ordered;
    ordered.reserve(fn.blocks.size());
    for (const auto& bb : fn.blocks) ordered.push_back(&bb);
    std::sort(ordered.begin(), ordered.end(),
              [](const BasicBlock* a, const BasicBlock* b) {
                  return a->start < b->start;
              });

    u32 inst_count = 0;
    u32 byte_count = 0;
    u64 h = fnv1a_64("prefix.v1");

    for (const auto* bb : ordered) {
        for (const auto& insn : bb->instructions) {
            if (insn.mnemonic == Mnemonic::Invalid) continue;
            ++inst_count;
            byte_count += insn.length;
            if (inst_count > kMaxInsns || byte_count > kMaxBytes) return 0;

            h = mix64(h, fnv1a_64(mnemonic_name(insn.mnemonic)));
            h = mix64(h, static_cast<u64>(insn.num_operands));
            for (u8 oi = 0; oi < insn.num_operands; ++oi) {
                const auto& op = insn.operands[oi];
                h = mix64(h, static_cast<u64>(op.kind));
                switch (op.kind) {
                    case Operand::Kind::None:
                        break;
                    case Operand::Kind::Register:
                        h = mix64(h, fnv1a_64(reg_name(op.reg)));
                        break;
                    case Operand::Kind::Memory:
                        h = mix64(h, fnv1a_64(reg_name(op.mem.base)));
                        h = mix64(h, fnv1a_64(reg_name(op.mem.index)));
                        h = mix64(h, static_cast<u64>(op.mem.scale));
                        h = mix64(h, static_cast<u64>(op.mem.size));
                        if (op.mem.has_disp) {
                            h = mix64(h, literal_class(static_cast<u64>(op.mem.disp)));
                        }
                        break;
                    case Operand::Kind::Immediate:
                        h = mix64(h, literal_class(static_cast<u64>(op.imm.value)));
                        h = mix64(h, static_cast<u64>(op.imm.size));
                        break;
                    case Operand::Kind::Relative:
                        // Branch/call relative - the target is address-
                        // dependent, so class it. Direction (forward/back)
                        // is preserved by the sign of offset.
                        h = mix64(h, op.rel.offset > 0 ? 1u : 0u);
                        h = mix64(h, static_cast<u64>(op.rel.size));
                        break;
                }
            }
        }
    }

    if (inst_count < kMinInsns) return 0;
    return h;
}

// Tail half of compute_teef_with_chunks / compute_teef_max - given a
// post-cleanup IR, run the structurer and produce L2 + chunks. Returns
// a partially-filled TeefFunction (whole/chunks). Caller is responsible
// for setting topo_hash and behav.
[[nodiscard]] TeefFunction
compute_l2_from_ir(const Binary& b, IrFunction& ir, u32 min_chunk_insts) {
    TeefFunction out;
    const Structurer s;
    auto sf = s.structure(ir);
    if (!sf || !sf->body) return out;

    out.whole = sig_for_region(b, ir, *sf->body);
    if (out.whole.exact_hash == 0) return out;

    collect_chunks(b, ir, *sf->body, min_chunk_insts,
                   /*is_root=*/true, out.chunks);
    std::sort(out.chunks.begin(), out.chunks.end(),
              [](const TeefChunk& x, const TeefChunk& y) {
                  return x.inst_count > y.inst_count;
              });
    return out;
}

}  // namespace

TeefFunction
compute_teef_with_chunks(const Binary& b, addr_t fn_start, u32 min_chunk_insts) {
    TeefComputeOptions opts;
    opts.min_chunk_insts = min_chunk_insts;
    return compute_teef_with_chunks(b, fn_start, opts);
}

TeefFunction
compute_teef_with_chunks(const Binary& b, addr_t fn_start,
                         const TeefComputeOptions& opts) {
    TeefFunction out;

    auto dec_r = make_decoder(b);
    if (!dec_r) return out;
    const CfgBuilder cfg(b, **dec_r);
    auto fn_r = cfg.build(fn_start, {});
    if (!fn_r) return out;

    out.topo_hash   = compute_topo_hash_from_cfg(*fn_r);
    out.prefix_hash = compute_prefix_hash(*fn_r);
    if (cfg_over_budget(*fn_r, opts)) return out;

    auto lifter_r = make_lifter(b);
    if (!lifter_r) return out;
    auto ir_r = (*lifter_r)->lift(*fn_r);
    if (!ir_r) return out;

    if (ir_over_budget(*ir_r, opts)) return out;

    const SsaBuilder ssa;
    if (auto rv = ssa.convert(*ir_r); !rv) return out;
    if (auto rv = run_cleanup(*ir_r); !rv) return out;

    auto l2 = compute_l2_from_ir(b, *ir_r, opts.min_chunk_insts);
    out.whole  = l2.whole;
    out.chunks = std::move(l2.chunks);
    return out;
}

TeefFunction
compute_teef_max(const Binary& b, addr_t fn_start, u32 min_chunk_insts,
                 const std::unordered_set<u64>* l4_topo_filter) {
    TeefComputeOptions opts;
    opts.min_chunk_insts = min_chunk_insts;
    opts.l4_topo_filter = l4_topo_filter;
    return compute_teef_max(b, fn_start, opts);
}

TeefFunction
compute_teef_max(const Binary& b, addr_t fn_start,
                 const TeefComputeOptions& opts) {
    TeefFunction out;

    auto dec_r = make_decoder(b);
    if (!dec_r) return out;
    const CfgBuilder cfg(b, **dec_r);
    auto fn_r = cfg.build(fn_start, {});
    if (!fn_r) return out;

    // Compute the topology hash directly from the CFG - pre-lift, so
    // we can use it as an early-exit gate. The lift + SSA + cleanup
    // pipeline is the dominant per-fn cost on obfuscated targets
    // (200+ ms on a heavy fn); skipping it for fns that can't match
    // anyway is the difference between a 50-minute scan and a few
    // minutes.
    out.topo_hash   = compute_topo_hash_from_cfg(*fn_r);
    out.prefix_hash = compute_prefix_hash(*fn_r);
    if (cfg_over_budget(*fn_r, opts)) return out;

    // L0 pre-filter: when the caller passes the corpus's topo-hash
    // set, fns whose topology isn't represented in the corpus return
    // early with only topo populated - no lift, no L2, no L4. The
    // recognizer ignores fns with `whole.exact_hash == 0`, so these
    // entries effectively don't participate in matching.
    if (opts.l4_topo_filter && !opts.l4_topo_filter->contains(out.topo_hash)) {
        return out;
    }

    auto lifter_r = make_lifter(b);
    if (!lifter_r) return out;
    auto ir_r = (*lifter_r)->lift(*fn_r);
    if (!ir_r) return out;

    if (ir_over_budget(*ir_r, opts)) return out;

    const SsaBuilder ssa;
    if (auto rv = ssa.convert(*ir_r); !rv) return out;
    if (auto rv = run_cleanup(*ir_r); !rv) return out;

    // L4 first - operates on the cleaned flat IR, no structurer needed.
    if (!opts.skip_l4) out.behav = compute_behav_sig_from_ir(*ir_r, b);

    // L2 - structurer + region tokenization on the same IR.
    auto l2 = compute_l2_from_ir(b, *ir_r, opts.min_chunk_insts);
    out.whole  = l2.whole;
    out.chunks = std::move(l2.chunks);
    return out;
}

}  // namespace spelunk
