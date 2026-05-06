#include <ember/analysis/forge_spec.hpp>

#include <algorithm>
#include <format>
#include <queue>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <ember/analysis/cfg_builder.hpp>
#include <ember/analysis/import_sigs.hpp>
#include <ember/analysis/pipeline.hpp>
#include <ember/analysis/type_infer_local.hpp>
#include <ember/disasm/decoder.hpp>
#include <ember/ir/abi.hpp>
#include <ember/ir/lifter.hpp>
#include <ember/ir/passes.hpp>
#include <ember/ir/ssa.hpp>

namespace ember {

namespace {

constexpr int kMaxExprDepth   = 24;   // bound symbolic walk depth
constexpr int kMaxFieldChain  = 6;    // [+a][+b][+c]... cap
constexpr int kMaxCallChain   = 8;    // BFS layers when finding entry → target
constexpr std::size_t kMaxBfsCallees = 256;

[[nodiscard]] u64 pack_key(const SsaKey& k) noexcept {
    return (static_cast<u64>(std::get<0>(k)) << 56)
         | (static_cast<u64>(std::get<1>(k)) << 32)
         |  static_cast<u64>(std::get<2>(k));
}

// Map an arg register to its 0-based ABI slot, or -1 if it isn't one.
[[nodiscard]] int arg_slot_for(Reg r, Abi abi) noexcept {
    auto regs = int_arg_regs(abi);
    for (std::size_t i = 0; i < regs.size(); ++i) {
        if (regs[i] == r) return static_cast<int>(i);
    }
    return -1;
}

struct LiftedFn {
    Function    fn;
    IrFunction  ir;
    std::unordered_map<u64, std::pair<addr_t, std::size_t>> def_site;
    Abi         abi = Abi::Unknown;
};

[[nodiscard]] Result<LiftedFn>
lift_one(const Binary& b, CfgBuilder& cb,
         const Lifter& lifter, addr_t entry) {
    auto fn_r = cb.build(entry, "");
    if (!fn_r) return std::unexpected(fn_r.error());
    auto ir_r = lifter.lift(*fn_r);
    if (!ir_r) return std::unexpected(ir_r.error());

    const SsaBuilder ssa;
    if (auto rv = ssa.convert(*ir_r); !rv) return std::unexpected(rv.error());
    if (auto rv = run_cleanup(*ir_r); !rv) return std::unexpected(rv.error());
    seed_call_return_types(b, *ir_r);
    infer_local_types(*ir_r);

    LiftedFn out;
    out.fn  = std::move(*fn_r);
    out.ir  = std::move(*ir_r);
    out.abi = lifter.abi();

    for (const auto& bb : out.ir.blocks) {
        for (std::size_t i = 0; i < bb.insts.size(); ++i) {
            const auto& in = bb.insts[i];
            if (auto k = ssa_key(in.dst); k) {
                out.def_site[pack_key(*k)] = {bb.start, i};
            }
            for (std::size_t pi = 0; pi < in.phi_operands.size(); ++pi) {
                // phi operand sites are not unique defs themselves
                (void)pi;
            }
        }
    }
    return out;
}

[[nodiscard]] const IrBlock*
ir_block_at(const IrFunction& ir, addr_t addr) noexcept {
    auto it = ir.block_at.find(addr);
    if (it == ir.block_at.end()) return nullptr;
    return &ir.blocks[it->second];
}

// BFS shortest path from ir.start to a block that satisfies `is_terminus`.
// Returns the addresses of the path including both endpoints, or empty
// when no path exists.
template <typename Pred>
[[nodiscard]] std::vector<addr_t>
bfs_block_path(const IrFunction& ir, Pred is_terminus) {
    std::queue<addr_t> q;
    std::unordered_map<addr_t, addr_t> parent;
    parent[ir.start] = 0;
    q.push(ir.start);
    addr_t hit = 0;
    while (!q.empty()) {
        addr_t cur = q.front(); q.pop();
        const IrBlock* bb = ir_block_at(ir, cur);
        if (!bb) continue;
        if (is_terminus(*bb)) { hit = cur; break; }
        for (addr_t s : bb->successors) {
            if (parent.contains(s)) continue;
            parent[s] = cur;
            q.push(s);
        }
    }
    if (hit == 0) return {};
    std::vector<addr_t> path;
    for (addr_t v = hit; ; ) {
        path.push_back(v);
        if (v == ir.start) break;
        auto it = parent.find(v);
        if (it == parent.end() || it->second == 0) {
            if (v != ir.start) return {};
            break;
        }
        v = it->second;
    }
    std::reverse(path.begin(), path.end());
    return path;
}

[[nodiscard]] std::vector<addr_t>
bfs_call_chain(const Binary& b, addr_t entry, addr_t target) {
    if (entry == target) return {entry};
    std::queue<std::pair<addr_t, int>> q;
    std::unordered_map<addr_t, addr_t> parent;
    parent[entry] = 0;
    q.push({entry, 0});
    bool found = false;
    while (!q.empty() && !found) {
        auto [cur, depth] = q.front(); q.pop();
        if (depth >= kMaxCallChain) continue;
        auto callees = compute_callees(b, cur);
        std::size_t budget = std::min(callees.size(), kMaxBfsCallees);
        for (std::size_t i = 0; i < budget; ++i) {
            addr_t c = callees[i];
            if (parent.contains(c)) continue;
            parent[c] = cur;
            if (c == target) { found = true; break; }
            q.push({c, depth + 1});
        }
    }
    if (!parent.contains(target)) return {};
    std::vector<addr_t> chain;
    addr_t v = target;
    while (true) {
        chain.push_back(v);
        if (v == entry) break;
        auto it = parent.find(v);
        if (it == parent.end()) return {};
        v = it->second;
        if (v == 0) {
            if (chain.back() != entry) return {};
            break;
        }
    }
    std::reverse(chain.begin(), chain.end());
    return chain;
}

// =============================================================
// Symbolic backwards walk
// =============================================================

class ExprBuilder {
public:
    ExprBuilder(const LiftedFn& lf,
                const std::unordered_map<addr_t, addr_t>& path_pred)
        : lf_(lf), path_pred_(path_pred) {}

    ForgeExpr build(const IrValue& v, addr_t /*use_block*/, int depth = 0) {
        ForgeExpr e;
        if (depth >= kMaxExprDepth) return e;

        if (v.kind == IrValueKind::Imm) {
            e.kind  = ForgeExpr::Kind::Imm;
            e.imm   = v.imm;
            e.width = v.type;
            return e;
        }

        if (v.kind == IrValueKind::None) return e;

        const auto k = ssa_key(v);
        if (!k) return e;

        // version 0 = live-in. For Reg, that's a parameter (or a
        // callee-saved that the function uses uninitialised — we
        // tag both as Param and let the formatter sort it out).
        if (v.version == 0 && v.kind == IrValueKind::Reg) {
            e.kind        = ForgeExpr::Kind::Param;
            e.param_reg   = v.reg;
            e.param_index = arg_slot_for(v.reg, lf_.abi);
            e.width       = v.type;
            return e;
        }

        // Memo
        u64 packed = pack_key(*k);
        auto cached = memo_.find(packed);
        if (cached != memo_.end()) return cached->second;

        auto site = lf_.def_site.find(packed);
        if (site == lf_.def_site.end()) return e;

        const auto [block, idx] = site->second;
        const IrBlock* bb = ir_block_at(lf_.ir, block);
        if (!bb || idx >= bb->insts.size()) return e;
        const IrInst& def = bb->insts[idx];

        e = lower_inst(def, block, depth);
        memo_[packed] = e;
        return e;
    }

private:
    [[nodiscard]] ForgeExpr lower_inst(const IrInst& def, addr_t def_block, int depth) {
        ForgeExpr e;
        switch (def.op) {
            case IrOp::Assign: {
                return build(def.srcs[0], def_block, depth + 1);
            }
            case IrOp::Load: {
                e.kind  = ForgeExpr::Kind::Load;
                e.width = def.dst.type;
                e.children.push_back(build(def.srcs[0], def_block, depth + 1));
                return e;
            }
            case IrOp::Add: case IrOp::Sub: case IrOp::Mul:
            case IrOp::And: case IrOp::Or:  case IrOp::Xor:
            case IrOp::Shl: case IrOp::Lshr: case IrOp::Ashr: {
                e.kind  = ForgeExpr::Kind::BinOp;
                e.op    = def.op;
                e.width = def.dst.type;
                e.children.push_back(build(def.srcs[0], def_block, depth + 1));
                e.children.push_back(build(def.srcs[1], def_block, depth + 1));
                return e;
            }
            case IrOp::CmpEq: case IrOp::CmpNe:
            case IrOp::CmpUlt: case IrOp::CmpUle:
            case IrOp::CmpUgt: case IrOp::CmpUge:
            case IrOp::CmpSlt: case IrOp::CmpSle:
            case IrOp::CmpSgt: case IrOp::CmpSge: {
                e.kind  = ForgeExpr::Kind::Cmp;
                e.op    = def.op;
                e.width = IrType::I1;
                e.children.push_back(build(def.srcs[0], def_block, depth + 1));
                e.children.push_back(build(def.srcs[1], def_block, depth + 1));
                return e;
            }
            case IrOp::ZExt: case IrOp::SExt: case IrOp::Trunc: {
                ForgeExpr inner = build(def.srcs[0], def_block, depth + 1);
                inner.width = def.dst.type;
                return inner;
            }
            case IrOp::Neg: case IrOp::Not: {
                e.kind = ForgeExpr::Kind::BinOp;
                e.op   = def.op;
                e.width = def.dst.type;
                e.children.push_back(build(def.srcs[0], def_block, depth + 1));
                return e;
            }
            case IrOp::Phi: {
                addr_t pred = 0;
                if (auto it = path_pred_.find(def_block); it != path_pred_.end()) {
                    pred = it->second;
                }
                if (pred != 0) {
                    for (std::size_t i = 0; i < def.phi_preds.size(); ++i) {
                        if (def.phi_preds[i] == pred &&
                            i < def.phi_operands.size()) {
                            return build(def.phi_operands[i], pred, depth + 1);
                        }
                    }
                }
                e.kind = ForgeExpr::Kind::Phi;
                e.op   = IrOp::Phi;
                for (const auto& op : def.phi_operands) {
                    e.children.push_back(build(op, def_block, depth + 1));
                }
                return e;
            }
            case IrOp::Call:
            case IrOp::CallIndirect: {
                e.kind        = ForgeExpr::Kind::Call;
                e.call_target = def.target1;
                e.width       = def.dst.type;
                return e;
            }
            case IrOp::Select: {
                // Pick the "then" branch as the canonical witness — the
                // chosen path is per-block, not per-operand, so we pick a
                // side and surface the other in unknown form rather than
                // produce a Phi-ish merge node.
                if (def.src_count >= 2) {
                    return build(def.srcs[1], def_block, depth + 1);
                }
                return e;
            }
            default:
                e.kind = ForgeExpr::Kind::Unknown;
                e.op   = def.op;
                return e;
        }
    }

    const LiftedFn& lf_;
    const std::unordered_map<addr_t, addr_t>& path_pred_;
    std::unordered_map<u64, ForgeExpr> memo_;
};

// =============================================================
// Pretty printer
// =============================================================

[[nodiscard]] std::string fmt_imm(i64 v) {
    if (v >= 0 && v < 16) return std::format("{}", v);
    if (v < 0) return std::format("-0x{:x}", -v);
    return std::format("0x{:x}", v);
}

[[nodiscard]] std::string_view cmp_op_str(IrOp o) noexcept {
    switch (o) {
        case IrOp::CmpEq:  return "==";
        case IrOp::CmpNe:  return "!=";
        case IrOp::CmpUlt: return "u<";
        case IrOp::CmpUle: return "u<=";
        case IrOp::CmpUgt: return "u>";
        case IrOp::CmpUge: return "u>=";
        case IrOp::CmpSlt: return "<";
        case IrOp::CmpSle: return "<=";
        case IrOp::CmpSgt: return ">";
        case IrOp::CmpSge: return ">=";
        default:           return "?";
    }
}

[[nodiscard]] std::string_view bin_op_str(IrOp o) noexcept {
    switch (o) {
        case IrOp::Add:  return "+";
        case IrOp::Sub:  return "-";
        case IrOp::Mul:  return "*";
        case IrOp::And:  return "&";
        case IrOp::Or:   return "|";
        case IrOp::Xor:  return "^";
        case IrOp::Shl:  return "<<";
        case IrOp::Lshr: return ">>u";
        case IrOp::Ashr: return ">>";
        case IrOp::Neg:  return "-";
        case IrOp::Not:  return "~";
        default:         return "?";
    }
}

[[nodiscard]] IrOp invert_cmp(IrOp o) noexcept {
    switch (o) {
        case IrOp::CmpEq:  return IrOp::CmpNe;
        case IrOp::CmpNe:  return IrOp::CmpEq;
        case IrOp::CmpUlt: return IrOp::CmpUge;
        case IrOp::CmpUle: return IrOp::CmpUgt;
        case IrOp::CmpUgt: return IrOp::CmpUle;
        case IrOp::CmpUge: return IrOp::CmpUlt;
        case IrOp::CmpSlt: return IrOp::CmpSge;
        case IrOp::CmpSle: return IrOp::CmpSgt;
        case IrOp::CmpSgt: return IrOp::CmpSle;
        case IrOp::CmpSge: return IrOp::CmpSlt;
        default:           return o;
    }
}

[[nodiscard]] std::string_view ir_type_short(IrType t) noexcept {
    switch (t) {
        case IrType::I1:  return "u8";
        case IrType::I8:  return "u8";
        case IrType::I16: return "u16";
        case IrType::I32: return "u32";
        case IrType::I64: return "u64";
        case IrType::F32: return "f32";
        case IrType::F64: return "f64";
        default:          return "u64";
    }
}

// Walk a Load chain and pull off `[arg + off][...]`. Returns true and
// fills `param`, `chain` if the entire address expression is rooted at
// a parameter through nested loads; false otherwise.
[[nodiscard]] bool
peel_load_chain(const ForgeExpr& expr,
                Reg& param_reg, int& param_idx,
                std::vector<i64>& chain,
                IrType& width) {
    chain.clear();
    const ForgeExpr* cur = &expr;
    width = expr.width;
    bool first = true;
    while (cur->kind == ForgeExpr::Kind::Load) {
        if (first) { width = cur->width; first = false; }
        if (cur->children.size() != 1) return false;
        const ForgeExpr& addr = cur->children[0];
        // Address shape:
        //   Param                         → offset 0
        //   BinOp(Add, Param, Imm)        → offset = imm
        //   BinOp(Add, Load(...), Imm)    → offset = imm, recurse on Load
        //   Load(...)                     → offset = 0, recurse
        i64 off = 0;
        const ForgeExpr* base = &addr;
        if (addr.kind == ForgeExpr::Kind::BinOp &&
            addr.op == IrOp::Add &&
            addr.children.size() == 2) {
            const ForgeExpr& a = addr.children[0];
            const ForgeExpr& b = addr.children[1];
            if (a.kind == ForgeExpr::Kind::Imm) {
                off  = a.imm;
                base = &b;
            } else if (b.kind == ForgeExpr::Kind::Imm) {
                off  = b.imm;
                base = &a;
            } else {
                return false;
            }
        }
        chain.push_back(off);
        if (chain.size() > kMaxFieldChain) return false;
        if (base->kind == ForgeExpr::Kind::Param) {
            param_reg = base->param_reg;
            param_idx = base->param_index;
            std::reverse(chain.begin(), chain.end());
            return true;
        }
        if (base->kind == ForgeExpr::Kind::Load) {
            cur = base;
            continue;
        }
        return false;
    }
    return false;
}

// Canonicalize a comparison so the constraint reads naturally:
//   Cmp(BinOp(Sub, A, B), Imm 0)        → Cmp(A, B)
//   Cmp(BinOp(Add, A, Imm c), Imm k)    → Cmp(A, k - c)
//   Cmp(BinOp(Sub, A, Imm c), Imm k)    → Cmp(A, k + c)
//   Cmp(BinOp(Xor, A, B), Imm 0)        → CmpEq → Cmp(A, B)
// Idempotent; only fires when the inner shape exactly matches.
[[nodiscard]] ForgeExpr canonicalize_cmp(ForgeExpr cmp) {
    if (cmp.kind != ForgeExpr::Kind::Cmp || cmp.children.size() != 2) return cmp;
    const ForgeExpr& lhs = cmp.children[0];
    const ForgeExpr& rhs = cmp.children[1];

    if (lhs.kind == ForgeExpr::Kind::BinOp && lhs.children.size() == 2 &&
        rhs.kind == ForgeExpr::Kind::Imm) {
        const ForgeExpr& a = lhs.children[0];
        const ForgeExpr& b = lhs.children[1];
        const i64 k = rhs.imm;

        if (lhs.op == IrOp::Sub && b.kind == ForgeExpr::Kind::Imm) {
            ForgeExpr c = cmp;
            c.children[0] = a;
            c.children[1].kind = ForgeExpr::Kind::Imm;
            c.children[1].imm  = k + b.imm;
            return c;
        }
        if (lhs.op == IrOp::Add && b.kind == ForgeExpr::Kind::Imm) {
            ForgeExpr c = cmp;
            c.children[0] = a;
            c.children[1].kind = ForgeExpr::Kind::Imm;
            c.children[1].imm  = k - b.imm;
            return c;
        }
        if (lhs.op == IrOp::Sub && k == 0) {
            ForgeExpr c = cmp;
            c.children[0] = a;
            c.children[1] = b;
            return c;
        }
        if (lhs.op == IrOp::Xor && k == 0 &&
            (cmp.op == IrOp::CmpEq || cmp.op == IrOp::CmpNe)) {
            ForgeExpr c = cmp;
            c.children[0] = a;
            c.children[1] = b;
            return c;
        }
    }
    return cmp;
}

[[nodiscard]] std::string format_field_chain(int param_index, Reg /*reg*/,
                                             std::span<const i64> chain) {
    std::string s = (param_index >= 0)
        ? std::format("arg{}", param_index)
        : std::string("local");
    for (i64 off : chain) {
        s = std::format("*({} + {})", s, fmt_imm(off));
    }
    return s;
}

}  // namespace

std::string format_forge_expr(const ForgeExpr& e) {
    switch (e.kind) {
        case ForgeExpr::Kind::Unknown: return "<unknown>";
        case ForgeExpr::Kind::Imm:     return fmt_imm(e.imm);
        case ForgeExpr::Kind::Param: {
            if (e.param_index >= 0) {
                return std::format("arg{}", e.param_index);
            }
            return std::format("livein_{}", reg_name(e.param_reg));
        }
        case ForgeExpr::Kind::Load: {
            if (e.children.empty()) return "<load>";
            return std::format("*({}*){}",
                ir_type_short(e.width),
                format_forge_expr(e.children[0]));
        }
        case ForgeExpr::Kind::BinOp: {
            if (e.children.size() == 1) {
                return std::format("({}{})",
                    bin_op_str(e.op), format_forge_expr(e.children[0]));
            }
            if (e.children.size() == 2) {
                return std::format("({} {} {})",
                    format_forge_expr(e.children[0]),
                    bin_op_str(e.op),
                    format_forge_expr(e.children[1]));
            }
            return "<binop>";
        }
        case ForgeExpr::Kind::Cmp: {
            if (e.children.size() == 2) {
                return std::format("{} {} {}",
                    format_forge_expr(e.children[0]),
                    cmp_op_str(e.op),
                    format_forge_expr(e.children[1]));
            }
            return "<cmp>";
        }
        case ForgeExpr::Kind::Phi: return "<phi>";
        case ForgeExpr::Kind::Call:
            return std::format("call({:#x})", e.call_target);
    }
    return "?";
}

namespace {

[[nodiscard]] std::string
format_decision(const ForgeExpr& cond, bool went_taken) {
    if (cond.kind == ForgeExpr::Kind::Cmp && cond.children.size() == 2) {
        const IrOp op = went_taken ? cond.op : invert_cmp(cond.op);
        return std::format("{} {} {}",
            format_forge_expr(cond.children[0]),
            cmp_op_str(op),
            format_forge_expr(cond.children[1]));
    }
    if (went_taken) return format_forge_expr(cond);
    return std::format("!({})", format_forge_expr(cond));
}

void extract_field_reqs(const ForgeExpr& cond, bool went_taken,
                        addr_t branch_va, addr_t in_fn,
                        std::vector<FieldRequirement>& out) {
    if (cond.kind != ForgeExpr::Kind::Cmp || cond.children.size() != 2) return;
    const IrOp eff_op = went_taken ? cond.op : invert_cmp(cond.op);

    auto try_side = [&](const ForgeExpr& field_side, const ForgeExpr& other,
                        bool lhs_is_field) {
        FieldRequirement req;
        std::vector<i64> chain;
        Reg              preg = Reg::None;
        int              pidx = -1;
        IrType           width = field_side.width;
        if (!peel_load_chain(field_side, preg, pidx, chain, width)) return false;
        req.param_reg     = preg;
        req.param_index   = pidx;
        req.offset_chain  = std::move(chain);
        req.access_width  = width;
        req.cmp_op        = eff_op;
        req.rhs           = other;
        req.lhs_is_field  = lhs_is_field;
        req.must_be_taken = true;
        req.site_va       = branch_va;
        req.in_function   = in_fn;
        out.push_back(std::move(req));
        return true;
    };

    if (try_side(cond.children[0], cond.children[1], true)) return;
    try_side(cond.children[1], cond.children[0], false);
}

}  // namespace

Result<ForgeSpec>
infer_forge_spec(const Binary& b, addr_t entry_va, addr_t target_va) {
    ForgeSpec out;
    out.entry_va  = entry_va;
    out.target_va = target_va;

    if (auto cfn = containing_function(b, entry_va)) {
        out.entry_name = cfn->name;
    }
    auto target_cfn = containing_function(b, target_va);
    if (!target_cfn) {
        return std::unexpected(Error::out_of_bounds(std::format(
            "--forge-spec: target VA {:#x} is not within any function",
            target_va)));
    }
    out.target_fn_name = target_cfn->name;

    auto chain = bfs_call_chain(b, entry_va, target_cfn->entry);
    if (chain.empty()) {
        out.warnings.push_back(std::format(
            "no call-graph path from {:#x} to {:#x} within {} hops",
            entry_va, target_cfn->entry, kMaxCallChain));
        return out;
    }
    out.call_chain = chain;

    auto dec_r = make_decoder(b);
    if (!dec_r) return std::unexpected(dec_r.error());
    const Decoder& dec = **dec_r;
    CfgBuilder cb(b, dec);
    auto lifter_r = make_lifter(b);
    if (!lifter_r) return std::unexpected(lifter_r.error());
    const Lifter& lifter = **lifter_r;

    bool any_path = false;

    for (std::size_t i = 0; i < chain.size(); ++i) {
        const addr_t fn_addr = chain[i];
        const bool   final_fn = (i + 1 == chain.size());
        const addr_t next_callee = final_fn ? 0 : chain[i + 1];

        auto lf_r = lift_one(b, cb, lifter, fn_addr);
        if (!lf_r) {
            out.warnings.push_back(std::format(
                "lift failed for fn {:#x}: {}", fn_addr, lf_r.error().message));
            continue;
        }
        LiftedFn& lf = *lf_r;

        std::vector<addr_t> path;
        if (final_fn) {
            // Reach the IR block containing target_va.
            path = bfs_block_path(lf.ir, [&](const IrBlock& bb) {
                return target_va >= bb.start && target_va < bb.end;
            });
        } else {
            // Reach a block whose terminator is a Call to next_callee, or
            // any block containing such a Call inst.
            path = bfs_block_path(lf.ir, [&](const IrBlock& bb) {
                for (const auto& in : bb.insts) {
                    if (in.op == IrOp::Call && in.target1 == next_callee) {
                        return true;
                    }
                }
                return false;
            });
        }

        if (path.empty()) {
            out.warnings.push_back(std::format(
                "no CFG path within fn {:#x} to {}",
                fn_addr,
                final_fn ? std::format("target {:#x}", target_va)
                         : std::format("call to {:#x}", next_callee)));
            continue;
        }
        any_path = true;

        // Path-relative phi resolution: for each block on the path, the
        // predecessor used to reach it (or 0 for the entry).
        std::unordered_map<addr_t, addr_t> path_pred;
        for (std::size_t j = 0; j < path.size(); ++j) {
            path_pred[path[j]] = (j == 0) ? 0 : path[j - 1];
        }

        ExprBuilder eb(lf, path_pred);

        // Walk every block on the path; if its terminator is a CondBranch
        // we record a BranchDecision and try to extract a FieldRequirement.
        for (std::size_t j = 0; j + 1 < path.size(); ++j) {
            const addr_t cur_addr = path[j];
            const addr_t nxt_addr = path[j + 1];
            const IrBlock* bb = ir_block_at(lf.ir, cur_addr);
            if (!bb || bb->insts.empty()) continue;
            // The terminator is the last non-phi inst with a branch op;
            // CondBranch is always last when present. Scan from the back.
            const IrInst* term = nullptr;
            for (auto it = bb->insts.rbegin(); it != bb->insts.rend(); ++it) {
                if (is_terminator(it->op)) { term = &*it; break; }
            }
            if (!term || term->op != IrOp::CondBranch) continue;

            BranchDecision d;
            d.branch_va        = term->source_addr;
            d.taken_target     = term->target1;
            d.not_taken_target = term->target2;
            d.went_taken       = (nxt_addr == term->target1);
            d.in_function      = fn_addr;
            d.condition        = canonicalize_cmp(eb.build(term->srcs[0], cur_addr));
            d.pretty           = format_decision(d.condition, d.went_taken);

            extract_field_reqs(d.condition, d.went_taken,
                               d.branch_va, fn_addr, out.fields);
            out.branches.push_back(std::move(d));
        }
    }

    out.reachable = any_path || (chain.size() == 1 && chain[0] == target_cfn->entry);
    return out;
}

namespace {

[[nodiscard]] std::string
format_field_one(const FieldRequirement& f) {
    std::string lhs = format_field_chain(f.param_index, f.param_reg, f.offset_chain);
    std::string rhs = format_forge_expr(f.rhs);
    if (!f.lhs_is_field) std::swap(lhs, rhs);
    return std::format("{} {} {}", lhs, cmp_op_str(f.cmp_op), rhs);
}

}  // namespace

std::string format_forge_spec(const ForgeSpec& spec) {
    std::string s;
    s += std::format("// forge-spec: reach {:#x}", spec.target_va);
    if (!spec.target_fn_name.empty()) s += std::format(" ({})", spec.target_fn_name);
    s += std::format(" from {:#x}", spec.entry_va);
    if (!spec.entry_name.empty()) s += std::format(" ({})", spec.entry_name);
    s += "\n";

    if (!spec.call_chain.empty()) {
        s += "// call chain:";
        for (std::size_t i = 0; i < spec.call_chain.size(); ++i) {
            if (i) s += " ->";
            s += std::format(" {:#x}", spec.call_chain[i]);
        }
        s += "\n";
    }

    if (!spec.reachable && spec.warnings.empty()) {
        s += "// (no path found)\n";
    }
    for (const auto& w : spec.warnings) {
        s += std::format("// warning: {}\n", w);
    }
    s += "\n";

    // Group fields by (param_index, in_function) for a struct-style print.
    if (!spec.fields.empty()) {
        s += "required input shape:\n";
        // De-duplicate field requirements that compare the exact same lhs
        // chain with the same operator and rhs at the same fn (the BFS
        // shortest path can hit the same gate from different blocks).
        std::vector<FieldRequirement> uniq;
        auto same = [](const FieldRequirement& a, const FieldRequirement& b) {
            return a.param_index == b.param_index &&
                   a.in_function == b.in_function &&
                   a.offset_chain == b.offset_chain &&
                   a.cmp_op == b.cmp_op &&
                   a.lhs_is_field == b.lhs_is_field &&
                   format_forge_expr(a.rhs) == format_forge_expr(b.rhs);
        };
        for (const auto& f : spec.fields) {
            bool found = false;
            for (const auto& u : uniq) {
                if (same(f, u)) { found = true; break; }
            }
            if (!found) uniq.push_back(f);
        }
        for (const auto& f : uniq) {
            s += std::format("    {}    // at {:#x}\n",
                             format_field_one(f), f.site_va);
        }
        s += "\n";
    }

    if (!spec.branches.empty()) {
        s += "branch decisions:\n";
        for (const auto& d : spec.branches) {
            s += std::format("    {:#x}  fn {:#x}  {} -> {:#x}    {}\n",
                d.branch_va, d.in_function,
                d.went_taken ? "taken" : "fallthrough",
                d.went_taken ? d.taken_target : d.not_taken_target,
                d.pretty);
        }
    }
    return s;
}

namespace {

void json_escape(std::string& out, std::string_view s) {
    out += '"';
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    out += std::format("\\u{:04x}", static_cast<unsigned>(c));
                } else {
                    out += c;
                }
        }
    }
    out += '"';
}

}  // namespace

std::string format_forge_spec_json(const ForgeSpec& spec) {
    std::string s;
    s += "{";
    s += std::format("\"entry_va\":{},\"target_va\":{},\"reachable\":{}",
                     spec.entry_va, spec.target_va,
                     spec.reachable ? "true" : "false");
    s += ",\"entry_name\":";  json_escape(s, spec.entry_name);
    s += ",\"target_fn_name\":"; json_escape(s, spec.target_fn_name);

    s += ",\"call_chain\":[";
    for (std::size_t i = 0; i < spec.call_chain.size(); ++i) {
        if (i) s += ",";
        s += std::format("{}", spec.call_chain[i]);
    }
    s += "]";

    s += ",\"fields\":[";
    for (std::size_t i = 0; i < spec.fields.size(); ++i) {
        const auto& f = spec.fields[i];
        if (i) s += ",";
        s += "{";
        s += std::format("\"param_index\":{},", f.param_index);
        s += "\"param_reg\":"; json_escape(s, reg_name(f.param_reg));
        s += ",\"offset_chain\":[";
        for (std::size_t j = 0; j < f.offset_chain.size(); ++j) {
            if (j) s += ",";
            s += std::format("{}", f.offset_chain[j]);
        }
        s += "],";
        s += "\"access_width\":"; json_escape(s, type_name(f.access_width));
        s += ",\"cmp_op\":"; json_escape(s, op_name(f.cmp_op));
        s += ",\"lhs_is_field\":"; s += f.lhs_is_field ? "true" : "false";
        s += ",\"rhs\":"; json_escape(s, format_forge_expr(f.rhs));
        s += ",\"site_va\":"; s += std::format("{}", f.site_va);
        s += ",\"in_function\":"; s += std::format("{}", f.in_function);
        s += "}";
    }
    s += "]";

    s += ",\"branches\":[";
    for (std::size_t i = 0; i < spec.branches.size(); ++i) {
        const auto& d = spec.branches[i];
        if (i) s += ",";
        s += "{";
        s += std::format("\"branch_va\":{},\"taken_target\":{},\"not_taken_target\":{},",
                         d.branch_va, d.taken_target, d.not_taken_target);
        s += std::format("\"went_taken\":{},\"in_function\":{},",
                         d.went_taken ? "true" : "false", d.in_function);
        s += "\"pretty\":"; json_escape(s, d.pretty);
        s += "}";
    }
    s += "]";

    s += ",\"warnings\":[";
    for (std::size_t i = 0; i < spec.warnings.size(); ++i) {
        if (i) s += ",";
        json_escape(s, spec.warnings[i]);
    }
    s += "]";

    s += "}";
    return s;
}

}  // namespace ember
