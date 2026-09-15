#include "ir_interpreter_cfg.hpp"

#include <algorithm>
#include <iterator>
#include <set>
#include <stdexcept>
#include <utility>

namespace spelunk::test {
namespace {

u8 operand_count(const IrInst& inst, bool allow_intrinsics, bool allow_calls) {
    switch (inst.op) {
        case IrOp::Call: case IrOp::Clobber:
            if (allow_calls) return 0;
            throw std::runtime_error("unsupported call or clobber");
        case IrOp::Intrinsic:
            if (inst.name.starts_with("call.args.")) {
                if (allow_calls && inst.src_count <= 3 &&
                    (inst.name == "call.args.1" || inst.name == "call.args.2" || inst.name == "call.args.3"))
                    return inst.src_count;
                throw std::runtime_error("unsupported call argument pack");
            }
            if (allow_intrinsics && inst.src_count <= 3) return inst.src_count;
            throw std::runtime_error("unsupported intrinsic");
        case IrOp::Nop: case IrOp::Phi: case IrOp::Branch: return 0;
        case IrOp::Return:
            if (inst.src_count > 1) throw std::runtime_error("wrong return arity");
            return inst.src_count;
        case IrOp::Assign: case IrOp::Load: case IrOp::Neg: case IrOp::Not:
        case IrOp::ZExt: case IrOp::SExt: case IrOp::Trunc:
        case IrOp::CondBranch: return 1;
        case IrOp::Store: case IrOp::Add: case IrOp::Sub: case IrOp::Mul:
        case IrOp::And: case IrOp::Or: case IrOp::Xor:
        case IrOp::Shl: case IrOp::Lshr: case IrOp::Ashr:
        case IrOp::CmpEq: case IrOp::CmpNe:
        case IrOp::CmpUlt: case IrOp::CmpUle: case IrOp::CmpUgt: case IrOp::CmpUge:
        case IrOp::CmpSlt: case IrOp::CmpSle: case IrOp::CmpSgt: case IrOp::CmpSge:
        case IrOp::AddCarry: case IrOp::SubBorrow:
        case IrOp::AddOverflow: case IrOp::SubOverflow:
            return 2;
        case IrOp::Select: return 3;
        default: throw std::runtime_error("unsupported opcode");
    }
}

bool defines_value(const IrInst& inst) {
    if (inst.op == IrOp::Intrinsic && inst.name.starts_with("call.args.")) return false;
    return inst.op != IrOp::Nop && inst.op != IrOp::Store && inst.op != IrOp::Branch &&
           inst.op != IrOp::CondBranch && inst.op != IrOp::Return && inst.op != IrOp::Call;
}

}  // namespace

void validate_interpreter_cfg(const IrFunction& fn, const MachineInput& input) {
    const std::size_t count = fn.blocks.size();
    if (count == 0 || fn.block_at.size() != count || !fn.block_at.contains(fn.start)) {
        throw std::runtime_error("invalid block map or missing entry");
    }
    std::vector<std::set<addr_t>> predecessors(count);
    std::map<SsaKey, std::pair<std::size_t, std::size_t>> definitions;
    for (std::size_t bi = 0; bi < count; ++bi) {
        const auto& block = fn.blocks[bi];
        const auto entry = fn.block_at.find(block.start);
        if (entry == fn.block_at.end() || entry->second != bi) {
            throw std::runtime_error("invalid block map");
        }
        if (block.insts.empty()) throw std::runtime_error("block has no terminator");
        bool seen_body = false;
        bool call_clobbers = false;
        unsigned next_pack = 1;
        for (std::size_t ii = 0; ii < block.insts.size(); ++ii) {
            const auto& inst = block.insts[ii];
            if (inst.op == IrOp::Intrinsic && inst.name.starts_with("call.args.")) {
                if (inst.name != "call.args." + std::to_string(next_pack++))
                    throw std::runtime_error("out-of-order call argument packs");
            }
            if (inst.op == IrOp::Call) next_pack = 1;
            if (inst.op == IrOp::Clobber && !call_clobbers)
                throw std::runtime_error("clobber outside a call's clobber sequence");
            if (inst.op != IrOp::Nop)
                call_clobbers = inst.op == IrOp::Call || (inst.op == IrOp::Clobber && call_clobbers);
            if (inst.src_count != operand_count(inst, static_cast<bool>(input.intrinsic),
                                                static_cast<bool>(input.call)))
                throw std::runtime_error("wrong operand count");
            if (inst.segment != Reg::None) throw std::runtime_error("segmented memory");
            if (inst.op == IrOp::Phi) {
                if (seen_body) throw std::runtime_error("phi after block body");
                if (inst.phi_operands.size() != inst.phi_preds.size() || inst.phi_preds.empty()) {
                    throw std::runtime_error("invalid phi operand list");
                }
                for (const auto& value : inst.phi_operands) {
                    if (value.type != inst.dst.type) throw std::runtime_error("phi type mismatch");
                }
            } else if (inst.op != IrOp::Nop) {
                seen_body = true;
            }
            if (is_terminator(inst.op) && ii + 1 != block.insts.size()) {
                throw std::runtime_error("instructions after terminator");
            }
            if (defines_value(inst)) {
                const auto key = ssa_key(inst.dst);
                if (!key || inst.dst.kind == IrValueKind::Imm) {
                    throw std::runtime_error("missing or immediate destination");
                }
                if (input.values.contains(*key) ||
                    !definitions.emplace(*key, std::pair{bi, ii}).second) {
                    throw std::runtime_error("SSA value defined twice");
                }
            }
        }
        const auto& terminator = block.insts.back();
        if (next_pack != 1) throw std::runtime_error("call argument pack without a call in the block");
        std::set<addr_t> targets;
        if (terminator.op == IrOp::Branch) {
            targets.insert(terminator.target1);
        } else if (terminator.op == IrOp::CondBranch) {
            if (terminator.srcs[0].type != IrType::I1) {
                throw std::runtime_error("branch condition is not i1");
            }
            targets.insert(terminator.target1);
            targets.insert(terminator.target2);
        } else if (terminator.op != IrOp::Return) {
            throw std::runtime_error("block has no terminator");
        }
        if (targets != std::set<addr_t>(block.successors.begin(), block.successors.end())) {
            throw std::runtime_error("branch targets disagree with successors");
        }
        for (addr_t target : targets) {
            const auto found = fn.block_at.find(target);
            if (found == fn.block_at.end() || found->second >= count) {
                throw std::runtime_error("branch target is missing");
            }
            predecessors[found->second].insert(block.start);
        }
    }
    for (std::size_t bi = 0; bi < count; ++bi) {
        const auto& block = fn.blocks[bi];
        if (predecessors[bi] != std::set<addr_t>(block.predecessors.begin(), block.predecessors.end())) {
            throw std::runtime_error("inconsistent predecessor metadata");
        }
        for (const auto& inst : block.insts) {
            if (inst.op != IrOp::Phi) continue;
            const std::set<addr_t> incoming(inst.phi_preds.begin(), inst.phi_preds.end());
            if (incoming.size() != inst.phi_preds.size() || incoming != predecessors[bi]) {
                throw std::runtime_error("phi predecessors do not match incoming edges");
            }
        }
    }
    const auto entry = fn.block_at.at(fn.start);
    if (!predecessors[entry].empty()) throw std::runtime_error("entry has incoming edges");

    std::set<std::size_t> reachable{entry};
    std::vector<std::size_t> work{entry};
    while (!work.empty()) {
        const auto bi = work.back();
        work.pop_back();
        for (addr_t successor : fn.blocks[bi].successors) {
            const auto next = fn.block_at.at(successor);
            if (reachable.insert(next).second) work.push_back(next);
        }
    }
    std::vector<std::set<std::size_t>> dominators(count, reachable);
    dominators[entry] = {entry};
    bool changed = true;
    while (changed) {
        changed = false;
        for (auto bi : reachable) {
            if (bi == entry) continue;
            auto common = reachable;
            for (addr_t pred : predecessors[bi]) {
                const auto pi = fn.block_at.at(pred);
                if (!reachable.contains(pi)) continue;
                std::set<std::size_t> intersection;
                std::set_intersection(common.begin(), common.end(),
                                      dominators[pi].begin(), dominators[pi].end(),
                                      std::inserter(intersection, intersection.end()));
                common = std::move(intersection);
            }
            common.insert(bi);
            if (common != dominators[bi]) {
                dominators[bi] = std::move(common);
                changed = true;
            }
        }
    }
    // A phi use belongs to the predecessor edge, not the phi's own block.
    // Other operands need a dominating definition, ordered before same-block
    // uses. Otherwise a previous iteration's value could mask malformed SSA.
    const auto validate_use = [&](const IrValue& value, std::size_t bi, std::size_t ii) {
        if (value.kind == IrValueKind::Imm) return;
        const auto key = ssa_key(value);
        if (!key) throw std::runtime_error("operand has no value");
        if (input.values.contains(*key)) return;
        const auto definition = definitions.find(*key);
        if (definition == definitions.end()) throw std::runtime_error("undefined SSA value");
        const auto [db, di] = definition->second;
        if (!dominators[bi].contains(db) || (db == bi && di >= ii)) {
            throw std::runtime_error("SSA definition does not dominate use");
        }
    };
    for (auto bi : reachable) {
        const auto& block = fn.blocks[bi];
        for (std::size_t ii = 0; ii < block.insts.size(); ++ii) {
            const auto& inst = block.insts[ii];
            for (u8 si = 0; si < inst.src_count; ++si) validate_use(inst.srcs[si], bi, ii);
            if (inst.op != IrOp::Phi) continue;
            for (std::size_t pi = 0; pi < inst.phi_preds.size(); ++pi) {
                const auto pred = fn.block_at.at(inst.phi_preds[pi]);
                if (reachable.contains(pred)) {
                    validate_use(inst.phi_operands[pi], pred, fn.blocks[pred].insts.size());
                }
            }
        }
    }
}

}  // namespace spelunk::test
