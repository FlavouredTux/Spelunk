#include "cfg_builder_internal.hpp"

#include <algorithm>
#include <deque>
#include <limits>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include <spelunk/analysis/function.hpp>
#include <spelunk/analysis/pipeline.hpp>
#include <spelunk/binary/binary.hpp>
#include <spelunk/binary/symbol.hpp>
#include <spelunk/disasm/decoder.hpp>
#include <spelunk/disasm/instruction.hpp>

namespace spelunk::cfg_builder_detail {

namespace {

[[nodiscard]] bool is_noreturn_import_name(std::string_view name) noexcept {
    name = strip_import_name_decorations(name);
    return name == "__stack_chk_fail" ||
           name == "__cxa_throw" ||
           name == "__cxa_rethrow" ||
           name == "_Unwind_Resume" ||
           name == "__android_log_assert" ||
           name == "__assert" ||
           name == "__assert2" ||
           name == "__assert_fail" ||
           name == "__assert_rtn" ||
           name == "abort" ||
           name == "exit" ||
           name == "_exit" ||
           name == "_Exit" ||
           name == "longjmp" ||
           name == "pthread_exit";
}

[[nodiscard]] bool is_noreturn_target(const Binary& b, addr_t target) noexcept {
    if (const Symbol* s = b.import_at_plt(target); s && !s->name.empty()) {
        return is_noreturn_import_name(s->name);
    }
    if (const Symbol* s = b.find_by_name("__stack_chk_fail");
        s && !s->is_import && s->addr == target) {
        return true;
    }
    return false;
}

}  // namespace

void walk_from(const Binary& b, const Decoder& dec, WalkState& ws, addr_t entry,
               const std::unordered_set<addr_t>& known_entries,
               addr_t owner_begin, addr_t owner_end) {
    const auto is_other_entry = [&](addr_t target) {
        return known_entries.contains(target) &&
               !(target > owner_begin && target < owner_end);
    };
    std::deque<addr_t> wl;
    wl.push_back(entry);
    ws.leaders.insert(entry);

    while (!wl.empty()) {
        addr_t ip = wl.front();
        wl.pop_front();

        while (true) {
            if (ws.insns.contains(ip)) break;
            // LC_DATA_IN_CODE / analogous: the linker flagged these bytes
            // as non-code (jump tables, ARM switch constants, etc.). Don't
            // try to decode them as instructions.
            if (b.is_data_in_code(ip)) break;

            const auto bytes = b.bytes_at(ip);
            if (bytes.empty()) break;

            auto decoded = dec.decode(bytes, ip);
            if (!decoded) break;

            auto [it, _] = ws.insns.emplace(ip, *decoded);
            const Instruction& insn = it->second;
            const addr_t fallthrough = ip + insn.length;
            const Mnemonic mn = insn.mnemonic;

            if (is_return_like(mn)) break;

            if (is_call(mn)) {
                if (auto t = branch_target(insn); t) {
                    if (ws.call_seen.insert(*t).second) {
                        ws.calls.push_back(*t);
                    }
                    if (is_noreturn_target(b, *t)) {
                        ws.noreturn_calls.insert(ip);
                        break;
                    }
                } else if (auto ct = resolve_ppc_ctr_target(b, ws, ip); ct) {
                    ws.resolved_indirect[ip] = *ct;
                    if (ws.call_seen.insert(*ct).second) {
                        ws.calls.push_back(*ct);
                    }
                    if (is_noreturn_target(b, *ct)) {
                        ws.noreturn_calls.insert(ip);
                        break;
                    }
                }
                ip = fallthrough;
                continue;
            }
            if (is_conditional_branch(mn)) {
                if (auto t = branch_target(insn); t) {
                    if (ws.leaders.insert(*t).second) wl.push_back(*t);
                }
                if (ws.leaders.insert(fallthrough).second) wl.push_back(fallthrough);
                break;
            }
            if (is_unconditional_jmp(mn)) {
                if (auto t = branch_target(insn); t) {
                    if (is_other_entry(*t) ||
                        b.import_at_plt(*t) != nullptr) {
                        // Tail call: don't walk into the target; record the
                        // call for xrefs and mark this jmp so partition()
                        // can materialize a TailCall block.
                        if (ws.call_seen.insert(*t).second) {
                            ws.calls.push_back(*t);
                        }
                        ws.tail_calls.insert(ip);
                    } else if (ws.leaders.insert(*t).second) {
                        wl.push_back(*t);
                    }
                } else if (auto ct = resolve_ppc_ctr_target(b, ws, ip); ct) {
                    ws.resolved_indirect[ip] = *ct;
                    if (is_other_entry(*ct) || b.import_at_plt(*ct) != nullptr) {
                        if (ws.call_seen.insert(*ct).second) {
                            ws.calls.push_back(*ct);
                        }
                        ws.tail_calls.insert(ip);
                    }
                }
                break;
            }

            ip = fallthrough;
        }
    }
}

void partition(const Binary& b, const WalkState& ws, Function& fn) {
    std::vector<BasicBlock> synthetic_blocks;
    addr_t next_synthetic = std::numeric_limits<addr_t>::max() - 0x10000u;

    auto make_indirect_arm = [&](const Instruction& branch, Reg target,
                                 addr_t fallthrough) -> addr_t {
        BasicBlock arm;
        arm.start = next_synthetic;
        next_synthetic -= 0x10u;
        arm.end = arm.start + 4;

        if (branch.ppc_link) {
            Instruction call;
            call.address = arm.start;
            call.length = 4;
            call.mnemonic = Mnemonic::Call;
            call.operands[0] = Operand::make_reg(target);
            call.num_operands = 1;
            arm.instructions.push_back(call);
            arm.kind = BlockKind::Fallthrough;
            arm.successors.push_back(fallthrough);
        } else if (target == Reg::PpcLr) {
            arm.kind = BlockKind::Return;
        } else {
            Instruction jump;
            jump.address = arm.start;
            jump.length = 4;
            jump.mnemonic = Mnemonic::Jmp;
            jump.operands[0] = Operand::make_reg(target);
            jump.num_operands = 1;
            arm.instructions.push_back(jump);
            arm.kind = BlockKind::IndirectJmp;
        }

        const addr_t result = arm.start;
        synthetic_blocks.push_back(std::move(arm));
        return result;
    };

    for (addr_t leader : ws.leaders) {
        auto it = ws.insns.find(leader);
        if (it == ws.insns.end()) continue;

        BasicBlock bb;
        bb.start = leader;

        while (it != ws.insns.end()) {
            const Instruction& insn = it->second;
            const addr_t addr = it->first;
            const addr_t next = addr + insn.length;

            bb.instructions.push_back(insn);
            bb.end = next;

            const Mnemonic mn = insn.mnemonic;
            if (ws.noreturn_calls.contains(addr)) {
                bb.kind = BlockKind::IndirectJmp;
                break;
            }
            if (ends_basic_block(mn)) {
                if (is_return_like(mn)) {
                    bb.kind = BlockKind::Return;
                } else if (is_conditional_branch(mn)) {
                    bb.kind = BlockKind::Conditional;
                    if (auto t = branch_target(insn); t) {
                        bb.successors.push_back(*t);
                    } else if (mn == Mnemonic::Bclr) {
                        bb.successors.push_back(make_indirect_arm(insn, Reg::PpcLr, next));
                    } else if (mn == Mnemonic::Bcctr) {
                        bb.successors.push_back(make_indirect_arm(insn, Reg::PpcCtr, next));
                    }
                    bb.successors.push_back(next);
                } else if (is_unconditional_jmp(mn)) {
                    auto ti = ws.tables.find(addr);
                    if (ti != ws.tables.end()) {
                        const JumpTable& jt = ti->second;
                        bb.kind = BlockKind::Switch;
                        bb.successors   = jt.targets;
                        bb.case_values  = jt.values;
                        bb.switch_index = jt.index_reg;
                        if (jt.default_tgt) {
                            bb.successors.push_back(*jt.default_tgt);
                            bb.has_default = true;
                        }
                    } else if (ws.tail_calls.contains(addr)) {
                        // Record the target as the single successor so later
                        // stages (lifter, emitter) can recover `return fn(...);`.
                        bb.kind = BlockKind::TailCall;
                        if (auto rt = ws.resolved_indirect.find(addr);
                            rt != ws.resolved_indirect.end()) {
                            bb.successors.push_back(rt->second);
                        } else if (auto t = branch_target(insn); t) {
                            bb.successors.push_back(*t);
                        }
                    } else if (auto t = branch_target(insn); t) {
                        bb.kind = BlockKind::Unconditional;
                        bb.successors.push_back(*t);
                    } else if (auto edges = b.indirect_edges_from(addr);
                               !edges.empty()) {
                        // Oracle-resolved indirect jmp. Render as a
                        // Switch-like block so the structurer sees the
                        // full successor set; case_values stay empty
                        // because we have no opcode-to-target mapping
                        // yet (the CLI flag carries pairs only).
                        bb.kind = BlockKind::Switch;
                        bb.successors.assign(edges.begin(), edges.end());
                    } else {
                        bb.kind = BlockKind::IndirectJmp;
                    }
                }
                break;
            }

            if (ws.leaders.contains(next) && next != leader) {
                bb.kind = BlockKind::Fallthrough;
                bb.successors.push_back(next);
                break;
            }

            auto next_it = ws.insns.find(next);
            if (next_it == ws.insns.end()) {
                bb.kind = BlockKind::Fallthrough;
                bb.successors.push_back(next);
                break;
            }
            it = next_it;
        }

        fn.block_at[bb.start] = fn.blocks.size();
        fn.blocks.push_back(std::move(bb));
    }

    for (const auto& blk : fn.blocks) {
        if (blk.end > fn.end) fn.end = blk.end;
    }

    for (auto& blk : synthetic_blocks) {
        fn.block_at[blk.start] = fn.blocks.size();
        fn.blocks.push_back(std::move(blk));
    }
}

void compute_predecessors(Function& fn) {
    for (const auto& bb : fn.blocks) {
        for (addr_t succ : bb.successors) {
            auto it = fn.block_at.find(succ);
            if (it != fn.block_at.end()) {
                fn.blocks[it->second].predecessors.push_back(bb.start);
            }
        }
    }
    for (auto& bb : fn.blocks) {
        std::ranges::sort(bb.predecessors);
        const auto dup = std::ranges::unique(bb.predecessors);
        bb.predecessors.erase(dup.begin(), dup.end());
    }
}

}  // namespace spelunk::cfg_builder_detail
