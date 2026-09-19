// Receiver-checked PowerPC virtual dispatch and local argument evidence.
#include "emitter_internal.hpp"
#include "emitter_tables.hpp"

#include <algorithm>
#include <format>
#include <map>

#include <spelunk/disasm/decoder.hpp>
#include <spelunk/ir/lifter.hpp>

namespace spelunk::emit {

std::optional<Emitter::RenderedCall>
Emitter::render_x64_virtual_call(const IrInst& call, const CallArgPack& pack) const {
    if (options.c_source || !binary || !fn || call.src_count == 0 || pack.ints.size() < 2 ||
        (abi != Abi::SysVAmd64 && abi != Abi::Win64) || call_annotation_signature(call) ||
        call_signature_target(call)) return std::nullopt;
    const auto dispatch = try_render_vfn_dispatch(call.srcs[0]);
    if (!dispatch) return std::nullopt;
    const auto* target = def_stripped(call.srcs[0]);
    if (!target || target->op != IrOp::Load || !target->src_count) return std::nullopt;
    const auto slot = try_base_plus_offset(target->srcs[0]);
    const auto* table = slot ? def_stripped(slot->first) : nullptr;
    if (!table || table->op != IrOp::Load || !table->src_count) return std::nullopt;
    const auto receiver = canonical_struct_access(table->srcs[0]);
    const auto first = canonical_struct_access(pack.ints[0]);
    if (!receiver || !first || receiver->second != first->second ||
        !same_value_key(receiver->first, first->first)) return std::nullopt;

    // Cleanup folds register copies, so equal SSA values alone cannot prove
    // a duplicate is stale. Re-lift the call's predecessor slice and preserve
    // every explicitly written ABI lane, including preparation across a jump.
    const IrBlock* site = nullptr;
    for (const auto& block : fn->blocks)
        if (block.start <= call.source_addr && call.source_addr < block.end) site = &block;
    if (!site) return std::nullopt;
    auto decoder = make_decoder(*binary);
    auto lifter = make_lifter(*binary);
    if (!decoder || !lifter) return std::nullopt;
    std::vector<addr_t> pending{site->start};
    std::set<addr_t> visited;
    std::set<Reg> writes;
    std::size_t budget = 512;
    while (!pending.empty()) {
        const auto address = pending.back(); pending.pop_back();
        if (!visited.insert(address).second) continue;
        const auto found = fn->block_at.find(address);
        if (found == fn->block_at.end()) return std::nullopt;
        const auto& block = fn->blocks[found->second];
        BasicBlock window;
        window.start = block.start;
        window.end = address == site->start ? call.source_addr : block.end;
        for (addr_t pc = window.start; pc < window.end;) {
            if (!budget) return std::nullopt;
            --budget;
            const auto instruction = (*decoder)->decode(binary->bytes_at(pc), pc);
            if (!instruction || !instruction->length || instruction->length > window.end - pc)
                return std::nullopt;
            window.instructions.push_back(*instruction);
            pc += instruction->length;
        }
        Function preparation;
        preparation.start = window.start; preparation.end = window.end;
        preparation.block_at[window.start] = 0;
        preparation.blocks.push_back(std::move(window));
        auto lifted = (*lifter)->lift(preparation);
        if (!lifted) return std::nullopt;
        for (const auto& bb : lifted->blocks) for (const auto& inst : bb.insts)
            if (inst.dst.kind == IrValueKind::Reg && inst.op != IrOp::Clobber)
                writes.insert(canonical_reg(inst.dst.reg));
        pending.insert(pending.end(), block.predecessors.begin(), block.predecessors.end());
    }
    const auto registers = int_arg_regs(abi);
    auto candidates = pack.ints;
    while (!candidates.empty() && is_stale_arg_reg(candidates.back())) candidates.pop_back();
    bool trimmed = false;
    while (candidates.size() > 1 && candidates.size() <= registers.size()) {
        const auto i = candidates.size() - 1;
        if (writes.contains(canonical_reg(registers[i])) ||
            !same_value_key(candidates[i], candidates[0])) break;
        candidates.pop_back();
        trimmed = true;
    }
    if (!trimmed) return std::nullopt;
    RenderedCall result;
    const auto arguments = format_call_args_fallback(candidates, &result.used_args);
    result.expr = std::format("{}({}) /* inferred ABI args */", *dispatch, arguments);
    return result;
}

std::optional<Emitter::RenderedCall>
Emitter::render_ppc_virtual_call(const IrInst& call, const CallArgPack& pack) const {
    if (!is_ppc_abi() || !fn || call.src_count == 0 || pack.ints.empty()) return std::nullopt;
    const IrInst* target = def_stripped(call.srcs[0]);
    if (!target || target->op != IrOp::Load || target->src_count != 1) return std::nullopt;
    const unsigned pointer_bytes = abi == Abi::Ppc32Sysv ? 4u : 8u;
    if (type_bits(target->dst.type) != pointer_bytes * 8) return std::nullopt;
    auto slot = try_base_plus_offset(target->srcs[0]);
    if (!slot || slot->second < 0 || slot->second % pointer_bytes != 0) return std::nullopt;
    const IrInst* table = def_stripped(slot->first);
    if (!table || table->op != IrOp::Load || table->src_count != 1 ||
        type_bits(table->dst.type) != pointer_bytes * 8) return std::nullopt;
    // A cached target/vptr may intentionally survive a store or another
    // call. Member-call notation would reload it and change that behavior.
    for (const IrValue& value : {target->dst, table->dst}) {
        if (auto key = ssa_key(value); key && memory_snapshot_loads.contains(*key))
            return std::nullopt;
    }
    auto vptr_address = canonical_struct_access(table->srcs[0]);
    auto receiver = canonical_struct_access(pack.ints.front());
    if (!vptr_address || !receiver || !same_value_key(vptr_address->first, receiver->first))
        return std::nullopt;
    if (vptr_address->second < receiver->second) return std::nullopt;
    const u64 offset = static_cast<u64>(vptr_address->second) - static_cast<u64>(receiver->second);
    if (offset > 0x100000 || offset % pointer_bytes != 0) return std::nullopt;

    // SSA cleanup intentionally folds register copies. Re-lift a bounded
    // straight-line window to distinguish fresh ABI writes from old values
    // left in the snapshot. Keep source PCs so an explicit copy of the vptr
    // into an argument register is retained, while the dispatch load's own
    // scratch register is omitted.
    std::optional<std::map<Reg, addr_t>> writes;
    if (binary && call.source_addr != 0) {
        const IrBlock* block = nullptr;
        for (const auto& candidate : fn->blocks) {
            if (call.source_addr >= candidate.start && call.source_addr < candidate.end) {
                block = &candidate;
                break;
            }
        }
        if (block) {
            auto decoder = make_decoder(*binary);
            auto lifter = make_lifter(*binary);
            const addr_t begin = std::max(block->start,
                call.source_addr > 128 ? call.source_addr - 128 : addr_t{0});
            BasicBlock window;
            window.start = begin; window.end = call.source_addr;
            bool valid = decoder.has_value() && lifter.has_value() && (begin & 3u) == 0;
            for (addr_t pc = begin; valid && pc < call.source_addr; pc += 4) {
                auto instruction = (*decoder)->decode(binary->bytes_at(pc), pc);
                if (!instruction || instruction->length != 4) { valid = false; break; }
                if (is_call(instruction->mnemonic) || ends_basic_block(instruction->mnemonic)) {
                    window.instructions.clear();
                    window.start = pc + 4;
                } else window.instructions.push_back(*instruction);
            }
            if (valid) {
                Function preparation;
                preparation.start = window.start; preparation.end = window.end;
                preparation.block_at[window.start] = 0;
                preparation.blocks.push_back(std::move(window));
                auto lifted = (*lifter)->lift(preparation);
                if (lifted) {
                    writes.emplace();
                    for (const auto& bb : lifted->blocks)
                        for (const auto& inst : bb.insts)
                            if (inst.dst.kind == IrValueKind::Reg && inst.op != IrOp::Clobber)
                                (*writes)[canonical_reg(inst.dst.reg)] = inst.source_addr;
                }
            }
        }
    }

    RenderedCall result;
    result.used_args.push_back(pack.ints.front()); // implicit receiver is still a semantic use
    std::string arguments;
    const auto append = [&](const IrValue& value, Reg lane) {
        if (!arguments.empty()) arguments += ", ";
        arguments += std::format("/* {} */ {}", reg_name(lane), expr(value));
        result.used_args.push_back(value);
    };
    const auto selected = [&](const IrValue& value, Reg lane) {
        if (!writes) return !is_stale_arg_reg(value);
        if (auto found = writes->find(canonical_reg(lane)); found != writes->end()) {
            const IrInst* definition = def_stripped(value);
            if ((definition == table || definition == target) &&
                found->second == definition->source_addr) return false;
            return true;
        }
        // Retain established incoming parameters even when prepared before
        // this block. Unknown extra lanes remain uncertain, not proven absent.
        return trace_to_self_arg_slot(value).has_value() && !is_stale_arg_reg(value);
    };
    const auto integers = int_arg_regs(abi);
    for (std::size_t i = 1; i < pack.ints.size() && i < integers.size(); ++i)
        if (selected(pack.ints[i], integers[i])) append(pack.ints[i], integers[i]);
    const auto floats = fp_arg_regs(abi);
    for (std::size_t i = 0; i < pack.fps.size() && i < floats.size(); ++i)
        if (selected(pack.fps[i], floats[i])) append(pack.fps[i], floats[i]);

    const std::string object = expr(pack.ints.front(), 0, std::to_underlying(Prec::Postfix));
    if (object.empty()) return std::nullopt;
    result.expr = std::format("{}->vfn_{}({}) /* vptr +{:#x}; inferred ABI args */",
        object, slot->second / pointer_bytes, arguments, offset);
    return result;
}

} // namespace spelunk::emit
