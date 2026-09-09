#include "structurer_fail_common.hpp"
#include "../core/src/decompile/emitter_internal.hpp"

namespace {
void test_call_stays_before_branch(bool cast_return) {
    using namespace ember;
    IrFunction fn;
    fn.start = 0x5000;
    fn.end = 0x5040;
    fn.name = "call_before_branch";
    fn.next_temp_id = 1;
    IrValue result = IrValue::make_reg(Reg::PpcR3, IrType::I32);
    result.version = 1;
    const IrValue condition = IrValue::make_reg(Reg::PpcR4, IrType::I1);
    const IrValue cast = IrValue::make_temp(0, IrType::I16);
    IrBlock entry;
    entry.start = 0x5000; entry.end = 0x5010;
    entry.kind = BlockKind::Conditional;
    entry.successors = {0x5010, 0x5020};
    entry.insts = {make_call_imm(0x5000, 0x6000), make_clobber(result)};
    IrInst branch;
    branch.op = IrOp::CondBranch; branch.src_count = 1; branch.srcs[0] = condition;
    branch.target1 = 0x5010; branch.target2 = 0x5020;
    entry.insts.push_back(branch);
    IrBlock yes;
    yes.start = 0x5010; yes.end = 0x5020; yes.predecessors = {0x5000};
    yes.kind = BlockKind::Return;
    yes.insts = {make_ret_value(0x5010, IrValue::make_imm(7, IrType::I32))};
    IrBlock no;
    no.start = 0x5020; no.end = 0x5040; no.predecessors = {0x5000};
    no.kind = BlockKind::Return;
    if (cast_return) {
        IrInst trunc; trunc.op = IrOp::Trunc; trunc.dst = cast;
        trunc.srcs[0] = result; trunc.src_count = 1; no.insts.push_back(trunc);
    }
    no.insts.push_back(make_ret_value(0x5024, cast_return ? cast : result));
    fn.blocks = {entry, yes, no};
    for (std::size_t i = 0; i < fn.blocks.size(); ++i) fn.block_at[fn.blocks[i].start] = i;
    Structurer structurer;
    auto sf = structurer.structure(fn);
    check(sf.has_value(), "branch call test structures");
    if (!sf) return;
    Annotations annotations;
    annotations.renames[0x6000] = "observe";
    annotations.signatures[0x6000] = FunctionSig{
        .return_type = "uint32_t", .params = {}, .variadic = false};
    MockPpcBinary binary;
    auto pc = PseudoCEmitter{}.emit(*sf, &binary, &annotations, {});
    check(pc.has_value(), "branch call test emits");
    if (!pc) return;
    const auto call = pc->find("observe()");
    const auto branch_at = pc->find("if (");
    const bool ordered = call != std::string::npos && branch_at != std::string::npos && call < branch_at;
    if (!ordered) std::fprintf(stderr, "%s\n", pc->c_str());
    check(ordered, "unconditional call remains before branch even with one return use");
    check(pc->find("observe()", call + 1) == std::string::npos,
          "unconditional call emitted exactly once");
}
void test_call_stays_before_store() {
    using namespace ember;
    IrFunction fn; fn.start = 0x6000; fn.end = 0x6010; fn.name = "call_before_store";
    IrValue result = IrValue::make_reg(Reg::PpcR3, IrType::I32); result.version = 1;
    IrBlock block; block.start = fn.start; block.end = fn.end; block.kind = BlockKind::Return;
    block.insts = {make_call_imm(0x6000, 0x9000), make_clobber(result),
                  make_store(IrValue::make_imm(0xa000, IrType::I32), IrValue::make_imm(1, IrType::I32)),
                  make_ret_value(0x600c, result)};
    fn.blocks.push_back(block); fn.block_at[fn.start] = 0;
    auto sf = Structurer{}.structure(fn); check(sf.has_value(), "store test structures"); if (!sf) return;
    Annotations ann; ann.renames[0x9000] = "observe";
    ann.signatures[0x9000] = FunctionSig{.return_type="uint32_t", .params={}, .variadic=false};
    MockPpcBinary binary;
    auto pc = PseudoCEmitter{}.emit(*sf, &binary, &ann, {});
    check(pc.has_value(), "store test emits"); if (!pc) return;
    const auto call = pc->find("observe()"); const auto store = pc->find("0xa000");
    check(call != std::string::npos && store != std::string::npos && call < store,
          "call remains before subsequent memory mutation");
}

void test_merge_used_only_as_call_argument() {
    using namespace ember;
    IrFunction fn;
    fn.start = 0x7000; fn.end = 0x7040; fn.name = "optional_buffer";
    auto source = IrValue::make_reg(Reg::PpcR3, IrType::I32);
    const auto prepared = IrValue::make_temp(0, IrType::I32);
    fn.next_temp_id = 1;
    auto allocated = source; allocated.version = 2;
    auto merged = source; merged.version = 3;
    IrBlock entry;
    entry.start = 0x7000; entry.end = 0x7010; entry.kind = BlockKind::Conditional;
    entry.successors = {0x7020, 0x7010};
    entry.insts.push_back(make_add(prepared, source, IrValue::make_imm(16, IrType::I32)));
    IrInst branch; branch.op = IrOp::CondBranch; branch.srcs[0] = prepared;
    branch.src_count = 1; branch.target1 = 0x7020; branch.target2 = 0x7010;
    entry.insts.push_back(branch);
    IrBlock allocate;
    allocate.start = 0x7010; allocate.end = 0x7020; allocate.kind = BlockKind::Conditional;
    allocate.predecessors = {0x7000}; allocate.successors = {0x7020, 0x7030};
    allocate.insts = {make_call_imm(0x7010, 0x8000), make_clobber(allocated)};
    IrInst jump; jump.op = IrOp::CondBranch; jump.target1 = 0x7020;
    jump.target2 = 0x7030; jump.srcs[0] = allocated; jump.src_count = 1;
    allocate.insts.push_back(jump);
    IrBlock use;
    use.start = 0x7020; use.end = 0x7040; use.kind = BlockKind::Return;
    use.predecessors = {0x7000, 0x7010};
    auto phi = make_phi(merged, {prepared, allocated}); phi.phi_preds = use.predecessors;
    use.insts.push_back(phi);
    IrInst args; args.op = IrOp::Intrinsic; args.name = "call.args.1";
    args.srcs[0] = merged; args.src_count = 1;
    use.insts.push_back(args); use.insts.push_back(make_call_imm(0x7020, 0x8100));
    use.insts.push_back(make_ret(0x7024));
    IrBlock exit; exit.start = 0x7030; exit.end = 0x7040;
    exit.kind = BlockKind::Return; exit.predecessors = {0x7010};
    exit.insts.push_back(make_ret(0x7030));
    fn.blocks = {entry, allocate, use, exit};
    for (std::size_t i = 0; i < fn.blocks.size(); ++i) fn.block_at[fn.blocks[i].start] = i;
    auto sf = Structurer{}.structure(fn);
    check(sf.has_value(), "call-only merge structures"); if (!sf) return;
    Annotations annotations;
    annotations.renames[0x8000] = "allocate";
    annotations.signatures[0x8000] = FunctionSig{.return_type="void*", .params={}, .variadic=false};
    annotations.renames[0x8100] = "consume";
    annotations.signatures[0x8100] = FunctionSig{.return_type="void", .params={{"void*", "buffer"}}, .variadic=false};
    MockPpcBinary binary;
    auto pc = PseudoCEmitter{}.emit(*sf, &binary, &annotations, {});
    check(pc.has_value(), "call-only merge emits"); if (!pc) return;

    const auto add = pc->find("+ 0x10");
    const auto condition = pc->find("if (");
    if (add == std::string::npos || add >= condition) std::fprintf(stderr, "%s\n", pc->c_str());
    check(add != std::string::npos && add < condition,
          "address feeder for call-only phi is initialized before the branch");
}

}
int main() {
    {
        ember::IrFunction fn;
        ember::emit::Emitter e(nullptr);
        e.fn = &fn;
        e.abi = ember::Abi::Ppc32Sysv;
        e.self_arity = 1;
        e.self_arg_layout.emplace_back(ember::Reg::PpcR3, ember::IrType::I32);
        e.merge_locals.try_emplace("value");
        e.infer_ppc_role_arg_names();
        check(e.self_arg_names[0] != "value",
              "inferred parameter name must not collide with a merge local");
    }
    test_call_stays_before_branch(false);
    test_call_stays_before_branch(true);
    test_merge_used_only_as_call_argument();
    test_call_stays_before_store();
    return fails ? 1 : 0;
}
