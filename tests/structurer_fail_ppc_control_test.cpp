// PowerPC / Wii control-flow and return-shape regressions.

#include "structurer_fail_common.hpp"
#include "structurer_fail_ppc_internal.hpp"

namespace ppc_structurer_tests {

int test_ppc_ctr_loop_keeps_predecrement() {
    using namespace ember;

    constexpr addr_t kStart = 0x402180;
    IrValue ctr1 = IrValue::make_reg(Reg::PpcCtr, IrType::I32);
    IrValue ctr2 = ctr1;
    IrValue ctr3 = ctr1;
    ctr1.version = 1;
    ctr2.version = 2;
    ctr3.version = 3;
    const IrValue decremented = IrValue::make_temp(0, IrType::I32);
    const IrValue condition = IrValue::make_temp(1, IrType::I1);

    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x20;
    fn.name = "ppc_ctr_loop";
    IrBlock bb;
    bb.start = kStart;
    bb.end = fn.end;
    bb.kind = BlockKind::Conditional;
    bb.insts.push_back(make_assign(ctr1, IrValue::make_imm(5, IrType::I32)));
    bb.insts.push_back(make_phi(ctr2, {ctr1, ctr3}));
    IrInst sub;
    sub.op = IrOp::Sub;
    sub.dst = decremented;
    sub.srcs[0] = ctr2;
    sub.srcs[1] = IrValue::make_imm(1, IrType::I32);
    sub.src_count = 2;
    bb.insts.push_back(sub);
    bb.insts.push_back(make_assign(ctr3, decremented));
    IrInst compare;
    compare.op = IrOp::CmpNe;
    compare.dst = condition;
    compare.srcs[0] = decremented;
    compare.srcs[1] = IrValue::make_imm(0, IrType::I32);
    compare.src_count = 2;
    bb.insts.push_back(compare);
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto loop = std::make_unique<Region>();
    loop->kind = RegionKind::DoWhile;
    loop->condition = condition;
    loop->children.push_back(std::move(block));
    StructuredFunction sf{&fn, std::move(loop)};

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, nullptr, EmitOptions{});
    check(pc.has_value(), "PPC CTR loop pseudo-C emits");
    if (!pc) return 1;
    check(pc->find("while (--i != 0);") != std::string::npos,
          "bdnz condition retains the CTR predecrement side effect");
    return 0;
}

int test_ppc_void_return_merge_becomes_entry_guard() {
    using namespace ember;

    constexpr addr_t kStart = 0x1000;
    constexpr addr_t kBody = 0x1010;
    constexpr addr_t kExit = 0x1020;

    IrValue r3_live = IrValue::make_reg(Reg::PpcR3, IrType::I32);
    IrValue r3_1 = r3_live; r3_1.version = 1;
    IrValue r3_2 = r3_live; r3_2.version = 2;
    IrValue r3_phi = r3_live; r3_phi.version = 7;

    IrFunction fn;
    fn.start = kStart;
    fn.end = kExit + 4;
    fn.name = "ppc_void_callback";

    IrBlock body_bb;
    body_bb.start = kBody;
    body_bb.end = kBody + 4;
    body_bb.kind = BlockKind::Fallthrough;
    body_bb.insts.push_back(make_call_imm(kBody, 0x2000));
    fn.block_at[kBody] = fn.blocks.size();
    fn.blocks.push_back(std::move(body_bb));

    IrBlock exit_bb;
    exit_bb.start = kExit;
    exit_bb.end = kExit + 4;
    exit_bb.kind = BlockKind::Return;
    IrInst c1; c1.op = IrOp::Clobber; c1.dst = r3_1;
    IrInst c2; c2.op = IrOp::Clobber; c2.dst = r3_2;
    exit_bb.insts.push_back(c1);
    exit_bb.insts.push_back(c2);
    exit_bb.insts.push_back(make_phi(r3_phi, {
        r3_live, r3_1, r3_2,
        IrValue::make_imm(1, IrType::I32),
        IrValue::make_imm(2, IrType::I32),
        IrValue::make_imm(3, IrType::I32),
    }));
    exit_bb.insts.push_back(make_ret_value(kExit, r3_phi));
    fn.block_at[kExit] = fn.blocks.size();
    fn.blocks.push_back(std::move(exit_bb));

    auto body_block = std::make_unique<Region>();
    body_block->kind = RegionKind::Block;
    body_block->block_start = kBody;
    auto guarded = std::make_unique<Region>();
    guarded->kind = RegionKind::IfThen;
    guarded->condition = IrValue::make_imm(1, IrType::I1);
    guarded->children.push_back(std::move(body_block));
    auto exit_block = std::make_unique<Region>();
    exit_block->kind = RegionKind::Block;
    exit_block->block_start = kExit;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
    tail->condition = r3_phi;
    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Seq;
    root->children.push_back(std::move(guarded));
    root->children.push_back(std::move(exit_block));
    root->children.push_back(std::move(tail));

    StructuredFunction sf;
    sf.ir = &fn;
    sf.body = std::move(root);

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, nullptr, EmitOptions{});
    check(pc.has_value(), "PPC void-merge pseudo-C emits");
    if (!pc) return 1;

    check(pc->find("void ppc_void_callback(void)") != std::string::npos,
          "incidental PPC r3 merge is inferred as void");
    check(pc->find(
              "if (!1) {\n    return;\n  }\n  sub_2000() /* unresolved target "
              "0x2000; inferred PPC signature (void) */;") != std::string::npos,
          "void tail if is recovered as an early entry guard");
    check(pc->find("return r3") == std::string::npos,
          "incidental PPC return-register value is not emitted");
    return 0;
}

int test_ppc_small_incidental_return_merge_is_void() {
    using namespace ember;

    constexpr addr_t kStart = 0x1200;
    IrValue r3_1 = IrValue::make_reg(Reg::PpcR3, IrType::I32);
    r3_1.version = 1;
    IrValue r3_phi = r3_1;
    r3_phi.version = 3;

    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x10;
    fn.name = "ppc_small_void_merge";

    IrBlock bb;
    bb.start = kStart;
    bb.end = kStart + 0x10;
    bb.kind = BlockKind::Return;
    IrInst clobber;
    clobber.op = IrOp::Clobber;
    clobber.dst = r3_1;
    bb.insts.push_back(clobber);
    bb.insts.push_back(make_store(IrValue::make_imm(0x3000, IrType::I32),
                                  IrValue::make_imm(4, IrType::I32)));
    IrInst phi = make_phi(r3_phi, {r3_1, IrValue::make_imm(4, IrType::I32)});
    phi.phi_preds = {kStart, kStart};
    bb.insts.push_back(std::move(phi));
    bb.insts.push_back(make_ret_value(kStart + 0xc, r3_phi));
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
    tail->condition = r3_phi;
    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Seq;
    root->children.push_back(std::move(block));
    root->children.push_back(std::move(tail));

    StructuredFunction sf;
    sf.ir = &fn;
    sf.body = std::move(root);

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, nullptr, EmitOptions{});
    check(pc.has_value(), "small incidental PPC return merge emits");
    if (!pc) return 1;
    check(pc->find("void sub_1200(void)") != std::string::npos,
          "small PPC clobber/side-effect merge is inferred as void");
    check(pc->find("return result") == std::string::npos &&
          pc->find("return 4") == std::string::npos,
          "incidental small PPC return value is suppressed");
    return 0;
}

int test_ppc_replicated_store_return_is_void() {
    using namespace ember;

    constexpr addr_t kStart = 0x1320;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x14;
    fn.name = "ppc_initializer";

    IrValue f1 = IrValue::make_reg(Reg::PpcF1, IrType::F32);
    f1.version = 1;
    IrValue r3 = IrValue::make_reg(Reg::PpcR3, IrType::I32);
    r3.version = 1;
    const IrValue scalar = IrValue::make_temp(0, IrType::F32);

    IrBlock bb;
    bb.start = kStart;
    bb.end = fn.end;
    bb.kind = BlockKind::Return;
    bb.insts.push_back(make_load(scalar,
                                 IrValue::make_imm(0x5000, IrType::I32)));
    bb.insts.push_back(make_assign(f1, scalar));
    bb.insts.push_back(make_store(IrValue::make_imm(0x6000, IrType::I32), f1));
    bb.insts.push_back(make_store(IrValue::make_imm(0x6004, IrType::I32), f1));
    IrInst ret;
    ret.op = IrOp::Return;
    ret.source_addr = kStart + 0x10;
    ret.srcs[0] = r3;
    ret.srcs[1] = f1;
    ret.src_count = 2;
    bb.insts.push_back(ret);
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
    tail->condition = f1;
    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Seq;
    root->children.push_back(std::move(block));
    root->children.push_back(std::move(tail));
    StructuredFunction sf{&fn, std::move(root)};

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, nullptr, EmitOptions{});
    check(pc.has_value(), "replicated-store PPC initializer emits");
    if (!pc) return 1;
    check(pc->find("void sub_1320(void)") != std::string::npos,
          "replicated stored FPR value is not mistaken for a return type");
    check(pc->find("return scalar") == std::string::npos,
          "incidental replicated-store return value is suppressed");
    return 0;
}

int test_ppc_switch_selector_prefers_bounds_operand() {
    using namespace ember;

    constexpr addr_t kBounds = 0x2280;
    constexpr addr_t kSwitch = 0x22a0;
    constexpr addr_t kCase0 = 0x22b0;
    constexpr addr_t kCase1 = 0x22c0;
    constexpr addr_t kDefault = 0x22d0;

    IrFunction fn;
    fn.start = kSwitch;
    fn.end = kDefault + 4;
    fn.name = "bounded_switch_selector";
    fn.next_temp_id = 2;

    const IrValue selector = IrValue::make_temp(0, IrType::I32);
    const IrValue condition = IrValue::make_temp(1, IrType::I1);
    IrValue stale_call_result = IrValue::make_reg(Reg::PpcR3, IrType::I32);
    stale_call_result.version = 3;

    IrBlock bounds;
    bounds.start = kBounds;
    bounds.end = kSwitch;
    bounds.kind = BlockKind::Conditional;
    bounds.successors = {kDefault, kSwitch};
    bounds.insts.push_back(make_clobber(stale_call_result));
    bounds.insts.push_back(make_load(
        selector, IrValue::make_imm(0x80500000, IrType::I32)));
    IrInst compare;
    compare.op = IrOp::CmpUgt;
    compare.dst = condition;
    compare.srcs[0] = selector;
    compare.srcs[1] = IrValue::make_imm(1, IrType::I32);
    compare.src_count = 2;
    bounds.insts.push_back(compare);
    bounds.insts.push_back(make_cond_branch(
        kSwitch - 4, condition, kDefault, kSwitch));
    fn.block_at[bounds.start] = fn.blocks.size();
    fn.blocks.push_back(std::move(bounds));

    IrBlock dispatch;
    dispatch.start = kSwitch;
    dispatch.end = kSwitch + 4;
    dispatch.kind = BlockKind::Switch;
    dispatch.predecessors = {kBounds};
    dispatch.successors = {kCase0, kCase1, kDefault};
    dispatch.case_values = {0, 1};
    dispatch.has_default = true;
    dispatch.switch_index = Reg::PpcR3;
    fn.block_at[dispatch.start] = fn.blocks.size();
    fn.blocks.push_back(std::move(dispatch));

    const auto add_return = [&](addr_t start, std::vector<addr_t> predecessors) {
        IrBlock block;
        block.start = start;
        block.end = start + 4;
        block.kind = BlockKind::Return;
        block.predecessors = std::move(predecessors);
        block.insts.push_back(make_ret(start));
        fn.block_at[block.start] = fn.blocks.size();
        fn.blocks.push_back(std::move(block));
    };
    add_return(kCase0, {kSwitch});
    add_return(kCase1, {kSwitch});
    add_return(kDefault, {kBounds, kSwitch});

    Structurer structurer;
    auto structured = structurer.structure(fn);
    check(structured.has_value(), "bounded PPC switch structures");
    if (!structured) return 1;
    const Region* recovered_switch = nullptr;
    const auto find_switch = [&](const auto& self, const Region& region) -> void {
        if (region.kind == RegionKind::Switch && recovered_switch == nullptr) {
            recovered_switch = &region;
        }
        for (const auto& child : region.children) {
            if (child) self(self, *child);
        }
    };
    find_switch(find_switch, *structured->body);
    check(recovered_switch != nullptr, "bounded PPC switch region is present");
    if (recovered_switch) {
        check(recovered_switch->condition.kind == IrValueKind::Temp &&
              recovered_switch->condition.temp == selector.temp,
              "switch selector uses the compared value, not a stale r3 clobber");
    }
    return 0;
}

}  // namespace ppc_structurer_tests
