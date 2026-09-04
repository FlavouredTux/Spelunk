// Structurer and emitter regressions that are not architecture specific.
// Each test builds a synthetic IrFunction, structures it and checks the
// pseudo-C.

#include "structurer_fail_common.hpp"

namespace {

// ----------------------------------------------------------------------------
// Test 1: a disconnected block carrying a Call surfaces as STRUCTURER_FAIL
// instead of vanishing silently.
int test_dropped_block_diagnostic() {
    using namespace ember;

    IrFunction fn;
    fn.start = 0x10404a846;
    fn.end   = 0x10404a8e0;
    fn.name  = "sub_10404a846";

    // Reachable entry: just a Return. Mirrors the simplest valid lifted
    // shape - single block, kind=Return, no successors. The structurer
    // produces `RegionKind::Block + RegionKind::Return` for this.
    {
        IrBlock bb;
        bb.start = 0x10404a846;
        bb.end   = 0x10404a850;
        bb.kind  = BlockKind::Return;
        bb.insts.push_back(make_ret(0x10404a846));
        fn.block_at[bb.start] = fn.blocks.size();
        fn.blocks.push_back(std::move(bb));
    }

    // Disconnected block carrying a real call. The CFG has no edge
    // pointing here (no entry into block_at-from-entry walks), so the
    // structurer's build_sequence never visits it. Without the
    // STRUCTURER_FAIL diagnostic the call vanishes from the output.
    {
        IrBlock bb;
        bb.start = 0x10404a8db;
        bb.end   = 0x10404a8e0;
        bb.kind  = BlockKind::Return;
        bb.insts.push_back(make_call_imm(0x10404a8db, 0x10404a270));
        bb.insts.push_back(make_ret(0x10404a8de));
        fn.block_at[bb.start] = fn.blocks.size();
        fn.blocks.push_back(std::move(bb));
    }

    Structurer s;
    auto sf_r = s.structure(fn);
    check(sf_r.has_value(), "structurer returned a result");
    if (!sf_r) return 1;

    const std::string structured_text = format_structured(*sf_r);

    // The dangling block isn't in the structured tree - confirm the
    // marker text carries its exact range so a reader can reach for
    // `--disasm-at 0x10404a8db` to see what the structurer dropped.
    const std::string expected_marker =
        "STRUCTURER_FAIL: 0x10404a8db..0x10404a8e0 (see --disasm-at)";
    check(structured_text.find(expected_marker) != std::string::npos,
          "format_structured emits STRUCTURER_FAIL for dropped block");

    // The reachable block should still be referenced by the structured
    // body - guards against the diagnostic firing on every block (which
    // would happen if the rendered-set walk got the predicate inverted).
    check(structured_text.find("STRUCTURER_FAIL: 0x10404a846") == std::string::npos,
          "reachable block does not get a STRUCTURER_FAIL marker");

    // The pseudo-C emitter's body output should also surface the
    // marker - the failure diagnostic must reach the actual rendered
    // pseudo-C, not just the structurer's debug printer.
    PseudoCEmitter em;
    auto pc_r = em.emit(*sf_r, /*binary=*/nullptr,
                        /*annotations=*/nullptr, EmitOptions{});
    check(pc_r.has_value(), "pseudo-c emit returned a result");
    if (pc_r) {
        check(pc_r->find(expected_marker) != std::string::npos,
              "PseudoCEmitter::emit surfaces STRUCTURER_FAIL");
    }

    return 0;
}

// ----------------------------------------------------------------------------
// Test 2: a multi-block infinite loop renders both header and body, not just
// the header. Shape:
//   bb_a (header): foo();   jmp bb_b
//   bb_b:          bar();   jmp bb_a   ; back-edge
// Without the body-walk fix in build_loop's RegionKind::Loop branch, bb_b
// would silently disappear inside `for (;;) { bb_a-only; }`. We detect the
// fix indirectly: format_structured should reference bb_b somewhere in the
// loop body, AND no STRUCTURER_FAIL marker should be emitted for bb_b.
int test_infinite_loop_body_recovered() {
    using namespace ember;

    constexpr addr_t kA = 0x401000;
    constexpr addr_t kB = 0x401010;

    IrFunction fn;
    fn.start = kA;
    fn.end   = kB + 0x10;
    fn.name  = "infinite_loop";

    {
        IrBlock bb;
        bb.start = kA;
        bb.end   = kA + 0x10;
        bb.kind  = BlockKind::Unconditional;
        bb.insts.push_back(make_call_imm(kA, 0x402000));   // foo()
        bb.insts.push_back(make_branch(kA + 5, kB));
        bb.successors.push_back(kB);
        fn.block_at[bb.start] = fn.blocks.size();
        fn.blocks.push_back(std::move(bb));
    }
    {
        IrBlock bb;
        bb.start = kB;
        bb.end   = kB + 0x10;
        bb.kind  = BlockKind::Unconditional;
        bb.insts.push_back(make_call_imm(kB, 0x402010));   // bar()
        bb.insts.push_back(make_branch(kB + 5, kA));
        bb.successors.push_back(kA);
        fn.block_at[bb.start] = fn.blocks.size();
        fn.blocks.push_back(std::move(bb));
    }
    // Cross-link predecessors so find_loops sees a real back-edge.
    fn.blocks[0].predecessors.push_back(kB);  // bb_b → bb_a (back-edge)
    fn.blocks[1].predecessors.push_back(kA);  // bb_a → bb_b

    Structurer s;
    auto sf_r = s.structure(fn);
    check(sf_r.has_value(), "structurer returned a result for infinite loop");
    if (!sf_r) return 1;

    const std::string structured_text = format_structured(*sf_r);

    // bb_b's address must appear in the rendered tree - the body block
    // would be omitted under the pre-fix `RegionKind::Loop` branch.
    const std::string bb_b_marker = std::format("bb_{:x}", kB);
    check(structured_text.find(bb_b_marker) != std::string::npos,
          "infinite-loop body block surfaces in the structured output");

    // And no STRUCTURER_FAIL should fire for either block - the diagnostic
    // is a safety net, not a substitute for actually rendering the body.
    check(structured_text.find("STRUCTURER_FAIL") == std::string::npos,
          "no STRUCTURER_FAIL fires for a recovered infinite-loop body");

    return 0;
}

// A one-block shared tail that flows directly into a diamond's merge should
// be duplicated in the two source arms. Emitting a goto here is technically
// correct but obscures the original nested condition and makes large Wii menu
// functions look loopy even though the CFG is acyclic.
int test_single_shared_diamond_tail_is_cloned() {
    using namespace ember;

    constexpr addr_t kEntry  = 0x401100;
    constexpr addr_t kAlt    = 0x401110;
    constexpr addr_t kShared = 0x401120;
    constexpr addr_t kUnique = 0x401130;
    constexpr addr_t kMerge  = 0x401140;

    IrFunction fn;
    fn.start = kEntry;
    fn.end   = kMerge + 0x10;
    fn.name  = "shared_diamond_tail";

    const auto add_block = [&](addr_t start, BlockKind kind,
                               std::vector<addr_t> successors,
                               std::vector<IrInst> insts) {
        IrBlock bb;
        bb.start = start;
        bb.end = start + 0x10;
        bb.kind = kind;
        bb.successors = std::move(successors);
        bb.insts = std::move(insts);
        fn.block_at[start] = fn.blocks.size();
        fn.blocks.push_back(std::move(bb));
    };

    add_block(kEntry, BlockKind::Conditional, {kShared, kAlt},
              {make_cond_branch(kEntry, IrValue::make_imm(1, IrType::I1),
                                kShared, kAlt)});
    add_block(kAlt, BlockKind::Conditional, {kShared, kUnique},
              {make_cond_branch(kAlt, IrValue::make_imm(0, IrType::I1),
                                kShared, kUnique)});
    add_block(kShared, BlockKind::Unconditional, {kMerge},
              {make_call_imm(kShared, 0x402100),
               make_branch(kShared + 4, kMerge)});
    add_block(kUnique, BlockKind::Unconditional, {kMerge},
              {make_call_imm(kUnique, 0x402200),
               make_branch(kUnique + 4, kMerge)});
    add_block(kMerge, BlockKind::Return, {}, {make_ret(kMerge)});

    fn.blocks[fn.block_at[kEntry]].predecessors = {};
    fn.blocks[fn.block_at[kAlt]].predecessors = {kEntry};
    fn.blocks[fn.block_at[kShared]].predecessors = {kEntry, kAlt};
    fn.blocks[fn.block_at[kUnique]].predecessors = {kAlt};
    fn.blocks[fn.block_at[kMerge]].predecessors = {kShared, kUnique};

    Structurer s;
    auto sf = s.structure(fn);
    check(sf.has_value(), "shared diamond tail structures");
    if (!sf) return 1;
    const std::string text = format_structured(*sf);
    check(text.find("goto bb_401120") == std::string::npos,
          "one-block shared tail is cloned instead of rendered as goto");
    check(text.find("STRUCTURER_FAIL") == std::string::npos,
          "cloned shared diamond tail keeps every CFG block represented");
    return 0;
}

// ----------------------------------------------------------------------------
// Test 3: phi merge values get role names instead of anonymous vN names.
int test_phi_merge_names_are_mined() {
    using namespace ember;

    constexpr addr_t kStart = 0x402000;

    IrValue rax1 = IrValue::make_reg(Reg::Rax, IrType::I64);
    rax1.version = 1;
    IrValue rax2 = IrValue::make_reg(Reg::Rax, IrType::I64);
    rax2.version = 2;
    IrValue rdx1 = IrValue::make_reg(Reg::Rdx, IrType::I64);
    rdx1.version = 1;
    IrValue t0 = IrValue::make_temp(0, IrType::I64);

    IrFunction fn;
    fn.start = kStart;
    fn.end   = kStart + 0x10;
    fn.name  = "phi_result_web";
    fn.next_temp_id = 1;

    IrBlock bb;
    bb.start = kStart;
    bb.end   = kStart + 0x10;
    bb.kind  = BlockKind::Return;
    bb.insts.push_back(make_phi(rax1, {IrValue::make_reg(Reg::Rax, IrType::I64), rax2}));
    bb.insts.push_back(make_phi(rdx1, {rax1}));
    bb.insts.push_back(make_assign(rax2, IrValue::make_imm(40, IrType::I64)));
    bb.insts.push_back(make_add(t0, rdx1, IrValue::make_imm(1, IrType::I64)));
    bb.insts.push_back(make_ret_value(kStart + 3, t0));
    fn.block_at[bb.start] = fn.blocks.size();
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto ret = std::make_unique<Region>();
    ret->kind = RegionKind::Return;
    ret->condition = t0;
    auto body = std::make_unique<Region>();
    body->kind = RegionKind::Seq;
    body->children.push_back(std::move(block));
    body->children.push_back(std::move(ret));

    StructuredFunction sf;
    sf.ir = &fn;
    sf.body = std::move(body);

    PseudoCEmitter em;
    auto pc_r = em.emit(sf, /*binary=*/nullptr,
                        /*annotations=*/nullptr, EmitOptions{});
    check(pc_r.has_value(), "pseudo-c emit returned a phi result-web body");
    if (!pc_r) return 1;

    check(pc_r->find("uint64_t result;") != std::string::npos,
          "return-register phi web is named result");
    check(pc_r->find("result = 0x28;") != std::string::npos,
          "phi incoming assignment reuses result name");
    check(pc_r->find("return result + 1;") != std::string::npos,
          "connected phi web reuses result at the use site");
    check(pc_r->find("v0") == std::string::npos &&
          pc_r->find("v1") == std::string::npos,
          "phi result-web output does not leak anonymous vN names");
    check(pc_r->find("uint64_t result;\n  uint64_t result;") == std::string::npos,
          "connected phi web emits one result declaration");

    return 0;
}

int test_phi_induction_name_is_mined() {
    using namespace ember;

    constexpr addr_t kStart = 0x402100;

    IrValue eax1 = IrValue::make_reg(Reg::Eax, IrType::I32);
    eax1.version = 1;
    IrValue eax2 = IrValue::make_reg(Reg::Eax, IrType::I32);
    eax2.version = 2;

    IrFunction fn;
    fn.start = kStart;
    fn.end   = kStart + 0x10;
    fn.name  = "phi_induction";

    IrBlock bb;
    bb.start = kStart;
    bb.end   = kStart + 0x10;
    bb.kind  = BlockKind::Return;
    bb.insts.push_back(make_phi(eax1, {IrValue::make_reg(Reg::Eax, IrType::I32), eax2}));
    bb.insts.push_back(make_add(eax2, eax1, IrValue::make_imm(1, IrType::I32)));
    bb.insts.push_back(make_ret_value(kStart + 2, eax1));
    fn.block_at[bb.start] = fn.blocks.size();
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto ret = std::make_unique<Region>();
    ret->kind = RegionKind::Return;
    ret->condition = eax1;
    auto body = std::make_unique<Region>();
    body->kind = RegionKind::Seq;
    body->children.push_back(std::move(block));
    body->children.push_back(std::move(ret));

    StructuredFunction sf;
    sf.ir = &fn;
    sf.body = std::move(body);

    PseudoCEmitter em;
    auto pc_r = em.emit(sf, /*binary=*/nullptr,
                        /*annotations=*/nullptr, EmitOptions{});
    check(pc_r.has_value(), "pseudo-c emit returned a phi induction body");
    if (!pc_r) return 1;

    check(pc_r->find("uint32_t i;") != std::string::npos,
          "unit-step phi is named i");
    check(pc_r->find("i++;") != std::string::npos,
          "unit-step phi update renders as a source-style increment");
    check(pc_r->find("return i;") != std::string::npos,
          "unit-step phi name is used in return");
    check(pc_r->find("v0") == std::string::npos,
          "phi induction output does not leak anonymous vN names");

    return 0;
}

int test_full_diamond_phi_renders_ternary() {
    using namespace ember;

    constexpr addr_t kCondition = 0x402180;
    constexpr addr_t kTrue = 0x402190;
    constexpr addr_t kFalse = 0x4021a0;
    constexpr addr_t kMerge = 0x4021b0;
    IrValue condition = IrValue::make_reg(Reg::PpcR4, IrType::I1);
    IrValue result = IrValue::make_reg(Reg::PpcR3, IrType::I32);
    result.version = 1;

    IrFunction fn;
    fn.start = kCondition;
    fn.end = kMerge + 0x10;
    fn.name = "full_diamond_phi";
    auto add_block = [&](addr_t start, BlockKind kind,
                         std::vector<addr_t> predecessors,
                         std::vector<addr_t> successors,
                         std::vector<IrInst> instructions) {
        IrBlock block;
        block.start = start;
        block.end = start + 0x10;
        block.kind = kind;
        block.predecessors = std::move(predecessors);
        block.successors = std::move(successors);
        block.insts = std::move(instructions);
        fn.block_at[start] = fn.blocks.size();
        fn.blocks.push_back(std::move(block));
    };
    add_block(kCondition, BlockKind::Conditional, {}, {kTrue, kFalse},
              {make_cond_branch(kCondition, condition, kTrue, kFalse)});
    add_block(kTrue, BlockKind::Unconditional, {kCondition}, {kMerge},
              {make_branch(kTrue, kMerge)});
    add_block(kFalse, BlockKind::Unconditional, {kCondition}, {kMerge},
              {make_branch(kFalse, kMerge)});
    IrInst phi = make_phi(result, {
        IrValue::make_imm(1, IrType::I32),
        IrValue::make_imm(2, IrType::I32),
    });
    phi.phi_preds = {kTrue, kFalse};
    add_block(kMerge, BlockKind::Return, {kTrue, kFalse}, {},
              {std::move(phi), make_ret_value(kMerge + 4, result)});

    auto ret = std::make_unique<Region>();
    ret->kind = RegionKind::Return;
    ret->condition = result;
    StructuredFunction sf{&fn, std::move(ret)};
    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, nullptr, EmitOptions{});
    check(pc.has_value(), "full diamond Phi emits");
    if (!pc) return 1;
    check(pc->find("? 1 : 2") != std::string::npos,
          "two-arm diamond Phi renders as a conditional expression");
    check(pc->find("unresolved SSA merge") == std::string::npos,
          "two-arm diamond does not invent an uninitialized merge local");
    return 0;
}

int test_phi_livein_initializer_is_mined() {
    using namespace ember;

    constexpr addr_t kStart = 0x402200;

    IrValue rdi1 = IrValue::make_reg(Reg::Rdi, IrType::I64);
    rdi1.version = 1;
    IrValue rdi2 = IrValue::make_reg(Reg::Rdi, IrType::I64);
    rdi2.version = 2;

    IrFunction fn;
    fn.start = kStart;
    fn.end   = kStart + 0x10;
    fn.name  = "phi_livein_init";

    IrBlock bb;
    bb.start = kStart;
    bb.end   = kStart + 0x10;
    bb.kind  = BlockKind::Return;
    bb.insts.push_back(make_phi(rdi1, {IrValue::make_reg(Reg::Rdi, IrType::I64), rdi2}));
    bb.insts.push_back(make_add(rdi2, rdi1, IrValue::make_imm(1, IrType::I64)));
    bb.insts.push_back(make_ret_value(kStart + 2, rdi1));
    fn.block_at[bb.start] = fn.blocks.size();
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto ret = std::make_unique<Region>();
    ret->kind = RegionKind::Return;
    ret->condition = rdi1;
    auto body = std::make_unique<Region>();
    body->kind = RegionKind::Seq;
    body->children.push_back(std::move(block));
    body->children.push_back(std::move(ret));

    StructuredFunction sf;
    sf.ir = &fn;
    sf.body = std::move(body);

    PseudoCEmitter em;
    auto pc_r = em.emit(sf, /*binary=*/nullptr,
                        /*annotations=*/nullptr, EmitOptions{});
    check(pc_r.has_value(), "pseudo-c emit returned a phi live-in init body");
    if (!pc_r) return 1;

    check(pc_r->find("(uint64_t a1)") != std::string::npos,
          "phi initializer live-in bumps the function arity");
    check(pc_r->find("uint64_t i = a1;") != std::string::npos,
          "phi live-in operand initializes the mined local");
    check(pc_r->find("i++;") != std::string::npos,
          "phi live-in update renders as a source-style increment");
    check(pc_r->find("return i;") != std::string::npos,
          "phi live-in local is used at return");
    check(pc_r->find("rdi") == std::string::npos,
          "phi live-in output does not leak the raw argument register");

    return 0;
}

int test_phi_accumulator_name_is_mined() {
    using namespace ember;

    constexpr addr_t kStart = 0x402300;

    IrValue rdi1 = IrValue::make_reg(Reg::Rdi, IrType::I64);
    rdi1.version = 1;
    IrValue rdi2 = IrValue::make_reg(Reg::Rdi, IrType::I64);
    rdi2.version = 2;

    IrFunction fn;
    fn.start = kStart;
    fn.end   = kStart + 0x10;
    fn.name  = "phi_accumulator";

    IrBlock bb;
    bb.start = kStart;
    bb.end   = kStart + 0x10;
    bb.kind  = BlockKind::Return;
    bb.insts.push_back(make_phi(rdi1, {IrValue::make_reg(Reg::Rdi, IrType::I64), rdi2}));
    bb.insts.push_back(make_add(rdi2, rdi1, IrValue::make_imm(5, IrType::I64)));
    bb.insts.push_back(make_ret_value(kStart + 2, rdi1));
    fn.block_at[bb.start] = fn.blocks.size();
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto ret = std::make_unique<Region>();
    ret->kind = RegionKind::Return;
    ret->condition = rdi1;
    auto body = std::make_unique<Region>();
    body->kind = RegionKind::Seq;
    body->children.push_back(std::move(block));
    body->children.push_back(std::move(ret));

    StructuredFunction sf;
    sf.ir = &fn;
    sf.body = std::move(body);

    PseudoCEmitter em;
    auto pc_r = em.emit(sf, /*binary=*/nullptr,
                        /*annotations=*/nullptr, EmitOptions{});
    check(pc_r.has_value(), "pseudo-c emit returned a phi accumulator body");
    if (!pc_r) return 1;

    check(pc_r->find("uint64_t acc = a1;") != std::string::npos,
          "non-unit phi add is named as an accumulator");
    check(pc_r->find("acc += 5;") != std::string::npos,
          "non-unit phi add renders as a compound accumulator update");
    check(pc_r->find("return acc;") != std::string::npos,
          "accumulator name is used at return");
    check(pc_r->find("uint64_t i") == std::string::npos,
          "non-unit accumulator is not mislabeled as induction i");

    return 0;
}

int test_phi_index_name_is_mined() {
    using namespace ember;

    constexpr addr_t kStart = 0x402400;

    IrValue eax1 = IrValue::make_reg(Reg::Eax, IrType::I32);
    eax1.version = 1;
    IrValue eax2 = IrValue::make_reg(Reg::Eax, IrType::I32);
    eax2.version = 2;
    IrValue scale = IrValue::make_temp(0, IrType::I64);
    IrValue addr = IrValue::make_temp(1, IrType::I64);
    IrValue val = IrValue::make_temp(2, IrType::I64);

    IrFunction fn;
    fn.start = kStart;
    fn.end   = kStart + 0x10;
    fn.name  = "phi_indexed_load";
    fn.next_temp_id = 3;

    IrBlock bb;
    bb.start = kStart;
    bb.end   = kStart + 0x10;
    bb.kind  = BlockKind::Return;
    bb.insts.push_back(make_phi(eax1, {IrValue::make_reg(Reg::Eax, IrType::I32), eax2}));
    bb.insts.push_back(make_add(eax2, eax1, IrValue::make_imm(1, IrType::I32)));
    bb.insts.push_back(make_mul(scale, eax1, IrValue::make_imm(8, IrType::I64)));
    bb.insts.push_back(make_add(addr, IrValue::make_reg(Reg::Rdi, IrType::I64), scale));
    bb.insts.push_back(make_load(val, addr));
    bb.insts.push_back(make_ret_value(kStart + 5, val));
    fn.block_at[bb.start] = fn.blocks.size();
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto ret = std::make_unique<Region>();
    ret->kind = RegionKind::Return;
    ret->condition = val;
    auto body = std::make_unique<Region>();
    body->kind = RegionKind::Seq;
    body->children.push_back(std::move(block));
    body->children.push_back(std::move(ret));

    StructuredFunction sf;
    sf.ir = &fn;
    sf.body = std::move(body);

    PseudoCEmitter em;
    auto pc_r = em.emit(sf, /*binary=*/nullptr,
                        /*annotations=*/nullptr, EmitOptions{});
    check(pc_r.has_value(), "pseudo-c emit returned a phi indexed-load body");
    if (!pc_r) return 1;

    check(pc_r->find("uint32_t idx") != std::string::npos,
          "unit-step memory-index phi is named idx");
    check(pc_r->find("idx++;") != std::string::npos,
          "indexed phi update renders as an increment");
    check(pc_r->find("return a1[idx];") != std::string::npos,
          "indexed phi name is used in array-like memory access");
    check(pc_r->find("uint32_t i;") == std::string::npos,
          "memory-index phi is not mislabeled as generic induction i");

    return 0;
}

}  // namespace

int main() {
    int rc = 0;
    rc |= test_dropped_block_diagnostic();
    rc |= test_infinite_loop_body_recovered();
    rc |= test_single_shared_diamond_tail_is_cloned();
    rc |= test_phi_merge_names_are_mined();
    rc |= test_phi_induction_name_is_mined();
    rc |= test_full_diamond_phi_renders_ternary();
    rc |= test_phi_livein_initializer_is_mined();
    rc |= test_phi_accumulator_name_is_mined();
    rc |= test_phi_index_name_is_mined();
    rc |= run_structurer_control_flow_tests();
    rc |= run_ppc_structurer_tests();
    return (fails == 0 && rc == 0) ? 0 : 1;
}
