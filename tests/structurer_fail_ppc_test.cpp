// PowerPC / Wii specific structurer and emitter regressions.

#include "structurer_fail_common.hpp"

namespace {

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

int test_ppc_float_phi_keeps_float_type_after_integer_seed() {
    using namespace ember;

    constexpr addr_t kStart = 0x402380;
    IrValue f1_live = IrValue::make_reg(Reg::PpcF1, IrType::F64);
    IrValue f1_phi = f1_live;
    f1_phi.version = 1;
    IrValue f1_next = f1_live;
    f1_next.version = 2;

    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x10;
    fn.name = "ppc_float_phi";

    IrBlock bb;
    bb.start = kStart;
    bb.end = fn.end;
    bb.kind = BlockKind::Return;
    bb.insts.push_back(make_phi(f1_phi, {f1_live, f1_next}));
    bb.insts.push_back(make_add(
        f1_next, f1_phi,
        IrValue::make_imm(static_cast<i64>(0x4014000000000000ULL),
                          IrType::F64)));  // 5.0
    bb.insts.push_back(make_ret_value(kStart + 8, f1_phi));
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

    // Reproduce the conservative ABI seed that used to override the stronger
    // F64 IR evidence when declaring and returning the merge local.
    fn.value_types[value_type_key(f1_phi)] = fn.types.int_t(64);

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto ret = std::make_unique<Region>();
    ret->kind = RegionKind::Return;
    ret->condition = f1_phi;
    auto body = std::make_unique<Region>();
    body->kind = RegionKind::Seq;
    body->children.push_back(std::move(block));
    body->children.push_back(std::move(ret));
    StructuredFunction sf{&fn, std::move(body)};

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, nullptr, EmitOptions{});
    check(pc.has_value(), "PPC floating phi pseudo-C emits");
    if (!pc) return 1;
    const bool float_header = pc->find("double sub_402380(") != std::string::npos;
    check(float_header,
          "PPC floating phi retains a floating return type");
    check(pc->find("double acc") != std::string::npos,
          "PPC floating phi retains a floating merge-local type");
    check(pc->find("int64_t acc") == std::string::npos,
          "integer ABI seed does not leak into floating phi presentation");
    return 0;
}

int test_ppc_float_compare_does_not_integer_cast() {
    using namespace ember;

    constexpr addr_t kStart = 0x4023c0;
    const IrValue lhs = IrValue::make_reg(Reg::PpcF1, IrType::F64);
    const IrValue rhs = IrValue::make_reg(Reg::PpcF2, IrType::F64);
    const IrValue compared = IrValue::make_temp(0, IrType::I1);

    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 8;
    fn.name = "ppc_float_compare";
    fn.next_temp_id = 1;
    IrBlock bb;
    bb.start = kStart;
    bb.end = fn.end;
    bb.kind = BlockKind::Return;
    IrInst cmp;
    cmp.op = IrOp::CmpSlt;
    cmp.dst = compared;
    cmp.srcs[0] = lhs;
    cmp.srcs[1] = rhs;
    cmp.src_count = 2;
    bb.insts.push_back(cmp);
    bb.insts.push_back(make_ret_value(kStart + 4, compared));
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto ret = std::make_unique<Region>();
    ret->kind = RegionKind::Return;
    ret->condition = compared;
    auto body = std::make_unique<Region>();
    body->kind = RegionKind::Seq;
    body->children.push_back(std::move(block));
    body->children.push_back(std::move(ret));
    StructuredFunction sf{&fn, std::move(body)};

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, nullptr, EmitOptions{});
    check(pc.has_value(), "PPC floating comparison pseudo-C emits");
    if (!pc) return 1;
    check(pc->find(" < ") != std::string::npos,
          "PPC floating comparison remains a relational expression");
    check(pc->find("(int64_t)") == std::string::npos,
          "PPC floating comparison does not gain integer casts");
    return 0;
}

int test_ppc_casted_call_result_initializes_phi_local() {
    using namespace ember;

    constexpr addr_t kStart = 0x402400;
    const IrValue lhs = IrValue::make_reg(Reg::PpcF1, IrType::F64);
    const IrValue rhs = IrValue::make_reg(Reg::PpcF2, IrType::F64);
    IrValue call_result = lhs;
    call_result.version = 1;
    const IrValue rounded = IrValue::make_temp(0, IrType::F32);
    IrValue feed = lhs;
    feed.version = 2;
    IrValue phi = lhs;
    phi.version = 3;
    IrValue next = lhs;
    next.version = 4;

    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x14;
    fn.name = "ppc_casted_call_phi";
    fn.next_temp_id = 1;
    IrBlock bb;
    bb.start = kStart;
    bb.end = fn.end;
    bb.kind = BlockKind::Return;
    IrInst args;
    args.op = IrOp::Intrinsic;
    args.name = "call.fp_args.1";
    args.srcs[0] = lhs;
    args.srcs[1] = rhs;
    args.src_count = 2;
    bb.insts.push_back(args);
    bb.insts.push_back(make_call_imm(kStart + 4, 0x2400));
    bb.insts.push_back(make_clobber(call_result));
    IrInst trunc;
    trunc.op = IrOp::Trunc;
    trunc.dst = rounded;
    trunc.srcs[0] = call_result;
    trunc.src_count = 1;
    bb.insts.push_back(trunc);
    bb.insts.push_back(make_assign(feed, rounded));
    bb.insts.push_back(make_phi(phi, {feed, next}));
    bb.insts.push_back(make_add(
        next, phi,
        IrValue::make_imm(static_cast<i64>(0x3ff0000000000000ULL),
                          IrType::F64)));
    bb.insts.push_back(make_ret_value(kStart + 0x10, phi));
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto ret = std::make_unique<Region>();
    ret->kind = RegionKind::Return;
    ret->condition = phi;
    auto body = std::make_unique<Region>();
    body->kind = RegionKind::Seq;
    body->children.push_back(std::move(block));
    body->children.push_back(std::move(ret));
    StructuredFunction sf{&fn, std::move(body)};

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, nullptr, EmitOptions{});
    check(pc.has_value(), "casted PPC call/phi pseudo-C emits");
    if (!pc) return 1;
    const bool initialized = pc->find("acc = fmod(") != std::string::npos;
    if (!initialized) {
        std::fprintf(stderr, "Casted call/phi output:\n%s\n", pc->c_str());
    }
    check(initialized,
          "call result traced through float cast initializes phi local");
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

int test_ppc_memory_base_live_in_is_pointer() {
    using namespace ember;

    constexpr addr_t kStart = 0x1300;
    IrValue r3 = IrValue::make_reg(Reg::PpcR3, IrType::I32);
    IrValue r31 = IrValue::make_reg(Reg::PpcR31, IrType::I32);
    r31.version = 1;
    IrValue addr = IrValue::make_temp(0, IrType::I32);

    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x10;
    fn.name = "ppc_pointer_arg";
    fn.next_temp_id = 1;

    IrBlock bb;
    bb.start = kStart;
    bb.end = kStart + 0x10;
    bb.kind = BlockKind::Return;
    bb.insts.push_back(make_assign(r31, r3));
    bb.insts.push_back(make_add(addr, r31, IrValue::make_imm(0x28, IrType::I32)));
    bb.insts.push_back(make_store(addr, IrValue::make_imm(7, IrType::I32)));
    bb.insts.push_back(make_ret(kStart + 0xc));
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
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
    check(pc.has_value(), "PPC pointer-shaped parameter emits");
    if (!pc) return 1;
    check(pc->find("void sub_1300(void* state)") != std::string::npos,
          "PPC live-in memory base receives pointer type and role name");
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

int test_ppc_small_data_bases_resolve_named_globals() {
    using namespace ember;

    constexpr addr_t kStart = 0x1380;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x18;
    fn.name = "small_data_user";
    fn.next_temp_id = 4;

    const IrValue r13 = IrValue::make_reg(Reg::PpcR13, IrType::I32);
    const IrValue r2 = IrValue::make_reg(Reg::PpcR2, IrType::I32);
    const IrValue work_addr = IrValue::make_temp(0, IrType::I32);
    const IrValue scale_addr = IrValue::make_temp(1, IrType::I32);
    const IrValue work = IrValue::make_temp(2, IrType::I32);
    const IrValue scale = IrValue::make_temp(3, IrType::F32);

    IrBlock bb;
    bb.start = kStart;
    bb.end = fn.end;
    bb.kind = BlockKind::Return;
    bb.insts.push_back(make_add(
        work_addr, r13, IrValue::make_imm(-0x7e08, IrType::I32)));
    bb.insts.push_back(make_load(work, work_addr));
    bb.insts.push_back(make_add(
        scale_addr, r2, IrValue::make_imm(-0x37f8, IrType::I32)));
    bb.insts.push_back(make_load(scale, scale_addr));
    bb.insts.push_back(make_store(
        IrValue::make_imm(0x6000, IrType::I32), work));
    bb.insts.push_back(make_store(
        IrValue::make_imm(0x6004, IrType::I32), scale));
    bb.insts.push_back(make_ret(kStart + 0x18));
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Seq;
    root->children.push_back(std::move(block));
    root->children.push_back(std::move(tail));
    StructuredFunction sf{&fn, std::move(root)};

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, nullptr, EmitOptions{});
    check(pc.has_value(), "PPC small-data pseudo-C emits");
    if (!pc) return 1;
    check(pc->find("work_ptr") != std::string::npos &&
          pc->find("scale_value") != std::string::npos,
          "PPC r13/r2 references use named globals");
    check(pc->find("r13") == std::string::npos &&
          pc->find("r2 -") == std::string::npos,
          "PPC small-data references hide raw anchor registers");
    return 0;
}

int test_ppc_struct_shape_is_shared_across_pointer_aliases() {
    using namespace ember;

    constexpr addr_t kStart = 0x13c0;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x20;
    fn.name = "shared_work_shape";
    fn.next_temp_id = 4;

    const IrValue r3 = IrValue::make_reg(Reg::PpcR3, IrType::I32);
    IrValue r30 = IrValue::make_reg(Reg::PpcR30, IrType::I32);
    IrValue r31 = IrValue::make_reg(Reg::PpcR31, IrType::I32);
    r30.version = 1;
    r31.version = 1;
    const IrValue word_addr = IrValue::make_temp(0, IrType::I32);
    const IrValue float_addr = IrValue::make_temp(1, IrType::I32);
    const IrValue word = IrValue::make_temp(2, IrType::I32);
    const IrValue scalar = IrValue::make_temp(3, IrType::F32);

    IrBlock bb;
    bb.start = kStart;
    bb.end = fn.end;
    bb.kind = BlockKind::Return;
    bb.insts.push_back(make_assign(r30, r3));
    bb.insts.push_back(make_assign(r31, r3));
    bb.insts.push_back(make_add(
        word_addr, r30, IrValue::make_imm(0, IrType::I32)));
    bb.insts.push_back(make_load(word, word_addr));
    bb.insts.push_back(make_add(
        float_addr, r31, IrValue::make_imm(8, IrType::I32)));
    bb.insts.push_back(make_load(scalar, float_addr));
    bb.insts.push_back(make_store(IrValue::make_imm(0x6000, IrType::I32), word));
    bb.insts.push_back(make_store(IrValue::make_imm(0x6004, IrType::I32), scalar));
    bb.insts.push_back(make_ret(kStart + 0x20));
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Seq;
    root->children.push_back(std::move(block));
    root->children.push_back(std::move(tail));
    StructuredFunction sf{&fn, std::move(root)};

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, nullptr, EmitOptions{});
    check(pc.has_value(), "shared PPC structure pseudo-C emits");
    if (!pc) return 1;
    const bool named_shape = pc->find("PpcState* state") != std::string::npos &&
                             pc->find("state->word_0") != std::string::npos &&
                             pc->find("state->float_8") != std::string::npos &&
                             pc->find("} PpcState;") != std::string::npos;
    if (!named_shape) std::fprintf(stderr, "Shared shape output:\n%s\n", pc->c_str());
    check(named_shape, "PPC pointer aliases share typed member names");
    return 0;
}

int test_ppc_struct_member_recovers_pointer_type() {
    using namespace ember;

    constexpr addr_t kStart = 0x13d0;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x20;
    fn.name = "pointer_member_shape";
    fn.next_temp_id = 5;

    const IrValue r3 = IrValue::make_reg(Reg::PpcR3, IrType::I32);
    const IrValue member_addr = IrValue::make_temp(0, IrType::I32);
    const IrValue member = IrValue::make_temp(1, IrType::I32);
    const IrValue pointee = IrValue::make_temp(2, IrType::I16);
    const IrValue tag_addr = IrValue::make_temp(3, IrType::I32);
    const IrValue tag = IrValue::make_temp(4, IrType::I32);

    IrBlock bb;
    bb.start = kStart;
    bb.end = fn.end;
    bb.kind = BlockKind::Return;
    bb.insts.push_back(make_add(member_addr, r3,
                                IrValue::make_imm(0, IrType::I32)));
    bb.insts.push_back(make_load(member, member_addr));
    bb.insts.push_back(make_load(pointee, member));
    bb.insts.push_back(make_add(tag_addr, r3,
                                IrValue::make_imm(8, IrType::I32)));
    bb.insts.push_back(make_load(tag, tag_addr));
    bb.insts.push_back(make_store(IrValue::make_imm(0x6000, IrType::I32),
                                  pointee));
    bb.insts.push_back(make_store(IrValue::make_imm(0x6004, IrType::I32), tag));
    bb.insts.push_back(make_ret(kStart + 0x1c));
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Seq;
    root->children.push_back(std::move(block));
    root->children.push_back(std::move(tail));
    StructuredFunction sf{&fn, std::move(root)};

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, nullptr, EmitOptions{});
    check(pc.has_value(), "pointer-valued PPC structure member emits");
    if (!pc) return 1;
    const bool typed = pc->find("uint16_t* data_0") != std::string::npos &&
                       pc->find("state->data_0[0]") != std::string::npos;
    if (!typed) std::fprintf(stderr, "Pointer member output:\n%s\n", pc->c_str());
    check(typed, "downstream dereference types the containing PPC member");
    return 0;
}

int test_ppc_struct_member_recovers_nested_object() {
    using namespace ember;

    constexpr addr_t kStart = 0x1410;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x28;
    fn.name = "nested_object_shape";
    fn.next_temp_id = 8;

    const IrValue r3 = IrValue::make_reg(Reg::PpcR3, IrType::I32);
    const IrValue member_addr = IrValue::make_temp(0, IrType::I32);
    const IrValue object = IrValue::make_temp(1, IrType::I32);
    const IrValue first = IrValue::make_temp(2, IrType::I32);
    const IrValue second_addr = IrValue::make_temp(3, IrType::I32);
    const IrValue second = IrValue::make_temp(4, IrType::F32);
    const IrValue tag_addr = IrValue::make_temp(5, IrType::I32);
    const IrValue tag = IrValue::make_temp(6, IrType::I32);

    IrBlock bb;
    bb.start = kStart;
    bb.end = fn.end;
    bb.kind = BlockKind::Return;
    bb.insts.push_back(make_add(member_addr, r3,
                                IrValue::make_imm(0, IrType::I32)));
    bb.insts.push_back(make_load(object, member_addr));
    bb.insts.push_back(make_load(first, object));
    bb.insts.push_back(make_add(second_addr, object,
                                IrValue::make_imm(4, IrType::I32)));
    bb.insts.push_back(make_load(second, second_addr));
    bb.insts.push_back(make_add(tag_addr, r3,
                                IrValue::make_imm(8, IrType::I32)));
    bb.insts.push_back(make_load(tag, tag_addr));
    bb.insts.push_back(make_store(IrValue::make_imm(0x6100, IrType::I32), first));
    bb.insts.push_back(make_store(IrValue::make_imm(0x6104, IrType::I32), second));
    bb.insts.push_back(make_store(IrValue::make_imm(0x6108, IrType::I32), tag));
    bb.insts.push_back(make_ret(kStart + 0x24));
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Seq;
    root->children.push_back(std::move(block));
    root->children.push_back(std::move(tail));
    StructuredFunction sf{&fn, std::move(root)};

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, nullptr, EmitOptions{});
    check(pc.has_value(), "nested PPC structure member emits");
    if (!pc) return 1;
    const bool nested =
        pc->find("typedef union PpcObject PpcObject;") != std::string::npos &&
        pc->find("PpcObject* object_0") != std::string::npos &&
        pc->find("PpcObject* object = state->object_0") != std::string::npos &&
        pc->find("object->word_0") != std::string::npos &&
        pc->find("object->float_4") != std::string::npos;
    if (!nested) std::fprintf(stderr, "Nested object output:\n%s\n", pc->c_str());
    check(nested, "loaded PPC members become nested object pointers");
    return 0;
}

int test_ppc_pointer_return_type_is_shared_across_calls() {
    using namespace ember;

    constexpr addr_t kStart = 0x13e0;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x20;
    fn.name = "shared_pointer_return";
    fn.next_temp_id = 2;

    IrValue first = IrValue::make_reg(Reg::PpcR3, IrType::I32);
    IrValue second = first;
    first.version = 1;
    second.version = 2;
    const IrValue field_addr = IrValue::make_temp(0, IrType::I32);
    const IrValue field = IrValue::make_temp(1, IrType::I32);

    IrBlock bb;
    bb.start = kStart;
    bb.end = fn.end;
    bb.kind = BlockKind::Return;
    bb.insts.push_back(make_call_imm(kStart, 0x1d00));
    bb.insts.push_back(make_clobber(first));
    bb.insts.push_back(make_add(
        field_addr, first, IrValue::make_imm(4, IrType::I32)));
    bb.insts.push_back(make_load(field, field_addr));
    bb.insts.push_back(make_store(IrValue::make_imm(0x6000, IrType::I32), field));
    bb.insts.push_back(make_call_imm(kStart + 0x14, 0x1d00));
    bb.insts.push_back(make_clobber(second));
    bb.insts.push_back(make_store(IrValue::make_imm(0x6004, IrType::I32), second));
    bb.insts.push_back(make_ret(kStart + 0x20));
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Seq;
    root->children.push_back(std::move(block));
    root->children.push_back(std::move(tail));
    StructuredFunction sf{&fn, std::move(root)};

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, nullptr, EmitOptions{});
    check(pc.has_value(), "shared PPC pointer return pseudo-C emits");
    if (!pc) return 1;
    const auto first_decl = pc->find("void* r_make_vec = make_vec(");
    const auto second_decl = pc->find("void* r_make_vec_2 = make_vec(");
    if (first_decl == std::string::npos || second_decl == std::string::npos) {
        std::fprintf(stderr, "Shared return output:\n%s\n", pc->c_str());
    }
    check(first_decl != std::string::npos && second_decl != std::string::npos,
          "dereference evidence types every call to the same PPC callee as pointer");
    return 0;
}

int test_ppc_mixed_call_arguments_follow_callee_layout() {
    using namespace ember;

    IrFunction fn;
    fn.start = 0x1000;
    fn.end = 0x1010;
    fn.name = "mixed_caller";

    IrBlock bb;
    bb.start = 0x1000;
    bb.end = 0x1010;
    bb.kind = BlockKind::Return;

    IrInst int_args;
    int_args.op = IrOp::Intrinsic;
    int_args.name = "call.args.1";
    int_args.srcs[0] = IrValue::make_imm(11, IrType::I32);
    int_args.srcs[1] = IrValue::make_imm(22, IrType::I32);
    int_args.src_count = 2;
    bb.insts.push_back(int_args);

    IrInst fp_args;
    fp_args.op = IrOp::Intrinsic;
    fp_args.name = "call.fp_args.1";
    fp_args.srcs[0] = IrValue::make_imm(
        static_cast<i64>(0x3ff0000000000000ULL), IrType::F64);  // 1.0
    fp_args.srcs[1] = IrValue::make_imm(
        static_cast<i64>(0x4000000000000000ULL), IrType::F64);  // 2.0
    fp_args.src_count = 2;
    bb.insts.push_back(fp_args);
    bb.insts.push_back(make_call_imm(0x1008, 0x1100));
    IrInst ret;
    ret.op = IrOp::Return;
    bb.insts.push_back(ret);
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = 0x1000;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
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
    check(pc.has_value(), "mixed PPC call pseudo-C emits");
    if (!pc) return 1;
    const bool ordered =
        pc->find("mixed_callee(1, 0xb, 2, 0x16)") != std::string::npos;
    if (!ordered) std::fprintf(stderr, "mixed PPC output:\n%s\n", pc->c_str());
    check(ordered, "mixed PPC call follows f1,r3,f2,r4 callee order");
    return 0;
}

int test_ppc_known_float_call_binds_f1_result() {
    using namespace ember;

    constexpr addr_t kStart = 0x1400;
    IrValue f1 = IrValue::make_reg(Reg::PpcF1, IrType::F64);
    f1.version = 1;
    IrValue f31 = IrValue::make_reg(Reg::PpcF31, IrType::F64);
    f31.version = 1;

    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x18;
    fn.name = "ppc_float_call";

    IrBlock bb;
    bb.start = kStart;
    bb.end = kStart + 0x14;
    bb.kind = BlockKind::Return;

    IrInst args;
    args.op = IrOp::Intrinsic;
    args.name = "call.args.1";
    args.srcs[0] = IrValue::make_imm(0x3000, IrType::I32);
    args.src_count = 1;
    bb.insts.push_back(args);
    bb.insts.push_back(make_call_imm(kStart + 4, 0x1800));
    bb.insts.push_back(make_clobber(f1));
    bb.insts.push_back(make_assign(f31, f1));
    bb.insts.push_back(make_store(IrValue::make_imm(0x4000, IrType::I32), f31));
    bb.insts.push_back(make_ret(kStart + 0x10));
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
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
    check(pc.has_value(), "known PPC float-return call emits");
    if (!pc) return 1;
    const bool binds_float =
        pc->find("float r_PSVecMag = PSVecMag(") != std::string::npos;
    if (!binds_float) std::fprintf(stderr, "PPC float call output:\n%s\n", pc->c_str());
    check(binds_float, "known PSVecMag result is bound from f1 as float");
    check(pc->find("f1_1") == std::string::npos &&
          pc->find("f31_1") == std::string::npos,
          "known float call does not leak raw FPR SSA names");
    return 0;
}

int test_ppc_annotated_float_call_selects_f1() {
    using namespace ember;

    constexpr addr_t kStart = 0x1500;
    constexpr addr_t kTarget = 0x1600;
    IrValue f1 = IrValue::make_reg(Reg::PpcF1, IrType::F64);
    f1.version = 1;

    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x10;
    fn.name = "ppc_annotated_float_call";

    IrBlock bb;
    bb.start = kStart;
    bb.end = kStart + 0x10;
    bb.kind = BlockKind::Return;
    bb.insts.push_back(make_call_imm(kStart, kTarget));
    bb.insts.push_back(make_clobber(f1));
    bb.insts.push_back(make_store(IrValue::make_imm(0x5000, IrType::I32), f1));
    bb.insts.push_back(make_ret(kStart + 0xc));
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Seq;
    root->children.push_back(std::move(block));
    root->children.push_back(std::move(tail));

    StructuredFunction sf;
    sf.ir = &fn;
    sf.body = std::move(root);

    Annotations ann;
    FunctionSig sig;
    sig.return_type = "f32";
    ann.signatures[kTarget] = std::move(sig);

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, &ann, EmitOptions{});
    check(pc.has_value(), "annotated PPC float-return call emits");
    if (!pc) return 1;
    check(pc->find("float r_sub_1600 = sub_1600()") != std::string::npos,
          "annotated f32 signature selects and types the f1 result lane");
    check(pc->find("f1_1") == std::string::npos,
          "annotated float call does not leak the f1 SSA name");
    return 0;
}

int test_ppc_unknown_float_call_recovers_f1_lane() {
    using namespace ember;

    constexpr addr_t kStart = 0x1580;
    constexpr addr_t kTarget = 0x1680;
    IrValue r3 = IrValue::make_reg(Reg::PpcR3, IrType::I32);
    r3.version = 1;
    IrValue f1 = IrValue::make_reg(Reg::PpcF1, IrType::F64);
    f1.version = 1;

    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x14;
    fn.name = "ppc_unknown_float_call";

    IrBlock bb;
    bb.start = kStart;
    bb.end = fn.end;
    bb.kind = BlockKind::Return;
    bb.insts.push_back(make_call_imm(kStart, kTarget));
    bb.insts.push_back(make_clobber(r3));
    bb.insts.push_back(make_clobber(f1));
    bb.insts.push_back(make_store(IrValue::make_imm(0x5000, IrType::I32), f1));
    bb.insts.push_back(make_ret(kStart + 0x10));
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Seq;
    root->children.push_back(std::move(block));
    root->children.push_back(std::move(tail));
    StructuredFunction sf{&fn, std::move(root)};

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, nullptr, EmitOptions{});
    check(pc.has_value(), "unknown PPC floating-return call emits");
    if (!pc) return 1;
    const bool binds_float = pc->find(
        "double r_sub_1680 = sub_1680()") != std::string::npos;
    if (!binds_float) std::fprintf(
        stderr, "Unknown PPC float call output:\n%s\n", pc->c_str());
    check(binds_float,
          "used f1 with unused r3 recovers unknown floating return lane");
    check(pc->find("f1_1") == std::string::npos &&
          pc->find("r3_1") == std::string::npos,
          "unknown floating return does not leak PPC SSA lane names");
    return 0;
}

int test_ppc_frame_layout_tracks_r1_float_slots() {
    using namespace ember;

    IrFunction fn;
    fn.start = 0x16c0;
    fn.end = fn.start + 8;
    fn.name = "ppc_stack_float";

    const IrValue address = IrValue::make_temp(0, IrType::I32);
    const IrValue scalar = IrValue::make_temp(1, IrType::F32);
    IrBlock bb;
    bb.start = fn.start;
    bb.end = fn.end;
    bb.kind = BlockKind::Return;
    bb.insts.push_back(make_add(
        address,
        IrValue::make_reg(Reg::PpcR1, IrType::I32),
        IrValue::make_imm(-0x20, IrType::I32)));
    bb.insts.push_back(make_load(scalar, address));
    bb.insts.push_back(make_ret(fn.start + 4));
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

    const StackFrameLayout layout = compute_frame_layout(fn);
    const auto slot = layout.slots.find(-0x20);
    check(slot != layout.slots.end(), "PPC r1-relative local is recovered");
    if (slot != layout.slots.end()) {
        check(slot->second.name == "local_20",
              "PPC r1-relative local receives a stable local name");
        check(slot->second.type == IrType::F32 &&
              slot->second.size_bytes == 4 &&
              slot->second.direct_observed,
              "direct float access overrides address-only stack evidence");
    }
    return 0;
}

int test_ppc_sdk_signature_seeds_mixed_lanes() {
    using namespace ember;

    IrFunction fn;
    fn.start = 0x1700;
    fn.end = 0x1720;
    fn.name = "ppc_sdk_seed";

    IrBlock bb;
    bb.start = fn.start;
    bb.end = fn.end;
    bb.kind = BlockKind::Return;

    IrInst int_args;
    int_args.op = IrOp::Intrinsic;
    int_args.name = "call.args.1";
    int_args.srcs[0] = IrValue::make_reg(Reg::PpcR3, IrType::I32);
    int_args.srcs[1] = IrValue::make_reg(Reg::PpcR4, IrType::I32);
    int_args.srcs[2] = IrValue::make_reg(Reg::PpcR5, IrType::I32);
    int_args.src_count = 3;
    bb.insts.push_back(int_args);

    IrInst fp_args;
    fp_args.op = IrOp::Intrinsic;
    fp_args.name = "call.fp_args.1";
    fp_args.srcs[0] = IrValue::make_reg(Reg::PpcF1, IrType::F64);
    fp_args.src_count = 1;
    bb.insts.push_back(fp_args);
    bb.insts.push_back(make_call_imm(0x1708, 0x1a00));
    bb.insts.push_back(make_ret(0x170c));
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

    MockPpcBinary binary;
    seed_call_return_types(binary, fn);

    const auto type_of = [&](Reg reg, IrType type) {
        IrValue value = IrValue::make_reg(reg, type);
        value.version = 0;
        return fn.type_of(value);
    };
    check(fn.types.kind(type_of(Reg::PpcR3, IrType::I32)) == TypeKind::Ptr,
          "PSVECScale first pointer seeds r3");
    check(fn.types.kind(type_of(Reg::PpcR4, IrType::I32)) == TypeKind::Ptr,
          "PSVECScale second pointer seeds r4");
    check(fn.types.kind(type_of(Reg::PpcF1, IrType::F64)) == TypeKind::Float,
          "PSVECScale scalar seeds f1");
    check(type_of(Reg::PpcR5, IrType::I32).is_top(),
          "PSVECScale floating scalar does not incorrectly seed r5");
    return 0;
}

int test_ppc_annotated_stack_argument_at_call_site() {
    using namespace ember;

    constexpr addr_t kStart = 0x1c00;
    constexpr addr_t kTarget = 0x1b00;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x24;
    fn.name = "stack_caller";

    IrBlock bb;
    bb.start = kStart;
    bb.end = fn.end;
    bb.kind = BlockKind::Return;

    IrValue stack_addr = IrValue::make_temp(0, IrType::I32);
    bb.insts.push_back(make_add(stack_addr,
        IrValue::make_reg(Reg::PpcR1, IrType::I32),
        IrValue::make_imm(0x28, IrType::I32)));
    bb.insts.push_back(make_store(stack_addr,
                                 IrValue::make_imm(9, IrType::I32)));
    for (std::size_t group = 0; group < 3; ++group) {
        IrInst args;
        args.op = IrOp::Intrinsic;
        args.name = std::format("call.args.{}", group + 1);
        for (std::size_t lane = 0; lane < 3; ++lane) {
            const std::size_t index = group * 3 + lane;
            if (index >= 8) break;
            args.srcs[args.src_count++] =
                IrValue::make_imm(static_cast<i64>(index + 1), IrType::I32);
        }
        bb.insts.push_back(std::move(args));
    }
    bb.insts.push_back(make_call_imm(kStart + 0x18, kTarget));
    bb.insts.push_back(make_ret(kStart + 0x1c));
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Seq;
    root->children.push_back(std::move(block));
    root->children.push_back(std::move(tail));
    StructuredFunction sf{&fn, std::move(root)};

    Annotations ann;
    FunctionSig sig;
    sig.return_type = "void";
    for (int i = 1; i <= 9; ++i) {
        sig.params.push_back({"uint32_t", std::format("p{}", i)});
    }
    ann.signatures[kTarget] = std::move(sig);

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, &ann, EmitOptions{});
    check(pc.has_value(), "PPC outgoing stack argument emits");
    if (!pc) return 1;
    const bool recovered = pc->find(
        "stack_nine(1, 2, 3, 4, 5, 6, 7, 8, 9)") != std::string::npos;
    if (!recovered) std::fprintf(stderr, "PPC stack call output:\n%s\n", pc->c_str());
    check(recovered, "ninth PPC integer argument is recovered from sp+0x28");
    check(pc->find("arg_28") == std::string::npos,
          "outgoing PPC argument store is not emitted as a local assignment");
    return 0;
}

int test_ppc_annotated_incoming_stack_argument_name() {
    using namespace ember;

    constexpr addr_t kStart = 0x1b00;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x10;
    fn.name = "stack_nine";

    IrBlock bb;
    bb.start = kStart;
    bb.end = fn.end;
    bb.kind = BlockKind::Return;
    IrValue addr = IrValue::make_temp(0, IrType::I32);
    IrValue value = IrValue::make_temp(1, IrType::I32);
    bb.insts.push_back(make_add(addr,
        IrValue::make_reg(Reg::PpcR1, IrType::I32),
        IrValue::make_imm(0x28, IrType::I32)));
    bb.insts.push_back(make_load(value, addr));
    bb.insts.push_back(make_ret_value(kStart + 8, value));
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
    tail->condition = value;
    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Seq;
    root->children.push_back(std::move(block));
    root->children.push_back(std::move(tail));
    StructuredFunction sf{&fn, std::move(root)};

    Annotations ann;
    FunctionSig sig;
    sig.return_type = "uint32_t";
    for (int i = 1; i <= 9; ++i) {
        sig.params.push_back({"uint32_t", i == 9 ? "ninth" : std::format("p{}", i)});
    }
    ann.signatures[kStart] = std::move(sig);

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, &ann, EmitOptions{});
    check(pc.has_value(), "PPC incoming stack argument emits");
    if (!pc) return 1;
    const bool named = pc->find("return ninth;") != std::string::npos;
    if (!named) std::fprintf(stderr, "PPC incoming stack output:\n%s\n", pc->c_str());
    check(named,
          "incoming sp+0x28 load uses the annotated ninth parameter name");
    check(pc->find("arg_28") == std::string::npos,
          "incoming PPC overflow parameter does not leak a synthetic slot name");
    return 0;
}

int test_ppc_pointer_parameters_shape_stack_locals() {
    using namespace ember;

    constexpr addr_t kStart = 0x1c80;
    constexpr addr_t kTarget = 0x1ca0;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x20;
    fn.name = "typed_stack_locals";

    IrValue sin_addr = IrValue::make_temp(0, IrType::I32);
    IrValue cos_addr = IrValue::make_temp(1, IrType::I32);
    IrValue r3 = IrValue::make_reg(Reg::PpcR3, IrType::I32);
    IrValue r4 = IrValue::make_reg(Reg::PpcR4, IrType::I32);
    IrValue f1 = IrValue::make_reg(Reg::PpcF1, IrType::F32);
    r3.version = 1;
    r4.version = 1;
    f1.version = 1;

    IrBlock bb;
    bb.start = kStart;
    bb.end = fn.end;
    bb.kind = BlockKind::Return;
    bb.insts.push_back(make_add(sin_addr,
        IrValue::make_reg(Reg::PpcR1, IrType::I32),
        IrValue::make_imm(-8, IrType::I32)));
    bb.insts.push_back(make_add(cos_addr,
        IrValue::make_reg(Reg::PpcR1, IrType::I32),
        IrValue::make_imm(-4, IrType::I32)));
    bb.insts.push_back(make_assign(r3, sin_addr));
    bb.insts.push_back(make_assign(r4, cos_addr));
    bb.insts.push_back(make_assign(f1,
        IrValue::make_imm(0x3f800000, IrType::F32)));
    IrInst int_args;
    int_args.op = IrOp::Intrinsic;
    int_args.name = "call.args.1";
    int_args.srcs[0] = r3;
    int_args.srcs[1] = r4;
    int_args.src_count = 2;
    bb.insts.push_back(int_args);
    IrInst fp_args;
    fp_args.op = IrOp::Intrinsic;
    fp_args.name = "call.fp_args.1";
    fp_args.srcs[0] = f1;
    fp_args.src_count = 1;
    bb.insts.push_back(fp_args);
    bb.insts.push_back(make_call_imm(kStart + 0x18, kTarget));
    bb.insts.push_back(make_ret(kStart + 0x1c));
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Seq;
    root->children.push_back(std::move(block));
    root->children.push_back(std::move(tail));
    StructuredFunction sf{&fn, std::move(root)};

    Annotations annotations;
    FunctionSig signature;
    signature.return_type = "void";
    signature.params = {{"f32", "x"}, {"const f32 *", "sinx"}, {"f32 *", "cosx"}};
    annotations.signatures[kTarget] = std::move(signature);

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, &annotations, EmitOptions{});
    check(pc.has_value(), "typed PPC stack locals emit");
    if (!pc) return 1;
    if (pc->find("float local_8;") == std::string::npos ||
        pc->find("float local_4;") == std::string::npos) {
        std::fprintf(stderr, "Typed stack-local output:\n%s\n", pc->c_str());
    }
    check(pc->find("float local_8;") != std::string::npos &&
          pc->find("float local_4;") != std::string::npos,
          "pointer parameter types refine stack slot declarations");
    check(pc->find("const float local_8") == std::string::npos,
          "pointer-to-const input does not make the caller's stack object const");
    check(pc->find("local_8[") == std::string::npos &&
          pc->find("local_4[") == std::string::npos,
          "prototype-shaped scalar locals are not widened into arrays");
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

int test_ppc_typed_pointer_stride_is_scaled_once() {
    using namespace ember;

    constexpr addr_t kStart = 0x2360;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x10;
    fn.name = "entry_at";
    fn.next_temp_id = 2;
    const IrValue entries = IrValue::make_reg(Reg::PpcR3, IrType::I32);
    const IrValue index = IrValue::make_reg(Reg::PpcR4, IrType::I32);
    const IrValue scaled = IrValue::make_temp(0, IrType::I32);
    const IrValue result = IrValue::make_temp(1, IrType::I32);

    IrBlock block;
    block.start = kStart;
    block.end = fn.end;
    block.kind = BlockKind::Return;
    block.insts.push_back(make_mul(
        scaled, index, IrValue::make_imm(0x78, IrType::I32)));
    block.insts.push_back(make_add(result, entries, scaled));
    block.insts.push_back(make_ret_value(kStart + 8, result));
    fn.block_at[block.start] = 0;
    fn.blocks.push_back(std::move(block));

    auto body = std::make_unique<Region>();
    body->kind = RegionKind::Block;
    body->block_start = kStart;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
    tail->condition = result;
    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Seq;
    root->children.push_back(std::move(body));
    root->children.push_back(std::move(tail));
    StructuredFunction sf{&fn, std::move(root)};

    Annotations annotations;
    annotations.signatures[kStart] = FunctionSig{
        .return_type = "Entry *",
        .params = {{"Entry *", "entries"}, {"int32_t", "id"}},
        .variadic = false};
    annotations.type_sizes["Entry"] = 0x78;
    annotations.imported_records["Entry"] = ImportedRecordLayout{
        .size = 0x78, .is_union = false, .fields = {}};

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, &annotations, EmitOptions{});
    check(pc.has_value(), "typed PPC pointer stride emits");
    if (!pc) return 1;
    const bool scaled_once = pc->find("return entries + id;") != std::string::npos &&
                             pc->find("id * 0x78") == std::string::npos;
    if (!scaled_once) std::fprintf(stderr, "Pointer stride output:\n%s\n", pc->c_str());
    check(scaled_once, "byte-scaled PPC pointer arithmetic becomes one C element step");
    check(pc->find("typedef union Entry") != std::string::npos,
          "imported record used by a signature is declared in pseudo-C");
    return 0;
}

int test_ppc_rotate_mask_pointer_stride_is_scaled_once() {
    using namespace ember;

    constexpr addr_t kStart = 0x2370;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x20;
    fn.name = "word_at";
    fn.next_temp_id = 5;
    const IrValue entries = IrValue::make_reg(Reg::PpcR3, IrType::I32);
    const IrValue index = IrValue::make_reg(Reg::PpcR4, IrType::I32);
    const IrValue left = IrValue::make_temp(0, IrType::I32);
    const IrValue right = IrValue::make_temp(1, IrType::I32);
    const IrValue rotated = IrValue::make_temp(2, IrType::I32);
    const IrValue scaled = IrValue::make_temp(3, IrType::I32);
    const IrValue result = IrValue::make_temp(4, IrType::I32);
    const auto binary = [](IrOp op, IrValue dst, IrValue lhs, IrValue rhs) {
        IrInst instruction;
        instruction.op = op;
        instruction.dst = dst;
        instruction.srcs[0] = lhs;
        instruction.srcs[1] = rhs;
        instruction.src_count = 2;
        return instruction;
    };

    IrBlock block;
    block.start = kStart;
    block.end = fn.end;
    block.kind = BlockKind::Return;
    block.insts.push_back(binary(
        IrOp::Shl, left, index, IrValue::make_imm(2, IrType::I32)));
    block.insts.push_back(binary(
        IrOp::Lshr, right, index, IrValue::make_imm(30, IrType::I32)));
    block.insts.push_back(binary(IrOp::Or, rotated, left, right));
    block.insts.push_back(binary(
        IrOp::And, scaled, rotated,
        IrValue::make_imm(0xfffffffc, IrType::I32)));
    block.insts.push_back(make_add(result, entries, scaled));
    block.insts.push_back(make_ret_value(kStart + 0x14, result));
    fn.block_at[block.start] = 0;
    fn.blocks.push_back(std::move(block));

    auto body = std::make_unique<Region>();
    body->kind = RegionKind::Block;
    body->block_start = kStart;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
    tail->condition = result;
    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Seq;
    root->children.push_back(std::move(body));
    root->children.push_back(std::move(tail));
    StructuredFunction sf{&fn, std::move(root)};

    Annotations annotations;
    annotations.signatures[kStart] = FunctionSig{
        .return_type = "Word *",
        .params = {{"Word *", "entries"}, {"int32_t", "id"}},
        .variadic = false};
    annotations.type_sizes["Word"] = 4;
    annotations.imported_records["Word"] = ImportedRecordLayout{
        .size = 4, .is_union = false, .fields = {}};

    MockPpcBinary mock;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &mock, &annotations, EmitOptions{});
    check(pc.has_value(), "rotate/mask PPC pointer stride emits");
    if (!pc) return 1;
    const bool scaled_once = pc->find("return entries + id;") != std::string::npos &&
                             pc->find("id * 4") == std::string::npos &&
                             pc->find("id >> 0x1e") == std::string::npos;
    if (!scaled_once) {
        std::fprintf(stderr, "Rotate/mask pointer output:\n%s\n", pc->c_str());
    }
    check(scaled_once,
          "masked rotate byte offset becomes one typed C element step");
    return 0;
}

int test_ppc_field_copy_run_collapses_to_memcpy() {
    using namespace ember;

    constexpr addr_t kStart = 0x2380;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x40;
    fn.name = "copy_record";
    fn.next_temp_id = 12;
    const IrValue destination = IrValue::make_reg(Reg::PpcR3, IrType::I32);
    const IrValue source = IrValue::make_reg(Reg::PpcR4, IrType::I32);

    IrBlock block;
    block.start = kStart;
    block.end = fn.end;
    block.kind = BlockKind::Return;
    for (u32 i = 0; i < 4; ++i) {
        const IrValue destination_address = IrValue::make_temp(i * 3, IrType::I32);
        const IrValue source_address = IrValue::make_temp(i * 3 + 1, IrType::I32);
        const IrValue value = IrValue::make_temp(i * 3 + 2, IrType::I32);
        block.insts.push_back(make_add(
            destination_address, destination,
            IrValue::make_imm(static_cast<i64>(i * 4), IrType::I32)));
        block.insts.push_back(make_add(
            source_address, source,
            IrValue::make_imm(static_cast<i64>(0x20 + i * 4), IrType::I32)));
        block.insts.push_back(make_load(value, source_address));
        block.insts.push_back(make_store(destination_address, value));
    }
    block.insts.push_back(make_ret(kStart + 0x3c));
    fn.block_at[block.start] = 0;
    fn.blocks.push_back(std::move(block));

    auto body = std::make_unique<Region>();
    body->kind = RegionKind::Block;
    body->block_start = kStart;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Seq;
    root->children.push_back(std::move(body));
    root->children.push_back(std::move(tail));
    StructuredFunction sf{&fn, std::move(root)};

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, nullptr, EmitOptions{});
    check(pc.has_value(), "PPC record-copy run emits");
    if (!pc) return 1;
    const bool collapsed = pc->find("memcpy(") != std::string::npos &&
                           pc->find(", 0x10);") != std::string::npos;
    if (!collapsed) std::fprintf(stderr, "Record copy output:\n%s\n", pc->c_str());
    check(collapsed, "contiguous PPC field-copy run becomes one memcpy");
    return 0;
}

int test_ppc_preferred_global_alias_is_rendered() {
    using namespace ember;

    constexpr addr_t kStart = 0x23c0;
    constexpr addr_t kGlobal = 0x805ae0f8;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 8;
    fn.name = "load_work_alias";
    fn.next_temp_id = 1;
    const IrValue value = IrValue::make_temp(0, IrType::I32);
    IrBlock block;
    block.start = kStart;
    block.end = fn.end;
    block.kind = BlockKind::Return;
    block.insts.push_back(make_load(
        value, IrValue::make_imm(kGlobal, IrType::I32)));
    block.insts.push_back(make_ret_value(kStart + 4, value));
    fn.block_at[block.start] = 0;
    fn.blocks.push_back(std::move(block));

    auto body = std::make_unique<Region>();
    body->kind = RegionKind::Block;
    body->block_start = kStart;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
    tail->condition = value;
    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Seq;
    root->children.push_back(std::move(body));
    root->children.push_back(std::move(tail));
    StructuredFunction sf{&fn, std::move(root)};

    Annotations annotations;
    annotations.global_types[kGlobal] = "AliasWork *";
    annotations.preferred_global_names[kGlobal] = "work_wp";
    annotations.imported_records["AliasWork"] = ImportedRecordLayout{
        .size = 4, .is_union = false, .fields = {}};

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, &annotations, EmitOptions{});
    check(pc.has_value(), "preferred PPC global alias emits");
    if (!pc) return 1;
    check(pc->find("extern AliasWork * work_wp;") != std::string::npos &&
          pc->find("work_ptr") == std::string::npos,
          "header/linker alias replaces the anonymous DTK global name");
    return 0;
}

int test_ppc_hidden_sret_shifts_declared_call_arguments() {
    using namespace ember;

    constexpr addr_t kStart = 0x1e00;
    constexpr addr_t kTarget = 0x1d00;
    IrValue r3_result = IrValue::make_reg(Reg::PpcR3, IrType::I32);
    r3_result.version = 1;

    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x14;
    fn.name = "sret_caller";
    IrBlock bb;
    bb.start = kStart;
    bb.end = fn.end;
    bb.kind = BlockKind::Return;

    IrInst args;
    args.op = IrOp::Intrinsic;
    args.name = "call.args.1";
    args.srcs[0] = IrValue::make_imm(0x3000, IrType::I32);  // hidden result buffer
    args.srcs[1] = IrValue::make_imm(7, IrType::I32);       // declared tag
    args.src_count = 2;
    bb.insts.push_back(args);
    bb.insts.push_back(make_call_imm(kStart + 4, kTarget));
    bb.insts.push_back(make_clobber(r3_result));
    bb.insts.push_back(make_store(IrValue::make_imm(0x5000, IrType::I32),
                                  r3_result));
    bb.insts.push_back(make_ret(kStart + 0x10));
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Seq;
    root->children.push_back(std::move(block));
    root->children.push_back(std::move(tail));
    StructuredFunction sf{&fn, std::move(root)};

    Annotations ann;
    FunctionSig sig;
    sig.return_type = "Vec3";
    sig.params.push_back({"uint32_t", "tag"});
    ann.signatures[kTarget] = std::move(sig);

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, &ann, EmitOptions{});
    check(pc.has_value(), "PPC hidden-sret call emits");
    if (!pc) return 1;
    const bool shifted = pc->find("Vec3 r_make_vec = make_vec(7)") !=
        std::string::npos;
    if (!shifted) std::fprintf(stderr, "PPC sret output:\n%s\n", pc->c_str());
    check(shifted, "large aggregate return hides r3 and maps first parameter to r4");
    check(pc->find("make_vec(0x3000") == std::string::npos,
          "hidden PPC result-buffer pointer is not emitted as a source argument");
    return 0;
}

int test_ppc_small_aggregate_consumes_multiple_gprs() {
    using namespace ember;

    constexpr addr_t kStart = 0x2000;
    constexpr addr_t kTarget = 0x1f00;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x10;
    fn.name = "aggregate_caller";
    IrBlock bb;
    bb.start = kStart;
    bb.end = fn.end;
    bb.kind = BlockKind::Return;

    IrInst args;
    args.op = IrOp::Intrinsic;
    args.name = "call.args.1";
    args.srcs[0] = IrValue::make_imm(0x11, IrType::I32);
    args.srcs[1] = IrValue::make_imm(0x22, IrType::I32);
    args.srcs[2] = IrValue::make_imm(9, IrType::I32);
    args.src_count = 3;
    bb.insts.push_back(args);
    bb.insts.push_back(make_call_imm(kStart + 4, kTarget));
    bb.insts.push_back(make_ret(kStart + 8));
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Seq;
    root->children.push_back(std::move(block));
    root->children.push_back(std::move(tail));
    StructuredFunction sf{&fn, std::move(root)};

    Annotations ann;
    FunctionSig sig;
    sig.return_type = "void";
    sig.params.push_back({"CXParsedHeader", "header"});
    sig.params.push_back({"uint32_t", "flags"});
    ann.signatures[kTarget] = std::move(sig);

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, &ann, EmitOptions{});
    check(pc.has_value(), "PPC small aggregate call emits");
    if (!pc) return 1;
    const bool aligned = pc->find(
        "consume_header((CXParsedHeader){0x11, 0x22}, 9)") != std::string::npos;
    if (!aligned) std::fprintf(stderr, "PPC aggregate output:\n%s\n", pc->c_str());
    check(aligned, "eight-byte aggregate consumes r3/r4 and following scalar uses r5");
    check(pc->find("}, 0x22)") == std::string::npos,
          "second aggregate word stays inside the aggregate compound literal");
    return 0;
}

int test_wii_sdk_prototype_groups() {
    using namespace ember;

    const auto check_spec = [](std::string_view name, std::size_t params,
                               TypeKind ret_kind) {
        TypeArena arena;
        auto spec = lookup_import_sig(name, arena);
        check(spec.has_value(), "Wii SDK prototype is present");
        if (!spec) return;
        check(spec->params.size() == params, "Wii SDK prototype arity matches");
        check(arena.kind(spec->ret) == ret_kind,
              "Wii SDK prototype return kind matches");
    };

    check_spec("PSMTXTrans", 4, TypeKind::Void);
    check_spec("fmod", 2, TypeKind::Float);
    check_spec("GXSetFog", 6, TypeKind::Void);
    check_spec("GXSetViewport", 6, TypeKind::Void);
    check_spec("GXGetTexBufferSize", 5, TypeKind::Int);
    check_spec("GXSetScissor", 4, TypeKind::Void);
    check_spec("GXPixModeSync", 0, TypeKind::Void);
    check_spec("GXInitTexObjLOD", 9, TypeKind::Void);
    check_spec("OSGetArenaHi", 0, TypeKind::Ptr);
    check_spec("DVDReadPrio", 5, TypeKind::Int);
    check_spec("KPADSetBtnRepeat", 3, TypeKind::Void);

    TypeArena arena;
    auto color = lookup_import_sig("GXSetTevColor", arena);
    check(color && color->params.size() == 2,
          "GX aggregate prototype is present");
    if (color && color->params.size() == 2) {
        const TypeNode& aggregate = arena.node(color->params[1]);
        check(aggregate.kind == TypeKind::Struct &&
              aggregate.s.name == "GXColor" && aggregate.s.size == 4,
              "GXColor by-value aggregate retains its name and size");
    }

    TypeArena cx_arena;
    auto cx = lookup_import_sig("CXGetCompressionHeader", cx_arena);
    check(cx && cx_arena.kind(cx->ret) == TypeKind::Struct,
          "CX aggregate return prototype is present");
    if (cx && cx_arena.kind(cx->ret) == TypeKind::Struct) {
        const auto& info = cx_arena.node(cx->ret).s;
        check(info.name == "CXParsedHeader" && info.size == 8,
              "CXParsedHeader return retains aggregate metadata");
    }
    return 0;
}

int test_ppc_gx_mixed_signature_layout() {
    using namespace ember;

    constexpr addr_t kStart = 0x2200;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x14;
    fn.name = "gx_fog_caller";
    IrBlock bb;
    bb.start = kStart;
    bb.end = fn.end;
    bb.kind = BlockKind::Return;

    IrInst int_args;
    int_args.op = IrOp::Intrinsic;
    int_args.name = "call.args.1";
    int_args.srcs[0] = IrValue::make_imm(1, IrType::I32);
    int_args.srcs[1] = IrValue::make_imm(0x5000, IrType::I32);
    int_args.src_count = 2;
    bb.insts.push_back(int_args);
    IrInst fp_args;
    fp_args.op = IrOp::Intrinsic;
    fp_args.name = "call.fp_args.1";
    fp_args.srcs[0] = IrValue::make_imm(0x3f800000, IrType::F32);
    fp_args.srcs[1] = IrValue::make_imm(0x40000000, IrType::F32);
    fp_args.srcs[2] = IrValue::make_imm(0x40400000, IrType::F32);
    fp_args.src_count = 3;
    bb.insts.push_back(fp_args);
    IrInst fp_args2;
    fp_args2.op = IrOp::Intrinsic;
    fp_args2.name = "call.fp_args.2";
    fp_args2.srcs[0] = IrValue::make_imm(0x40800000, IrType::F32);
    fp_args2.src_count = 1;
    bb.insts.push_back(fp_args2);
    bb.insts.push_back(make_call_imm(kStart + 0xc, 0x2100));
    bb.insts.push_back(make_ret(kStart + 0x10));
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Seq;
    root->children.push_back(std::move(block));
    root->children.push_back(std::move(tail));
    StructuredFunction sf{&fn, std::move(root)};

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, nullptr, EmitOptions{});
    check(pc.has_value(), "GX mixed signature emits");
    if (!pc) return 1;
    const bool ordered = pc->find(
        "GXSetFog(1, 1f, 2f, 3f, 4f, (GXColor){0x5000})") != std::string::npos;
    if (!ordered) std::fprintf(stderr, "GX signature output:\n%s\n", pc->c_str());
    check(ordered, "GXSetFog prototype interleaves r3/f1-f4/r4 in source order");
    return 0;
}

}  // namespace

int run_ppc_structurer_tests() {
    int rc = 0;
    rc |= test_ppc_ctr_loop_keeps_predecrement();
    rc |= test_ppc_float_phi_keeps_float_type_after_integer_seed();
    rc |= test_ppc_float_compare_does_not_integer_cast();
    rc |= test_ppc_casted_call_result_initializes_phi_local();
    rc |= test_ppc_void_return_merge_becomes_entry_guard();
    rc |= test_ppc_small_incidental_return_merge_is_void();
    rc |= test_ppc_memory_base_live_in_is_pointer();
    rc |= test_ppc_replicated_store_return_is_void();
    rc |= test_ppc_small_data_bases_resolve_named_globals();
    rc |= test_ppc_struct_shape_is_shared_across_pointer_aliases();
    rc |= test_ppc_struct_member_recovers_pointer_type();
    rc |= test_ppc_struct_member_recovers_nested_object();
    rc |= test_ppc_pointer_return_type_is_shared_across_calls();
    rc |= test_ppc_mixed_call_arguments_follow_callee_layout();
    rc |= test_ppc_known_float_call_binds_f1_result();
    rc |= test_ppc_annotated_float_call_selects_f1();
    rc |= test_ppc_unknown_float_call_recovers_f1_lane();
    rc |= test_ppc_frame_layout_tracks_r1_float_slots();
    rc |= test_ppc_sdk_signature_seeds_mixed_lanes();
    rc |= test_ppc_annotated_stack_argument_at_call_site();
    rc |= test_ppc_annotated_incoming_stack_argument_name();
    rc |= test_ppc_pointer_parameters_shape_stack_locals();
    rc |= test_ppc_switch_selector_prefers_bounds_operand();
    rc |= test_ppc_typed_pointer_stride_is_scaled_once();
    rc |= test_ppc_rotate_mask_pointer_stride_is_scaled_once();
    rc |= test_ppc_field_copy_run_collapses_to_memcpy();
    rc |= test_ppc_preferred_global_alias_is_rendered();
    rc |= test_ppc_hidden_sret_shifts_declared_call_arguments();
    rc |= test_ppc_small_aggregate_consumes_multiple_gprs();
    rc |= test_wii_sdk_prototype_groups();
    rc |= test_ppc_gx_mixed_signature_layout();
    return rc;
}
