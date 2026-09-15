// PowerPC / Wii floating-point inference, call-result and frame regressions.

#include "structurer_fail_common.hpp"
#include "structurer_fail_ppc_internal.hpp"

namespace ppc_structurer_tests {

int test_ppc_float_phi_keeps_float_type_after_integer_seed() {
    using namespace spelunk;

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
    using namespace spelunk;

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
    using namespace spelunk;

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

int test_ppc_known_float_call_binds_f1_result() {
    using namespace spelunk;

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
    using namespace spelunk;

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
    using namespace spelunk;

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
    using namespace spelunk;

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

}  // namespace ppc_structurer_tests
