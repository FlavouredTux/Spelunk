// PowerPC / Wii call ABI, annotation and Wii SDK signature regressions.

#include "structurer_fail_common.hpp"
#include "structurer_fail_ppc_internal.hpp"

namespace ppc_structurer_tests {

int test_ppc_mixed_call_arguments_follow_callee_layout() {
    using namespace spelunk;

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
        pc->find("mixed_callee(1.0, 0xb, 2.0, 0x16)") != std::string::npos;
    if (!ordered) std::fprintf(stderr, "mixed PPC output:\n%s\n", pc->c_str());
    check(ordered, "mixed PPC call follows f1,r3,f2,r4 callee order");
    return 0;
}

int test_ppc_sdk_signature_seeds_mixed_lanes() {
    using namespace spelunk;

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
    using namespace spelunk;

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
    using namespace spelunk;

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

int test_ppc_hidden_sret_shifts_declared_call_arguments() {
    using namespace spelunk;

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
    using namespace spelunk;

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
    using namespace spelunk;

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
    using namespace spelunk;

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
        "GXSetFog(1, 1.0f, 2.0f, 3.0f, 4.0f, (GXColor){0x5000})") != std::string::npos;
    if (!ordered) std::fprintf(stderr, "GX signature output:\n%s\n", pc->c_str());
    check(ordered, "GXSetFog prototype interleaves r3/f1-f4/r4 in source order");
    return 0;
}

}  // namespace ppc_structurer_tests
