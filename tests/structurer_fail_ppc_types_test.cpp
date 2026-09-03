// PowerPC / Wii pointer, aggregate-shape and global-name recovery regressions.

#include "structurer_fail_common.hpp"
#include "structurer_fail_ppc_internal.hpp"

namespace ppc_structurer_tests {

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

}  // namespace ppc_structurer_tests
