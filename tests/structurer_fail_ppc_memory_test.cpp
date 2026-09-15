// PowerPC / Wii typed address-expression and memory-copy lowering regressions.

#include "structurer_fail_common.hpp"
#include "structurer_fail_ppc_internal.hpp"

namespace ppc_structurer_tests {

int test_ppc_typed_pointer_stride_is_scaled_once() {
    using namespace spelunk;

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
    using namespace spelunk;

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
    using namespace spelunk;

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

}  // namespace ppc_structurer_tests
