#include "structurer_fail_common.hpp"

#include <optional>

namespace {

spelunk::StructuredFunction linear_structured_function(
    const spelunk::IrFunction& function,
    std::optional<spelunk::IrValue> returned = std::nullopt)
{
    auto statements = std::make_unique<spelunk::Region>();
    statements->kind = spelunk::RegionKind::Block;
    statements->block_start = function.start;
    auto tail = std::make_unique<spelunk::Region>();
    tail->kind = spelunk::RegionKind::Return;
    if (returned) tail->condition = *returned;
    auto root = std::make_unique<spelunk::Region>();
    root->kind = spelunk::RegionKind::Seq;
    root->children.push_back(std::move(statements));
    root->children.push_back(std::move(tail));
    return spelunk::StructuredFunction{&function, std::move(root)};
}

int test_load_crossing_call_is_materialized() {
    using namespace spelunk;

    constexpr addr_t kStart = 0x22e0;
    constexpr addr_t kReset = 0x2500;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x14;
    fn.name = "save_across_reset";
    fn.next_temp_id = 1;

    const IrValue saved = IrValue::make_temp(0, IrType::I32);
    IrValue preserved = IrValue::make_reg(Reg::PpcR31, IrType::I32);
    preserved.version = 1;
    const IrValue address = IrValue::make_imm(0x805ae0f8, IrType::I32);

    IrBlock block;
    block.start = kStart;
    block.end = fn.end;
    block.kind = BlockKind::Return;
    block.insts.push_back(make_load(saved, address));
    block.insts.push_back(make_assign(preserved, saved));
    block.insts.push_back(make_call_imm(kStart + 8, kReset));
    block.insts.push_back(make_store(address, preserved));
    block.insts.push_back(make_ret(kStart + 0x10));
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

    Annotations annotations;
    annotations.signatures[kReset] = FunctionSig{
        .return_type = "void", .params = {}, .variadic = false};
    annotations.renames[kReset] = "reset_work";
    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, &annotations, EmitOptions{});
    check(pc.has_value(), "PPC memory snapshot pseudo-C emits");
    if (!pc) return 1;
    const bool saved_before_call =
        pc->find("uint32_t value = work_ptr;") != std::string::npos &&
        pc->find("reset_work();") != std::string::npos &&
        pc->find("work_ptr = value;") != std::string::npos;
    if (!saved_before_call) {
        std::fprintf(stderr, "Memory snapshot output:\n%s\n", pc->c_str());
    }
    check(saved_before_call,
          "load used after a call is materialized before the memory barrier");
    check(pc->find("work_ptr = work_ptr") == std::string::npos,
          "save/restore does not collapse into a false self-assignment");
    return 0;
}

int test_x64_load_crossing_aliasing_store_is_materialized() {
    using namespace spelunk;

    constexpr addr_t kStart = 0x2320;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x18;
    fn.name = "x64_load_snapshot";
    fn.next_temp_id = 3;

    const IrValue captured = IrValue::make_temp(0, IrType::I32);
    const IrValue safe = IrValue::make_temp(1, IrType::I32);
    const IrValue sum = IrValue::make_temp(2, IrType::I32);
    const IrValue mutated_address = IrValue::make_imm(0x5000, IrType::I64);
    const IrValue safe_address = IrValue::make_imm(0x6000, IrType::I64);

    IrBlock block;
    block.start = kStart;
    block.end = fn.end;
    block.kind = BlockKind::Return;
    block.insts.push_back(make_load(captured, mutated_address));
    block.insts.push_back(make_load(safe, safe_address));
    block.insts.push_back(make_store(
        mutated_address, IrValue::make_imm(7, IrType::I32)));
    block.insts.push_back(make_add(sum, captured, safe));
    block.insts.push_back(make_ret_value(kStart + 0x14, sum));
    fn.block_at[block.start] = 0;
    fn.blocks.push_back(std::move(block));

    auto body = std::make_unique<Region>();
    body->kind = RegionKind::Block;
    body->block_start = kStart;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
    tail->condition = sum;
    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Seq;
    root->children.push_back(std::move(body));
    root->children.push_back(std::move(tail));
    StructuredFunction sf{&fn, std::move(root)};

    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, nullptr, nullptr, EmitOptions{});
    check(pc.has_value(), "x64 memory snapshot pseudo-C emits");
    if (!pc) return 1;

    const std::size_t capture = pc->find("uint32_t t0 =");
    const std::size_t mutation = pc->find("0x5000) = 7;");
    check(capture != std::string::npos && mutation != std::string::npos &&
              capture < mutation,
          "x64 load is captured before an aliasing store");
    check(pc->find("return t0 +") != std::string::npos,
          "x64 post-store use reads the captured value");
    check(pc->find("uint32_t t1 =") == std::string::npos,
          "x64 load unaffected by the store remains inline");
    return 0;
}

int test_x64_unknown_pointer_store_may_alias_load() {
    using namespace spelunk;

    constexpr addr_t kStart = 0x2460;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x10;
    fn.name = "x64_unknown_alias_snapshot";
    fn.next_temp_id = 1;

    IrValue load_address = IrValue::make_reg(Reg::Rdi, IrType::I64);
    IrValue store_address = IrValue::make_reg(Reg::Rsi, IrType::I64);
    const IrValue captured = IrValue::make_temp(0, IrType::I32);

    IrBlock block;
    block.start = kStart;
    block.end = fn.end;
    block.kind = BlockKind::Return;
    block.insts.push_back(make_load(captured, load_address));
    block.insts.push_back(make_store(
        store_address, IrValue::make_imm(9, IrType::I32)));
    block.insts.push_back(make_ret_value(kStart + 8, captured));
    fn.block_at[block.start] = 0;
    fn.blocks.push_back(std::move(block));

    auto body = std::make_unique<Region>();
    body->kind = RegionKind::Block;
    body->block_start = kStart;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
    tail->condition = captured;
    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Seq;
    root->children.push_back(std::move(body));
    root->children.push_back(std::move(tail));
    StructuredFunction sf{&fn, std::move(root)};

    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, nullptr, nullptr, EmitOptions{});
    check(pc.has_value(), "unknown-pointer alias snapshot pseudo-C emits");
    if (!pc) return 1;

    const std::size_t capture = pc->find("uint32_t t0 =");
    const std::size_t mutation = pc->find(" = 9;");
    check(capture != std::string::npos && mutation != std::string::npos &&
              capture < mutation,
          "distinct unknown pointer roots conservatively preserve the load");
    check(pc->find("return t0;") != std::string::npos,
          "unknown-pointer store cannot make the return re-read memory");
    return 0;
}

int test_absolute_ranges_alias_across_sign_boundary() {
    using namespace spelunk;

    constexpr addr_t kStart = 0x2468;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x10;
    fn.name = "absolute_sign_boundary_snapshot";
    fn.next_temp_id = 1;

    const IrValue captured = IrValue::make_temp(0, IrType::I64);
    const IrValue load_address = IrValue::make_imm(
        std::numeric_limits<i64>::min(), IrType::I64);
    const IrValue store_address = IrValue::make_imm(
        std::numeric_limits<i64>::max() - 3, IrType::I64);
    IrBlock block;
    block.start = kStart;
    block.end = fn.end;
    block.kind = BlockKind::Return;
    block.insts.push_back(make_load(captured, load_address));
    block.insts.push_back(make_store(
        store_address, IrValue::make_imm(7, IrType::I64)));
    block.insts.push_back(make_ret_value(kStart + 8, captured));
    fn.block_at[block.start] = 0;
    fn.blocks.push_back(std::move(block));

    auto structured = linear_structured_function(fn, captured);
    PseudoCEmitter emitter;
    auto output = emitter.emit(structured, nullptr, nullptr, EmitOptions{});
    check(output.has_value(), "sign-boundary memory snapshot pseudo-C emits");
    if (!output) return 1;
    const std::size_t capture = output->find("uint64_t t0 =");
    const std::size_t mutation = output->find(" = 7;");
    check(capture != std::string::npos && mutation != std::string::npos &&
              capture < mutation && output->find("return t0;") != std::string::npos,
          "absolute memory ranges overlap across the signed-address boundary");
    return 0;
}

int test_memory_writing_intrinsic_forces_snapshot() {
    using namespace spelunk;

    constexpr addr_t kStart = 0x2470;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x10;
    fn.name = "x64_intrinsic_snapshot";
    fn.next_temp_id = 1;

    const IrValue captured = IrValue::make_temp(0, IrType::I32);
    IrInst memory_write;
    memory_write.op = IrOp::Intrinsic;
    memory_write.name = "rep.stosq";
    memory_write.srcs[0] = IrValue::make_reg(Reg::Rdi, IrType::I64);
    memory_write.srcs[1] = IrValue::make_reg(Reg::Rax, IrType::I64);
    memory_write.srcs[2] = IrValue::make_reg(Reg::Rcx, IrType::I64);
    memory_write.src_count = 3;

    IrBlock block;
    block.start = kStart;
    block.end = fn.end;
    block.kind = BlockKind::Return;
    block.insts.push_back(make_load(
        captured, IrValue::make_imm(0x5000, IrType::I64)));
    block.insts.push_back(std::move(memory_write));
    block.insts.push_back(make_ret_value(kStart + 8, captured));
    fn.block_at[block.start] = 0;
    fn.blocks.push_back(std::move(block));

    auto statements = std::make_unique<Region>();
    statements->kind = RegionKind::Block;
    statements->block_start = kStart;
    auto returned = std::make_unique<Region>();
    returned->kind = RegionKind::Return;
    returned->condition = captured;
    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Seq;
    root->children.push_back(std::move(statements));
    root->children.push_back(std::move(returned));
    StructuredFunction structured{&fn, std::move(root)};

    PseudoCEmitter emitter;
    auto output = emitter.emit(structured, nullptr, nullptr, EmitOptions{});
    check(output.has_value(), "memory-intrinsic snapshot pseudo-C emits");
    if (!output) return 1;
    check(output->find("uint32_t t0 =") != std::string::npos &&
              output->find("return t0;") != std::string::npos,
          "memory-writing intrinsic preserves the preceding load value");
    return 0;
}

int test_destination_intrinsic_remains_memory_barrier() {
    using namespace spelunk;

    constexpr addr_t kStart = 0x2478;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x10;
    fn.name = "opaque_rmw_snapshot";
    fn.next_temp_id = 2;

    const IrValue address = IrValue::make_reg(Reg::Rdi, IrType::I64);
    const IrValue captured = IrValue::make_temp(0, IrType::I32);
    IrInst rmw;
    rmw.op = IrOp::Intrinsic;
    rmw.name = "opaque.rmw";
    rmw.dst = IrValue::make_temp(1, IrType::I32);
    rmw.srcs[0] = address;
    rmw.src_count = 1;

    IrBlock block;
    block.start = kStart;
    block.end = fn.end;
    block.kind = BlockKind::Return;
    block.insts.push_back(make_load(captured, address));
    block.insts.push_back(std::move(rmw));
    block.insts.push_back(make_ret_value(kStart + 8, captured));
    fn.block_at[block.start] = 0;
    fn.blocks.push_back(std::move(block));

    auto structured = linear_structured_function(fn, captured);
    PseudoCEmitter emitter;
    auto output = emitter.emit(structured, nullptr, nullptr, EmitOptions{});
    check(output.has_value(), "destination intrinsic snapshot pseudo-C emits");
    if (!output) return 1;
    const std::size_t capture = output->find("uint32_t t0 =");
    const std::size_t intrinsic = output->find("opaque.rmw(");
    check(capture != std::string::npos && intrinsic != std::string::npos &&
              capture < intrinsic && output->find("return t0;") != std::string::npos,
          "an opaque destination-bearing intrinsic remains a memory barrier");
    return 0;
}

int test_x64_loop_revisit_observes_late_memory_barrier() {
    using namespace spelunk;

    constexpr addr_t kEntry = 0x2420;
    constexpr addr_t kLoop = 0x2430;
    constexpr addr_t kExit = 0x2440;
    IrFunction fn;
    fn.start = kEntry;
    fn.end = kExit + 8;
    fn.name = "x64_loop_snapshot";
    fn.next_temp_id = 2;

    const IrValue captured = IrValue::make_temp(0, IrType::I32);
    const IrValue incremented = IrValue::make_temp(1, IrType::I32);
    const IrValue source = IrValue::make_imm(0x5000, IrType::I64);

    IrBlock entry;
    entry.start = kEntry;
    entry.end = kLoop;
    entry.kind = BlockKind::Unconditional;
    entry.insts.push_back(make_load(captured, source));
    entry.insts.push_back(make_branch(kEntry + 4, kLoop));
    entry.successors.push_back(kLoop);
    fn.block_at[entry.start] = fn.blocks.size();
    fn.blocks.push_back(std::move(entry));

    IrBlock loop;
    loop.start = kLoop;
    loop.end = kExit;
    loop.kind = BlockKind::Conditional;
    loop.insts.push_back(make_add(
        incremented, captured, IrValue::make_imm(1, IrType::I32)));
    loop.insts.push_back(make_store(
        IrValue::make_imm(0x7000, IrType::I64), incremented));
    loop.insts.push_back(make_store(
        source, IrValue::make_imm(7, IrType::I32)));
    loop.insts.push_back(make_cond_branch(
        kLoop + 0xc, IrValue::make_imm(1, IrType::I1), kLoop, kExit));
    loop.predecessors = {kEntry, kLoop};
    loop.successors = {kLoop, kExit};
    fn.block_at[loop.start] = fn.blocks.size();
    fn.blocks.push_back(std::move(loop));

    IrBlock exit;
    exit.start = kExit;
    exit.end = fn.end;
    exit.kind = BlockKind::Return;
    exit.insts.push_back(make_ret(kExit));
    exit.predecessors.push_back(kLoop);
    fn.block_at[exit.start] = fn.blocks.size();
    fn.blocks.push_back(std::move(exit));

    auto entry_region = std::make_unique<Region>();
    entry_region->kind = RegionKind::Block;
    entry_region->block_start = kEntry;
    auto loop_block = std::make_unique<Region>();
    loop_block->kind = RegionKind::Block;
    loop_block->block_start = kLoop;
    auto loop_region = std::make_unique<Region>();
    loop_region->kind = RegionKind::While;
    loop_region->condition = IrValue::make_imm(1, IrType::I1);
    loop_region->children.push_back(std::move(loop_block));
    auto exit_region = std::make_unique<Region>();
    exit_region->kind = RegionKind::Block;
    exit_region->block_start = kExit;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Seq;
    root->children.push_back(std::move(entry_region));
    root->children.push_back(std::move(loop_region));
    root->children.push_back(std::move(exit_region));
    root->children.push_back(std::move(tail));
    StructuredFunction sf{&fn, std::move(root)};

    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, nullptr, nullptr, EmitOptions{});
    check(pc.has_value(), "loop-revisit snapshot pseudo-C emits");
    if (!pc) return 1;

    check(pc->find("uint32_t t0 =") != std::string::npos,
          "barrier after a loop use protects that use on the next iteration");
    check(pc->find(" = t0 + 1;") != std::string::npos,
          "revisited loop use reads the pre-loop snapshot");
    return 0;
}

int test_x64_many_disjoint_loads_remain_inline() {
    using namespace spelunk;

    constexpr addr_t kStart = 0x2480;
    constexpr std::size_t kLoadCount = 32;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x20;
    fn.name = "x64_many_safe_loads";
    fn.next_temp_id = static_cast<u32>(kLoadCount);

    IrBlock block;
    block.start = kStart;
    block.end = fn.end;
    block.kind = BlockKind::Return;
    std::vector<IrValue> values;
    values.reserve(kLoadCount);
    for (std::size_t i = 0; i < kLoadCount; ++i) {
        const IrValue value = IrValue::make_temp(
            static_cast<u32>(i), IrType::I32);
        values.push_back(value);
        block.insts.push_back(make_load(
            value, IrValue::make_imm(
                       static_cast<i64>(0x10000 + i * 8), IrType::I64)));
    }
    for (std::size_t i = 0; i < kLoadCount; ++i) {
        block.insts.push_back(make_store(
            IrValue::make_imm(
                static_cast<i64>(0x20000 + i * 8), IrType::I64),
            values[i]));
    }
    block.insts.push_back(make_ret(kStart + 0x1c));
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

    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, nullptr, nullptr, EmitOptions{});
    check(pc.has_value(), "many-load snapshot stress pseudo-C emits");
    if (!pc) return 1;
    check(pc->find("uint32_t t") == std::string::npos,
          "many provably disjoint loads remain inline");
    check(pc->find("0x200f8") != std::string::npos,
          "many-load snapshot stress reaches its final use");
    return 0;
}

int test_deferred_expression_keeps_load_snapshot() {
    using namespace spelunk;

    constexpr addr_t kStart = 0x2490;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x14;
    fn.name = "derived_load_snapshot";
    fn.next_temp_id = 2;

    const IrValue address = IrValue::make_imm(0x5000, IrType::I64);
    const IrValue captured = IrValue::make_temp(0, IrType::I32);
    const IrValue incremented = IrValue::make_temp(1, IrType::I32);
    IrBlock block;
    block.start = kStart;
    block.end = fn.end;
    block.kind = BlockKind::Return;
    block.insts.push_back(make_load(captured, address));
    block.insts.push_back(make_add(
        incremented, captured, IrValue::make_imm(1, IrType::I32)));
    block.insts.push_back(make_store(
        address, IrValue::make_imm(7, IrType::I32)));
    block.insts.push_back(make_ret_value(kStart + 0xc, incremented));
    fn.block_at[block.start] = 0;
    fn.blocks.push_back(std::move(block));

    auto structured = linear_structured_function(fn, incremented);
    PseudoCEmitter emitter;
    auto output = emitter.emit(structured, nullptr, nullptr, EmitOptions{});
    check(output.has_value(), "derived load-snapshot pseudo-C emits");
    if (!output) return 1;
    const std::size_t capture = output->find("uint32_t t0 =");
    const std::size_t mutation = output->find(" = 7;");
    check(capture != std::string::npos && mutation != std::string::npos &&
              capture < mutation &&
              output->find("return t0 + 1;") != std::string::npos,
          "deferred arithmetic uses the value loaded before an aliasing store");
    return 0;
}

int test_call_argument_keeps_load_snapshot() {
    using namespace spelunk;

    constexpr addr_t kStart = 0x24a0;
    constexpr addr_t kConsume = 0x420200;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x18;
    fn.name = "call_argument_snapshot";
    fn.next_temp_id = 1;

    const IrValue address = IrValue::make_imm(0x5000, IrType::I64);
    const IrValue captured = IrValue::make_temp(0, IrType::I32);
    IrInst call_args;
    call_args.op = IrOp::Intrinsic;
    call_args.name = "call.args.1";
    call_args.srcs[0] = captured;
    call_args.src_count = 1;

    IrBlock block;
    block.start = kStart;
    block.end = fn.end;
    block.kind = BlockKind::Return;
    block.insts.push_back(make_load(captured, address));
    block.insts.push_back(make_store(
        address, IrValue::make_imm(7, IrType::I32)));
    block.insts.push_back(std::move(call_args));
    block.insts.push_back(make_call_imm(kStart + 0xc, kConsume));
    block.insts.push_back(make_ret(kStart + 0x10));
    fn.block_at[block.start] = 0;
    fn.blocks.push_back(std::move(block));

    auto structured = linear_structured_function(fn);
    Annotations annotations;
    annotations.renames[kConsume] = "consume_snapshot";
    annotations.signatures[kConsume] = FunctionSig{
        .return_type = "void",
        .params = {{"uint32_t", "value"}},
        .variadic = false,
    };
    PseudoCEmitter emitter;
    auto output = emitter.emit(
        structured, nullptr, &annotations, EmitOptions{});
    check(output.has_value(), "call-argument snapshot pseudo-C emits");
    if (!output) return 1;
    const std::size_t capture = output->find("uint32_t t0 =");
    const std::size_t mutation = output->find(" = 7;");
    const bool preserved =
        capture != std::string::npos && mutation != std::string::npos &&
        capture < mutation &&
        output->find("consume_snapshot(t0);") != std::string::npos;
    if (!preserved) {
        std::fprintf(stderr, "Call-argument snapshot output:\n%s\n",
                     output->c_str());
    }
    check(preserved,
          "hidden call-argument packs preserve the pre-store load value");
    return 0;
}

int test_stack_slot_does_not_forward_load_dependent_value() {
    using namespace spelunk;

    constexpr addr_t kStart = 0x24b0;
    constexpr addr_t kBarrier = 0x420300;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x20;
    fn.name = "load_dependent_stack_slot";
    fn.next_temp_id = 4;

    const IrValue captured = IrValue::make_temp(0, IrType::I32);
    const IrValue alias = IrValue::make_temp(1, IrType::I32);
    const IrValue local_address = IrValue::make_temp(2, IrType::I64);
    const IrValue reloaded = IrValue::make_temp(3, IrType::I32);
    const IrValue source = IrValue::make_imm(0x5000, IrType::I64);
    const IrValue rsp = IrValue::make_reg(Reg::Rsp, IrType::I64);

    IrBlock block;
    block.start = kStart;
    block.end = fn.end;
    block.kind = BlockKind::Return;
    block.insts.push_back(make_load(captured, source));
    block.insts.push_back(make_assign(alias, captured));
    block.insts.push_back(make_add(
        local_address, rsp, IrValue::make_imm(-0x20, IrType::I64)));
    block.insts.push_back(make_store(local_address, alias));
    block.insts.push_back(make_call_imm(kStart + 0x10, kBarrier));
    block.insts.push_back(make_load(reloaded, local_address));
    block.insts.push_back(make_ret_value(kStart + 0x18, reloaded));
    fn.block_at[block.start] = 0;
    fn.blocks.push_back(std::move(block));

    auto structured = linear_structured_function(fn, reloaded);
    Annotations annotations;
    annotations.renames[kBarrier] = "mutate_source";
    annotations.signatures[kBarrier] = FunctionSig{
        .return_type = "void", .params = {}, .variadic = false};
    PseudoCEmitter emitter;
    auto output = emitter.emit(
        structured, nullptr, &annotations, EmitOptions{});
    check(output.has_value(), "load-dependent stack-slot pseudo-C emits");
    if (!output) return 1;
    const std::size_t save = output->find("local_20 =");
    const std::size_t barrier = output->find("mutate_source();");
    check(save != std::string::npos && barrier != std::string::npos &&
              save < barrier &&
              output->find("return local_20;") != std::string::npos,
          "stack forwarding does not move a nested load across a call");
    return 0;
}

int test_opaque_ppc_intrinsic_forces_snapshot() {
    using namespace spelunk;

    constexpr addr_t kStart = 0x24c0;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x10;
    fn.name = "ppc_cache_write_snapshot";
    fn.next_temp_id = 1;

    const IrValue address = IrValue::make_imm(0x805ae0f8, IrType::I32);
    const IrValue captured = IrValue::make_temp(0, IrType::I32);
    IrInst clear_line;
    clear_line.op = IrOp::Intrinsic;
    clear_line.name = "ppc.dcbz";
    clear_line.srcs[0] = address;
    clear_line.src_count = 1;

    IrBlock block;
    block.start = kStart;
    block.end = fn.end;
    block.kind = BlockKind::Return;
    block.insts.push_back(make_load(captured, address));
    block.insts.push_back(std::move(clear_line));
    block.insts.push_back(make_ret_value(kStart + 8, captured));
    fn.block_at[block.start] = 0;
    fn.blocks.push_back(std::move(block));

    auto structured = linear_structured_function(fn, captured);
    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto output = emitter.emit(
        structured, &binary, nullptr, EmitOptions{});
    check(output.has_value(), "PPC opaque-intrinsic snapshot pseudo-C emits");
    if (!output) return 1;
    check(output->find("uint32_t value = work_ptr;") != std::string::npos &&
              output->find("return value;") != std::string::npos,
          "opaque PPC memory intrinsic preserves the preceding load value");
    return 0;
}

int test_x64_escaped_stack_slot_store_is_retained() {
    using namespace spelunk;

    constexpr addr_t kStart = 0x2520;
    constexpr addr_t kConsume = 0x420100;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x18;
    fn.name = "escaped_stack_local";
    fn.next_temp_id = 1;

    const IrValue local_address = IrValue::make_temp(0, IrType::I64);
    IrValue rsp = IrValue::make_reg(Reg::Rsp, IrType::I64);

    IrInst call_args;
    call_args.op = IrOp::Intrinsic;
    call_args.name = "call.args.1";
    call_args.srcs[0] = local_address;
    call_args.src_count = 1;

    IrBlock block;
    block.start = kStart;
    block.end = fn.end;
    block.kind = BlockKind::Return;
    block.insts.push_back(make_add(
        local_address, rsp, IrValue::make_imm(-0x20, IrType::I64)));
    block.insts.push_back(make_store(
        local_address, IrValue::make_reg(Reg::Rdi, IrType::I64)));
    block.insts.push_back(std::move(call_args));
    block.insts.push_back(make_call_imm(kStart + 0xc, kConsume));
    block.insts.push_back(make_ret(kStart + 0x10));
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

    Annotations annotations;
    annotations.renames[kConsume] = "consume_local";
    annotations.signatures[kConsume] = FunctionSig{
        .return_type = "void",
        .params = {{"uint64_t*", "value"}},
        .variadic = false,
    };

    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, nullptr, &annotations, EmitOptions{});
    check(pc.has_value(), "escaped stack-local pseudo-C emits");
    if (!pc) return 1;

    const std::size_t initialization = pc->find("local_20 = a1;");
    const std::size_t call = pc->find("consume_local(&local_20);");
    check(initialization != std::string::npos && call != std::string::npos &&
              initialization < call,
          "store remains before a call that observes the stack-slot address");
    return 0;
}

int test_x64_partial_stack_load_retains_overlapping_store() {
    using namespace spelunk;

    constexpr addr_t kStart = 0x2530;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x18;
    fn.name = "partial_stack_observer";
    fn.next_temp_id = 3;

    const IrValue local_address = IrValue::make_temp(0, IrType::I64);
    const IrValue interior_address = IrValue::make_temp(1, IrType::I64);
    const IrValue partial = IrValue::make_temp(2, IrType::I32);
    const IrValue rsp = IrValue::make_reg(Reg::Rsp, IrType::I64);

    IrBlock block;
    block.start = kStart;
    block.end = fn.end;
    block.kind = BlockKind::Return;
    block.insts.push_back(make_add(
        local_address, rsp, IrValue::make_imm(-0x20, IrType::I64)));
    block.insts.push_back(make_add(
        interior_address, rsp, IrValue::make_imm(-0x1c, IrType::I64)));
    block.insts.push_back(make_store(
        local_address, IrValue::make_reg(Reg::Rdi, IrType::I64)));
    block.insts.push_back(make_load(partial, interior_address));
    block.insts.push_back(make_ret_value(kStart + 0x10, partial));
    fn.block_at[block.start] = 0;
    fn.blocks.push_back(std::move(block));

    auto structured = linear_structured_function(fn, partial);
    PseudoCEmitter emitter;
    auto output = emitter.emit(structured, nullptr, nullptr, EmitOptions{});
    check(output.has_value(), "partial stack-load pseudo-C emits");
    if (!output) return 1;
    check(output->find("uint8_t local_20[8];") != std::string::npos &&
              output->find("*(uint64_t*)local_20 = a1;") != std::string::npos &&
              output->find("*(uint32_t*)(local_20 + 0x4)") !=
                  std::string::npos &&
              output->find("local_1c") == std::string::npos,
          "an interior partial load aliases the wider stack object");
    return 0;
}

int test_x64_overlapping_store_disables_slot_forwarding() {
    using namespace spelunk;

    constexpr addr_t kStart = 0x2534;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x18;
    fn.name = "overlapping_stack_writes";
    fn.next_temp_id = 3;

    const IrValue local_address = IrValue::make_temp(0, IrType::I64);
    const IrValue interior_address = IrValue::make_temp(1, IrType::I64);
    const IrValue reloaded = IrValue::make_temp(2, IrType::I64);
    const IrValue rsp = IrValue::make_reg(Reg::Rsp, IrType::I64);
    IrBlock block;
    block.start = kStart;
    block.end = fn.end;
    block.kind = BlockKind::Return;
    block.insts.push_back(make_add(
        local_address, rsp, IrValue::make_imm(-0x20, IrType::I64)));
    block.insts.push_back(make_add(
        interior_address, rsp, IrValue::make_imm(-0x1c, IrType::I64)));
    block.insts.push_back(make_store(
        local_address, IrValue::make_reg(Reg::Rdi, IrType::I64)));
    block.insts.push_back(make_store(
        interior_address, IrValue::make_imm(7, IrType::I32)));
    block.insts.push_back(make_load(reloaded, local_address));
    block.insts.push_back(make_ret_value(kStart + 0x14, reloaded));
    fn.block_at[block.start] = 0;
    fn.blocks.push_back(std::move(block));

    auto structured = linear_structured_function(fn, reloaded);
    PseudoCEmitter emitter;
    auto output = emitter.emit(structured, nullptr, nullptr, EmitOptions{});
    check(output.has_value(), "overlapping stack-write pseudo-C emits");
    if (!output) return 1;
    check(output->find("uint8_t local_20[8];") != std::string::npos &&
              output->find("*(uint64_t*)local_20 = a1;") != std::string::npos &&
              output->find("*(uint32_t*)(local_20 + 0x4) = 7;") !=
                  std::string::npos &&
              output->find("return *(uint64_t*)local_20;") != std::string::npos,
          "partial overwrite prevents forwarding the original full slot value");
    return 0;
}

int test_x64_equal_width_stack_type_pun_uses_byte_storage() {
    using namespace spelunk;

    constexpr addr_t kStart = 0x2536;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x10;
    fn.name = "stack_bit_reinterpret";
    fn.next_temp_id = 2;

    const IrValue local_address = IrValue::make_temp(0, IrType::I64);
    const IrValue reloaded = IrValue::make_temp(1, IrType::F64);
    const IrValue rsp = IrValue::make_reg(Reg::Rsp, IrType::I64);
    IrBlock block;
    block.start = kStart;
    block.end = fn.end;
    block.kind = BlockKind::Return;
    block.insts.push_back(make_add(
        local_address, rsp, IrValue::make_imm(-0x20, IrType::I64)));
    block.insts.push_back(make_store(
        local_address, IrValue::make_reg(Reg::Rdi, IrType::I64)));
    block.insts.push_back(make_load(reloaded, local_address));
    block.insts.push_back(make_ret_value(kStart + 0xc, reloaded));
    fn.block_at[block.start] = 0;
    fn.blocks.push_back(std::move(block));

    auto structured = linear_structured_function(fn, reloaded);
    Annotations annotations;
    annotations.signatures[kStart] = FunctionSig{
        .return_type = "double",
        .params = {{"uint64_t", "bits"}},
        .variadic = false,
    };
    PseudoCEmitter emitter;
    auto output = emitter.emit(
        structured, nullptr, &annotations, EmitOptions{});
    check(output.has_value(), "equal-width stack type-pun pseudo-C emits");
    if (!output) return 1;
    check(output->find("uint8_t local_20[8];") != std::string::npos &&
              output->find("*(uint64_t*)local_20 = bits;") !=
                  std::string::npos &&
              output->find("return *(double*)local_20;") !=
                  std::string::npos,
          "equal-width integer/float stack accesses share byte storage");
    return 0;
}

int test_x64_interior_stack_pointer_escape_retains_store() {
    using namespace spelunk;

    constexpr addr_t kStart = 0x2538;
    constexpr addr_t kConsume = 0x420180;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x18;
    fn.name = "interior_stack_escape";
    fn.next_temp_id = 2;

    const IrValue local_address = IrValue::make_temp(0, IrType::I64);
    const IrValue interior_address = IrValue::make_temp(1, IrType::I64);
    const IrValue rsp = IrValue::make_reg(Reg::Rsp, IrType::I64);
    IrInst call_args;
    call_args.op = IrOp::Intrinsic;
    call_args.name = "call.args.1";
    call_args.srcs[0] = interior_address;
    call_args.src_count = 1;

    IrBlock block;
    block.start = kStart;
    block.end = fn.end;
    block.kind = BlockKind::Return;
    block.insts.push_back(make_add(
        local_address, rsp, IrValue::make_imm(-0x20, IrType::I64)));
    block.insts.push_back(make_add(
        interior_address, rsp, IrValue::make_imm(-0x1c, IrType::I64)));
    block.insts.push_back(make_store(
        local_address, IrValue::make_reg(Reg::Rdi, IrType::I64)));
    block.insts.push_back(std::move(call_args));
    block.insts.push_back(make_call_imm(kStart + 0x10, kConsume));
    block.insts.push_back(make_ret(kStart + 0x14));
    fn.block_at[block.start] = 0;
    fn.blocks.push_back(std::move(block));

    auto structured = linear_structured_function(fn);
    Annotations annotations;
    annotations.renames[kConsume] = "consume_interior";
    annotations.signatures[kConsume] = FunctionSig{
        .return_type = "void",
        .params = {{"uint8_t*", "value"}},
        .variadic = false,
    };
    PseudoCEmitter emitter;
    auto output = emitter.emit(
        structured, nullptr, &annotations, EmitOptions{});
    check(output.has_value(), "interior stack-pointer escape pseudo-C emits");
    if (!output) return 1;
    check(output->find("uint8_t local_20[8];") != std::string::npos &&
              output->find("*(uint64_t*)local_20 = a1;") != std::string::npos &&
              output->find("(local_20 + 0x4)") !=
                  std::string::npos &&
              output->find("local_1c") == std::string::npos,
          "an interior escaped pointer aliases the full stack object");
    return 0;
}

int test_x64_one_past_stack_pointer_keeps_storage_identity() {
    using namespace spelunk;

    constexpr addr_t kStart = 0x253c;
    constexpr addr_t kConsume = 0x420190;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x18;
    fn.name = "one_past_stack_escape";
    fn.next_temp_id = 3;

    const IrValue local_address = IrValue::make_temp(0, IrType::I64);
    const IrValue end_address = IrValue::make_temp(1, IrType::I64);
    const IrValue interior_address = IrValue::make_temp(2, IrType::I64);
    const IrValue rsp = IrValue::make_reg(Reg::Rsp, IrType::I64);
    IrInst call_args;
    call_args.op = IrOp::Intrinsic;
    call_args.name = "call.args.1";
    call_args.srcs[0] = end_address;
    call_args.src_count = 1;

    IrBlock block;
    block.start = kStart;
    block.end = fn.end;
    block.kind = BlockKind::Return;
    block.insts.push_back(make_add(
        local_address, rsp, IrValue::make_imm(-0x20, IrType::I64)));
    block.insts.push_back(make_store(
        local_address, IrValue::make_reg(Reg::Rdi, IrType::I64)));
    block.insts.push_back(make_add(
        interior_address, local_address, IrValue::make_imm(4, IrType::I64)));
    block.insts.push_back(make_store(
        interior_address, IrValue::make_imm(7, IrType::I32)));
    block.insts.push_back(make_add(
        end_address, interior_address, IrValue::make_imm(4, IrType::I64)));
    block.insts.push_back(std::move(call_args));
    block.insts.push_back(make_call_imm(kStart + 0x10, kConsume));
    block.insts.push_back(make_ret(kStart + 0x14));
    fn.block_at[block.start] = 0;
    fn.blocks.push_back(std::move(block));

    auto structured = linear_structured_function(fn);
    Annotations annotations;
    annotations.renames[kConsume] = "consume_end";
    annotations.signatures[kConsume] = FunctionSig{
        .return_type = "void",
        .params = {{"uint8_t*", "end"}},
        .variadic = false,
    };
    PseudoCEmitter emitter;
    auto output = emitter.emit(
        structured, nullptr, &annotations, EmitOptions{});
    check(output.has_value(), "one-past stack-pointer pseudo-C emits");
    if (!output) return 1;
    check(output->find("uint8_t local_20[8];") != std::string::npos &&
              output->find("consume_end((local_20 + 0x8));") !=
                  std::string::npos &&
              output->find("local_18") == std::string::npos,
          "one-past pointer remains relative to its backing stack object");
    return 0;
}

int test_x64_unobserved_stack_spill_is_suppressed() {
    using namespace spelunk;

    constexpr addr_t kStart = 0x2540;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x10;
    fn.name = "unused_stack_spill";
    fn.next_temp_id = 1;

    const IrValue local_address = IrValue::make_temp(0, IrType::I64);
    IrValue rsp = IrValue::make_reg(Reg::Rsp, IrType::I64);
    IrBlock block;
    block.start = kStart;
    block.end = fn.end;
    block.kind = BlockKind::Return;
    block.insts.push_back(make_add(
        local_address, rsp, IrValue::make_imm(-0x28, IrType::I64)));
    block.insts.push_back(make_store(
        local_address, IrValue::make_reg(Reg::Rdi, IrType::I64)));
    block.insts.push_back(make_ret(kStart + 8));
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

    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, nullptr, nullptr, EmitOptions{});
    check(pc.has_value(), "unobserved stack-spill pseudo-C emits");
    if (!pc) return 1;
    check(pc->find("local_28") == std::string::npos,
          "non-escaping stack spill remains suppressed");
    return 0;
}

int test_unused_nonvoid_call_keeps_side_effect() {
    using namespace spelunk;

    constexpr addr_t kStart = 0x2340;
    constexpr addr_t kCall = 0x410100;

    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x10;
    fn.name = "ignored_call_result";

    IrValue result = IrValue::make_reg(Reg::Rax, IrType::I64);
    result.version = 1;

    IrBlock block;
    block.start = kStart;
    block.end = fn.end;
    block.kind = BlockKind::Return;
    block.insts.push_back(make_call_imm(kStart, kCall));
    block.insts.push_back(make_clobber(result));
    block.insts.push_back(make_ret(kStart + 8));
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

    Annotations annotations;
    annotations.renames[kCall] = "observe_side_effect";
    annotations.signatures[kCall] = FunctionSig{
        .return_type = "uint64_t", .params = {}, .variadic = false};

    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, nullptr, &annotations, EmitOptions{});
    check(pc.has_value(), "unused non-void call pseudo-C emits");
    if (!pc) return 1;

    const std::string call = "observe_side_effect();";
    const std::size_t first = pc->find(call);
    check(first != std::string::npos,
          "unused non-void call remains as an effectful statement");
    check(first == std::string::npos ||
              pc->find(call, first + call.size()) == std::string::npos,
          "unused non-void call is emitted exactly once");
    check(pc->find("r_observe_side_effect") == std::string::npos,
          "unused call result binding is removed without removing the call");
    return 0;
}

int test_x64_xmm_clobber_phi_is_not_a_float_return() {
    using namespace spelunk;

    constexpr addr_t kStart = 0x2378;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x10;
    fn.name = "integer_main_like";

    IrValue rax = IrValue::make_reg(Reg::Rax, IrType::I64);
    rax.version = 1;
    IrValue xmm_clobber = IrValue::make_reg(Reg::Xmm0, IrType::I128);
    xmm_clobber.version = 1;
    IrValue xmm_phi = IrValue::make_reg(Reg::Xmm0, IrType::I128);
    xmm_phi.version = 2;

    IrBlock block;
    block.start = kStart;
    block.end = fn.end;
    block.kind = BlockKind::Return;
    block.insts.push_back(make_assign(rax, IrValue::make_imm(0, IrType::I64)));
    block.insts.push_back(make_clobber(xmm_clobber));
    block.insts.push_back(make_phi(
        xmm_phi, {IrValue::make_reg(Reg::Xmm0, IrType::I128), xmm_clobber}));
    IrInst returned = make_ret(kStart + 8);
    returned.srcs[0] = rax;
    returned.srcs[1] = xmm_phi;
    returned.src_count = 2;
    block.insts.push_back(std::move(returned));
    fn.block_at[block.start] = 0;
    fn.blocks.push_back(std::move(block));

    Structurer structurer;
    auto structured = structurer.structure(fn);
    check(structured.has_value(), "x64 return-lane fixture structures");
    if (!structured) return 1;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(*structured, nullptr, nullptr, EmitOptions{});
    check(pc.has_value(), "x64 return-lane pseudo-C emits");
    if (!pc) return 1;
    const bool integer_return = pc->find("return 0;") != std::string::npos &&
                                pc->find("__m128i") == std::string::npos &&
                                pc->find("double integer_main_like") == std::string::npos;
    if (!integer_return) {
        std::fprintf(stderr, "x64 incidental XMM return output:\n%s\n", pc->c_str());
    }
    check(integer_return,
          "XMM0 clobber-only Phi does not override an integer return lane");
    return 0;
}

int test_memory_use_recovers_pointer_after_integer_seed_conflict() {
    using namespace spelunk;

    constexpr addr_t kStart = 0x2300;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x14;
    fn.name = "seeded_pointer_local";
    fn.next_temp_id = 4;

    const IrValue pointer = IrValue::make_temp(0, IrType::I32);
    const IrValue first = IrValue::make_temp(1, IrType::I16);
    const IrValue second = IrValue::make_temp(2, IrType::I16);
    const IrValue sum = IrValue::make_temp(3, IrType::I16);
    IrBlock bb;
    bb.start = kStart;
    bb.end = fn.end;
    bb.kind = BlockKind::Return;
    bb.insts.push_back(make_load(
        pointer, IrValue::make_imm(0x5000, IrType::I32)));
    bb.insts.push_back(make_load(first, pointer));
    bb.insts.push_back(make_load(second, pointer));
    bb.insts.push_back(make_add(sum, first, second));
    bb.insts.push_back(make_store(
        IrValue::make_imm(0x6000, IrType::I32), sum));
    bb.insts.push_back(make_ret(kStart + 0x14));
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

    // Model an ABI/signature pass that conservatively seeded the loaded word
    // as an integer before its body use proved it was a pointer.
    fn.value_types[value_type_key(pointer)] = fn.types.int_t(32);
    infer_local_types(fn);
    check(fn.type_of(pointer).is_bottom(),
          "conflicting integer and pointer lattice evidence remains explicit");

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
    check(pc.has_value(), "seed-conflicted pointer local emits");
    if (!pc) return 1;
    const bool recovered = pc->find("uint16_t* data =") != std::string::npos;
    if (!recovered) std::fprintf(stderr, "Pointer recovery output:\n%s\n", pc->c_str());
    check(recovered, "visible dereferences recover the pointer declaration type");
    check(pc->find(" t0") == std::string::npos,
          "materialized PPC temporary receives a role-based name");
    return 0;
}

int test_runtime_pointer_offset_uses_byte_arithmetic() {
    using namespace spelunk;

    const auto render = [](addr_t start, IrOp op, bool pointer_first,
                           std::string pointer_type,
                           std::string second_type = "uint64_t",
                           bool alias_pointer = false,
                           std::string return_type = {}) {
        IrFunction fn;
        fn.start = start;
        fn.end = start + 8;
        fn.name = "runtime_pointer_offset";
        fn.next_temp_id = alias_pointer ? 2 : 1;

        const IrValue base = IrValue::make_reg(Reg::Rdi, IrType::I64);
        const IrValue byte_offset = IrValue::make_reg(Reg::Rsi, IrType::I64);
        const IrValue result = IrValue::make_temp(0, IrType::I64);
        const IrValue base_alias = IrValue::make_temp(1, IrType::I64);
        const IrValue arithmetic_base = alias_pointer ? base_alias : base;
        IrInst arithmetic;
        arithmetic.op = op;
        arithmetic.dst = result;
        arithmetic.srcs[0] = pointer_first ? arithmetic_base : byte_offset;
        arithmetic.srcs[1] = pointer_first ? byte_offset : arithmetic_base;
        arithmetic.src_count = 2;

        IrBlock block;
        block.start = start;
        block.end = fn.end;
        block.kind = BlockKind::Return;
        if (alias_pointer) {
            block.insts.push_back(make_assign(base_alias, base));
        }
        block.insts.push_back(std::move(arithmetic));
        block.insts.push_back(make_ret_value(start + 4, result));
        fn.block_at[block.start] = 0;
        fn.blocks.push_back(std::move(block));
        fn.value_types[value_type_key(base)] =
            fn.types.ptr_t(fn.types.int_t(32));
        if (alias_pointer) {
            fn.value_types[value_type_key(base_alias)] =
                fn.types.ptr_t(fn.types.int_t(32));
        }
        if (second_type.find('*') != std::string::npos) {
            fn.value_types[value_type_key(byte_offset)] =
                fn.types.ptr_t(fn.types.int_t(32));
        }

        auto statements = std::make_unique<Region>();
        statements->kind = RegionKind::Block;
        statements->block_start = start;
        auto returned = std::make_unique<Region>();
        returned->kind = RegionKind::Return;
        returned->condition = result;
        auto root = std::make_unique<Region>();
        root->kind = RegionKind::Seq;
        root->children.push_back(std::move(statements));
        root->children.push_back(std::move(returned));
        StructuredFunction structured{&fn, std::move(root)};

        Annotations annotations;
        annotations.signatures[start] = FunctionSig{
            .return_type = return_type.empty() ? pointer_type : return_type,
            .params = {{pointer_type, "base"}, {second_type, "byte_offset"}},
            .variadic = false,
        };
        PseudoCEmitter emitter;
        auto output = emitter.emit(
            structured, nullptr, &annotations, EmitOptions{});
        check(output.has_value(), "runtime pointer-offset pseudo-C emits");
        return output ? *output : std::string{};
    };

    const std::string added = render(0x2390, IrOp::Add, true, "uint32_t *");
    check(added.find(
              "return (uint32_t *)((uint8_t*)base + byte_offset);") !=
              std::string::npos,
          "unknown runtime offsets use byte arithmetic and restore pointer type");
    const std::string commuted = render(
        0x23a0, IrOp::Add, false, "uint32_t *");
    check(commuted.find(
              "return (uint32_t *)((uint8_t*)base + byte_offset);") !=
              std::string::npos,
          "commuted pointer addition keeps the pointer operand as its base");
    const std::string subtracted = render(
        0x23b0, IrOp::Sub, true, "uint32_t *");
    check(subtracted.find(
              "return (uint32_t *)((uint8_t*)base - byte_offset);") !=
              std::string::npos,
          "runtime pointer subtraction retains byte scaling");
    const std::string qualified = render(
        0x23c0, IrOp::Add, true, "const volatile uint32_t *");
    check(qualified.find(
              "return (const volatile uint32_t *)((const volatile uint8_t*)"
              "base + byte_offset);") != std::string::npos,
          "byte arithmetic preserves pointee const and volatile qualifiers");
    const std::string qualified_alias = render(
        0x23d0, IrOp::Add, true, "const volatile uint32_t *",
        "uint64_t", true);
    check(qualified_alias.find(
              "return (const volatile uint32_t *)((const volatile uint8_t*)"
              "base + byte_offset);") != std::string::npos,
          "byte arithmetic preserves qualifiers through a pointer alias");

    const std::string pointer_difference = render(
        0x23e0, IrOp::Sub, true, "uint32_t *", "uint32_t *", false,
        "int64_t");
    check(pointer_difference.find(
              "return (uint8_t*)base - (uint8_t*)byte_offset;") !=
              std::string::npos &&
              pointer_difference.find("(uint32_t *)((uint8_t*)") ==
                  std::string::npos,
          "pointer subtraction produces an integer byte difference");

    IrFunction converted_fn;
    converted_fn.start = 0x23f0;
    converted_fn.end = 0x23fc;
    converted_fn.name = "integerized_pointer_offset";
    converted_fn.next_temp_id = 2;
    const IrValue pointer = IrValue::make_reg(Reg::Rdi, IrType::I64);
    const IrValue offset = IrValue::make_reg(Reg::Rsi, IrType::I64);
    const IrValue truncated = IrValue::make_temp(0, IrType::I32);
    const IrValue integer_sum = IrValue::make_temp(1, IrType::I64);
    IrInst trunc;
    trunc.op = IrOp::Trunc;
    trunc.dst = truncated;
    trunc.srcs[0] = pointer;
    trunc.src_count = 1;
    IrBlock converted_block;
    converted_block.start = converted_fn.start;
    converted_block.end = converted_fn.end;
    converted_block.kind = BlockKind::Return;
    converted_block.insts.push_back(std::move(trunc));
    converted_block.insts.push_back(make_add(integer_sum, truncated, offset));
    converted_block.insts.push_back(
        make_ret_value(converted_fn.start + 8, integer_sum));
    converted_fn.block_at[converted_block.start] = 0;
    converted_fn.blocks.push_back(std::move(converted_block));
    converted_fn.value_types[value_type_key(pointer)] =
        converted_fn.types.ptr_t(converted_fn.types.int_t(32));
    converted_fn.value_types[value_type_key(truncated)] =
        converted_fn.types.int_t(32);
    auto converted_structured =
        linear_structured_function(converted_fn, integer_sum);
    Annotations converted_annotations;
    converted_annotations.signatures[converted_fn.start] = FunctionSig{
        .return_type = "uint64_t",
        .params = {{"Widget *", "base"}, {"uint64_t", "offset"}},
        .variadic = false,
    };
    converted_annotations.type_sizes["Widget"] = 4;
    PseudoCEmitter converted_emitter;
    auto converted_output = converted_emitter.emit(
        converted_structured, nullptr, &converted_annotations, EmitOptions{});
    check(converted_output.has_value() &&
              converted_output->find("uint8_t*") == std::string::npos,
          "integer width conversion stops pointer-arithmetic classification");

    IrFunction nested_fn;
    nested_fn.start = 0x2400;
    nested_fn.end = 0x240c;
    nested_fn.name = "nested_qualified_pointer_offset";
    nested_fn.next_temp_id = 2;
    const IrValue nested_base = IrValue::make_reg(Reg::Rdi, IrType::I64);
    const IrValue first_offset = IrValue::make_reg(Reg::Rsi, IrType::I64);
    const IrValue second_offset = IrValue::make_reg(Reg::Rdx, IrType::I64);
    const IrValue first_address = IrValue::make_temp(0, IrType::I64);
    const IrValue second_address = IrValue::make_temp(1, IrType::I64);
    IrBlock nested_block;
    nested_block.start = nested_fn.start;
    nested_block.end = nested_fn.end;
    nested_block.kind = BlockKind::Return;
    nested_block.insts.push_back(make_add(
        first_address, nested_base, first_offset));
    nested_block.insts.push_back(make_add(
        second_address, first_address, second_offset));
    nested_block.insts.push_back(
        make_ret_value(nested_fn.start + 8, second_address));
    nested_fn.block_at[nested_block.start] = 0;
    nested_fn.blocks.push_back(std::move(nested_block));
    const TypeRef nested_pointer_type =
        nested_fn.types.ptr_t(nested_fn.types.int_t(32));
    nested_fn.value_types[value_type_key(nested_base)] = nested_pointer_type;
    nested_fn.value_types[value_type_key(first_address)] = nested_pointer_type;
    nested_fn.value_types[value_type_key(second_address)] = nested_pointer_type;
    auto nested_structured =
        linear_structured_function(nested_fn, second_address);
    Annotations nested_annotations;
    nested_annotations.signatures[nested_fn.start] = FunctionSig{
        .return_type = "const volatile uint32_t *",
        .params = {{"const volatile uint32_t *", "base"},
                   {"uint64_t", "first_offset"},
                   {"uint64_t", "second_offset"}},
        .variadic = false,
    };
    PseudoCEmitter nested_emitter;
    auto nested_output = nested_emitter.emit(
        nested_structured, nullptr, &nested_annotations, EmitOptions{});
    const bool nested_qualified = nested_output.has_value() &&
              nested_output->find(
                  "return (const volatile uint32_t *)"
                  "((const volatile uint8_t*)(const volatile uint32_t *)"
                  "((const volatile uint8_t*)base + first_offset) + "
                  "second_offset);") != std::string::npos;
    if (nested_output && !nested_qualified) {
        std::fprintf(stderr, "Nested pointer offset output:\n%s\n",
                     nested_output->c_str());
    }
    check(nested_qualified,
          "nested pointer offsets retain declared pointee qualifiers");
    return 0;
}

}  // namespace

int main() {
    int rc = 0;
    rc |= test_load_crossing_call_is_materialized();
    rc |= test_x64_load_crossing_aliasing_store_is_materialized();
    rc |= test_x64_unknown_pointer_store_may_alias_load();
    rc |= test_absolute_ranges_alias_across_sign_boundary();
    rc |= test_memory_writing_intrinsic_forces_snapshot();
    rc |= test_destination_intrinsic_remains_memory_barrier();
    rc |= test_x64_loop_revisit_observes_late_memory_barrier();
    rc |= test_x64_many_disjoint_loads_remain_inline();
    rc |= test_deferred_expression_keeps_load_snapshot();
    rc |= test_call_argument_keeps_load_snapshot();
    rc |= test_stack_slot_does_not_forward_load_dependent_value();
    rc |= test_opaque_ppc_intrinsic_forces_snapshot();
    rc |= test_x64_escaped_stack_slot_store_is_retained();
    rc |= test_x64_partial_stack_load_retains_overlapping_store();
    rc |= test_x64_overlapping_store_disables_slot_forwarding();
    rc |= test_x64_equal_width_stack_type_pun_uses_byte_storage();
    rc |= test_x64_interior_stack_pointer_escape_retains_store();
    rc |= test_x64_one_past_stack_pointer_keeps_storage_identity();
    rc |= test_x64_unobserved_stack_spill_is_suppressed();
    rc |= test_unused_nonvoid_call_keeps_side_effect();
    rc |= test_x64_xmm_clobber_phi_is_not_a_float_return();
    rc |= test_memory_use_recovers_pointer_after_integer_seed_conflict();
    rc |= test_runtime_pointer_offset_uses_byte_arithmetic();
    return (fails == 0 && rc == 0) ? 0 : 1;
}
