#include <ember/ir/passes.hpp>

#include <cstdio>

namespace {

int fails = 0;

void check(bool condition, const char* message) {
    if (condition) return;
    std::fprintf(stderr, "FAIL: %s\n", message);
    ++fails;
}

ember::IrInst store(ember::IrValue address, ember::i64 value) {
    ember::IrInst i;
    i.op = ember::IrOp::Store;
    i.srcs[0] = address;
    i.srcs[1] = ember::IrValue::make_imm(value, ember::IrType::I64);
    i.src_count = 2;
    return i;
}

ember::IrFunction base_function() {
    ember::IrFunction fn;
    fn.start = 0x1000;
    fn.end = 0x1010;
    ember::IrBlock block;
    block.start = fn.start;
    block.end = fn.end;
    block.kind = ember::BlockKind::Return;
    fn.block_at.emplace(block.start, 0);
    fn.blocks.push_back(std::move(block));
    return fn;
}

void test_forwarding_respects_may_alias_store() {
    auto fn = base_function();
    auto& insts = fn.blocks[0].insts;
    const auto p = ember::IrValue::make_reg(ember::Reg::Rdi, ember::IrType::I64);
    const auto q = ember::IrValue::make_reg(ember::Reg::Rsi, ember::IrType::I64);
    insts.push_back(store(p, 1));
    insts.push_back(store(q, 2));

    ember::IrValue loaded = ember::IrValue::make_temp(0, ember::IrType::I64);
    ember::IrInst load;
    load.op = ember::IrOp::Load;
    load.dst = loaded;
    load.srcs[0] = p;
    load.src_count = 1;
    insts.push_back(load);

    ember::IrInst ret;
    ret.op = ember::IrOp::Return;
    ret.srcs[0] = loaded;
    ret.src_count = 1;
    insts.push_back(ret);

    auto result = ember::run_cleanup(fn);
    check(result.has_value(), "cleanup succeeds for forwarding test");
    const auto& out = fn.blocks[0].insts;
    bool returned_one = false;
    for (const auto& i : out) {
        if (i.op == ember::IrOp::Return && i.src_count == 1 &&
            i.srcs[0].kind == ember::IrValueKind::Imm && i.srcs[0].imm == 1) {
            returned_one = true;
        }
    }
    check(!returned_one, "load is not forwarded across a may-alias store");
}

void test_dse_respects_may_alias_load() {
    auto fn = base_function();
    auto& insts = fn.blocks[0].insts;
    const auto p = ember::IrValue::make_reg(ember::Reg::Rdi, ember::IrType::I64);
    const auto q = ember::IrValue::make_reg(ember::Reg::Rsi, ember::IrType::I64);
    insts.push_back(store(p, 1));

    ember::IrValue loaded = ember::IrValue::make_temp(0, ember::IrType::I64);
    ember::IrInst load;
    load.op = ember::IrOp::Load;
    load.dst = loaded;
    load.srcs[0] = q;
    load.src_count = 1;
    insts.push_back(load);
    insts.push_back(store(p, 2));

    ember::IrInst ret;
    ret.op = ember::IrOp::Return;
    ret.srcs[0] = loaded;
    ret.src_count = 1;
    insts.push_back(ret);

    auto result = ember::run_cleanup(fn);
    check(result.has_value(), "cleanup succeeds for DSE test");
    std::size_t stores = 0;
    for (const auto& i : fn.blocks[0].insts) stores += i.op == ember::IrOp::Store;
    check(stores == 2, "load through a may-alias pointer keeps the earlier store");
}

void test_dse_keeps_global_across_disjoint_stack_load() {
    auto fn = base_function();
    auto& insts = fn.blocks[0].insts;
    const auto global = ember::IrValue::make_imm(0x404018, ember::IrType::I64);
    const auto stack = ember::IrValue::make_reg(ember::Reg::Rsp,
                                                ember::IrType::I64);
    insts.push_back(store(global, 1));

    const auto loaded = ember::IrValue::make_temp(0, ember::IrType::I64);
    ember::IrInst load;
    load.op = ember::IrOp::Load;
    load.dst = loaded;
    load.srcs[0] = stack;
    load.src_count = 1;
    insts.push_back(load);
    insts.push_back(store(global, 2));

    ember::IrInst ret;
    ret.op = ember::IrOp::Return;
    ret.srcs[0] = loaded;
    ret.src_count = 1;
    insts.push_back(ret);

    auto result = ember::run_cleanup(fn);
    check(result.has_value(), "cleanup succeeds for disjoint storage classes");
    std::size_t stores = 0;
    for (const auto& i : fn.blocks[0].insts) stores += i.op == ember::IrOp::Store;
    check(stores == 1, "stack load does not block dead global-store removal");
}

void test_absolute_ranges_alias_across_sign_boundary() {
    auto fn = base_function();
    auto& insts = fn.blocks[0].insts;
    const auto before = ember::IrValue::make_imm(
        static_cast<ember::i64>(0x7ffffffffffffffcull), ember::IrType::I64);
    const auto after = ember::IrValue::make_imm(
        static_cast<ember::i64>(0x8000000000000000ull), ember::IrType::I64);
    insts.push_back(store(before, 1));

    const auto loaded = ember::IrValue::make_temp(0, ember::IrType::I64);
    ember::IrInst load;
    load.op = ember::IrOp::Load;
    load.dst = loaded;
    load.srcs[0] = after;
    load.src_count = 1;
    insts.push_back(load);
    insts.push_back(store(before, 2));

    ember::IrInst ret;
    ret.op = ember::IrOp::Return;
    ret.srcs[0] = loaded;
    ret.src_count = 1;
    insts.push_back(ret);

    auto result = ember::run_cleanup(fn);
    check(result.has_value(), "cleanup succeeds across absolute sign boundary");
    std::size_t stores = 0;
    for (const auto& i : fn.blocks[0].insts) stores += i.op == ember::IrOp::Store;
    check(stores == 2, "overlapping absolute ranges keep the observed store");
}

}  // namespace

int main() {
    test_forwarding_respects_may_alias_store();
    test_dse_respects_may_alias_load();
    test_dse_keeps_global_across_disjoint_stack_load();
    test_absolute_ranges_alias_across_sign_boundary();
    return fails == 0 ? 0 : 1;
}
