#include <ember/ir/passes.hpp>
#include <ember/ir/ssa.hpp>

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

// --- helpers for algebraic-identity tests ---------------------------------

ember::IrInst unary(ember::IrOp op, ember::IrValue dst, ember::IrValue src) {
    ember::IrInst i;
    i.op = op;
    i.dst = std::move(dst);
    i.srcs[0] = std::move(src);
    i.src_count = 1;
    return i;
}

ember::IrInst binary(ember::IrOp op, ember::IrValue dst, ember::IrValue lhs,
                     ember::IrValue rhs) {
    ember::IrInst i;
    i.op = op;
    i.dst = std::move(dst);
    i.srcs[0] = std::move(lhs);
    i.srcs[1] = std::move(rhs);
    i.src_count = 2;
    return i;
}

ember::IrInst ret(ember::IrValue v) {
    ember::IrInst i;
    i.op = ember::IrOp::Return;
    i.srcs[0] = std::move(v);
    i.src_count = 1;
    return i;
}

std::size_t count_op(const ember::IrFunction& fn, ember::IrOp op) {
    std::size_t n = 0;
    for (const auto& bb : fn.blocks)
        for (const auto& inst : bb.insts) n += inst.op == op;
    return n;
}

bool returns_value(const ember::IrFunction& fn, const ember::IrValue& v) {
    for (const auto& bb : fn.blocks)
        for (const auto& inst : bb.insts)
            if (inst.op == ember::IrOp::Return && inst.src_count == 1 &&
                ember::same_ssa_value(inst.srcs[0], v)) return true;
    return false;
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

void test_double_not_cancels_to_identity() {
    auto fn = base_function();
    auto& insts = fn.blocks[0].insts;
    const auto x = ember::IrValue::make_reg(ember::Reg::Rdi, ember::IrType::I64);
    insts.push_back(unary(ember::IrOp::Not,
                          ember::IrValue::make_temp(0, ember::IrType::I64), x));
    insts.push_back(unary(ember::IrOp::Not,
                          ember::IrValue::make_temp(1, ember::IrType::I64),
                          ember::IrValue::make_temp(0, ember::IrType::I64)));
    insts.push_back(ret(ember::IrValue::make_temp(1, ember::IrType::I64)));

    auto result = ember::run_cleanup(fn);
    check(result.has_value(), "cleanup succeeds for double-not test");
    check(count_op(fn, ember::IrOp::Not) == 0,
          "double negation cancels: no Not ops remain");
    check(returns_value(fn, x), "double negation returns the original operand");
}

void test_single_not_is_preserved() {
    auto fn = base_function();
    auto& insts = fn.blocks[0].insts;
    const auto x = ember::IrValue::make_reg(ember::Reg::Rdi, ember::IrType::I64);
    insts.push_back(unary(ember::IrOp::Not,
                          ember::IrValue::make_temp(0, ember::IrType::I64), x));
    insts.push_back(ret(ember::IrValue::make_temp(0, ember::IrType::I64)));

    auto result = ember::run_cleanup(fn);
    check(result.has_value(), "cleanup succeeds for single-not test");
    check(count_op(fn, ember::IrOp::Not) == 1, "a lone Not is never rewritten");
}

void test_xor_chain_cancels_matching_operand() {
    auto fn = base_function();
    auto& insts = fn.blocks[0].insts;
    const auto a = ember::IrValue::make_reg(ember::Reg::Rdi, ember::IrType::I64);
    const auto b = ember::IrValue::make_reg(ember::Reg::Rsi, ember::IrType::I64);
    insts.push_back(binary(ember::IrOp::Xor,
                           ember::IrValue::make_temp(0, ember::IrType::I64), a, b));
    insts.push_back(binary(ember::IrOp::Xor,
                           ember::IrValue::make_temp(1, ember::IrType::I64),
                           ember::IrValue::make_temp(0, ember::IrType::I64), b));
    insts.push_back(ret(ember::IrValue::make_temp(1, ember::IrType::I64)));

    auto result = ember::run_cleanup(fn);
    check(result.has_value(), "cleanup succeeds for xor-cancel test");
    check(count_op(fn, ember::IrOp::Xor) == 0,
          "(a^b)^b cancels: no Xor ops remain");
    check(returns_value(fn, a), "(a^b)^b returns a");
}

void test_xor_chain_mirrored_operand_orders_cancel() {
    auto fn = base_function();
    auto& insts = fn.blocks[0].insts;
    const auto a = ember::IrValue::make_reg(ember::Reg::Rdi, ember::IrType::I64);
    const auto b = ember::IrValue::make_reg(ember::Reg::Rsi, ember::IrType::I64);
    insts.push_back(binary(ember::IrOp::Xor,
                           ember::IrValue::make_temp(0, ember::IrType::I64), b, a));
    insts.push_back(binary(ember::IrOp::Xor,
                           ember::IrValue::make_temp(1, ember::IrType::I64),
                           b, ember::IrValue::make_temp(0, ember::IrType::I64)));
    insts.push_back(ret(ember::IrValue::make_temp(1, ember::IrType::I64)));

    auto result = ember::run_cleanup(fn);
    check(result.has_value(), "cleanup succeeds for mirrored xor-cancel test");
    check(count_op(fn, ember::IrOp::Xor) == 0,
          "(b^(b^a)) cancels: no Xor ops remain");
    check(returns_value(fn, a), "(b^(b^a)) returns a");
}

void test_xor_chain_with_mismatched_operand_is_kept() {
    auto fn = base_function();
    auto& insts = fn.blocks[0].insts;
    const auto c = ember::IrValue::make_reg(ember::Reg::Rdx, ember::IrType::I64);
    insts.push_back(binary(
        ember::IrOp::Xor, ember::IrValue::make_temp(0, ember::IrType::I64),
        ember::IrValue::make_reg(ember::Reg::Rdi, ember::IrType::I64),
        ember::IrValue::make_reg(ember::Reg::Rsi, ember::IrType::I64)));
    insts.push_back(binary(ember::IrOp::Xor,
                           ember::IrValue::make_temp(1, ember::IrType::I64),
                           ember::IrValue::make_temp(0, ember::IrType::I64), c));
    insts.push_back(ret(ember::IrValue::make_temp(1, ember::IrType::I64)));

    auto result = ember::run_cleanup(fn);
    check(result.has_value(), "cleanup succeeds for xor-keep test");
    check(count_op(fn, ember::IrOp::Xor) == 2,
          "(a^b)^c with c != b is never rewritten");
}

void test_add_negate_cancels_to_zero() {
    auto fn = base_function();
    auto& insts = fn.blocks[0].insts;
    const auto x = ember::IrValue::make_reg(ember::Reg::Rdi, ember::IrType::I64);
    const auto n0 = ember::IrValue::make_temp(0, ember::IrType::I64);
    insts.push_back(unary(ember::IrOp::Neg, n0, x));
    insts.push_back(binary(ember::IrOp::Add,
                           ember::IrValue::make_temp(1, ember::IrType::I64),
                           x, n0));
    insts.push_back(ret(ember::IrValue::make_temp(1, ember::IrType::I64)));

    auto result = ember::run_cleanup(fn);
    check(result.has_value(), "cleanup succeeds for add-neg test");
    check(returns_value(fn, ember::IrValue::make_imm(0, ember::IrType::I64)),
          "x + (-x) folds to constant 0");
    check(count_op(fn, ember::IrOp::Neg) == 0 &&
              count_op(fn, ember::IrOp::Add) == 0,
          "x + (-x) removes the negation and the addition");
}

void test_and_all_ones_mask_is_identity() {
    auto fn = base_function();
    auto& insts = fn.blocks[0].insts;
    const auto x = ember::IrValue::make_reg(ember::Reg::Rdi, ember::IrType::I64);
    insts.push_back(binary(ember::IrOp::And,
                           ember::IrValue::make_temp(0, ember::IrType::I64), x,
                           ember::IrValue::make_imm(-1, ember::IrType::I64)));
    insts.push_back(ret(ember::IrValue::make_temp(0, ember::IrType::I64)));

    auto result = ember::run_cleanup(fn);
    check(result.has_value(), "cleanup succeeds for all-ones-and test");
    check(count_op(fn, ember::IrOp::And) == 0,
          "x & ~0 cancels: no And ops remain");
    check(returns_value(fn, x), "x & ~0 returns x");
}

void test_and_partial_mask_is_kept() {
    auto fn = base_function();
    auto& insts = fn.blocks[0].insts;
    const auto x = ember::IrValue::make_reg(ember::Reg::Rdi, ember::IrType::I64);
    insts.push_back(binary(ember::IrOp::And,
                           ember::IrValue::make_temp(0, ember::IrType::I64), x,
                           ember::IrValue::make_imm(0xff, ember::IrType::I64)));
    insts.push_back(ret(ember::IrValue::make_temp(0, ember::IrType::I64)));

    auto result = ember::run_cleanup(fn);
    check(result.has_value(), "cleanup succeeds for partial-mask test");
    check(count_op(fn, ember::IrOp::And) == 1,
          "x & 0xff is never rewritten");
}

}  // namespace

int main() {
    test_forwarding_respects_may_alias_store();
    test_dse_respects_may_alias_load();
    test_dse_keeps_global_across_disjoint_stack_load();
    test_absolute_ranges_alias_across_sign_boundary();
    test_double_not_cancels_to_identity();
    test_single_not_is_preserved();
    test_xor_chain_cancels_matching_operand();
    test_xor_chain_mirrored_operand_orders_cancel();
    test_xor_chain_with_mismatched_operand_is_kept();
    test_add_negate_cancels_to_zero();
    test_and_all_ones_mask_is_identity();
    test_and_partial_mask_is_kept();
    return fails == 0 ? 0 : 1;
}
