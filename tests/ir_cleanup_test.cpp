#include <spelunk/ir/passes.hpp>
#include <spelunk/ir/ssa.hpp>

#include <cstdio>

namespace {

int fails = 0;

void check(bool condition, const char* message) {
    if (condition) return;
    std::fprintf(stderr, "FAIL: %s\n", message);
    ++fails;
}

spelunk::IrInst store(spelunk::IrValue address, spelunk::i64 value) {
    spelunk::IrInst i;
    i.op = spelunk::IrOp::Store;
    i.srcs[0] = address;
    i.srcs[1] = spelunk::IrValue::make_imm(value, spelunk::IrType::I64);
    i.src_count = 2;
    return i;
}

spelunk::IrFunction base_function() {
    spelunk::IrFunction fn;
    fn.start = 0x1000;
    fn.end = 0x1010;
    spelunk::IrBlock block;
    block.start = fn.start;
    block.end = fn.end;
    block.kind = spelunk::BlockKind::Return;
    fn.block_at.emplace(block.start, 0);
    fn.blocks.push_back(std::move(block));
    return fn;
}

// --- helpers for algebraic-identity tests ---------------------------------

spelunk::IrInst unary(spelunk::IrOp op, spelunk::IrValue dst, spelunk::IrValue src) {
    spelunk::IrInst i;
    i.op = op;
    i.dst = std::move(dst);
    i.srcs[0] = std::move(src);
    i.src_count = 1;
    return i;
}

spelunk::IrInst binary(spelunk::IrOp op, spelunk::IrValue dst, spelunk::IrValue lhs,
                     spelunk::IrValue rhs) {
    spelunk::IrInst i;
    i.op = op;
    i.dst = std::move(dst);
    i.srcs[0] = std::move(lhs);
    i.srcs[1] = std::move(rhs);
    i.src_count = 2;
    return i;
}

spelunk::IrInst ret(spelunk::IrValue v) {
    spelunk::IrInst i;
    i.op = spelunk::IrOp::Return;
    i.srcs[0] = std::move(v);
    i.src_count = 1;
    return i;
}

std::size_t count_op(const spelunk::IrFunction& fn, spelunk::IrOp op) {
    std::size_t n = 0;
    for (const auto& bb : fn.blocks)
        for (const auto& inst : bb.insts) n += inst.op == op;
    return n;
}

bool returns_value(const spelunk::IrFunction& fn, const spelunk::IrValue& v) {
    for (const auto& bb : fn.blocks)
        for (const auto& inst : bb.insts)
            if (inst.op == spelunk::IrOp::Return && inst.src_count == 1 &&
                spelunk::same_ssa_value(inst.srcs[0], v)) return true;
    return false;
}

void test_forwarding_respects_may_alias_store() {
    auto fn = base_function();
    auto& insts = fn.blocks[0].insts;
    const auto p = spelunk::IrValue::make_reg(spelunk::Reg::Rdi, spelunk::IrType::I64);
    const auto q = spelunk::IrValue::make_reg(spelunk::Reg::Rsi, spelunk::IrType::I64);
    insts.push_back(store(p, 1));
    insts.push_back(store(q, 2));

    spelunk::IrValue loaded = spelunk::IrValue::make_temp(0, spelunk::IrType::I64);
    spelunk::IrInst load;
    load.op = spelunk::IrOp::Load;
    load.dst = loaded;
    load.srcs[0] = p;
    load.src_count = 1;
    insts.push_back(load);

    spelunk::IrInst ret;
    ret.op = spelunk::IrOp::Return;
    ret.srcs[0] = loaded;
    ret.src_count = 1;
    insts.push_back(ret);

    auto result = spelunk::run_cleanup(fn);
    check(result.has_value(), "cleanup succeeds for forwarding test");
    const auto& out = fn.blocks[0].insts;
    bool returned_one = false;
    for (const auto& i : out) {
        if (i.op == spelunk::IrOp::Return && i.src_count == 1 &&
            i.srcs[0].kind == spelunk::IrValueKind::Imm && i.srcs[0].imm == 1) {
            returned_one = true;
        }
    }
    check(!returned_one, "load is not forwarded across a may-alias store");
}

void test_dse_respects_may_alias_load() {
    auto fn = base_function();
    auto& insts = fn.blocks[0].insts;
    const auto p = spelunk::IrValue::make_reg(spelunk::Reg::Rdi, spelunk::IrType::I64);
    const auto q = spelunk::IrValue::make_reg(spelunk::Reg::Rsi, spelunk::IrType::I64);
    insts.push_back(store(p, 1));

    spelunk::IrValue loaded = spelunk::IrValue::make_temp(0, spelunk::IrType::I64);
    spelunk::IrInst load;
    load.op = spelunk::IrOp::Load;
    load.dst = loaded;
    load.srcs[0] = q;
    load.src_count = 1;
    insts.push_back(load);
    insts.push_back(store(p, 2));

    spelunk::IrInst ret;
    ret.op = spelunk::IrOp::Return;
    ret.srcs[0] = loaded;
    ret.src_count = 1;
    insts.push_back(ret);

    auto result = spelunk::run_cleanup(fn);
    check(result.has_value(), "cleanup succeeds for DSE test");
    std::size_t stores = 0;
    for (const auto& i : fn.blocks[0].insts) stores += i.op == spelunk::IrOp::Store;
    check(stores == 2, "load through a may-alias pointer keeps the earlier store");
}

void test_dse_keeps_global_across_disjoint_stack_load() {
    auto fn = base_function();
    auto& insts = fn.blocks[0].insts;
    const auto global = spelunk::IrValue::make_imm(0x404018, spelunk::IrType::I64);
    const auto stack = spelunk::IrValue::make_reg(spelunk::Reg::Rsp,
                                                spelunk::IrType::I64);
    insts.push_back(store(global, 1));

    const auto loaded = spelunk::IrValue::make_temp(0, spelunk::IrType::I64);
    spelunk::IrInst load;
    load.op = spelunk::IrOp::Load;
    load.dst = loaded;
    load.srcs[0] = stack;
    load.src_count = 1;
    insts.push_back(load);
    insts.push_back(store(global, 2));

    spelunk::IrInst ret;
    ret.op = spelunk::IrOp::Return;
    ret.srcs[0] = loaded;
    ret.src_count = 1;
    insts.push_back(ret);

    auto result = spelunk::run_cleanup(fn);
    check(result.has_value(), "cleanup succeeds for disjoint storage classes");
    std::size_t stores = 0;
    for (const auto& i : fn.blocks[0].insts) stores += i.op == spelunk::IrOp::Store;
    check(stores == 1, "stack load does not block dead global-store removal");
}

void test_absolute_ranges_alias_across_sign_boundary() {
    auto fn = base_function();
    auto& insts = fn.blocks[0].insts;
    const auto before = spelunk::IrValue::make_imm(
        static_cast<spelunk::i64>(0x7ffffffffffffffcull), spelunk::IrType::I64);
    const auto after = spelunk::IrValue::make_imm(
        static_cast<spelunk::i64>(0x8000000000000000ull), spelunk::IrType::I64);
    insts.push_back(store(before, 1));

    const auto loaded = spelunk::IrValue::make_temp(0, spelunk::IrType::I64);
    spelunk::IrInst load;
    load.op = spelunk::IrOp::Load;
    load.dst = loaded;
    load.srcs[0] = after;
    load.src_count = 1;
    insts.push_back(load);
    insts.push_back(store(before, 2));

    spelunk::IrInst ret;
    ret.op = spelunk::IrOp::Return;
    ret.srcs[0] = loaded;
    ret.src_count = 1;
    insts.push_back(ret);

    auto result = spelunk::run_cleanup(fn);
    check(result.has_value(), "cleanup succeeds across absolute sign boundary");
    std::size_t stores = 0;
    for (const auto& i : fn.blocks[0].insts) stores += i.op == spelunk::IrOp::Store;
    check(stores == 2, "overlapping absolute ranges keep the observed store");
}

void test_double_not_cancels_to_identity() {
    auto fn = base_function();
    auto& insts = fn.blocks[0].insts;
    const auto x = spelunk::IrValue::make_reg(spelunk::Reg::Rdi, spelunk::IrType::I64);
    insts.push_back(unary(spelunk::IrOp::Not,
                          spelunk::IrValue::make_temp(0, spelunk::IrType::I64), x));
    insts.push_back(unary(spelunk::IrOp::Not,
                          spelunk::IrValue::make_temp(1, spelunk::IrType::I64),
                          spelunk::IrValue::make_temp(0, spelunk::IrType::I64)));
    insts.push_back(ret(spelunk::IrValue::make_temp(1, spelunk::IrType::I64)));

    auto result = spelunk::run_cleanup(fn);
    check(result.has_value(), "cleanup succeeds for double-not test");
    check(count_op(fn, spelunk::IrOp::Not) == 0,
          "double negation cancels: no Not ops remain");
    check(returns_value(fn, x), "double negation returns the original operand");
}

void test_single_not_is_preserved() {
    auto fn = base_function();
    auto& insts = fn.blocks[0].insts;
    const auto x = spelunk::IrValue::make_reg(spelunk::Reg::Rdi, spelunk::IrType::I64);
    insts.push_back(unary(spelunk::IrOp::Not,
                          spelunk::IrValue::make_temp(0, spelunk::IrType::I64), x));
    insts.push_back(ret(spelunk::IrValue::make_temp(0, spelunk::IrType::I64)));

    auto result = spelunk::run_cleanup(fn);
    check(result.has_value(), "cleanup succeeds for single-not test");
    check(count_op(fn, spelunk::IrOp::Not) == 1, "a lone Not is never rewritten");
}

void test_xor_chain_cancels_matching_operand() {
    auto fn = base_function();
    auto& insts = fn.blocks[0].insts;
    const auto a = spelunk::IrValue::make_reg(spelunk::Reg::Rdi, spelunk::IrType::I64);
    const auto b = spelunk::IrValue::make_reg(spelunk::Reg::Rsi, spelunk::IrType::I64);
    insts.push_back(binary(spelunk::IrOp::Xor,
                           spelunk::IrValue::make_temp(0, spelunk::IrType::I64), a, b));
    insts.push_back(binary(spelunk::IrOp::Xor,
                           spelunk::IrValue::make_temp(1, spelunk::IrType::I64),
                           spelunk::IrValue::make_temp(0, spelunk::IrType::I64), b));
    insts.push_back(ret(spelunk::IrValue::make_temp(1, spelunk::IrType::I64)));

    auto result = spelunk::run_cleanup(fn);
    check(result.has_value(), "cleanup succeeds for xor-cancel test");
    check(count_op(fn, spelunk::IrOp::Xor) == 0,
          "(a^b)^b cancels: no Xor ops remain");
    check(returns_value(fn, a), "(a^b)^b returns a");
}

void test_xor_chain_mirrored_operand_orders_cancel() {
    auto fn = base_function();
    auto& insts = fn.blocks[0].insts;
    const auto a = spelunk::IrValue::make_reg(spelunk::Reg::Rdi, spelunk::IrType::I64);
    const auto b = spelunk::IrValue::make_reg(spelunk::Reg::Rsi, spelunk::IrType::I64);
    insts.push_back(binary(spelunk::IrOp::Xor,
                           spelunk::IrValue::make_temp(0, spelunk::IrType::I64), b, a));
    insts.push_back(binary(spelunk::IrOp::Xor,
                           spelunk::IrValue::make_temp(1, spelunk::IrType::I64),
                           b, spelunk::IrValue::make_temp(0, spelunk::IrType::I64)));
    insts.push_back(ret(spelunk::IrValue::make_temp(1, spelunk::IrType::I64)));

    auto result = spelunk::run_cleanup(fn);
    check(result.has_value(), "cleanup succeeds for mirrored xor-cancel test");
    check(count_op(fn, spelunk::IrOp::Xor) == 0,
          "(b^(b^a)) cancels: no Xor ops remain");
    check(returns_value(fn, a), "(b^(b^a)) returns a");
}

void test_xor_chain_with_mismatched_operand_is_kept() {
    auto fn = base_function();
    auto& insts = fn.blocks[0].insts;
    const auto c = spelunk::IrValue::make_reg(spelunk::Reg::Rdx, spelunk::IrType::I64);
    insts.push_back(binary(
        spelunk::IrOp::Xor, spelunk::IrValue::make_temp(0, spelunk::IrType::I64),
        spelunk::IrValue::make_reg(spelunk::Reg::Rdi, spelunk::IrType::I64),
        spelunk::IrValue::make_reg(spelunk::Reg::Rsi, spelunk::IrType::I64)));
    insts.push_back(binary(spelunk::IrOp::Xor,
                           spelunk::IrValue::make_temp(1, spelunk::IrType::I64),
                           spelunk::IrValue::make_temp(0, spelunk::IrType::I64), c));
    insts.push_back(ret(spelunk::IrValue::make_temp(1, spelunk::IrType::I64)));

    auto result = spelunk::run_cleanup(fn);
    check(result.has_value(), "cleanup succeeds for xor-keep test");
    check(count_op(fn, spelunk::IrOp::Xor) == 2,
          "(a^b)^c with c != b is never rewritten");
}

void test_add_negate_cancels_to_zero() {
    auto fn = base_function();
    auto& insts = fn.blocks[0].insts;
    const auto x = spelunk::IrValue::make_reg(spelunk::Reg::Rdi, spelunk::IrType::I64);
    const auto n0 = spelunk::IrValue::make_temp(0, spelunk::IrType::I64);
    insts.push_back(unary(spelunk::IrOp::Neg, n0, x));
    insts.push_back(binary(spelunk::IrOp::Add,
                           spelunk::IrValue::make_temp(1, spelunk::IrType::I64),
                           x, n0));
    insts.push_back(ret(spelunk::IrValue::make_temp(1, spelunk::IrType::I64)));

    auto result = spelunk::run_cleanup(fn);
    check(result.has_value(), "cleanup succeeds for add-neg test");
    check(returns_value(fn, spelunk::IrValue::make_imm(0, spelunk::IrType::I64)),
          "x + (-x) folds to constant 0");
    check(count_op(fn, spelunk::IrOp::Neg) == 0 &&
              count_op(fn, spelunk::IrOp::Add) == 0,
          "x + (-x) removes the negation and the addition");
}

void test_and_all_ones_mask_is_identity() {
    auto fn = base_function();
    auto& insts = fn.blocks[0].insts;
    const auto x = spelunk::IrValue::make_reg(spelunk::Reg::Rdi, spelunk::IrType::I64);
    insts.push_back(binary(spelunk::IrOp::And,
                           spelunk::IrValue::make_temp(0, spelunk::IrType::I64), x,
                           spelunk::IrValue::make_imm(-1, spelunk::IrType::I64)));
    insts.push_back(ret(spelunk::IrValue::make_temp(0, spelunk::IrType::I64)));

    auto result = spelunk::run_cleanup(fn);
    check(result.has_value(), "cleanup succeeds for all-ones-and test");
    check(count_op(fn, spelunk::IrOp::And) == 0,
          "x & ~0 cancels: no And ops remain");
    check(returns_value(fn, x), "x & ~0 returns x");
}

void test_and_partial_mask_is_kept() {
    auto fn = base_function();
    auto& insts = fn.blocks[0].insts;
    const auto x = spelunk::IrValue::make_reg(spelunk::Reg::Rdi, spelunk::IrType::I64);
    insts.push_back(binary(spelunk::IrOp::And,
                           spelunk::IrValue::make_temp(0, spelunk::IrType::I64), x,
                           spelunk::IrValue::make_imm(0xff, spelunk::IrType::I64)));
    insts.push_back(ret(spelunk::IrValue::make_temp(0, spelunk::IrType::I64)));

    auto result = spelunk::run_cleanup(fn);
    check(result.has_value(), "cleanup succeeds for partial-mask test");
    check(count_op(fn, spelunk::IrOp::And) == 1,
          "x & 0xff is never rewritten");
}

void test_float_folding_preserves_operations() {
    using namespace spelunk;
    for (const auto type : {IrType::F32, IrType::F64, IrType::V2F32}) {
        const auto x = IrValue::make_reg(Reg::Xmm0, type);
        const auto zero = IrValue::make_imm(0, type);
        const auto bit_one = IrValue::make_imm(1, type);
        const auto result = IrValue::make_temp(0, type);
        for (const auto op : {IrOp::Add, IrOp::Sub, IrOp::Mul, IrOp::Div}) {
            for (const auto rhs : {x, zero, bit_one}) {
                auto fn = base_function();
                fn.next_temp_id = 1;
                fn.blocks[0].insts = {binary(op, result, x, rhs), ret(result)};
                check(run_cleanup(fn).has_value(), "floating cleanup succeeds");
                check(count_op(fn, op) == 1, "integer identities do not rewrite floating arithmetic");
            }
        }
        for (const auto op : {IrOp::Add, IrOp::Sub, IrOp::Mul, IrOp::CmpEq, IrOp::CmpUlt}) {
            auto fn = base_function();
            fn.next_temp_id = 1;
            const auto dst = IrValue::make_temp(0,
                op == IrOp::CmpEq || op == IrOp::CmpUlt ? IrType::I1 : type);
            fn.blocks[0].insts = {binary(op, dst, bit_one, zero), ret(dst)};
            check(run_cleanup(fn).has_value(), "floating constant cleanup succeeds");
            check(count_op(fn, op) == 1, "FP bit patterns are not integer constants");
        }
        auto fn = base_function();
        fn.next_temp_id = 2;
        const auto negative = IrValue::make_temp(1, type);
        fn.blocks[0].insts = {unary(IrOp::Neg, negative, x),
                             binary(IrOp::Add, result, x, negative), ret(result)};
        check(run_cleanup(fn).has_value(), "floating add-negate cleanup succeeds");
        check(count_op(fn, IrOp::Add) == 1, "x + -x retains floating NaN behavior");
        fn = base_function();
        fn.next_temp_id = 1;
        fn.blocks[0].insts = {unary(IrOp::Neg, result, bit_one), ret(result)};
        check(run_cleanup(fn).has_value(), "floating constant negation cleanup succeeds");
        check(count_op(fn, IrOp::Neg) == 1, "FP negation does not negate the integer bit pattern");
    }
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
    test_float_folding_preserves_operations();
    return fails == 0 ? 0 : 1;
}
