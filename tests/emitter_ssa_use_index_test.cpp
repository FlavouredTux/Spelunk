// Focused coverage for the emitter's private SSA definition/use policies.
#include "emitter_ssa_use_index.hpp"

#include <algorithm>
#include <cstdio>
#include <initializer_list>
#include <span>
#include <utility>

namespace {

using spelunk::Flag;
using spelunk::IrBlock;
using spelunk::IrFunction;
using spelunk::IrInst;
using spelunk::IrOp;
using spelunk::IrType;
using spelunk::IrValue;
using spelunk::SsaKey;
using spelunk::emit::SsaUseIndex;

int failures = 0;

void check(bool condition, const char* context) {
    if (condition) return;
    std::fprintf(stderr, "FAIL: %s\n", context);
    ++failures;
}

void check_count(spelunk::u32 actual, spelunk::u32 expected,
                 const char* context) {
    if (actual == expected) return;
    std::fprintf(stderr, "FAIL: %s (got %u, expected %u)\n",
                 context, actual, expected);
    ++failures;
}

void check_positions(std::span<const SsaUseIndex::Position> actual,
                     std::initializer_list<SsaUseIndex::Position> expected,
                     const char* context) {
    if (std::ranges::equal(actual, expected)) return;
    std::fprintf(stderr, "FAIL: %s (got %zu positions, expected %zu)\n",
                 context, actual.size(), expected.size());
    ++failures;
}

[[nodiscard]] IrValue temp(spelunk::u32 id) {
    return IrValue::make_temp(id, IrType::I64);
}

[[nodiscard]] SsaKey key_of(const IrValue& value) {
    return *spelunk::ssa_key(value);
}

[[nodiscard]] IrInst instruction(IrOp op, IrValue dst,
                                 std::initializer_list<IrValue> operands = {}) {
    IrInst inst;
    inst.op = op;
    inst.dst = dst;
    inst.src_count = static_cast<spelunk::u8>(operands.size());
    std::ranges::copy(operands, inst.srcs.begin());
    return inst;
}

[[nodiscard]] IrInst barrier(const char* name, IrValue operand) {
    IrInst inst = instruction(IrOp::Intrinsic, {}, {operand});
    inst.name = name;
    return inst;
}

void test_definitions_and_last_positions() {
    const IrValue value = temp(7);
    const IrValue use_only = temp(3);
    IrFunction fn;
    fn.blocks.resize(2);
    fn.blocks[0].insts.push_back(instruction(
        IrOp::Assign, value, {use_only}));
    fn.blocks[1].insts.push_back(instruction(
        IrOp::Assign, value, {IrValue::make_imm(2, IrType::I64)}));

    SsaUseIndex index;
    index.scan(fn);
    const SsaKey key = key_of(value);
    check(index.definition(key) == &fn.blocks[1].insts[0],
          "duplicate definitions keep the last scanned instruction");
    check(index.definition_position(key) == SsaUseIndex::Position{1, 0},
          "duplicate definitions keep the last scanned position");

    std::size_t visits = 0;
    const IrInst* visited = nullptr;
    index.for_each_definition([&](const SsaKey& visited_key,
                                  const IrInst* definition) {
        check(visited_key == key, "definition visitor reports the key");
        ++visits;
        visited = definition;
    });
    check(visits == 1 && visited == &fn.blocks[1].insts[0],
          "definition visitor skips use-only entries and exposes one "
          "last-definition record per key");
}

void test_incremental_observation_order() {
    const IrValue first_value = temp(30);
    const IrValue later_value = temp(31);
    IrInst first = instruction(IrOp::Assign, first_value, {later_value});
    IrInst later = instruction(
        IrOp::Assign, later_value, {IrValue::make_imm(7, IrType::I64)});

    SsaUseIndex index;
    index.reset();
    index.observe(first, {0, 0});
    check(index.definition(key_of(first_value)) == &first,
          "incremental scan exposes the current definition");
    check(index.definition(key_of(later_value)) == nullptr,
          "incremental scan does not expose a forward definition");
    check_count(index.semantic_use_count(key_of(later_value)), 1,
                "incremental scan records uses before a later definition");

    index.observe(later, {0, 1});
    check(index.definition(key_of(later_value)) == &later,
          "incremental scan exposes a definition once observed");
}

void test_literals_are_not_indexed() {
    const IrValue first_literal = IrValue::make_imm(7, IrType::I64);
    const IrValue equal_literal = IrValue::make_imm(7, IrType::I64);
    const SsaKey literal_key = key_of(first_literal);

    IrFunction fn;
    fn.blocks.resize(1);
    fn.blocks[0].insts.push_back(instruction(
        IrOp::Add, temp(40), {first_literal, equal_literal}));
    fn.blocks[0].insts.push_back(instruction(
        IrOp::Assign, temp(41), {equal_literal}));

    SsaUseIndex index;
    index.scan(fn);
    index.scan_visible(fn, {});

    check(index.definition(literal_key) == nullptr &&
              !index.definition_position(literal_key),
          "literal operands do not create definition entries");
    check_count(index.syntactic_use_count(literal_key), 0,
                "equal literals do not share a syntactic-use entry");
    check_count(index.semantic_use_count(literal_key), 0,
                "equal literals do not share a semantic-use entry");
    check_count(index.visible_use_count(literal_key), 0,
                "equal literals do not share a visible-use entry");
    check(index.syntactic_user_positions(literal_key).empty() &&
              index.semantic_user_positions(literal_key).empty() &&
              index.visible_user_positions(literal_key).empty(),
          "literal operands do not retain user positions");
}

void test_use_policies_and_scan_order() {
    const IrValue value = temp(1);
    IrFunction fn;
    fn.blocks.resize(1);
    auto& insts = fn.blocks[0].insts;
    insts.push_back(instruction(
        IrOp::Assign, value, {IrValue::make_imm(1, IrType::I64)}));
    insts.push_back(instruction(IrOp::Add, temp(2), {value, value}));

    IrInst phi = instruction(IrOp::Phi, temp(3));
    phi.phi_operands = {value, value};
    insts.push_back(std::move(phi));
    insts.push_back(barrier("call.args.1", value));
    insts.push_back(barrier("call.fp_args.1", value));
    insts.push_back(instruction(IrOp::And, temp(4), {value}));
    insts.push_back(instruction(IrOp::Sub, temp(5), {value}));

    const SsaKey key = key_of(value);
    SsaUseIndex index;
    index.scan(fn);

    check_count(index.syntactic_use_count(key), 8,
                "syntactic count includes repeated, Phi, and both barriers");
    check_count(index.semantic_use_count(key), 6,
                "semantic count excludes both call argument barriers");
    check_positions(index.syntactic_user_positions(key),
                    {{0, 1}, {0, 1}, {0, 2}, {0, 2},
                     {0, 3}, {0, 4}, {0, 5}, {0, 6}},
                    "syntactic positions retain hidden call argument packs");
    check_positions(index.semantic_user_positions(key),
                    {{0, 1}, {0, 1}, {0, 2}, {0, 2}, {0, 5}, {0, 6}},
                    "semantic user positions retain occurrences and scan order");
    check_count(index.visible_use_count(key), 0,
                "visible phase is empty until hidden analysis finishes");
    check(index.visible_user_positions(key).empty(),
          "visible positions are empty before the second phase");

    index.scan_visible(fn, {{0, 5}});
    check_count(index.visible_use_count(key), 3,
                "visible count excludes barriers, Phi operands, and hidden users");
    check_positions(index.visible_user_positions(key),
                    {{0, 1}, {0, 1}, {0, 6}},
                    "visible positions retain repeated occurrences and scan order");
    check_count(index.semantic_use_count(key), 6,
                "hidden filtering does not alter semantic counts");

    index.scan_visible(fn, {});
    check_count(index.visible_use_count(key), 4,
                "visible phase can be recomputed after hidden state changes");
}

void test_flag_only_visible_users() {
    const IrValue flag_only = temp(10);
    const IrValue mixed = temp(11);
    IrFunction fn;
    fn.blocks.resize(1);
    auto& insts = fn.blocks[0].insts;
    insts.push_back(instruction(
        IrOp::Assign, flag_only, {IrValue::make_imm(1, IrType::I64)}));
    insts.push_back(instruction(
        IrOp::Assign, mixed, {IrValue::make_imm(2, IrType::I64)}));
    insts.push_back(instruction(
        IrOp::Assign, IrValue::make_flag(Flag::Zf), {flag_only}));
    insts.push_back(instruction(
        IrOp::Assign, IrValue::make_flag(Flag::Sf), {flag_only}));
    insts.push_back(instruction(
        IrOp::Assign, IrValue::make_flag(Flag::Cf), {mixed}));
    insts.push_back(instruction(IrOp::Add, temp(12), {mixed}));

    SsaUseIndex index;
    index.scan(fn);
    index.scan_visible(fn, {});
    check(index.every_visible_use_is_flag_assign(key_of(flag_only)),
          "multiple flag assignments are recognized as flag-only users");
    check(!index.every_visible_use_is_flag_assign(key_of(mixed)),
          "a visible general user rejects flag-only classification");

    index.scan_visible(fn, {{0, 5}});
    check(index.every_visible_use_is_flag_assign(key_of(mixed)),
          "hidden general users do not affect visible flag-only classification");
    check(!index.every_visible_use_is_flag_assign(key_of(temp(99))),
          "a value with no visible users is not flag-only");
}

void test_empty_queries_and_reset_reuse() {
    const IrValue old_value = temp(20);
    const IrValue new_value = temp(21);
    const SsaKey old_key = key_of(old_value);
    const SsaKey new_key = key_of(new_value);
    const SsaKey missing = key_of(temp(999));

    SsaUseIndex index;
    check(index.definition(missing) == nullptr,
          "empty definition query returns null");
    check(!index.definition_position(missing),
          "empty definition-position query returns nullopt");
    check_count(index.syntactic_use_count(missing), 0,
                "empty syntactic count is zero");
    check_count(index.semantic_use_count(missing), 0,
                "empty semantic count is zero");
    check_count(index.visible_use_count(missing), 0,
                "empty visible count is zero");
    check(index.syntactic_user_positions(missing).empty() &&
              index.semantic_user_positions(missing).empty() &&
              index.visible_user_positions(missing).empty(),
          "empty user-position queries return empty spans");

    IrFunction first;
    first.blocks.resize(1);
    first.blocks[0].insts.push_back(instruction(
        IrOp::Assign, old_value, {IrValue::make_imm(1, IrType::I64)}));
    first.blocks[0].insts.push_back(
        instruction(IrOp::Add, temp(22), {old_value}));
    index.scan(first);
    index.scan_visible(first, {});
    check(index.definition(old_key) != nullptr &&
              index.visible_use_count(old_key) == 1,
          "first scan populates the index");

    IrFunction second;
    second.blocks.resize(1);
    second.blocks[0].insts.push_back(instruction(
        IrOp::Assign, new_value, {IrValue::make_imm(2, IrType::I64)}));
    index.scan(second);
    check(index.definition(old_key) == nullptr &&
              index.semantic_use_count(old_key) == 0 &&
              index.visible_use_count(old_key) == 0 &&
              index.visible_user_positions(old_key).empty(),
          "rescanning clears definitions, counts, positions, and visibility");
    check(index.definition(new_key) == &second.blocks[0].insts[0],
          "rescanning records the replacement function");

    index.reset();
    check(index.definition(new_key) == nullptr &&
              !index.definition_position(new_key),
          "explicit reset clears reusable index state");
}

}  // namespace

int main() {
    test_definitions_and_last_positions();
    test_incremental_observation_order();
    test_literals_are_not_indexed();
    test_use_policies_and_scan_order();
    test_flag_only_visible_users();
    test_empty_queries_and_reset_reuse();
    return failures == 0 ? 0 : 1;
}
