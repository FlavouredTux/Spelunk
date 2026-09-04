#include "structurer_fail_common.hpp"

#include <utility>
#include <vector>

namespace {

using namespace ember;

void add_block(IrFunction& fn, addr_t start, BlockKind kind,
               std::vector<addr_t> predecessors,
               std::vector<addr_t> successors,
               std::vector<IrInst> instructions) {
    IrBlock block;
    block.start = start;
    block.end = start + 4;
    block.kind = kind;
    block.predecessors = std::move(predecessors);
    block.successors = std::move(successors);
    block.insts = std::move(instructions);
    fn.block_at[start] = fn.blocks.size();
    fn.blocks.push_back(std::move(block));
}

const Region* find_region(const Region& region, RegionKind kind) {
    if (region.kind == kind) return &region;
    for (const auto& child : region.children) {
        if (!child) continue;
        if (const Region* found = find_region(*child, kind)) return found;
    }
    return nullptr;
}

const Region* terminal_region(const Region& region) {
    const Region* current = &region;
    while (current->kind == RegionKind::Seq && !current->children.empty()) {
        current = current->children.back().get();
    }
    return current;
}

bool contains_block(const Region& region, addr_t address) {
    if (region.kind == RegionKind::Block && region.block_start == address) {
        return true;
    }
    for (const auto& child : region.children) {
        if (child && contains_block(*child, address)) return true;
    }
    return false;
}

std::size_t count_regions(const Region& region, RegionKind kind) {
    std::size_t count = region.kind == kind ? 1u : 0u;
    for (const auto& child : region.children) {
        if (child) count += count_regions(*child, kind);
    }
    return count;
}

std::size_t count_blocks(const Region& region, addr_t address) {
    std::size_t count =
        region.kind == RegionKind::Block && region.block_start == address
            ? 1u : 0u;
    for (const auto& child : region.children) {
        if (child) count += count_blocks(*child, address);
    }
    return count;
}

IrInst make_branch_indirect(IrValue target) {
    IrInst branch;
    branch.op = IrOp::BranchIndirect;
    branch.srcs[0] = target;
    branch.src_count = 1;
    return branch;
}

int test_switch_direct_merge_is_explicit() {
    constexpr addr_t kDispatch = 0x5000;
    constexpr addr_t kCaseOne = 0x5010;
    constexpr addr_t kMerge = 0x5020;
    constexpr addr_t kExit = 0x5030;

    IrFunction fn;
    fn.start = kDispatch;
    fn.end = kExit + 4;
    fn.name = "switch_direct_merge";

    add_block(fn, kDispatch, BlockKind::Switch, {}, {kMerge, kCaseOne}, {});
    auto& dispatch = fn.blocks[fn.block_at[kDispatch]];
    dispatch.case_values = {0, 1};
    dispatch.switch_index = Reg::Eax;
    add_block(fn, kCaseOne, BlockKind::Unconditional, {kDispatch}, {kMerge},
              {make_call_imm(kCaseOne, 0x6000),
               make_branch(kCaseOne + 1, kMerge)});
    add_block(fn, kMerge, BlockKind::Unconditional, {kDispatch, kCaseOne},
              {kExit}, {make_branch(kMerge, kExit)});
    add_block(fn, kExit, BlockKind::Return, {kMerge}, {}, {make_ret(kExit)});

    const Structurer structurer;
    auto structured = structurer.structure(fn);
    check(structured.has_value(), "direct-to-merge switch structures");
    if (!structured) return 1;
    const Region* sw = find_region(*structured->body, RegionKind::Switch);
    check(sw && sw->children.size() == 2,
          "direct-to-merge switch retains both cases");
    if (!sw || sw->children.size() != 2) return 1;
    check(terminal_region(*sw->children[0])->kind == RegionKind::Break,
          "case targeting the merge ends with an explicit break");
    check(!contains_block(*sw->children[0], kCaseOne) &&
              !contains_block(*sw->children[0], kMerge),
          "direct-merge case contains no foreign case or merge body");
    check(contains_block(*sw->children[1], kCaseOne),
          "following case body remains separate from the direct-merge case");
    return 0;
}

int test_switch_direct_phi_return_is_resolved() {
    constexpr addr_t kDispatch = 0x5100;
    constexpr addr_t kCaseOne = 0x5110;
    constexpr addr_t kMerge = 0x5120;
    IrValue result = IrValue::make_temp(0, IrType::I32);

    IrFunction fn;
    fn.start = kDispatch;
    fn.end = kMerge + 4;
    fn.name = "switch_direct_phi_return";
    fn.next_temp_id = 1;

    add_block(fn, kDispatch, BlockKind::Switch, {}, {kMerge, kCaseOne}, {});
    auto& dispatch = fn.blocks[fn.block_at[kDispatch]];
    dispatch.case_values = {0, 1};
    dispatch.switch_index = Reg::Eax;
    add_block(fn, kCaseOne, BlockKind::Unconditional, {kDispatch}, {kMerge},
              {make_branch(kCaseOne, kMerge)});
    IrInst phi = make_phi(result, {
        IrValue::make_imm(20, IrType::I32),
        IrValue::make_imm(10, IrType::I32),
    });
    phi.phi_preds = {kCaseOne, kDispatch};
    add_block(fn, kMerge, BlockKind::Return, {kDispatch, kCaseOne}, {},
              {std::move(phi), make_ret_value(kMerge, result)});

    const Structurer structurer;
    auto structured = structurer.structure(fn);
    check(structured.has_value(), "direct phi-return switch structures");
    if (!structured) return 1;
    const Region* sw = find_region(*structured->body, RegionKind::Switch);
    check(sw && sw->children.size() == 2,
          "direct phi-return switch retains both cases");
    if (!sw || sw->children.size() != 2) return 1;
    const Region* direct_return = terminal_region(*sw->children[0]);
    const Region* other_return = terminal_region(*sw->children[1]);
    check(direct_return->kind == RegionKind::Return &&
              direct_return->condition.kind == IrValueKind::Imm &&
              direct_return->condition.imm == 10,
          "direct switch edge resolves the dispatch Phi operand");
    check(other_return->kind == RegionKind::Return &&
              other_return->condition.kind == IrValueKind::Imm &&
              other_return->condition.imm == 20,
          "ordinary switch edge keeps its own Phi operand");
    check(count_regions(*structured->body, RegionKind::Return) == 2 &&
              count_blocks(*structured->body, kMerge) == 2,
          "consumed switch return merge is not emitted again after the switch");
    return 0;
}

int test_switch_metadata_validation_and_unlabeled_multiway() {
    constexpr addr_t kDispatch = 0x5200;
    constexpr addr_t kFirst = 0x5210;
    constexpr addr_t kSecond = 0x5220;

    IrFunction malformed;
    malformed.start = kDispatch;
    malformed.end = kFirst + 4;
    add_block(malformed, kDispatch, BlockKind::Switch, {}, {kFirst}, {});
    malformed.blocks[0].case_values = {0, 1};
    add_block(malformed, kFirst, BlockKind::Return, {kDispatch}, {},
              {make_ret(kFirst)});
    const Structurer structurer;
    auto rejected = structurer.structure(malformed);
    check(!rejected && rejected.error().kind == ErrorKind::InvalidFormat,
          "mismatched switch case and successor counts are rejected safely");

    IrFunction missing_indirect;
    missing_indirect.start = kDispatch;
    missing_indirect.end = kSecond + 4;
    add_block(missing_indirect, kDispatch, BlockKind::Switch, {},
              {kFirst, kSecond}, {});
    add_block(missing_indirect, kFirst, BlockKind::Return, {kDispatch}, {},
              {make_ret(kFirst)});
    add_block(missing_indirect, kSecond, BlockKind::Return, {kDispatch}, {},
              {make_ret(kSecond)});
    auto missing_indirect_result = structurer.structure(missing_indirect);
    check(!missing_indirect_result &&
              missing_indirect_result.error().kind == ErrorKind::InvalidFormat,
          "unlabeled multiway metadata requires a usable indirect target");

    IrFunction surplus_default;
    surplus_default.start = kDispatch;
    surplus_default.end = kSecond + 4;
    add_block(surplus_default, kDispatch, BlockKind::Switch, {},
              {kFirst, kSecond}, {});
    surplus_default.blocks[0].case_values = {0};
    surplus_default.blocks[0].has_default = false;
    add_block(surplus_default, kFirst, BlockKind::Return, {kDispatch}, {},
              {make_ret(kFirst)});
    add_block(surplus_default, kSecond, BlockKind::Return, {kDispatch}, {},
              {make_ret(kSecond)});
    auto surplus_result = structurer.structure(surplus_default);
    check(!surplus_result &&
              surplus_result.error().kind == ErrorKind::InvalidFormat,
          "surplus switch successors are rejected without a default marker");

    IrFunction missing_default;
    missing_default.start = kDispatch;
    missing_default.end = kFirst + 4;
    add_block(missing_default, kDispatch, BlockKind::Switch, {}, {kFirst}, {});
    missing_default.blocks[0].case_values = {0};
    missing_default.blocks[0].has_default = true;
    add_block(missing_default, kFirst, BlockKind::Return, {kDispatch}, {},
              {make_ret(kFirst)});
    auto missing_default_result = structurer.structure(missing_default);
    check(!missing_default_result &&
              missing_default_result.error().kind == ErrorKind::InvalidFormat,
          "default-marked switches require a separate default successor");

    IrFunction unlabeled;
    unlabeled.start = kDispatch;
    unlabeled.end = kSecond + 4;
    IrValue target = IrValue::make_temp(0, IrType::I64);
    add_block(unlabeled, kDispatch, BlockKind::Switch, {}, {kFirst, kSecond},
              {make_branch_indirect(target)});
    add_block(unlabeled, kFirst, BlockKind::Return, {kDispatch}, {},
              {make_ret(kFirst)});
    add_block(unlabeled, kSecond, BlockKind::Return, {kDispatch}, {},
              {make_ret(kSecond)});
    auto structured = structurer.structure(unlabeled);
    check(structured.has_value(), "unlabeled oracle multiway branch structures");
    if (!structured) return 1;
    const Region* sw = find_region(*structured->body, RegionKind::Switch);
    check(sw && sw->case_values == std::vector<i64>{
                  static_cast<i64>(kFirst), static_cast<i64>(kSecond)},
          "unlabeled multiway branch uses target addresses as case values");
    check(sw && sw->condition.kind == IrValueKind::Temp &&
              sw->condition.temp == target.temp,
          "unlabeled multiway branch retains its indirect target expression");
    check(sw && contains_block(*sw, kFirst) && contains_block(*sw, kSecond),
          "unlabeled multiway branch retains every successor body");
    return 0;
}

int test_post_loop_phi_uses_exit_predecessor() {
    constexpr addr_t kEntry = 0x5300;
    constexpr addr_t kHeader = 0x5310;
    constexpr addr_t kBody = 0x5320;
    constexpr addr_t kExit = 0x5330;
    IrValue result = IrValue::make_temp(0, IrType::I32);

    IrFunction fn;
    fn.start = kEntry;
    fn.end = kExit + 4;
    fn.name = "post_loop_phi";
    fn.next_temp_id = 1;
    add_block(fn, kEntry, BlockKind::Unconditional, {}, {kHeader},
              {make_branch(kEntry, kHeader)});
    add_block(fn, kHeader, BlockKind::Conditional, {kEntry, kBody},
              {kBody, kExit},
              {make_cond_branch(kHeader,
                  IrValue::make_imm(1, IrType::I1), kBody, kExit)});
    add_block(fn, kBody, BlockKind::Unconditional, {kHeader}, {kHeader},
              {make_branch(kBody, kHeader)});
    IrInst phi = make_phi(result, {IrValue::make_imm(42, IrType::I32)});
    phi.phi_preds = {kHeader};
    add_block(fn, kExit, BlockKind::Return, {kHeader}, {},
              {std::move(phi), make_ret_value(kExit, result)});

    const Structurer structurer;
    auto structured = structurer.structure(fn);
    check(structured.has_value(), "loop followed by Phi return structures");
    if (!structured) return 1;
    const Region* returned = find_region(*structured->body, RegionKind::Return);
    check(returned && returned->condition.kind == IrValueKind::Imm &&
              returned->condition.imm == 42,
          "post-loop return resolves through the unique loop-exit predecessor");
    return 0;
}

int test_post_loop_phi_keeps_multi_predecessor_merge() {
    constexpr addr_t kEntry = 0x5400;
    constexpr addr_t kHeader = 0x5410;
    constexpr addr_t kBody = 0x5420;
    constexpr addr_t kExit = 0x5430;
    IrValue result = IrValue::make_temp(0, IrType::I32);

    IrFunction fn;
    fn.start = kEntry;
    fn.end = kExit + 4;
    fn.name = "post_loop_multi_pred_phi";
    fn.next_temp_id = 1;
    add_block(fn, kEntry, BlockKind::Unconditional, {}, {kHeader},
              {make_branch(kEntry, kHeader)});
    add_block(fn, kHeader, BlockKind::Conditional, {kEntry, kBody},
              {kBody, kExit},
              {make_cond_branch(kHeader,
                  IrValue::make_imm(1, IrType::I1), kBody, kExit)});
    add_block(fn, kBody, BlockKind::Unconditional, {kHeader}, {kHeader},
              {make_branch(kBody, kHeader)});
    IrInst phi = make_phi(result, {
        IrValue::make_imm(42, IrType::I32),
        IrValue::make_imm(99, IrType::I32),
    });
    phi.phi_preds = {kHeader, kBody};
    add_block(fn, kExit, BlockKind::Return, {kHeader, kBody}, {},
              {std::move(phi), make_ret_value(kExit, result)});

    const Structurer structurer;
    auto structured = structurer.structure(fn);
    check(structured.has_value(),
          "loop with a multi-predecessor Phi exit structures");
    if (!structured) return 1;
    const Region* returned = terminal_region(*structured->body);
    const bool unresolved = returned &&
        returned->condition.kind == IrValueKind::Temp &&
        returned->condition.temp == result.temp;
    if (!unresolved) {
        std::fprintf(stderr, "Multi-predecessor loop structure:\n%s\n",
                     format_structured(*structured).c_str());
    }
    check(unresolved,
          "multi-predecessor loop exit keeps the Phi unresolved");
    return 0;
}

}  // namespace

int run_structurer_control_flow_tests() {
    int rc = 0;
    rc |= test_switch_direct_merge_is_explicit();
    rc |= test_switch_direct_phi_return_is_resolved();
    rc |= test_switch_metadata_validation_and_unlabeled_multiway();
    rc |= test_post_loop_phi_uses_exit_predecessor();
    rc |= test_post_loop_phi_keeps_multi_predecessor_merge();
    return rc;
}
