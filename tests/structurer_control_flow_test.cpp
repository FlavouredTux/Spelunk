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

bool is_loop_region(RegionKind kind) {
    return kind == RegionKind::While || kind == RegionKind::DoWhile ||
           kind == RegionKind::For || kind == RegionKind::Loop;
}

const Region* find_loop_with_header(const Region& region, addr_t header) {
    if (is_loop_region(region.kind) && !region.children.empty() &&
        region.children.front() &&
        region.children.front()->kind == RegionKind::Block &&
        region.children.front()->block_start == header) {
        return &region;
    }
    for (const auto& child : region.children) {
        if (!child) continue;
        if (const Region* found = find_loop_with_header(*child, header)) {
            return found;
        }
    }
    return nullptr;
}

bool contains_goto_to(const Region& region, addr_t target) {
    if (region.kind == RegionKind::Goto && region.target == target) return true;
    for (const auto& child : region.children) {
        if (child && contains_goto_to(*child, target)) return true;
    }
    return false;
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

int test_nested_loop_outer_targets_remain_explicit() {
    constexpr addr_t kEntry = 0x6000;
    constexpr addr_t kOuterHeader = 0x6010;
    constexpr addr_t kInnerHeader = 0x6020;
    constexpr addr_t kOuterContinue = 0x6030;
    constexpr addr_t kInnerTail = 0x6040;
    constexpr addr_t kAfterInner = 0x6050;
    constexpr addr_t kOuterExit = 0x6060;
    constexpr addr_t kFinal = 0x6070;
    const IrValue condition = IrValue::make_temp(0, IrType::I1);

    IrFunction fn;
    fn.start = kEntry;
    fn.end = kFinal + 4;
    fn.name = "nested_loop_outer_targets";
    fn.next_temp_id = 1;
    add_block(fn, kEntry, BlockKind::Unconditional, {}, {kOuterHeader},
              {make_branch(kEntry, kOuterHeader)});
    add_block(fn, kOuterHeader, BlockKind::Conditional,
              {kEntry, kOuterContinue, kAfterInner},
              {kInnerHeader, kOuterExit},
              {make_cond_branch(kOuterHeader, condition,
                                kInnerHeader, kOuterExit)});
    add_block(fn, kInnerHeader, BlockKind::Conditional,
              {kOuterHeader, kInnerTail},
              {kOuterContinue, kAfterInner},
              {make_cond_branch(kInnerHeader, condition,
                                kOuterContinue, kAfterInner)});
    add_block(fn, kOuterContinue, BlockKind::Conditional, {kInnerHeader},
              {kOuterHeader, kInnerTail},
              {make_cond_branch(kOuterContinue, condition,
                                kOuterHeader, kInnerTail)});
    add_block(fn, kInnerTail, BlockKind::Conditional, {kOuterContinue},
              {kInnerHeader, kOuterExit},
              {make_cond_branch(kInnerTail, condition,
                                kInnerHeader, kOuterExit)});
    add_block(fn, kAfterInner, BlockKind::Unconditional, {kInnerHeader},
              {kOuterHeader}, {make_branch(kAfterInner, kOuterHeader)});
    add_block(fn, kOuterExit, BlockKind::Unconditional,
              {kOuterHeader, kInnerTail}, {kFinal},
              {make_branch(kOuterExit, kFinal)});
    add_block(fn, kFinal, BlockKind::Return, {kOuterExit}, {},
              {make_ret(kFinal)});

    const Structurer structurer;
    auto structured = structurer.structure(fn);
    check(structured.has_value(), "nested loop with outer targets structures");
    if (!structured) return 1;
    const Region* inner = find_loop_with_header(*structured->body, kInnerHeader);
    check(inner && contains_goto_to(*inner, kOuterHeader),
          "inner edge to outer header remains an explicit goto");
    check(inner && contains_goto_to(*inner, kOuterExit),
          "inner edge to outer exit remains an explicit goto");
    return 0;
}

int test_nested_loops_preserve_shared_exit_owner() {
    constexpr addr_t kEntry = 0x6100;
    constexpr addr_t kOuterHeader = 0x6110;
    constexpr addr_t kInnerHeader = 0x6120;
    constexpr addr_t kBody = 0x6130;
    constexpr addr_t kExit = 0x6140;
    const IrValue condition = IrValue::make_temp(0, IrType::I1);

    IrFunction fn;
    fn.start = kEntry;
    fn.end = kExit + 4;
    fn.name = "nested_loop_shared_exit";
    fn.next_temp_id = 1;
    add_block(fn, kEntry, BlockKind::Unconditional, {}, {kOuterHeader},
              {make_branch(kEntry, kOuterHeader)});
    add_block(fn, kOuterHeader, BlockKind::Conditional, {kEntry, kBody},
              {kInnerHeader, kExit},
              {make_cond_branch(kOuterHeader, condition,
                                kInnerHeader, kExit)});
    add_block(fn, kInnerHeader, BlockKind::Conditional,
              {kOuterHeader, kBody}, {kBody, kExit},
              {make_cond_branch(kInnerHeader, condition, kBody, kExit)});
    add_block(fn, kBody, BlockKind::Conditional, {kInnerHeader},
              {kInnerHeader, kOuterHeader},
              {make_cond_branch(kBody, condition,
                                kInnerHeader, kOuterHeader)});
    add_block(fn, kExit, BlockKind::Return,
              {kOuterHeader, kInnerHeader}, {}, {make_ret(kExit)});

    const Structurer structurer;
    auto structured = structurer.structure(fn);
    check(structured.has_value(), "nested loops with a shared exit structure");
    if (!structured) return 1;
    const Region* outer = find_loop_with_header(*structured->body, kOuterHeader);
    const Region* inner = find_loop_with_header(*structured->body, kInnerHeader);
    check(inner && contains_goto_to(*inner, kOuterHeader),
          "inner edge to the outer header is not an inner continue");
    check(outer && !contains_block(*outer, kExit) &&
              count_blocks(*structured->body, kExit) == 1,
          "inner loop pop preserves the outer loop's shared exit owner");
    return 0;
}

int test_loop_exit_inside_switch_remains_targeted() {
    constexpr addr_t kEntry = 0x6180;
    constexpr addr_t kHeader = 0x6190;
    constexpr addr_t kSwitch = 0x61a0;
    constexpr addr_t kLatch = 0x61b0;
    constexpr addr_t kExit = 0x61c0;
    constexpr addr_t kCaseReturn = 0x61d0;
    constexpr addr_t kFinal = 0x61e0;
    const IrValue condition = IrValue::make_temp(0, IrType::I1);

    IrFunction fn;
    fn.start = kEntry;
    fn.end = kFinal + 4;
    fn.name = "loop_exit_inside_switch";
    fn.next_temp_id = 1;
    add_block(fn, kEntry, BlockKind::Unconditional, {}, {kHeader},
              {make_branch(kEntry, kHeader)});
    add_block(fn, kHeader, BlockKind::Conditional, {kEntry, kLatch},
              {kSwitch, kExit},
              {make_cond_branch(kHeader, condition, kSwitch, kExit)});
    add_block(fn, kSwitch, BlockKind::Switch, {kHeader},
              {kExit, kCaseReturn, kLatch}, {});
    auto& dispatch = fn.blocks[fn.block_at[kSwitch]];
    dispatch.case_values = {0, 1, 2};
    dispatch.switch_index = Reg::Eax;
    add_block(fn, kLatch, BlockKind::Unconditional, {kSwitch}, {kHeader},
              {make_branch(kLatch, kHeader)});
    add_block(fn, kExit, BlockKind::Unconditional, {kHeader, kSwitch},
              {kFinal}, {make_branch(kExit, kFinal)});
    add_block(fn, kCaseReturn, BlockKind::Return, {kSwitch}, {},
              {make_ret(kCaseReturn)});
    add_block(fn, kFinal, BlockKind::Return, {kExit}, {}, {make_ret(kFinal)});

    const Structurer structurer;
    auto structured = structurer.structure(fn);
    check(structured.has_value(), "loop containing an exit switch structures");
    if (!structured) return 1;
    const Region* loop = find_loop_with_header(*structured->body, kHeader);
    const Region* sw = loop ? find_region(*loop, RegionKind::Switch) : nullptr;
    check(sw && contains_goto_to(*sw, kExit),
          "switch case loop exit remains a goto instead of switch break");
    return 0;
}

int test_for_update_requires_one_direct_latch() {
    const auto make_loop = [](bool conditional_latch, bool multiple_latches) {
        constexpr addr_t kEntry = 0x6200;
        constexpr addr_t kHeader = 0x6210;
        constexpr addr_t kLatch = 0x6220;
        constexpr addr_t kBody = 0x6230;
        constexpr addr_t kExit = 0x6240;
        constexpr addr_t kSecondExit = 0x6250;
        const IrValue condition = IrValue::make_temp(0, IrType::I1);

        IrFunction fn;
        fn.start = kEntry;
        fn.end = (conditional_latch ? kSecondExit : kExit) + 4;
        fn.name = multiple_latches ? "for_multiple_latches"
            : (conditional_latch ? "for_conditional_latch"
                                 : "for_direct_latch");
        fn.next_temp_id = 1;
        add_block(fn, kEntry, BlockKind::Unconditional, {}, {kHeader},
                  {make_branch(kEntry, kHeader)});
        add_block(fn, kHeader, BlockKind::Conditional,
                  multiple_latches ? std::vector<addr_t>{kEntry, kLatch, kBody}
                                   : std::vector<addr_t>{kEntry, kLatch},
                  {kBody, kExit},
                  {make_cond_branch(kHeader, condition, kBody, kExit)});
        add_block(fn, kLatch, conditional_latch ? BlockKind::Conditional
                                                : BlockKind::Unconditional,
                  {kBody},
                  conditional_latch
                      ? std::vector<addr_t>{kHeader, kSecondExit}
                      : std::vector<addr_t>{kHeader},
                  {make_store(IrValue::make_imm(0x7000, IrType::I64),
                              IrValue::make_imm(1, IrType::I32)),
                   conditional_latch
                       ? make_cond_branch(kLatch, condition,
                                          kHeader, kSecondExit)
                       : make_branch(kLatch, kHeader)});
        add_block(fn, kBody, multiple_latches ? BlockKind::Conditional
                                              : BlockKind::Unconditional,
                  {kHeader},
                  multiple_latches ? std::vector<addr_t>{kLatch, kHeader}
                                   : std::vector<addr_t>{kLatch},
                  {multiple_latches
                       ? make_cond_branch(kBody, condition, kLatch, kHeader)
                       : make_branch(kBody, kLatch)});
        add_block(fn, kExit, BlockKind::Return, {kHeader}, {},
                  {make_ret(kExit)});
        if (conditional_latch) {
            add_block(fn, kSecondExit, BlockKind::Return, {kLatch}, {},
                      {make_ret(kSecondExit)});
        }
        return fn;
    };

    const Structurer structurer;
    IrFunction direct_fn = make_loop(false, false);
    auto direct = structurer.structure(direct_fn);
    check(direct.has_value(), "single-direct-latch loop structures");
    if (!direct) return 1;
    const Region* direct_loop = find_loop_with_header(*direct->body, 0x6210);
    check(direct_loop && direct_loop->kind == RegionKind::For &&
              direct_loop->has_update,
          "single direct latch store remains eligible as a for update");

    IrFunction conditional_fn = make_loop(true, false);
    auto conditional = structurer.structure(conditional_fn);
    check(conditional.has_value(), "conditional-latch loop structures");
    if (!conditional) return 1;
    const Region* conditional_loop =
        find_loop_with_header(*conditional->body, 0x6210);
    check(conditional_loop && conditional_loop->kind == RegionKind::While &&
              !conditional_loop->has_update,
          "conditional latch store is not hoisted into a for update");

    IrFunction multiple_fn = make_loop(false, true);
    auto multiple = structurer.structure(multiple_fn);
    check(multiple.has_value(), "multi-latch loop structures");
    if (!multiple) return 1;
    const Region* multiple_loop = find_loop_with_header(*multiple->body, 0x6210);
    check(multiple_loop && multiple_loop->kind == RegionKind::While &&
              !multiple_loop->has_update,
          "one latch's store is not hoisted across another back edge");
    return 0;
}

int test_single_conditional_latch_is_do_while() {
    constexpr addr_t kEntry = 0x6300;
    constexpr addr_t kHeader = 0x6310;
    constexpr addr_t kTail = 0x6320;
    constexpr addr_t kExit = 0x6330;
    const IrValue condition = IrValue::make_temp(0, IrType::I1);

    IrFunction fn;
    fn.start = kEntry;
    fn.end = kExit + 4;
    fn.name = "single_do_while_latch";
    fn.next_temp_id = 1;
    add_block(fn, kEntry, BlockKind::Unconditional, {}, {kHeader},
              {make_branch(kEntry, kHeader)});
    add_block(fn, kHeader, BlockKind::Unconditional, {kEntry, kTail}, {kTail},
              {make_branch(kHeader, kTail)});
    add_block(fn, kTail, BlockKind::Conditional, {kHeader}, {kHeader, kExit},
              {make_cond_branch(kTail, condition, kHeader, kExit)});
    add_block(fn, kExit, BlockKind::Return, {kTail}, {}, {make_ret(kExit)});

    const Structurer structurer;
    auto structured = structurer.structure(fn);
    check(structured.has_value(), "single-tail do-while structures");
    if (!structured) return 1;
    const Region* loop = find_loop_with_header(*structured->body, kHeader);
    check(loop && loop->kind == RegionKind::DoWhile &&
              contains_block(*loop, kTail),
          "one conditional tail remains eligible for do-while");
    return 0;
}

int test_do_while_requires_sole_exiting_backedge() {
    const auto make_extra_latch = [] {
        constexpr addr_t kEntry = 0x6500;
        constexpr addr_t kHeader = 0x6510;
        constexpr addr_t kDirectLatch = 0x6520;
        constexpr addr_t kConditionalTail = 0x6530;
        constexpr addr_t kExit = 0x6540;
        constexpr addr_t kFinal = 0x6550;
        const IrValue condition = IrValue::make_temp(0, IrType::I1);

        IrFunction fn;
        fn.start = kEntry;
        fn.end = kFinal + 4;
        fn.name = "do_while_extra_latch";
        fn.next_temp_id = 1;
        add_block(fn, kEntry, BlockKind::Unconditional, {}, {kHeader},
                  {make_branch(kEntry, kHeader)});
        add_block(fn, kHeader, BlockKind::Conditional,
                  {kEntry, kDirectLatch, kConditionalTail},
                  {kDirectLatch, kConditionalTail},
                  {make_cond_branch(kHeader, condition,
                                    kDirectLatch, kConditionalTail)});
        add_block(fn, kDirectLatch, BlockKind::Unconditional, {kHeader},
                  {kHeader}, {make_branch(kDirectLatch, kHeader)});
        add_block(fn, kConditionalTail, BlockKind::Conditional, {kHeader},
                  {kHeader, kExit},
                  {make_cond_branch(kConditionalTail, condition,
                                    kHeader, kExit)});
        add_block(fn, kExit, BlockKind::Unconditional, {kConditionalTail},
                  {kFinal}, {make_branch(kExit, kFinal)});
        add_block(fn, kFinal, BlockKind::Return, {kExit}, {},
                  {make_ret(kFinal)});
        return fn;
    };

    const auto make_internal_successor = [] {
        constexpr addr_t kEntry = 0x6600;
        constexpr addr_t kHeader = 0x6610;
        constexpr addr_t kConditionalTail = 0x6620;
        constexpr addr_t kInternalLatch = 0x6630;
        const IrValue condition = IrValue::make_temp(0, IrType::I1);

        IrFunction fn;
        fn.start = kEntry;
        fn.end = kInternalLatch + 4;
        fn.name = "do_while_internal_successor";
        fn.next_temp_id = 1;
        add_block(fn, kEntry, BlockKind::Unconditional, {}, {kHeader},
                  {make_branch(kEntry, kHeader)});
        add_block(fn, kHeader, BlockKind::Unconditional,
                  {kEntry, kConditionalTail, kInternalLatch},
                  {kConditionalTail},
                  {make_branch(kHeader, kConditionalTail)});
        add_block(fn, kConditionalTail, BlockKind::Conditional, {kHeader},
                  {kHeader, kInternalLatch},
                  {make_cond_branch(kConditionalTail, condition,
                                    kHeader, kInternalLatch)});
        add_block(fn, kInternalLatch, BlockKind::Unconditional,
                  {kConditionalTail}, {kHeader},
                  {make_branch(kInternalLatch, kHeader)});
        return fn;
    };

    const Structurer structurer;
    IrFunction extra_latch_fn = make_extra_latch();
    auto extra_latch = structurer.structure(extra_latch_fn);
    check(extra_latch.has_value(), "loop with an extra direct latch structures");
    if (!extra_latch) return 1;
    const Region* extra_loop = find_loop_with_header(*extra_latch->body, 0x6510);
    check(extra_loop && extra_loop->kind == RegionKind::Loop &&
              contains_block(*extra_loop, 0x6520) &&
              contains_block(*extra_loop, 0x6530) &&
              !contains_block(*extra_loop, 0x6540),
          "extra direct latch keeps all tests inside a generic loop");

    IrFunction internal_successor_fn = make_internal_successor();
    auto internal_successor = structurer.structure(internal_successor_fn);
    check(internal_successor.has_value(),
          "loop whose conditional arm stays internal structures");
    if (!internal_successor) return 1;
    const Region* internal_loop =
        find_loop_with_header(*internal_successor->body, 0x6610);
    check(internal_loop && internal_loop->kind == RegionKind::Loop &&
              contains_block(*internal_loop, 0x6620) &&
              contains_block(*internal_loop, 0x6630),
          "non-header arm that reaches another latch is not treated as exit");
    return 0;
}

int test_multiple_conditional_latches_are_not_do_while() {
    constexpr addr_t kEntry = 0x6400;
    constexpr addr_t kHeader = 0x6410;
    constexpr addr_t kFirstTail = 0x6420;
    constexpr addr_t kSecondTail = 0x6430;
    constexpr addr_t kExit = 0x6440;
    constexpr addr_t kFinal = 0x6450;
    const IrValue first_condition = IrValue::make_temp(0, IrType::I1);
    const IrValue second_condition = IrValue::make_temp(1, IrType::I1);

    IrFunction fn;
    fn.start = kEntry;
    fn.end = kFinal + 4;
    fn.name = "multiple_do_while_latches";
    fn.next_temp_id = 2;
    add_block(fn, kEntry, BlockKind::Unconditional, {}, {kHeader},
              {make_branch(kEntry, kHeader)});
    add_block(fn, kHeader, BlockKind::Conditional,
              {kEntry, kFirstTail, kSecondTail},
              {kFirstTail, kSecondTail},
              {make_cond_branch(kHeader, first_condition,
                                kFirstTail, kSecondTail)});
    add_block(fn, kFirstTail, BlockKind::Conditional, {kHeader},
              {kHeader, kExit},
              {make_cond_branch(kFirstTail, first_condition,
                                kHeader, kExit)});
    add_block(fn, kSecondTail, BlockKind::Conditional, {kHeader},
              {kHeader, kExit},
              {make_cond_branch(kSecondTail, second_condition,
                                kHeader, kExit)});
    add_block(fn, kExit, BlockKind::Unconditional,
              {kFirstTail, kSecondTail}, {kFinal},
              {make_branch(kExit, kFinal)});
    add_block(fn, kFinal, BlockKind::Return, {kExit}, {}, {make_ret(kFinal)});

    const Structurer structurer;
    auto structured = structurer.structure(fn);
    check(structured.has_value(), "multi-conditional-latch loop structures");
    if (!structured) return 1;
    const Region* loop = find_loop_with_header(*structured->body, kHeader);
    check(loop && loop->kind == RegionKind::Loop,
          "multiple conditional latches remain explicit in a generic loop");
    check(loop && contains_block(*loop, kFirstTail) &&
              contains_block(*loop, kSecondTail) &&
              !contains_block(*loop, kExit) &&
              count_blocks(*structured->body, kExit) == 1,
          "generic multi-latch loop retains both tests and its shared exit");
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
    rc |= test_nested_loop_outer_targets_remain_explicit();
    rc |= test_nested_loops_preserve_shared_exit_owner();
    rc |= test_loop_exit_inside_switch_remains_targeted();
    rc |= test_for_update_requires_one_direct_latch();
    rc |= test_single_conditional_latch_is_do_while();
    rc |= test_do_while_requires_sole_exiting_backedge();
    rc |= test_multiple_conditional_latches_are_not_do_while();
    return rc;
}
