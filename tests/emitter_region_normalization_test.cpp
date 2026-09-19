#include "structurer_fail_common.hpp"

#include "emitter_internal.hpp"

#include <algorithm>
#include <cstdio>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using namespace spelunk;
using spelunk::emit::Emitter;

class CanaryBinary final : public Binary {
public:
    explicit CanaryBinary(addr_t fail_target) {
        Symbol fail;
        fail.name = "__stack_chk_fail";
        fail.addr = fail_target;
        fail.size = 16;
        fail.kind = SymbolKind::Function;
        fail.is_import = true;
        symbols_.push_back(std::move(fail));
    }

    [[nodiscard]] Format format() const noexcept override { return Format::Elf; }
    [[nodiscard]] Arch arch() const noexcept override { return Arch::X86_64; }
    [[nodiscard]] Endian endian() const noexcept override { return Endian::Little; }
    [[nodiscard]] addr_t entry_point() const noexcept override { return 0; }
    [[nodiscard]] std::span<const Section> sections() const noexcept override {
        return {};
    }
    [[nodiscard]] std::span<const Symbol> symbols() const noexcept override {
        return symbols_;
    }
    [[nodiscard]] std::span<const std::byte> image() const noexcept override {
        return {};
    }

protected:
    [[nodiscard]] std::vector<Symbol>& mutable_symbols() noexcept override {
        return symbols_;
    }

private:
    std::vector<Symbol> symbols_;
};

std::unique_ptr<Region> block_region(addr_t start) {
    auto region = std::make_unique<Region>();
    region->kind = RegionKind::Block;
    region->block_start = start;
    return region;
}

std::unique_ptr<Region> return_region(IrValue value,
                                      addr_t block_start = 0) {
    auto region = std::make_unique<Region>();
    region->kind = RegionKind::Return;
    region->condition = value;
    region->block_start = block_start;
    return region;
}

std::unique_ptr<Region> sequence(
    std::vector<std::unique_ptr<Region>> children) {
    auto region = std::make_unique<Region>();
    region->kind = RegionKind::Seq;
    region->children = std::move(children);
    return region;
}

std::unique_ptr<Region> if_then(IrValue condition,
                                std::unique_ptr<Region> body) {
    auto region = std::make_unique<Region>();
    region->kind = RegionKind::IfThen;
    region->condition = condition;
    region->children.push_back(std::move(body));
    return region;
}

void add_call_block(IrFunction& function, addr_t block_start,
                    addr_t source_addr, addr_t target) {
    IrInst call = make_call_imm(source_addr, target);
    IrBlock block;
    block.start = block_start;
    block.end = block_start + 4;
    block.kind = BlockKind::Fallthrough;
    block.insts.push_back(std::move(call));
    function.block_at[block.start] = function.blocks.size();
    function.blocks.push_back(std::move(block));
}

std::size_t count_regions(const Region& region, RegionKind kind) {
    std::size_t count = region.kind == kind ? 1u : 0u;
    for (const auto& child : region.children) {
        if (child) count += count_regions(*child, kind);
    }
    return count;
}

bool contains_block(const Region& region, addr_t block_start) {
    if (region.kind == RegionKind::Block &&
        region.block_start == block_start) return true;
    return std::ranges::any_of(region.children, [&](const auto& child) {
        return child && contains_block(*child, block_start);
    });
}

std::size_t count_text(std::string_view text, std::string_view needle) {
    std::size_t count = 0;
    for (std::size_t at = 0;
         (at = text.find(needle, at)) != std::string_view::npos;
         at += needle.size()) {
        ++count;
    }
    return count;
}

std::unique_ptr<Region> common_tail_fixture(addr_t guarded_effect,
                                            addr_t fallback_effect) {
    const IrValue value = IrValue::make_imm(7, IrType::I32);
    auto nested_guard = if_then(
        IrValue::make_imm(1, IrType::I1), return_region(value));
    std::vector<std::unique_ptr<Region>> guarded_children;
    guarded_children.push_back(std::move(nested_guard));
    guarded_children.push_back(block_region(guarded_effect));
    guarded_children.push_back(return_region(value));

    std::vector<std::unique_ptr<Region>> root_children;
    root_children.push_back(if_then(
        IrValue::make_imm(1, IrType::I1),
        sequence(std::move(guarded_children))));
    root_children.push_back(block_region(fallback_effect));
    root_children.push_back(return_region(value));
    return sequence(std::move(root_children));
}

void test_common_tail_strips_only_terminal_returns() {
    constexpr addr_t kGuardedEffect = 0x2010;
    constexpr addr_t kFallbackEffect = 0x2020;
    auto root = common_tail_fixture(kGuardedEffect, kFallbackEffect);
    Emitter emitter(nullptr);
    Region& guarded_sequence =
        *root->children[0]->children[0];
    emitter.strip_matching_tail_returns(
        guarded_sequence, IrValue::make_imm(7, IrType::I32));

    check(count_regions(guarded_sequence, RegionKind::Return) == 1,
          "common-tail folding preserves an earlier guarded return");
    check(contains_block(guarded_sequence, kGuardedEffect) &&
              contains_block(*root, kFallbackEffect),
          "terminal stripping preserves preceding side effects");
}

void test_public_emit_does_not_mutate_region_tree() {
    constexpr addr_t kStart = 0x2100;
    constexpr addr_t kGuardedBlock = 0x2110;
    constexpr addr_t kFallbackBlock = 0x2120;
    constexpr addr_t kGuardedTarget = 0x3100;
    constexpr addr_t kFallbackTarget = 0x3110;

    IrFunction function;
    function.start = kStart;
    function.end = kFallbackBlock + 4;
    function.name = "stable_region_tree";
    add_call_block(function, kGuardedBlock, kGuardedBlock, kGuardedTarget);
    add_call_block(function, kFallbackBlock, kFallbackBlock, kFallbackTarget);
    StructuredFunction structured{
        &function, common_tail_fixture(kGuardedBlock, kFallbackBlock)};

    Annotations annotations;
    annotations.signatures[kStart] = FunctionSig{
        .return_type = "int", .params = {}, .variadic = false};
    annotations.renames[kGuardedTarget] = "guarded_effect";
    annotations.signatures[kGuardedTarget] = FunctionSig{
        .return_type = "void", .params = {}, .variadic = false};
    annotations.renames[kFallbackTarget] = "fallback_effect";
    annotations.signatures[kFallbackTarget] = FunctionSig{
        .return_type = "void", .params = {}, .variadic = false};

    const std::string before = format_structured(structured);
    const PseudoCEmitter emitter;
    auto first = emitter.emit(structured, nullptr, &annotations, EmitOptions{});
    const std::string between = format_structured(structured);
    auto second = emitter.emit(structured, nullptr, &annotations, EmitOptions{});
    const std::string after = format_structured(structured);

    check(first.has_value() && second.has_value() && *first == *second,
          "repeated emitter calls produce identical output");
    check(before == between && between == after,
          "emitter presentation rewrites do not mutate the caller's tree");
}

void test_void_tail_probe_keeps_deferred_call() {
    constexpr addr_t kStart = 0x2200;
    constexpr addr_t kGuardBlock = 0x2210;
    constexpr addr_t kCallBlock = 0x2220;
    constexpr addr_t kGuardTarget = 0x3200;
    constexpr addr_t kEffectTarget = 0x3210;

    IrFunction function;
    function.start = kStart;
    function.end = kCallBlock + 12;
    function.name = "void_tail_deferred_call";
    add_call_block(function, kGuardBlock, kGuardBlock, kGuardTarget);

    IrValue result = IrValue::make_reg(Reg::Rax, IrType::I64);
    result.version = 1;
    IrBlock call_block;
    call_block.start = kCallBlock;
    call_block.end = function.end;
    call_block.kind = BlockKind::Return;
    call_block.insts.push_back(make_call_imm(kCallBlock, kEffectTarget));
    call_block.insts.push_back(make_clobber(result));
    call_block.insts.push_back(make_ret_value(kCallBlock + 8, result));
    function.block_at[call_block.start] = function.blocks.size();
    function.blocks.push_back(std::move(call_block));

    std::vector<std::unique_ptr<Region>> children;
    children.push_back(if_then(
        IrValue::make_reg(Reg::Rdi, IrType::I1),
        block_region(kGuardBlock)));
    children.push_back(block_region(kCallBlock));
    children.push_back(return_region(result, kCallBlock));
    StructuredFunction structured{&function, sequence(std::move(children))};

    Annotations annotations;
    annotations.signatures[kStart] = FunctionSig{
        .return_type = "void", .params = {}, .variadic = false};
    annotations.renames[kGuardTarget] = "guarded_work";
    annotations.signatures[kGuardTarget] = FunctionSig{
        .return_type = "void", .params = {}, .variadic = false};
    annotations.renames[kEffectTarget] = "effectful_call";
    annotations.signatures[kEffectTarget] = FunctionSig{
        .return_type = "uint64_t", .params = {}, .variadic = false};

    const PseudoCEmitter emitter;
    auto output = emitter.emit(
        structured, nullptr, &annotations, EmitOptions{});
    check(output.has_value() &&
              count_text(*output, "effectful_call();") == 1,
          "void-tail probing emits a folded effectful call exactly once");
}

void test_nested_canary_path_is_not_suppressed() {
    constexpr addr_t kStart = 0x2300;
    constexpr addr_t kFailBlock = 0x2310;
    constexpr addr_t kAuditBlock = 0x2320;
    constexpr addr_t kFailTarget = 0x3300;
    constexpr addr_t kAuditTarget = 0x3310;

    IrFunction function;
    function.start = kStart;
    function.end = kAuditBlock + 4;
    function.name = "nested_canary_path";
    function.next_temp_id = 4;
    const IrValue stack_address = IrValue::make_temp(0, IrType::I64);
    const IrValue saved = IrValue::make_temp(1, IrType::I64);
    const IrValue guard = IrValue::make_temp(2, IrType::I64);
    const IrValue mismatch = IrValue::make_temp(3, IrType::I1);
    IrInst guard_load = make_load(
        guard, IrValue::make_imm(0x28, IrType::I64));
    guard_load.segment = Reg::Fs;
    IrInst compare;
    compare.op = IrOp::CmpNe;
    compare.dst = mismatch;
    compare.srcs[0] = saved;
    compare.srcs[1] = guard;
    compare.src_count = 2;
    IrBlock entry;
    entry.start = kStart;
    entry.end = kStart + 16;
    entry.kind = BlockKind::Fallthrough;
    entry.insts.push_back(make_add(
        stack_address, IrValue::make_reg(Reg::Rsp, IrType::I64),
        IrValue::make_imm(-8, IrType::I64)));
    entry.insts.push_back(make_load(saved, stack_address));
    entry.insts.push_back(std::move(guard_load));
    entry.insts.push_back(std::move(compare));
    function.block_at[entry.start] = function.blocks.size();
    function.blocks.push_back(std::move(entry));
    add_call_block(function, kFailBlock, kFailBlock, kFailTarget);
    add_call_block(function, kAuditBlock, kAuditBlock, kAuditTarget);

    auto nested = std::make_unique<Region>();
    nested->kind = RegionKind::IfElse;
    nested->condition = IrValue::make_reg(Reg::Rdi, IrType::I1);
    nested->children.push_back(block_region(kFailBlock));
    nested->children.push_back(block_region(kAuditBlock));
    auto outer = if_then(mismatch, std::move(nested));

    CanaryBinary binary(kFailTarget);
    Emitter emitter(&binary);
    emitter.abi = Abi::SysVAmd64;
    emitter.analyze(function);
    emitter.suppress_canary_regions(*outer);

    check(outer->kind == RegionKind::IfThen &&
              contains_block(*outer, kAuditBlock),
          "canary suppression keeps a nested continuing path");

    std::vector<std::unique_ptr<Region>> audited_children;
    audited_children.push_back(block_region(kAuditBlock));
    audited_children.push_back(block_region(kFailBlock));
    auto audited_failure = if_then(
        mismatch, sequence(std::move(audited_children)));
    emitter.suppress_canary_regions(*audited_failure);
    check(audited_failure->kind == RegionKind::IfThen &&
              contains_block(*audited_failure, kAuditBlock) &&
              contains_block(*audited_failure, kFailBlock),
          "canary suppression preserves observable effects before failure");

    std::vector<std::unique_ptr<Region>> bypass_children;
    bypass_children.push_back(if_then(
        IrValue::make_reg(Reg::Rsi, IrType::I1), return_region({})));
    bypass_children.push_back(block_region(kFailBlock));
    auto conditional_bypass = if_then(
        mismatch, sequence(std::move(bypass_children)));
    emitter.suppress_canary_regions(*conditional_bypass);
    check(conditional_bypass->kind == RegionKind::IfThen &&
              count_regions(*conditional_bypass, RegionKind::Return) == 1 &&
              contains_block(*conditional_bypass, kFailBlock),
          "canary suppression preserves a conditional path that bypasses failure");
}

void test_folded_return_maps_call_and_return_sources() {
    constexpr addr_t kStart = 0x2400;
    constexpr addr_t kTarget = 0x3400;
    constexpr addr_t kCallSource = 0x2404;
    constexpr addr_t kReturnSource = 0x2408;

    IrFunction function;
    function.start = kStart;
    function.end = kStart + 12;
    function.name = "folded_return_line_map";
    IrValue result = IrValue::make_reg(Reg::Rax, IrType::I64);
    result.version = 1;
    IrBlock block;
    block.start = kStart;
    block.end = function.end;
    block.kind = BlockKind::Return;
    block.insts.push_back(make_call_imm(kCallSource, kTarget));
    block.insts.push_back(make_clobber(result));
    block.insts.push_back(make_ret_value(kReturnSource, result));
    function.block_at[block.start] = 0;
    function.blocks.push_back(std::move(block));

    std::vector<std::unique_ptr<Region>> children;
    children.push_back(block_region(kStart));
    children.push_back(return_region(result, kStart));
    StructuredFunction structured{&function, sequence(std::move(children))};
    Annotations annotations;
    annotations.signatures[kStart] = FunctionSig{
        .return_type = "uint64_t", .params = {}, .variadic = false};
    annotations.renames[kTarget] = "folded_call";
    annotations.signatures[kTarget] = FunctionSig{
        .return_type = "uint64_t", .params = {}, .variadic = false};
    LineMap line_map;
    EmitOptions options;
    options.line_map = &line_map;

    const PseudoCEmitter emitter;
    auto output = emitter.emit(structured, nullptr, &annotations, options);
    check(output.has_value(), "folded-return LineMap fixture emits");
    if (!output) return;
    const std::size_t statement = output->find("return folded_call();");
    const std::size_t line_start = statement == std::string::npos
        ? std::string::npos
        : output->rfind('\n', statement) + 1;
    auto call_hit = std::ranges::find_if(line_map.hits, [](const auto& hit) {
        return hit.source_addr == kCallSource;
    });
    auto return_hit = std::ranges::find_if(line_map.hits, [](const auto& hit) {
        return hit.source_addr == kReturnSource;
    });
    check(statement != std::string::npos &&
              call_hit != line_map.hits.end() &&
              return_hit != line_map.hits.end() &&
              call_hit->byte_offset == line_start &&
              return_hit->byte_offset == line_start,
          "folded return line carries both call and return provenance");
}

void test_inlined_return_maps_call_and_return_sources() {
    constexpr addr_t kStart = 0x2500;
    constexpr addr_t kTarget = 0x3500;
    constexpr addr_t kCallSource = 0x2504;
    constexpr addr_t kReturnSource = 0x250c;

    IrFunction function;
    function.start = kStart;
    function.end = kStart + 16;
    function.name = "inlined_return_line_map";
    function.next_temp_id = 1;
    IrValue result = IrValue::make_reg(Reg::Rax, IrType::I64);
    result.version = 1;
    const IrValue adjusted = IrValue::make_temp(0, IrType::I64);
    IrBlock block;
    block.start = kStart;
    block.end = function.end;
    block.kind = BlockKind::Return;
    block.insts.push_back(make_call_imm(kCallSource, kTarget));
    block.insts.push_back(make_clobber(result));
    block.insts.push_back(make_add(
        adjusted, result, IrValue::make_imm(1, IrType::I64)));
    block.insts.push_back(make_ret_value(kReturnSource, adjusted));
    function.block_at[block.start] = 0;
    function.blocks.push_back(std::move(block));

    std::vector<std::unique_ptr<Region>> children;
    children.push_back(block_region(kStart));
    children.push_back(return_region(adjusted, kStart));
    StructuredFunction structured{&function, sequence(std::move(children))};
    Annotations annotations;
    annotations.signatures[kStart] = FunctionSig{
        .return_type = "uint64_t", .params = {}, .variadic = false};
    annotations.renames[kTarget] = "inlined_call";
    annotations.signatures[kTarget] = FunctionSig{
        .return_type = "uint64_t", .params = {}, .variadic = false};
    LineMap line_map;
    EmitOptions options;
    options.line_map = &line_map;

    const PseudoCEmitter emitter;
    auto output = emitter.emit(structured, nullptr, &annotations, options);
    check(output.has_value(), "inlined-return LineMap fixture emits");
    if (!output) return;
    const std::size_t statement = output->find("return inlined_call() + 1;");
    const std::size_t line_start = statement == std::string::npos
        ? std::string::npos
        : output->rfind('\n', statement) + 1;
    auto call_hit = std::ranges::find_if(line_map.hits, [](const auto& hit) {
        return hit.source_addr == kCallSource;
    });
    auto return_hit = std::ranges::find_if(line_map.hits, [](const auto& hit) {
        return hit.source_addr == kReturnSource;
    });
    check(statement != std::string::npos &&
              call_hit != line_map.hits.end() &&
              return_hit != line_map.hits.end() &&
              call_hit->byte_offset == line_start &&
              return_hit->byte_offset == line_start,
          "inlined return line carries both call and return provenance");
}

}  // namespace

void test_bounded_loop_shift_count() {
    const auto prove = [](unsigned width, i64 limit, i64 initial_shift,
                          bool bypass, bool signed_compare, bool after_update) {
        IrFunction fn;
        fn.start = 0x5000; fn.end = 0x5050; fn.next_temp_id = 9;
        const auto type = width == 64 ? IrType::I64 : IrType::I32;
        const auto shift = IrValue::make_temp(0, type);
        const auto index = IrValue::make_temp(1, type);
        const auto next_shift = IrValue::make_temp(2, type);
        const auto next_index = IrValue::make_temp(3, type);
        auto shift_phi = make_phi(shift, {IrValue::make_imm(initial_shift, type), next_shift});
        auto index_phi = make_phi(index, {IrValue::make_imm(0, type), next_index});
        shift_phi.phi_preds = index_phi.phi_preds = {0x5000, 0x5030};
        const auto add = [&](addr_t address, std::vector<addr_t> successors, std::vector<IrInst> insts) {
            IrBlock block;
            block.start = address; block.end = address + 0x10;
            block.successors = std::move(successors); block.insts = std::move(insts);
            fn.block_at[address] = fn.blocks.size(); fn.blocks.push_back(std::move(block));
        };
        add(0x5000, {0x5010}, {make_branch(0x5000, 0x5010)});
        add(0x5010, bypass ? std::vector<addr_t>{0x5020, 0x5030} : std::vector<addr_t>{0x5020},
            {shift_phi, index_phi});
        IrInst narrow;
        narrow.op = IrOp::Trunc; narrow.dst = IrValue::make_temp(4, IrType::I8);
        narrow.srcs[0] = shift; narrow.src_count = 1;
        IrInst widen;
        widen.op = IrOp::ZExt; widen.dst = IrValue::make_temp(5, type);
        widen.srcs[0] = narrow.dst; widen.src_count = 1;
        IrInst masked = make_add(IrValue::make_temp(6, type), widen.dst, IrValue::make_imm(width - 1, type));
        masked.op = IrOp::And;
        IrInst shifted = make_add(IrValue::make_temp(7, type), IrValue::make_imm(1, type), masked.dst);
        shifted.op = IrOp::Shl;
        IrInst comparison = make_add(IrValue::make_temp(8, IrType::I1), index, IrValue::make_imm(limit, type));
        comparison.op = signed_compare ? IrOp::CmpSgt : IrOp::CmpUgt;
        std::vector<IrInst> work{narrow, widen, masked};
        if (!after_update) work.push_back(shifted);
        work.push_back(comparison);
        work.push_back(make_cond_branch(0x5020, comparison.dst, 0x5040, 0x5030));
        add(0x5020, {0x5040, 0x5030}, std::move(work));
        std::vector<IrInst> update{
            make_add(next_shift, shift, IrValue::make_imm(7, type)),
            make_add(next_index, index, IrValue::make_imm(1, type))};
        if (after_update) update.push_back(shifted);
        update.push_back(make_branch(0x5030, 0x5010));
        add(0x5030, {0x5010}, std::move(update));
        add(0x5040, {}, {make_ret(0x5040)});
        for (const auto& block : fn.blocks) for (const auto successor : block.successors)
            fn.blocks[fn.block_at.at(successor)].predecessors.push_back(block.start);
        Emitter emitter(nullptr);
        emitter.fn = &fn; emitter.abi = Abi::SysVAmd64;
        emitter.ssa_uses.scan(fn);
        return emitter.bounded_loop_shift_count(shifted).has_value();
    };
    check(prove(64, 8, 0, false, false, false), "nine increments of seven bound shifts to 0..63");
    check(!prove(64, 9, 0, false, false, false), "a possible shift of 70 retains the hardware mask");
    check(!prove(64, 8, 1, false, false, false), "nonzero seed that permits 64 retains the mask");
    check(prove(32, 3, 0, false, false, false), "32-bit shift proof respects its smaller count range");
    check(!prove(32, 4, 0, false, false, false), "32-bit shift at 35 is not unmasked");
    check(!prove(64, 8, 0, true, false, false), "a path bypassing the bound invalidates the proof");
    check(!prove(64, 8, 0, false, true, false), "signed guards are not treated as unsigned bounds");
    check(!prove(64, 8, 0, false, false, true), "old count is not rendered through an already updated merge local");
}

void test_output_address_does_not_claim_source_return_type() {
    constexpr addr_t start = 0x4000;
    IrFunction fn;
    fn.start = start; fn.end = start + 4; fn.name = "write_output";
    const auto pointer = IrValue::make_reg(Reg::Rdi, IrType::I64);
    IrBlock block;
    block.start = start; block.end = fn.end; block.kind = BlockKind::Return;
    block.insts = {make_store(pointer, IrValue::make_imm(7, IrType::I64)), make_ret_value(start + 3, pointer)};
    fn.block_at[start] = 0;
    fn.blocks.push_back(std::move(block));
    std::vector<std::unique_ptr<Region>> body;
    body.push_back(block_region(start));
    auto returned = return_region(pointer);
    returned->block_start = start;
    body.push_back(std::move(returned));
    StructuredFunction sf{&fn, sequence(std::move(body))};
    Annotations annotations;
    annotations.signatures[start] = FunctionSig{.return_type = "", .params = {{"uint64_t*", "output"}}};
    PseudoCEmitter emitter;
    auto inferred = emitter.emit(sf, nullptr, &annotations, {});
    check(inferred && inferred->find("unknown_return_t ") != std::string::npos &&
          inferred->find("return output;") == std::string::npos &&
          inferred->find("source return value unproven") != std::string::npos,
          "incidental output address is labelled unknown rather than a source pointer return");
    for (const std::string type : {"void", "uint64_t*"}) {
        annotations.signatures[start].return_type = type;
        auto declared = emitter.emit(sf, nullptr, &annotations, {});
        check(declared && declared->find("unknown_return_t") == std::string::npos,
              "explicit void and pointer return signatures override uncertainty");
        if (type != "void") check(declared && declared->find("return output;") != std::string::npos,
                                  "declared pointer return remains a real value return");
    }
    annotations.signatures[start].return_type.clear();
    EmitOptions strict;
    strict.c_source = true;
    auto exported = emitter.emit(sf, nullptr, &annotations, strict);
    check(exported && exported->find("unknown_return_t") == std::string::npos &&
          exported->find("return output;") != std::string::npos,
          "strict C export continues to model the actual ABI return register");
}

int main() {
    test_bounded_loop_shift_count();
    test_output_address_does_not_claim_source_return_type();
    test_common_tail_strips_only_terminal_returns();
    test_public_emit_does_not_mutate_region_tree();
    test_void_tail_probe_keeps_deferred_call();
    test_nested_canary_path_is_not_suppressed();
    test_folded_return_maps_call_and_return_sources();
    test_inlined_return_maps_call_and_return_sources();
    return fails == 0 ? 0 : 1;
}
