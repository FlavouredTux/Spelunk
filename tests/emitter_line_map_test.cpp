#include <ember/common/annotations.hpp>
#include <ember/decompile/emitter.hpp>
#include <ember/structure/region.hpp>

#include <algorithm>
#include <cstdio>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using namespace ember;

int failures = 0;

void check(bool condition, const char* message) {
    if (condition) return;
    std::fprintf(stderr, "FAIL: %s\n", message);
    ++failures;
}

std::unique_ptr<Region> block_region(addr_t start) {
    auto region = std::make_unique<Region>();
    region->kind = RegionKind::Block;
    region->block_start = start;
    return region;
}

std::unique_ptr<Region> return_region(addr_t block_start = 0) {
    auto region = std::make_unique<Region>();
    region->kind = RegionKind::Return;
    region->block_start = block_start;
    return region;
}

std::unique_ptr<Region>
sequence(std::vector<std::unique_ptr<Region>> children) {
    auto region = std::make_unique<Region>();
    region->kind = RegionKind::Seq;
    region->children = std::move(children);
    return region;
}

std::unique_ptr<Region>
if_else(IrValue condition, std::unique_ptr<Region> then_region,
        std::unique_ptr<Region> else_region) {
    auto region = std::make_unique<Region>();
    region->kind = RegionKind::IfElse;
    region->condition = condition;
    region->children.push_back(std::move(then_region));
    region->children.push_back(std::move(else_region));
    return region;
}

void add_call_block(IrFunction& function, Annotations& annotations,
                    addr_t block_start, addr_t source_addr,
                    addr_t target, std::string name) {
    IrInst call;
    call.op = IrOp::Call;
    call.source_addr = source_addr;
    call.target1 = target;

    IrBlock block;
    block.start = block_start;
    block.end = block_start + 4;
    block.kind = BlockKind::Fallthrough;
    block.insts.push_back(std::move(call));
    function.block_at[block_start] = function.blocks.size();
    function.blocks.push_back(std::move(block));

    annotations.renames[target] = std::move(name);
    annotations.signatures[target] = FunctionSig{
        .return_type = "void", .params = {}, .variadic = false};
}

void add_empty_block(IrFunction& function, addr_t block_start) {
    IrBlock block;
    block.start = block_start;
    block.end = block_start + 4;
    block.kind = BlockKind::Fallthrough;
    function.block_at[block_start] = function.blocks.size();
    function.blocks.push_back(std::move(block));
}

std::string_view line_at(std::string_view text, std::size_t offset) {
    if (offset >= text.size()) return {};
    const std::size_t previous = offset == 0
        ? std::string_view::npos : text.rfind('\n', offset - 1);
    const std::size_t start = previous == std::string_view::npos
        ? 0 : previous + 1;
    const std::size_t next = text.find('\n', offset);
    return text.substr(start, next == std::string_view::npos
        ? text.size() - start : next - start);
}

void check_hit(const std::string& text, const LineMap& line_map,
               addr_t source_addr, std::string_view expected_statement) {
    const auto matches = std::ranges::count_if(
        line_map.hits, [&](const LineMap::Hit& hit) {
            return hit.source_addr == source_addr;
        });
    check(matches == 1, "source address has exactly one LineMap hit");
    const auto found = std::ranges::find_if(
        line_map.hits, [&](const LineMap::Hit& hit) {
            return hit.source_addr == source_addr;
        });
    if (found == line_map.hits.end()) return;
    check(found->byte_offset < text.size(),
          "LineMap hit lies within returned pseudo-C text");
    const std::size_t statement = text.find(expected_statement);
    const std::size_t previous = statement == std::string::npos || statement == 0
        ? std::string::npos : text.rfind('\n', statement - 1);
    const std::size_t expected_offset = previous == std::string::npos
        ? 0 : previous + 1;
    check(statement != std::string::npos &&
              found->byte_offset == expected_offset,
          "LineMap hit points at the exact start of the statement line");
    check(line_at(text, found->byte_offset).find(expected_statement) !=
              std::string_view::npos,
          "LineMap hit resolves to its emitted statement line");
}

void check_all_offsets(const std::string& text, const LineMap& line_map) {
    check(std::ranges::all_of(line_map.hits, [&](const LineMap::Hit& hit) {
              return hit.byte_offset < text.size();
          }),
          "every LineMap offset lies within returned pseudo-C text");
    for (std::size_t i = 1; i < line_map.hits.size(); ++i) {
        check(line_map.hits[i - 1].byte_offset <= line_map.hits[i].byte_offset,
              "LineMap offsets remain in emitted-text order");
    }
}

void test_nested_if_else_and_early_return() {
    constexpr addr_t kFunction = 0x1000;
    constexpr addr_t kThenBlock = 0x1010;
    constexpr addr_t kNestedElseBlock = 0x1020;
    constexpr addr_t kOuterElseBlock = 0x1030;
    constexpr addr_t kThenSource = 0x2010;
    constexpr addr_t kNestedElseSource = 0x2020;
    constexpr addr_t kOuterElseSource = 0x2030;

    IrFunction function;
    function.start = kFunction;
    function.end = kOuterElseBlock + 4;
    function.name = "line_map_nested_if";
    Annotations annotations;
    add_call_block(function, annotations, kThenBlock, kThenSource,
                   0x3010, "nested_then_statement");
    add_call_block(function, annotations, kNestedElseBlock,
                   kNestedElseSource, 0x3020, "nested_else_statement");
    add_call_block(function, annotations, kOuterElseBlock,
                   kOuterElseSource, 0x3030, "outer_else_statement");

    IrValue outer_condition = IrValue::make_reg(Reg::Rdi, IrType::I1);
    IrValue inner_condition = IrValue::make_reg(Reg::Rsi, IrType::I1);
    auto nested = if_else(inner_condition, block_region(kThenBlock),
                          block_region(kNestedElseBlock));
    std::vector<std::unique_ptr<Region>> then_children;
    then_children.push_back(std::move(nested));
    then_children.push_back(return_region());
    auto body = if_else(outer_condition, sequence(std::move(then_children)),
                        block_region(kOuterElseBlock));
    StructuredFunction structured{&function, std::move(body)};

    LineMap line_map;
    line_map.hits.push_back({
        std::numeric_limits<std::size_t>::max(), 0xdeadbeef});
    EmitOptions options;
    options.line_map = &line_map;
    const PseudoCEmitter emitter;
    auto rendered = emitter.emit(structured, nullptr, &annotations, options);
    check(rendered.has_value(), "nested if/else pseudo-C emits");
    if (!rendered) return;

    check_hit(*rendered, line_map, kThenSource, "nested_then_statement();");
    check_hit(*rendered, line_map, kNestedElseSource,
              "nested_else_statement();");
    check_hit(*rendered, line_map, kOuterElseSource,
              "outer_else_statement();");
    check(line_map.hits.size() == 3,
          "each render replaces stale hits and discards scratch duplicates");
    check_all_offsets(*rendered, line_map);
}

void test_swapped_empty_then_branch() {
    constexpr addr_t kFunction = 0x1100;
    constexpr addr_t kEmptyBlock = 0x1110;
    constexpr addr_t kElseBlock = 0x1120;
    constexpr addr_t kElseSource = 0x2120;

    IrFunction function;
    function.start = kFunction;
    function.end = kElseBlock + 4;
    function.name = "line_map_empty_then";
    Annotations annotations;
    add_empty_block(function, kEmptyBlock);
    add_call_block(function, annotations, kElseBlock, kElseSource,
                   0x3120, "surviving_else_statement");

    auto body = if_else(IrValue::make_reg(Reg::Rdi, IrType::I1),
                        block_region(kEmptyBlock), block_region(kElseBlock));
    StructuredFunction structured{&function, std::move(body)};
    LineMap line_map;
    EmitOptions options;
    options.line_map = &line_map;
    options.show_bb_labels = true;
    const PseudoCEmitter emitter;
    auto rendered = emitter.emit(structured, nullptr, &annotations, options);
    check(rendered.has_value(), "empty-then if/else pseudo-C emits");
    if (!rendered) return;

    check(rendered->find("bb_1110") == std::string::npos,
          "discarded empty then branch leaves no text");
    check_hit(*rendered, line_map, kElseSource,
              "surviving_else_statement();");
    check(line_map.hits.size() == 1,
          "discarded empty branch leaves no LineMap hit");
    check_all_offsets(*rendered, line_map);
}

void test_while_header_chunk() {
    constexpr addr_t kFunction = 0x1200;
    constexpr addr_t kHeaderBlock = 0x1210;
    constexpr addr_t kBodyBlock = 0x1220;
    constexpr addr_t kHeaderSource = 0x2210;
    constexpr addr_t kBodySource = 0x2220;

    IrFunction function;
    function.start = kFunction;
    function.end = kBodyBlock + 4;
    function.name = "line_map_while_header";
    Annotations annotations;
    add_call_block(function, annotations, kHeaderBlock, kHeaderSource,
                   0x3210, "while_header_statement");
    add_call_block(function, annotations, kBodyBlock, kBodySource,
                   0x3220, "while_body_statement");

    auto loop = std::make_unique<Region>();
    loop->kind = RegionKind::While;
    loop->condition = IrValue::make_reg(Reg::Rdi, IrType::I1);
    loop->children.push_back(block_region(kHeaderBlock));
    loop->children.push_back(block_region(kBodyBlock));
    StructuredFunction structured{&function, std::move(loop)};

    LineMap line_map;
    EmitOptions options;
    options.line_map = &line_map;
    const PseudoCEmitter emitter;
    auto rendered = emitter.emit(structured, nullptr, &annotations, options);
    check(rendered.has_value(), "while-header pseudo-C emits");
    if (!rendered) return;

    check(rendered->find("for (;;) {") != std::string::npos,
          "live while header selects the explicit header form");
    check_hit(*rendered, line_map, kHeaderSource, "while_header_statement();");
    check_hit(*rendered, line_map, kBodySource, "while_body_statement();");
    check(line_map.hits.size() == 2,
          "while header and body each retain one LineMap hit");
    check_all_offsets(*rendered, line_map);
}

void test_return_provenance_and_per_block_reset() {
    constexpr addr_t kFunction = 0x1300;
    constexpr addr_t kReturnSource = 0x2300;

    IrFunction function;
    function.start = kFunction;
    function.end = kFunction + 4;
    function.name = "line_map_return";
    IrInst returned;
    returned.op = IrOp::Return;
    returned.source_addr = kReturnSource;
    IrBlock block;
    block.start = kFunction;
    block.end = function.end;
    block.kind = BlockKind::Return;
    block.insts.push_back(std::move(returned));
    function.block_at[block.start] = 0;
    function.blocks.push_back(std::move(block));

    std::vector<std::unique_ptr<Region>> children;
    children.push_back(block_region(kFunction));
    children.push_back(return_region(kFunction));
    StructuredFunction structured{&function, sequence(std::move(children))};
    LineMap line_map;
    EmitOptions options;
    options.line_map = &line_map;
    const PseudoCEmitter emitter;
    auto rendered = emitter.emit(structured, nullptr, nullptr, options);
    check(rendered.has_value(), "structured return pseudo-C emits");
    if (rendered) {
        check_hit(*rendered, line_map, kReturnSource, "return;");
        check_all_offsets(*rendered, line_map);
    }

    line_map.hits.push_back({
        std::numeric_limits<std::size_t>::max(), 0xdeadbeef});
    auto per_block = emitter.emit_per_block(
        structured, nullptr, nullptr, options);
    check(per_block.has_value(), "per-block return pseudo-C emits");
    if (per_block) {
        check_hit(*per_block, line_map, kReturnSource, "return;");
        check(line_map.hits.size() == 1,
              "per-block rendering replaces stale LineMap hits");
        check_all_offsets(*per_block, line_map);
    }
}

void test_nonempty_void_tail_probe_discards_scratch_hit() {
    constexpr addr_t kFunction = 0x1400;
    constexpr addr_t kGuardBlock = 0x1410;
    constexpr addr_t kLiveBlock = 0x1420;
    constexpr addr_t kReturnBlock = 0x1430;
    constexpr addr_t kGuardSource = 0x2410;
    constexpr addr_t kLiveSource = 0x2420;
    constexpr addr_t kReturnSource = 0x2430;

    IrFunction function;
    function.start = kFunction;
    function.end = kReturnBlock + 4;
    function.name = "line_map_void_tail_probe";
    Annotations annotations;
    annotations.signatures[kFunction] = FunctionSig{
        .return_type = "void", .params = {}, .variadic = false};
    add_call_block(function, annotations, kGuardBlock, kGuardSource,
                   0x3410, "guard_statement");
    add_call_block(function, annotations, kLiveBlock, kLiveSource,
                   0x3420, "live_tail_statement");
    IrInst returned;
    returned.op = IrOp::Return;
    returned.source_addr = kReturnSource;
    IrBlock return_block;
    return_block.start = kReturnBlock;
    return_block.end = kReturnBlock + 4;
    return_block.kind = BlockKind::Return;
    return_block.insts.push_back(std::move(returned));
    function.block_at[kReturnBlock] = function.blocks.size();
    function.blocks.push_back(std::move(return_block));

    auto guard = std::make_unique<Region>();
    guard->kind = RegionKind::IfThen;
    guard->condition = IrValue::make_reg(Reg::Rdi, IrType::I1);
    guard->children.push_back(block_region(kGuardBlock));
    std::vector<std::unique_ptr<Region>> children;
    children.push_back(std::move(guard));
    children.push_back(block_region(kLiveBlock));
    children.push_back(return_region(kReturnBlock));
    StructuredFunction structured{&function, sequence(std::move(children))};

    LineMap line_map;
    EmitOptions options;
    options.line_map = &line_map;
    const PseudoCEmitter emitter;
    auto rendered = emitter.emit(structured, nullptr, &annotations, options);
    check(rendered.has_value(), "void-tail probe pseudo-C emits");
    if (!rendered) return;
    check_hit(*rendered, line_map, kLiveSource, "live_tail_statement();");
    check(std::ranges::count_if(line_map.hits, [](const LineMap::Hit& hit) {
              return hit.source_addr == kLiveSource;
          }) == 1,
          "nonempty speculative suffix leaves one live statement hit");
    check_all_offsets(*rendered, line_map);
}

}  // namespace

int main() {
    test_nested_if_else_and_early_return();
    test_swapped_empty_then_branch();
    test_while_header_chunk();
    test_return_provenance_and_per_block_reset();
    test_nonempty_void_tail_probe_discards_scratch_hit();
    return failures == 0 ? 0 : 1;
}
