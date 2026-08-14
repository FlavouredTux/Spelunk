// Unit test for the structurer's drop-block diagnostic.
//
// Builds a synthetic IrFunction with one reachable Return block plus a
// disconnected dangling block (no predecessors, no successor edges from
// the entry). The structurer's build_sequence walks from `start` and
// never visits the dangling block - without the fix this dropped a
// real call silently. The fix surfaces the omission as a
// `STRUCTURER_FAIL: <lo>..<hi>` marker carrying the disconnected
// block's address range.

#include <ember/decompile/emitter.hpp>
#include <ember/analysis/import_sigs.hpp>
#include <ember/binary/binary.hpp>
#include <ember/ir/ir.hpp>
#include <ember/structure/region.hpp>
#include <ember/structure/structurer.hpp>

#include <cstdio>
#include <array>
#include <format>
#include <string>
#include <vector>

namespace {

int fails = 0;

class MockPpcBinary final : public ember::Binary {
public:
    MockPpcBinary() {
        ember::Symbol symbol;
        symbol.name = "ppc_void_callback";
        symbol.addr = 0x1000;
        symbol.size = 0x24;
        symbol.kind = ember::SymbolKind::Function;
        symbols_.push_back(std::move(symbol));

        // mixed_callee consumes f1, r3, f2, r4 in that first-use order.
        put(0x100, 0xd02b0000);  // stfs f1,0(r11)
        put(0x104, 0x906b0000);  // stw  r3,0(r11)
        put(0x108, 0xd04b0004);  // stfs f2,4(r11)
        put(0x10c, 0x908b0008);  // stw  r4,8(r11)
        put(0x110, 0x4e800020);  // blr
        ember::Symbol mixed;
        mixed.name = "mixed_callee";
        mixed.addr = 0x1100;
        mixed.size = 0x14;
        mixed.kind = ember::SymbolKind::Function;
        symbols_.push_back(std::move(mixed));

        ember::Symbol mag;
        mag.name = "PSVecMag";
        mag.addr = 0x1800;
        mag.size = 0x44;
        mag.kind = ember::SymbolKind::Function;
        symbols_.push_back(std::move(mag));

        ember::Symbol subtract;
        subtract.name = "PSVECSubtract";
        subtract.addr = 0x1900;
        subtract.size = 0x24;
        subtract.kind = ember::SymbolKind::Function;
        symbols_.push_back(std::move(subtract));

        ember::Symbol scale;
        scale.name = "PSVECScale";
        scale.addr = 0x1a00;
        scale.size = 0x1c;
        scale.kind = ember::SymbolKind::Function;
        symbols_.push_back(std::move(scale));

        ember::Symbol stack_nine;
        stack_nine.name = "stack_nine";
        stack_nine.addr = 0x1b00;
        stack_nine.size = 0x20;
        stack_nine.kind = ember::SymbolKind::Function;
        symbols_.push_back(std::move(stack_nine));

        ember::Symbol make_vec;
        make_vec.name = "make_vec";
        make_vec.addr = 0x1d00;
        make_vec.size = 0x20;
        make_vec.kind = ember::SymbolKind::Function;
        symbols_.push_back(std::move(make_vec));

        ember::Symbol consume_header;
        consume_header.name = "consume_header";
        consume_header.addr = 0x1f00;
        consume_header.size = 0x20;
        consume_header.kind = ember::SymbolKind::Function;
        symbols_.push_back(std::move(consume_header));

        section_.name = ".text";
        section_.vaddr = 0x1000;
        section_.size = text_.size();
        section_.flags.readable = true;
        section_.flags.executable = true;
        section_.flags.allocated = true;
        section_.data = text_;
    }
    [[nodiscard]] ember::Format format() const noexcept override {
        return ember::Format::Dol;
    }
    [[nodiscard]] ember::Arch arch() const noexcept override {
        return ember::Arch::Ppc32;
    }
    [[nodiscard]] ember::Endian endian() const noexcept override {
        return ember::Endian::Big;
    }
    [[nodiscard]] ember::addr_t entry_point() const noexcept override { return 0x1000; }
    [[nodiscard]] std::span<const ember::Section> sections() const noexcept override {
        return std::span<const ember::Section>(&section_, 1);
    }
    [[nodiscard]] std::span<const ember::Symbol> symbols() const noexcept override {
        return symbols_;
    }
    [[nodiscard]] std::span<const std::byte> image() const noexcept override { return {}; }

protected:
    [[nodiscard]] std::vector<ember::Symbol>& mutable_symbols() noexcept override {
        return symbols_;
    }

private:
    void put(std::size_t off, ember::u32 word) {
        text_[off + 0] = static_cast<std::byte>(word >> 24);
        text_[off + 1] = static_cast<std::byte>(word >> 16);
        text_[off + 2] = static_cast<std::byte>(word >> 8);
        text_[off + 3] = static_cast<std::byte>(word);
    }

    std::array<std::byte, 0x120> text_{};
    ember::Section section_{};
    std::vector<ember::Symbol> symbols_;
};

void check(bool cond, const char* ctx) {
    if (!cond) {
        std::fprintf(stderr, "FAIL: %s\n", ctx);
        ++fails;
    }
}

ember::IrInst make_ret(ember::addr_t pc) {
    ember::IrInst ri;
    ri.op          = ember::IrOp::Return;
    ri.source_addr = pc;
    return ri;
}

ember::IrInst make_call_imm(ember::addr_t pc, ember::addr_t target) {
    ember::IrInst ci;
    ci.op          = ember::IrOp::Call;
    ci.source_addr = pc;
    ci.target1     = target;
    return ci;
}

ember::IrInst make_clobber(ember::IrValue dst) {
    ember::IrInst ci;
    ci.op = ember::IrOp::Clobber;
    ci.dst = dst;
    return ci;
}

ember::IrInst make_branch(ember::addr_t pc, ember::addr_t target) {
    ember::IrInst bi;
    bi.op          = ember::IrOp::Branch;
    bi.source_addr = pc;
    bi.target1     = target;
    return bi;
}

ember::IrInst make_phi(ember::IrValue dst, std::initializer_list<ember::IrValue> ops) {
    ember::IrInst pi;
    pi.op  = ember::IrOp::Phi;
    pi.dst = dst;
    for (ember::IrValue op : ops) pi.phi_operands.push_back(op);
    return pi;
}

ember::IrInst make_add(ember::IrValue dst, ember::IrValue a, ember::IrValue b) {
    ember::IrInst ai;
    ai.op        = ember::IrOp::Add;
    ai.dst       = dst;
    ai.srcs[0]   = a;
    ai.srcs[1]   = b;
    ai.src_count = 2;
    return ai;
}

ember::IrInst make_mul(ember::IrValue dst, ember::IrValue a, ember::IrValue b) {
    ember::IrInst mi;
    mi.op        = ember::IrOp::Mul;
    mi.dst       = dst;
    mi.srcs[0]   = a;
    mi.srcs[1]   = b;
    mi.src_count = 2;
    return mi;
}

ember::IrInst make_load(ember::IrValue dst, ember::IrValue addr) {
    ember::IrInst li;
    li.op        = ember::IrOp::Load;
    li.dst       = dst;
    li.srcs[0]   = addr;
    li.src_count = 1;
    return li;
}

ember::IrInst make_store(ember::IrValue addr, ember::IrValue value) {
    ember::IrInst si;
    si.op        = ember::IrOp::Store;
    si.srcs[0]   = addr;
    si.srcs[1]   = value;
    si.src_count = 2;
    return si;
}

ember::IrInst make_assign(ember::IrValue dst, ember::IrValue src) {
    ember::IrInst ai;
    ai.op        = ember::IrOp::Assign;
    ai.dst       = dst;
    ai.srcs[0]   = src;
    ai.src_count = 1;
    return ai;
}

ember::IrInst make_ret_value(ember::addr_t pc, ember::IrValue value) {
    ember::IrInst ri = make_ret(pc);
    ri.srcs[0] = value;
    ri.src_count = 1;
    return ri;
}

// ----------------------------------------------------------------------------
// Test 1: a disconnected block carrying a Call surfaces as STRUCTURER_FAIL
// instead of vanishing silently.

int test_dropped_block_diagnostic() {
    using namespace ember;


    IrFunction fn;
    fn.start = 0x10404a846;
    fn.end   = 0x10404a8e0;
    fn.name  = "sub_10404a846";

    // Reachable entry: just a Return. Mirrors the simplest valid lifted
    // shape - single block, kind=Return, no successors. The structurer
    // produces `RegionKind::Block + RegionKind::Return` for this.
    {
        IrBlock bb;
        bb.start = 0x10404a846;
        bb.end   = 0x10404a850;
        bb.kind  = BlockKind::Return;
        bb.insts.push_back(make_ret(0x10404a846));
        fn.block_at[bb.start] = fn.blocks.size();
        fn.blocks.push_back(std::move(bb));
    }

    // Disconnected block carrying a real call. The CFG has no edge
    // pointing here (no entry into block_at-from-entry walks), so the
    // structurer's build_sequence never visits it. Without the
    // STRUCTURER_FAIL diagnostic the call vanishes from the output.
    {
        IrBlock bb;
        bb.start = 0x10404a8db;
        bb.end   = 0x10404a8e0;
        bb.kind  = BlockKind::Return;
        bb.insts.push_back(make_call_imm(0x10404a8db, 0x10404a270));
        bb.insts.push_back(make_ret(0x10404a8de));
        fn.block_at[bb.start] = fn.blocks.size();
        fn.blocks.push_back(std::move(bb));
    }

    Structurer s;
    auto sf_r = s.structure(fn);
    check(sf_r.has_value(), "structurer returned a result");
    if (!sf_r) return 1;

    const std::string structured_text = format_structured(*sf_r);

    // The dangling block isn't in the structured tree - confirm the
    // marker text carries its exact range so a reader can reach for
    // `--disasm-at 0x10404a8db` to see what the structurer dropped.
    const std::string expected_marker =
        "STRUCTURER_FAIL: 0x10404a8db..0x10404a8e0 (see --disasm-at)";
    check(structured_text.find(expected_marker) != std::string::npos,
          "format_structured emits STRUCTURER_FAIL for dropped block");

    // The reachable block should still be referenced by the structured
    // body - guards against the diagnostic firing on every block (which
    // would happen if the rendered-set walk got the predicate inverted).
    check(structured_text.find("STRUCTURER_FAIL: 0x10404a846") == std::string::npos,
          "reachable block does not get a STRUCTURER_FAIL marker");

    // The pseudo-C emitter's body output should also surface the
    // marker - the failure diagnostic must reach the actual rendered
    // pseudo-C, not just the structurer's debug printer.
    PseudoCEmitter em;
    auto pc_r = em.emit(*sf_r, /*binary=*/nullptr,
                        /*annotations=*/nullptr, EmitOptions{});
    check(pc_r.has_value(), "pseudo-c emit returned a result");
    if (pc_r) {
        check(pc_r->find(expected_marker) != std::string::npos,
              "PseudoCEmitter::emit surfaces STRUCTURER_FAIL");
    }

    return 0;
}

// ----------------------------------------------------------------------------
// Test 2: a multi-block infinite loop renders both header and body, not just
// the header. Shape:
//   bb_a (header): foo();   jmp bb_b
//   bb_b:          bar();   jmp bb_a   ; back-edge
// Without the body-walk fix in build_loop's RegionKind::Loop branch, bb_b
// would silently disappear inside `for (;;) { bb_a-only; }`. We detect the
// fix indirectly: format_structured should reference bb_b somewhere in the
// loop body, AND no STRUCTURER_FAIL marker should be emitted for bb_b.

int test_infinite_loop_body_recovered() {
    using namespace ember;

    constexpr addr_t kA = 0x401000;
    constexpr addr_t kB = 0x401010;

    IrFunction fn;
    fn.start = kA;
    fn.end   = kB + 0x10;
    fn.name  = "infinite_loop";

    {
        IrBlock bb;
        bb.start = kA;
        bb.end   = kA + 0x10;
        bb.kind  = BlockKind::Unconditional;
        bb.insts.push_back(make_call_imm(kA, 0x402000));   // foo()
        bb.insts.push_back(make_branch(kA + 5, kB));
        bb.successors.push_back(kB);
        fn.block_at[bb.start] = fn.blocks.size();
        fn.blocks.push_back(std::move(bb));
    }
    {
        IrBlock bb;
        bb.start = kB;
        bb.end   = kB + 0x10;
        bb.kind  = BlockKind::Unconditional;
        bb.insts.push_back(make_call_imm(kB, 0x402010));   // bar()
        bb.insts.push_back(make_branch(kB + 5, kA));
        bb.successors.push_back(kA);
        fn.block_at[bb.start] = fn.blocks.size();
        fn.blocks.push_back(std::move(bb));
    }
    // Cross-link predecessors so find_loops sees a real back-edge.
    fn.blocks[0].predecessors.push_back(kB);  // bb_b → bb_a (back-edge)
    fn.blocks[1].predecessors.push_back(kA);  // bb_a → bb_b

    Structurer s;
    auto sf_r = s.structure(fn);
    check(sf_r.has_value(), "structurer returned a result for infinite loop");
    if (!sf_r) return 1;

    const std::string structured_text = format_structured(*sf_r);

    // bb_b's address must appear in the rendered tree - the body block
    // would be omitted under the pre-fix `RegionKind::Loop` branch.
    const std::string bb_b_marker = std::format("bb_{:x}", kB);
    check(structured_text.find(bb_b_marker) != std::string::npos,
          "infinite-loop body block surfaces in the structured output");

    // And no STRUCTURER_FAIL should fire for either block - the diagnostic
    // is a safety net, not a substitute for actually rendering the body.
    check(structured_text.find("STRUCTURER_FAIL") == std::string::npos,
          "no STRUCTURER_FAIL fires for a recovered infinite-loop body");

    return 0;
}

// ----------------------------------------------------------------------------
// Test 3: phi merge values get role names instead of anonymous vN names.

int test_phi_merge_names_are_mined() {
    using namespace ember;

    constexpr addr_t kStart = 0x402000;

    IrValue rax1 = IrValue::make_reg(Reg::Rax, IrType::I64);
    rax1.version = 1;
    IrValue rax2 = IrValue::make_reg(Reg::Rax, IrType::I64);
    rax2.version = 2;
    IrValue rdx1 = IrValue::make_reg(Reg::Rdx, IrType::I64);
    rdx1.version = 1;
    IrValue t0 = IrValue::make_temp(0, IrType::I64);

    IrFunction fn;
    fn.start = kStart;
    fn.end   = kStart + 0x10;
    fn.name  = "phi_result_web";
    fn.next_temp_id = 1;

    IrBlock bb;
    bb.start = kStart;
    bb.end   = kStart + 0x10;
    bb.kind  = BlockKind::Return;
    bb.insts.push_back(make_phi(rax1, {IrValue::make_reg(Reg::Rax, IrType::I64), rax2}));
    bb.insts.push_back(make_phi(rdx1, {rax1}));
    bb.insts.push_back(make_assign(rax2, IrValue::make_imm(40, IrType::I64)));
    bb.insts.push_back(make_add(t0, rdx1, IrValue::make_imm(1, IrType::I64)));
    bb.insts.push_back(make_ret_value(kStart + 3, t0));
    fn.block_at[bb.start] = fn.blocks.size();
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto ret = std::make_unique<Region>();
    ret->kind = RegionKind::Return;
    ret->condition = t0;
    auto body = std::make_unique<Region>();
    body->kind = RegionKind::Seq;
    body->children.push_back(std::move(block));
    body->children.push_back(std::move(ret));

    StructuredFunction sf;
    sf.ir = &fn;
    sf.body = std::move(body);

    PseudoCEmitter em;
    auto pc_r = em.emit(sf, /*binary=*/nullptr,
                        /*annotations=*/nullptr, EmitOptions{});
    check(pc_r.has_value(), "pseudo-c emit returned a phi result-web body");
    if (!pc_r) return 1;

    check(pc_r->find("uint64_t result;") != std::string::npos,
          "return-register phi web is named result");
    check(pc_r->find("result = 0x28;") != std::string::npos,
          "phi incoming assignment reuses result name");
    check(pc_r->find("return result + 1;") != std::string::npos,
          "connected phi web reuses result at the use site");
    check(pc_r->find("v0") == std::string::npos &&
          pc_r->find("v1") == std::string::npos,
          "phi result-web output does not leak anonymous vN names");
    check(pc_r->find("uint64_t result;\n  uint64_t result;") == std::string::npos,
          "connected phi web emits one result declaration");

    return 0;
}

int test_phi_induction_name_is_mined() {
    using namespace ember;

    constexpr addr_t kStart = 0x402100;

    IrValue eax1 = IrValue::make_reg(Reg::Eax, IrType::I32);
    eax1.version = 1;
    IrValue eax2 = IrValue::make_reg(Reg::Eax, IrType::I32);
    eax2.version = 2;

    IrFunction fn;
    fn.start = kStart;
    fn.end   = kStart + 0x10;
    fn.name  = "phi_induction";

    IrBlock bb;
    bb.start = kStart;
    bb.end   = kStart + 0x10;
    bb.kind  = BlockKind::Return;
    bb.insts.push_back(make_phi(eax1, {IrValue::make_reg(Reg::Eax, IrType::I32), eax2}));
    bb.insts.push_back(make_add(eax2, eax1, IrValue::make_imm(1, IrType::I32)));
    bb.insts.push_back(make_ret_value(kStart + 2, eax1));
    fn.block_at[bb.start] = fn.blocks.size();
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto ret = std::make_unique<Region>();
    ret->kind = RegionKind::Return;
    ret->condition = eax1;
    auto body = std::make_unique<Region>();
    body->kind = RegionKind::Seq;
    body->children.push_back(std::move(block));
    body->children.push_back(std::move(ret));

    StructuredFunction sf;
    sf.ir = &fn;
    sf.body = std::move(body);

    PseudoCEmitter em;
    auto pc_r = em.emit(sf, /*binary=*/nullptr,
                        /*annotations=*/nullptr, EmitOptions{});
    check(pc_r.has_value(), "pseudo-c emit returned a phi induction body");
    if (!pc_r) return 1;

    check(pc_r->find("uint32_t i;") != std::string::npos,
          "unit-step phi is named i");
    check(pc_r->find("i++;") != std::string::npos,
          "unit-step phi update renders as a source-style increment");
    check(pc_r->find("return i;") != std::string::npos,
          "unit-step phi name is used in return");
    check(pc_r->find("v0") == std::string::npos,
          "phi induction output does not leak anonymous vN names");

    return 0;
}

int test_phi_livein_initializer_is_mined() {
    using namespace ember;

    constexpr addr_t kStart = 0x402200;

    IrValue rdi1 = IrValue::make_reg(Reg::Rdi, IrType::I64);
    rdi1.version = 1;
    IrValue rdi2 = IrValue::make_reg(Reg::Rdi, IrType::I64);
    rdi2.version = 2;

    IrFunction fn;
    fn.start = kStart;
    fn.end   = kStart + 0x10;
    fn.name  = "phi_livein_init";

    IrBlock bb;
    bb.start = kStart;
    bb.end   = kStart + 0x10;
    bb.kind  = BlockKind::Return;
    bb.insts.push_back(make_phi(rdi1, {IrValue::make_reg(Reg::Rdi, IrType::I64), rdi2}));
    bb.insts.push_back(make_add(rdi2, rdi1, IrValue::make_imm(1, IrType::I64)));
    bb.insts.push_back(make_ret_value(kStart + 2, rdi1));
    fn.block_at[bb.start] = fn.blocks.size();
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto ret = std::make_unique<Region>();
    ret->kind = RegionKind::Return;
    ret->condition = rdi1;
    auto body = std::make_unique<Region>();
    body->kind = RegionKind::Seq;
    body->children.push_back(std::move(block));
    body->children.push_back(std::move(ret));

    StructuredFunction sf;
    sf.ir = &fn;
    sf.body = std::move(body);

    PseudoCEmitter em;
    auto pc_r = em.emit(sf, /*binary=*/nullptr,
                        /*annotations=*/nullptr, EmitOptions{});
    check(pc_r.has_value(), "pseudo-c emit returned a phi live-in init body");
    if (!pc_r) return 1;

    check(pc_r->find("(uint64_t a1)") != std::string::npos,
          "phi initializer live-in bumps the function arity");
    check(pc_r->find("uint64_t i = a1;") != std::string::npos,
          "phi live-in operand initializes the mined local");
    check(pc_r->find("i++;") != std::string::npos,
          "phi live-in update renders as a source-style increment");
    check(pc_r->find("return i;") != std::string::npos,
          "phi live-in local is used at return");
    check(pc_r->find("rdi") == std::string::npos,
          "phi live-in output does not leak the raw argument register");

    return 0;
}

int test_phi_accumulator_name_is_mined() {
    using namespace ember;

    constexpr addr_t kStart = 0x402300;

    IrValue rdi1 = IrValue::make_reg(Reg::Rdi, IrType::I64);
    rdi1.version = 1;
    IrValue rdi2 = IrValue::make_reg(Reg::Rdi, IrType::I64);
    rdi2.version = 2;

    IrFunction fn;
    fn.start = kStart;
    fn.end   = kStart + 0x10;
    fn.name  = "phi_accumulator";

    IrBlock bb;
    bb.start = kStart;
    bb.end   = kStart + 0x10;
    bb.kind  = BlockKind::Return;
    bb.insts.push_back(make_phi(rdi1, {IrValue::make_reg(Reg::Rdi, IrType::I64), rdi2}));
    bb.insts.push_back(make_add(rdi2, rdi1, IrValue::make_imm(5, IrType::I64)));
    bb.insts.push_back(make_ret_value(kStart + 2, rdi1));
    fn.block_at[bb.start] = fn.blocks.size();
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto ret = std::make_unique<Region>();
    ret->kind = RegionKind::Return;
    ret->condition = rdi1;
    auto body = std::make_unique<Region>();
    body->kind = RegionKind::Seq;
    body->children.push_back(std::move(block));
    body->children.push_back(std::move(ret));

    StructuredFunction sf;
    sf.ir = &fn;
    sf.body = std::move(body);

    PseudoCEmitter em;
    auto pc_r = em.emit(sf, /*binary=*/nullptr,
                        /*annotations=*/nullptr, EmitOptions{});
    check(pc_r.has_value(), "pseudo-c emit returned a phi accumulator body");
    if (!pc_r) return 1;

    check(pc_r->find("uint64_t acc = a1;") != std::string::npos,
          "non-unit phi add is named as an accumulator");
    check(pc_r->find("acc += 5;") != std::string::npos,
          "non-unit phi add renders as a compound accumulator update");
    check(pc_r->find("return acc;") != std::string::npos,
          "accumulator name is used at return");
    check(pc_r->find("uint64_t i") == std::string::npos,
          "non-unit accumulator is not mislabeled as induction i");

    return 0;
}

int test_phi_index_name_is_mined() {
    using namespace ember;

    constexpr addr_t kStart = 0x402400;

    IrValue eax1 = IrValue::make_reg(Reg::Eax, IrType::I32);
    eax1.version = 1;
    IrValue eax2 = IrValue::make_reg(Reg::Eax, IrType::I32);
    eax2.version = 2;
    IrValue scale = IrValue::make_temp(0, IrType::I64);
    IrValue addr = IrValue::make_temp(1, IrType::I64);
    IrValue val = IrValue::make_temp(2, IrType::I64);

    IrFunction fn;
    fn.start = kStart;
    fn.end   = kStart + 0x10;
    fn.name  = "phi_indexed_load";
    fn.next_temp_id = 3;

    IrBlock bb;
    bb.start = kStart;
    bb.end   = kStart + 0x10;
    bb.kind  = BlockKind::Return;
    bb.insts.push_back(make_phi(eax1, {IrValue::make_reg(Reg::Eax, IrType::I32), eax2}));
    bb.insts.push_back(make_add(eax2, eax1, IrValue::make_imm(1, IrType::I32)));
    bb.insts.push_back(make_mul(scale, eax1, IrValue::make_imm(8, IrType::I64)));
    bb.insts.push_back(make_add(addr, IrValue::make_reg(Reg::Rdi, IrType::I64), scale));
    bb.insts.push_back(make_load(val, addr));
    bb.insts.push_back(make_ret_value(kStart + 5, val));
    fn.block_at[bb.start] = fn.blocks.size();
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto ret = std::make_unique<Region>();
    ret->kind = RegionKind::Return;
    ret->condition = val;
    auto body = std::make_unique<Region>();
    body->kind = RegionKind::Seq;
    body->children.push_back(std::move(block));
    body->children.push_back(std::move(ret));

    StructuredFunction sf;
    sf.ir = &fn;
    sf.body = std::move(body);

    PseudoCEmitter em;
    auto pc_r = em.emit(sf, /*binary=*/nullptr,
                        /*annotations=*/nullptr, EmitOptions{});
    check(pc_r.has_value(), "pseudo-c emit returned a phi indexed-load body");
    if (!pc_r) return 1;

    check(pc_r->find("uint32_t idx") != std::string::npos,
          "unit-step memory-index phi is named idx");
    check(pc_r->find("idx++;") != std::string::npos,
          "indexed phi update renders as an increment");
    check(pc_r->find("return a1[idx];") != std::string::npos,
          "indexed phi name is used in array-like memory access");
    check(pc_r->find("uint32_t i;") == std::string::npos,
          "memory-index phi is not mislabeled as generic induction i");

    return 0;
}

int test_ppc_void_return_merge_becomes_entry_guard() {
    using namespace ember;

    constexpr addr_t kStart = 0x1000;
    constexpr addr_t kBody = 0x1010;
    constexpr addr_t kExit = 0x1020;

    IrValue r3_live = IrValue::make_reg(Reg::PpcR3, IrType::I32);
    IrValue r3_1 = r3_live; r3_1.version = 1;
    IrValue r3_2 = r3_live; r3_2.version = 2;
    IrValue r3_phi = r3_live; r3_phi.version = 7;

    IrFunction fn;
    fn.start = kStart;
    fn.end = kExit + 4;
    fn.name = "ppc_void_callback";

    IrBlock body_bb;
    body_bb.start = kBody;
    body_bb.end = kBody + 4;
    body_bb.kind = BlockKind::Fallthrough;
    body_bb.insts.push_back(make_call_imm(kBody, 0x2000));
    fn.block_at[kBody] = fn.blocks.size();
    fn.blocks.push_back(std::move(body_bb));

    IrBlock exit_bb;
    exit_bb.start = kExit;
    exit_bb.end = kExit + 4;
    exit_bb.kind = BlockKind::Return;
    IrInst c1; c1.op = IrOp::Clobber; c1.dst = r3_1;
    IrInst c2; c2.op = IrOp::Clobber; c2.dst = r3_2;
    exit_bb.insts.push_back(c1);
    exit_bb.insts.push_back(c2);
    exit_bb.insts.push_back(make_phi(r3_phi, {
        r3_live, r3_1, r3_2,
        IrValue::make_imm(1, IrType::I32),
        IrValue::make_imm(2, IrType::I32),
        IrValue::make_imm(3, IrType::I32),
    }));
    exit_bb.insts.push_back(make_ret_value(kExit, r3_phi));
    fn.block_at[kExit] = fn.blocks.size();
    fn.blocks.push_back(std::move(exit_bb));

    auto body_block = std::make_unique<Region>();
    body_block->kind = RegionKind::Block;
    body_block->block_start = kBody;
    auto guarded = std::make_unique<Region>();
    guarded->kind = RegionKind::IfThen;
    guarded->condition = IrValue::make_imm(1, IrType::I1);
    guarded->children.push_back(std::move(body_block));
    auto exit_block = std::make_unique<Region>();
    exit_block->kind = RegionKind::Block;
    exit_block->block_start = kExit;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
    tail->condition = r3_phi;
    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Seq;
    root->children.push_back(std::move(guarded));
    root->children.push_back(std::move(exit_block));
    root->children.push_back(std::move(tail));

    StructuredFunction sf;
    sf.ir = &fn;
    sf.body = std::move(root);

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, nullptr, EmitOptions{});
    check(pc.has_value(), "PPC void-merge pseudo-C emits");
    if (!pc) return 1;

    check(pc->find("void ppc_void_callback(void)") != std::string::npos,
          "incidental PPC r3 merge is inferred as void");
    check(pc->find("if (!1) {\n    return;\n  }\n  sub_2000();") != std::string::npos,
          "void tail if is recovered as an early entry guard");
    check(pc->find("return r3") == std::string::npos,
          "incidental PPC return-register value is not emitted");
    return 0;
}

int test_ppc_small_incidental_return_merge_is_void() {
    using namespace ember;

    constexpr addr_t kStart = 0x1200;
    IrValue r3_1 = IrValue::make_reg(Reg::PpcR3, IrType::I32);
    r3_1.version = 1;
    IrValue r3_phi = r3_1;
    r3_phi.version = 3;

    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x10;
    fn.name = "ppc_small_void_merge";

    IrBlock bb;
    bb.start = kStart;
    bb.end = kStart + 0x10;
    bb.kind = BlockKind::Return;
    IrInst clobber;
    clobber.op = IrOp::Clobber;
    clobber.dst = r3_1;
    bb.insts.push_back(clobber);
    bb.insts.push_back(make_store(IrValue::make_imm(0x3000, IrType::I32),
                                  IrValue::make_imm(4, IrType::I32)));
    IrInst phi = make_phi(r3_phi, {r3_1, IrValue::make_imm(4, IrType::I32)});
    phi.phi_preds = {kStart, kStart};
    bb.insts.push_back(std::move(phi));
    bb.insts.push_back(make_ret_value(kStart + 0xc, r3_phi));
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
    tail->condition = r3_phi;
    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Seq;
    root->children.push_back(std::move(block));
    root->children.push_back(std::move(tail));

    StructuredFunction sf;
    sf.ir = &fn;
    sf.body = std::move(root);

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, nullptr, EmitOptions{});
    check(pc.has_value(), "small incidental PPC return merge emits");
    if (!pc) return 1;
    check(pc->find("void sub_1200(void)") != std::string::npos,
          "small PPC clobber/side-effect merge is inferred as void");
    check(pc->find("return result") == std::string::npos &&
          pc->find("return 4") == std::string::npos,
          "incidental small PPC return value is suppressed");
    return 0;
}

int test_ppc_memory_base_live_in_is_pointer() {
    using namespace ember;

    constexpr addr_t kStart = 0x1300;
    IrValue r3 = IrValue::make_reg(Reg::PpcR3, IrType::I32);
    IrValue r31 = IrValue::make_reg(Reg::PpcR31, IrType::I32);
    r31.version = 1;
    IrValue addr = IrValue::make_temp(0, IrType::I32);

    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x10;
    fn.name = "ppc_pointer_arg";
    fn.next_temp_id = 1;

    IrBlock bb;
    bb.start = kStart;
    bb.end = kStart + 0x10;
    bb.kind = BlockKind::Return;
    bb.insts.push_back(make_assign(r31, r3));
    bb.insts.push_back(make_add(addr, r31, IrValue::make_imm(0x28, IrType::I32)));
    bb.insts.push_back(make_store(addr, IrValue::make_imm(7, IrType::I32)));
    bb.insts.push_back(make_ret(kStart + 0xc));
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Seq;
    root->children.push_back(std::move(block));
    root->children.push_back(std::move(tail));

    StructuredFunction sf;
    sf.ir = &fn;
    sf.body = std::move(root);

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, nullptr, EmitOptions{});
    check(pc.has_value(), "PPC pointer-shaped parameter emits");
    if (!pc) return 1;
    check(pc->find("void sub_1300(void* a1)") != std::string::npos,
          "PPC live-in copied to a memory base is typed as void pointer");
    return 0;
}

int test_ppc_mixed_call_arguments_follow_callee_layout() {
    using namespace ember;

    IrFunction fn;
    fn.start = 0x1000;
    fn.end = 0x1010;
    fn.name = "mixed_caller";

    IrBlock bb;
    bb.start = 0x1000;
    bb.end = 0x1010;
    bb.kind = BlockKind::Return;

    IrInst int_args;
    int_args.op = IrOp::Intrinsic;
    int_args.name = "call.args.1";
    int_args.srcs[0] = IrValue::make_imm(11, IrType::I32);
    int_args.srcs[1] = IrValue::make_imm(22, IrType::I32);
    int_args.src_count = 2;
    bb.insts.push_back(int_args);

    IrInst fp_args;
    fp_args.op = IrOp::Intrinsic;
    fp_args.name = "call.fp_args.1";
    fp_args.srcs[0] = IrValue::make_imm(
        static_cast<i64>(0x3ff0000000000000ULL), IrType::F64);  // 1.0
    fp_args.srcs[1] = IrValue::make_imm(
        static_cast<i64>(0x4000000000000000ULL), IrType::F64);  // 2.0
    fp_args.src_count = 2;
    bb.insts.push_back(fp_args);
    bb.insts.push_back(make_call_imm(0x1008, 0x1100));
    IrInst ret;
    ret.op = IrOp::Return;
    bb.insts.push_back(ret);
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = 0x1000;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Seq;
    root->children.push_back(std::move(block));
    root->children.push_back(std::move(tail));

    StructuredFunction sf;
    sf.ir = &fn;
    sf.body = std::move(root);

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, nullptr, EmitOptions{});
    check(pc.has_value(), "mixed PPC call pseudo-C emits");
    if (!pc) return 1;
    const bool ordered =
        pc->find("mixed_callee(1, 0xb, 2, 0x16)") != std::string::npos;
    if (!ordered) std::fprintf(stderr, "mixed PPC output:\n%s\n", pc->c_str());
    check(ordered, "mixed PPC call follows f1,r3,f2,r4 callee order");
    return 0;
}

int test_ppc_known_float_call_binds_f1_result() {
    using namespace ember;

    constexpr addr_t kStart = 0x1400;
    IrValue f1 = IrValue::make_reg(Reg::PpcF1, IrType::F64);
    f1.version = 1;
    IrValue f31 = IrValue::make_reg(Reg::PpcF31, IrType::F64);
    f31.version = 1;

    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x14;
    fn.name = "ppc_float_call";

    IrBlock bb;
    bb.start = kStart;
    bb.end = kStart + 0x14;
    bb.kind = BlockKind::Return;

    IrInst args;
    args.op = IrOp::Intrinsic;
    args.name = "call.args.1";
    args.srcs[0] = IrValue::make_imm(0x3000, IrType::I32);
    args.src_count = 1;
    bb.insts.push_back(args);
    bb.insts.push_back(make_call_imm(kStart + 4, 0x1800));
    bb.insts.push_back(make_clobber(f1));
    bb.insts.push_back(make_assign(f31, f1));
    bb.insts.push_back(make_store(IrValue::make_imm(0x4000, IrType::I32), f31));
    bb.insts.push_back(make_ret(kStart + 0x10));
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Seq;
    root->children.push_back(std::move(block));
    root->children.push_back(std::move(tail));

    StructuredFunction sf;
    sf.ir = &fn;
    sf.body = std::move(root);

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, nullptr, EmitOptions{});
    check(pc.has_value(), "known PPC float-return call emits");
    if (!pc) return 1;
    const bool binds_float =
        pc->find("float r_PSVecMag = PSVecMag(") != std::string::npos;
    if (!binds_float) std::fprintf(stderr, "PPC float call output:\n%s\n", pc->c_str());
    check(binds_float, "known PSVecMag result is bound from f1 as float");
    check(pc->find("f1_1") == std::string::npos &&
          pc->find("f31_1") == std::string::npos,
          "known float call does not leak raw FPR SSA names");
    return 0;
}

int test_ppc_annotated_float_call_selects_f1() {
    using namespace ember;

    constexpr addr_t kStart = 0x1500;
    constexpr addr_t kTarget = 0x1600;
    IrValue f1 = IrValue::make_reg(Reg::PpcF1, IrType::F64);
    f1.version = 1;

    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x10;
    fn.name = "ppc_annotated_float_call";

    IrBlock bb;
    bb.start = kStart;
    bb.end = kStart + 0x10;
    bb.kind = BlockKind::Return;
    bb.insts.push_back(make_call_imm(kStart, kTarget));
    bb.insts.push_back(make_clobber(f1));
    bb.insts.push_back(make_store(IrValue::make_imm(0x5000, IrType::I32), f1));
    bb.insts.push_back(make_ret(kStart + 0xc));
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Seq;
    root->children.push_back(std::move(block));
    root->children.push_back(std::move(tail));

    StructuredFunction sf;
    sf.ir = &fn;
    sf.body = std::move(root);

    Annotations ann;
    FunctionSig sig;
    sig.return_type = "float";
    ann.signatures[kTarget] = std::move(sig);

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, &ann, EmitOptions{});
    check(pc.has_value(), "annotated PPC float-return call emits");
    if (!pc) return 1;
    check(pc->find("float r_sub_1600 = sub_1600()") != std::string::npos,
          "annotated float signature selects and types the f1 result lane");
    check(pc->find("f1_1") == std::string::npos,
          "annotated float call does not leak the f1 SSA name");
    return 0;
}

int test_ppc_sdk_signature_seeds_mixed_lanes() {
    using namespace ember;

    IrFunction fn;
    fn.start = 0x1700;
    fn.end = 0x1720;
    fn.name = "ppc_sdk_seed";

    IrBlock bb;
    bb.start = fn.start;
    bb.end = fn.end;
    bb.kind = BlockKind::Return;

    IrInst int_args;
    int_args.op = IrOp::Intrinsic;
    int_args.name = "call.args.1";
    int_args.srcs[0] = IrValue::make_reg(Reg::PpcR3, IrType::I32);
    int_args.srcs[1] = IrValue::make_reg(Reg::PpcR4, IrType::I32);
    int_args.srcs[2] = IrValue::make_reg(Reg::PpcR5, IrType::I32);
    int_args.src_count = 3;
    bb.insts.push_back(int_args);

    IrInst fp_args;
    fp_args.op = IrOp::Intrinsic;
    fp_args.name = "call.fp_args.1";
    fp_args.srcs[0] = IrValue::make_reg(Reg::PpcF1, IrType::F64);
    fp_args.src_count = 1;
    bb.insts.push_back(fp_args);
    bb.insts.push_back(make_call_imm(0x1708, 0x1a00));
    bb.insts.push_back(make_ret(0x170c));
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

    MockPpcBinary binary;
    seed_call_return_types(binary, fn);

    const auto type_of = [&](Reg reg, IrType type) {
        IrValue value = IrValue::make_reg(reg, type);
        value.version = 0;
        return fn.type_of(value);
    };
    check(fn.types.kind(type_of(Reg::PpcR3, IrType::I32)) == TypeKind::Ptr,
          "PSVECScale first pointer seeds r3");
    check(fn.types.kind(type_of(Reg::PpcR4, IrType::I32)) == TypeKind::Ptr,
          "PSVECScale second pointer seeds r4");
    check(fn.types.kind(type_of(Reg::PpcF1, IrType::F64)) == TypeKind::Float,
          "PSVECScale scalar seeds f1");
    check(type_of(Reg::PpcR5, IrType::I32).is_top(),
          "PSVECScale floating scalar does not incorrectly seed r5");
    return 0;
}

int test_ppc_annotated_stack_argument_at_call_site() {
    using namespace ember;

    constexpr addr_t kStart = 0x1c00;
    constexpr addr_t kTarget = 0x1b00;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x24;
    fn.name = "stack_caller";

    IrBlock bb;
    bb.start = kStart;
    bb.end = fn.end;
    bb.kind = BlockKind::Return;

    IrValue stack_addr = IrValue::make_temp(0, IrType::I32);
    bb.insts.push_back(make_add(stack_addr,
        IrValue::make_reg(Reg::PpcR1, IrType::I32),
        IrValue::make_imm(0x28, IrType::I32)));
    bb.insts.push_back(make_store(stack_addr,
                                 IrValue::make_imm(9, IrType::I32)));
    for (std::size_t group = 0; group < 3; ++group) {
        IrInst args;
        args.op = IrOp::Intrinsic;
        args.name = std::format("call.args.{}", group + 1);
        for (std::size_t lane = 0; lane < 3; ++lane) {
            const std::size_t index = group * 3 + lane;
            if (index >= 8) break;
            args.srcs[args.src_count++] =
                IrValue::make_imm(static_cast<i64>(index + 1), IrType::I32);
        }
        bb.insts.push_back(std::move(args));
    }
    bb.insts.push_back(make_call_imm(kStart + 0x18, kTarget));
    bb.insts.push_back(make_ret(kStart + 0x1c));
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

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

    Annotations ann;
    FunctionSig sig;
    sig.return_type = "void";
    for (int i = 1; i <= 9; ++i) {
        sig.params.push_back({"uint32_t", std::format("p{}", i)});
    }
    ann.signatures[kTarget] = std::move(sig);

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, &ann, EmitOptions{});
    check(pc.has_value(), "PPC outgoing stack argument emits");
    if (!pc) return 1;
    const bool recovered = pc->find(
        "stack_nine(1, 2, 3, 4, 5, 6, 7, 8, 9)") != std::string::npos;
    if (!recovered) std::fprintf(stderr, "PPC stack call output:\n%s\n", pc->c_str());
    check(recovered, "ninth PPC integer argument is recovered from sp+0x28");
    check(pc->find("arg_28") == std::string::npos,
          "outgoing PPC argument store is not emitted as a local assignment");
    return 0;
}

int test_ppc_annotated_incoming_stack_argument_name() {
    using namespace ember;

    constexpr addr_t kStart = 0x1b00;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x10;
    fn.name = "stack_nine";

    IrBlock bb;
    bb.start = kStart;
    bb.end = fn.end;
    bb.kind = BlockKind::Return;
    IrValue addr = IrValue::make_temp(0, IrType::I32);
    IrValue value = IrValue::make_temp(1, IrType::I32);
    bb.insts.push_back(make_add(addr,
        IrValue::make_reg(Reg::PpcR1, IrType::I32),
        IrValue::make_imm(0x28, IrType::I32)));
    bb.insts.push_back(make_load(value, addr));
    bb.insts.push_back(make_ret_value(kStart + 8, value));
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

    auto block = std::make_unique<Region>();
    block->kind = RegionKind::Block;
    block->block_start = kStart;
    auto tail = std::make_unique<Region>();
    tail->kind = RegionKind::Return;
    tail->condition = value;
    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Seq;
    root->children.push_back(std::move(block));
    root->children.push_back(std::move(tail));
    StructuredFunction sf{&fn, std::move(root)};

    Annotations ann;
    FunctionSig sig;
    sig.return_type = "uint32_t";
    for (int i = 1; i <= 9; ++i) {
        sig.params.push_back({"uint32_t", i == 9 ? "ninth" : std::format("p{}", i)});
    }
    ann.signatures[kStart] = std::move(sig);

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, &ann, EmitOptions{});
    check(pc.has_value(), "PPC incoming stack argument emits");
    if (!pc) return 1;
    const bool named = pc->find("return ninth;") != std::string::npos;
    if (!named) std::fprintf(stderr, "PPC incoming stack output:\n%s\n", pc->c_str());
    check(named,
          "incoming sp+0x28 load uses the annotated ninth parameter name");
    check(pc->find("arg_28") == std::string::npos,
          "incoming PPC overflow parameter does not leak a synthetic slot name");
    return 0;
}

int test_ppc_hidden_sret_shifts_declared_call_arguments() {
    using namespace ember;

    constexpr addr_t kStart = 0x1e00;
    constexpr addr_t kTarget = 0x1d00;
    IrValue r3_result = IrValue::make_reg(Reg::PpcR3, IrType::I32);
    r3_result.version = 1;

    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x14;
    fn.name = "sret_caller";
    IrBlock bb;
    bb.start = kStart;
    bb.end = fn.end;
    bb.kind = BlockKind::Return;

    IrInst args;
    args.op = IrOp::Intrinsic;
    args.name = "call.args.1";
    args.srcs[0] = IrValue::make_imm(0x3000, IrType::I32);  // hidden result buffer
    args.srcs[1] = IrValue::make_imm(7, IrType::I32);       // declared tag
    args.src_count = 2;
    bb.insts.push_back(args);
    bb.insts.push_back(make_call_imm(kStart + 4, kTarget));
    bb.insts.push_back(make_clobber(r3_result));
    bb.insts.push_back(make_store(IrValue::make_imm(0x5000, IrType::I32),
                                  r3_result));
    bb.insts.push_back(make_ret(kStart + 0x10));
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

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

    Annotations ann;
    FunctionSig sig;
    sig.return_type = "Vec3";
    sig.params.push_back({"uint32_t", "tag"});
    ann.signatures[kTarget] = std::move(sig);

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, &ann, EmitOptions{});
    check(pc.has_value(), "PPC hidden-sret call emits");
    if (!pc) return 1;
    const bool shifted = pc->find("Vec3 r_make_vec = make_vec(7)") !=
        std::string::npos;
    if (!shifted) std::fprintf(stderr, "PPC sret output:\n%s\n", pc->c_str());
    check(shifted, "large aggregate return hides r3 and maps first parameter to r4");
    check(pc->find("make_vec(0x3000") == std::string::npos,
          "hidden PPC result-buffer pointer is not emitted as a source argument");
    return 0;
}

int test_ppc_small_aggregate_consumes_multiple_gprs() {
    using namespace ember;

    constexpr addr_t kStart = 0x2000;
    constexpr addr_t kTarget = 0x1f00;
    IrFunction fn;
    fn.start = kStart;
    fn.end = kStart + 0x10;
    fn.name = "aggregate_caller";
    IrBlock bb;
    bb.start = kStart;
    bb.end = fn.end;
    bb.kind = BlockKind::Return;

    IrInst args;
    args.op = IrOp::Intrinsic;
    args.name = "call.args.1";
    args.srcs[0] = IrValue::make_imm(0x11, IrType::I32);
    args.srcs[1] = IrValue::make_imm(0x22, IrType::I32);
    args.srcs[2] = IrValue::make_imm(9, IrType::I32);
    args.src_count = 3;
    bb.insts.push_back(args);
    bb.insts.push_back(make_call_imm(kStart + 4, kTarget));
    bb.insts.push_back(make_ret(kStart + 8));
    fn.block_at[bb.start] = 0;
    fn.blocks.push_back(std::move(bb));

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

    Annotations ann;
    FunctionSig sig;
    sig.return_type = "void";
    sig.params.push_back({"CXParsedHeader", "header"});
    sig.params.push_back({"uint32_t", "flags"});
    ann.signatures[kTarget] = std::move(sig);

    MockPpcBinary binary;
    PseudoCEmitter emitter;
    auto pc = emitter.emit(sf, &binary, &ann, EmitOptions{});
    check(pc.has_value(), "PPC small aggregate call emits");
    if (!pc) return 1;
    const bool aligned = pc->find(
        "consume_header((CXParsedHeader){0x11, 0x22}, 9)") != std::string::npos;
    if (!aligned) std::fprintf(stderr, "PPC aggregate output:\n%s\n", pc->c_str());
    check(aligned, "eight-byte aggregate consumes r3/r4 and following scalar uses r5");
    check(pc->find("}, 0x22)") == std::string::npos,
          "second aggregate word stays inside the aggregate compound literal");
    return 0;
}

}  // namespace

int main() {
    int rc = 0;
    rc |= test_dropped_block_diagnostic();
    rc |= test_infinite_loop_body_recovered();
    rc |= test_phi_merge_names_are_mined();
    rc |= test_phi_induction_name_is_mined();
    rc |= test_phi_livein_initializer_is_mined();
    rc |= test_phi_accumulator_name_is_mined();
    rc |= test_phi_index_name_is_mined();
    rc |= test_ppc_void_return_merge_becomes_entry_guard();
    rc |= test_ppc_small_incidental_return_merge_is_void();
    rc |= test_ppc_memory_base_live_in_is_pointer();
    rc |= test_ppc_mixed_call_arguments_follow_callee_layout();
    rc |= test_ppc_known_float_call_binds_f1_result();
    rc |= test_ppc_annotated_float_call_selects_f1();
    rc |= test_ppc_sdk_signature_seeds_mixed_lanes();
    rc |= test_ppc_annotated_stack_argument_at_call_site();
    rc |= test_ppc_annotated_incoming_stack_argument_name();
    rc |= test_ppc_hidden_sret_shifts_declared_call_arguments();
    rc |= test_ppc_small_aggregate_consumes_multiple_gprs();
    return (fails == 0 && rc == 0) ? 0 : 1;
}
