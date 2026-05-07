// Unit test for the structurer's drop-block diagnostic.
//
// Builds a synthetic IrFunction with one reachable Return block plus a
// disconnected dangling block (no predecessors, no successor edges from
// the entry). The structurer's build_sequence walks from `start` and
// never visits the dangling block — without the fix this dropped a
// real call silently. The fix surfaces the omission as a
// `STRUCTURER_FAIL: <lo>..<hi>` marker carrying the disconnected
// block's address range.

#include <ember/decompile/emitter.hpp>
#include <ember/ir/ir.hpp>
#include <ember/structure/region.hpp>
#include <ember/structure/structurer.hpp>

#include <cstdio>
#include <string>

namespace {

int fails = 0;

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

ember::IrInst make_branch(ember::addr_t pc, ember::addr_t target) {
    ember::IrInst bi;
    bi.op          = ember::IrOp::Branch;
    bi.source_addr = pc;
    bi.target1     = target;
    return bi;
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
    // shape — single block, kind=Return, no successors. The structurer
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

    // The dangling block isn't in the structured tree — confirm the
    // marker text carries its exact range so a reader can reach for
    // `--disasm-at 0x10404a8db` to see what the structurer dropped.
    const std::string expected_marker =
        "STRUCTURER_FAIL: 0x10404a8db..0x10404a8e0 (see --disasm-at)";
    check(structured_text.find(expected_marker) != std::string::npos,
          "format_structured emits STRUCTURER_FAIL for dropped block");

    // The reachable block should still be referenced by the structured
    // body — guards against the diagnostic firing on every block (which
    // would happen if the rendered-set walk got the predicate inverted).
    check(structured_text.find("STRUCTURER_FAIL: 0x10404a846") == std::string::npos,
          "reachable block does not get a STRUCTURER_FAIL marker");

    // The pseudo-C emitter's body output should also surface the
    // marker — the failure diagnostic must reach the actual rendered
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

    // bb_b's address must appear in the rendered tree — the body block
    // would be omitted under the pre-fix `RegionKind::Loop` branch.
    const std::string bb_b_marker = std::format("bb_{:x}", kB);
    check(structured_text.find(bb_b_marker) != std::string::npos,
          "infinite-loop body block surfaces in the structured output");

    // And no STRUCTURER_FAIL should fire for either block — the diagnostic
    // is a safety net, not a substitute for actually rendering the body.
    check(structured_text.find("STRUCTURER_FAIL") == std::string::npos,
          "no STRUCTURER_FAIL fires for a recovered infinite-loop body");

    return 0;
}

}  // namespace

int main() {
    int rc = 0;
    rc |= test_dropped_block_diagnostic();
    rc |= test_infinite_loop_body_recovered();
    return (fails == 0 && rc == 0) ? 0 : 1;
}
