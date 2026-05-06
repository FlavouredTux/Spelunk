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

}  // namespace

int main() {
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

    return fails == 0 ? 0 : 1;
}
