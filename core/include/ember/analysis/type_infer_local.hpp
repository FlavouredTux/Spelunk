#pragma once

#include <ember/ir/ir.hpp>

namespace ember {

// Phase 2 type inference: refine `Top` to concrete types within a single
// function using the operations each SSA value participates in. Populates
// `fn.value_types` in place; safe to call more than once (idempotent — a
// second run meets the same evidence into the same lattice points).
//
// Rules (intra-procedural, no call-graph awareness yet):
//   * Load/Store address operand → Ptr(Int{access_width})
//   * SExt result → signed Int; ZExt result → unsigned Int
//   * Ashr first operand → signed; Lshr first operand → unsigned
//   * CmpSlt/Sle/Sgt/Sge operands → signed; CmpUlt/Ule/Ugt/Uge → unsigned
//   * Assign / Phi propagate the source type to the dest
//   * Add(Ptr, *) and Add(*, Ptr) → Ptr (pointer arithmetic)
//
// Bounded fixpoint (≤ 10 sweeps); no global cleanup invariants are
// touched, so this pass is safe to run after run_cleanup() and before
// structuring + emit.
void infer_local_types(IrFunction& fn);

}  // namespace ember
