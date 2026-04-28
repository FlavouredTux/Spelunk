#pragma once

#include <map>
#include <string>

#include <ember/common/types.hpp>
#include <ember/ir/ir.hpp>

namespace ember {

class Binary;

// One recovered stack-frame slot. `offset` is signed, measured from
// the function's entry-rsp. Negative ⇒ local (below saved rsp);
// positive ⇒ stack-passed argument (above saved rsp); zero is the
// return-address slot and is never declared.
//
// `type_override` is set non-empty when an external source (PDB) gave
// a richer type name than IrType can express ("int", "Player*",
// "wchar_t"). Empty means consumers should fall back to IrType.
struct FrameSlot {
    i64         offset      = 0;
    std::string name;
    IrType      type        = IrType::I64;
    u32         size_bytes  = 0;     // 0 = not yet observed
    std::string type_override;
};

struct StackFrameLayout {
    std::map<i64, FrameSlot> slots;
    [[nodiscard]] bool empty() const noexcept { return slots.empty(); }
};

// Walk every Load/Store, trace each address back to entry-rsp/rbp,
// and build a flat map of distinct slots. Synthetic names:
// `local_<hex>` for negative offsets, `arg_<hex>` for positive.
// Per-slot type = widest observed access width (a slot read as both
// u32 and u64 ends up u64; the access-site cast in the body still
// shows the actual width).
//
// When `binary` is a PE with PDB-attached, S_BPREL32 / S_REGREL32
// hints for `fn.start` get merged in: their offsets are converted to
// entry-rsp-relative using the analysis-derived frame size (deepest
// observed offset), and matching slots get the PDB name + rendered
// type string. PDB hints with no analysis match still surface as
// fresh slots so the user gets every named local declared.
[[nodiscard]] StackFrameLayout
compute_frame_layout(const IrFunction& fn, const Binary* binary = nullptr);

}  // namespace ember
