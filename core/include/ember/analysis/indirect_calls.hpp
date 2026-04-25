#pragma once

#include <map>

#include <ember/binary/binary.hpp>
#include <ember/common/types.hpp>

namespace ember {

// Global indirect-call resolver. Walks every discovered function's SSA IR
// looking for `CallIndirect` whose target traces back to one of:
//
//   1. `Load(imm_addr)` where imm_addr is a known import GOT slot — the
//      thunk's PLT/IAT address is recorded.
//   2. `Load(imm_addr + small_const)` — same as above, one arithmetic hop.
//   3. Vtable dispatch through a constant vtable address: the SSA def-walk
//      bottoms out at `Load(vtable_const + slot*8)`. Resolved against the
//      union of Itanium (`parse_itanium_rtti`) and MSVC (`parse_msvc_rtti`)
//      vtable indices.
//
// Result keys are call-site instruction VAs; values are resolved target
// VAs. Consumed by `EmitOptions::call_resolutions` so the pseudo-C
// emitter renders `(*(u64*)(...))(this)` as a named function call.
//
// Only fires when the receiver/vtable resolves to a CONSTANT — runtime
// receiver-typed dispatch needs IPA (Phase 3) and is intentionally
// out of scope here.
[[nodiscard]] std::map<addr_t, addr_t>
resolve_indirect_calls(const Binary& b);

}  // namespace ember
