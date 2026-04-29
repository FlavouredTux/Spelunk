#pragma once

#include <cstddef>
#include <vector>

#include <ember/common/error.hpp>
#include <ember/common/types.hpp>
#include <ember/debug/target.hpp>

namespace ember { class Binary; }

namespace ember::debug {

// One stack frame in a backtrace. `sp` is meaningful only for the
// innermost frame (the live RSP); for frames above we only know the
// saved frame pointer and return address.
struct Frame {
    addr_t pc = 0;
    addr_t fp = 0;
    addr_t sp = 0;
};

// Frame-pointer walk for x86-64 binaries built with frame pointers
// (`-fno-omit-frame-pointer`, the default outside `-O2`/`-O3`). The
// walker assumes the prologue is `push rbp; mov rbp, rsp`, so each
// frame has saved-RBP at [rbp] and return address at [rbp+8]. It
// stops when RBP is zero, doesn't advance, or the read fails.
//
// On binaries compiled with `-fomit-frame-pointer` this returns
// nonsense for frames past the innermost. Use unwind_eh_frame when
// the binary carries .eh_frame CFI.
[[nodiscard]] Result<std::vector<Frame>> unwind_rbp(
    Target& t, ThreadId tid, std::size_t max_frames = 256);

// DWARF .eh_frame-driven unwinder. Looks up the FDE covering each
// frame's PC, runs the CFI VM, and uses the resulting register-save
// rules to walk to the parent frame. Works on `-fomit-frame-pointer`
// binaries and tolerates frames where RBP isn't preserved.
//
// `slide` is the PIE/ASLR offset (live PC = static PC + slide); the
// adapter un-slides before consulting the binary's .eh_frame and
// re-slides the recovered return address before reporting.
//
// Stops when CFI is unavailable for a frame (no FDE / DWARF
// expression / malformed); callers wanting a hybrid trace should
// fall back to unwind_rbp at that point.
[[nodiscard]] Result<std::vector<Frame>> unwind_eh_frame(
    Target& t, ThreadId tid, const Binary& bin, addr_t slide,
    std::size_t max_frames = 256);

}  // namespace ember::debug
