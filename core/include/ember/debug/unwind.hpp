#pragma once

#include <cstddef>
#include <span>
#include <vector>

#include <ember/common/error.hpp>
#include <ember/common/types.hpp>
#include <ember/debug/target.hpp>

namespace ember { class Binary; }

namespace ember::debug {

// One stack frame in a backtrace. `sp` is meaningful only for the
// innermost frame (the live RSP); for frames above we only know the
// saved frame pointer and return address. `scavenged` flags frames
// recovered by the heuristic stack-scan unwinder rather than CFI or
// RBP-walk — they're not guaranteed to be real call sites; the user
// should sanity-check before trusting one.
struct Frame {
    addr_t pc        = 0;
    addr_t fp        = 0;
    addr_t sp        = 0;
    bool   scavenged = false;
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

// Heuristic stack-scan ("scavenged") unwinder for code where neither
// CFI nor RBP-walk gives anything useful — Rust panics through
// abort-shim shims, control-flow-flattened code, hand-rolled
// assembler that doesn't carry .eh_frame. We read a window starting
// at RSP and label every qword that falls inside a known function's
// extent. False positives are tolerated; the caller renders the
// result as `*scavenged*` so the user knows not to trust the order.
//
// Each (Binary*, slide) pair is consulted in order; the first hit
// wins. `window_qwords` bounds the read so a runaway RSP can't
// stall the debugger.
struct BinarySlide {
    const Binary* bin   = nullptr;
    addr_t        slide = 0;
};

[[nodiscard]] Result<std::vector<Frame>> unwind_scavenge(
    Target& t, ThreadId tid, std::span<const BinarySlide> bins,
    std::size_t window_qwords = 256);

}  // namespace ember::debug
