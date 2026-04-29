#pragma once

#include <cstddef>
#include <vector>

#include <ember/common/error.hpp>
#include <ember/common/types.hpp>
#include <ember/debug/target.hpp>

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
// nonsense for frames past the innermost. The eventual `.eh_frame`
// unwinder will replace this — for v0 the rule is "live with it".
[[nodiscard]] Result<std::vector<Frame>> unwind_rbp(
    Target& t, ThreadId tid, std::size_t max_frames = 256);

}  // namespace ember::debug
