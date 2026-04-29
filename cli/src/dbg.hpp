#pragma once

namespace ember { class Binary; }

namespace ember::cli {

struct Args;

// Enter the debugger REPL. `bin` may be null in attach-only mode (no
// binary path supplied) — symbol lookup is then disabled but address-
// only commands still work. Returns the process exit code.
int run_debug(const Args& args, const Binary* bin);

}  // namespace ember::cli
