#pragma once

#include <optional>
#include <span>
#include <string>

#include <ember/common/types.hpp>

namespace ember { class Binary; }

namespace ember::cli {

struct Args;

// One aux symbol oracle pre-loaded by main.cpp. `manual_base` when
// non-empty pins the runtime base (slide = manual_base - bin's
// preferred_load_base()); otherwise the debugger auto-detects it by
// matching `bin->mapped_size()` against /proc/<pid>/maps anon-rwx
// regions after attach.
struct AuxBinarySpec {
    const Binary*        bin = nullptr;
    std::string          path;
    std::optional<addr_t> manual_base;
};

// Enter the debugger REPL. `bin` may be null in attach-only mode (no
// binary path supplied) — symbol lookup is then disabled but address-
// only commands still work. `aux` is a list of secondary Binary
// objects the debugger consults as additional symbol oracles, one
// per --aux-binary CLI flag. Returns the process exit code.
int run_debug(const Args& args, const Binary* bin,
              std::span<const AuxBinarySpec> aux);

}  // namespace ember::cli
