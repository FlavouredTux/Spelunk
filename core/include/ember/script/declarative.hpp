#pragma once

#include <cstddef>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <ember/common/annotations.hpp>
#include <ember/common/error.hpp>

namespace ember {

class Binary;

namespace script {

// Declarative project script (`*.ember`). A flat, section-keyed config
// file consumed by `apply()` to populate / mutate an `Annotations`
// struct. No expressions or control flow — every directive is a single
// key=value (or pattern->template) pair. Designed for the high-volume
// but low-complexity workflows: bulk renames, signature batches,
// log-format driven recovery, glob renames over the discovered
// function set.
//
// Sections (case-insensitive):
//
//   [rename]
//     0x401234 = do_thing                    # by VA
//     sub_4051a0 = main_loop                 # by sub_-name
//     resolve_path = resolve_canonical_path  # by user-rename or symbol
//
//   [note]
//     0x401234 = entry point; see ticket #42
//     do_thing = first thing the binary does
//
//   [signature]
//     0x401234 = int do_thing(char* name, int x)
//     do_thing = void do_thing(void)
//
//   [pattern-rename]
//     sub_4* -> roblox_sub_*                 # `*` in template = matched part
//
//   [from-strings]
//     "[HttpClient] %s" -> HttpClient_$1     # captured %s/%d/%* → $1, $2, …
//     "NetworkClient::%s" -> NetworkClient_$1
//
//   [delete]
//     0x401234   = rename                    # drop one entry kind
//     log_handler = all                      # drop rename + note + signature
//
// Comments start with `#`. Mid-line ` # …` (whitespace before `#`,
// outside `"..."`) is also treated as a trailing comment, so values
// like `note = see ticket #42` keep `#42`. Quoted forms `"..."` allow
// values with spaces or special characters; standard escapes
// (`\\`, `\"`, `\n`, `\t`).

struct Directive {
    enum class Kind : u8 {
        Rename,
        Note,
        Signature,
        PatternRename,
        FromStrings,
        Delete,
    };
    Kind        kind = Kind::Rename;
    std::string lhs;        // VA, identifier, glob, or string-pattern
    std::string rhs;        // new name, note, signature decl, template, or delete-kind
    std::size_t line = 0;   // 1-based source line, for error/warning context
};

[[nodiscard]] Result<std::vector<Directive>>
parse(std::string_view text);

[[nodiscard]] Result<std::vector<Directive>>
parse_file(const std::filesystem::path& path);

struct ApplyStats {
    std::size_t renames_added            = 0;
    std::size_t notes_added              = 0;
    std::size_t signatures_added         = 0;
    std::size_t pattern_renames_applied  = 0;
    std::size_t string_renames_applied   = 0;
    std::size_t renames_removed          = 0;
    std::size_t notes_removed            = 0;
    std::size_t signatures_removed       = 0;
    // Non-fatal issues encountered while applying directives:
    // unresolvable names, malformed signature bodies, glob templates
    // that produced empty names, etc. Each entry is prefixed with the
    // source line number.
    std::vector<std::string> warnings;
};

// Apply parsed directives to `ann`, using `b` for symbol lookup,
// pattern-walking the discovered-function set, and string-xref
// resolution. Direct VA / name → action directives are applied first;
// pattern-rename and from-strings are best-effort and only assign to
// addresses without an existing user rename. `ann` is mutated in place.
[[nodiscard]] ApplyStats
apply(std::span<const Directive> directives,
      const Binary& b,
      Annotations& ann);

// Convenience wrapper that parses + applies in one call.
[[nodiscard]] Result<ApplyStats>
apply_file(const std::filesystem::path& path,
           const Binary& b,
           Annotations& ann);

}  // namespace script
}  // namespace ember
