#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/common/error.hpp>
#include <ember/common/types.hpp>

namespace ember::analysis {

// One entry from a packed NUL-terminated string table. `length` is the
// byte length excluding the terminating NUL; `text` holds the full
// string content.
struct SymtableEntry {
    addr_t       va;
    std::size_t  offset;
    std::size_t  length;
    std::string  text;
};

enum class SymtableTermination {
    PaddingRun,    // 4+ consecutive NULs after a string terminator
    NonPrintable,  // byte < 0x20 (other than NUL) or > 0x7e
    SegmentEnd,    // walked off the end of the readable span
    HardCap,       // exceeded the 1 MB sanity bound
};

struct SymtableWalk {
    std::vector<SymtableEntry> entries;
    addr_t                     base_va;
    std::size_t                table_size;   // bytes consumed
    addr_t                     end_va;       // base_va + table_size
    SymtableTermination        terminated_by;
};

// Walk a packed NUL-terminated string table starting at `va`. Stops on
// the first termination criterion: 4+ NUL run after a terminator, a
// non-printable non-NUL byte, end of the readable segment, or the 1 MB
// sanity cap. Returns an error when `va` is not in any loadable
// segment.
[[nodiscard]] Result<SymtableWalk>
walk_symtable(const Binary& b, addr_t va);

// One named category of symbols (loader / env / exec / mmap /
// anti-tamper / syscall / threading). The matcher is keyword-based and
// a single symbol may match multiple categories.
struct SymtableCategory {
    std::string_view name;
    std::vector<std::string_view> hits;   // matched symbol names, in walk order
};

// Bucket the entries from a walk into the built-in category list. Only
// non-empty categories are returned, in fixed display order.
[[nodiscard]] std::vector<SymtableCategory>
categorize_symtable(const SymtableWalk& walk);

// Stable display name for a termination cause. Used in human-readable
// summaries.
[[nodiscard]] std::string_view
symtable_termination_name(SymtableTermination t) noexcept;

}  // namespace ember::analysis
