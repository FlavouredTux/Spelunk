#pragma once

#include <map>
#include <optional>
#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/common/types.hpp>

namespace ember {

// One RUNTIME_FUNCTION entry from a PE image's `.pdata` section. Addresses
// are absolute VAs (image_base + RVA), consistent with everything else
// Ember exposes. Always sorted ascending by `begin`, duplicates removed.
struct PeUnwindEntry {
    addr_t begin;
    addr_t end;
    // UnwindInfoAddress as an absolute VA. Zero for chained entries and
    // when the .xdata can't be reached.
    addr_t unwind_info;
};

// Walk IMAGE_DIRECTORY_ENTRY_EXCEPTION on a PE binary and return every
// RUNTIME_FUNCTION entry. Returns empty for non-PE binaries or when the
// directory is absent. x86-64 entries only; ARM64 uses a variable-length
// packed format that this parser does not handle.
[[nodiscard]] std::vector<PeUnwindEntry>
parse_pe_pdata(const Binary& b);

// One decoded UNWIND_CODE slot from an UNWIND_INFO record.
struct UnwindCode {
    u8  code_offset;   // offset within prologue (bytes)
    u8  op;            // UWOP_*
    u8  op_info;
    u32 operand;       // resolved value: alloc size, save offset, etc. 0 if N/A.
};

// Microsoft x86-64 UNWIND_INFO header + decoded codes.
struct ParsedUnwindInfo {
    u8  version;
    u8  flags;
    u8  size_of_prolog;        // BYTES from function start
    u8  frame_register;        // 0 = no frame reg; otherwise reg index
    u8  frame_register_offset;
    std::vector<UnwindCode> codes;
    addr_t handler_rva = 0;    // 0 if no UNW_FLAG_*HANDLER
    addr_t chained_va  = 0;    // 0 if no UNW_FLAG_CHAININFO; absolute VA of chained RUNTIME_FUNCTION
};

// Resolve and parse the UNWIND_INFO at `unwind_info_va`. Returns nullopt
// on truncation / corrupt data — caller should treat as "no info".
[[nodiscard]] std::optional<ParsedUnwindInfo>
parse_unwind_info(const Binary& b, addr_t unwind_info_va);

// For every PE x64 function with PDATA, the byte range [begin, begin+size_of_prolog)
// is the prologue. Map function entry VA → prologue end VA.
// Empty for non-PE / non-x64 / no PDATA. Chained entries are skipped — the
// prologue belongs to the parent.
[[nodiscard]] std::map<addr_t, addr_t>
build_prologue_ranges(const Binary& b);

}  // namespace ember
