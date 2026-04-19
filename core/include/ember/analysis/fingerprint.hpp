#pragma once

#include <string_view>

#include <ember/binary/binary.hpp>
#include <ember/common/types.hpp>

namespace ember {

// Schema token for the fingerprint algorithm. Folded into the hash itself
// AND into cache tags so bumping it invalidates on-disk TSVs without
// breaking unrelated cache entries (xrefs, strings, arities).
inline constexpr std::string_view kFingerprintSchema = "v2";

// Address-independent content hash of one function. Same algorithm compiled
// in the same way across two shifted binaries → same hash, so names learned
// on one build carry over to the next.
//
// What gets baked into `hash`:
//   - opcode sequence (canonicalized IR op names, per-block in RPO order)
//   - operand shape: kind + type + (for Reg) canonical register
//   - import call targets by name (not by address)
//   - referenced string literals (by content)
//   - referenced global data symbols by name (not by address)
//   - CFG topology (block count + per-block successor count sequence)
//
// What gets explicitly *excluded*:
//   - all absolute addresses (PIE slides, rebases)
//   - SSA versions, temp ids
//   - concrete immediate values that look like addresses (|v| >= 0x1000)
//   - source x86 instruction offsets
//
// Small immediates (|v| < 16) ARE included — they're usually loop bounds,
// struct offsets, flag bits, and help distinguish otherwise-identical shapes.
struct FunctionFingerprint {
    u64 hash   = 0;   // 0 means "could not fingerprint"
    u32 blocks = 0;
    u32 insts  = 0;
    u32 calls  = 0;
};

[[nodiscard]] FunctionFingerprint
compute_fingerprint(const Binary& b, addr_t fn_start);

}  // namespace ember
