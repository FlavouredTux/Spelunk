#pragma once

#include <cstddef>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/common/error.hpp>
#include <ember/common/types.hpp>

namespace ember {

struct DiscoveredFunction;  // <ember/analysis/pipeline.hpp>

namespace sigs {

// FLIRT-equivalent library function recognition.
//
// `.pat` files are the standard text format produced by IDA's `flair`
// tool, the open-source `sigkit`/`pat_creator` chain, and Ghidra's
// signature export. One signature per line:
//
//   <prefix-bytes> <crc-len> <crc16> <total-len> :0000 <pub-name> [@offs name]*
//
// Each function in the loaded binary whose name is still `sub_*` /
// `vt_*` is matched against this database. On a unique match we apply
// the public name as a rename in the existing annotations system, so
// downstream consumers (emitter, fingerprints, function list) see the
// resolved name without any further plumbing.

// FLIRT's standard prefix length. Functions shorter than this carry a
// shorter prefix; the rest of the buffer is wildcarded.
inline constexpr std::size_t kPrefixLen = 32;

// One reference symbol the signature expects this function to call.
// `offset` is the byte offset of the call/jmp instruction within the
// function. Used to disambiguate when multiple sigs share the same
// prefix (e.g. compiler-emitted variants of the same function).
struct SigRef {
    u16         offset = 0;
    std::string name;
};

// One library-function signature.
struct Sig {
    // Bytes 0..prefix_len-1 of the function. `mask[i] == false` marks
    // a wildcard position — the byte at i wasn't pinned by the .o
    // file's relocations (typically a relocated address or a
    // displacement to an extern).
    std::array<u8,   kPrefixLen> prefix      = {};
    std::array<bool, kPrefixLen> mask        = {};
    u16                          prefix_len  = 0;

    // CRC of bytes prefix_len..(prefix_len + crc_length). When
    // crc_length == 0 the CRC step is skipped. Lets two functions
    // with identical prefixes but different bodies disambiguate
    // without bumping the prefix length.
    u8                           crc_length  = 0;
    u16                          crc16       = 0;

    // Full function length in bytes. Informational; not used to
    // bound matching since a function in the target binary may be
    // longer/shorter than the reference (epilogue variation).
    u32                          total_length = 0;

    std::string                  name;
    std::vector<SigRef>          refs;

    // Pre-computed: number of non-wildcard bytes in prefix. Higher =
    // more specific; tie-break for collision resolution.
    u16                          specificity  = 0;
};

struct SigDb {
    std::vector<Sig> sigs;

    [[nodiscard]] std::size_t size() const noexcept { return sigs.size(); }
    [[nodiscard]] bool        empty() const noexcept { return sigs.empty(); }
};

// Parse a single `.pat` file. Lines that don't parse are skipped with a
// warning to stderr; the format is text and a stray edit shouldn't fail
// the whole load. Returns Error::not_found if the file is missing.
[[nodiscard]] Result<SigDb> load_pat(const std::filesystem::path& path);

// Convenience: load and merge several `.pat` files into one database.
// Duplicate (name, prefix) entries are kept once.
[[nodiscard]] Result<SigDb>
load_pats(std::span<const std::filesystem::path> paths);

// One sig→address resolution. `addr` is the function entry; `name` is
// the public name to apply.
struct MatchResult {
    addr_t      addr = 0;
    std::string name;
};

// Match every `sub_*`/`vt_*` candidate against `db` and return the
// resolved renames. Pure: callers apply via the annotations system.
//
// `existing_renames`: addresses that already carry a non-default name
// (user renames, symbol-table names) — we skip these so a sig match
// never overrides operator intent.
[[nodiscard]] std::vector<MatchResult>
apply_signatures(const Binary& b,
                 const SigDb& db,
                 std::span<const DiscoveredFunction> candidates,
                 std::span<const addr_t> existing_renames = {});

// FLIRT CRC16 — reversed CCITT (polynomial 0x8408, init 0xFFFF, no
// final XOR). Public so a future `.o`-file sig generator can use the
// same routine.
[[nodiscard]] u16 crc16(std::span<const std::byte> bytes) noexcept;

}  // namespace sigs
}  // namespace ember
