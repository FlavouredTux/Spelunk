#pragma once

#include <array>
#include <cstddef>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

#include <ember/common/error.hpp>
#include <ember/common/types.hpp>

namespace ember::pdb {

// Public symbol from the PDB's symbol-record stream. Coordinates are
// (segment, offset) pairs — segment is a 1-based index into the PE's
// section table, offset is the byte offset inside that section. Resolving
// to a VA is the caller's responsibility (the PDB does not carry the
// image base or section addresses).
struct PublicSymbol {
    std::string name;
    u32         section_offset = 0;
    u16         segment        = 0;
    bool        is_function    = false;  // S_PUB32.flags bit 1
};

// One frame-relative local variable (S_BPREL32 / S_REGREL32) nested
// inside a procedure scope. The offset's frame of reference is named
// by `reg`: CV register IDs CV_AMD64_RSP (332) / CV_AMD64_RBP (333)
// are the only ones we currently translate. `reg == 0` is the
// S_BPREL32 form — implicit RBP on x64 — and is treated like the
// REGREL32-RBP case downstream.
struct LocalVarSymbol {
    std::string name;
    i32         frame_offset = 0;
    u32         type_index   = 0;
    u16         reg          = 0;
};

// Per-procedure symbol from a module's compile-unit stream
// (S_GPROC32 / S_LPROC32 / *_ID variants). Carries a TPI/IPI type
// index on top of the address — the link to the function's signature.
struct ProcSymbol {
    std::string name;
    u32         section_offset = 0;
    u16         segment        = 0;
    u32         length         = 0;   // proc length in bytes
    u32         type_index     = 0;   // index into TPI (or IPI, normalized at parse)
    bool        is_id_record   = false;  // *_ID variant points into IPI; we resolve to TPI
    std::vector<LocalVarSymbol> locals;  // S_BPREL32 / S_REGREL32 inside the proc scope
};

// Global / local data symbol (S_GDATA32 / S_LDATA32) from either the
// global symbol stream or a module stream. Carries a type index for
// future struct/class field rendering.
struct DataSymbol {
    std::string name;
    u32         section_offset = 0;
    u16         segment        = 0;
    u32         type_index     = 0;
    bool        is_local       = false;
};

// PDB Info stream (stream 1) header. The GUID + age form the unique
// identity stamp the PE's CodeView RSDS record refers to — verifying
// the match is a cheap way to reject mismatched PDB / EXE pairs.
struct PdbInfo {
    u32 version    = 0;            // 20000404 (V41) / 20030901 (V50) / 20091201 (V70)
    u32 signature  = 0;            // unix timestamp of the PDB build
    u32 age        = 0;            // bumped on every linker pass
    std::array<u8, 16> guid {};    // raw 16 bytes; mixed-endian Microsoft GUID
};

// Multi-Stream File container. The PDB v7 on-disk format is a stream of
// fixed-size blocks; logical "streams" are reconstructed by walking
// per-stream block lists out of the file directory. Provides random
// read-access to each stream as a contiguous byte buffer.
//
// Stream-index conventions (well-known):
//   1 = PDB Info        (signature, age, GUID — used to match against
//                        the .exe's CodeView entry)
//   2 = TPI             (type index)
//   3 = DBI             (debug info header + module list)
//   4 = IPI             (item index, since pdb v7)
//   ≥5 = module / GSI / PSI / SymRecord / contributions, indexed by
//         per-pdb fields in the DBI header
class Msf {
public:
    [[nodiscard]] static Result<Msf>
    from_buffer(std::vector<std::byte> data);

    [[nodiscard]] u32 num_streams() const noexcept {
        return static_cast<u32>(stream_sizes_.size());
    }
    [[nodiscard]] u32 stream_size(u32 idx) const noexcept {
        return idx < stream_sizes_.size() ? stream_sizes_[idx] : 0;
    }
    // Concatenate every block of stream `idx`, trimmed to its real size.
    // Returns an error if the stream is "deleted" (size == 0xFFFFFFFF) or
    // any block index is out of range. An empty stream → empty buffer
    // (not an error).
    [[nodiscard]] Result<std::vector<std::byte>>
    read_stream(u32 idx) const;

private:
    Msf() noexcept = default;

    std::vector<std::byte>           data_;
    u32                              block_size_ = 0;
    std::vector<u32>                 stream_sizes_;
    std::vector<std::vector<u32>>    stream_blocks_;
};

// Parsed CodeView type record. We collapse the LF_* universe into a
// small enum + a few unioned fields — every consumer in Ember speaks
// "render to a C string", not "I need to programmatically inspect a
// struct's field list."
struct TypeRecord {
    enum class Kind : u8 {
        Unknown,    // unrecognized leaf code; rendered as `?`
        Pointer,    // LF_POINTER — to base_type, with const/volatile/ref bits
        Modifier,   // LF_MODIFIER — const/volatile wrap around base_type
        Array,      // LF_ARRAY
        Procedure,  // LF_PROCEDURE — return + arg list + call conv
        MFunction,  // LF_MFUNCTION — like Procedure plus class/this
        ArgList,    // LF_ARGLIST — list of arg types
        Structure,  // LF_STRUCTURE / LF_CLASS
        Union,      // LF_UNION
        Enum,       // LF_ENUM
        Bitfield,   // LF_BITFIELD
        Alias,      // LF_ALIAS — typedef-ish wrapper
    };

    Kind kind = Kind::Unknown;

    // Base type for Pointer/Modifier/Array(element)/Bitfield/Alias.
    // Return type for Procedure/MFunction.
    u32 base_type      = 0;

    // Pointer attributes (decoded from LF_POINTER.Attrs).
    bool is_const      = false;
    bool is_volatile   = false;
    bool is_reference  = false;     // lvalue or rvalue ref
    bool is_rvalue_ref = false;
    u8   ptr_size      = 0;         // 4 or 8 bytes typically

    // LF_MODIFIER bits (in addition to is_const / is_volatile).
    bool is_unaligned  = false;

    // Procedure / MFunction.
    u32  arg_list      = 0;
    u16  param_count   = 0;
    u8   call_conv     = 0;
    u32  class_type    = 0;         // MFunction only
    u32  this_type     = 0;         // MFunction only

    // ArgList.
    std::vector<u32> arg_types;

    // Structure/Union/Enum.
    std::string name;
    u64         size_bytes   = 0;
    u32         field_list   = 0;   // unused beyond presence checks for now
    bool        is_forward_ref = false;

    // Array.
    u64         array_size_bytes = 0;
    u32         index_type       = 0;
};

// Flat type table indexed by CodeView type index. TPI hands us
// records with indices in [ti_begin, ti_end); we materialize them
// lazily during parse (no explicit hash stream is consulted —
// renaming "look up by name" isn't a current consumer).
class TpiTable {
public:
    [[nodiscard]] static Result<TpiTable>
    parse(std::span<const std::byte> tpi_stream);

    [[nodiscard]] u32 ti_begin() const noexcept { return ti_begin_; }
    [[nodiscard]] u32 ti_end()   const noexcept { return ti_end_; }
    [[nodiscard]] bool empty()   const noexcept { return records_.empty(); }

    // Look up a parsed record. Returns nullptr for primitive indices
    // (TI < ti_begin_) and for any TI outside [ti_begin, ti_end).
    [[nodiscard]] const TypeRecord*
    lookup(u32 type_index) const noexcept;

    // Render `type_index` as a C type string — primitives get their
    // canonical short names (`int`, `unsigned int`, `char*`, `void`),
    // structs/classes/unions get their name (or an anonymous tag when
    // the PDB didn't carry one), pointers/modifiers wrap recursively.
    // Cycles in the type graph (LF_STRUCTURE referencing itself via a
    // pointer field, common with linked lists) are broken by capping
    // recursion depth.
    [[nodiscard]] std::string
    render_type(u32 type_index, int depth = 0) const;

private:
    u32                     ti_begin_ = 0;
    u32                     ti_end_   = 0;
    std::vector<TypeRecord> records_;   // indexed by (ti - ti_begin)
};

// One-shot result of fully parsing a PDB. Consumers (PeBinary mostly)
// pull out the bits they care about and stop holding a reference; the
// PdbReader struct itself isn't long-lived.
struct PdbReader {
    PdbInfo                   info;
    std::vector<PublicSymbol> publics;     // S_PUB32 from the public symbol stream
    std::vector<ProcSymbol>   procs;       // S_GPROC32 / S_LPROC32 with type indices
    std::vector<DataSymbol>   globals;     // S_GDATA32 / S_LDATA32
    TpiTable                  types;       // owned type table
};

// Read the PDB at `path`, walk every interesting stream, return a
// fully-populated reader. Any individual sub-parse that fails is
// non-fatal — the caller still gets whatever bits we managed to
// extract — except for the MSF / DBI header parse, which is the
// minimum viable surface (without it we can't find anything else).
[[nodiscard]] Result<PdbReader>
load_pdb(const std::filesystem::path& path);

// Buffer-mode equivalent. Used by tests so they don't have to spill
// synthetic PDB bytes to a tempfile.
[[nodiscard]] Result<PdbReader>
load_pdb_from_buffer(std::vector<std::byte> data);

// Legacy single-purpose entry: only walks the symbol-record stream
// for S_PUB32 names. Kept for test back-compat. New callers should
// prefer `load_pdb` since it returns the richer PdbReader.
[[nodiscard]] Result<std::vector<PublicSymbol>>
load_publics(const std::filesystem::path& path);

[[nodiscard]] Result<std::vector<PublicSymbol>>
load_publics_from_buffer(std::vector<std::byte> data);

}  // namespace ember::pdb
