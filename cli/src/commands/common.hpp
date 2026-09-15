#pragma once

// Helpers shared by more than one command group.

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <spelunk/binary/binary.hpp>
#include <spelunk/common/annotations.hpp>
#include <spelunk/common/error.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/disasm/instruction.hpp>

#include "../args.hpp"

namespace spelunk::cli {

// Quiet sibling of load_annotations_for(): resolves and reads the
// annotations file using the same precedence chain (explicit > sidecar
// > cache, with --no-cache suppressing the cache leg) but never prints
// the "spelunk: annotations: …" status line. Used by the per-command
// resolvers that just need to thread renames into resolve_function;
// the noisy variant, load_annotations_for(), runs once per emit pass.
[[nodiscard]] Annotations load_annotations_quiet(const Args& args);

// Shape test for "the user typed an address, just a mangled one".
// A token that starts with 0x / sub_ or is pure hex must never fall
// through to symbol lookup and masquerade as `no symbol named '...'`;
// names like "main" or "seqGame" stay on the symbol path.
[[nodiscard]] bool looks_like_address(std::string_view spec) noexcept;

// Address-or-name resolution shared by the one-shot VA flags. Numeric
// input (0x… / sub_…) parses directly; anything else falls through to
// resolve_function so a bare symbol name works everywhere the
// FN|VA-taking siblings (--side-effects, --callees, …) already do.
// An address-shaped token that fails to parse is reported here as
// `invalid address` instead of pretending it was a symbol name.
// Returns nullopt only after the failure reason has been reported;
// callers should not print a second diagnostic.
[[nodiscard]] std::optional<addr_t> resolve_flag_target(const Binary& b,
                                                        const Args& args,
                                                        std::string_view spec);

// Address-range scope filter, populated from --module NAME against a
// minidump (or any Binary that synthesizes module Symbols of kind=Section
// with addr=base / size=image-size - currently just MinidumpBinary). When
// inactive, contains() returns true for every address; the caller-side
// code paths run unchanged. When active, fn-walking subcommands skip
// every address outside [lo, hi) before fingerprinting/decompiling - the
// motivating case is a process minidump where ~95% of discovered fns
// belong to wine ntdll/kernelbase reimpl pages and would never match
// the real-Microsoft TEEF corpus.
struct ModuleScope {
    addr_t lo = 0;
    addr_t hi = 0;
    bool   active = false;
    std::string matched_name;       // for stderr diagnostics

    [[nodiscard]] bool contains(addr_t a) const noexcept {
        return !active || (a >= lo && a < hi);
    }
};

// Case-insensitive substring match on basenames. The minidump loader
// already trims paths to basenames before populating Symbol::name, so
// `loader.exe` finds `loader.exe` - but accept partials too (`loader`
// finds `loader.exe`, `kernel32` finds `kernel32.dll`). Ambiguous
// matches: use the first hit and warn - the user can disambiguate by
// passing the full basename.
[[nodiscard]] ModuleScope resolve_module_scope(const Binary& b,
                                               std::string_view name);

[[nodiscard]] std::vector<addr_t>
compute_callers_to_fast(const Binary& b, addr_t want);

[[nodiscard]] std::string_view section_name_containing(const Binary& b,
                                                       addr_t va) noexcept;

[[nodiscard]] bool addr_in_executable_section_cli(const Binary& b,
                                                  addr_t va) noexcept;

[[nodiscard]] std::string first_disasm_line_at(const Binary& b, addr_t va);

[[nodiscard]] std::optional<addr_t>
cli_rip_relative_target(const Instruction& insn) noexcept;

[[nodiscard]] bool is_short_relative_branch(const Instruction& insn) noexcept;

[[nodiscard]] bool is_rel32_call_or_jump(const Instruction& insn) noexcept;

struct DisasmProbe {
    std::vector<Instruction> insns;
    addr_t first_bb_end = 0;
    std::size_t steal_len = 0;
    bool needs_relocation = false;
    bool safe_abs_trampoline = true;
};

[[nodiscard]] Result<DisasmProbe>
decode_disasm_probe(const Binary& b, addr_t start, std::size_t count);

[[nodiscard]] Result<std::string> disasm_probe_json(const Binary& b, addr_t start,
                                                    std::size_t count);

[[nodiscard]] std::string disasm_probe_summary(const Binary& b, addr_t start,
                                               std::size_t count);

[[nodiscard]] bool address_is_mapped(const Binary& b, addr_t va) noexcept;

[[nodiscard]] std::optional<addr_t>
read_pointer_value(const Binary& b, addr_t va) noexcept;

[[nodiscard]] std::optional<std::pair<addr_t, addr_t>>
parse_obj_off_spec(std::string_view spec);

[[nodiscard]] std::string compact_pseudo_summary(const Binary& b, addr_t target,
                                                  const Annotations* ann);

[[nodiscard]] std::optional<std::string> read_c_string(const Binary& b, addr_t va);

struct ObjectFieldRow {
    addr_t offset = 0;
    addr_t addr = 0;
    u64 value = 0;
    std::string kind;
    std::string detail;
};

[[nodiscard]] std::vector<ObjectFieldRow>
classify_object_fields(const Binary& b, addr_t obj, addr_t size);

// Resolve + load the annotation source. Sets `loaded` true when a file
// was successfully read; returns the populated Annotations either way.
[[nodiscard]] Annotations load_annotations_for(const Args& args, bool& loaded);

}  // namespace spelunk::cli
