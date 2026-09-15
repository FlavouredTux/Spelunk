#pragma once

#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include <spelunk/binary/binary.hpp>
#include <spelunk/common/types.hpp>

namespace spelunk {

// IAT (import address table) reconstruction for memory captures that
// have no IMAGE_DIRECTORY_ENTRY_IMPORT to parse - Scylla-style scrapes,
// process dumps, unpacked images where the original import directory was
// stripped. The IAT bytes are present (the loader filled the slots with
// resolved function pointers), but nothing names them.
//
// The pointer in a slot is `loaded_module_base + export_rva`. We don't
// know either term, but given the actual DLLs the process imported we can
// solve both: harvest the slots, cluster them by module, then for each
// cluster find the base that makes the most pointers land on a real
// export RVA. The winning base also identifies which DLL the cluster is.
//
// The one hard dependency is the reference DLLs: a pointer into a module
// we don't have can't be named, because the export RVA→name table lives
// in that DLL, not in the dump. Point the recovery at real Windows system
// DLLs (ntdll, kernel32, kernelbase, user32, ...). Export RVAs are stable
// across Win10/11 updates, so build-exact copies aren't required.

// Parsed export table of one reference DLL: export RVA → name.
struct ReferenceExports {
    std::string                          module;   // e.g. "kernel32.dll"
    std::unordered_map<u32, std::string> by_rva;
};

// Build a ReferenceExports from an already-loaded PE DLL. `module_name`
// is the label emitted for matched slots (typically the lowercased file
// name). Export RVAs are taken as `sym.addr - dll.preferred_load_base()`
// over every is_export symbol.
[[nodiscard]] ReferenceExports
reference_exports_from(const Binary& dll, std::string module_name);

struct ImportRecoveryOptions {
    // User-space module pointer band. Win64 system DLLs load high; the
    // default brackets the 0x00007FFx_xxxxxxxx range they occupy. A slot
    // qword outside this band is not treated as a module pointer.
    addr_t band_low  = 0x00007FF000000000ull;
    addr_t band_high = 0x0000800000000000ull;
    // Split harvested pointers into per-module clusters on any sorted gap
    // larger than this (one DLL's image is far smaller). 16 MiB default.
    u64 cluster_gap = 0x1000000ull;
    // Base search: step down from `cluster_low & ~0xffff` by 64 KiB this
    // many times (modules load on 64 KiB boundaries). 64 steps = 4 MiB,
    // comfortably past any real DLL's lowest export RVA.
    unsigned base_search_steps = 64;
    // When set, each recovered slot also reports `slot - own_base` as its
    // RVA (the natural key for a slot-RVA → name manifest). 0 leaves rva
    // equal to the absolute slot VA.
    addr_t own_base = 0;
    // Also scan executable sections for slots. Off by default: the IAT
    // lives in readable data, and scanning code adds noise.
    bool scan_executable = false;
};

struct RecoveredImport {
    addr_t      slot   = 0;   // absolute VA of the IAT slot
    addr_t      target = 0;   // pointer value stored in the slot
    addr_t      rva    = 0;   // slot - own_base (or slot if own_base==0)
    std::string module;       // resolved DLL name
    std::string name;         // export name / "Ordinal#N"
};

// One module's worth of clustered slots plus how the base solve went.
struct ImportCluster {
    addr_t      low    = 0;
    addr_t      high   = 0;
    std::size_t slots  = 0;
    std::string module;       // empty if the cluster couldn't be identified
    addr_t      base   = 0;   // solved load base; 0 if unsolved
    std::size_t hits   = 0;   // slots that landed on a real export
};

struct ImportRecoveryResult {
    std::vector<RecoveredImport> imports;    // resolved, sorted by slot
    std::vector<ImportCluster>   clusters;   // sorted by low, incl. unsolved
    std::size_t                  harvested = 0;  // total in-band slots found
};

// Harvest IAT slots from `dump`, cluster them, and name each against the
// supplied reference export tables. `dump` may be any Binary, but the
// feature targets raw-region / minidump captures whose import directory
// is gone.
[[nodiscard]] ImportRecoveryResult
recover_imports(const Binary& dump,
                std::span<const ReferenceExports> refs,
                const ImportRecoveryOptions& opts = {});

}  // namespace spelunk
