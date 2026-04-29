#pragma once

#include <cstddef>
#include <map>
#include <string>
#include <vector>

#include <ember/analysis/eh_frame.hpp>
#include <ember/analysis/sig_inference.hpp>
#include <ember/common/types.hpp>

namespace ember {

// Sidecar provenance produced by the emitter. One Hit per IR
// instruction whose statement was appended to the output buffer:
// `byte_offset` is the position in the returned string where the
// statement's first character lands, `source_addr` is the IR's
// source_addr (i.e. the machine-instruction VA the IR was lifted
// from). Translate to line numbers by counting '\n's up to the
// offset — keeps the emitter hot path O(1) per statement.
struct LineMap {
    struct Hit {
        std::size_t byte_offset = 0;
        addr_t      source_addr = 0;
    };
    std::vector<Hit> hits;
};


struct EmitOptions {
    // Emit `// bb_XXXX` labels before each block. Off by default — labels
    // are useful when cross-ref'ing with the CFG view but pure clutter in
    // day-to-day reading.
    bool show_bb_labels = false;
    // Interprocedural signature hints, keyed by function entry address.
    // When populated (via infer_signatures()), the emitter consults this
    // for char*-arg propagation across function boundaries instead of
    // being limited to the direct libc-sink pass.
    const std::map<addr_t, InferredSig>* signatures = nullptr;
    // Binary-wide type arena owning every TypeRef inside `signatures`.
    // Set alongside `signatures` by the IPA driver. Required for the
    // emitter to resolve typed param/return TypeRefs from sigs into
    // printable C type names.
    const TypeArena* type_arena = nullptr;
    // Pre-parsed landing-pad map from parse_landing_pads(). When set, the
    // emitter annotates blocks that begin a catch range with real LSDA
    // info instead of falling back to __cxa_* pattern matching.
    const LpMap* landing_pads = nullptr;
    // __objc_selrefs address → selector-name. When set, the emitter
    // renders `*(u64*)(0x105e61378)` as `@selector(initWithHandler:)`.
    const std::map<addr_t, std::string>* objc_selrefs = nullptr;
    // __objc_classrefs address → class-name. When set, the emitter
    // renders `*(u64*)(0x105e63820)` as `[NSApplication class]`.
    const std::map<addr_t, std::string>* objc_classrefs = nullptr;
    // Itanium RTTI-derived method names: IMP address → "<Class>::vfn_<N>".
    // Consulted by function_display_name after the Obj-C IMP check and
    // before the generic symbol-table lookup.
    const std::map<addr_t, std::string>* rtti_methods = nullptr;
    // Per-call-site resolution: call/jmp instruction VA → resolved
    // target function. Populated by compute_call_resolutions; when
    // set, the CallIndirect printer consults it so
    // `mov rax, [rip+vtable]; call [rax+0x38]` renders as a named
    // method rather than the opaque `(*fn)(args)` fallback.
    const std::map<addr_t, addr_t>* call_resolutions = nullptr;
    // Function entry VA → prologue end VA (from PE UNWIND_INFO via
    // build_prologue_ranges). When set, the emitter suppresses every IR
    // instruction whose source_addr lies in [entry, prologue_end), and
    // also strips the matching trailing-block epilogue (heuristically
    // bounded by prologue length, since Win64 epilogues mirror the
    // prologue and never exceed its byte count in practice).
    const std::map<addr_t, addr_t>* prologue_ranges = nullptr;
    // When non-null, the emitter records (byte_offset, source_addr)
    // pairs into this map at every per-IR statement emit point. Used
    // by the debugger's `code` command to mark the line corresponding
    // to a runtime PC, and by `b <symbol>:<line>` to set bps from
    // pseudo-C lines back to PC ranges.
    LineMap* line_map = nullptr;
};

}  // namespace ember
