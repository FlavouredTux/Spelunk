#pragma once

#include <map>
#include <string>

#include <ember/analysis/eh_frame.hpp>
#include <ember/analysis/sig_inference.hpp>
#include <ember/binary/binary.hpp>
#include <ember/common/annotations.hpp>
#include <ember/common/error.hpp>
#include <ember/common/types.hpp>
#include <ember/structure/region.hpp>

namespace ember {

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
};

class PseudoCEmitter {
public:
    PseudoCEmitter() = default;

    [[nodiscard]] Result<std::string>
    emit(const StructuredFunction& sf,
         const Binary* binary = nullptr,
         const Annotations* annotations = nullptr,
         EmitOptions options = {}) const;

    // Per-basic-block pseudo-C. Each block's IR statements rendered with
    // the same expression machinery `emit()` uses, but block boundaries
    // are preserved (no structurer collapsing them into if/while/for)
    // and an explicit terminator summary line states the block's exit
    // (`if (cond)`, `switch (idx)`, `return <expr>;`, etc.). Output
    // format mirrors the asm CFG view (`format_cfg`) — `bb_<addr>:`
    // header, body lines, `-> bb_xxx (label)` successor arrows — so
    // graph consumers can reuse the same parser shape.
    [[nodiscard]] Result<std::string>
    emit_per_block(const StructuredFunction& sf,
                   const Binary* binary = nullptr,
                   const Annotations* annotations = nullptr,
                   EmitOptions options = {}) const;
};

}  // namespace ember
