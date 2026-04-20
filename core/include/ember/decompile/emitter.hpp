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
    // Pre-parsed landing-pad map from parse_landing_pads(). When set, the
    // emitter annotates blocks that begin a catch range with real LSDA
    // info instead of falling back to __cxa_* pattern matching.
    const LpMap* landing_pads = nullptr;
    // __objc_selrefs address → selector-name. When set, the emitter
    // renders `*(u64*)(0x105e61378)` as `@selector(initWithHandler:)`.
    const std::map<addr_t, std::string>* objc_selrefs = nullptr;
};

class PseudoCEmitter {
public:
    PseudoCEmitter() = default;

    [[nodiscard]] Result<std::string>
    emit(const StructuredFunction& sf,
         const Binary* binary = nullptr,
         const Annotations* annotations = nullptr,
         EmitOptions options = {}) const;
};

}  // namespace ember
