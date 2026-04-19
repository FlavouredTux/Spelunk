#pragma once

#include <string>

#include <ember/binary/binary.hpp>
#include <ember/common/annotations.hpp>
#include <ember/common/error.hpp>
#include <ember/structure/region.hpp>

namespace ember {

struct EmitOptions {
    // Emit `// bb_XXXX` labels before each block. Off by default — labels
    // are useful when cross-ref'ing with the CFG view but pure clutter in
    // day-to-day reading.
    bool show_bb_labels = false;
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
