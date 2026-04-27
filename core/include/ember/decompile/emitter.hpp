#pragma once

#include <string>

#include <ember/binary/binary.hpp>
#include <ember/common/annotations.hpp>
#include <ember/common/error.hpp>
#include <ember/decompile/emit_options.hpp>
#include <ember/structure/region.hpp>

namespace ember {

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
