#pragma once

#include <spelunk/common/annotations.hpp>

namespace spelunk { class Binary; }
namespace spelunk::cli {

struct Args;

// Merge Clang-imported prototypes, enum constants, and direct parameter
// fields into the normal annotation overlay. Existing user annotations win.
int apply_header_annotations(const Args& args, const Binary& b,
                             Annotations& annotations, bool& loaded);

}  // namespace spelunk::cli
