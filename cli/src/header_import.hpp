#pragma once

#include <ember/common/annotations.hpp>

namespace ember { class Binary; }
namespace ember::cli {

struct Args;

// Merge Clang-imported prototypes, enum constants, and direct parameter
// fields into the normal annotation overlay. Existing user annotations win.
int apply_header_annotations(const Args& args, const Binary& b,
                             Annotations& annotations, bool& loaded);

}  // namespace ember::cli
