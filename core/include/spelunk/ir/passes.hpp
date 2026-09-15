#pragma once

#include <spelunk/common/error.hpp>
#include <spelunk/ir/ir.hpp>

namespace spelunk {

struct CleanupStats {
    std::size_t iterations         = 0;
    std::size_t insts_removed      = 0;
    std::size_t phis_removed       = 0;
    std::size_t constants_folded   = 0;
    std::size_t copies_propagated  = 0;
};

[[nodiscard]] Result<CleanupStats> run_cleanup(IrFunction& fn);

}  // namespace spelunk
