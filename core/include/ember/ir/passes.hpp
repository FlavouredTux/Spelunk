#pragma once

#include <ember/common/error.hpp>
#include <ember/ir/ir.hpp>

namespace ember {

struct CleanupStats {
    std::size_t iterations         = 0;
    std::size_t insts_removed      = 0;
    std::size_t phis_removed       = 0;
    std::size_t constants_folded   = 0;
    std::size_t copies_propagated  = 0;
};

[[nodiscard]] Result<CleanupStats> run_cleanup(IrFunction& fn);

}  // namespace ember
