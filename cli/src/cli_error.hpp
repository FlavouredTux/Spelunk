#pragma once

#include <cstdlib>
#include <print>

#include <ember/common/error.hpp>

namespace ember::cli {

// Standard CLI failure path: print "ember: <kind>: <message>" to stderr and
// return EXIT_FAILURE. The 5 `run_*` runners and several main() code paths
// repeated this verbatim.
[[nodiscard]] inline int report(const Error& e) {
    std::println(stderr, "ember: {}: {}", e.kind_name(), e.message);
    return EXIT_FAILURE;
}

}  // namespace ember::cli
