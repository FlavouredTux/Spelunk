#pragma once

#include <cstdlib>
#include <print>

#include <spelunk/common/error.hpp>

namespace spelunk::cli {

// Standard CLI failure path: print "spelunk: <kind>: <message>" to stderr and
// return EXIT_FAILURE. The 5 `run_*` runners and several main() code paths
// repeated this verbatim.
[[nodiscard]] inline int report(const Error& e) {
    std::println(stderr, "spelunk: {}: {}", e.kind_name(), e.message);
    return EXIT_FAILURE;
}

}  // namespace spelunk::cli
