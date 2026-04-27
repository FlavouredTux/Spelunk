#pragma once

#include <string>

namespace ember { class Binary; }

namespace ember::cli {

// Per-subcommand output builders. Each returns the full canonical text
// that --SUBCOMMAND would print. Pulled out of main.cpp so the cached-
// output helper (run_cached) can pass them as the compute step without
// mixing dispatch with formatting.

[[nodiscard]] std::string build_strings_output     (const Binary& b);
[[nodiscard]] std::string build_xrefs_output       (const Binary& b);
[[nodiscard]] std::string build_data_xrefs_output  (const Binary& b, bool json);
[[nodiscard]] std::string build_arities_output     (const Binary& b);
[[nodiscard]] std::string build_functions_output   (const Binary& b, bool full_analysis);
[[nodiscard]] std::string build_objc_names_output  (const Binary& b);
[[nodiscard]] std::string build_objc_protocols_output(const Binary& b);
[[nodiscard]] std::string build_rtti_output        (const Binary& b);
[[nodiscard]] std::string build_vm_detect_output   (const Binary& b);

}  // namespace ember::cli
