#pragma once

#include <string_view>

namespace ember { class Binary; }

namespace ember::cli {

// Default action when no subcommand is given: dump the file format /
// arch / sections / symbols summary to stdout.
void print_info(const Binary& b, std::string_view path);

// `ember --help` / -h.
void print_help();

}  // namespace ember::cli
