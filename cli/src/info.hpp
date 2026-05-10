#pragma once

#include <string_view>

namespace ember { class Binary; }

namespace ember::cli {

// Default action when no subcommand is given: dump the file format /
// arch / sections / symbols summary to stdout.
void print_info(const Binary& b, std::string_view path);

// `ember --help` / -h. Short topical overview.
void print_help();

// `ember --help <topic>`. Prints flag detail for one topic. Unknown
// topics fall back to the overview with a stderr note.
void print_help_topic(std::string_view topic);

}  // namespace ember::cli
