#pragma once

#include <cstddef>
#include <string_view>

namespace spelunk { class Binary; }

namespace spelunk::cli {

// Default action when no subcommand is given: dump the file format /
// arch / sections / symbols summary to stdout.
void print_info(const Binary& b, std::string_view path,
                std::size_t row_limit, bool verbose);

// `spelunk --help` / -h. Short topical overview.
void print_help();

// `spelunk --help <topic>`. Prints flag detail for one topic. Unknown
// topics fall back to the overview with a stderr note.
void print_help_topic(std::string_view topic);

}  // namespace spelunk::cli
