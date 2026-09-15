// YARA-like function identification (--identify).

#include <cstdio>

#include <spelunk/analysis/identify.hpp>
#include <spelunk/binary/binary.hpp>

#include "../subcommands.hpp"

namespace spelunk::cli {

int run_identify(const Args& args, const Binary& b) {
    auto hits = identify_functions(b, args.identify_threshold);
    const auto tsv = format_identify_tsv(hits);
    std::fwrite(tsv.data(), 1, tsv.size(), stdout);
    return EXIT_SUCCESS;
}

}  // namespace spelunk::cli
