#pragma once

#include <cstdio>
#include <cstdlib>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

namespace ember {

// True when progress output should be written to stderr. Suppressed unless
// stderr is a TTY, and always suppressed when EMBER_QUIET=1 is set (the
// CLI's --quiet flag exports it before analysis begins).
[[nodiscard]] inline bool progress_enabled() {
    if (const char* q = std::getenv("EMBER_QUIET"); q && q[0] == '1') {
        return false;
    }
#ifdef _WIN32
    return ::_isatty(::_fileno(stderr)) != 0;
#else
    return ::isatty(fileno(stderr)) != 0;
#endif
}

}  // namespace ember
