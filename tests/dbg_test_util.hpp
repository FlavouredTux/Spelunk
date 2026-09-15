#pragma once

#include <cstdio>
#include <string>

#include <spelunk/common/error.hpp>

inline bool spelunk_dbg_unavailable(const spelunk::Error& e) {
    const auto kind = e.kind_name();
    if (kind == "unsupported") return true;
    if (kind != "io") return false;
    return e.message.find("Operation not permitted") != std::string::npos ||
           e.message.find("Permission denied")      != std::string::npos;
}

inline int spelunk_dbg_skip(const char* what, const spelunk::Error& e) {
    std::fprintf(stderr, "SKIP: %s (%s)\n", what, e.message.c_str());
    return 77;
}
