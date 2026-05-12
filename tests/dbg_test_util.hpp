#pragma once

#include <cstdio>
#include <string>

#include <ember/common/error.hpp>

inline bool ember_dbg_unavailable(const ember::Error& e) {
    const auto kind = e.kind_name();
    if (kind == "unsupported") return true;
    if (kind != "io") return false;
    return e.message.find("Operation not permitted") != std::string::npos ||
           e.message.find("Permission denied")      != std::string::npos;
}

inline int ember_dbg_skip(const char* what, const ember::Error& e) {
    std::fprintf(stderr, "SKIP: %s (%s)\n", what, e.message.c_str());
    return 77;
}
