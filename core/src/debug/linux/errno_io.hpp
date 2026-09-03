#pragma once

#include <cerrno>
#include <cstring>
#include <string>

#include <ember/common/error.hpp>

namespace ember::debug {

// Error::io naming the failed syscall plus strerror(errno).
[[nodiscard]] inline Error errno_io(const char* op) {
    return Error::io(std::string(op) + ": " + std::strerror(errno));
}

}  // namespace ember::debug
