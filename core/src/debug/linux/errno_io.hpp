#pragma once

#include <cerrno>
#include <cstring>
#include <string>

#include <spelunk/common/error.hpp>

namespace spelunk::debug {

// Error::io naming the failed syscall plus strerror(errno).
[[nodiscard]] inline Error errno_io(const char* op) {
    return Error::io(std::string(op) + ": " + std::strerror(errno));
}

}  // namespace spelunk::debug
