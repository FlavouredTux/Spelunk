#pragma once

#include <string_view>

#include <ember/common/types.hpp>

namespace ember {

[[nodiscard]] constexpr u64 fnv1a_64(std::string_view s) noexcept {
    u64 h = 0xcbf29ce484222325ULL;
    for (char c : s) {
        h ^= static_cast<unsigned char>(c);
        h *= 0x100000001b3ULL;
    }
    return h;
}

}  // namespace ember
