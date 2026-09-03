#pragma once

#include <cstddef>
#include <string_view>

#include <ember/common/types.hpp>

namespace ember {

inline constexpr u64 kFnvOffset64 = 0xcbf29ce484222325ULL;
inline constexpr u64 kFnvPrime64  = 0x100000001b3ULL;

[[nodiscard]] constexpr u64 fnv1a_64(std::string_view s) noexcept {
    u64 h = kFnvOffset64;
    for (char c : s) {
        h ^= static_cast<unsigned char>(c);
        h *= kFnvPrime64;
    }
    return h;
}

[[nodiscard]] constexpr u64 fnv1a_64(const void* p, std::size_t n) noexcept {
    const auto* b = static_cast<const unsigned char*>(p);
    u64 h = kFnvOffset64;
    for (std::size_t i = 0; i < n; ++i) {
        h ^= b[i];
        h *= kFnvPrime64;
    }
    return h;
}

// Order-sensitive combine of two 64-bit hashes (splitmix64 finalizer over
// a boost-style seed mix).
[[nodiscard]] constexpr u64 mix64(u64 a, u64 b) noexcept {
    u64 x = a ^ (b + 0x9e3779b97f4a7c15ULL + (a << 6) + (a >> 2));
    x ^= x >> 30;  x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;  x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return x;
}

}  // namespace ember
