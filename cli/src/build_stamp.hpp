#pragma once

#include <format>
#include <string>
#include <string_view>

namespace spelunk::cli {

[[nodiscard]] inline constexpr std::string_view build_version() noexcept {
    return SPELUNK_VERSION_STRING;
}

[[nodiscard]] inline constexpr std::string_view build_revision() noexcept {
    return SPELUNK_GIT_REVISION;
}

[[nodiscard]] inline std::string build_json_member() {
    return std::format("\"build\":{{\"version\":\"{}\",\"revision\":\"{}\"}}",
                       build_version(), build_revision());
}

[[nodiscard]] inline std::string build_comment(std::string_view prefix) {
    return std::format("{} spelunk-build: {} {}\n", prefix,
                       build_version(), build_revision());
}

}  // namespace spelunk::cli
