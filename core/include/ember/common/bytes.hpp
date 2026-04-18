#pragma once

#include <bit>
#include <cstring>
#include <format>
#include <span>
#include <string_view>
#include <type_traits>

#include <ember/common/error.hpp>
#include <ember/common/types.hpp>

namespace ember {

template <typename T>
    requires std::is_trivially_copyable_v<T>
[[nodiscard]] inline T read_le_at(const std::byte* p) noexcept {
    T v{};
    std::memcpy(&v, p, sizeof(T));
    if constexpr (std::endian::native == std::endian::big) {
        if constexpr (sizeof(T) > 1) v = std::byteswap(v);
    }
    return v;
}

class ByteReader {
public:
    explicit ByteReader(std::span<const std::byte> bytes) noexcept : bytes_(bytes) {}

    [[nodiscard]] std::span<const std::byte> bytes() const noexcept { return bytes_; }
    [[nodiscard]] std::size_t size() const noexcept { return bytes_.size(); }

    template <typename T>
        requires std::is_trivially_copyable_v<T>
    [[nodiscard]] Result<T> read_le(std::size_t offset) const noexcept {
        if (offset > bytes_.size() || bytes_.size() - offset < sizeof(T)) {
            return std::unexpected(Error::truncated(std::format(
                "read_le<{}> at offset {:#x} past end {:#x}",
                sizeof(T), offset, bytes_.size())));
        }
        return read_le_at<T>(bytes_.data() + offset);
    }

    [[nodiscard]] Result<std::span<const std::byte>>
    slice(std::size_t offset, std::size_t length) const noexcept {
        if (offset > bytes_.size() || length > bytes_.size() - offset) {
            return std::unexpected(Error::out_of_bounds(std::format(
                "slice [{:#x}, {:#x}) past end {:#x}",
                offset, offset + length, bytes_.size())));
        }
        return bytes_.subspan(offset, length);
    }

    [[nodiscard]] Result<std::string_view> read_cstr(std::size_t offset) const noexcept {
        if (offset >= bytes_.size()) {
            return std::unexpected(Error::out_of_bounds(std::format(
                "read_cstr offset {:#x} past end {:#x}", offset, bytes_.size())));
        }
        const char* start = reinterpret_cast<const char*>(bytes_.data() + offset);
        const std::size_t max_len = bytes_.size() - offset;
        std::size_t len = 0;
        while (len < max_len && start[len] != '\0') ++len;
        if (len == max_len) {
            return std::unexpected(Error::truncated(std::format(
                "unterminated string at {:#x}", offset)));
        }
        return std::string_view(start, len);
    }

private:
    std::span<const std::byte> bytes_;
};

}  // namespace ember
