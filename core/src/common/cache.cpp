#include <ember/common/cache.hpp>

#include <cstdlib>
#include <format>
#include <fstream>
#include <sstream>
#include <string>

#include <ember/common/types.hpp>

namespace ember::cache {

namespace {

u64 fnv1a_64(std::string_view s) noexcept {
    u64 h = 0xcbf29ce484222325ULL;
    for (char c : s) {
        h ^= static_cast<unsigned char>(c);
        h *= 0x100000001b3ULL;
    }
    return h;
}

}  // namespace

std::filesystem::path default_dir() {
    namespace fs = std::filesystem;
    if (const char* xdg = std::getenv("XDG_CACHE_HOME"); xdg && *xdg) {
        return fs::path(xdg) / "ember";
    }
    if (const char* home = std::getenv("HOME"); home && *home) {
        return fs::path(home) / ".cache" / "ember";
    }
    return fs::current_path() / ".ember-cache";
}

std::string key_for(const std::filesystem::path& binary) {
    namespace fs = std::filesystem;
    std::error_code ec;
    const auto abs   = fs::weakly_canonical(binary, ec).string();
    const auto size  = fs::file_size(binary, ec);
    const auto mtime = fs::last_write_time(binary, ec);
    const auto mts   = mtime.time_since_epoch().count();

    std::string manifest = std::format("{}|{}|{}|v{}", abs, size, mts, kVersion);
    return std::format("{:016x}", fnv1a_64(manifest));
}

std::optional<std::string>
read(const std::filesystem::path& cache_dir,
     std::string_view key, std::string_view tag) {
    namespace fs = std::filesystem;
    const auto p = cache_dir / std::string(key) / std::string(tag);
    std::error_code ec;
    if (!fs::exists(p, ec) || ec) return std::nullopt;
    std::ifstream f(p, std::ios::binary);
    if (!f) return std::nullopt;
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

Result<void>
write(const std::filesystem::path& cache_dir,
      std::string_view key, std::string_view tag,
      std::string_view content) {
    namespace fs = std::filesystem;
    const auto dir = cache_dir / std::string(key);

    std::error_code ec;
    fs::create_directories(dir, ec);
    if (ec) {
        return std::unexpected(Error::io(std::format(
            "cache: mkdir '{}': {}", dir.string(), ec.message())));
    }

    // Atomic: write to tmp then rename so readers never see a partial file.
    const auto tmp = dir / (std::string(tag) + ".tmp");
    const auto final_path = dir / std::string(tag);
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) {
            return std::unexpected(Error::io(std::format(
                "cache: cannot write '{}'", tmp.string())));
        }
        f.write(content.data(), static_cast<std::streamsize>(content.size()));
        if (!f) {
            return std::unexpected(Error::io(std::format(
                "cache: short write to '{}'", tmp.string())));
        }
    }
    fs::rename(tmp, final_path, ec);
    if (ec) {
        return std::unexpected(Error::io(std::format(
            "cache: rename '{}' -> '{}': {}",
            tmp.string(), final_path.string(), ec.message())));
    }
    return {};
}

}  // namespace ember::cache
