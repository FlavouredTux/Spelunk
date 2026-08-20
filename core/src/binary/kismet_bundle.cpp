#include <ember/binary/kismet_bundle.hpp>

#include <charconv>
#include <fstream>
#include <iterator>
#include <system_error>
#include <unordered_set>

namespace ember {
namespace {

[[nodiscard]] std::vector<std::string_view> split_tabs(std::string_view line) {
    std::vector<std::string_view> fields;
    std::size_t start = 0;
    while (start <= line.size()) {
        const std::size_t tab = line.find('\t', start);
        fields.push_back(line.substr(
            start, tab == std::string_view::npos ? line.size() - start : tab - start));
        if (tab == std::string_view::npos) break;
        start = tab + 1;
    }
    return fields;
}

[[nodiscard]] Result<u64> parse_u64(std::string_view value, std::string_view field) {
    u64 parsed = 0;
    const auto result = std::from_chars(
        value.data(), value.data() + value.size(), parsed, 10);
    if (value.empty() || result.ec != std::errc{} ||
        result.ptr != value.data() + value.size()) {
        return std::unexpected(Error::invalid_format(
            "kismet bundle: invalid " + std::string(field)));
    }
    return parsed;
}

[[nodiscard]] bool safe_relative_path(const std::filesystem::path& path) {
    if (path.empty() || path.is_absolute()) return false;
    for (const auto& component : path) {
        if (component == "..") return false;
    }
    return true;
}

[[nodiscard]] Result<std::vector<std::byte>>
read_bytes(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) {
        return std::unexpected(Error::io(
            "kismet bundle: cannot open '" + path.string() + "'"));
    }
    const std::streampos end = input.tellg();
    if (end < 0) {
        return std::unexpected(Error::io(
            "kismet bundle: cannot size '" + path.string() + "'"));
    }
    const auto size = static_cast<std::size_t>(end);
    std::vector<std::byte> data(size);
    input.seekg(0, std::ios::beg);
    if (size > 0 && !input.read(reinterpret_cast<char*>(data.data()),
                                static_cast<std::streamsize>(size))) {
        return std::unexpected(Error::io(
            "kismet bundle: short read from '" + path.string() + "'"));
    }
    return data;
}

}  // namespace

Result<KismetBundle> KismetBundle::load(const std::filesystem::path& path) {
    KismetBundle bundle;
    std::error_code ec;
    bundle.root_ = std::filesystem::is_directory(path, ec) && !ec
        ? path
        : path.parent_path();
    const std::filesystem::path manifest =
        std::filesystem::is_directory(path, ec) && !ec
            ? path / "manifest.tsv"
            : path;

    std::ifstream input(manifest);
    if (!input) {
        return std::unexpected(Error::io(
            "kismet bundle: cannot open manifest '" + manifest.string() + "'"));
    }

    std::string line;
    if (!std::getline(input, line)) {
        return std::unexpected(Error::truncated("kismet bundle: empty manifest"));
    }
    if (!line.empty() && line.back() == '\r') line.pop_back();
    const auto header = split_tabs(line);
    if (header.size() < 2 || header[0] != "EMBER_KISMET_BUNDLE" || header[1] != "1") {
        return std::unexpected(Error::invalid_format(
            "kismet bundle: expected EMBER_KISMET_BUNDLE version 1"));
    }
    for (std::size_t i = 2; i < header.size(); ++i) {
        if (header[i].starts_with("engine=")) {
            bundle.engine_version_ = std::string(header[i].substr(7));
        } else if (header[i].starts_with("pointer_size=")) {
            auto value = parse_u64(header[i].substr(13), "pointer_size");
            if (!value) return std::unexpected(std::move(value).error());
            bundle.pointer_size_ = *value;
        }
    }

    std::unordered_set<std::string> ids;
    std::unordered_set<std::string> paths;
    std::size_t line_number = 1;
    while (std::getline(input, line)) {
        ++line_number;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        const auto fields = split_tabs(line);
        if (fields.size() != 8 || fields[0] != "FUNCTION") {
            return std::unexpected(Error::invalid_format(
                "kismet bundle: malformed function record at line " +
                std::to_string(line_number)));
        }
        KismetFunction function;
        function.id = fields[1];
        auto size = parse_u64(fields[2], "bytecode size");
        if (!size) return std::unexpected(std::move(size).error());
        function.bytecode_size = *size;
        auto flags = parse_u64(fields[3], "function flags");
        if (!flags) return std::unexpected(std::move(flags).error());
        function.function_flags = *flags;
        function.class_path = fields[4];
        function.function_path = fields[5];
        function.raw_path = fields[6];
        function.disassembly_path = fields[7];
        if (function.id.empty() || function.function_path.empty() ||
            !safe_relative_path(function.raw_path) ||
            !safe_relative_path(function.disassembly_path)) {
            return std::unexpected(Error::invalid_format(
                "kismet bundle: invalid function record at line " +
                std::to_string(line_number)));
        }
        if (!ids.insert(function.id).second ||
            !paths.insert(function.function_path).second) {
            return std::unexpected(Error::invalid_format(
                "kismet bundle: duplicate function at line " +
                std::to_string(line_number)));
        }
        bundle.functions_.push_back(std::move(function));
    }
    if (bundle.functions_.empty()) {
        return std::unexpected(Error::invalid_format(
            "kismet bundle: manifest contains no functions"));
    }
    return bundle;
}

Result<std::string>
KismetBundle::read_disassembly(const KismetFunction& function) const {
    auto bytes = read_bytes(root_ / function.disassembly_path);
    if (!bytes) return std::unexpected(std::move(bytes).error());
    return std::string(reinterpret_cast<const char*>(bytes->data()), bytes->size());
}

Result<std::vector<std::byte>>
KismetBundle::read_bytecode(const KismetFunction& function) const {
    auto bytes = read_bytes(root_ / function.raw_path);
    if (!bytes) return std::unexpected(std::move(bytes).error());
    if (bytes->size() != function.bytecode_size) {
        return std::unexpected(Error::invalid_format(
            "kismet bundle: bytecode size mismatch for '" +
            function.function_path + "'"));
    }
    return bytes;
}

}  // namespace ember
