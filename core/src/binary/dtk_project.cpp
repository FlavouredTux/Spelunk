#include <ember/binary/dtk_project.hpp>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <format>
#include <map>
#include <system_error>
#include <vector>

namespace ember {

namespace {

[[nodiscard]] std::string_view trim(std::string_view s) noexcept {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) {
        s.remove_prefix(1);
    }
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) {
        s.remove_suffix(1);
    }
    return s;
}

[[nodiscard]] std::string strip_yaml_comment(std::string_view line) {
    bool single = false;
    bool quoted = false;
    bool escaped = false;
    for (std::size_t i = 0; i < line.size(); ++i) {
        const char c = line[i];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (quoted && c == '\\') {
            escaped = true;
            continue;
        }
        if (!quoted && c == '\'') {
            single = !single;
            continue;
        }
        if (!single && c == '"') {
            quoted = !quoted;
            continue;
        }
        if (!single && !quoted && c == '#') {
            return std::string(line.substr(0, i));
        }
    }
    return std::string(line);
}

[[nodiscard]] std::string scalar_value(std::string_view value) {
    value = trim(value);
    if (value.size() >= 2 &&
        ((value.front() == '\'' && value.back() == '\'') ||
         (value.front() == '"' && value.back() == '"'))) {
        value.remove_prefix(1);
        value.remove_suffix(1);
    }
    return std::string(value);
}

[[nodiscard]] Result<std::map<std::string, std::string>>
read_top_level_scalars(const std::filesystem::path& path) {
    std::ifstream in(path);
    if (!in) {
        return std::unexpected(Error::io(std::format(
            "dtk: cannot open config '{}'", path.string())));
    }

    std::map<std::string, std::string> out;
    std::string line;
    std::size_t lineno = 0;
    while (std::getline(in, line)) {
        ++lineno;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || std::isspace(static_cast<unsigned char>(line.front()))) {
            continue;  // nested YAML belongs to REL/module configuration
        }

        std::string without_comment = strip_yaml_comment(line);
        const std::string_view view = trim(without_comment);
        if (view.empty() || view == "---" || view == "...") continue;
        const auto colon = view.find(':');
        if (colon == std::string_view::npos) {
            return std::unexpected(Error::invalid_format(std::format(
                "dtk: {}:{}: expected a top-level key:value entry",
                path.string(), lineno)));
        }
        const std::string_view key = trim(view.substr(0, colon));
        const std::string_view value = trim(view.substr(colon + 1));
        if (key.empty()) continue;
        // Mapping/list-valued keys are intentionally ignored in the first
        // main-DOL slice. The scalar keys below are all we consume.
        if (value.empty() || value == "{}" || value == "[]") continue;
        out[std::string(key)] = scalar_value(value);
    }
    return out;
}

[[nodiscard]] Result<std::map<std::string, std::string>>
read_module_scalars(const std::filesystem::path& path,
                    std::string_view wanted_module) {
    std::ifstream in(path);
    if (!in) {
        return std::unexpected(Error::io(std::format(
            "dtk: cannot open config '{}'", path.string())));
    }

    std::vector<std::map<std::string, std::string>> modules;
    std::map<std::string, std::string> current;
    bool in_modules = false;
    std::string line;
    std::size_t lineno = 0;
    auto finish_current = [&] {
        if (!current.empty()) modules.push_back(std::move(current));
        current.clear();
    };
    while (std::getline(in, line)) {
        ++lineno;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::string without_comment = strip_yaml_comment(line);
        const std::string_view view = trim(without_comment);
        if (view.empty()) continue;

        const bool indented = !without_comment.empty() &&
            std::isspace(static_cast<unsigned char>(without_comment.front()));
        if (!indented && !(in_modules && view.starts_with('-'))) {
            if (view == "modules:") {
                in_modules = true;
                continue;
            }
            if (in_modules) break;
            continue;
        }
        if (!in_modules) continue;

        std::string_view field = view;
        if (field.starts_with('-')) {
            finish_current();
            field = trim(field.substr(1));
            if (field.empty()) continue;
        }
        const auto colon = field.find(':');
        if (colon == std::string_view::npos) {
            return std::unexpected(Error::invalid_format(std::format(
                "dtk: {}:{}: expected a module key:value entry",
                path.string(), lineno)));
        }
        const auto key = trim(field.substr(0, colon));
        const auto value = trim(field.substr(colon + 1));
        if (!key.empty() && !value.empty()) {
            current[std::string(key)] = scalar_value(value);
        }
    }
    finish_current();

    auto module_name = [](const std::map<std::string, std::string>& values) {
        if (const auto it = values.find("name"); it != values.end() && !it->second.empty()) {
            return it->second;
        }
        const auto object = values.find("object");
        if (object == values.end()) return std::string{};
        std::string_view object_path = object->second;
        if (const auto colon = object_path.find(':'); colon != std::string_view::npos) {
            object_path = object_path.substr(0, colon);
        }
        return std::filesystem::path(object_path).stem().string();
    };

    for (auto& values : modules) {
        if (module_name(values) == wanted_module) return values;
    }
    return std::unexpected(Error::invalid_format(std::format(
        "dtk: module '{}' was not found in '{}'",
        wanted_module, path.string())));
}

[[nodiscard]] std::filesystem::path
absolute_normal(const std::filesystem::path& path) {
    std::error_code ec;
    auto out = std::filesystem::weakly_canonical(path, ec);
    if (!ec) return out;
    ec.clear();
    out = std::filesystem::absolute(path, ec);
    return ec ? path.lexically_normal() : out.lexically_normal();
}

[[nodiscard]] std::filesystem::path
project_root_for(const std::filesystem::path& config) {
    for (auto dir = config.parent_path(); !dir.empty(); dir = dir.parent_path()) {
        if (dir.filename() == "config") return dir.parent_path();
        const auto parent = dir.parent_path();
        if (parent == dir) break;
    }
    return config.parent_path();
}

[[nodiscard]] std::vector<std::filesystem::path>
find_version_configs(const std::filesystem::path& root) {
    std::vector<std::filesystem::path> out;
    std::error_code ec;
    const auto config_root = root / "config";
    if (!std::filesystem::is_directory(config_root, ec) || ec) return out;
    for (const auto& entry : std::filesystem::directory_iterator(config_root, ec)) {
        if (ec) break;
        if (!entry.is_directory(ec) || ec) continue;
        const auto candidate = entry.path() / "config.yml";
        if (std::filesystem::is_regular_file(candidate, ec) && !ec) {
            out.push_back(candidate);
        }
    }
    std::ranges::sort(out);
    return out;
}

[[nodiscard]] Result<std::filesystem::path>
resolve_config_path(const std::filesystem::path& raw_input,
                    std::string_view version) {
    const auto input = absolute_normal(raw_input);
    std::error_code ec;
    if (std::filesystem::is_regular_file(input, ec) && !ec) return input;
    if (!std::filesystem::is_directory(input, ec) || ec) {
        return std::unexpected(Error::io(std::format(
            "dtk: '{}' is not a project directory or config file",
            raw_input.string())));
    }

    const auto direct = input / "config.yml";
    if (std::filesystem::is_regular_file(direct, ec) && !ec) return direct;

    if (!version.empty()) {
        for (const auto& candidate : {
                 input / "config" / std::string(version) / "config.yml",
                 input / std::string(version) / "config.yml"}) {
            if (std::filesystem::is_regular_file(candidate, ec) && !ec) {
                return candidate;
            }
        }
        return std::unexpected(Error::io(std::format(
            "dtk: cannot find config for version '{}' under '{}'",
            version, input.string())));
    }

    auto configs = find_version_configs(input);
    if (configs.size() == 1) return configs.front();
    if (configs.empty()) {
        return std::unexpected(Error::io(std::format(
            "dtk: cannot find config.yml under '{}'", input.string())));
    }
    return std::unexpected(Error::invalid_format(std::format(
        "dtk: project has {} versions; select one with --version",
        configs.size())));
}

[[nodiscard]] std::filesystem::path
resolve_project_path(const std::filesystem::path& root,
                     std::string_view value) {
    const std::filesystem::path path(value);
    return absolute_normal(path.is_absolute() ? path : root / path);
}

[[nodiscard]] std::filesystem::path
resolve_object_path(const std::filesystem::path& root,
                    std::string_view value) {
    const auto colon = value.find(':');
    if (colon == std::string_view::npos) return resolve_project_path(root, value);

    std::filesystem::path container(value.substr(0, colon));
    container.replace_extension();
    std::string nested(value.substr(colon + 1));
    std::ranges::replace(nested, ':', '/');
    return absolute_normal(root / container / nested);
}

}  // namespace

Result<DtkProject>
resolve_dtk_project(const std::filesystem::path& input,
                    std::string_view version,
                    std::string_view module) {
    if (input.empty()) {
        return std::unexpected(Error::invalid_format(
            "dtk: project path is empty"));
    }
    auto config = resolve_config_path(input, version);
    if (!config) return std::unexpected(std::move(config).error());

    auto values = read_top_level_scalars(*config);
    if (!values) return std::unexpected(std::move(values).error());
    std::map<std::string, std::string> selected_values;
    const std::map<std::string, std::string>* object_values = &*values;
    if (!module.empty()) {
        auto selected = read_module_scalars(*config, module);
        if (!selected) return std::unexpected(std::move(selected).error());
        selected_values = std::move(*selected);
        object_values = &selected_values;
    }
    const auto object_it = object_values->find("object");
    if (object_it == object_values->end() || object_it->second.empty()) {
        return std::unexpected(Error::invalid_format(std::format(
            "dtk: config '{}' has no '{}' object path",
            config->string(), module.empty() ? "main-module" : std::string(module))));
    }

    DtkProject out;
    out.config_path = absolute_normal(*config);
    out.project_root = project_root_for(out.config_path);
    out.version = std::string(version);
    if (out.version.empty() && out.config_path.parent_path().parent_path().filename() == "config") {
        out.version = out.config_path.parent_path().filename().string();
    }
    if (const auto it = object_values->find("name"); it != object_values->end()) {
        out.module_name = it->second;
    }
    if (out.module_name.empty()) out.module_name = module.empty() ? "main" : std::string(module);

    std::filesystem::path object_root = out.project_root;
    if (const auto it = values->find("object_base");
        it != values->end() && !it->second.empty() && it->second != "null" && it->second != "~") {
        object_root = resolve_project_path(out.project_root, it->second);
    }
    out.object_path = resolve_object_path(object_root, object_it->second);

    if (const auto it = object_values->find("symbols");
        it != object_values->end() && !it->second.empty()) {
        out.symbols_path = resolve_project_path(out.project_root, it->second);
    } else if (!module.empty()) {
        out.symbols_path = out.config_path.parent_path() /
                           std::string(module) / "symbols.txt";
    } else {
        out.symbols_path = out.config_path.parent_path() / "symbols.txt";
    }

    std::error_code ec;
    if (!std::filesystem::is_regular_file(out.object_path, ec) || ec) {
        const bool looks_vfs = object_it->second.find(':') != std::string::npos;
        return std::unexpected(Error::io(std::format(
            "dtk: {} object '{}' does not exist{}",
            module.empty() ? "main" : std::string(module),
            out.object_path.string(),
            looks_vfs ? " (extract the DTK disc-image/VFS object first)" : "")));
    }
    if (!std::filesystem::is_regular_file(out.symbols_path, ec) || ec) {
        return std::unexpected(Error::io(std::format(
            "dtk: symbols file '{}' does not exist",
            out.symbols_path.string())));
    }
    return out;
}

}  // namespace ember
