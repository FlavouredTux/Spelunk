#include <ember/common/annotations.hpp>

#include <charconv>
#include <cstddef>
#include <format>
#include <fstream>
#include <sstream>
#include <string_view>

namespace ember {

namespace {

[[nodiscard]] std::string_view trim(std::string_view s) noexcept {
    auto notspace = [](unsigned char c) { return c != ' ' && c != '\t' && c != '\r'; };
    std::size_t b = 0;
    while (b < s.size() && !notspace(static_cast<unsigned char>(s[b]))) ++b;
    std::size_t e = s.size();
    while (e > b && !notspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

[[nodiscard]] std::vector<std::string_view>
split(std::string_view s, char delim) {
    std::vector<std::string_view> out;
    std::size_t start = 0;
    for (std::size_t i = 0; i <= s.size(); ++i) {
        if (i == s.size() || s[i] == delim) {
            out.emplace_back(s.substr(start, i - start));
            start = i + 1;
        }
    }
    return out;
}

[[nodiscard]] bool parse_hex_addr(std::string_view s, addr_t& out) noexcept {
    if (s.starts_with("0x") || s.starts_with("0X")) s.remove_prefix(2);
    u64 v = 0;
    const auto* first = s.data();
    const auto* last  = s.data() + s.size();
    auto r = std::from_chars(first, last, v, 16);
    if (r.ec != std::errc{} || r.ptr != last) return false;
    out = static_cast<addr_t>(v);
    return true;
}

}  // namespace

Result<Annotations>
Annotations::load(const std::filesystem::path& path) {
    std::ifstream f(path);
    if (!f) {
        return std::unexpected(Error::io(std::format(
            "annotations: cannot open '{}'", path.string())));
    }

    std::stringstream buf;
    buf << f.rdbuf();
    const std::string all = buf.str();

    Annotations out;

    std::size_t cursor = 0;
    while (cursor < all.size()) {
        const std::size_t nl = all.find('\n', cursor);
        const std::size_t end = (nl == std::string::npos) ? all.size() : nl;
        std::string_view raw(all.data() + cursor, end - cursor);
        cursor = (nl == std::string::npos) ? end : (nl + 1);

        const std::string_view line = trim(raw);
        if (line.empty() || line.front() == '#') continue;

        // Split record-kind from the rest.
        const std::size_t first_sp = line.find(' ');
        if (first_sp == std::string_view::npos) continue;
        const std::string_view kind = line.substr(0, first_sp);
        const std::string_view rest = trim(line.substr(first_sp + 1));

        if (kind == "rename") {
            const std::size_t sp = rest.find(' ');
            if (sp == std::string_view::npos) continue;
            addr_t addr = 0;
            if (!parse_hex_addr(rest.substr(0, sp), addr)) continue;
            const std::string_view name = trim(rest.substr(sp + 1));
            if (name.empty()) continue;
            out.renames[addr] = std::string(name);
        } else if (kind == "sig") {
            const std::size_t sp = rest.find(' ');
            if (sp == std::string_view::npos) continue;
            addr_t addr = 0;
            if (!parse_hex_addr(rest.substr(0, sp), addr)) continue;
            const std::string_view fields = trim(rest.substr(sp + 1));
            // Pipe-separated: return_type|param_type|param_name|...
            auto parts = split(fields, '|');
            if (parts.empty()) continue;
            FunctionSig sig;
            sig.return_type = std::string(trim(parts[0]));
            for (std::size_t i = 1; i + 1 < parts.size(); i += 2) {
                ParamSig ps;
                ps.type = std::string(trim(parts[i]));
                ps.name = std::string(trim(parts[i + 1]));
                if (ps.type.empty()) continue;
                sig.params.push_back(std::move(ps));
            }
            out.signatures[addr] = std::move(sig);
        }
        else if (kind == "note") {
            const std::size_t sp = rest.find(' ');
            if (sp == std::string_view::npos) continue;
            addr_t addr = 0;
            if (!parse_hex_addr(rest.substr(0, sp), addr)) continue;
            const std::string_view text = trim(rest.substr(sp + 1));
            out.notes[addr] = std::string(text);
        }
    }

    return out;
}

namespace {

std::string escape_note(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            default:   out += c;
        }
    }
    return out;
}

}  // namespace

Result<void>
Annotations::save(const std::filesystem::path& path) const {
    std::error_code ec;
    if (path.has_parent_path()) {
        std::filesystem::create_directories(path.parent_path(), ec);
        if (ec) {
            return std::unexpected(Error::io(std::format(
                "annotations: cannot create '{}': {}",
                path.parent_path().string(), ec.message())));
        }
    }

    std::ofstream f(path, std::ios::trunc);
    if (!f) {
        return std::unexpected(Error::io(std::format(
            "annotations: cannot write '{}'", path.string())));
    }

    f << "# ember annotations\n";
    for (const auto& [addr, name] : renames) {
        f << std::format("rename {:x} {}\n", addr, name);
    }
    for (const auto& [addr, sig] : signatures) {
        f << std::format("sig {:x} {}", addr, sig.return_type);
        for (const auto& p : sig.params) {
            f << '|' << p.type << '|' << p.name;
        }
        f << '\n';
    }
    for (const auto& [addr, text] : notes) {
        f << std::format("note {:x} {}\n", addr, escape_note(text));
    }
    if (!f) {
        return std::unexpected(Error::io(std::format(
            "annotations: short write to '{}'", path.string())));
    }
    return {};
}

}  // namespace ember
