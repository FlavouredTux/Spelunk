#include <ember/common/annotations.hpp>

#include <charconv>
#include <cstddef>
#include <format>
#include <fstream>
#include <limits>
#include <sstream>
#include <string_view>
#include <system_error>

#include <ember/common/hash.hpp>

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

[[nodiscard]] bool parse_hex_u64(std::string_view s, u64& out) noexcept {
    return parse_hex_addr(s, out);  // same wire format as addr_t
}

[[nodiscard]] bool parse_float_clamped(std::string_view s, float& out) noexcept {
    // Keep this locale-independent without relying on libc++ float from_chars,
    // which is not available on all supported CI targets.
    if (s.empty()) return false;

    std::size_t i = 0;
    bool neg = false;
    if (s[i] == '-' || s[i] == '+') {
        neg = s[i] == '-';
        ++i;
        if (i == s.size()) return false;
    }

    double v = 0.0;
    bool any_digit = false;
    while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
        any_digit = true;
        v = v * 10.0 + static_cast<double>(s[i] - '0');
        ++i;
    }
    if (i < s.size() && s[i] == '.') {
        ++i;
        double place = 0.1;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
            any_digit = true;
            v += static_cast<double>(s[i] - '0') * place;
            place *= 0.1;
            ++i;
        }
    }
    if (!any_digit) return false;

    if (i < s.size() && (s[i] == 'e' || s[i] == 'E')) {
        ++i;
        if (i == s.size()) return false;
        bool exp_neg = false;
        if (s[i] == '-' || s[i] == '+') {
            exp_neg = s[i] == '-';
            ++i;
            if (i == s.size()) return false;
        }
        int exp = 0;
        bool exp_digit = false;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
            exp_digit = true;
            if (exp < 64) exp = exp * 10 + (s[i] - '0');
            ++i;
        }
        if (!exp_digit) return false;
        const int capped = exp > 64 ? 64 : exp;
        for (int n = 0; n < capped; ++n) v = exp_neg ? (v / 10.0) : (v * 10.0);
    }

    if (i != s.size()) return false;
    if (neg) v = -v;
    if (v < 0.0) v = 0.0;
    if (v > 1.0) v = 1.0;
    out = static_cast<float>(v);
    return true;
}

// Pipe-separated split that honours `\|` as an escaped delimiter.
// Used by the meta-record tail parser.
[[nodiscard]] std::vector<std::string_view>
split_unescaped_pipe(std::string_view s) {
    std::vector<std::string_view> out;
    std::size_t start = 0;
    for (std::size_t i = 0; i <= s.size(); ++i) {
        if (i + 1 < s.size() && s[i] == '\\' && s[i + 1] == '|') {
            ++i;  // skip past the escaped pipe
            continue;
        }
        if (i == s.size() || s[i] == '|') {
            out.emplace_back(s.substr(start, i - start));
            start = i + 1;
        }
    }
    return out;
}

[[nodiscard]] std::string unescape_meta_value(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            const char n = s[i + 1];
            if (n == '\\' || n == '|') { out += n; ++i; continue; }
            if (n == 'n')               { out += '\n'; ++i; continue; }
            if (n == 'r')               { out += '\r'; ++i; continue; }
        }
        out += s[i];
    }
    return out;
}

[[nodiscard]] bool parse_i64_auto(std::string_view s, i64& out) noexcept {
    bool neg = false;
    if (s.starts_with("-")) {
        neg = true;
        s.remove_prefix(1);
    } else if (s.starts_with("+")) {
        s.remove_prefix(1);
    }
    if (s.starts_with("0x") || s.starts_with("0X")) {
        s.remove_prefix(2);
        u64 v = 0;
        auto r = std::from_chars(s.data(), s.data() + s.size(), v, 16);
        if (r.ec != std::errc{} || r.ptr != s.data() + s.size()) return false;
        const u64 limit = static_cast<u64>(std::numeric_limits<i64>::max()) + (neg ? 1ull : 0ull);
        if (v > limit) return false;
        if (neg && v == limit) out = std::numeric_limits<i64>::min();
        else out = neg ? -static_cast<i64>(v) : static_cast<i64>(v);
        return true;
    }
    i64 v = 0;
    auto r = std::from_chars(s.data(), s.data() + s.size(), v, 10);
    if (r.ec != std::errc{} || r.ptr != s.data() + s.size()) return false;
    out = neg ? -v : v;
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
        else if (kind == "const") {
            const std::size_t sp = rest.find(' ');
            if (sp == std::string_view::npos) continue;
            u64 value = 0;
            if (!parse_hex_u64(rest.substr(0, sp), value)) continue;
            const std::string_view name = trim(rest.substr(sp + 1));
            if (name.empty()) continue;
            out.named_constants[value] = std::string(name);
        }
        else if (kind == "meta") {
            // meta <subkind> <hex-addr> conf=<float>|src=<tag>|ev=<text>
            // Subkind: rename | note | sig. Tail keys are pipe-separated
            // key=value pairs; embedded `|` is `\|`, `\n` / `\r` / `\\`
            // also escape themselves. Unknown subkinds and unknown keys
            // are silently dropped — newer ember can produce records old
            // ember reads cleanly without exploding.
            const std::size_t sp1 = rest.find(' ');
            if (sp1 == std::string_view::npos) continue;
            const std::string_view subkind = rest.substr(0, sp1);
            const std::string_view rest2 = trim(rest.substr(sp1 + 1));
            const std::size_t sp2 = rest2.find(' ');
            if (sp2 == std::string_view::npos) continue;
            addr_t addr = 0;
            if (!parse_hex_addr(rest2.substr(0, sp2), addr)) continue;
            const std::string_view tail = trim(rest2.substr(sp2 + 1));

            AnnotationMeta m;
            for (auto raw_part : split_unescaped_pipe(tail)) {
                const std::string_view part = trim(raw_part);
                const std::size_t eq = part.find('=');
                if (eq == std::string_view::npos) continue;
                const std::string_view key = trim(part.substr(0, eq));
                const std::string_view val = part.substr(eq + 1);
                if (key == "conf") {
                    (void)parse_float_clamped(trim(val), m.confidence);
                } else if (key == "ev") {
                    m.evidence = unescape_meta_value(val);
                } else if (key == "src") {
                    m.source = unescape_meta_value(trim(val));
                }
                // Unknown keys: skip silently (forward compat).
            }

            if (subkind == "rename")    out.rename_meta[addr]    = std::move(m);
            else if (subkind == "note") out.note_meta[addr]      = std::move(m);
            else if (subkind == "sig")  out.signature_meta[addr] = std::move(m);
            // Unknown subkinds: skip silently (forward compat).
        }
        else if (kind == "field") {
            const std::size_t sp = rest.find(' ');
            if (sp == std::string_view::npos) continue;
            addr_t addr = 0;
            if (!parse_hex_addr(rest.substr(0, sp), addr)) continue;
            auto parts = split(trim(rest.substr(sp + 1)), '|');
            if (parts.size() < 3) continue;
            u64 param = 0;
            if (!parse_hex_u64(trim(parts[0]), param)) continue;
            i64 off = 0;
            if (!parse_i64_auto(trim(parts[1]), off)) continue;
            const std::string_view name = trim(parts[2]);
            if (name.empty()) continue;
            out.field_names[FieldKey{addr, static_cast<std::size_t>(param), off}] =
                std::string(name);
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

// Same as escape_note but also escapes `|` since meta-record values
// share their line with pipe-separated key=value siblings. Round-trips
// cleanly through unescape_meta_value above.
std::string escape_meta_value(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '|':  out += "\\|";  break;
            default:   out += c;
        }
    }
    return out;
}

[[nodiscard]] bool meta_is_empty(const AnnotationMeta& m) noexcept {
    return m.confidence == 0.0f && m.evidence.empty() && m.source.empty();
}

void append_meta_line(std::string& out, std::string_view subkind,
                      addr_t addr, const AnnotationMeta& m) {
    if (meta_is_empty(m)) return;
    out += std::format("meta {} {:x}", subkind, addr);
    bool first = true;
    auto sep = [&] { out += first ? ' ' : '|'; first = false; };
    if (m.confidence > 0.0f) {
        sep();
        out += std::format("conf={:.3g}", m.confidence);
    }
    if (!m.source.empty()) {
        sep();
        out += "src=";
        out += escape_meta_value(m.source);
    }
    if (!m.evidence.empty()) {
        sep();
        out += "ev=";
        out += escape_meta_value(m.evidence);
    }
    out += '\n';
}

}  // namespace

std::string Annotations::to_text() const {
    std::string out = "# ember annotations\n";
    for (const auto& [addr, name] : renames) {
        out += std::format("rename {:x} {}\n", addr, name);
        if (auto it = rename_meta.find(addr); it != rename_meta.end()) {
            append_meta_line(out, "rename", addr, it->second);
        }
    }
    for (const auto& [addr, sig] : signatures) {
        out += std::format("sig {:x} {}", addr, sig.return_type);
        for (const auto& p : sig.params) {
            out += '|';
            out += p.type;
            out += '|';
            out += p.name;
        }
        out += '\n';
        if (auto it = signature_meta.find(addr); it != signature_meta.end()) {
            append_meta_line(out, "sig", addr, it->second);
        }
    }
    for (const auto& [addr, text] : notes) {
        out += std::format("note {:x} {}\n", addr, escape_note(text));
        if (auto it = note_meta.find(addr); it != note_meta.end()) {
            append_meta_line(out, "note", addr, it->second);
        }
    }
    for (const auto& [value, name] : named_constants) {
        out += std::format("const {:x} {}\n", value, name);
    }
    for (const auto& [key, name] : field_names) {
        out += std::format("field {:x} {:x}|{:#x}|{}\n",
                           key.function, key.param, key.offset, name);
    }
    return out;
}

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

    // Write to a sibling tmp file then rename, so a crash or ENOSPC
    // mid-write can't leave the annotations file truncated.
    namespace fs = std::filesystem;
    const fs::path tmp = path.string() + ".tmp";
    {
        std::ofstream f(tmp, std::ios::trunc);
        if (!f) {
            return std::unexpected(Error::io(std::format(
                "annotations: cannot write '{}'", tmp.string())));
        }
        const std::string text = to_text();
        f.write(text.data(), static_cast<std::streamsize>(text.size()));
        if (!f) {
            return std::unexpected(Error::io(std::format(
                "annotations: short write to '{}'", tmp.string())));
        }
    }
    fs::rename(tmp, path, ec);
    if (ec) {
        return std::unexpected(Error::io(std::format(
            "annotations: rename '{}' -> '{}': {}",
            tmp.string(), path.string(), ec.message())));
    }
    return {};
}

std::filesystem::path
sidecar_annotation_path(const std::filesystem::path& binary) {
    namespace fs = std::filesystem;
    if (binary.empty()) return {};
    fs::path p = binary;
    p += ".ember-annotations";
    return p;
}

std::filesystem::path
cache_annotation_path(const std::filesystem::path& binary,
                      const std::filesystem::path& cache_dir) {
    namespace fs = std::filesystem;
    if (binary.empty() || cache_dir.empty()) return {};
    // Path-keyed, not content-keyed: the whole point of persistent
    // annotations is surviving binary version swaps at the same path.
    // Using a content hash would throw away every rename as soon as the
    // user drops in v N+1 of the target. FNV of the absolute parent dir
    // plus the basename is stable under content changes and distinct
    // across "same name in a different directory".
    std::error_code ec;
    fs::path abs = fs::weakly_canonical(binary, ec);
    if (ec || abs.empty()) abs = fs::absolute(binary, ec);
    if (ec) abs = binary;
    const fs::path parent = abs.has_parent_path() ? abs.parent_path() : fs::path{"."};
    const std::string parent_s = parent.string();
    const std::string key = std::format("{}@{:016x}",
        abs.filename().string(),
        fnv1a_64(parent_s));
    return cache_dir / "annotations" / key / "annotations.db";
}

AnnotationLocation
resolve_annotation_location(const std::filesystem::path& binary,
                            const std::filesystem::path& explicit_path,
                            const std::filesystem::path& cache_dir) {
    namespace fs = std::filesystem;
    if (!explicit_path.empty()) {
        return {explicit_path, AnnotationSource::Explicit};
    }
    if (binary.empty()) return {};

    const auto sidecar = sidecar_annotation_path(binary);
    std::error_code ec;
    if (!sidecar.empty() && fs::exists(sidecar, ec) && !ec) {
        return {sidecar, AnnotationSource::Sidecar};
    }
    return {cache_annotation_path(binary, cache_dir), AnnotationSource::Cache};
}

}  // namespace ember
