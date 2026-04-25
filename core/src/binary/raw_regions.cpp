#include <ember/binary/raw_regions.hpp>

#include <algorithm>
#include <charconv>
#include <cstdio>
#include <fstream>
#include <format>
#include <sstream>
#include <string_view>

namespace ember {

namespace {

[[nodiscard]] Result<u64> parse_hex(std::string_view tok) {
    if (tok.starts_with("0x") || tok.starts_with("0X")) tok.remove_prefix(2);
    if (tok.empty()) {
        return std::unexpected(Error::invalid_format("regions: empty hex token"));
    }
    u64 v = 0;
    auto r = std::from_chars(tok.data(), tok.data() + tok.size(), v, 16);
    if (r.ec != std::errc{} || r.ptr != tok.data() + tok.size()) {
        return std::unexpected(Error::invalid_format(
            std::format("regions: bad hex '{}'", tok)));
    }
    return v;
}

[[nodiscard]] SectionFlags parse_flags(std::string_view tok) noexcept {
    SectionFlags f{};
    f.allocated = true;
    if (tok.size() >= 1 && tok[0] == 'r') f.readable   = true;
    if (tok.size() >= 2 && tok[1] == 'w') f.writable   = true;
    if (tok.size() >= 3 && tok[2] == 'x') f.executable = true;
    return f;
}

}  // namespace

std::span<const std::byte>
RawRegionsBinary::bytes_at(addr_t vaddr) const noexcept {
    auto it = std::upper_bound(
        ranges_.begin(), ranges_.end(), vaddr,
        [](addr_t v, const Range& r) { return v < r.vaddr; });
    if (it == ranges_.begin()) return {};
    --it;
    if (vaddr < it->vaddr) return {};
    const u64 off = vaddr - it->vaddr;
    if (off >= it->size) return {};
    const std::size_t bound =
        static_cast<std::size_t>(it->size - off);
    return std::span<const std::byte>(buffer_.data() + it->file_off + off, bound);
}

Result<std::unique_ptr<RawRegionsBinary>>
RawRegionsBinary::load_from_manifest(const std::filesystem::path& manifest) {
    std::ifstream in(manifest);
    if (!in) {
        return std::unexpected(Error::io(std::format(
            "regions: cannot open '{}'", manifest.string())));
    }
    auto out = std::unique_ptr<RawRegionsBinary>(new RawRegionsBinary());

    const auto base_dir = manifest.parent_path();

    std::string line;
    std::size_t lineno = 0;
    while (std::getline(in, line)) {
        ++lineno;
        // Strip leading whitespace + skip blanks/comments.
        std::string_view sv = line;
        while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t')) {
            sv.remove_prefix(1);
        }
        if (sv.empty() || sv.front() == '#') continue;

        // Tokenize: vaddr  size  flags  file
        std::istringstream toks{std::string(sv)};
        std::string tva, tsz, tfl, tfile;
        if (!(toks >> tva >> tsz >> tfl >> tfile)) {
            return std::unexpected(Error::invalid_format(std::format(
                "regions: line {}: expected `vaddr size flags file`", lineno)));
        }

        auto va_r = parse_hex(tva);
        if (!va_r) return std::unexpected(std::move(va_r).error());
        auto sz_r = parse_hex(tsz);
        if (!sz_r) return std::unexpected(std::move(sz_r).error());

        const auto file_path = base_dir / tfile;
        std::ifstream rf(file_path, std::ios::binary | std::ios::ate);
        if (!rf) {
            return std::unexpected(Error::io(std::format(
                "regions: line {}: cannot open '{}'", lineno, file_path.string())));
        }
        const auto disk_sz = static_cast<std::size_t>(rf.tellg());
        rf.seekg(0);
        // The manifest's declared size wins — pad with zeros if the file
        // is shorter (uninitialized BSS-like range), truncate if longer.
        const std::size_t take = std::min<std::size_t>(disk_sz, *sz_r);
        const std::size_t file_off = out->buffer_.size();
        out->buffer_.resize(file_off + *sz_r);
        if (take > 0) {
            rf.read(reinterpret_cast<char*>(out->buffer_.data() + file_off),
                    static_cast<std::streamsize>(take));
        }

        out->ranges_.push_back({
            *va_r, *sz_r, file_off, parse_flags(tfl)
        });
    }

    std::sort(out->ranges_.begin(), out->ranges_.end(),
              [](const Range& a, const Range& b) { return a.vaddr < b.vaddr; });

    out->sections_.reserve(out->ranges_.size());
    for (const auto& rg : out->ranges_) {
        Section s;
        s.name        = std::format("region_{:x}", rg.vaddr);
        s.vaddr       = rg.vaddr;
        s.file_offset = rg.file_off;
        s.size        = rg.size;
        s.flags       = rg.flags;
        s.data = std::span<const std::byte>(
            out->buffer_.data() + rg.file_off,
            static_cast<std::size_t>(rg.size));
        out->sections_.push_back(std::move(s));
    }

    return out;
}

}  // namespace ember
