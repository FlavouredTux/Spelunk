#include <ember/binary/dol.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <fstream>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>

#include <ember/common/bytes.hpp>

namespace ember {

namespace {

constexpr std::size_t kHeaderSize = 0x100;
constexpr std::size_t kTextCount = 7;
constexpr std::size_t kDataCount = 11;
constexpr std::size_t kSectionCount = kTextCount + kDataCount;

struct DolSeg {
    bool is_text = false;
    std::size_t index = 0;
    u32 offset = 0;
    u32 addr = 0;
    u32 size = 0;
};

[[nodiscard]] u32 word_at(std::span<const std::byte> bytes, std::size_t off) noexcept {
    return read_be_at<u32>(bytes.data() + off);
}

[[nodiscard]] bool valid_segment(std::span<const std::byte> bytes, const DolSeg& seg) noexcept {
    if (seg.size == 0) return true;
    if (seg.offset < kHeaderSize) return false;
    if (seg.offset > bytes.size()) return false;
    if (seg.size > bytes.size() - seg.offset) return false;
    return true;
}

[[nodiscard]] bool ranges_overlap(const DolSeg& a, const DolSeg& b) noexcept {
    if (a.size == 0 || b.size == 0) return false;
    const u64 ae = static_cast<u64>(a.offset) + a.size;
    const u64 be = static_cast<u64>(b.offset) + b.size;
    return static_cast<u64>(a.offset) < be && static_cast<u64>(b.offset) < ae;
}

[[nodiscard]] Section make_section(std::span<const std::byte> bytes, const DolSeg& seg) {
    Section s;
    s.name = std::format(".{}{}", seg.is_text ? "text" : "data", seg.index);
    s.vaddr = seg.addr;
    s.file_offset = seg.offset;
    s.size = seg.size;
    s.flags.readable = true;
    s.flags.allocated = true;
    s.flags.executable = seg.is_text;
    s.flags.writable = !seg.is_text;
    s.data = bytes.subspan(seg.offset, seg.size);
    return s;
}

[[nodiscard]] bool is_hex_token(std::string_view tok) noexcept {
    if (tok.starts_with("0x") || tok.starts_with("0X")) tok.remove_prefix(2);
    if (tok.size() < 6 || tok.size() > 16) return false;
    for (char c : tok) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

[[nodiscard]] std::optional<addr_t> parse_addr(std::string_view tok) noexcept {
    if (tok.starts_with("0x") || tok.starts_with("0X")) tok.remove_prefix(2);
    if (!is_hex_token(tok)) return std::nullopt;
    u64 value = 0;
    const auto* first = tok.data();
    const auto* last = tok.data() + tok.size();
    auto [ptr, ec] = std::from_chars(first, last, value, 16);
    if (ec != std::errc{} || ptr != last) return std::nullopt;
    return static_cast<addr_t>(value);
}

[[nodiscard]] bool plausible_name(std::string_view tok) noexcept {
    if (tok.empty() || is_hex_token(tok)) return false;
    if (tok.starts_with(".") || tok.starts_with("0x") || tok.starts_with("0X")) return false;
    bool has_alpha = false;
    for (char c : tok) {
        const unsigned char uc = static_cast<unsigned char>(c);
        if (std::isalpha(uc) || c == '_') has_alpha = true;
        if (std::isalnum(uc) || c == '_' || c == '$' || c == '.' || c == ':' || c == '~') continue;
        return false;
    }
    return has_alpha;
}

[[nodiscard]] std::vector<std::string_view> split_ws(std::string_view line) {
    std::vector<std::string_view> out;
    for (std::size_t i = 0; i < line.size();) {
        while (i < line.size() && std::isspace(static_cast<unsigned char>(line[i]))) ++i;
        const std::size_t start = i;
        while (i < line.size() && !std::isspace(static_cast<unsigned char>(line[i]))) ++i;
        if (start != i) out.push_back(line.substr(start, i - start));
    }
    return out;
}

}  // namespace

bool looks_like_dol_path(const std::filesystem::path& path,
                         std::span<const std::byte> bytes) noexcept {
    if (bytes.size() < kHeaderSize) return false;
    return path.extension() == ".dol" || path.extension() == ".DOL";
}

Result<std::unique_ptr<DolBinary>>
DolBinary::load_from_buffer(std::vector<std::byte> buffer) {
    std::unique_ptr<DolBinary> self(new DolBinary(std::move(buffer)));
    if (auto rv = self->parse(); !rv) return std::unexpected(std::move(rv).error());
    return self;
}

Result<void> DolBinary::parse() {
    if (buffer_.size() < kHeaderSize) {
        return std::unexpected(Error::truncated(std::format(
            "dol: file smaller than header ({} < {})", buffer_.size(), kHeaderSize)));
    }

    const std::span<const std::byte> bytes(buffer_);
    std::array<DolSeg, kSectionCount> segs{};
    for (std::size_t i = 0; i < kTextCount; ++i) {
        segs[i] = DolSeg{
            .is_text = true,
            .index = i,
            .offset = word_at(bytes, i * 4),
            .addr = word_at(bytes, 0x48 + i * 4),
            .size = word_at(bytes, 0x90 + i * 4),
        };
    }
    for (std::size_t i = 0; i < kDataCount; ++i) {
        const std::size_t j = kTextCount + i;
        segs[j] = DolSeg{
            .is_text = false,
            .index = i,
            .offset = word_at(bytes, 0x1c + i * 4),
            .addr = word_at(bytes, 0x64 + i * 4),
            .size = word_at(bytes, 0xac + i * 4),
        };
    }
    entry_ = word_at(bytes, 0xe0);

    std::vector<DolSeg> present;
    for (const auto& seg : segs) {
        if (seg.size == 0) continue;
        if (!valid_segment(bytes, seg)) {
            return std::unexpected(Error::invalid_format(std::format(
                "dol: {}{} range [{:#x}, +{:#x}) is outside file",
                seg.is_text ? "text" : "data", seg.index, seg.offset, seg.size)));
        }
        present.push_back(seg);
    }
    if (present.empty()) return std::unexpected(Error::invalid_format("dol: no loadable sections"));

    for (std::size_t i = 0; i < present.size(); ++i) {
        for (std::size_t j = i + 1; j < present.size(); ++j) {
            if (ranges_overlap(present[i], present[j])) {
                return std::unexpected(Error::invalid_format("dol: overlapping file-backed sections"));
            }
        }
    }

    std::ranges::sort(present, [](const DolSeg& a, const DolSeg& b) {
        if (a.addr != b.addr) return a.addr < b.addr;
        return a.offset < b.offset;
    });

    load_base_ = present.front().addr;
    addr_t max_end = load_base_;
    sections_.reserve(present.size());
    for (const auto& seg : present) {
        sections_.push_back(make_section(bytes, seg));
        max_end = std::max<addr_t>(max_end, static_cast<addr_t>(seg.addr) + seg.size);
    }
    const u32 bss_addr = word_at(bytes, 0xd8);
    const u32 bss_size = word_at(bytes, 0xdc);
    if (bss_size != 0) {
        load_base_ = std::min<addr_t>(load_base_, bss_addr);
        max_end = std::max<addr_t>(max_end, static_cast<addr_t>(bss_addr) + bss_size);
    }
    mapped_size_ = max_end - load_base_;

    Symbol start;
    start.name = "_start";
    start.addr = entry_;
    start.kind = SymbolKind::Function;
    start.is_import = false;
    start.is_export = true;
    for (const auto& s : sections_) {
        if (!s.flags.executable) continue;
        if (entry_ >= s.vaddr && entry_ < s.vaddr + s.size) {
            start.size = (s.vaddr + s.size) - entry_;
            break;
        }
    }
    symbols_.push_back(std::move(start));
    sort_and_dedupe_symbols();
    return {};
}

Result<std::size_t> DolBinary::attach_map_from_path(const std::filesystem::path& path) {
    std::ifstream in(path);
    if (!in) {
        return std::unexpected(Error::io(std::format("cannot open '{}'", path.string())));
    }

    std::size_t added = 0;
    std::string line;
    while (std::getline(in, line)) {
        const auto hash = line.find('#');
        if (hash != std::string::npos) line.resize(hash);
        auto toks = split_ws(line);
        for (std::size_t i = 0; i < toks.size(); ++i) {
            auto addr = parse_addr(toks[i]);
            if (!addr) continue;

            std::string_view name;
            for (std::size_t j = i + 1; j < toks.size(); ++j) {
                if (plausible_name(toks[j])) { name = toks[j]; break; }
            }
            if (name.empty() && i > 0 && plausible_name(toks[i - 1])) name = toks[i - 1];
            if (name.empty()) continue;

            bool in_section = false;
            bool executable = false;
            u64 size = 0;
            for (const auto& s : sections_) {
                if (*addr < s.vaddr || *addr >= s.vaddr + s.size) continue;
                in_section = true;
                executable = s.flags.executable;
                size = (s.vaddr + s.size) - *addr;
                break;
            }
            if (!in_section) continue;

            auto synthetic_start = std::ranges::find_if(symbols_, [&](const Symbol& s) {
                return s.addr == *addr && !s.is_import && s.name == "_start";
            });
            if (synthetic_start != symbols_.end()) {
                synthetic_start->name = std::string(name);
                synthetic_start->kind = executable ? SymbolKind::Function : SymbolKind::Object;
                synthetic_start->size = size;
                ++added;
                break;
            }

            auto existing = std::ranges::find_if(symbols_, [&](const Symbol& s) {
                return s.addr == *addr && !s.is_import && s.name == name;
            });
            if (existing != symbols_.end()) continue;

            Symbol sym;
            sym.name = std::string(name);
            sym.addr = *addr;
            sym.size = size;
            sym.kind = executable ? SymbolKind::Function : SymbolKind::Object;
            sym.is_import = false;
            sym.is_export = true;
            symbols_.push_back(std::move(sym));
            ++added;
            break;
        }
    }
    sort_and_dedupe_symbols();
    invalidate_caches();
    return added;
}

void DolBinary::sort_and_dedupe_symbols() {
    std::ranges::sort(symbols_, [](const Symbol& a, const Symbol& b) {
        if (a.addr != b.addr) return a.addr < b.addr;
        if (a.kind != b.kind) return a.kind < b.kind;
        return a.name < b.name;
    });
    auto last = std::ranges::unique(symbols_, {}, [](const Symbol& s) {
        return std::tuple{s.addr, s.kind, s.name};
    });
    symbols_.erase(last.begin(), last.end());
}

}  // namespace ember
