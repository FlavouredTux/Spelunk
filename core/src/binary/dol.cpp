#include <spelunk/binary/dol.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <expected>
#include <filesystem>
#include <format>
#include <fstream>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

#include <spelunk/binary/section.hpp>
#include <spelunk/binary/symbol.hpp>
#include <spelunk/common/bytes.hpp>
#include <spelunk/common/error.hpp>
#include <spelunk/common/text.hpp>
#include <spelunk/common/types.hpp>

namespace spelunk {

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

[[nodiscard]] std::optional<u64> parse_integer(std::string_view text) noexcept {
    text = trim_space(text);
    int base = 10;
    if (text.starts_with("0x") || text.starts_with("0X")) {
        text.remove_prefix(2);
        base = 16;
    }
    if (text.empty()) return std::nullopt;
    u64 value = 0;
    const auto [ptr, ec] = std::from_chars(
        text.data(), text.data() + text.size(), value, base);
    if (ec != std::errc{} || ptr != text.data() + text.size()) return std::nullopt;
    return value;
}

[[nodiscard]] bool dtk_section_name_matches(std::string_view declared,
                                            std::string_view actual) noexcept {
    if (declared == actual) return true;
    if ((declared == ".text" || declared == ".data") && actual.starts_with(declared)) {
        const auto suffix = actual.substr(declared.size());
        return !suffix.empty() && std::ranges::all_of(suffix, [](char c) {
            return std::isdigit(static_cast<unsigned char>(c));
        });
    }
    return false;
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
        Section bss;
        bss.name = ".bss";
        bss.vaddr = bss_addr;
        bss.size = bss_size;
        bss.flags.readable = true;
        bss.flags.writable = true;
        bss.flags.allocated = true;
        sections_.push_back(std::move(bss));
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
                synthetic_start->size = executable ? 0 : size;
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
            sym.size = executable ? 0 : size;
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

Result<std::size_t>
DolBinary::attach_dtk_symbols_from_path(const std::filesystem::path& path) {
    std::ifstream in(path);
    if (!in) {
        return std::unexpected(Error::io(std::format("cannot open '{}'", path.string())));
    }

    std::size_t added = 0;
    std::size_t lineno = 0;
    std::string line;
    while (std::getline(in, line)) {
        ++lineno;
        if (!line.empty() && line.back() == '\r') line.pop_back();

        const auto slash = line.find("//");
        const std::string_view attributes = slash == std::string::npos
            ? std::string_view{} : trim_space(std::string_view(line).substr(slash + 2));
        std::string_view declaration = trim_space(std::string_view(line).substr(0, slash));
        if (declaration.empty() || declaration.starts_with('#')) continue;

        const auto equal = declaration.find('=');
        const auto colon = declaration.rfind(':');
        if (equal == std::string_view::npos || colon == std::string_view::npos || colon < equal) {
            return std::unexpected(Error::invalid_format(std::format(
                "dtk symbols: {}:{}: expected NAME = SECTION:ADDRESS",
                path.string(), lineno)));
        }

        const std::string_view name = trim_space(declaration.substr(0, equal));
        const std::string_view section_name = trim_space(
            declaration.substr(equal + 1, colon - equal - 1));
        std::string_view address_text = trim_space(declaration.substr(colon + 1));
        if (address_text.ends_with(';')) address_text = trim_space(address_text.substr(0, address_text.size() - 1));
        const auto address = parse_integer(address_text);
        if (name.empty() || !address) {
            return std::unexpected(Error::invalid_format(std::format(
                "dtk symbols: {}:{}: invalid name or address",
                path.string(), lineno)));
        }

        // Metrowerks EABI places each small-data anchor 0x8000 bytes past
        // the beginning of its addressable range. DTK's exact section-tagged
        // map lets us retain that information even though a DOL header itself
        // only calls these generic data sections.
        auto remember_small_data_start = [&](std::optional<addr_t>& base) {
            const addr_t candidate = static_cast<addr_t>(*address) + 0x8000;
            if (!base || candidate < *base) base = candidate;
        };
        if (section_name == ".sdata" || section_name == ".sbss") {
            remember_small_data_start(sda_base_);
        } else if (section_name == ".sdata2" || section_name == ".sbss2") {
            remember_small_data_start(sda2_base_);
        }

        std::optional<SymbolKind> declared_kind;
        u64 declared_size = 0;
        bool is_export = true;
        for (const auto token : split_ws(attributes)) {
            if (token.starts_with("type:")) {
                const auto value = token.substr(5);
                if (value == "function") declared_kind = SymbolKind::Function;
                else if (value == "object") declared_kind = SymbolKind::Object;
            } else if (token.starts_with("size:")) {
                auto value = parse_integer(token.substr(5));
                if (!value) {
                    return std::unexpected(Error::invalid_format(std::format(
                        "dtk symbols: {}:{}: invalid size attribute",
                        path.string(), lineno)));
                }
                declared_size = *value;
            } else if (token == "scope:local") {
                is_export = false;
            }
        }

        const Section* containing = nullptr;
        for (const auto& section : sections_) {
            if (*address < section.vaddr || *address >= section.vaddr + section.size) continue;
            if (dtk_section_name_matches(section_name, section.name)) {
                containing = &section;
                break;
            }
            if (!containing) containing = &section;
            if (declared_kind &&
                ((*declared_kind == SymbolKind::Function) == section.flags.executable)) {
                containing = &section;
            }
        }
        // DTK symbol files can contain absolute/special linker symbols that
        // do not belong to the selected DOL image. They are not loadable
        // symbols, so skip them without poisoning the rest of the file.
        if (!containing) continue;

        const SymbolKind kind = declared_kind.value_or(
            containing->flags.executable ? SymbolKind::Function : SymbolKind::Object);
        auto synthetic_start = std::ranges::find_if(symbols_, [&](const Symbol& symbol) {
            return symbol.addr == *address && !symbol.is_import && symbol.name == "_start";
        });
        if (synthetic_start != symbols_.end()) {
            synthetic_start->name = std::string(name);
            synthetic_start->kind = kind;
            synthetic_start->size = declared_size;
            synthetic_start->is_export = is_export;
            ++added;
            continue;
        }

        const auto existing = std::ranges::find_if(symbols_, [&](const Symbol& symbol) {
            return symbol.addr == *address && !symbol.is_import && symbol.name == name;
        });
        if (existing != symbols_.end()) continue;

        Symbol symbol;
        symbol.name = std::string(name);
        symbol.addr = *address;
        symbol.size = declared_size;
        symbol.kind = kind;
        symbol.is_export = is_export;
        symbols_.push_back(std::move(symbol));
        ++added;
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

}  // namespace spelunk
