// `[Category::Sub]` log-tag mining across string references.

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <map>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include <ember/analysis/pipeline.hpp>
#include <ember/analysis/strings.hpp>
#include <ember/binary/arch.hpp>
#include <ember/common/types.hpp>
#include <ember/disasm/decoder.hpp>
#include <ember/disasm/instruction.hpp>
#include <ember/disasm/register.hpp>
#include <ember/disasm/x64_decoder.hpp>
#include <ember/ir/lifter.hpp>

#include "strings_internal.hpp"

namespace ember {

namespace {

[[nodiscard]] bool looks_like_log_category(std::string_view s) noexcept {
    if (s.size() < 4 || s.size() > 96) return false;
    if (s.find("::") == std::string_view::npos) return false;
    bool alpha = false;
    for (char c : s) {
        const auto u = static_cast<unsigned char>(c);
        if (std::isalpha(u)) alpha = true;
        if (!(std::isalnum(u) || c == '_' || c == ':' || c == '.' || c == '-')) {
            return false;
        }
    }
    return alpha;
}

[[nodiscard]] std::vector<std::string>
extract_log_categories(std::string_view text) {
    std::vector<std::string> out;
    std::size_t pos = 0;
    while ((pos = text.find('[', pos)) != std::string_view::npos) {
        const std::size_t end = text.find(']', pos + 1);
        if (end == std::string_view::npos) break;
        const std::string_view inside = text.substr(pos + 1, end - pos - 1);
        if (looks_like_log_category(inside)) {
            out.emplace_back(inside);
        }
        pos = end + 1;
    }
    return out;
}

}  // namespace

std::vector<LogCategoryCluster>
mine_log_categories(const Binary& b) {
    struct Accum {
        std::set<addr_t> functions;
        std::vector<std::string> examples;
        std::set<std::string> seen_examples;
    };
    std::map<std::string, Accum> by_category;
    struct CategoryString {
        std::string text;
        std::vector<std::string> categories;
    };
    std::map<addr_t, CategoryString> category_strings;

    std::vector<StringEntry> strings;
    for (const auto& sec : b.sections()) {
        scan_section(sec, strings, {});
    }
    for (auto& s : strings) {
        auto categories = extract_log_categories(s.text);
        if (categories.empty()) continue;
        category_strings.emplace(s.addr, CategoryString{
            .text = std::move(s.text),
            .categories = std::move(categories),
        });
    }
    if (category_strings.empty()) return {};

    if (b.arch() == Arch::X86_64) {
        struct WorkItem { addr_t addr; u64 size; };
        std::vector<WorkItem> work;
        std::unordered_set<addr_t> seen;
        for (const auto& fn : enumerate_functions(b, EnumerateMode::Cheap)) {
            if (b.import_at_plt(fn.addr) != nullptr) continue;
            if (fn.size == 0) continue;
            if (!seen.insert(fn.addr).second) continue;
            work.push_back({fn.addr, fn.size});
        }

        X64Decoder dec;
        for (const auto& w : work) {
            auto span = b.bytes_at(w.addr);
            if (span.empty()) continue;
            const std::size_t limit = std::min<std::size_t>(
                span.size(), static_cast<std::size_t>(w.size));

            addr_t ip = w.addr;
            std::size_t off = 0;
            while (off < limit) {
                auto remaining = span.subspan(off, limit - off);
                auto decoded = dec.decode(remaining, ip);
                if (!decoded) { ip += 1; off += 1; continue; }
                const auto& insn = *decoded;

                for (u8 j = 0; j < insn.num_operands; ++j) {
                    const Operand& op = insn.operands[j];
                    addr_t candidate = 0;
                    bool have = false;
                    if (op.kind == Operand::Kind::Relative) {
                        candidate = op.rel.target;
                        have = true;
                    } else if (op.kind == Operand::Kind::Memory && op.mem.has_disp) {
                        if (op.mem.base == Reg::Rip && op.mem.index == Reg::None) {
                            candidate = ip + insn.length +
                                        static_cast<addr_t>(op.mem.disp);
                            have = true;
                        } else if (op.mem.base == Reg::None &&
                                   op.mem.index == Reg::None) {
                            candidate = static_cast<addr_t>(op.mem.disp);
                            have = true;
                        }
                    } else if (op.kind == Operand::Kind::Immediate &&
                               op.imm.size >= 4) {
                        candidate = static_cast<addr_t>(op.imm.value);
                        have = true;
                    }
                    if (!have) continue;
                    auto it = category_strings.find(candidate);
                    if (it == category_strings.end()) continue;
                    for (const auto& cat : it->second.categories) {
                        auto& acc = by_category[cat];
                        acc.functions.insert(w.addr);
                        if (acc.examples.size() < 3 &&
                            acc.seen_examples.insert(it->second.text).second) {
                            acc.examples.push_back(it->second.text);
                        }
                    }
                }

                ip  += insn.length;
                off += insn.length;
            }
        }
    } else {
        for (const auto& [_, s] : category_strings) {
            for (const auto& cat : s.categories) {
                auto& acc = by_category[cat];
                if (acc.examples.size() < 3 &&
                    acc.seen_examples.insert(s.text).second) {
                    acc.examples.push_back(s.text);
                }
            }
        }
    }

    std::vector<LogCategoryCluster> out;
    out.reserve(by_category.size());
    for (auto& [cat, acc] : by_category) {
        LogCategoryCluster c;
        c.category = cat;
        c.functions.assign(acc.functions.begin(), acc.functions.end());
        c.examples = std::move(acc.examples);
        out.push_back(std::move(c));
    }
    std::ranges::sort(out, [](const auto& lhs, const auto& rhs) {
        if (lhs.functions.size() != rhs.functions.size()) {
            return lhs.functions.size() > rhs.functions.size();
        }
        return lhs.category < rhs.category;
    });
    return out;
}

}  // namespace ember
