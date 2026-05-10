#pragma once

#include <algorithm>
#include <string>
#include <vector>

#include <ember/analysis/pipeline.hpp>

namespace ember::analysis {

struct FnTable {
    struct Row {
        addr_t      entry;
        addr_t      end;
        std::string name;
    };
    std::vector<Row> rows;

    explicit FnTable(const Binary& b) {
        const auto fns = enumerate_functions(b, EnumerateMode::Cheap);
        rows.reserve(fns.size());
        for (std::size_t i = 0; i < fns.size(); ++i) {
            Row r{fns[i].addr, 0, fns[i].name};
            if (fns[i].size != 0) {
                r.end = fns[i].addr + fns[i].size;
            } else if (i + 1 < fns.size()) {
                r.end = fns[i + 1].addr;
            } else {
                for (const auto& s : b.sections()) {
                    if (fns[i].addr >= s.vaddr &&
                        fns[i].addr <  s.vaddr + s.size) {
                        r.end = s.vaddr + s.size;
                        break;
                    }
                }
            }
            rows.push_back(std::move(r));
        }
    }

    [[nodiscard]] const Row* containing(addr_t pc) const noexcept {
        auto it = std::ranges::upper_bound(rows, pc,
            {}, [](const Row& r) noexcept { return r.entry; });
        if (it == rows.begin()) return nullptr;
        --it;
        if (it->end != 0 && pc >= it->end) return nullptr;
        return &*it;
    }
};

}  // namespace ember::analysis
