#pragma once

#include <string>
#include <unordered_map>

#include <ember/analysis/function.hpp>
#include <ember/binary/binary.hpp>
#include <ember/common/error.hpp>
#include <ember/common/types.hpp>
#include <ember/disasm/decoder.hpp>

namespace ember {

class CfgBuilder {
public:
    CfgBuilder(const Binary& binary, const Decoder& decoder) noexcept
        : binary_(binary), decoder_(decoder) {}

    [[nodiscard]] Result<Function>
    build(addr_t entry, std::string name = {}) const;

private:
    // Populated on first build() call. Maps function entry VA to the
    // exception-table-reported byte length (.eh_frame FDE pc_range or
    // PE .pdata end - begin). Used by build() to extend fn.end past
    // CFG-unreachable cleanup tails that the walker can't reach via
    // fallthrough/branch alone.
    void ensure_unwind_ranges_() const;

    const Binary&   binary_;
    const Decoder&  decoder_;
    mutable std::unordered_map<addr_t, u64> unwind_ranges_;
    mutable bool unwind_ranges_init_ = false;
};

}  // namespace ember
