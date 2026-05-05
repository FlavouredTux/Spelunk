#pragma once

#include <string>
#include <unordered_map>
#include <unordered_set>

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

    // True when `target` is a known function entry — named symbol, PLT
    // import stub, or discovered `sub_*`. Used by the walker to classify
    // tail-call jmps; exposed because external callers occasionally
    // need the same predicate.
    [[nodiscard]] bool is_function_entry(addr_t target) const noexcept;

private:
    // Populated on first build() call. Maps function entry VA to the
    // exception-table-reported byte length (.eh_frame FDE pc_range or
    // PE .pdata end - begin). Used by build() to extend fn.end past
    // CFG-unreachable cleanup tails that the walker can't reach via
    // fallthrough/branch alone.
    void ensure_unwind_ranges_() const;

    // Populated on first is_function_entry() call. Union of named-symbol
    // function entries + PLT imports + discovered sub_* entries. Without
    // the discovered set, tail-call jmps on a stripped binary look like
    // intra-function branches and the call graph misses ~all of them.
    void ensure_known_entries_() const;

    const Binary&   binary_;
    const Decoder&  decoder_;
    mutable std::unordered_map<addr_t, u64> unwind_ranges_;
    mutable bool unwind_ranges_init_ = false;
    mutable std::unordered_set<addr_t> known_entries_;
    mutable bool known_entries_init_ = false;
};

}  // namespace ember
