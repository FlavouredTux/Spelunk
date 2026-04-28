#pragma once

#include <optional>
#include <string_view>

namespace ember {
struct IrBlock;
class Binary;
}  // namespace ember

namespace ember::detail {

// A block is an exception-handler landing pad when its first (non-ABI) call
// is to a C++/Itanium unwinder helper. We don't have LSDA parsed yet, so the
// next best signal is pattern-matching these names — they make the reader
// aware that control arrived here by throw, not by normal flow.
[[nodiscard]] std::optional<std::string_view>
eh_pattern_hint(const IrBlock& bb, const Binary* binary);

}  // namespace ember::detail
