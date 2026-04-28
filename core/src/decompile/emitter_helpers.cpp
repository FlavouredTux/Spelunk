#include "emitter_helpers.hpp"

#include <ember/binary/binary.hpp>
#include <ember/binary/symbol.hpp>
#include <ember/ir/ir.hpp>

namespace ember::detail {

std::optional<std::string_view>
eh_pattern_hint(const IrBlock& bb, const Binary* binary) {
    if (!binary) return std::nullopt;
    for (const auto& inst : bb.insts) {
        if (inst.op != IrOp::Call) continue;
        const Symbol* s = binary->import_at_plt(inst.target1);
        if (!s) continue;
        std::string_view n = s->name;
        if (auto at = n.find('@'); at != std::string_view::npos) n = n.substr(0, at);
        if (n == "__cxa_begin_catch")  return std::string_view{"catch (...)"};
        if (n == "__cxa_throw")        return std::string_view{"throw"};
        if (n == "__cxa_rethrow")      return std::string_view{"throw  // rethrow"};
        if (n == "_Unwind_Resume")     return std::string_view{"unwind-resume"};
        if (n == "__cxa_end_catch")    return std::string_view{"end-catch"};
        if (n == "__cxa_allocate_exception") return std::string_view{"throw  // allocate"};
        return std::nullopt;  // first call wasn't an EH helper
    }
    return std::nullopt;
}

}  // namespace ember::detail
