#pragma once

#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <spelunk/ir/ir.hpp>
#include <spelunk/ir/ssa.hpp>

namespace spelunk {

// Source-like local recovered from an SSA Phi web. The decompiler can still
// keep SSA internally, but this gives later stages a single object to carry
// the source variable's name, role, representative type, member values, and
// optional entry initializer.
enum class SsaMergeLocalRole {
    Value,
    Result,
    Induction,
    Index,
    Accumulator,
    Pointer,
    String,
    Flag,
};

[[nodiscard]] std::string_view base_name_for(SsaMergeLocalRole role) noexcept;

struct SsaMergeLocal {
    std::string            name;
    SsaMergeLocalRole      role = SsaMergeLocalRole::Value;
    IrValue                type_value;
    std::vector<SsaKey>    keys;
    std::optional<IrValue> initializer;
};

struct SsaMergeLocalRecoveryCallbacks {
    std::function<u32(const SsaKey&)> use_count;
    std::function<const IrInst*(const IrValue&)> def_of;
    std::function<std::string(const IrValue&)> type_name;
    std::function<SsaMergeLocalRole(const IrInst&)> role_for_phi;
    std::function<std::optional<IrValue>(const IrValue&)> initializer_candidate;
};

struct SsaMergeLocalRecoveryResult {
    std::map<SsaKey, std::string>     value_names;
    std::map<std::string, SsaMergeLocal> locals;
};

[[nodiscard]] SsaMergeLocalRecoveryResult
recover_ssa_merge_locals(const IrFunction& fn,
                         const SsaMergeLocalRecoveryCallbacks& callbacks);

}  // namespace spelunk
