#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <ember/common/error.hpp>
#include <ember/common/types.hpp>

namespace ember {

struct KismetBlock {
    u64 offset = 0;
    std::vector<std::string> lines;
    std::vector<u64> successors;
    bool computed_jump = false;
};

struct KismetCfg {
    std::vector<KismetBlock> blocks;
};

struct KismetUbergraphEntry {
    u64 offset = 0;
    std::string wrapper_function;
};

[[nodiscard]] Result<KismetCfg>
parse_kismet_cfg(std::string_view disassembly);

[[nodiscard]] std::vector<KismetUbergraphEntry>
discover_kismet_ubergraph_entries(
    std::string_view ubergraph_name,
    const std::vector<std::pair<std::string, std::string>>& function_disassemblies);

[[nodiscard]] std::string emit_kismet_cfg(const KismetCfg& cfg);

[[nodiscard]] std::string emit_kismet_pseudocode(
    const KismetCfg& cfg,
    std::string_view function_name,
    std::optional<u64> entry_offset = std::nullopt);

}  // namespace ember
