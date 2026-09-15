#pragma once

#include <cstddef>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <spelunk/common/error.hpp>
#include <spelunk/common/types.hpp>

namespace spelunk {

struct KismetFunction {
    std::string id;
    u64 bytecode_size = 0;
    u64 function_flags = 0;
    std::string class_path;
    std::string function_path;
    std::filesystem::path raw_path;
    std::filesystem::path disassembly_path;
};

class KismetBundle {
public:
    [[nodiscard]] static Result<KismetBundle>
    load(const std::filesystem::path& path);

    [[nodiscard]] const std::vector<KismetFunction>& functions() const noexcept {
        return functions_;
    }

    [[nodiscard]] std::string_view engine_version() const noexcept {
        return engine_version_;
    }

    [[nodiscard]] u64 pointer_size() const noexcept { return pointer_size_; }

    [[nodiscard]] Result<std::string>
    read_disassembly(const KismetFunction& function) const;

    [[nodiscard]] Result<std::vector<std::byte>>
    read_bytecode(const KismetFunction& function) const;

private:
    std::filesystem::path root_;
    std::string engine_version_;
    u64 pointer_size_ = 0;
    std::vector<KismetFunction> functions_;
};

}  // namespace spelunk
