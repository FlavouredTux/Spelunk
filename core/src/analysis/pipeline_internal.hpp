#pragma once

// Helpers shared by the pipeline_*.cpp translation units.

#include <cstddef>
#include <optional>
#include <span>
#include <string>

#include <spelunk/analysis/pipeline.hpp>
#include <spelunk/binary/arch.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/disasm/instruction.hpp>

namespace spelunk::pipeline {

std::size_t decode_failure_advance(Arch arch, std::span<const std::byte> bytes) noexcept;

std::optional<addr_t> rip_relative_target(const Instruction& insn) noexcept;

FuncWindow window_from_addr(addr_t start, u64 size_hint, std::string label);

[[nodiscard]] std::optional<FuncWindow>
resolve_containing_function(const Binary& b, addr_t addr);

}  // namespace spelunk::pipeline
