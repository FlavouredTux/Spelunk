#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <ember/analysis/function.hpp>
#include <ember/binary/binary.hpp>
#include <ember/common/annotations.hpp>
#include <ember/common/error.hpp>
#include <ember/common/types.hpp>
#include <ember/decompile/emitter.hpp>

namespace ember {

struct FuncWindow {
    addr_t      start = 0;
    u64         size  = 0;   // 0 when unknown; formatters fall back to terminator
    std::string label;
};

std::optional<FuncWindow>
resolve_function(const Binary& b, std::string_view symbol);

std::optional<FuncWindow>
resolve_function_at(const Binary& b, addr_t addr);

Result<std::string>
format_disasm(const Binary& b, const FuncWindow& w);

Result<std::string>
format_disasm_range(const Binary& b, addr_t start, addr_t end);

Result<std::string>
format_cfg(const Binary& b, const FuncWindow& w);

Result<std::string>
format_struct(const Binary& b, const FuncWindow& w,
              bool pseudo, const Annotations* ann,
              EmitOptions options = {});

struct CallEdge { addr_t caller = 0; addr_t callee = 0; };
std::vector<CallEdge> compute_call_graph(const Binary& b);
std::vector<addr_t>   compute_callees(const Binary& b, addr_t fn);
std::vector<addr_t>   compute_callers(const Binary& b, addr_t fn);

}  // namespace ember
