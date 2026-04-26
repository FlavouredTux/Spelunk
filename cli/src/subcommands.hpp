#pragma once

#include <string_view>

#include <ember/common/annotations.hpp>
#include <ember/decompile/emitter.hpp>

namespace ember { class Binary; }

namespace ember::cli {

int run_disasm(const Binary& b, std::string_view symbol);
int run_cfg(const Binary& b, std::string_view symbol);
int run_cfg_pseudo(const Binary& b, std::string_view symbol,
                   const Annotations* ann, EmitOptions opts);
int run_ir(const Binary& b, std::string_view symbol,
           bool run_ssa, bool run_opt);
int run_struct(const Binary& b, std::string_view symbol, bool pseudo,
               const Annotations* annotations, EmitOptions opts);

}  // namespace ember::cli
