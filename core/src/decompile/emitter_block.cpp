// Basic-block emission and terminators.

#include <algorithm>
#include <cstddef>
#include <format>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <ember/analysis/arity.hpp>
#include <ember/analysis/eh_frame.hpp>
#include <ember/analysis/function.hpp>
#include <ember/analysis/import_sigs.hpp>
#include <ember/binary/arch.hpp>
#include <ember/binary/symbol.hpp>
#include <ember/common/annotations.hpp>
#include <ember/common/bytes.hpp>
#include <ember/common/types.hpp>
#include <ember/disasm/register.hpp>
#include <ember/ir/abi.hpp>
#include <ember/ir/ir.hpp>
#include <ember/ir/ssa.hpp>

#include "emitter_internal.hpp"
#include "emitter_tables.hpp"

namespace ember::emit {

namespace {

// A block is an exception-handler landing pad when its first (non-ABI) call
// is to a C++/Itanium unwinder helper. We don't have LSDA parsed yet, so the
// next best signal is pattern-matching these names - they make the reader
// aware that control arrived here by throw, not by normal flow.
[[nodiscard]] std::optional<std::string_view>
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

}  // namespace

void Emitter::emit_call_binding(std::string& out, std::string_view ind,
                                std::pair<std::size_t, std::size_t> pos,
                                const std::string& call_expr,
                                bool result_is_void) const {
    if (suppressed_call_positions.contains(pos)) return;
    if (fold_call_positions.contains(pos)) {
        auto k = fold_call_ssa_key.find(pos);
        if (k != fold_call_ssa_key.end()) {
            if (result_is_void) fold_void_call_stmt[k->second] = call_expr;
            else                fold_return_expr[k->second]    = call_expr;
        }
        return;
    }
    if (inline_call_positions.contains(pos)) {
        auto k = inline_call_ssa_key.find(pos);
        if (k != inline_call_ssa_key.end() && !result_is_void) {
            inline_call_expr[k->second] = call_expr;
        }
        return;
    }
    // Source addr for the LineMap hit. fn is guaranteed non-null while
    // emit is in flight; pos came from the active block walk.
    const auto src = (fn && pos.first < fn->blocks.size() &&
                      pos.second < fn->blocks[pos.first].insts.size())
        ? fn->blocks[pos.first].insts[pos.second].source_addr
        : addr_t{0};

    if (auto bk = bound_call_key.find(pos); bk != bound_call_key.end()) {
        if (options.line_map) {
            options.line_map->hits.push_back({out.size(), src});
        }
        if (result_is_void) {
            out += std::format("{}{};\n", ind, call_expr);
            return;
        }
        const std::string& name = call_return_names.at(bk->second);
        if (merge_bound_calls.contains(pos)) {
            // Merge name already declared at the function head; emit a plain
            // assignment so the dead-decl pass (which only matches
            // `TYPE NAME = ...;`) doesn't strip it.
            out += std::format("{}{} = {};\n", ind, name, call_expr);
        } else {
            std::string type_name = "uint64_t";
            if (auto df = defs.find(bk->second); df != defs.end()) {
                type_name = c_type_name_for(df->second->dst);
            }
            if (fn && pos.first < fn->blocks.size() &&
                pos.second < fn->blocks[pos.first].insts.size()) {
                if (auto known = known_call_return_c_type(
                        fn->blocks[pos.first].insts[pos.second]); known &&
                    *known != "void") {
                    const bool generic_pointer = *known == "void*";
                    const bool concrete_inferred = type_name.ends_with('*') &&
                        type_name != "void*";
                    if (!generic_pointer || !concrete_inferred) type_name = *known;
                }
            }
            out += std::format("{}{} {} = {};\n", ind, type_name, name, call_expr);
        }
        return;
    }
    if (options.line_map) {
        options.line_map->hits.push_back({out.size(), src});
    }
    out += std::format("{}{};\n", ind, call_expr);
}

// Metrowerks writes overflow parameters into the outgoing parameter area
// immediately before `bl`. Pair those stores with the following call so
// the call can render the source argument and the raw stack assignment can
// disappear. The scan is deliberately block-local and signature/layout-
// gated; an arbitrary positive stack store is never hidden on its own.
Emitter::PpcOutgoingStackArgs
Emitter::collect_ppc_outgoing_stack_args(const IrBlock& bb) const {
    PpcOutgoingStackArgs ppc_args;
    if (!is_ppc_abi()) return ppc_args;
    std::map<i64, std::pair<std::size_t, IrValue>> recent_stores;
    for (std::size_t scan = 0; scan < bb.insts.size(); ++scan) {
        const IrInst& candidate = bb.insts[scan];
        if (candidate.op == IrOp::Store && candidate.src_count >= 2) {
            if (auto off = stack_offset(candidate.srcs[0]); off &&
                *off >= ppc_parameter_area_base()) {
                recent_stores[*off] = {scan, candidate.srcs[1]};
            }
            continue;
        }
        if (candidate.op != IrOp::Call && candidate.op != IrOp::CallIndirect) {
            continue;
        }

        const std::vector<InferredArgument> layout = [&]() -> std::vector<InferredArgument> {
            if (candidate.op == IrOp::Call) {
                if (auto import_name = import_name_for_direct_call(candidate.target1)) {
                    return abi_layout_for_import(*import_name);
                }
                return cached_argument_layout(candidate.target1);
            }
            if (const FunctionSig* sig = call_annotation_signature(candidate); sig) {
                return abi_layout_for(*sig);
            }
            return {};
        }();
        auto& values = ppc_args.by_call[scan];
        for (const auto& arg : layout) {
            if (!arg.stack_offset) continue;
            const i64 words = std::max<i64>(1, arg.register_count);
            for (i64 word_index = 0; word_index < words; ++word_index) {
                const i64 off = *arg.stack_offset +
                    word_index * ppc_parameter_word_size();
                auto store = recent_stores.find(off);
                if (store == recent_stores.end()) continue;
                values.emplace(off, store->second.second);
                ppc_args.stores.insert(store->second.first);
            }
        }
        if (values.empty()) ppc_args.by_call.erase(scan);
        recent_stores.clear();
    }
    return ppc_args;
}

// Map a callee's parameter layout onto the pending call.args packs (and,
// on PPC, the paired outgoing stack stores). `rendered` receives an
// aggregate initialiser per multi-register argument, or "" to render the
// value normally.
std::vector<IrValue>
Emitter::args_for_layout(const std::vector<InferredArgument>& layout,
                         std::size_t call_index, const CallArgPack& pack,
                         const PpcOutgoingStackArgs& ppc_args,
                         std::vector<std::string>* rendered) const {
    std::vector<IrValue> result;
    result.reserve(layout.size());
    if (rendered) {
        rendered->clear();
        rendered->reserve(layout.size());
    }
    const auto int_regs = int_arg_regs(abi);
    const auto fp_regs = fp_arg_regs(abi);
    for (const auto& arg : layout) {
        if (arg.stack_offset) {
            auto call = ppc_args.by_call.find(call_index);
            if (call != ppc_args.by_call.end()) {
                auto value = call->second.find(*arg.stack_offset);
                if (value != call->second.end()) {
                    result.push_back(value->second);
                    std::string aggregate;
                    if (arg.aggregate_size != 0 && !arg.aggregate_type.empty()) {
                        aggregate = std::format("({}){{", arg.aggregate_type);
                        bool complete = true;
                        for (u8 wi = 0; wi < arg.register_count; ++wi) {
                            auto piece = call->second.find(*arg.stack_offset +
                                static_cast<i64>(wi) * ppc_parameter_word_size());
                            if (piece == call->second.end()) {
                                complete = false;
                                break;
                            }
                            if (wi > 0) aggregate += ", ";
                            aggregate += expr(piece->second);
                        }
                        aggregate += "}";
                        if (!complete) aggregate.clear();
                    }
                    if (rendered) rendered->push_back(std::move(aggregate));
                }
            }
            continue;
        }
        const Reg canon = canonical_reg(arg.reg);
        const auto append_from = [&](std::span<const Reg> regs,
                                     const std::vector<IrValue>& values) {
            for (std::size_t i = 0; i < regs.size() && i < values.size(); ++i) {
                if (canonical_reg(regs[i]) == canon) {
                    result.push_back(values[i]);
                    std::string aggregate;
                    if (arg.aggregate_size != 0 && !arg.aggregate_type.empty() &&
                        i + arg.register_count <= values.size()) {
                        aggregate = std::format("({}){{", arg.aggregate_type);
                        for (u8 wi = 0; wi < arg.register_count; ++wi) {
                            if (wi > 0) aggregate += ", ";
                            aggregate += expr(values[i + wi]);
                        }
                        aggregate += "}";
                    }
                    if (rendered) rendered->push_back(std::move(aggregate));
                    return true;
                }
            }
            return false;
        };
        if (append_from(int_regs, pack.ints)) continue;
        (void)append_from(fp_regs, pack.fps);
    }
    return result;
}

// Fallback for callees with no known arity: drop args that look stale
// (live-in regs the caller never set, or regs whose most recent def is
// a Clobber from an earlier call).
std::string
Emitter::format_call_args_fallback(const std::vector<IrValue>& args,
                                   std::vector<IrValue>* used) const {
    std::string s;
    bool first = true;
    for (const auto& a : args) {
        if (is_stale_arg_reg(a)) continue;
        if (used) used->push_back(a);
        if (!first) s += ", ";
        s += expr(a);
        first = false;
    }
    return s;
}

std::string
Emitter::fallback_call_arg_types(const std::vector<IrValue>& args) const {
    std::string s;
    bool first = true;
    for (const auto& a : args) {
        if (is_stale_arg_reg(a)) continue;
        if (!first) s += ", ";
        s += c_type_name(call_arg_display_type(a));
        first = false;
    }
    return first ? std::string{"void"} : s;
}

// When we know the callee's arity, show up to that many args. Trim
// trailing args that are provably stale ABI register pass-throughs:
// live-ins the caller never set, or values whose only local def is a
// call-clobber marker. This used to happen only for max-arity guesses,
// but stripped callees can infer a smaller concrete arity from noisy
// register reads; printing `foo(a1, rdx_4, rcx_3)` is worse than
// admitting the trailing values were not real caller-provided args.
std::string
Emitter::format_call_args_with_arity(const std::vector<IrValue>& args, u8 arity,
                                     bool trim_raw_arch_regs,
                                     std::vector<IrValue>* used,
                                     const std::vector<std::string>* rendered) const {
    std::size_t limit = std::min<std::size_t>(arity, args.size());
    while (limit > 0 &&
           (is_stale_arg_reg(args[limit - 1]) ||
            (trim_raw_arch_regs &&
             renders_raw_arch_reg_name(args[limit - 1])))) {
        --limit;
    }
    std::string s;
    bool first = true;
    for (std::size_t i = 0; i < limit; ++i) {
        if (trim_raw_arch_regs &&
            (is_stale_arg_reg(args[i]) ||
             renders_raw_arch_reg_name(args[i]))) {
            continue;
        }
        if (used) used->push_back(args[i]);
        if (!first) s += ", ";
        if (rendered && i < rendered->size() && !(*rendered)[i].empty()) {
            s += (*rendered)[i];
        } else {
            s += expr(args[i]);
        }
        first = false;
    }
    return s;
}

// Per-argument spelling overrides: enum names from a declared
// signature, setcc payloads, decayed char arrays and string literals for
// parameters known to take char*.
void Emitter::refine_rendered_call_args(const std::string& direct_name,
                                        const FunctionSig* annotated_sig,
                                        const std::vector<IrValue>& call_args,
                                        std::vector<std::string>& rendered_call_args) const {
    if (annotated_sig) {
        if (rendered_call_args.size() < call_args.size()) {
            rendered_call_args.resize(call_args.size());
        }
        for (std::size_t arg_i = 0;
             arg_i < annotated_sig->params.size() && arg_i < call_args.size();
             ++arg_i) {
            if (auto named = imported_enum_value(
                    call_args[arg_i], annotated_sig->params[arg_i].type); named) {
                rendered_call_args[arg_i] = *named;
            }
        }
    }
    if (rendered_call_args.size() < call_args.size()) {
        rendered_call_args.resize(call_args.size());
    }
    for (std::size_t arg_i = 0; arg_i < call_args.size(); ++arg_i) {
        if (low_byte_merge_has_raw_carrier(call_args[arg_i])) {
            if (auto payload = match_low_byte_setcc_merge(call_args[arg_i]);
                payload) {
                rendered_call_args[arg_i] = expr(*payload);
            }
        }
        if (auto off = stack_offset(call_args[arg_i]); off &&
            charp_local_slots.contains(*off)) {
            // A char array decays at a call boundary; `&array` has
            // pointer-to-array type and is needlessly incompatible.
            // This is a C rule, not a PPC ABI special case.
            rendered_call_args[arg_i] = stack_name(*off);
        }
        bool expects_string = import_arg_string_kind(
            direct_name, static_cast<u8>(arg_i + 1)) ==
            ImportStringKind::Narrow;
        expects_string = expects_string || variadic_scanf_arg_is_charp(
            direct_name, call_args, arg_i);
        if (!expects_string && annotated_sig &&
            arg_i < annotated_sig->params.size()) {
            const std::string normalized = normalize_c_type_alias(
                annotated_sig->params[arg_i].type);
            expects_string = normalized.find("char*") != std::string::npos;
        }
        if (expects_string) {
            if (auto off = stack_offset(call_args[arg_i]); off) {
                charp_local_slots.insert(*off);
                rendered_call_args[arg_i] = stack_name(*off);
            }
            if (auto address = try_resolve_imm_addr(call_args[arg_i]); address) {
                if (auto literal = try_string_at(
                        normalized_address(*address), 1); literal) {
                    rendered_call_args[arg_i] = escape_string(*literal);
                }
            }
        }
    }
}

// Arity sources: imports → user sig at PLT / baked-in libc table;
// printf/scanf family → parse format string to count args;
// defined functions → infer_sysv_arity. No arity known → fallback
// drops stale-looking args.
Emitter::DirectCallArity
Emitter::direct_call_arity(const IrInst& inst,
                           const std::optional<std::string>& import_name,
                           const std::string& direct_name,
                           const std::vector<IrValue>& call_args,
                           const FunctionSig* annotated_sig) const {
    const bool ppc_abi = is_ppc_abi();
    std::optional<u8> arity;
    bool objc_sized = false;
    if (import_name) {
        arity = objc_call_arity(*import_name, call_args);
        objc_sized = arity.has_value();
        if (!arity) arity = import_arity(inst.target1, *import_name);
        if (!arity) {
            if (auto fi = variadic_format_index(*import_name); fi) {
                arity = variadic_arity(call_args, *fi);
            }
        }
    } else {
        arity = objc_call_arity(direct_name, call_args);
        objc_sized = arity.has_value();
        if (!arity) arity = import_arity(inst.target1, direct_name);
        if (!arity && is_generic_sub_name(direct_name)) {
            arity = printf_like_arity_from_literal_args(call_args);
        }
        if (!arity) {
            arity = ppc_abi
                ? static_cast<u8>(std::min<std::size_t>(
                      call_args.size(), std::numeric_limits<u8>::max()))
                : cached_arity(inst.target1);
        }
    }
    // A fixed prototype gives only the named part of a variadic
    // call.  Let a literal printf/scanf format raise that arity, and
    // retain the raw ABI argument pack so the unnamed arguments are
    // not discarded by the fixed-parameter layout.
    if (auto fi = variadic_format_index(direct_name); fi) {
        if (auto formatted = variadic_arity(call_args, *fi); formatted) {
            arity = arity ? std::max(*arity, formatted) : formatted;
        }
    } else if (annotated_sig && annotated_sig->variadic) {
        const u8 observed = static_cast<u8>(std::min<std::size_t>(
            call_args.size(), std::numeric_limits<u8>::max()));
        arity = arity ? std::max(*arity, observed) : observed;
    }
    return {arity, objc_sized};
}

// Bounded library calls prove a minimum byte extent for the stack slot
// they write; frame_slot_declarations turns that into an array.
void Emitter::note_buffer_extents(std::string_view callee,
                                  const std::vector<IrValue>& used_args) const {
    if (used_args.empty()) return;
    auto base = stack_offset(used_args[0]);
    std::optional<u64> required;
    const auto positive_size = [&](std::size_t index) -> std::optional<u64> {
        if (index >= used_args.size()) return std::nullopt;
        auto value = resolve_imm(used_args[index]);
        if (!value || *value <= 0) return std::nullopt;
        return static_cast<u64>(*value);
    };
    if (callee == "memset" || callee == "memcpy" ||
        callee == "memmove" || callee == "strncpy" ||
        callee == "read" || callee == "recv") {
        required = positive_size(2);
    } else if (callee == "fgets") {
        required = positive_size(1);
    } else if (callee == "fread") {
        auto size = positive_size(1);
        auto count = positive_size(2);
        if (size && count && *size <= (1u << 20) / *count) {
            required = *size * *count;
        }
    }
    if (base && required && *required <= (1u << 20)) {
        auto& extent = stack_required_extents[*base];
        extent = std::max(extent, static_cast<u32>(*required));
    }
}

// Header layouts let a raw aggregate clear become the source
// expression the programmer wrote. Keep this exact: the first
// argument must be a known global and the byte count must equal
// that imported type's complete size.
std::optional<std::string>
Emitter::memset_aggregate_args(std::string_view callee,
                               const std::vector<IrValue>& used_args) const {
    if (!annotations || callee != "memset" || used_args.size() < 3) return std::nullopt;
    const Symbol* global = nullptr;
    if (auto address = try_resolve_imm_addr(used_args[0]); address)
        global = binary ? binary->defined_object_at(normalized_address(*address)) : nullptr;
    // Wii code commonly passes a work pointer loaded from an
    // SDA slot. Follow the slot's initialized pointer so the
    // aggregate object, not the pointer variable, gets typed.
    if (!global && binary) {
        if (const Symbol* slot = global_object_for_load(used_args[0]); slot) {
            auto raw = binary->bytes_at(slot->addr);
            if (raw.size() >= 4) {
                const addr_t pointee = binary->endian() == Endian::Big
                    ? read_be_at<u32>(raw.data()) : read_le_at<u32>(raw.data());
                global = binary->defined_object_at(pointee);
            }
        }
    }
    if (!global) return std::nullopt;
    const addr_t at = global->addr;
    const auto byte_count = resolve_imm(used_args[2]);
    const std::string* type = annotations->global_type_for(at);
    if (!type && byte_count && *byte_count > 0)
        type = annotations->unique_type_for_size(static_cast<std::size_t>(*byte_count));
    if (!type) return std::nullopt;
    const std::string base = normalize_c_type_alias(*type);
    const auto size = annotations->type_size_for(base);
    if (!size || byte_count != static_cast<i64>(*size)) return std::nullopt;
    const std::string* imported_name = annotations->global_name_for_type(base);
    const std::string& name = imported_name ? *imported_name : global->name;
    std::string value = expr(used_args[1]);
    if (imported_name) global_decls.try_emplace(name, base);
    else note_global_decl(*global, base);
    return std::format("&{}, {}, sizeof({})", name, value, base);
}

// Trailing comment for a PPC call whose target has no name or signature:
// the argument types the call site implies, and whether it looks
// printf-shaped.
std::string
Emitter::ppc_unresolved_signature_comment(const IrInst& inst,
                                          const std::vector<IrValue>& used_args) const {
    std::string types;
    for (std::size_t arg_i = 0; arg_i < used_args.size(); ++arg_i) {
        if (arg_i != 0)
            types += ", ";
        types += c_type_name(call_arg_display_type(used_args[arg_i]));
    }
    if (types.empty())
        types = "void";
    bool format_like = false;
    for (const auto& value : used_args) {
        if (auto literal = resolve_string_value(value);
            literal && literal->find('%') != std::string::npos) {
            format_like = true;
            break;
        }
    }
    bool known_entry = false;
    if (binary) {
        if (const Symbol* symbol = binary->defined_object_at(inst.target1);
            symbol && symbol->kind == SymbolKind::Function &&
            symbol->addr == inst.target1) known_entry = true;
    }
    return std::format(
        " /* {} target {:#x}; inferred PPC signature ({}){} */",
        known_entry ? "unnamed" : "unresolved", inst.target1,
        types, format_like ? "; format-like" : "");
}

Emitter::RenderedCall
Emitter::render_direct_call(const IrInst& inst, std::size_t call_index,
                            const CallArgPack& pack,
                            const PpcOutgoingStackArgs& ppc_args) const {
    auto import_name = import_name_for_direct_call(inst.target1);
    std::vector<IrValue> call_args = pack.ints;
    std::vector<std::string> rendered_call_args;
    const std::string direct_name = import_name
        ? *import_name : function_display_name(inst.target1);
    const FunctionSig* annotated_sig = call_annotation_signature(inst);
    const bool known_variadic =
        (annotated_sig && annotated_sig->variadic) ||
        variadic_format_index(direct_name).has_value();
    const bool ppc_abi = is_ppc_abi();
    if (ppc_abi && !known_variadic) {
        const auto layout = import_name
            ? abi_layout_for_import(*import_name)
            : cached_argument_layout(inst.target1);
        if (!layout.empty() || !import_name) {
            call_args = args_for_layout(layout, call_index, pack, ppc_args, &rendered_call_args);
        }
    }
    refine_rendered_call_args(direct_name, annotated_sig, call_args,
                              rendered_call_args);
    const auto [arity, objc_sized] =
        direct_call_arity(inst, import_name, direct_name, call_args, annotated_sig);
    std::vector<IrValue> used_args;
    const bool trim_unproven_registers = !objc_sized && !annotated_sig;
    std::string args = arity
        ? format_call_args_with_arity(call_args, *arity,
                                      trim_unproven_registers,
                                      &used_args, &rendered_call_args)
        : format_call_args_fallback(call_args, &used_args);
    const std::string& callee = direct_name;
    note_buffer_extents(callee, used_args);
    if (auto aggregate = memset_aggregate_args(callee, used_args)) {
        args = *aggregate;
    }
    std::string call_expr = render_objc_runtime_call(callee, call_args)
                                .value_or(std::format("{}({})", callee, args));
    if (ppc_abi && !annotated_sig && !call_has_inferred_signature(inst) &&
        is_unresolved_function_name(callee)) {
        call_expr += ppc_unresolved_signature_comment(inst, used_args);
    }
    return {std::move(call_expr), std::move(used_args)};
}

Emitter::RenderedCall
Emitter::render_indirect_call(const IrInst& inst, std::size_t call_index,
                              const CallArgPack& pack,
                              const PpcOutgoingStackArgs& ppc_args) const {
    std::string call_expr;
    std::vector<IrValue> used_args;
    if (auto name = import_name_for_indirect_call(inst.srcs[0]); name) {
        std::vector<IrValue> indirect_args = pack.ints;
        std::vector<std::string> rendered_indirect_args;
        if (is_ppc_abi()) {
            const auto layout = abi_layout_for_import(*name);
            if (!layout.empty()) {
                indirect_args = args_for_layout(layout, call_index, pack, ppc_args,
                                                &rendered_indirect_args);
            }
        }
        // No PLT address here, so user-sig lookup can't key off one.
        auto arity = objc_call_arity(*name, indirect_args);
        const bool objc_sized = arity.has_value();
        if (!arity) arity = libc_arity_by_name(*name);
        if (!arity) {
            if (auto fi = variadic_format_index(*name); fi) {
                arity = variadic_arity(indirect_args, *fi);
            }
        }
        const std::string args = arity
            ? format_call_args_with_arity(indirect_args, *arity, !objc_sized,
                                          &used_args, &rendered_indirect_args)
            : format_call_args_fallback(indirect_args, &used_args);
        call_expr = render_objc_runtime_call(*name, indirect_args)
            .value_or(std::format("{}({})", *name, args));
    } else if (options.call_resolutions && inst.source_addr != 0) {
        // Vtable back-trace hit: the classifier decoded the
        // preceding `mov reg, [rip+vtable]` and resolved the
        // slot. Render as a named call so `IClient::vfn_3(this)`
        // replaces `(*(u64*)(this + 0x18))(this)`.
        if (auto res_it = options.call_resolutions->find(inst.source_addr);
            res_it != options.call_resolutions->end()) {
            const addr_t target = res_it->second;
            const std::string fname = function_display_name(target);
            std::optional<u8> arity;
            bool objc_sized = false;
            const auto direct_import = import_name_for_direct_call(target);
            std::vector<IrValue> resolved_args = pack.ints;
            std::vector<std::string> rendered_resolved_args;
            if (is_ppc_abi()) {
                const auto layout = direct_import
                    ? abi_layout_for_import(*direct_import)
                    : cached_argument_layout(target);
                if (!layout.empty() || !direct_import) {
                    resolved_args = args_for_layout(layout, call_index, pack, ppc_args,
                                                    &rendered_resolved_args);
                }
            }
            if (direct_import) {
                arity = objc_call_arity(*direct_import, resolved_args);
                objc_sized = arity.has_value();
                if (!arity) arity = import_arity(target, *direct_import);
                if (!arity) {
                    if (auto fi = variadic_format_index(*direct_import); fi) {
                        arity = variadic_arity(resolved_args, *fi);
                    }
                }
            } else if (annotations) {
                if (const FunctionSig* sig = annotations->signature_for(target); sig) {
                    arity = static_cast<u8>(sig->params.size());
                }
            }
            if (!arity && !direct_import) {
                if (is_generic_sub_name(fname)) {
                    arity = printf_like_arity_from_literal_args(resolved_args);
                }
                if (!arity) {
                    arity = is_ppc_abi()
                        ? static_cast<u8>(std::min<std::size_t>(
                              resolved_args.size(),
                              std::numeric_limits<u8>::max()))
                        : cached_arity(target);
                }
            }
            const std::string args = arity
                ? format_call_args_with_arity(resolved_args, *arity, !objc_sized,
                                              &used_args,
                                              &rendered_resolved_args)
                : format_call_args_fallback(resolved_args, &used_args);
            call_expr = std::format("{}({}){}",
                                    fname, args,
                                    observed_targets_comment(inst.source_addr));
        }
    }
    if (call_expr.empty()) {
        const std::string args = format_call_args_fallback(pack.ints,
                                                           &used_args);
        // Virtual-method-dispatch shape recognition: when the
        // call target traces back as `Load(Add(Load(<recv>), K))`
        // - i.e., load vptr from receiver, add slot offset,
        // load method pointer - render as `<recv>->vfn_<K/8>(args)`.
        // This is what every C++ `obj->method()` compiles to,
        // and IPA isn't required to recognise the shape; type
        // info would only refine the slot to a real class
        // method name. Fixed-base `Load(Add(<rip-rel-vtable>, K))`
        // is already covered by the call_resolutions path above
        // (--resolve-calls); this handles the per-instance case.
        if (auto vt = try_render_vfn_dispatch(inst.srcs[0]); vt) {
            call_expr = std::format("{}({})", *vt, args);
        } else if (auto slot = constant_fnptr_slot_for_call_target(inst.srcs[0]); slot) {
            const std::string slot_expr = format_numeric_imm(
                IrValue::make_imm(static_cast<i64>(*slot), IrType::I64));
            call_expr = std::format(
                "(*(uint64_t (**)({})){})({}) /* unresolved indirect: fnptr slot @ {} */",
                fallback_call_arg_types(pack.ints),
                slot_expr,
                args,
                slot_expr);
        } else {
            // Fall back to the textual `(*expr)(args)` form. When
            // expr already starts with `*`, paren-wrap to avoid
            // a double-deref read.
            const std::string tgt =
                expr(inst.srcs[0], 0, std::to_underlying(Prec::Postfix));
            if (const Symbol* s = global_object_for_load(inst.srcs[0]);
                s && tgt == s->name) {
                note_global_decl(*s, std::format("uint64_t (*{})()", s->name));
            }
            if (!tgt.empty() && tgt.front() == '*') {
                call_expr = std::format("(*{})({})", expr(inst.srcs[0]), args);
            } else {
                const std::string target_type = c_type_name_for(inst.srcs[0]);
                if (!target_type.ends_with('*') &&
                    target_type.find("(*") == std::string::npos) {
                    call_expr = std::format(
                        "((uint64_t (*)({}))({}))({})",
                        fallback_call_arg_types(pack.ints), tgt, args);
                } else {
                    call_expr = std::format("{}({})", tgt, args);
                }
            }
        }
    }
    return {std::move(call_expr), std::move(used_args)};
}

// Assignments the structurer hoisted onto this block's outgoing edge.
void Emitter::emit_merge_edge_assignments(addr_t block_start, std::string_view ind,
                                          std::string& out) const {
    auto assignments = merge_edge_assignments.find(block_start);
    if (assignments == merge_edge_assignments.end()) return;
    for (const auto& [name, value] : assignments->second) {
        std::string rendered;
        if (auto payload = low_byte_return_payload(value); payload) {
            rendered = expr(*payload);
        }
        if (auto key = ssa_key(value); key) {
            auto alias = merge_value_names.find(*key);
            const IrInst* definition = def_of(value);
            if (rendered.empty() && alias != merge_value_names.end() &&
                alias->second == name &&
                definition && definition->op != IrOp::Phi) {
                rendered = expand(*definition, 0);
            }
        }
        if (rendered.empty()) rendered = expr(value);
        if (auto local = merge_locals.find(name); local != merge_locals.end()) {
            const std::string type = c_type_name_for(local->second.type_value);
            if (type.ends_with('*') && rendered.starts_with('&')) {
                rendered = std::format("({}){}", type, rendered);
            }
        }
        out += std::format("{}{} = {};\n", ind, name, rendered);
    }
}

void Emitter::emit_block(addr_t block_addr, int depth, std::string& out) const {
    auto it = fn->block_at.find(block_addr);
    if (it == fn->block_at.end()) return;
    const auto& bb = fn->blocks[it->second];

    const std::string ind(static_cast<std::size_t>(depth) * 2u, ' ');
    // C label for any block referenced by a structurer-emitted goto. Sit
    // one indent shallower than the block body when possible - that's the
    // conventional layout for `bb_<addr>:` and avoids the label appearing
    // to belong to the surrounding statement.
    if (goto_targets.contains(bb.start)) {
        const std::size_t label_indent = depth > 0
            ? (static_cast<std::size_t>(depth) - 1) * 2u
            : 0u;
        out += std::format("{}bb_{:x}:\n",
                           std::string(label_indent, ' '), bb.start);
    }
    if (options.show_bb_labels) {
        out += std::format("{}// bb_{:x}\n", ind, bb.start);
    }
    // Real LSDA-driven landing-pad annotation when we have the map; fall
    // back to the __cxa_*-pattern hint when LSDA isn't parsed. The two are
    // complementary: LSDA tells us which CALL-range instructions protected
    // this block (emitted on the protected range's start address), while
    // the pattern check tells us which block IS the catch body.
    bool annotated = false;
    if (options.landing_pads) {
        if (auto lp = landing_pad_for(*options.landing_pads, bb.start); lp) {
            if (lp->lp_addr == bb.start) {
                out += std::format("{}// [eh] landing pad (action {})\n",
                                   ind, lp->action_index);
                annotated = true;
            } else if (lp->lp_addr != 0) {
                out += std::format("{}// [eh] may throw → landing pad at bb_{:x}\n",
                                   ind, lp->lp_addr);
                annotated = true;
            }
        }
    }
    if (!annotated) {
        if (auto h = eh_pattern_hint(bb, binary); h) {
            out += std::format("{}// [eh] {}\n", ind, *h);
        }
    }

    const std::size_t block_index = it->second;
    CallArgPack pack;
    const PpcOutgoingStackArgs ppc_args = collect_ppc_outgoing_stack_args(bb);
    auto flush_args_as_intrinsics = [&]() {
        if (pack.have_pending) {
            out += std::format("{}// stray call.args: {} values\n",
                               ind, pack.ints.size() + pack.fps.size());
            pack.clear();
        }
    };

    for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
        const auto& inst = bb.insts[ii];
        if (ppc_args.stores.contains(ii)) continue;
        // Skip ABI-noise prologue/epilogue insts detected during analysis.
        // A hidden PPC save/restore helper still terminates the preceding
        // call.args pack; clear it so it cannot leak out as a stray marker or
        // become the arguments of the next source-level call.
        if (hidden.contains({block_index, ii})) {
            if (inst.op == IrOp::Call || inst.op == IrOp::CallIndirect) {
                pack.clear();
            }
            continue;
        }
        // Skip the for-loop update statement; it'll render in the for-header.
        if (for_update_positions.contains({block_index, ii})) continue;
        switch (inst.op) {
            case IrOp::Branch:
            case IrOp::CondBranch:
            case IrOp::BranchIndirect:
            case IrOp::Return:
            case IrOp::Unreachable:
            case IrOp::Nop:
            case IrOp::Phi:
            case IrOp::Clobber:   // ABI-marker; models call-clobber of caller-saved regs
                continue;
            default:
                break;
        }

        if (inst.op == IrOp::Intrinsic && inst.name.starts_with("call.args.")) {
            if (inst.name == "call.args.1") pack.ints.clear();
            for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                pack.ints.push_back(inst.srcs[i]);
            }
            pack.have_pending = true;
            continue;
        }
        if (inst.op == IrOp::Intrinsic && inst.name.starts_with("call.fp_args.")) {
            if (inst.name == "call.fp_args.1") pack.fps.clear();
            for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                pack.fps.push_back(inst.srcs[i]);
            }
            pack.have_pending = true;
            continue;
        }

        if (inst.op == IrOp::Call || inst.op == IrOp::CallIndirect) {
            if (inst.op == IrOp::CallIndirect) {
                if (inst.src_count < 1) {
                    pack.clear();
                    out += std::format("{}(*?)();\n", ind);
                    continue;
                }
                emit_materializations_for_value(inst.srcs[0], 0, out, ind);
            }
            const RenderedCall call = inst.op == IrOp::Call
                ? render_direct_call(inst, ii, pack, ppc_args)
                : render_indirect_call(inst, ii, pack, ppc_args);
            for (const auto& a : call.used_args) {
                emit_materializations_for_value(a, 0, out, ind);
            }
            pack.clear();
            emit_call_binding(out, ind, std::pair{block_index, ii}, call.expr,
                              call_inst_returns_void(inst));
            continue;
        }

        const std::string stmt = format_stmt(inst);
        if (!stmt.empty()) {
            emit_materializations_for_inst(inst, out, ind);
            flush_args_as_intrinsics();
            if (options.line_map) {
                // Record where the statement starts so `byte_offset`
                // resolves to the correct line via newline-counting.
                options.line_map->hits.push_back({out.size(), inst.source_addr});
            }
            out += std::format("{}{}\n", ind, stmt);
            mark_binding_emitted(inst.dst);
        }
    }

    flush_args_as_intrinsics();
    emit_merge_edge_assignments(bb.start, ind, out);
}

void Emitter::emit_block_terminator(const IrBlock& bb, int depth,
                                    std::string& out) const {
    const std::string ind(static_cast<std::size_t>(depth) * 2u, ' ');

    // Find the block's explicit IR terminator (last non-Nop instruction
    // with a control-flow op). Terminators are normally the very last
    // entry but Phi/Nop padding can sit after them in some passes.
    const IrInst* term = nullptr;
    for (auto it = bb.insts.rbegin(); it != bb.insts.rend(); ++it) {
        const auto op = it->op;
        if (op == IrOp::Branch         || op == IrOp::CondBranch ||
            op == IrOp::BranchIndirect || op == IrOp::Return     ||
            op == IrOp::Unreachable) { term = &*it; break; }
    }

    switch (bb.kind) {
        case BlockKind::Return: {
            if (term && term->op == IrOp::Return && term->src_count > 0) {
                // Pick which return source to render. lift_ret packs rax
                // first and xmm0 second, but on an FP-returning early-exit
                // path rax is uninitialized live-in while xmm0 carries the
                // actual value. Prefer the source whose SSA value has a
                // local definition over one that doesn't.
                std::size_t pick = 0;
                if (term->src_count >= 2) {
                    auto has_value_def = [&](const IrValue& v) {
                        auto k = ssa_key(v);
                        if (!k) return false;
                        auto it = defs.find(*k);
                        return it != defs.end() && it->second->op != IrOp::Clobber;
                    };
                    if (!has_value_def(term->srcs[0]) &&
                        has_value_def(term->srcs[1])) {
                        pick = 1;
                    }
                }
                IrValue rv = term->srcs[pick];
                if (is_msvc_cookie_return_clobber(rv)) {
                    if (auto preserved = return_value_before_msvc_cookie(rv); preserved) {
                        rv = *preserved;
                    } else {
                        out += std::format("{}return;\n", ind);
                        break;
                    }
                }
                if (auto payload = low_byte_return_payload(rv); payload) {
                    rv = *payload;
                }

                if (auto k = ssa_key(rv); k) {
                    auto s = fold_void_call_stmt.find(*k);
                    if (s != fold_void_call_stmt.end()) {
                        out += std::format("{}{};\n", ind, s->second);
                        out += std::format("{}return;\n", ind);
                        break;
                    }
                }
                if (current_return_is_void) {
                    if (auto k = ssa_key(rv); k) {
                        auto f = fold_return_expr.find(*k);
                        if (f != fold_return_expr.end()) {
                            out += std::format("{}{};\n", ind, f->second);
                        }
                    }
                    out += std::format("{}return;\n", ind);
                    break;
                }
                if (is_void_call_result(rv)) {
                    out += std::format("{}return;\n", ind);
                    break;
                }
                if (renders_stack_chk_guard_value(rv)) {
                    out += std::format("{}return;\n", ind);
                    break;
                }
                // Reuse the return-fold table populated during region
                // analysis - when a call directly feeds the return,
                // `fold_return_expr` carries the rendered call expr.
                if (auto k = ssa_key(rv); k) {
                    auto f = fold_return_expr.find(*k);
                    if (f != fold_return_expr.end()) {
                        out += std::format("{}return {};\n", ind, f->second);
                        break;
                    }
                }
                const std::string rendered_rv = expr(rv);
                if (rendered_rv.find("__stack_chk_guard") != std::string::npos) {
                    out += std::format("{}return;\n", ind);
                    break;
                }
                out += std::format("{}return {};\n", ind, rendered_rv);
            } else {
                out += std::format("{}return;\n", ind);
            }
            break;
        }
        case BlockKind::Conditional: {
            if (term && term->op == IrOp::CondBranch && term->src_count > 0) {
                const std::string cond = expr(term->srcs[0]);
                emit_materializations_for_rendered_value(term->srcs[0], cond, out, ind);
                out += std::format("{}if ({})\n", ind, cond);
            } else {
                out += std::format("{}if (?)\n", ind);
            }
            break;
        }
        case BlockKind::Switch: {
            if (bb.switch_index != Reg::None) {
                out += std::format("{}switch ({})\n", ind,
                                   reg_name(bb.switch_index));
            } else {
                out += std::format("{}switch (?)\n", ind);
            }
            break;
        }
        case BlockKind::IndirectJmp: {
            if (term && term->op == IrOp::BranchIndirect && term->src_count > 0) {
                out += std::format("{}goto *{};\n", ind, expr(term->srcs[0]));
            } else {
                out += std::format("{}goto *(?);\n", ind);
            }
            break;
        }
        // Unconditional / Fallthrough / TailCall: no extra summary line.
        // The successor edge tells the consumer where execution goes,
        // and tail-calls already render a `tgt(args)` from emit_block
        // via the lifter's call+return rewrite.
        case BlockKind::Unconditional:
        case BlockKind::Fallthrough:
        case BlockKind::TailCall:
            break;
    }
}

}  // namespace ember::emit
