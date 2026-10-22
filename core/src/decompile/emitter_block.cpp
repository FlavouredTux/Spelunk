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

#include <spelunk/analysis/arity.hpp>
#include <spelunk/analysis/eh_frame.hpp>
#include <spelunk/analysis/function.hpp>
#include <spelunk/analysis/import_sigs.hpp>
#include <spelunk/binary/arch.hpp>
#include <spelunk/binary/symbol.hpp>
#include <spelunk/common/annotations.hpp>
#include <spelunk/common/bytes.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/ir/abi.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/ir/ssa.hpp>

#include "emitter_internal.hpp"
#include "emitter_tables.hpp"

namespace spelunk::emit {

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
        const std::string_view n = strip_import_name_decorations(s->name);
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
    // Source addr for provenance. fn is guaranteed non-null while emit is in
    // flight; pos came from the active block walk.
    const auto src = (fn && pos.first < fn->blocks.size() &&
                      pos.second < fn->blocks[pos.first].insts.size())
        ? fn->blocks[pos.first].insts[pos.second].source_addr
        : addr_t{0};
    if (suppressed_call_positions.contains(pos)) return;
    if (fold_call_positions.contains(pos)) {
        auto k = fold_call_ssa_key.find(pos);
        if (k != fold_call_ssa_key.end()) {
            if (result_is_void) fold_void_call_stmt[k->second] = call_expr;
            else                fold_return_expr[k->second]    = call_expr;
            fold_call_source[k->second] = src;
        }
        return;
    }
    if (inline_call_positions.contains(pos)) {
        auto k = inline_call_ssa_key.find(pos);
        if (k != inline_call_ssa_key.end() && !result_is_void) {
            inline_call_expr[k->second] = call_expr;
            inline_call_source[k->second] = src;
        }
        return;
    }
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
            if (const IrInst* definition = ssa_uses.definition(bk->second)) {
                type_name = c_type_name_for(definition->dst);
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

void Emitter::record_folded_call_hit(const SsaKey& key,
                                     std::size_t output_offset) const {
    if (!options.line_map) return;
    auto source = fold_call_source.find(key);
    if (source == fold_call_source.end() || source->second == 0) return;
    options.line_map->hits.push_back({output_offset, source->second});
}

void Emitter::record_inline_call_hit(const IrValue& value,
                                     std::size_t output_offset) const {
    if (!options.line_map) return;
    const auto key = single_call_return_key_in_expr(value);
    if (!key) return;
    auto source = inline_call_source.find(*key);
    if (source == inline_call_source.end() || source->second == 0) return;
    options.line_map->hits.push_back({output_offset, source->second});
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
    const auto int_regs = int_arg_regs(is_x86_32_abi(abi) ? Abi::Win32Fastcall : abi);
    const auto fp_regs = fp_arg_regs(abi);
    if (is_x86_32_abi(abi)) pack.consumed_stack = pack.consumed_stack.value_or(0);
    for (const auto& arg : layout) {
        if (arg.stack_offset) {
            if (is_x86_32_abi(abi) || abi == Abi::SysVAmd64 || abi == Abi::Win64) {
                const i64 first = is_x86_32_abi(abi) ? 4 : (abi == Abi::SysVAmd64 ? 8 : 40);
                if (is_x86_32_abi(abi)) {
                    const i64 bytes = std::max<i64>(type_bits(arg.type) / 8, 4);
                    pack.consumed_stack = std::max(*pack.consumed_stack,
                                                   *arg.stack_offset - first + bytes);
                }
                const auto at = std::ranges::find(pack.stack_offsets,
                                                  *arg.stack_offset - first);
                IrValue value;
                if (at != pack.stack_offsets.end()) {
                    value = pack.stack[static_cast<std::size_t>(
                        at - pack.stack_offsets.begin())];
                } else if (abi == Abi::Win64 && *arg.stack_offset >= 40 &&
                           static_cast<std::size_t>((*arg.stack_offset - 8) / 8) < pack.ints.size()) {
                    value = pack.ints[static_cast<std::size_t>((*arg.stack_offset - 8) / 8)];
                }
                value.type = arg.type;
                result.push_back(value);
                if (rendered) rendered->push_back(value.kind == IrValueKind::None
                    ? std::format("unresolved_stack_arg_{:x}", *arg.stack_offset) : "");
                continue;
            }
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
                    IrValue value = values[i];
                    if (is_float_type(arg.type)) value.type = arg.type;
                    result.push_back(value);
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

// Register ABIs commonly materialize a source-level narrow integer as
// zext/sext(trunc(param)) before a call. At a C call boundary the prototype or
// default promotions perform that transport conversion. Recover the declared
// source name only when the cast chain never narrows the source type.
std::optional<std::string_view>
Emitter::source_arg_name_for_call_transport(const IrValue& value) const {
    const auto slot = trace_to_self_arg_slot(value);
    if (!slot || *slot >= self_arg_names.size() ||
        self_arg_names[*slot].empty()) {
        return std::nullopt;
    }

    IrValue current = value;
    std::optional<IrType> narrowest;
    bool cast_chain = false;
    for (int depth = 0; depth < 8; ++depth) {
        const IrInst* definition = def_of(current);
        if (!definition || definition->src_count < 1) break;
        if (definition->op == IrOp::Assign) {
            current = definition->srcs[0];
            continue;
        }
        if (definition->op != IrOp::Trunc &&
            definition->op != IrOp::ZExt &&
            definition->op != IrOp::SExt) {
            break;
        }
        cast_chain = true;
        const IrType candidate =
            type_bits(definition->dst.type) <
                    type_bits(definition->srcs[0].type)
                ? definition->dst.type
                : definition->srcs[0].type;
        if (!narrowest || type_bits(candidate) < type_bits(*narrowest)) {
            narrowest = candidate;
        }
        current = definition->srcs[0];
    }
    if (!cast_chain || !narrowest ||
        !declared_arg_signedness_for_width(*slot, *narrowest).has_value()) {
        return std::nullopt;
    }
    return self_arg_names[*slot];
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
        const auto name = source_arg_name_for_call_transport(a);
        s += c_transport_cast(a, name ? std::string(*name) : expr(a));
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
        const std::string rendered = expr(a);
        s += options.c_source
            ? (rendered.starts_with('&') ? "void*" : rendered.starts_with('"') ? "const char*" : c_type_name_for(a))
            : std::string(c_type_name(call_arg_display_type(a)));
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
        } else if (auto name = source_arg_name_for_call_transport(args[i])) {
            s += c_transport_cast(args[i], std::string(*name));
        } else {
            s += c_transport_cast(args[i], expr(args[i]));
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
    const auto char_address = [&](i64 offset) {
        // char* also describes an out-parameter pointing to one scalar byte.
        // Only arrays decay: scalar out-parameters still need their address,
        // even when the compiler eliminated initialization before the call.
        const auto required = stack_required_extents.find(offset);
        const auto storage = stack_byte_storage_ranges.find(offset);
        if (fn && (required == stack_required_extents.end() || required->second <= 1) &&
            (storage == stack_byte_storage_ranges.end() || storage->second <= 1)) {
            for (const auto& block : fn->blocks) for (const auto& inst : block.insts) {
                if (inst.op == IrOp::Store && inst.src_count >= 2 &&
                    inst.srcs[1].type == IrType::I8 && stack_offset(inst.srcs[0]) == offset)
                    return "&" + stack_name(offset);
            }
            const auto slot = frame_layout.slots.find(offset);
            if (slot != frame_layout.slots.end() && slot->second.direct_observed && slot->second.size_bytes == 1) {
                const auto next = std::next(slot);
                if (options.c_source || (next != frame_layout.slots.end() && next->first - offset == 1))
                    return "&" + stack_name(offset);
            }
        }
        return stack_name(offset);
    };
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
    std::vector<std::string> printf_types;
    const auto format_index = variadic_format_index(direct_name);
    // The v* variants take one va_list, not the format's individual arguments.
    if (options.c_source && !direct_name.starts_with('v') &&
        direct_name.find("printf") != std::string::npos &&
        format_index && *format_index < call_args.size()) {
        if (auto format = resolve_string_value(call_args[*format_index])) {
            printf_types = printf_argument_types(*format);
        }
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
            rendered_call_args[arg_i] = char_address(*off);
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
                rendered_call_args[arg_i] = char_address(*off);
            }
            if (auto address = try_resolve_imm_addr(call_args[arg_i]); address) {
                if (auto literal = string_literals.try_c_string_at(
                        normalized_address(*address), 1); literal) {
                    rendered_call_args[arg_i] = escape_string(*literal);
                }
            }
        }
        if (options.c_source && annotated_sig && arg_i < annotated_sig->params.size()) {
            const std::string type = normalize_c_type_alias(annotated_sig->params[arg_i].type);
            if (type.ends_with('*')) {
                const std::string value = rendered_call_args[arg_i].empty() ? expr(call_args[arg_i]) : rendered_call_args[arg_i];
                rendered_call_args[arg_i] = std::format("({})({})", type, value);
            }
        }
        if (options.c_source && format_index && arg_i > *format_index &&
            arg_i - *format_index - 1 < printf_types.size()) {
            const std::string& type = printf_types[arg_i - *format_index - 1];
            if (!type.empty()) {
                const std::string value = rendered_call_args[arg_i].empty() ? expr(call_args[arg_i]) : rendered_call_args[arg_i];
                const bool floating = type == "double" || type == "long double";
                rendered_call_args[arg_i] = std::format("({}){}({})", type,
                    floating ? "" : "(uintptr_t)", value);
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
    if (abi == Abi::SysVAmd64 && is_objc_msgsend_name(direct_name)) {
        call_args.insert(call_args.end(), pack.stack.begin(), pack.stack.end());
    }
    const FunctionSig* annotated_sig = call_annotation_signature(inst);
    const bool known_variadic =
        (annotated_sig && annotated_sig->variadic) ||
        variadic_format_index(direct_name).has_value();
    const bool ppc_abi = is_ppc_abi();
    std::optional<u8> layout_arity;
    if (ppc_abi && !known_variadic) {
        const auto layout = import_name
            ? abi_layout_for_import(*import_name)
            : cached_argument_layout(inst.target1);
        if (!layout.empty() || !import_name) {
            call_args = args_for_layout(layout, call_index, pack, ppc_args, &rendered_call_args);
        }
    }
    if ((is_x86_32_abi(abi) || abi == Abi::SysVAmd64 || abi == Abi::Win64) && !known_variadic &&
        !is_objc_msgsend_name(direct_name)) {
        const auto layout = annotated_sig ? abi_layout_for(*annotated_sig)
            : import_name ? abi_layout_for_import(*import_name)
            : cached_argument_layout(inst.target1);
        const bool needs_layout = std::ranges::any_of(layout, [](const auto& arg) {
            return is_float_type(arg.type) || arg.stack_offset.has_value();
        });
        if (needs_layout || is_x86_32_abi(abi)) {
            call_args = args_for_layout(layout, call_index, pack, ppc_args, &rendered_call_args);
            layout_arity = static_cast<u8>(layout.size());
        }
    }
    refine_rendered_call_args(direct_name, annotated_sig, call_args,
                              rendered_call_args);
    auto [arity, objc_sized] =
        direct_call_arity(inst, import_name, direct_name, call_args, annotated_sig);
    if (layout_arity) arity = layout_arity;
    std::vector<IrValue> used_args;
    // A prototype's arity is authoritative: a value in its argument
    // register is the argument, even when it renders as a raw register.
    const bool trim_unproven_registers = !objc_sized && !annotated_sig &&
        !(import_name && has_fixed_import_prototype(*import_name));
    std::string args = arity
        ? format_call_args_with_arity(call_args, *arity,
                                      trim_unproven_registers,
                                      &used_args, &rendered_call_args)
        : format_call_args_fallback(call_args, &used_args);
    const std::string& callee = direct_name;
    if (options.c_source) note_c_call(inst, callee, used_args);
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
        if (abi == Abi::SysVAmd64 && is_objc_msgsend_name(*name)) {
            indirect_args.insert(indirect_args.end(), pack.stack.begin(), pack.stack.end());
        }
        std::vector<std::string> rendered_indirect_args;
        if (is_ppc_abi() || is_x86_32_abi(abi)) {
            const auto layout = abi_layout_for_import(*name);
            if (!layout.empty()) {
                indirect_args = args_for_layout(layout, call_index, pack, ppc_args,
                                                &rendered_indirect_args);
            }
        }
        // No PLT address here, so user-sig lookup can't key off one.
        auto arity = objc_call_arity(*name, indirect_args);
        const bool objc_sized = arity.has_value();
        // An IAT call (`call [rip+slot]`) has no PLT stub to key a signature
        // off, so ask the prototype table by name.
        const bool prototype_sized = !arity && has_fixed_import_prototype(*name);
        if (prototype_sized) arity = import_arity(0, *name);
        if (!arity) arity = libc_arity_by_name(*name);
        if (!arity) {
            if (auto fi = variadic_format_index(*name); fi) {
                arity = variadic_arity(indirect_args, *fi);
            }
        }
        const std::string args = arity
            ? format_call_args_with_arity(indirect_args, *arity,
                                          !objc_sized && !prototype_sized,
                                          &used_args, &rendered_indirect_args)
            : format_call_args_fallback(indirect_args, &used_args);
        if (options.c_source) note_c_call(inst, *name, used_args);
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
            if (is_ppc_abi() || is_x86_32_abi(abi)) {
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
            if (options.c_source) note_c_call(inst, fname, used_args);
            call_expr = std::format("{}({}){}",
                                    fname, args,
                                    observed_targets_comment(inst.source_addr));
        }
    }
    if (call_expr.empty()) {
        if ((is_x86_32_abi(abi) || abi == Abi::SysVAmd64 || abi == Abi::Win64) && inst.src_count) {
            const auto target = call_signature_target(inst);
            const auto* signature = call_annotation_signature(inst);
            if (target || signature) {
                const auto layout = signature ? abi_layout_for(*signature) : cached_argument_layout(*target);
                if (signature || std::ranges::any_of(layout, [](const auto& arg) {
                        return is_float_type(arg.type) || arg.stack_offset.has_value();
                    })) {
                    std::vector<std::string> rendered;
                    const auto values = args_for_layout(layout, call_index, pack, ppc_args, &rendered);
                    const auto arguments = format_call_args_with_arity(values,
                        static_cast<u8>(layout.size()), false, &used_args, &rendered);
                    std::string types;
                    for (std::size_t i = 0; i < layout.size(); ++i) {
                        if (i) types += ", ";
                        types += signature && i < signature->params.size()
                            ? normalize_c_type_alias(signature->params[i].type)
                            : std::string(c_type_name(layout[i].type));
                    }
                    if (types.empty()) types = "void";
                    const std::string ret = known_call_return_c_type(inst).value_or(
                        std::string(default_call_return_c_type()));
                    const std::string indirect = expr(inst.srcs[0]);
                    if (const auto* object = global_object_for_load(inst.srcs[0])) {
                        note_global_decl(*object, std::format("{} (*{})({})", ret, object->name, types));
                    }
                    return {std::format("(({} (*)({}))({}))({})", ret, types, indirect, arguments), std::move(used_args)};
                }
            }
        }
        if (auto virtual_call = render_ppc_virtual_call(inst, pack)) return *virtual_call;
        if (auto virtual_call = render_x64_virtual_call(inst, pack)) return *virtual_call;
        // An unknown x86-32 callee takes what was pushed for it since the
        // previous call, after any register (thiscall/fastcall) lanes.
        std::vector<IrValue> fallback_args = pack.ints;
        if (is_x86_32_abi(abi)) {
            fallback_args.insert(fallback_args.end(), pack.stack.begin(),
                                 pack.stack.begin() + static_cast<std::ptrdiff_t>(pack.fresh_stack));
        }
        const std::string args = format_call_args_fallback(fallback_args,
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
        if (auto vt = (is_ppc_abi() || options.c_source) ? std::nullopt : try_render_vfn_dispatch(inst.srcs[0]); vt) {
            call_expr = std::format("{}({})", *vt, args);
        } else if (auto slot = constant_fnptr_slot_for_call_target(inst.srcs[0]); slot) {
            const std::string slot_expr = format_numeric_imm(
                IrValue::make_imm(static_cast<i64>(*slot), IrType::I64));
            call_expr = std::format(
                "(*({} (**)({})){})({}) /* unresolved indirect: fnptr slot @ {} */",
                default_call_return_c_type(),
                fallback_call_arg_types(fallback_args),
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
                note_global_decl(*s, std::format("{} (*{})()", default_call_return_c_type(), s->name));
            }
            if (!tgt.empty() && tgt.front() == '*') {
                call_expr = std::format("(*{})({})", expr(inst.srcs[0]), args);
            } else {
                const std::string target_type = c_type_name_for(inst.srcs[0]);
                if (!target_type.ends_with('*') &&
                    target_type.find("(*") == std::string::npos) {
                    call_expr = std::format(
                        "(({} (*)({}))({}))({})", default_call_return_c_type(),
                        fallback_call_arg_types(fallback_args), tgt, args);
                } else {
                    call_expr = std::format("{}({})", tgt, args);
                }
            }
        }
    }
    return {std::move(call_expr), std::move(used_args)};
}

// Assignments the structurer hoisted onto this block's outgoing edge.
std::vector<Emitter::EdgeCopyBlock>
Emitter::take_trailing_edge_copies(std::string& out, const IrValue& condition) const {
    std::vector<EdgeCopyBlock> taken;
    if (options.line_map) return taken;
    while (!trailing_edge_copies.empty()) {
        EdgeCopyBlock& last = trailing_edge_copies.back();
        if (!same_value_key(last.condition, condition) || !out.ends_with(last.text)) break;
        out.resize(out.size() - last.text.size());
        taken.push_back(std::move(last));
        trailing_edge_copies.pop_back();
    }
    std::ranges::reverse(taken);
    return taken;
}

void Emitter::emit_merge_edge_assignments(addr_t block_start, std::string_view ind,
                                          std::string& out) const {
    trailing_edge_copies.clear();
    if (explicit_phi_copies || scalar_join_copies) {
        if (auto block = fn->block_at.find(block_start); block != fn->block_at.end())
            emit_phi_copies(fn->blocks[block->second], ind, out);
        if (explicit_phi_copies) return;
    }
    const auto render_value = [&](const std::string& name, const IrValue& value) {
        if (const auto* scoped = scoped_ssa_name(value)) return *scoped;
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
        return rendered;
    };
    if (auto assignments = merge_edge_assignments.find(block_start);
        assignments != merge_edge_assignments.end()) {
        for (const auto& [name, value] : assignments->second) {
            const std::string rendered = render_value(name, value);
            emit_materializations_for_rendered_value(value, rendered, out, ind);
            out += std::format("{}{} = {};\n", ind, name, rendered);
        }
    }
    const auto guarded = merge_guarded_edge_assignments.find(block_start);
    const auto block = fn->block_at.find(block_start);
    if (guarded == merge_guarded_edge_assignments.end() || block == fn->block_at.end()) return;
    const IrInst& terminator = fn->blocks[block->second].insts.back();
    std::vector<addr_t> targets;
    for (const auto& assignment : guarded->second) {
        if (std::ranges::find(targets, assignment.target) == targets.end()) {
            targets.push_back(assignment.target);
        }
    }
    // Bindings the condition or values need are emitted before the `if`,
    // where the branch would otherwise first materialize them.
    const std::string inner = std::string(ind) + "  ";
    for (const addr_t target : targets) {
        const std::string condition =
            render_condition(terminator.srcs[0], target != terminator.target1);
        emit_materializations_for_rendered_value(terminator.srcs[0], condition, out, ind);
        std::string copies;
        for (const auto& assignment : guarded->second) {
            if (assignment.target != target) continue;
            const std::string rendered = render_value(assignment.name, assignment.value);
            emit_materializations_for_rendered_value(assignment.value, rendered, out, ind);
            copies += std::format("{}{} = {};\n", inner, assignment.name, rendered);
        }
        std::string text = std::format("{}if ({}) {{\n{}{}}}\n", ind, condition, copies, ind);
        out += text;
        trailing_edge_copies.push_back({terminator.srcs[0], target == terminator.target1,
                                        std::move(text), std::move(copies)});
    }
}

void Emitter::emit_block(addr_t block_addr, int depth, std::string& out) const {
    auto it = fn->block_at.find(block_addr);
    if (it == fn->block_at.end()) return;
    const auto& bb = fn->blocks[it->second];

    const std::string ind(static_cast<std::size_t>(depth) * 2u, ' ');
    if (shared_throw_blocks.contains(bb.start) && !emitted_throw_blocks.insert(bb.start).second) {
        out += std::format("{}goto bb_{:x};\n", ind, bb.start);
        return;
    }
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

    struct StackStore {
        i64 width;
        IrValue value;
        std::size_t epoch;  // calls seen before this store
    };
    std::map<i64, StackStore> recent_stack_stores;
    std::size_t call_epoch = 0;
    // A call consumes the argument words it read. Words above them stay:
    // MSVC pushes an outer call's arguments around an inner call
    // (`push a; push b; push 0; call GetModuleHandleA; push eax; call f`).
    const auto retire_call_stores = [&](const CallArgPack& consumed) {
        ++call_epoch;
        if (!is_x86_32_abi(abi) || !consumed.stack_base) {
            recent_stack_stores.clear();
            return;
        }
        i64 extent = 0;
        if (consumed.consumed_stack) {
            extent = *consumed.consumed_stack;
        } else if (consumed.fresh_stack) {
            const std::size_t last = consumed.fresh_stack - 1;
            extent = consumed.stack_offsets[last] + 4;
        }
        const i64 limit = *consumed.stack_base + extent;
        std::erase_if(recent_stack_stores, [&](const auto& stored) {
            return stored.first < limit;
        });
    };
    for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
        const auto& inst = bb.insts[ii];
        // Register saves are not arguments, however close to the call.
        if ((is_x86_32_abi(abi) || abi == Abi::SysVAmd64 || abi == Abi::Win64) &&
            inst.op == IrOp::Store && inst.src_count >= 2 &&
            !hidden.contains({block_index, ii})) {
            if (auto offset = entry_stack_offset(inst.srcs[0])) {
                const i64 width = static_cast<i64>(type_bits(inst.srcs[1].type) / 8);
                std::erase_if(recent_stack_stores, [&](const auto& stored) {
                    return stored.first < *offset + width && *offset < stored.first + stored.second.width;
                });
                // A narrow argument may store only its low bytes into the
                // slot (`mov word ptr [esp], ax`); it still owns the word.
                if (width == 1 || width == 2 || width == 4 || width == 8)
                    recent_stack_stores[*offset] = {width, inst.srcs[1], call_epoch};
            }
        }
        if (inst.op == IrOp::Intrinsic && inst.name == "call.stack_pointer") {
            pack.stack.clear();
            pack.stack_offsets.clear();
            pack.stack_base.reset();
            pack.fresh_stack = 0;
            pack.consumed_stack.reset();
            if (inst.src_count && (is_x86_32_abi(abi) || abi == Abi::SysVAmd64 || abi == Abi::Win64)) {
                if (auto offset = entry_stack_offset(inst.srcs[0])) {
                    if (abi == Abi::Win64) *offset += 32;
                    pack.stack_base = *offset;
                    // Walk the stores by width: an 8-byte argument on x86-32
                    // covers two parameter words.
                    const i64 word = is_x86_32_abi(abi) ? 4 : 8;
                    i64 cursor = 0;
                    bool fresh = true;
                    for (std::size_t i = 0; i < kMaxAbiArgs - int_arg_regs(abi).size(); ++i) {
                        auto found = recent_stack_stores.find(*offset + cursor);
                        if (found == recent_stack_stores.end()) break;
                        pack.stack.push_back(found->second.value);
                        pack.stack_offsets.push_back(cursor);
                        fresh = fresh && found->second.epoch == call_epoch;
                        if (fresh) ++pack.fresh_stack;
                        cursor += std::max(found->second.width, word);
                    }
                }
            }
            continue;
        }
        if (const auto* name = scoped_ssa_name(inst.dst);
            name && inst.op != IrOp::Phi && inst.op != IrOp::Call &&
            inst.op != IrOp::CallIndirect && inst.op != IrOp::Clobber) {
            const std::string statement = format_merge_assignment(inst, *name);
            if (!statement.empty()) {
                if (options.line_map)
                    options.line_map->hits.push_back({out.size(), inst.source_addr});
                out += std::format("{}{}\n", ind, statement);
                mark_binding_emitted(inst.dst);
                continue;
            }
        }
        if (ppc_args.stores.contains(ii)) continue;
        // Skip ABI-noise prologue/epilogue insts detected during analysis.
        // A hidden PPC save/restore helper still terminates the preceding
        // call.args pack; clear it so it cannot leak out as a stray marker or
        // become the arguments of the next source-level call.
        if (hidden.contains({block_index, ii})) {
            if (inst.op == IrOp::Call || inst.op == IrOp::CallIndirect) {
                pack.clear();
                recent_stack_stores.clear();
                ++call_epoch;
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
            retire_call_stores(pack);
            pack.clear();
            emit_call_binding(out, ind, std::pair{block_index, ii}, call.expr,
                              call_inst_returns_void(inst));
            continue;
        }

        const std::string stmt = format_stmt(inst);
        if (!stmt.empty()) {
            emit_materializations_for_inst(inst, out, ind);
            if (options.c_source) {
                const auto assignment = stmt.find(" = ");
                emit_materializations_for_raw_temps(
                    assignment == std::string::npos ? std::string_view(stmt)
                        : std::string_view(stmt).substr(assignment + 3), out, ind);
            }
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
    const auto append_terminator = [&](std::string statement) {
        if (options.line_map && term && term->source_addr != 0) {
            options.line_map->hits.push_back({out.size(), term->source_addr});
        }
        out += ind + std::move(statement) + "\n";
    };

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
                        const IrInst* definition = ssa_uses.definition(*k);
                        return definition && definition->op != IrOp::Clobber;
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
                        append_terminator("return;");
                        break;
                    }
                }
                if (auto payload = low_byte_return_payload(rv); payload) {
                    rv = *payload;
                }

                if (auto k = ssa_key(rv); k) {
                    auto s = fold_void_call_stmt.find(*k);
                    if (s != fold_void_call_stmt.end()) {
                        record_folded_call_hit(*k, out.size());
                        out += std::format("{}{};\n", ind, s->second);
                        append_terminator("return;");
                        break;
                    }
                }
                if (current_return_is_void) {
                    if (auto k = ssa_key(rv); k) {
                        auto f = fold_return_expr.find(*k);
                        if (f != fold_return_expr.end()) {
                            record_folded_call_hit(*k, out.size());
                            out += std::format("{}{};\n", ind, f->second);
                        }
                    }
                    append_terminator("return;");
                    break;
                }
                if (is_void_call_result(rv)) {
                    append_terminator("return;");
                    break;
                }
                if (renders_stack_chk_guard_value(rv)) {
                    append_terminator("return;");
                    break;
                }
                // Reuse the return-fold table populated during region
                // analysis - when a call directly feeds the return,
                // `fold_return_expr` carries the rendered call expr.
                if (auto k = ssa_key(rv); k) {
                    auto f = fold_return_expr.find(*k);
                    if (f != fold_return_expr.end()) {
                        record_folded_call_hit(*k, out.size());
                        append_terminator(std::format("return {};", f->second));
                        break;
                    }
                }
                const std::string rendered_rv = expr(rv);
                if (rendered_rv.find("__stack_chk_guard") != std::string::npos) {
                    append_terminator("return;");
                    break;
                }
                append_terminator(std::format("return {};", rendered_rv));
            } else {
                append_terminator("return;");
            }
            break;
        }
        case BlockKind::Conditional: {
            if (term && term->op == IrOp::CondBranch && term->src_count > 0) {
                const std::string cond = expr(term->srcs[0]);
                emit_materializations_for_rendered_value(term->srcs[0], cond, out, ind);
                append_terminator(std::format("if ({})", cond));
            } else {
                append_terminator("if (?)");
            }
            break;
        }
        case BlockKind::Switch: {
            if (bb.switch_index != Reg::None) {
                append_terminator(std::format(
                    "switch ({})", display_reg_name(bb.switch_index)));
            } else {
                append_terminator("switch (?)");
            }
            break;
        }
        case BlockKind::IndirectJmp: {
            if (term && term->op == IrOp::BranchIndirect && term->src_count > 0) {
                append_terminator(std::format(
                    "goto *{};", expr(term->srcs[0])));
            } else {
                append_terminator("goto *(?);");
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

}  // namespace spelunk::emit
