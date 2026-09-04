// Argument name/type inference from call sites and memory uses.
#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <format>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <ember/analysis/import_sigs.hpp>
#include <ember/binary/symbol.hpp>
#include <ember/common/annotations.hpp>
#include <ember/common/types.hpp>
#include <ember/disasm/register.hpp>
#include <ember/ir/abi.hpp>
#include <ember/ir/ir.hpp>
#include <ember/ir/ssa.hpp>
#include <ember/ir/types.hpp>

#include "emitter_internal.hpp"
#include "emitter_tables.hpp"

namespace ember::emit {

const Symbol*
Emitter::global_object_for_load(const IrValue& v) const {
    if (!binary) return nullptr;
    const IrInst* d = def_stripped(v);
    if (!d || d->op != IrOp::Load || d->src_count < 1) return nullptr;
    auto imm = try_resolve_imm_addr(d->srcs[0]);
    if (!imm) return nullptr;
    const Symbol* s = binary->defined_object_at(static_cast<addr_t>(*imm));
    if (!s || s->kind != SymbolKind::Object || s->name.empty()) return nullptr;
    return s;
}

std::optional<addr_t>
Emitter::constant_fnptr_slot_for_call_target(const IrValue& v) const {
    const IrInst* d = def_stripped(v);
    if (!d || d->op != IrOp::Load || d->src_count < 1) return std::nullopt;
    auto imm = try_resolve_imm_addr(d->srcs[0]);
    if (!imm) return std::nullopt;
    const addr_t slot = static_cast<addr_t>(*imm);
    if (binary) {
        if (binary->import_at_got(slot)) return std::nullopt;
        if (const Symbol* s = binary->defined_object_at(slot);
            s && s->kind == SymbolKind::Object && !s->name.empty()) {
            return std::nullopt;
        }
    }
    return slot;
}

IrType Emitter::call_arg_display_type(const IrValue& v) const {
    if (auto k = ssa_key(v); k) {
        if (const IrInst* d = ssa_uses.definition(*k)) {
            if (d->op == IrOp::Trunc) return d->dst.type;
            if ((d->op == IrOp::ZExt || d->op == IrOp::SExt) &&
                d->src_count >= 1) {
                if (const IrInst* inner = def_stripped(d->srcs[0]);
                    inner && inner->op == IrOp::Trunc) {
                    return inner->dst.type;
                }
            }
        }
    }
    return v.type;
}

void Emitter::record_funcptr_arg_types(u8 slot, const std::vector<IrValue>& args,
                                       u8 arity) {
    if (slot >= self_funcptr_arg_types.size()) return;
    const std::size_t limit = std::min<std::size_t>(arity, args.size());
    if (limit != arity) return;
    std::vector<IrType> types;
    types.reserve(limit);
    for (std::size_t i = 0; i < limit; ++i) {
        types.push_back(call_arg_display_type(args[i]));
    }
    auto& existing = self_funcptr_arg_types[slot];
    if (existing.empty()) {
        existing = std::move(types);
    } else if (existing != types) {
        existing.clear();
    }
}

void Emitter::record_self_arg_type(u8 slot, IrType type) {
    if (slot >= self_arg_type_overrides.size()) return;
    auto& existing = self_arg_type_overrides[slot];
    if (!existing) {
        existing = type;
    } else if (*existing != type) {
        existing.reset();
    }
}

void Emitter::record_funcptr_return_type(u8 slot, IrType type) {
    if (slot >= self_funcptr_return_type.size()) return;
    auto& existing = self_funcptr_return_type[slot];
    if (!existing) {
        existing = type;
    } else if (*existing != type) {
        existing.reset();
    }
}

void Emitter::infer_charp_args() {
    if (!binary) return;
    for (const auto& bb : fn->blocks) {
        std::vector<IrValue> args;
        args.reserve(kMaxAbiIntArgs);
        for (const auto& inst : bb.insts) {
            if (inst.op == IrOp::Intrinsic && inst.name == "call.args.1") {
                args.clear();
                for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i)
                    args.push_back(inst.srcs[i]);
                continue;
            }
            if (inst.op == IrOp::Intrinsic &&
                (inst.name == "call.args.2" || inst.name == "call.args.3")) {
                for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i)
                    args.push_back(inst.srcs[i]);
                continue;
            }
            if (inst.op == IrOp::Call || inst.op == IrOp::CallIndirect) {
                // Callee-side char*-slot bitset: for an import, consult the
                // shared metadata but admit only narrow strings; for an
                // internal function, consult the pre-computed IPA map.
                std::array<bool, kMaxAbiIntArgs> callee_charp{};
                bool have_info = false;
                if (inst.op == IrOp::Call) {
                    if (const Symbol* s = binary->import_at_plt(inst.target1); s) {
                        const std::string callee = clean_import_name(s->name);
                        for (u8 i = 0; i < callee_charp.size(); ++i) {
                            callee_charp[i] = import_arg_string_kind(
                                callee, static_cast<u8>(i + 1)) ==
                                ImportStringKind::Narrow;
                            if (callee_charp[i]) have_info = true;
                        }
                    } else if (annotations) {
                        if (const FunctionSig* sig = annotations->signature_for(inst.target1);
                            sig) {
                            for (std::size_t i = 0;
                                 i < sig->params.size() && i < callee_charp.size(); ++i) {
                                std::string type = normalize_c_type_alias(sig->params[i].type);
                                type.erase(std::remove_if(type.begin(), type.end(),
                                    [](unsigned char c) { return std::isspace(c) != 0; }),
                                    type.end());
                                callee_charp[i] = type.find("char*") != std::string::npos;
                                have_info |= callee_charp[i];
                            }
                        }
                    }
                    if (!have_info && options.signatures) {
                        auto it = options.signatures->find(inst.target1);
                        if (it != options.signatures->end()) {
                            callee_charp = it->second.charp;
                            for (bool v : callee_charp) if (v) { have_info = true; break; }
                        }
                    }
                } else if (inst.src_count >= 1) {
                    if (auto callee = import_name_for_indirect_call(inst.srcs[0])) {
                        for (u8 i = 0; i < callee_charp.size(); ++i) {
                            callee_charp[i] = import_arg_string_kind(
                                *callee, static_cast<u8>(i + 1)) ==
                                ImportStringKind::Narrow;
                            if (callee_charp[i]) have_info = true;
                        }
                    }
                }
                if (!have_info) { args.clear(); continue; }
                for (std::size_t i = 0; i < args.size() && i < callee_charp.size(); ++i) {
                    if (!callee_charp[i]) continue;
                    if (auto slot = trace_to_self_arg_slot(args[i]);
                        slot && *slot < charp_arg.size()) {
                        charp_arg[*slot] = true;
                    }
                    // Stack-local char* propagation: a `&local_X`
                    // value passed into a char*-taking parameter
                    // tells us that local_X is the underlying buffer.
                    // Override its frame-layout type so the local
                    // declaration emits as `char local_X[N]` instead
                    // of `u64 local_X[N/8]`. Catches fgets/strcpy/
                    // strcmp buffers that ember would otherwise leave
                    // as opaque u64 arrays.
                    if (auto off = stack_offset(args[i]); off) {
                        charp_local_slots.insert(*off);
                    }
                }
                args.clear();
                continue;
            }
            // Any non-arg, non-Clobber inst between the packing and the
            // Call invalidates the accumulator.
            if (inst.op != IrOp::Clobber &&
                !is_call_arg_barrier(inst)) {
                // Nothing: but stash in case Call follows after pure
                // side-effect-free compute (common with lea).
            }
        }
    }
}

void Emitter::infer_typed_stack_slots_from_calls() {
    if (!annotations || !is_ppc_abi()) return;
    const auto int_regs = int_arg_regs(abi);
    const auto fp_regs = fp_arg_regs(abi);
    for (const auto& bb : fn->blocks) {
        std::vector<IrValue> int_values;
        std::vector<IrValue> fp_values;
        for (const IrInst& inst : bb.insts) {
            if (inst.op == IrOp::Intrinsic && inst.name.starts_with("call.args.")) {
                if (inst.name == "call.args.1") int_values.clear();
                for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                    int_values.push_back(inst.srcs[i]);
                }
                continue;
            }
            if (inst.op == IrOp::Intrinsic && inst.name.starts_with("call.fp_args.")) {
                if (inst.name == "call.fp_args.1") fp_values.clear();
                for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                    fp_values.push_back(inst.srcs[i]);
                }
                continue;
            }
            if (inst.op != IrOp::Call && inst.op != IrOp::CallIndirect) continue;
            const FunctionSig* signature = call_annotation_signature(inst);
            if (!signature) {
                int_values.clear();
                fp_values.clear();
                continue;
            }
            const auto layout = abi_layout_for(*signature);
            for (std::size_t i = 0; i < layout.size() && i < signature->params.size(); ++i) {
                std::string type = normalize_c_type_alias(signature->params[i].type);
                if (type.find("[4]") != std::string::npos &&
                    inst.op == IrOp::Call) {
                    const std::string callee = function_display_name(inst.target1);
                    if (callee.find("MTX44") != std::string::npos ||
                        callee.starts_with("C_MTX")) {
                        type = "Mtx44 *";
                    } else if (callee.find("MTX") != std::string::npos ||
                               callee == "QUATMtx") {
                        type = "Mtx34 *";
                    }
                }
                const auto star = type.rfind('*');
                if (star == std::string::npos || type.find("char") != std::string::npos) {
                    continue;
                }
                const Reg wanted = canonical_reg(layout[i].reg);
                const IrValue* value = nullptr;
                const auto find_value = [&](std::span<const Reg> regs,
                                            const std::vector<IrValue>& values) {
                    for (std::size_t j = 0; j < regs.size() && j < values.size(); ++j) {
                        if (canonical_reg(regs[j]) == wanted) return &values[j];
                    }
                    return static_cast<const IrValue*>(nullptr);
                };
                if (wanted != Reg::None) {
                    value = find_value(int_regs, int_values);
                    if (!value) value = find_value(fp_regs, fp_values);
                }
                if (!value) continue;
                auto offset = entry_stack_offset(*value);
                if (!offset) continue;
                auto slot = frame_layout.slots.find(*offset);
                if (slot == frame_layout.slots.end()) continue;
                type.erase(star);
                while (!type.empty() && std::isspace(
                           static_cast<unsigned char>(type.back()))) {
                    type.pop_back();
                }
                // A pointer-to-const parameter proves that the callee
                // does not mutate the object; it does not prove that the
                // caller's stack object was declared const. Stack locals
                // are often written by one call and later consumed through
                // a const pointer by another, so keep the recovered object
                // declaration mutable.
                for (std::string_view qualifier : {"const ", "volatile "}) {
                    while (type.starts_with(qualifier)) {
                        type.erase(0, qualifier.size());
                    }
                }
                if (type.empty() || type == "void") continue;
                slot->second.type_override = std::move(type);
            }
            int_values.clear();
            fp_values.clear();
        }
    }
}

void Emitter::infer_import_pointer_stack_values() {
    if (!fn || abi != Abi::Win64) return;
    for (const auto& block : fn->blocks) {
        std::vector<IrValue> args;
        for (const IrInst& instruction : block.insts) {
            if (instruction.op == IrOp::Intrinsic &&
                instruction.name.starts_with("call.args.")) {
                if (instruction.name == "call.args.1") args.clear();
                for (u8 i = 0;
                     i < instruction.src_count && i < instruction.srcs.size(); ++i) {
                    args.push_back(instruction.srcs[i]);
                }
                continue;
            }
            if (instruction.op != IrOp::Call &&
                instruction.op != IrOp::CallIndirect) continue;
            auto import = call_import_name(instruction);
            if (!import) {
                args.clear();
                continue;
            }
            TypeArena arena;
            auto signature = lookup_import_sig(*import, arena);
            if (!signature) {
                args.clear();
                continue;
            }
            const auto type_name = [&](const auto& self, TypeRef type,
                                       int depth) -> std::string {
                if (depth > 4 || type.is_top() || type.is_bottom()) return {};
                const TypeNode& node = arena.node(type);
                if (node.kind == TypeKind::Int) {
                    const char* prefix = node.i.sign_known && node.i.is_signed
                        ? "int" : "uint";
                    return std::format("{}{}_t", prefix, node.i.bits);
                }
                if (node.kind == TypeKind::Ptr) {
                    if (node.p.pointee.is_top()) return "void*";
                    std::string pointee = self(self, node.p.pointee, depth + 1);
                    if (pointee == "uint8_t") pointee = "char";
                    return pointee.empty() ? std::string{"void*"} : pointee + "*";
                }
                if (node.kind == TypeKind::Float) {
                    return node.f.bits == 32 ? "float" : "double";
                }
                if (node.kind == TypeKind::Struct) return node.s.name;
                return {};
            };
            const std::size_t count = std::min(args.size(), signature->params.size());
            for (std::size_t index = 0; index < count; ++index) {
                const TypeRef parameter = signature->params[index];
                if (arena.kind(parameter) != TypeKind::Ptr) continue;
                const IrInst* load = def_stripped(args[index]);
                if (!load || load->op != IrOp::Load || load->src_count < 1) continue;
                auto offset = stack_offset(load->srcs[0]);
                if (!offset) continue;
                auto slot = frame_layout.slots.find(*offset);
                if (slot == frame_layout.slots.end()) continue;
                std::string rendered = type_name(type_name, parameter, 0);
                if (!rendered.empty()) slot->second.type_override = std::move(rendered);
            }
            args.clear();
        }
    }
}

void Emitter::infer_function_pointer_args() {
    std::size_t fn_count = 0;
    std::vector<IrValue> args;
    args.reserve(kMaxAbiIntArgs);
    for (const auto& bb : fn->blocks) {
        for (const auto& inst : bb.insts) {
            if (inst.op == IrOp::Intrinsic && inst.name == "call.args.1") {
                args.clear();
                for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i)
                    args.push_back(inst.srcs[i]);
                continue;
            }
            if (inst.op == IrOp::Intrinsic &&
                (inst.name == "call.args.2" || inst.name == "call.args.3")) {
                for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i)
                    args.push_back(inst.srcs[i]);
                continue;
            }
            if (inst.op != IrOp::CallIndirect || inst.src_count < 1) continue;
            auto slot = trace_to_self_arg_slot(inst.srcs[0]);
            if (!slot || *slot >= self_arg_names.size()) {
                args.clear();
                continue;
            }
            if (self_arg_names[*slot].empty()) {
                self_arg_names[*slot] = (fn_count == 0)
                    ? std::string{"fn"}
                    : std::format("fn{}", fn_count + 1);
                ++fn_count;
            }
            if (!self_funcptr_arity[*slot]) {
                if (auto arity = known_call_arity_for_arg_names(inst, args); arity) {
                    self_funcptr_arity[*slot] = *arity;
                    record_funcptr_arg_types(*slot, args, *arity);
                }
            } else {
                record_funcptr_arg_types(*slot, args, *self_funcptr_arity[*slot]);
            }
            args.clear();
        }
    }
}

std::optional<u8>
Emitter::known_call_arity_for_arg_names(const IrInst& inst,
                                        const std::vector<IrValue>& args) const {
    std::optional<u8> arity;
    if (inst.op == IrOp::Call) {
        if (auto direct_import = import_name_for_direct_call(inst.target1)) {
            arity = objc_call_arity(*direct_import, args);
            if (!arity) arity = import_arity(inst.target1, *direct_import);
            if (!arity) {
                if (auto fi = variadic_format_index(*direct_import); fi) {
                    arity = variadic_arity(args, *fi);
                }
            }
        } else if (annotations) {
            if (const FunctionSig* sig = annotations->signature_for(inst.target1);
                sig) {
                arity = static_cast<u8>(sig->params.size());
            }
        }
        if (!arity && !import_name_for_direct_call(inst.target1)) {
            arity = cached_arity(inst.target1);
        }
    } else if (inst.op == IrOp::CallIndirect && inst.src_count >= 1 &&
        options.call_resolutions && inst.source_addr != 0) {
        auto res_it = options.call_resolutions->find(inst.source_addr);
        if (res_it != options.call_resolutions->end()) {
            const addr_t target = res_it->second;
            if (auto direct_import = import_name_for_direct_call(target)) {
                arity = objc_call_arity(*direct_import, args);
                if (!arity) arity = import_arity(target, *direct_import);
                if (!arity) {
                    if (auto fi = variadic_format_index(*direct_import); fi) {
                        arity = variadic_arity(args, *fi);
                    }
                }
            } else if (annotations) {
                if (const FunctionSig* sig = annotations->signature_for(target); sig) {
                    arity = static_cast<u8>(sig->params.size());
                }
            }
            if (!arity && !import_name_for_direct_call(target)) {
                arity = cached_arity(target);
            }
        }
    }
    if (arity && *arity == int_arg_regs(abi).size()) return std::nullopt;
    return arity;
}

void Emitter::infer_call_value_arg_names() {
    static constexpr std::array<std::string_view, 3> kAxisNames{
        "x", "y", "z"
    };
    const auto sdk_param_name = [](std::string_view callee,
                                   std::size_t index)
        -> std::optional<std::string_view> {
        static constexpr std::array<std::string_view, 6> viewport{
            "x", "y", "width", "height", "near_z", "far_z"};
        static constexpr std::array<std::string_view, 4> rectangle{
            "left", "top", "width", "height"};
        static constexpr std::array<std::string_view, 8> texture{
            "texture", "image", "width", "height", "format",
            "wrap_s", "wrap_t", "mipmap"};
        static constexpr std::array<std::string_view, 2> copy{
            "source", "destination"};
        if (callee == "GXSetViewport" && index < viewport.size()) {
            return viewport[index];
        }
        if ((callee == "GXSetScissor" || callee == "GXSetTexCopySrc" ||
             callee == "GXSetDispCopySrc") && index < rectangle.size()) {
            return rectangle[index];
        }
        if (callee == "GXInitTexObj" && index < texture.size()) {
            return texture[index];
        }
        if (callee == "PSMTXCopy" && index < copy.size()) {
            return copy[index];
        }
        if ((callee.find("SetMessage") != std::string_view::npos ||
             callee.find("Msg") != std::string_view::npos) && index < 3) {
            static constexpr std::array<std::string_view, 3> message{
                "entry", "message_id", "flags"};
            return message[index];
        }
        return std::nullopt;
    };
    for (const auto& bb : fn->blocks) {
        std::vector<IrValue> args;
        std::vector<IrValue> fp_args;
        args.reserve(kMaxAbiIntArgs);
        fp_args.reserve(kMaxAbiFpArgs);
        for (const auto& inst : bb.insts) {
            if (inst.op == IrOp::Intrinsic && inst.name == "call.args.1") {
                args.clear();
                for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i)
                    args.push_back(inst.srcs[i]);
                continue;
            }
            if (inst.op == IrOp::Intrinsic &&
                (inst.name == "call.args.2" || inst.name == "call.args.3")) {
                for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i)
                    args.push_back(inst.srcs[i]);
                continue;
            }
            if (inst.op == IrOp::Intrinsic && inst.name.starts_with("call.fp_args.")) {
                if (inst.name == "call.fp_args.1") fp_args.clear();
                for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                    fp_args.push_back(inst.srcs[i]);
                }
                continue;
            }
            if (inst.op != IrOp::Call && inst.op != IrOp::CallIndirect) continue;

            auto arity = known_call_arity_for_arg_names(inst, args);
            if (!arity) {
                args.clear();
                fp_args.clear();
                continue;
            }
            std::vector<IrValue> named_values;
            std::vector<std::size_t> parameter_indices;
            const FunctionSig* signature = call_annotation_signature(inst);
            if (signature && is_ppc_abi()) {
                const auto layout = abi_layout_for(*signature);
                const auto int_regs = int_arg_regs(abi);
                const auto fp_regs = fp_arg_regs(abi);
                for (std::size_t parameter = 0; parameter < layout.size(); ++parameter) {
                    const Reg wanted = canonical_reg(layout[parameter].reg);
                    const auto append = [&](std::span<const Reg> regs,
                                            const std::vector<IrValue>& values) {
                        for (std::size_t j = 0; j < regs.size() && j < values.size(); ++j) {
                            if (canonical_reg(regs[j]) != wanted) continue;
                            named_values.push_back(values[j]);
                            parameter_indices.push_back(parameter);
                            return true;
                        }
                        return false;
                    };
                    if (wanted != Reg::None && !append(int_regs, args)) {
                        (void)append(fp_regs, fp_args);
                    }
                }
            } else {
                const std::size_t limit = std::min<std::size_t>(*arity, args.size());
                for (std::size_t i = 0; i < limit; ++i) {
                    named_values.push_back(args[i]);
                    parameter_indices.push_back(i);
                }
            }
            const std::size_t limit = named_values.size();
            for (std::size_t i = 0; i < limit; ++i) {
                const std::size_t parameter = parameter_indices[i];
                auto slot = trace_to_self_arg_slot(named_values[i]);
                if (!slot || *slot >= self_arg_names.size()) continue;
                if (!self_arg_names[*slot].empty()) continue;

                std::optional<std::string> semantic_name;
                if (inst.op == IrOp::Call) {
                    if (annotations) {
                        if (const FunctionSig* sig =
                                annotations->signature_for(inst.target1);
                            sig && parameter < sig->params.size() &&
                            !sig->params[parameter].name.empty()) {
                            semantic_name = sig->params[parameter].name;
                        }
                    }
                    if (!semantic_name) {
                        const std::string callee =
                            function_display_name(inst.target1);
                        if (auto role = sdk_param_name(callee, parameter); role) {
                            semantic_name = std::string{*role};
                        }
                    }
                } else if (i < kAxisNames.size()) {
                    semantic_name = std::string{kAxisNames[i]};
                }
                if (!semantic_name) continue;
                self_arg_names[*slot] = std::move(*semantic_name);
                record_self_arg_type(*slot, call_arg_display_type(named_values[i]));
            }
            args.clear();
            fp_args.clear();
        }
    }
}

void Emitter::bump_arity_from_body_reads() {
    u8 need = self_arity;
    auto check = [&](const IrValue& v) {
        if (auto slot = trace_to_self_arg_slot(v); slot) {
            if (*slot + 1 > need) need = static_cast<u8>(*slot + 1);
            return;
        }
        if (v.kind != IrValueKind::Reg || v.version != 0) return;
        const Reg canon = canonical_reg(v.reg);
        for (u8 i = 0; i < self_arg_layout.size(); ++i) {
            if (canonical_reg(self_arg_layout[i].reg) == canon) {
                if (i + 1 > need) need = static_cast<u8>(i + 1);
                return;
            }
        }
    };
    for (std::size_t bi = 0; bi < fn->blocks.size(); ++bi) {
        const auto& bb = fn->blocks[bi];
        for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
            if (hidden.contains({bi, ii})) continue;
            const auto& inst = bb.insts[ii];
            // call.args.* packs live-in regs as trailing placeholders the
            // callee may never consume; Clobbers are ABI markers; Phis
            // conservatively name every arg reg at join points regardless
            // of whether anything downstream reads it. None of these
            // represents a real body read.
            if (is_call_arg_barrier(inst)) continue;
            if (inst.op == IrOp::Clobber)  continue;
            if (inst.op == IrOp::Phi)      continue;
            for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i)
                check(inst.srcs[i]);
        }
    }
    for (const auto& [_, root] : struct_root_values) check(root);
    self_arity = need;
}

void Emitter::bump_arity_from_call_sites() {
    u8 need = self_arity;
    for (const auto& bb : fn->blocks) {
        std::vector<IrValue> args;
        args.reserve(kMaxAbiIntArgs);
        for (const auto& inst : bb.insts) {
            if (inst.op == IrOp::Intrinsic && inst.name == "call.args.1") {
                args.clear();
                for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i)
                    args.push_back(inst.srcs[i]);
                continue;
            }
            if (inst.op == IrOp::Intrinsic &&
                (inst.name == "call.args.2" || inst.name == "call.args.3")) {
                for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i)
                    args.push_back(inst.srcs[i]);
                continue;
            }

            std::optional<u8> arity;
            if (inst.op == IrOp::Call) {
                if (auto import_name = import_name_for_direct_call(inst.target1)) {
                    arity = objc_call_arity(*import_name, args);
                    if (!arity) arity = import_arity(inst.target1, *import_name);
                } else {
                    arity = cached_arity(inst.target1);
                }
            } else if (inst.op == IrOp::CallIndirect && inst.src_count >= 1) {
                if (auto import_name = import_name_for_indirect_call(inst.srcs[0])) {
                    arity = objc_call_arity(*import_name, args);
                    if (!arity) arity = libc_arity_by_name(*import_name);
                }
            } else {
                continue;
            }
            if (!arity) {
                args.clear();
                continue;
            }

            const std::size_t limit = std::min<std::size_t>(*arity, args.size());
            for (std::size_t i = 0; i < limit; ++i) {
                auto slot = trace_to_self_arg_slot(args[i]);
                if (slot && *slot + 1 > need) need = static_cast<u8>(*slot + 1);
            }
            args.clear();
        }
    }
    self_arity = need;
}

void Emitter::infer_narrow_arg_types_from_uses() {
    const u8 limit = std::min<u8>(self_arity,
        static_cast<u8>(self_arg_layout.size()));
    for (u8 slot = 0; slot < limit; ++slot) {
        if (self_arg_layout[slot].reg == Reg::None ||
            is_ppc_fpr(self_arg_layout[slot].reg)) {
            continue;
        }
        IrValue arg = IrValue::make_reg(self_arg_layout[slot].reg,
                                         self_arg_layout[slot].type);
        arg.version = 0;

        // Refined local inference already found a stronger type such as
        // `char*` / `u32*`; don't overwrite pointer evidence with an
        // integer-width guess from an incidental cast.
        if (c_type_name_for(arg) != abi_word_c_type()) continue;

        std::optional<IrType> narrowed;
        bool saw_use = false;
        bool all_narrow = true;
        for (std::size_t bi = 0; bi < fn->blocks.size(); ++bi) {
            const auto& bb = fn->blocks[bi];
            for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
                if (hidden.contains({bi, ii})) continue;
                const auto& inst = bb.insts[ii];
                if (is_call_arg_barrier(inst) ||
                    inst.op == IrOp::Clobber ||
                    inst.op == IrOp::Phi) {
                    continue;
                }
                for (u8 si = 0; si < inst.src_count && si < inst.srcs.size(); ++si) {
                    if (!same_ssa(inst.srcs[si], arg)) continue;
                    saw_use = true;
                    if (inst.op != IrOp::Trunc || si != 0) {
                        all_narrow = false;
                        break;
                    }
                    if (!narrowed) {
                        narrowed = inst.dst.type;
                    } else if (*narrowed != inst.dst.type) {
                        all_narrow = false;
                        break;
                    }
                }
                if (!all_narrow) break;
            }
            if (!all_narrow) break;
        }
        if (saw_use && all_narrow && narrowed) {
            record_self_arg_type(slot, *narrowed);
        }
    }
}

void Emitter::infer_pointer_arg_types_from_memory_uses() {
    const u8 limit = std::min<u8>(self_arity,
        static_cast<u8>(self_arg_layout.size()));

    // A load through an argument whose result is itself pointer-typed
    // proves one additional pointer level: `loaded` is char* and its
    // address traces to a2, therefore a2 is char**. This also follows
    // the common -O0 spill/reload through init_only_slot_value.
    for (const auto& block : fn->blocks) {
        for (const IrInst& instruction : block.insts) {
            if (instruction.op != IrOp::Load || instruction.src_count < 1) continue;
            auto slot = trace_to_self_arg_slot(instruction.srcs[0]);
            if (!slot) {
                if (auto access = canonical_struct_access(instruction.srcs[0]);
                    access) {
                    slot = trace_to_self_arg_slot(access->first);
                }
            }
            if (!slot) {
                if (auto access = try_base_plus_offset(instruction.srcs[0]);
                    access) {
                    slot = trace_to_self_arg_slot(access->first);
                }
            }
            if (!slot || *slot >= limit) continue;
            std::string loaded = c_type_name_for(instruction.dst);
            auto& current = self_arg_type_names[*slot];
            if (loaded.ends_with('*')) {
                const std::string nested = loaded + "*";
                if (current.empty() || current == "void*") current = nested;
                continue;
            }
            if (current.empty()) current = "void*";
        }
    }

    for (u8 slot = 0; slot < limit; ++slot) {
        const auto& layout = self_arg_layout[slot];
        if (layout.reg == Reg::None || is_ppc_fpr(layout.reg) ||
            is_xmm(layout.reg) || is_aarch64_vector(layout.reg)) continue;

        IrValue arg = IrValue::make_reg(layout.reg, layout.type);
        arg.version = 0;
        auto key = ssa_key(arg);
        if (!key) continue;
        std::set<SsaKey> seen;
        if (!layout.pointer_like &&
            !value_flows_to_memory_address(*key, seen, 0, true)) continue;

        // Preserve stronger local/import evidence such as char* or
        // uint32_t*. self_arg_type_names is reserved for the case where
        // the normal lattice still sees only the ABI word type.
        const std::string local = c_type_name_for(arg);
        if (!local.empty() && local.ends_with('*')) continue;
        if (self_arg_type_names[slot].empty()) {
            self_arg_type_names[slot] = "void*";
        }
    }
}

void Emitter::infer_synthetic_self_arg_types() {
    if (!is_ppc_abi()) return;
    for (const auto& [key, type_name] : struct_type_names) {
        auto root = struct_root_values.find(key);
        if (root == struct_root_values.end()) continue;
        auto slot = trace_to_self_arg_slot(root->second);
        if (!slot || *slot >= self_arg_type_names.size()) continue;
        // Two or more member offsets outweigh a `T**` guessed from one
        // pointer-typed member load.
        auto& current = self_arg_type_names[*slot];
        const std::string inferred = type_name + "*";
        if (current.empty() || current == "void*" || current.ends_with("**")) {
            current = inferred;
        }
    }
}

void Emitter::infer_ppc_helper_preserved_arg_types() {
    const auto consider = [&](const IrValue& v) {
        if (v.kind != IrValueKind::Reg || v.version == 0) return;
        auto original = preserved_call_arg_for_clobber(v.reg, v.version);
        if (!original) return;
        auto slot = trace_to_self_arg_slot(*original);
        if (!slot || *slot >= self_arg_type_names.size()) return;
        const std::string refined = c_type_name_for(v);
        if (refined == c_type_name(v.type) || !refined.ends_with('*')) return;
        auto& dst = self_arg_type_names[*slot];
        if (dst.empty()) dst = refined;
        else if (dst != refined) dst.clear();
    };
    for (const auto& bb : fn->blocks) {
        for (const auto& inst : bb.insts) {
            consider(inst.dst);
            for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                consider(inst.srcs[i]);
            }
        }
    }
}

void Emitter::infer_ppc_role_arg_names() {
    if (!is_ppc_abi()) return;
    std::set<std::string> claimed;
    for (const std::string& name : self_arg_names) {
        if (!name.empty()) claimed.insert(name);
    }
    const std::string lower_fn = [&] {
        std::string value = fn ? fn->name : std::string{};
        for (char& c : value) {
            c = static_cast<char>(std::tolower(
                static_cast<unsigned char>(c)));
        }
        return value;
    }();
    const auto unique_name = [&](std::string base) {
        if (claimed.insert(base).second) return base;
        for (u32 suffix = 2;; ++suffix) {
            std::string candidate = std::format("{}{}", base, suffix);
            if (claimed.insert(candidate).second) return candidate;
        }
    };

    const u8 limit = std::min<u8>(self_arity,
        static_cast<u8>(self_arg_layout.size()));
    u8 fp_index = 0;
    for (u8 slot = 0; slot < limit; ++slot) {
        if (!self_arg_names[slot].empty()) continue;
        const auto& layout = self_arg_layout[slot];
        if (layout.reg == Reg::None) continue;
        IrValue arg = IrValue::make_reg(layout.reg, layout.type);
        arg.version = 0;
        std::string type = self_arg_type_names[slot];
        if (type.empty()) type = c_type_name_for(arg);

        std::string role;
        if (is_float_type(layout.type)) {
            static constexpr std::array<std::string_view, 3> axes{
                "x", "y", "z"
            };
            role = fp_index < axes.size()
                ? std::string{axes[fp_index]}
                : "scalar";
            ++fp_index;
        } else if (type.ends_with('*') || type == "void*") {
            if (lower_fn.find("shadow") != std::string::npos) {
                role = "shadow";
            } else {
                auto key = ssa_key(arg);
                std::set<SsaKey> seen;
                const bool memory_base = key &&
                    value_flows_to_memory_address(*key, seen, 0, true);
                role = memory_base ? "state" : "context";
            }
        } else {
            bool bit_mask = false;
            if (auto key = ssa_key(arg); key) {
                for (const auto& [bi, ii] :
                     ssa_uses.visible_user_positions(*key)) {
                    if (bi >= fn->blocks.size() ||
                        ii >= fn->blocks[bi].insts.size()) continue;
                    const IrOp op = fn->blocks[bi].insts[ii].op;
                    bit_mask |= op == IrOp::And || op == IrOp::Or ||
                        op == IrOp::Xor || op == IrOp::Shl ||
                        op == IrOp::Lshr;
                }
            }
            role = bit_mask ? "flags" : "value";
        }
        self_arg_names[slot] = unique_name(std::move(role));
    }
}

}  // namespace ember::emit
