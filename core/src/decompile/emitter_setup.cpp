// Per-function metadata and signature context setup.
#include <algorithm>
#include <cstddef>
#include <format>
#include <utility>

#include <ember/analysis/arity.hpp>
#include <ember/analysis/msvc_rtti.hpp>
#include <ember/analysis/objc.hpp>
#include <ember/analysis/pipeline.hpp>
#include <ember/analysis/rtti.hpp>
#include <ember/binary/binary.hpp>
#include <ember/binary/format.hpp>
#include <ember/common/annotations.hpp>
#include <ember/common/types.hpp>
#include <ember/ir/abi.hpp>
#include <ember/structure/region.hpp>

#include "emitter_internal.hpp"

namespace ember::emit {

bool is_incomplete_decomp_signature(const FunctionSig& signature) {
    return signature.return_type.empty() && signature.params.empty() &&
           signature.variadic;
}

std::string signature_parameter_name(const ParamSig& parameter,
                                     std::size_t index) {
    return parameter.name.empty()
        ? std::format("a{}", index + 1)
        : parameter.name;
}

void setup_emitter_metadata(Emitter& e,
                            const StructuredFunction& sf,
                            const Binary* binary,
                            EmitterMetadataStorage& storage) {
    if (binary && binary->format() == Format::MachO) {
        if (!e.options.objc_selrefs) {
            storage.local_selrefs = parse_objc_selrefs(*binary);
            if (!storage.local_selrefs.empty()) {
                e.options.objc_selrefs = &storage.local_selrefs;
            }
        }
        if (!e.options.objc_classrefs) {
            storage.local_classrefs = parse_objc_classrefs(*binary);
            if (!storage.local_classrefs.empty()) {
                e.options.objc_classrefs = &storage.local_classrefs;
            }
        }

        storage.local_objc_methods = parse_objc_methods(*binary);
        for (const auto& m : storage.local_objc_methods) {
            if (m.imp != 0) e.objc_by_imp.emplace(m.imp, &m);
        }
        if (auto it = e.objc_by_imp.find(sf.ir->start);
            it != e.objc_by_imp.end()) {
            e.current_objc_method = it->second;
        }

        storage.local_objc_ivars = parse_objc_ivars(*binary);
        for (const auto& iv : storage.local_objc_ivars) {
            if (iv.offset_slot != 0) e.objc_ivar_by_slot.emplace(iv.offset_slot, &iv);
            e.objc_ivar_by_class_offset.emplace(std::pair{iv.cls, iv.offset}, &iv);
        }

        storage.local_objc_properties = parse_objc_properties(*binary);
        for (const auto& prop : storage.local_objc_properties) {
            if (!prop.ivar_name.empty()) {
                e.objc_property_by_ivar.emplace(
                    std::pair{prop.cls, prop.ivar_name}, &prop);
            }
        }

        storage.local_objc_blocks = parse_objc_blocks(*binary);
        for (const auto& blk : storage.local_objc_blocks) {
            if (blk.literal != 0) e.objc_block_by_literal.emplace(blk.literal, &blk);
            if (blk.invoke != 0) e.objc_block_by_invoke.emplace(blk.invoke, &blk);
        }
        storage.local_objc_stack_blocks = discover_objc_stack_block_invokes(*binary);
        for (const auto& blk : storage.local_objc_stack_blocks) {
            if (blk.invoke != 0) e.objc_stack_block_by_invoke.emplace(blk.invoke, &blk);
        }

        if (!e.options.rtti_methods) {
            storage.local_rtti_methods = rtti_method_names(parse_itanium_rtti(*binary));
            if (!storage.local_rtti_methods.empty()) {
                e.options.rtti_methods = &storage.local_rtti_methods;
            }
        }

    } else if (binary && binary->format() == Format::Pe) {
        if (!e.options.rtti_methods) {
            storage.local_rtti_methods = rtti_method_names(parse_msvc_rtti(*binary));
            if (!storage.local_rtti_methods.empty()) {
                e.options.rtti_methods = &storage.local_rtti_methods;
            }
        }
    }
}

SignatureContext setup_signature_context(Emitter& e,
                                         const StructuredFunction& sf,
                                         const Binary* binary,
                                         const Annotations* annotations) {
    SignatureContext ctx;
    if (annotations) {
        if (const FunctionSig* sig = annotations->signature_for(sf.ir->start);
            sig && !is_incomplete_decomp_signature(*sig)) {
            e.self_arity = static_cast<u8>(
                std::min(sig->params.size(), kMaxAbiArgs));
            e.self_arg_layout = e.abi_layout_for(*sig);
            for (std::size_t i = 0;
                 i < sig->params.size() && i < e.self_arg_names.size(); ++i) {
                e.self_arg_names[i] = signature_parameter_name(sig->params[i], i);
                e.self_arg_type_names[i] = Emitter::normalize_c_type_alias(
                    sig->params[i].type);
            }
            ctx.has_user_sig = true;
            ctx.has_authoritative_arity = true;
            ctx.has_authoritative_types = true;
        }
    }
    if (!ctx.has_user_sig && e.current_objc_method) {
        const auto selector_names = objc_selector_arg_names(e.current_objc_method->selector);
        const auto parts = decode_objc_type_parts(
            e.current_objc_method->type_encoding);
        FunctionSig signature;
        if (!parts.empty()) signature.return_type = parts[0];
        const std::string self_type = e.current_objc_method->cls.empty()
            ? std::string{"id"}
            : e.current_objc_method->cls + "*";
        signature.params.push_back({self_type, "self"});
        signature.params.push_back({"SEL", "_cmd"});
        const std::size_t encoded_args = parts.size() > 3
            ? parts.size() - 3 : 0;
        const std::size_t source_args = std::max(
            encoded_args, selector_names.size());
        for (std::size_t i = 0; i < source_args; ++i) {
            const std::string type = i < encoded_args
                ? parts[i + 3] : std::string{};
            const std::string name = i < selector_names.size()
                ? selector_names[i] : std::format("arg{}", i);
            signature.params.push_back({type, name});
        }
        if (signature.params.size() > kMaxAbiArgs) {
            signature.params.resize(kMaxAbiArgs);
        }
        e.self_arity = static_cast<u8>(signature.params.size());
        e.self_arg_layout = e.abi_layout_for(signature);
        for (std::size_t i = 0; i < signature.params.size(); ++i) {
            e.self_arg_names[i] = signature.params[i].name;
            if (i < 2 || i - 2 < encoded_args) {
                e.self_arg_type_names[i] = Emitter::normalize_c_type_alias(
                    signature.params[i].type);
            }
        }
        ctx.has_metadata_sig = true;
        ctx.has_authoritative_arity = true;
        ctx.has_authoritative_types =
            parts.size() >= 3 && encoded_args >= selector_names.size();
        ctx.effective_metadata_signature = std::move(signature);
    }
    if (!ctx.has_user_sig && !ctx.has_metadata_sig) {
        if (auto it = e.objc_block_by_invoke.find(sf.ir->start);
            it != e.objc_block_by_invoke.end() && !it->second->signature.empty()) {
            const auto parts = decode_objc_type_parts(it->second->signature);
            if (parts.size() > 1) {
                FunctionSig signature;
                signature.return_type = block_param_type(parts[0]);
                for (std::size_t i = 2;
                     i < parts.size(); ++i) {
                    signature.params.push_back({
                        block_param_type(parts[i]),
                        std::format("arg{}", i - 2)});
                }
                signature.params.insert(
                    signature.params.begin(),
                    ParamSig{block_param_type(parts[1]), "block"});
                if (signature.params.size() > kMaxAbiArgs) {
                    signature.params.resize(kMaxAbiArgs);
                }
                e.self_arity = static_cast<u8>(signature.params.size());
                e.self_arg_layout = e.abi_layout_for(signature);
                for (std::size_t i = 0; i < signature.params.size(); ++i) {
                    e.self_arg_names[i] = signature.params[i].name;
                    e.self_arg_type_names[i] = Emitter::normalize_c_type_alias(
                        signature.params[i].type);
                }
                ctx.has_metadata_sig = true;
                ctx.has_authoritative_arity = true;
                ctx.has_authoritative_types = true;
                ctx.effective_metadata_signature = std::move(signature);
            }
        }
    }
    if (!ctx.has_authoritative_arity && e.options.signatures &&
        e.options.type_arena) {
        auto inferred = e.options.signatures->find(sf.ir->start);
        if (inferred != e.options.signatures->end()) {
            std::size_t concrete_arity = 0;
            const std::size_t limit = std::min<std::size_t>(
                inferred->second.params.size(), kMaxAbiArgs);
            for (std::size_t i = 0; i < limit; ++i) {
                if (!e.ipa_type_name(inferred->second.params[i]).empty()) {
                    concrete_arity = i + 1;
                }
            }
            if (concrete_arity > e.self_arity) {
                FunctionSig signature;
                signature.params.reserve(concrete_arity);
                for (std::size_t i = 0; i < concrete_arity; ++i) {
                    std::string type =
                        e.ipa_type_name(inferred->second.params[i]);
                    if (type.empty()) type = std::string(e.abi_word_c_type());
                    signature.params.push_back({
                        std::move(type), std::format("a{}", i + 1)});
                }
                e.self_arity = static_cast<u8>(concrete_arity);
                e.self_arg_layout = e.abi_layout_for(signature);
            }
        }
    }
    if (e.self_arity == 0 && !ctx.has_authoritative_arity) {
        if (binary) e.self_arg_layout = infer_arguments(*binary, sf.ir->start, e.abi);
        e.self_arity = static_cast<u8>(std::min<std::size_t>(
            e.self_arg_layout.size(), kMaxAbiArgs));
    }
    if (e.self_arg_layout.empty()) {
        // Keep the complete candidate bank available even when the initial
        // arity is zero. Later body/phi passes can then prove a live-in and
        // raise self_arity without leaking an architectural register name.
        const auto regs = int_arg_regs(e.abi);
        e.self_arg_layout.reserve(regs.size());
        for (std::size_t i = 0; i < regs.size(); ++i) {
            e.self_arg_layout.push_back({regs[i], e.abi_word_type()});
        }
    } else if (!ctx.has_authoritative_arity &&
               e.abi != Abi::Ppc32Sysv && e.abi != Abi::Ppc64ElfV1Be &&
               e.abi != Abi::Ppc64ElfV2Le) {
        // Scalar arity gives non-PPC ABIs only the consumed prefix, while
        // later body/phi analysis still needs to recognize a higher live-in
        // register and raise that initial estimate.
        const auto regs = int_arg_regs(e.abi);
        if (abi_positional_arg_slots(e.abi)) {
            for (std::size_t i = e.self_arg_layout.size(); i < regs.size(); ++i) {
                e.self_arg_layout.push_back({regs[i], e.abi_word_type()});
            }
        } else {
            for (Reg reg : regs) {
                const bool already_used = std::ranges::any_of(
                    e.self_arg_layout, [&](const InferredArgument& argument) {
                        return canonical_reg(argument.reg) == canonical_reg(reg);
                    });
                if (!already_used) {
                    e.self_arg_layout.push_back({reg, e.abi_word_type()});
                }
            }
        }
    }
    const bool has_fp_parameter = std::ranges::any_of(
        e.self_arg_layout, [](const InferredArgument& argument) {
            return is_float_type(argument.type);
        });
    if (!ctx.has_authoritative_arity && !has_fp_parameter &&
        (e.abi == Abi::SysVAmd64 || e.abi == Abi::Win64 ||
         e.abi == Abi::Aapcs64 || e.abi == Abi::AapcsArm32)) {
        const std::size_t register_count = int_arg_regs(e.abi).size();
        const i64 word = e.abi_word_type() == IrType::I32 ? 4 : 8;
        while (e.self_arg_layout.size() < kMaxAbiArgs) {
            const std::size_t parameter = e.self_arg_layout.size();
            if (parameter < register_count) break;
            i64 stack_offset = 0;
            if (e.abi == Abi::SysVAmd64) {
                stack_offset = 8 + static_cast<i64>(
                    parameter - register_count) * 8;
            } else if (e.abi == Abi::Win64) {
                stack_offset = 8 + static_cast<i64>(parameter) * 8;
            } else {
                stack_offset = static_cast<i64>(
                    parameter - register_count) * word;
            }
            e.self_arg_layout.push_back({
                Reg::None, e.abi_word_type(), false, stack_offset});
        }
    }
    return ctx;
}

}  // namespace ember::emit
