// Per-function metadata and signature context setup.
#include <algorithm>
#include <cstddef>
#include <format>
#include <string_view>
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

        for (const auto& s : binary->sections()) {
            const std::string_view n = s.name;
            if (n == "__cfstring" || n.ends_with(",__cfstring")) {
                e.cfstring_lo = static_cast<addr_t>(s.vaddr);
                e.cfstring_hi = static_cast<addr_t>(s.vaddr + s.size);
                break;
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
            ctx.has_user_sig = true;
        }
    }
    if (!ctx.has_user_sig && e.current_objc_method) {
        const auto selector_names = objc_selector_arg_names(e.current_objc_method->selector);
        e.self_arg_names[0] = "self";
        if (e.self_arg_names.size() > 1) e.self_arg_names[1] = "_cmd";
        for (std::size_t i = 0;
             i < selector_names.size() && i + 2 < e.self_arg_names.size(); ++i) {
            e.self_arg_names[i + 2] = selector_names[i];
        }
        const u8 selector_arity = static_cast<u8>(std::min<std::size_t>(
            int_arg_regs(e.abi).size(), selector_names.size() + 2));
        if (!e.current_objc_method->type_encoding.empty()) {
            const auto parts = decode_objc_type_parts(e.current_objc_method->type_encoding);
            if (parts.size() > 1) {
                e.self_arity = static_cast<u8>(std::min<std::size_t>(
                    int_arg_regs(e.abi).size(), parts.size() - 1));
            }
        }
        if (e.self_arity < selector_arity) e.self_arity = selector_arity;
    }
    if (!ctx.has_user_sig) {
        if (auto it = e.objc_block_by_invoke.find(sf.ir->start);
            it != e.objc_block_by_invoke.end() && !it->second->signature.empty()) {
            const auto parts = decode_objc_type_parts(it->second->signature);
            if (parts.size() > 1) {
                e.self_arity = static_cast<u8>(std::min<std::size_t>(
                    int_arg_regs(e.abi).size(), parts.size() - 1));
                e.self_arg_names[0] = "block";
                for (std::size_t i = 2;
                     i < parts.size() && i - 1 < e.self_arg_names.size(); ++i) {
                    e.self_arg_names[i - 1] = std::format("arg{}", i - 2);
                }
                ctx.has_metadata_sig = true;
            }
        }
    }
    if (e.self_arity == 0) {
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
    } else if (e.abi != Abi::Ppc32Sysv && e.abi != Abi::Ppc64ElfV1Be &&
               e.abi != Abi::Ppc64ElfV2Le) {
        // Scalar arity gives non-PPC ABIs only the consumed prefix, while
        // later body/phi analysis still needs to recognize a higher live-in
        // register and raise that initial estimate.
        const auto regs = int_arg_regs(e.abi);
        for (std::size_t i = e.self_arg_layout.size(); i < regs.size(); ++i) {
            e.self_arg_layout.push_back({regs[i], e.abi_word_type()});
        }
    }
    return ctx;
}

}  // namespace ember::emit
