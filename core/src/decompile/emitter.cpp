#include <ember/decompile/emitter.hpp>

#include <cstddef>
#include <expected>
#include <format>
#include <functional>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <ember/analysis/cfg_util.hpp>
#include <ember/analysis/demangle.hpp>
#include <ember/analysis/frame.hpp>
#include <ember/analysis/function.hpp>
#include <ember/analysis/objc.hpp>
#include <ember/analysis/sig_inference.hpp>
#include <ember/binary/binary.hpp>
#include <ember/binary/symbol.hpp>
#include <ember/common/annotations.hpp>
#include <ember/common/error.hpp>
#include <ember/common/types.hpp>
#include <ember/decompile/emit_options.hpp>
#include <ember/disasm/register.hpp>
#include <ember/ir/abi.hpp>
#include <ember/ir/ir.hpp>
#include <ember/ir/ssa.hpp>
#include <ember/structure/region.hpp>

#include "emitter_document.hpp"
#include "emitter_internal.hpp"
#include "emitter_setup.hpp"
#include "emitter_text.hpp"
#include "emitter_render_chunk.hpp"
#include "emitter_tables.hpp"

namespace ember {

using namespace emit;

namespace {

[[nodiscard]] std::unique_ptr<Region> clone_region_tree(const Region& source) {
    auto clone = std::make_unique<Region>();
    clone->kind = source.kind;
    clone->block_start = source.block_start;
    clone->condition = source.condition;
    clone->invert = source.invert;
    clone->target = source.target;
    clone->case_values = source.case_values;
    clone->has_default = source.has_default;
    clone->switch_index = source.switch_index;
    clone->update_block = source.update_block;
    clone->update_inst = source.update_inst;
    clone->has_update = source.has_update;
    clone->children.reserve(source.children.size());
    for (const auto& child : source.children) {
        clone->children.push_back(child ? clone_region_tree(*child) : nullptr);
    }
    return clone;
}

// Every inference pass the emitter runs before rendering, in dependency
// order. Signature-shaping passes are skipped when the user or the
// binary's metadata already declared one.
void run_analysis_passes(Emitter& e, const StructuredFunction& sf,
                         const SignatureContext& sig_ctx,
                         bool structured_render) {
    e.analyze(*sf.ir);
    if (structured_render && sf.body) e.refine_call_return_regions(*sf.body);
    e.assign_synthetic_struct_types();
    e.infer_shared_call_return_types();
    if (sf.body) e.collect_structured_return_values(*sf.body);
    e.name_merge_values();
    e.infer_objc_block_capture_names();
    e.frame_layout = compute_frame_layout(*sf.ir, e.binary);
    if (structured_render && sf.body) {
        e.suppress_canary_regions(*sf.body);
        e.fold_common_tail_returns(*sf.body);
        e.analyze_return_folds(*sf.body);
        e.analyze_return_expr_call_folds(*sf.body);
        e.collect_for_updates(*sf.body);
        e.collect_goto_targets(*sf.body);
    }
    e.analyze_arc_claim_folds();
    if (!sig_ctx.has_authoritative_arity) {
        e.bump_arity_from_call_sites();
        e.bump_arity_from_body_reads();
        e.bump_arity_from_merge_initializers();
    }
    if (!sig_ctx.has_authoritative_types) {
        e.infer_narrow_arg_types_from_uses();
        e.infer_pointer_arg_types_from_memory_uses();
        e.infer_synthetic_self_arg_types();
        e.infer_ppc_helper_preserved_arg_types();
    }
    e.infer_function_pointer_args();
    e.infer_call_value_arg_names();
    e.infer_ppc_role_arg_names();
    e.infer_charp_args();
    e.infer_typed_stack_slots_from_calls();
    e.infer_import_pointer_stack_values();
    if (!sig_ctx.has_user_sig && !sig_ctx.has_metadata_sig) {
        e.promote_block_like_first_arg();
    }
    e.bind_call_returns();
    e.refine_synthetic_member_types_from_stores();
    e.analyze_merge_definite_assignment();
    if (structured_render) e.prepare_phi_copies();
}

// Optional provenance preamble: when --show-provenance is set and
// the resolved annotations carry metadata for this function, surface
// confidence + source + evidence as a comment block right under the
// function name. Lets downstream consumers decide whether to trust
// the rename without re-deriving it. Off by default - these lines
// double the visible header for human readers.
[[nodiscard]] std::string
provenance_preamble(const Annotations& annotations, addr_t start) {
    std::string out;
    if (const AnnotationMeta* m = annotations.meta_for_rename(start);
            m && (m->confidence > 0.0f || !m->evidence.empty() || !m->source.empty())) {
        std::string head = "// provenance:";
        if (m->confidence > 0.0f) {
            head += std::format(" confidence={:.3g}", m->confidence);
        }
        if (!m->source.empty()) {
            head += std::format(" source={}", m->source);
        }
        out += head + "\n";
        if (!m->evidence.empty()) {
            // Multi-line evidence renders as one comment per line so
            // long reasons don't break the surrounding comment shape.
            std::size_t i = 0;
            while (i < m->evidence.size()) {
                const auto nl = m->evidence.find('\n', i);
                const auto end = nl == std::string::npos ? m->evidence.size() : nl;
                out += "//   evidence: ";
                out.append(m->evidence, i, end - i);
                out += '\n';
                i = nl == std::string::npos ? end : nl + 1;
            }
        }
    }
    return out;
}

// Infer return type from body: any Return region carrying a non-None
// condition means the function yields a value. We use the condition's
// IrType to pick an appropriate C type rather than always saying `u64`.
[[nodiscard]] std::string
infer_return_type(const Emitter& e, const StructuredFunction& sf) {
    // Interprocedural inference is the strongest available type evidence and
    // wins over presentation heuristics for PPC carriers and low-byte Phis.
    if (e.options.signatures && e.options.type_arena && sf.ir) {
        auto it = e.options.signatures->find(sf.ir->start);
        if (it != e.options.signatures->end()) {
            std::string name = e.ipa_type_name(it->second.return_type);
            if (!name.empty()) return name;
        }
    }
    if (e.has_incidental_ppc_return_merge() ||
        e.has_incidental_ppc_stored_return()) return "void";
    if (sf.ir) {
        for (const auto& block : sf.ir->blocks) {
            for (const IrInst& instruction : block.insts) {
                if (instruction.op != IrOp::Return ||
                    instruction.src_count == 0) continue;
                const IrInst* definition = e.def_stripped(instruction.srcs[0]);
                if (!definition || definition->op != IrOp::Phi ||
                    definition->phi_operands.empty()) continue;
                bool all_low_bytes = true;
                for (const IrValue& operand : definition->phi_operands) {
                    if (!e.low_byte_return_payload(operand)) {
                        all_low_bytes = false;
                        break;
                    }
                }
                if (all_low_bytes) return "uint8_t";
            }
        }
    }
    if (!sf.body) return "void";
    struct ReturnTypeCandidate {
        IrValue value;
        bool    widened_from_narrow = false;
    };

    auto return_type_value = [&](IrValue v) {
        ReturnTypeCandidate candidate{v};
        for (int depth = 0; depth < 8; ++depth) {
            const IrInst* d = e.def_of(v);
            if (!d || d->src_count < 1) break;
            if (d->op == IrOp::Assign) {
                v = d->srcs[0];
                candidate.value = v;
                continue;
            }
            if ((d->op == IrOp::ZExt || d->op == IrOp::SExt) &&
                type_bits(d->srcs[0].type) <= type_bits(d->dst.type)) {
                v = d->srcs[0];
                candidate.value = v;
                candidate.widened_from_narrow = true;
            }
            if (d->op == IrOp::Phi && !d->phi_operands.empty()) {
                std::optional<IrValue> representative;
                bool all_low_bytes = true;
                for (const IrValue& operand : d->phi_operands) {
                    auto payload = e.low_byte_return_payload(operand);
                    if (!payload) {
                        all_low_bytes = false;
                        break;
                    }
                    if (!representative) representative = *payload;
                }
                if (all_low_bytes && representative) {
                    candidate.value = *representative;
                    candidate.widened_from_narrow = true;
                }
            }
            break;
        }
        return candidate;
    };

    std::vector<ReturnTypeCandidate> candidates;
    bool saw_void_return = false;
    bool saw_undefined_integer_return = false;
    std::function<void(const Region&)> walk = [&](const Region& r) {
        if (r.kind == RegionKind::Return &&
            r.condition.kind != IrValueKind::None) {
            IrValue return_value = r.condition;
            if ((e.abi == Abi::SysVAmd64 || e.abi == Abi::Win64) &&
                return_value.kind == IrValueKind::Reg &&
                canonical_reg(return_value.reg) == Reg::Rax &&
                return_value.version == 0) {
                saw_undefined_integer_return = true;
                return;
            }
            if (e.is_msvc_cookie_return_clobber(return_value)) {
                auto preserved = e.return_value_before_msvc_cookie(return_value);
                if (!preserved) {
                    saw_void_return = true;
                    return;
                }
                return_value = *preserved;
            }
            if (e.is_void_call_result(return_value)) {
                saw_void_return = true;
                return;
            }
            if (e.is_unbound_clobber_result(return_value)) return;
            if (e.is_incidental_x86_fp_return(return_value)) return;
            if (e.renders_stack_chk_guard_value(return_value)) return;
            // ABI return registers are often wider than the source-level
            // value and usually appear behind an `Assign` to RAX. Prefer
            // the narrowed producer for return-type inference so
            // `return zext(i32)` becomes a `u32` function instead of a
            // `u64` function with casts.
            candidates.push_back(return_type_value(return_value));
        }
        for (const auto& c : r.children) if (c) walk(*c);
    };
    walk(*sf.body);
    // An untouched RAX on a reachable exit is not a source-level result.
    // Other exits can still leave incidental arithmetic or call results there.
    if (saw_undefined_integer_return) return "void";
    // A C function cannot be value-returning on only some paths. On PPC,
    // a sibling path often carries an unknown call's incidental r3 while
    // a known SDK void call proves the real source signature is void.
    if (e.is_ppc_abi() && saw_void_return) return "void";
    if (candidates.empty()) return "void";
    // Pick the most-informative Return candidate. Many functions have
    // an early-return arm with `return 0;` (e.g. `if (!v0) return 0;`)
    // alongside the real-value path that yields the inferred-pointer
    // return. Walking-order picks the early-return first, so its
    // bit-width-only Imm type would mask the real `u64*` shape. Prefer
    // candidates whose c_type_name_for resolves to something other
    // than the raw IR-bit-width name (i.e. picked up a refined type
    // from infer_local_types - `u64*`, `char*`, `s32`, …).
    const auto raw_name_for = [&](const IrValue& v) {
        return std::string(c_type_name(v.type));
    };
    const ReturnTypeCandidate* refined = nullptr;
    for (const auto& c : candidates) {
        if (e.c_type_name_for(c.value) != raw_name_for(c.value)) {
            refined = &c;
            break;
        }
    }
    const ReturnTypeCandidate* narrowed = nullptr;
    if (!refined) {
        for (const auto& c : candidates) {
            if (c.widened_from_narrow) {
                narrowed = &c;
                break;
            }
        }
    }
    const ReturnTypeCandidate& picked =
        refined ? *refined : (narrowed ? *narrowed : candidates.front());
    const IrValue& picked_value = picked.value;
    return e.c_type_name_for(picked_value);
}

// Pick a display name: user rename beats binary symbol beats the
// sub_<hex> fallback. Used below for the header so named functions
// (e.g. `main` from LC_MAIN) don't render as `sub_<entry>`.
[[nodiscard]] std::string
header_display_name(const Emitter& e, const StructuredFunction& sf,
                    const Binary* binary, const Annotations* annotations) {
    if (annotations) {
        if (const std::string* n = annotations->name_for(sf.ir->start); n)
            return *n;
    }
    // Obj-C IMP match - the function header gets `-[Class sel]` directly.
    if (auto it = e.objc_by_imp.find(sf.ir->start);
        it != e.objc_by_imp.end()) {
        return std::format("{}[{} {}]",
                           it->second->is_class ? '+' : '-',
                           it->second->cls,
                           it->second->selector);
    }
    if (auto it = e.objc_block_by_invoke.find(sf.ir->start);
        it != e.objc_block_by_invoke.end()) {
        return objc_block_invoke_name(sf.ir->start);
    }
    // Itanium RTTI-derived virtual-method name - usable as the header
    // label on stripped C++ binaries where only typeinfos survive.
    if (e.options.rtti_methods) {
        auto it = e.options.rtti_methods->find(sf.ir->start);
        if (it != e.options.rtti_methods->end()) return it->second;
    }
    if (binary) {
        for (const auto& s : binary->symbols()) {
            if (s.is_import) continue;
            if (s.kind != SymbolKind::Function) continue;
            if (s.addr != sf.ir->start) continue;
            if (s.name.empty()) continue;
            return pretty_symbol_base(s.name);
        }
    }
    return std::format("sub_{:x}", sf.ir->start);
}

[[nodiscard]] std::string
function_header(Emitter& e, std::string_view ret, std::string_view name,
                std::string_view params) {
    e.current_return_is_void = ret == "void";
    return std::format("{} {}({}) {{\n", ret, name, params);
}

// A declared signature wins outright; only a missing return type is
// still inferred from the body.
[[nodiscard]] std::string
header_from_signature(Emitter& e, const StructuredFunction& sf,
                      const FunctionSig& sig, std::string_view display_name) {
    std::string params;
    if (sig.params.empty()) {
        params = sig.variadic ? "..." : "void";
    } else {
        for (std::size_t i = 0; i < sig.params.size(); ++i) {
            if (i > 0) params += ", ";
            params += std::format("{} {}",
                                  Emitter::normalize_c_type_alias(sig.params[i].type),
                                  signature_parameter_name(sig.params[i], i));
        }
        if (sig.variadic) params += ", ...";
    }
    const std::string ret = sig.return_type.empty()
        ? infer_return_type(e, sf)
        : Emitter::normalize_c_type_alias(sig.return_type);
    return function_header(e, ret, display_name, params);
}

// No declared or metadata signature: arity-inferred parameters with the
// best type evidence the body offered.
[[nodiscard]] std::string
header_from_inference(Emitter& e, const StructuredFunction& sf,
                      std::string_view display_name) {
    // Use the Emitter's bumped self_arity rather than re-inferring: the
    // body may have read live-in regs beyond the conservative inference.
    const u8 arity = e.self_arity;
    std::string params;
    if (arity == 0) {
        params = "void";
    } else {
        // IPA's typed params override the legacy charp_arg view.
        const InferredSig* ipa_sig = nullptr;
        if (e.options.signatures && e.options.type_arena) {
            auto it = e.options.signatures->find(sf.ir->start);
            if (it != e.options.signatures->end()) ipa_sig = &it->second;
        }
        for (u8 i = 0; i < arity; ++i) {
            if (i > 0) params += ", ";
            std::string t;
            if (ipa_sig && i < ipa_sig->params.size()) {
                t = e.ipa_type_name(ipa_sig->params[i]);
            }
            const bool concrete_ipa_type = !t.empty();
            // No IPA: consult the per-function value_types side table
            // (populated by seed_call_return_types + infer_local_types
            // ahead of emit). This is what surfaces import-derived
            // arg types in non-IPA mode - `char*`, `void*`, etc.
            if (t.empty() && i < e.self_arg_layout.size() &&
                e.self_arg_layout[i].reg != Reg::None) {
                IrValue probe = IrValue::make_reg(e.self_arg_layout[i].reg,
                                                  e.self_arg_layout[i].type);
                probe.version = 0;
                const auto local = e.c_type_name_for(probe);
                if (local != e.abi_word_c_type() ||
                    is_float_type(e.self_arg_layout[i].type)) {
                    t = local;
                }
            }
            if (t.empty()) {
                if (i < e.self_arg_layout.size() &&
                    is_float_type(e.self_arg_layout[i].type)) {
                    t = c_type_name(e.self_arg_layout[i].type);
                } else {
                    t = (i < e.charp_arg.size() && e.charp_arg[i])
                        ? std::string{"char*"}
                        : std::string{e.abi_word_c_type()};
                }
            }
            if (!concrete_ipa_type && i < e.self_arg_type_overrides.size() &&
                e.self_arg_type_overrides[i]) {
                t = c_type_name(*e.self_arg_type_overrides[i]);
            }
            if (!concrete_ipa_type && i < e.self_arg_type_names.size() &&
                !e.self_arg_type_names[i].empty()) {
                t = e.self_arg_type_names[i];
            }
            const std::string name =
                (i < e.self_arg_names.size() && !e.self_arg_names[i].empty())
                    ? e.self_arg_names[i]
                    : std::format("a{}", i + 1);
            if (i < e.self_funcptr_arity.size() && e.self_funcptr_arity[i]) {
                std::string fn_params;
                const u8 fn_arity = *e.self_funcptr_arity[i];
                if (fn_arity == 0) {
                    fn_params = "void";
                } else {
                    for (u8 j = 0; j < fn_arity; ++j) {
                        if (j > 0) fn_params += ", ";
                        if (i < e.self_funcptr_arg_types.size() &&
                            j < e.self_funcptr_arg_types[i].size()) {
                            fn_params += c_type_name(e.self_funcptr_arg_types[i][j]);
                        } else {
                            fn_params += "uint64_t";
                        }
                    }
                }
                const std::string fn_ret =
                    (i < e.self_funcptr_return_type.size() &&
                     e.self_funcptr_return_type[i])
                        ? std::string{c_type_name(*e.self_funcptr_return_type[i])}
                        : std::string{"uint64_t"};
                params += std::format("{} (*{})({})", fn_ret, name, fn_params);
            } else {
                params += std::format("{} {}", t, name);
            }
        }
    }
    std::string ret = infer_return_type(e, sf);
    // Even a stripped binary normally preserves `main` as a public
    // symbol. Its ABI return register is pointer-width on x86-64, but the
    // language-level return type is int when no debug signature survives.
    if (display_name == "main") ret = "int";
    return function_header(e, ret, display_name, params);
}

[[nodiscard]] std::string
select_function_header(Emitter& e, const StructuredFunction& sf,
                       const SignatureContext& signature_context,
                       const Annotations* annotations,
                       std::string_view display_name,
                       bool infer_when_missing = true) {
    const addr_t start = sf.ir->start;
    if (annotations) {
        if (const FunctionSig* signature = annotations->signature_for(start);
            signature && !is_incomplete_decomp_signature(*signature)) {
            if (!infer_when_missing && signature->return_type.empty()) {
                return {};
            }
            return header_from_signature(e, sf, *signature, display_name);
        }
    }
    if (signature_context.effective_metadata_signature) {
        if (!infer_when_missing &&
            signature_context.effective_metadata_signature->return_type.empty()) {
            return {};
        }
        FunctionSig effective =
            *signature_context.effective_metadata_signature;
        for (std::size_t i = 0; i < effective.params.size(); ++i) {
            if (!effective.params[i].type.empty()) continue;
            std::string type;
            if (i < e.self_arg_layout.size() &&
                e.self_arg_layout[i].reg != Reg::None) {
                IrValue probe = IrValue::make_reg(
                    e.self_arg_layout[i].reg, e.self_arg_layout[i].type);
                type = e.c_type_name_for(probe);
            }
            if (i < e.charp_arg.size() && e.charp_arg[i]) type = "char*";
            if (i < e.self_arg_type_overrides.size() &&
                e.self_arg_type_overrides[i]) {
                type = c_type_name(*e.self_arg_type_overrides[i]);
            }
            if (i < e.self_arg_type_names.size() &&
                !e.self_arg_type_names[i].empty()) {
                type = e.self_arg_type_names[i];
            }
            if (type.empty()) type = std::string(e.abi_word_c_type());
            effective.params[i].type = std::move(type);
        }
        return header_from_signature(
            e, sf, effective, display_name);
    }
    if (!infer_when_missing) {
        if (!e.options.signatures || !e.options.type_arena) return {};
        auto inferred = e.options.signatures->find(start);
        if (inferred == e.options.signatures->end() ||
            e.ipa_type_name(inferred->second.return_type).empty()) {
            return {};
        }
    }
    return header_from_inference(e, sf, display_name);
}

}  // namespace

Result<std::string> PseudoCEmitter::emit(const StructuredFunction& sf,
                                         const Binary* binary,
                                         const Annotations* annotations,
                                         EmitOptions options) const {
    if (options.line_map) options.line_map->hits.clear();
    if (!sf.ir) {
        return std::unexpected(Error::invalid_format(
            "pseudo-c: StructuredFunction has no IR"));
    }

    // Rendering performs a few presentation-only region rewrites (canary
    // removal and common-tail folding). Keep those private to this call: the
    // public API accepts a const StructuredFunction, and callers may render
    // the same structured tree more than once with different options.
    StructuredFunction working{
        sf.ir, sf.body ? clone_region_tree(*sf.body) : nullptr};

    Emitter e(binary);
    e.annotations = annotations;
    e.options     = options;
    e.abi         = binary
        ? abi_for(binary->format(), binary->arch(), binary->endian())
        : Abi::SysVAmd64;

    EmitterMetadataStorage metadata;
    setup_emitter_metadata(e, working, binary, metadata);
    const SignatureContext sig_ctx =
        setup_signature_context(e, working, binary, annotations);
    run_analysis_passes(e, working, sig_ctx, true);

    const addr_t start = working.ir->start;
    std::string out;
    out += std::format("// {}\n", working.ir->name.empty()
                                    ? std::string("<unknown>") : working.ir->name);
    if (annotations && options.show_provenance) {
        out += provenance_preamble(*annotations, start);
    }

    // Build the function header: a declared signature wins outright, then
    // Objective-C metadata, then arity inference.
    const std::string name = header_display_name(
        e, working, binary, annotations);
    const std::string header = select_function_header(
        e, working, sig_ctx, annotations, name);
    out += rtti_alias_comment(e, start);

    // Render the body into a buffer first so we can decide which
    // recovered frame slots actually appear in the output text. Some
    // Loads / Stores get hidden by the emitter (canary writes, ABI
    // shuffle stores) and don't surface a `local_<hex>` reference, so
    // a slot in the layout isn't proof of a live mention. Emitting
    // declarations only for referenced slots keeps the function head
    // tidy without leaning on the dead-decl pruner (which only
    // recognises `TYPE NAME = expr;` form).
    auto body = RenderChunk::capture(options.line_map, [&](std::string& text) {
        if (working.body) e.emit_region(*working.body, 1, text);
    });
    std::string& body_buf = body.text();
    if (working.body && !working.ir->blocks.empty()) {
        body_buf += structurer_fail_markers(working, binary);
    }

    const std::set<std::string> matrix_locals = matrix_stack_locals(body_buf);
    collect_address_taken_functions(e, body_buf, binary);
    std::string declaration_context = header + body_buf;
    for (const std::string& local : matrix_locals) {
        declaration_context += std::format("\nMtx34 {};", local);
    }
    if (e.is_ppc_abi() && !options.line_map) {
        body_buf = collapse_ppc_field_copy_runs(body_buf);
    }
    const auto fallbacks = fallback_materializations(e, body_buf);

    out += file_scope_declarations(e, declaration_context);
    out += header;
    if (text_contains_identifier_in_code(body_buf, "stack_top")) {
        out += "  uint64_t stack_top; /* entry stack word */\n";
    }
    out += fallback_temp_declarations(e, fallbacks);
    out += synthetic_merge_stack_declarations(e);
    out += frame_slot_declarations(e, body_buf, matrix_locals);
    out += merge_local_declarations(e, body_buf);
    out += e.scoped_ssa_declarations();

    std::move(body).append_to(out);

    out += "}\n";

    // Text-level cleanups are skipped when a LineMap is being collected:
    // deleting lines would invalidate the byte_offset values already
    // recorded (the debugger can live with a slightly noisier function
    // listing in exchange for accurate PC-to-line mapping).
    if (!options.line_map) {
        out = strip_label_only_if_blocks(out);
        out = strip_dead_declarations(e, out, header);
        out = collapse_empty_then_else_blocks(out);
        if (e.is_ppc_abi()) {
            out = rename_ppc_temporaries(std::move(out));
            out = fix_ppc_offset_pointer_declarations(std::move(out));
            out = compact_ppc_type_names(std::move(out));
        }
        prepend_untyped_pointer_note(out, header);
    }

    return out;
}

Result<std::string>
PseudoCEmitter::emit_per_block(const StructuredFunction& sf,
                               const Binary* binary,
                               const Annotations* annotations,
                               EmitOptions options) const {
    if (options.line_map) options.line_map->hits.clear();
    if (!sf.ir) {
        return std::unexpected(Error::invalid_format(
            "pseudo-c per-block: StructuredFunction has no IR"));
    }

    // Setup mirrors emit() - same ABI plumbing, same ObjC / RTTI lookup,
    // same per-emit signature inference. We deliberately skip the
    // body-tree walks (suppress_canary_regions / analyze_return_folds /
    // collect_for_updates) since per-block output has no structured body
    // to reason about.
    Emitter e(binary);
    e.annotations = annotations;
    e.options     = options;
    e.abi         = binary
        ? abi_for(binary->format(), binary->arch(), binary->endian())
        : Abi::SysVAmd64;

    EmitterMetadataStorage metadata;
    setup_emitter_metadata(e, sf, binary, metadata);
    const SignatureContext sig_ctx =
        setup_signature_context(e, sf, binary, annotations);
    run_analysis_passes(e, sf, sig_ctx, false);
    const std::string display_name = header_display_name(
        e, sf, binary, annotations);
    // Per-block output does not print a C function header, but selecting it
    // establishes the same authoritative return/parameter state used by the
    // structured formatter (notably whether ABI return lanes are void).
    (void)select_function_header(
        e, sf, sig_ctx, annotations, display_name, false);

    // Output mirrors format_cfg's framing - same `bb_<addr>` headers,
    // same `<-` predecessor list, same `-> bb_xxx (label)` arrows - so
    // any consumer parsing the asm CFG view (UI, scripts) parses this
    // identically up to the body content swap.
    std::string out;
    out += std::format("// {}\n", display_name);
    out += std::format("//   per-block pseudo-C ({} blocks)\n",
                       sf.ir->blocks.size());
    for (const auto& [name, local] : e.merge_locals) {
        if (local.initializer) {
            out += std::format("//   {} {} = {};\n",
                               e.c_type_name_for(local.type_value),
                               name,
                               e.expr(*local.initializer));
        } else {
            if (e.is_ppc_abi()) {
                out += std::format("//   {} {} = {{0}}; /* unresolved SSA merge */\n",
                                   e.c_type_name_for(local.type_value), name);
            } else {
                out += std::format("//   {} {};\n",
                                   e.c_type_name_for(local.type_value), name);
            }
        }
    }

    const auto rpo = compute_rpo(*sf.ir);
    for (addr_t ba : rpo) {
        auto it = sf.ir->block_at.find(ba);
        if (it == sf.ir->block_at.end()) continue;
        const auto& bb = sf.ir->blocks[it->second];

        std::string header = std::format("\nbb_{:x}", bb.start);
        if (bb.start == sf.ir->start) header += "  (entry)";
        if (!bb.predecessors.empty()) {
            header += "  <-";
            for (addr_t p : bb.predecessors) header += std::format(" bb_{:x}", p);
        }
        out += header + ":\n";

        e.emit_block(bb.start, 1, out);
        e.emit_block_terminator(bb, 1, out);

        // Successor arrows - copy the format used by append_function_text
        // in pipeline.cpp's `format_cfg` so a single CFG parser handles
        // both rendering modes.
        switch (bb.kind) {
            case BlockKind::Return:
                out += "  -> <return>\n";
                break;
            case BlockKind::TailCall:
                if (!bb.successors.empty())
                    out += std::format("  -> bb_{:x}  (tail-call)\n",
                                       bb.successors[0]);
                break;
            case BlockKind::Conditional:
                if (bb.successors.size() >= 2) {
                    out += std::format("  -> bb_{:x}  (taken)\n", bb.successors[0]);
                    out += std::format("  -> bb_{:x}  (fallthrough)\n",
                                       bb.successors[1]);
                } else if (bb.successors.size() == 1) {
                    out += std::format("  -> bb_{:x}  (fallthrough)\n",
                                       bb.successors[0]);
                }
                break;
            case BlockKind::Unconditional:
            case BlockKind::Fallthrough:
                if (!bb.successors.empty())
                    out += std::format("  -> bb_{:x}\n", bb.successors[0]);
                break;
            case BlockKind::IndirectJmp:
                out += "  -> <indirect>\n";
                break;
            case BlockKind::Switch: {
                const std::size_t ncases = bb.case_values.size();
                for (std::size_t i = 0; i < ncases && i < bb.successors.size(); ++i) {
                    out += std::format("  -> bb_{:x}  (case {})\n",
                                       bb.successors[i], bb.case_values[i]);
                }
                if (bb.has_default && !bb.successors.empty())
                    out += std::format("  -> bb_{:x}  (default)\n",
                                       bb.successors.back());
                break;
            }
        }
    }

    return out;
}

}  // namespace ember
