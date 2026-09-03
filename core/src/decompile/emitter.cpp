#include <ember/decompile/emitter.hpp>

#include <cctype>
#include <cstddef>
#include <expected>
#include <format>
#include <functional>
#include <map>
#include <optional>
#include <regex>
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

#include "emitter_internal.hpp"
#include "emitter_tables.hpp"

namespace ember {

using namespace emit;

namespace {

// Every inference pass the emitter runs before rendering, in dependency
// order. Signature-shaping passes are skipped when the user or the
// binary's metadata already declared one.
void run_analysis_passes(Emitter& e, const StructuredFunction& sf,
                         const SignatureContext& sig_ctx) {
    e.analyze(*sf.ir);
    e.assign_synthetic_struct_types();
    e.infer_shared_call_return_types();
    if (sf.body) e.collect_structured_return_values(*sf.body);
    e.name_merge_values();
    e.infer_objc_block_capture_names();
    e.frame_layout = compute_frame_layout(*sf.ir, e.binary);
    if (sf.body) {
        e.suppress_canary_regions(*sf.body);
        e.fold_common_tail_returns(*sf.body);
        e.analyze_return_folds(*sf.body);
        e.analyze_return_expr_call_folds(*sf.body);
        e.collect_for_updates(*sf.body);
        e.collect_goto_targets(*sf.body);
    }
    e.analyze_arc_claim_folds();
    const bool infer_signature =
        !sig_ctx.has_user_sig && !sig_ctx.has_metadata_sig;
    if (infer_signature) {
        e.bump_arity_from_call_sites();
        e.bump_arity_from_body_reads();
        e.bump_arity_from_merge_initializers();
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
    if (!sig_ctx.has_user_sig) e.promote_block_like_first_arg();
    e.bind_call_returns();
    e.refine_synthetic_member_types_from_stores();
    e.analyze_merge_definite_assignment();
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
    // IPA wins outright when it has concrete evidence - the typed
    // return came from harvesting Return-operand types after Phase 2
    // local inference, which sees more than this function's
    // bit-width-only fallback.
    if (e.options.signatures && e.options.type_arena && sf.ir) {
        auto it = e.options.signatures->find(sf.ir->start);
        if (it != e.options.signatures->end()) {
            std::string n = e.ipa_type_name(it->second.return_type);
            if (!n.empty()) return n;
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
    std::function<void(const Region&)> walk = [&](const Region& r) {
        if (r.kind == RegionKind::Return &&
            r.condition.kind != IrValueKind::None) {
            IrValue return_value = r.condition;
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
        params = "void";
    } else {
        for (std::size_t i = 0; i < sig.params.size(); ++i) {
            if (i > 0) params += ", ";
            params += std::format("{} {}",
                                  Emitter::normalize_c_type_alias(sig.params[i].type),
                                  sig.params[i].name);
        }
    }
    const std::string ret = sig.return_type.empty()
        ? infer_return_type(e, sf)
        : Emitter::normalize_c_type_alias(sig.return_type);
    return function_header(e, ret, display_name, params);
}

// Obj-C IMP: derive the header from the method's ObjC type
// encoding. Gives us proper self / _cmd / typed args instead of
// u64 placeholders - for a method with encoding "v40@0:8@16i32"
// we get `void -[Foo bar:](Foo* self, SEL _cmd, id arg0, int arg1)`.
[[nodiscard]] std::string
header_from_objc_method(Emitter& e, const ObjcMethod& meth,
                        std::string_view display_name) {
    const auto parts = decode_objc_type_parts(meth.type_encoding);
    if (parts.empty()) return {};
    const std::string& ret_ty = parts[0];
    std::string params;
    if (parts.size() <= 1) {
        params = "void";
    } else {
        // `self` is typed as `Class*` when we know the class,
        // otherwise `id`.
        const std::string self_ty = meth.cls.empty()
            ? std::string{"id"}
            : meth.cls + "*";
        params = self_ty + " self";
        if (parts.size() > 1) params += ", SEL _cmd";
        const auto arg_names = objc_selector_arg_names(meth.selector);
        for (std::size_t i = 3; i < parts.size(); ++i) {
            const std::size_t arg_idx = i - 3;
            const std::string name = arg_idx < arg_names.size()
                ? arg_names[arg_idx]
                : std::format("arg{}", arg_idx);
            params += std::format(", {} {}", parts[i], name);
        }
    }
    return function_header(e, ret_ty, display_name, params);
}

[[nodiscard]] std::string
header_from_objc_block(Emitter& e, std::string_view signature,
                       std::string_view display_name) {
    const auto parts = decode_objc_type_parts(signature);
    if (parts.empty()) return {};
    std::string params;
    if (parts.size() <= 1) {
        params = "void";
    } else {
        for (std::size_t i = 1; i < parts.size(); ++i) {
            if (i > 1) params += ", ";
            const std::string name = (i == 1)
                ? std::string{"block"}
                : std::format("arg{}", i - 2);
            params += std::format("{} {}", block_param_type(parts[i]), name);
        }
    }
    return function_header(e, block_param_type(parts[0]), display_name, params);
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
            if (ipa_sig == nullptr && i < e.self_arg_type_overrides.size() &&
                e.self_arg_type_overrides[i]) {
                t = c_type_name(*e.self_arg_type_overrides[i]);
            }
            if (i < e.self_arg_type_names.size() &&
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

// When the header name is a long RTTI `Class::vfn_N` - especially for
// templates - advertise a shorter alias the user can type with `-s`.
// Purely a discoverability comment; the resolver accepts the short form
// via the same class_aliases machinery used here.
[[nodiscard]] std::string rtti_alias_comment(const Emitter& e, addr_t start) {
    if (!e.options.rtti_methods) return {};
    const auto it = e.options.rtti_methods->find(start);
    if (it == e.options.rtti_methods->end()) return {};
    const std::string& full = it->second;
    const auto vfn_pos = full.rfind("::vfn_");
    if (vfn_pos != std::string::npos) {
        std::string_view cls_sv{full.data(), vfn_pos};
        std::string_view base_sv = cls_sv;
        for (std::size_t i = 0; i < cls_sv.size(); ++i) {
            if (cls_sv[i] == '<') { base_sv = cls_sv.substr(0, i); break; }
        }
        const auto slash = base_sv.rfind("::");
        const std::string_view short_sv = slash == std::string_view::npos
            ? base_sv
            : base_sv.substr(slash + 2);
        if (!short_sv.empty() && short_sv != cls_sv) {
            return std::format("// alias: {}{}\n",
                               short_sv,
                               std::string_view{full}.substr(vfn_pos));
        }
    }
    return {};
}

// Surface blocks the structurer failed to fit as explicit markers
// rather than letting their content vanish silently. Any IR block
// not reached by a `RegionKind::Block` node in the structured tree
// is unrendered - its instructions (calls included) would otherwise
// disappear with no diagnostic. The marker carries the address range
// so the user can fall back to `--disasm-at` to see what was dropped.
//
// Blocks the emitter intentionally suppressed (the canary `if
// (cookie) __stack_chk_fail()` fail-arm) are exempt - they're
// dropped on purpose, not by structurer failure.
[[nodiscard]] std::string
structurer_fail_markers(const StructuredFunction& sf, const Binary* binary) {
    std::string out;
    std::set<addr_t> rendered_blocks;
    std::function<void(const Region&)> collect = [&](const Region& r) {
        if (r.kind == RegionKind::Block) rendered_blocks.insert(r.block_start);
        for (const auto& c : r.children) if (c) collect(*c);
    };
    collect(*sf.body);
    auto is_intentionally_suppressed = [&](const IrBlock& bb) noexcept {
        if (!binary) return false;
        for (const auto& inst : bb.insts) {
            if (inst.op != IrOp::Call) continue;
            if (const Symbol* s = binary->import_at_plt(inst.target1); s) {
                if (Emitter::clean_import_name(s->name) == "__stack_chk_fail") {
                    return true;
                }
            }
        }
        return false;
    };
    for (const auto& bb : sf.ir->blocks) {
        if (bb.end <= bb.start) continue;
        if (rendered_blocks.contains(bb.start)) continue;
        if (is_intentionally_suppressed(bb)) continue;
        out += std::format(
            "  // STRUCTURER_FAIL: {:#x}..{:#x} (see --disasm-at)\n",
            bb.start, bb.end);
    }
    return out;
}

// Stack slots handed by address to the PPC matrix helpers are Mtx34s,
// whatever their observed access width says.
[[nodiscard]] std::set<std::string> matrix_stack_locals(const std::string& body) {
    std::set<std::string> out;
    const std::regex matrix_call(
        R"((?:PSMTX[A-Za-z0-9_]*|C_MTX[A-Za-z0-9_]*|QUATMtx)\([^;\n]*&((?:local|arg)_[0-9a-fA-F]+))");
    for (std::sregex_iterator it(body.begin(), body.end(), matrix_call), end;
         it != end; ++it) {
        out.insert((*it)[1].str());
    }
    return out;
}

// `&fn /* 0x... */` in the body needs an extern declaration above it.
void collect_address_taken_functions(Emitter& e, const std::string& body,
                                     const Binary* binary) {
    const std::regex addressed_function(
        R"(&([A-Za-z_][A-Za-z0-9_]*)\s*/\*\s*0x[0-9a-fA-F]+\s*\*/)");
    for (std::sregex_iterator it(
             body.begin(), body.end(), addressed_function), end;
         it != end; ++it) {
        const std::string name = (*it)[1].str();
        if (binary) {
            const Symbol* symbol = binary->find_by_name(name);
            if (!symbol || symbol->kind != SymbolKind::Function) continue;
        }
        e.address_taken_function_decls.insert(name);
    }
}

    // A depth-capped expression may intentionally stop at `tN`. Resolve
    // dependency-safe PPC snapshots before file-scope declarations are
    // emitted so any globals discovered by expansion also receive an extern.
    struct FallbackMaterialization {
        IrValue value;
        std::string initializer;
    };

[[nodiscard]] std::map<u32, FallbackMaterialization>
fallback_materializations(const Emitter& e, const std::string& body) {
    std::map<u32, FallbackMaterialization> out;
    const auto contains_raw_temp = [](std::string_view text) {
        for (std::size_t i = 0; i + 1 < text.size(); ++i) {
            if (text[i] != 't' ||
                !std::isdigit(static_cast<unsigned char>(text[i + 1])) ||
                (i != 0 && c_ident_char(text[i - 1]))) continue;
            std::size_t end = i + 2;
            while (end < text.size() && std::isdigit(
                       static_cast<unsigned char>(text[end]))) ++end;
            if (end == text.size() || !c_ident_char(text[end])) return true;
        }
        return false;
    };
    for (const auto& [_, definition] : e.defs) {
        if (!definition || definition->dst.kind != IrValueKind::Temp) continue;
        const std::string name = std::format("t{}", definition->dst.temp);
        if (!text_contains_identifier_in_code(body, name) ||
            text_declares_identifier(body, name)) continue;
        std::string initializer;
        if (auto key = ssa_key(definition->dst);
            key && e.memory_snapshot_loads.contains(*key) &&
            Emitter::inlinable_op(definition->op)) {
            initializer = e.expand(*definition, 0, 0);
            if (initializer == name || contains_raw_temp(initializer)) {
                initializer.clear();
            }
        }
        out.emplace(
            definition->dst.temp,
            FallbackMaterialization{definition->dst, std::move(initializer)});
    }
    return out;
}

// Record definitions, function externs and global externs, in that
// order, ahead of the function itself.
[[nodiscard]] std::string
file_scope_declarations(const Emitter& e, const std::string& declaration_context) {
    std::string out;
    out += e.imported_record_declarations(declaration_context);
    out += e.synthetic_struct_declarations(declaration_context);
    for (const std::string& function : e.address_taken_function_decls) {
        out += std::format("extern void {}(void);\n", function);
    }
    if (!e.address_taken_function_decls.empty()) out += "\n";
    for (const auto& [name, ty] : e.global_decls) {
        if (ty.find("(*") != std::string::npos) {
            out += std::format("extern {};\n", ty);
        } else if (ty.ends_with("[]")) {
            out += std::format("extern {} {}[];\n",
                               std::string_view(ty).substr(0, ty.size() - 2),
                               name);
        } else {
            out += std::format("extern {} {};\n", ty, name);
        }
    }
    if (!e.global_decls.empty()) out += "\n";
    return out;
}

[[nodiscard]] std::string fallback_temp_declarations(
    const Emitter& e, const std::map<u32, FallbackMaterialization>& fallbacks) {
    std::string out;
    for (const auto& [temp, materialization] : fallbacks) {
        if (!materialization.initializer.empty()) {
            out += std::format("  {} t{} = {};\n",
                               e.c_type_name_for(materialization.value), temp,
                               materialization.initializer);
        } else {
            out += std::format(
                "  {} t{} = {{0}}; /* unresolved expression materialization */\n",
                e.c_type_name_for(materialization.value), temp);
        }
    }
    return out;
}

// Merge locals initialised from a stack address that the frame layout
// never saw still need a declaration; conflicting pointee types render
// as a union.
[[nodiscard]] std::string synthetic_merge_stack_declarations(const Emitter& e) {
    std::string out;
    std::map<i64, std::set<std::string>> synthetic_merge_stack_types;
    for (const auto& [_, local] : e.merge_locals) {
        if (!local.initializer) continue;
        auto offset = e.stack_offset(*local.initializer);
        if (!offset || e.frame_layout.slots.contains(*offset)) continue;
        std::string type = e.c_type_name_for(local.type_value);
        if (!type.ends_with('*')) continue;
        type.pop_back();
        while (!type.empty() && std::isspace(
                   static_cast<unsigned char>(type.back()))) {
            type.pop_back();
        }
        if (!type.empty()) synthetic_merge_stack_types[*offset].insert(std::move(type));
    }
    for (const auto& [offset, types] : synthetic_merge_stack_types) {
        const std::string name = Emitter::stack_name(offset);
        if (types.size() == 1) {
            out += std::format("  {} {};\n", *types.begin(), name);
            continue;
        }
        out += "  union { ";
        for (const std::string& type : types) {
            out += std::format("{} as_{}; ", type, type);
        }
        out += std::format("}} {};\n", name);
    }
    return out;
}

// Slot extent → array recovery: if a slot's footprint (the gap to the
// next slot above it in the frame) is bigger than its observed access
// width, the user wrote `T arr[N]`, not a single scalar. Render it as
// such so a 128-byte `fgets` buffer doesn't read as `u64 local_208;`.
// The map iterates in ascending offset order; for stack locals (negative
// offsets) that means deepest-first, so each slot's "next" entry sits
// closer to entry rsp and gives us the slot's upper edge directly.
[[nodiscard]] std::string
frame_slot_declarations(const Emitter& e, const std::string& body,
                        const std::set<std::string>& matrix_locals) {
    std::string out;
    auto next_slot_offset = [&](i64 off) -> std::optional<i64> {
        auto it = e.frame_layout.slots.upper_bound(off);
        if (it == e.frame_layout.slots.end()) return std::nullopt;
        return it->second.offset;
    };
    const auto assigned_as_scalar = [&](std::string_view name) {
        std::size_t start = 0;
        while (start <= body.size()) {
            std::size_t end = body.find('\n', start);
            if (end == std::string::npos) end = body.size();
            const std::string_view line = trim_line_view(
                std::string_view(body).substr(start, end - start));
            if (line.starts_with(name) && line.size() > name.size() &&
                line.substr(name.size()).starts_with(" =")) return true;
            if (end == body.size()) break;
            start = end + 1;
        }
        return false;
    };
    for (const auto& [_, slot] : e.frame_layout.slots) {
        if (slot.name.empty()) continue;
        bool used_by_merge_initializer = false;
        for (const auto& [_, local] : e.merge_locals) {
            if (!local.initializer) continue;
            auto offset = e.stack_offset(*local.initializer);
            used_by_merge_initializer |= offset && *offset == slot.offset;
        }
        if (!text_contains_identifier_in_code(body, slot.name) &&
            !used_by_merge_initializer) continue;
        // char* type propagation overrides the access-width-derived type
        // when an inferred libc-char* call observed `&local_X` flowing in.
        const bool charp = slot.type_override.empty() &&
                           e.charp_local_slots.contains(slot.offset);
        std::string ty;
        u32 elem_size = slot.size_bytes;
        if (!slot.type_override.empty()) {
            ty = Emitter::normalize_c_type_alias(slot.type_override);
        } else if (charp) {
            ty = "char";
            elem_size = 1;
        } else {
            ty = std::string(c_type_name(slot.type));
        }
        if (matrix_locals.contains(slot.name)) {
            ty = "Mtx34";
            elem_size = 48;
        }
        std::string suffix;
        if (!matrix_locals.contains(slot.name) &&
            slot.type_override.empty()) {
            if (auto required = e.stack_required_extents.find(slot.offset);
                required != e.stack_required_extents.end() &&
                required->second > elem_size) {
                ty = charp ? "char" : "uint8_t";
                elem_size = 1;
                suffix = std::format("[{}]", required->second);
            }
        }
        if (suffix.empty() && !matrix_locals.contains(slot.name) &&
            slot.type_override.empty() && elem_size > 0 &&
            !assigned_as_scalar(slot.name)) {
            if (auto next_off = next_slot_offset(slot.offset)) {
                i64 span = *next_off - slot.offset;
                // CodeWarrior frequently leaves alignment/padding between a
                // 256-byte character buffer and the next typed local. Do not
                // turn that padding into a fictional 292-byte source array.
                if (charp && e.is_ppc_abi() && span >= 64 && span <= 4096) {
                    i64 power = 1;
                    while (power <= span / 2) power *= 2;
                    if (span - power <= 64) span = power;
                }
                if (span > 0 && static_cast<u32>(span) > elem_size &&
                    span % elem_size == 0) {
                    const u32 n = static_cast<u32>(span) / elem_size;
                    suffix = std::format("[{}]", n);
                }
            }
        }
        out += std::format("  {} {}{};\n", ty, slot.name, suffix);
    }
    return out;
}

[[nodiscard]] std::string
merge_local_declarations(const Emitter& e, const std::string& body) {
    std::string out;
    const auto first_body_use_is_assignment = [&](const std::string& name) {
        std::size_t start = 0;
        while (start <= body.size()) {
            std::size_t end = body.find('\n', start);
            if (end == std::string::npos) end = body.size();
            const std::string_view line(body.data() + start, end - start);
            if (text_contains_identifier_in_code(line, name)) {
                const std::string prefix = "  " + name + " =";
                return line.starts_with(prefix);
            }
            if (end == body.size()) break;
            start = end + 1;
        }
        return false;
    };
    for (const auto& [name, local] : e.merge_locals) {
        if (!text_contains_identifier_in_code(body, name)) continue;
        std::string type = e.c_type_name_for(local.type_value);
        if (local.initializer) {
            std::string initializer = e.expr(*local.initializer);
            if (type.ends_with('*')) {
                if (const IrInst* definition = e.def_stripped(*local.initializer);
                    definition && (definition->op == IrOp::Mul ||
                                   definition->op == IrOp::And ||
                                   definition->op == IrOp::Or ||
                                   definition->op == IrOp::Xor ||
                                   definition->op == IrOp::Shl ||
                                   definition->op == IrOp::Lshr ||
                                   definition->op == IrOp::Ashr)) {
                    type = std::string(c_type_name(local.initializer->type));
                }
            }
            if (type.ends_with('*') &&
                (e.stack_offset(*local.initializer).has_value() ||
                 (e.try_resolve_imm_addr(*local.initializer).has_value() &&
                  initializer.starts_with('&')))) {
                initializer = std::format("({}){}", type, initializer);
            }
            out += std::format("  {} {} = {};\n", type, name, initializer);
        } else {
            const bool assigned_in_body = first_body_use_is_assignment(name);
            if (e.is_ppc_abi() &&
                !e.definitely_assigned_merge_locals.contains(name) &&
                !assigned_in_body) {
                out += std::format("  {} {} = {{0}}; /* unresolved SSA merge */\n",
                                   type, name);
            } else {
                out += std::format("  {} {};\n", type, name);
            }
        }
    }
    return out;
}

// Dead-temp pass: drop `T tN = ...;` lines whose `tN` doesn't appear
// anywhere else in the output. visible_use_count can over-count when
// the sole reader folds the value through a register-assign chain.
[[nodiscard]] std::string
strip_dead_declarations(const std::string& out, const std::string& header) {
    std::vector<std::string> lines;
    {
        std::string buf;
        for (char c : out) {
            if (c == '\n') { lines.push_back(std::move(buf)); buf.clear(); }
            else { buf.push_back(c); }
        }
        if (!buf.empty()) lines.push_back(std::move(buf));
    }
    const std::string header_line = header.ends_with('\n')
        ? header.substr(0, header.size() - 1)
        : header;
    std::size_t function_header_line = lines.size();
    for (std::size_t li = 0; li < lines.size(); ++li) {
        if (lines[li] == header_line) {
            function_header_line = li;
            break;
        }
    }
    auto is_decl = [&](const std::string& line, std::string& name) {
        // File-scope synthetic record terminators also resemble a
        // two-token declaration. The caller limits this parser to lines
        // after the function header, so nested case/if declarations are
        // safe to consider as well as top-level locals.
        if (!line.starts_with("  ")) return false;
        std::size_t i = 0;
        while (i < line.size() && line[i] == ' ') ++i;
        // Type token (one word like u32, u64, bool, double).
        const std::size_t type_start = i;
        while (i < line.size() && line[i] != ' ') ++i;
        if (i == type_start || i >= line.size()) return false;
        const std::string_view type_word{
            line.data() + type_start, i - type_start};
        if (type_word == "return" || type_word == "if" ||
            type_word == "for" || type_word == "while" ||
            type_word == "switch" || type_word == "goto" ||
            type_word == "break" || type_word == "continue") {
            return false;
        }
        while (i < line.size() && line[i] == ' ') ++i;
        // Identifier token.
        const std::size_t name_start = i;
        if (i >= line.size()) return false;
        const char c0 = line[i];
        if (!(std::isalpha(static_cast<unsigned char>(c0)) || c0 == '_')) return false;
        ++i;
        while (i < line.size() && c_ident_char(line[i])) ++i;
        const std::size_t name_end = i;
        while (i < line.size() && line[i] == ' ') ++i;
        if (i < line.size() && line[i] == '[') {
            ++i;
            while (i < line.size() && line[i] != ']') ++i;
            if (i < line.size() && line[i] == ']') ++i;
            while (i < line.size() && line[i] == ' ') ++i;
        }
        if (i >= line.size() || (line[i] != '=' && line[i] != ';')) return false;
        name = line.substr(name_start, name_end - name_start);
        return true;
    };
    auto name_appears_elsewhere = [&](const std::string& name,
                                      std::size_t skip_idx) {
        const std::size_t declaration_indent =
            lines[skip_idx].find_first_not_of(' ');
        for (std::size_t li = skip_idx + 1; li < lines.size(); ++li) {
            const std::size_t indent = lines[li].find_first_not_of(' ');
            const std::string_view trimmed = trim_line_view(lines[li]);
            if (indent < declaration_indent && trimmed.starts_with('}')) break;
            if (text_contains_identifier_in_code(lines[li], name)) return true;
        }
        return false;
    };

    for (int pass = 0; pass < 4; ++pass) {
        bool changed = false;
        std::vector<std::string> kept;
        kept.reserve(lines.size());
        for (std::size_t li = 0; li < lines.size(); ++li) {
            std::string name;
            if (li > function_header_line && is_decl(lines[li], name) &&
                !name_appears_elsewhere(name, li)) {
                changed = true;
                continue;  // dead declaration
            }
            kept.push_back(std::move(lines[li]));
        }
        lines = std::move(kept);
        if (!changed) break;
    }

    std::string cleaned;
    cleaned.reserve(out.size());
    for (const auto& line : lines) {
        cleaned += line;
        cleaned += '\n';
    }
    return cleaned;
}

// Non-compilable-spelling note: subscripting through a void* is
// deliberate RE guidance here, but unlike everything else in a
// listing it will not compile as written. Say so once, above the
// function, instead of letting the reader discover it at cc time.
void prepend_untyped_pointer_note(std::string& out, const std::string& header) {
    if (const std::size_t sites = count_untyped_pointer_index_sites(out);
        sites > 0) {
        std::string note = std::format(
            "// note: {} statement{} index through untyped pointers "
            "(void*); guidance only, not valid C without record types\n",
            sites, sites == 1 ? "" : "s");
        const std::string signature = header.ends_with('\n')
            ? header.substr(0, header.size() - 1)
            : header;
        const std::size_t at = out.find(signature);
        if (at != std::string::npos) {
            out.insert(at, std::move(note) + "\n");
        }
    }
}

}  // namespace

Result<std::string> PseudoCEmitter::emit(const StructuredFunction& sf,
                                         const Binary* binary,
                                         const Annotations* annotations,
                                         EmitOptions options) const {
    if (!sf.ir) {
        return std::unexpected(Error::invalid_format(
            "pseudo-c: StructuredFunction has no IR"));
    }

    Emitter e;
    e.binary      = binary;
    e.annotations = annotations;
    e.options     = options;
    e.abi         = binary
        ? abi_for(binary->format(), binary->arch(), binary->endian())
        : Abi::SysVAmd64;

    EmitterMetadataStorage metadata;
    setup_emitter_metadata(e, sf, binary, metadata);
    const SignatureContext sig_ctx =
        setup_signature_context(e, sf, binary, annotations);
    run_analysis_passes(e, sf, sig_ctx);

    const addr_t start = sf.ir->start;
    std::string out;
    out += std::format("// {}\n", sf.ir->name.empty()
                                    ? std::string("<unknown>") : sf.ir->name);
    if (annotations && options.show_provenance) {
        out += provenance_preamble(*annotations, start);
    }

    // Build the function header: a declared signature wins outright, then
    // Objective-C metadata, then arity inference.
    const std::string name = header_display_name(e, sf, binary, annotations);
    std::string header;
    if (annotations) {
        if (const FunctionSig* sig = annotations->signature_for(start);
            sig && !is_incomplete_decomp_signature(*sig)) {
            header = header_from_signature(e, sf, *sig, name);
        }
    }
    if (header.empty()) {
        if (auto it = e.objc_by_imp.find(start);
            it != e.objc_by_imp.end() && !it->second->type_encoding.empty()) {
            header = header_from_objc_method(e, *it->second, name);
        }
    }
    if (header.empty()) {
        if (auto it = e.objc_block_by_invoke.find(start);
            it != e.objc_block_by_invoke.end() && !it->second->signature.empty()) {
            header = header_from_objc_block(e, it->second->signature, name);
        }
    }
    if (header.empty()) header = header_from_inference(e, sf, name);
    out += rtti_alias_comment(e, start);

    // Render the body into a buffer first so we can decide which
    // recovered frame slots actually appear in the output text. Some
    // Loads / Stores get hidden by the emitter (canary writes, ABI
    // shuffle stores) and don't surface a `local_<hex>` reference, so
    // a slot in the layout isn't proof of a live mention. Emitting
    // declarations only for referenced slots keeps the function head
    // tidy without leaning on the dead-decl pruner (which only
    // recognises `TYPE NAME = expr;` form).
    // Hits added to options.line_map during emit_region carry offsets
    // relative to body_buf. We snapshot the index of the first hit
    // recorded for this body so we can re-shift them once body_buf
    // gets concatenated into `out` below.
    const std::size_t lm_first_body_hit =
        options.line_map ? options.line_map->hits.size() : 0;

    std::string body_buf;
    if (sf.body) {
        e.emit_region(*sf.body, 1, body_buf);
    }
    if (sf.body && !sf.ir->blocks.empty()) {
        body_buf += structurer_fail_markers(sf, binary);
    }

    const std::set<std::string> matrix_locals = matrix_stack_locals(body_buf);
    collect_address_taken_functions(e, body_buf, binary);
    std::string declaration_context = header + body_buf;
    for (const std::string& local : matrix_locals) {
        declaration_context += std::format("\nMtx34 {};", local);
    }
    if (e.is_ppc_abi()) {
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

    const std::size_t body_offset = out.size();
    out += body_buf;
    if (options.line_map) {
        for (std::size_t i = lm_first_body_hit;
             i < options.line_map->hits.size(); ++i) {
            options.line_map->hits[i].byte_offset += body_offset;
        }
    }

    out += "}\n";

    // Text-level cleanups are skipped when a LineMap is being collected:
    // deleting lines would invalidate the byte_offset values already
    // recorded (the debugger can live with a slightly noisier function
    // listing in exchange for accurate PC-to-line mapping).
    if (!options.line_map) {
        out = strip_label_only_if_blocks(out);
        out = strip_dead_declarations(out, header);
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
    if (!sf.ir) {
        return std::unexpected(Error::invalid_format(
            "pseudo-c per-block: StructuredFunction has no IR"));
    }

    // Setup mirrors emit() - same ABI plumbing, same ObjC / RTTI lookup,
    // same per-emit signature inference. We deliberately skip the
    // body-tree walks (suppress_canary_regions / analyze_return_folds /
    // collect_for_updates) since per-block output has no structured body
    // to reason about.
    Emitter e;
    e.binary      = binary;
    e.annotations = annotations;
    e.options     = options;
    e.abi         = binary
        ? abi_for(binary->format(), binary->arch(), binary->endian())
        : Abi::SysVAmd64;

    EmitterMetadataStorage metadata;
    setup_emitter_metadata(e, sf, binary, metadata);
    const SignatureContext sig_ctx =
        setup_signature_context(e, sf, binary, annotations);
    e.analyze(*sf.ir);
    e.assign_synthetic_struct_types();
    e.infer_shared_call_return_types();
    e.name_merge_values();
    if (!sig_ctx.has_user_sig && !sig_ctx.has_metadata_sig) e.bump_arity_from_body_reads();
    if (!sig_ctx.has_user_sig && !sig_ctx.has_metadata_sig) e.bump_arity_from_merge_initializers();
    if (!sig_ctx.has_user_sig && !sig_ctx.has_metadata_sig) {
        e.infer_pointer_arg_types_from_memory_uses();
    }
    if (!sig_ctx.has_user_sig && !sig_ctx.has_metadata_sig) {
        e.infer_ppc_helper_preserved_arg_types();
    }
    e.infer_function_pointer_args();
    e.infer_call_value_arg_names();
    e.infer_ppc_role_arg_names();
    e.infer_charp_args();
    if (!sig_ctx.has_user_sig) e.promote_block_like_first_arg();
    e.bind_call_returns();

    // Output mirrors format_cfg's framing - same `bb_<addr>` headers,
    // same `<-` predecessor list, same `-> bb_xxx (label)` arrows - so
    // any consumer parsing the asm CFG view (UI, scripts) parses this
    // identically up to the body content swap.
    std::string out;
    out += std::format("// {}\n", sf.ir->name.empty()
                                    ? std::string("<unknown>") : sf.ir->name);
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
