#pragma once

// Private state and helpers of the pseudo-C emitter, shared by the
// emitter_*.cpp translation units. Nothing here is part of the public
// <ember/decompile/emitter.hpp> surface.

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <ember/decompile/emitter.hpp>
#include <ember/analysis/arity.hpp>
#include <ember/analysis/cfg_util.hpp>
#include <ember/analysis/demangle.hpp>
#include <ember/analysis/frame.hpp>
#include <ember/analysis/import_sigs.hpp>
#include <ember/analysis/name_resolver.hpp>
#include <ember/analysis/objc.hpp>
#include <ember/analysis/msvc_rtti.hpp>
#include <ember/analysis/pipeline.hpp>
#include <ember/analysis/rtti.hpp>
#include <ember/analysis/ssa_cleanup.hpp>
#include <ember/common/types.hpp>
#include <ember/common/bytes.hpp>
#include <ember/disasm/x64_decoder.hpp>
#include <ember/ir/abi.hpp>
#include <ember/ir/ssa.hpp>

#include "emitter_tables.hpp"

namespace ember::emit {

// ---- rendered-text post-processing (emitter_text.cpp) ----

[[nodiscard]] std::string_view trim_line_view(std::string_view line) noexcept;
[[nodiscard]] bool is_bb_label_line(std::string_view line) noexcept;
[[nodiscard]] bool line_semantically_empty(std::string_view line) noexcept;
[[nodiscard]] bool c_ident_char(char c) noexcept;
[[nodiscard]] bool text_contains_identifier(std::string_view text,
                                            std::string_view name) noexcept;
[[nodiscard]] bool text_contains_identifier_in_code(std::string_view text,
                                                    std::string_view name) noexcept;
[[nodiscard]] bool line_declares_identifier(std::string_view line,
                                            std::string_view name) noexcept;
[[nodiscard]] bool text_declares_identifier(std::string_view text,
                                            std::string_view name) noexcept;
[[nodiscard]] std::string replace_identifier(std::string_view text,
                                             std::string_view old_name,
                                             std::string_view new_name);
// SSA temporaries are useful internally, but `t57` carries no meaning in the
// final decompilation. Give materialized PPC values stable, type-oriented
// names. The numeric suffix is retained only when more than one value of the
// same role is simultaneously live in the rendered function.
[[nodiscard]] std::string rename_ppc_temporaries(std::string text);
[[nodiscard]] std::string fix_ppc_offset_pointer_declarations(std::string text);
// Count statements that subscript or shift-index through an untyped
// pointer. A parameter or declaration spelled `void* name` makes any
// later `name[...]` invalid C - deliberate RE guidance in a listing,
// but worth flagging since everything else around it compiles.
// Casts like `((T*)p)[i]` are already valid and never match.
[[nodiscard]] std::size_t count_untyped_pointer_index_sites(
    const std::string& text);
[[nodiscard]] std::string compact_ppc_type_names(std::string text);
[[nodiscard]] std::string collapse_ppc_field_copy_runs(const std::string& text);
[[nodiscard]] bool line_starts_empty_if(std::string_view line) noexcept;
[[nodiscard]] std::string lower_first_ascii(std::string s);
[[nodiscard]] std::string sanitize_ident(std::string_view s,
                                         std::string_view fallback);
[[nodiscard]] std::vector<std::string>
objc_selector_arg_names(std::string_view selector);
[[nodiscard]] std::string objc_block_literal_name(addr_t literal);
[[nodiscard]] std::string objc_block_invoke_name(addr_t invoke);
[[nodiscard]] std::string block_param_type(std::string_view ty);
[[nodiscard]] bool line_is_close_brace(std::string_view line) noexcept;
[[nodiscard]] bool line_is_else_open(std::string_view line) noexcept;
[[nodiscard]] std::string strip_outer_parens(std::string_view s);
[[nodiscard]] std::string invert_condition_text(std::string_view cond);
[[nodiscard]] std::optional<std::string>
inverted_if_line(std::string_view line);
[[nodiscard]] std::string collapse_empty_then_else_blocks(std::string_view text);
[[nodiscard]] std::string strip_label_only_if_blocks(std::string_view text);

// C operator precedence, scaled so "tighter binds" = higher value. Used to
// decide whether a sub-expression needs wrapping in parens. Only the handful
// of levels the emitter actually produces are enumerated; add more as new
// operator kinds start rendering.
enum class Prec : int {
    Stmt    = 0,
    Cond    = 2,    // ?: ternary
    LogOr   = 3,
    LogAnd  = 4,
    BitOr   = 5,
    BitXor  = 6,
    BitAnd  = 7,
    Eq      = 8,    // == !=
    Rel     = 9,    // < <= > >=
    Shift   = 10,   // << >>
    Add     = 11,   // + -
    Mul     = 12,   // * / %
    Unary   = 13,   // ! ~ unary- (T)x *x &x
    Postfix = 14,   // a[i] a->b a.b f(x) - binds tighter than unary
    Primary = 15,   // ident, literal
};

enum class CallReturnLane : u8 {
    Void,
    Integer,
    Floating,
};

[[nodiscard]] inline std::string
wrap_if_lt(std::string s, Prec own, int min_prec) {
    if (std::to_underlying(own) < min_prec) return "(" + std::move(s) + ")";
    return s;
}

struct Emitter {
    // Calling convention the emitted function uses. Drives which int-arg
    // register set maps to a1/a2/..., which slots are considered arg regs
    // for live-in-from-caller detection, and which registers a callee may
    // legitimately clobber. Defaults to SysV - back-compat with the
    // pre-Win64 world - and is set by the driver when the binary carries
    // a Win64 hint (PE on x86_64).
    Abi abi = Abi::SysVAmd64;
    const IrFunction*                                fn = nullptr;
    const Binary*                                    binary = nullptr;
    const Annotations*                               annotations = nullptr;
    EmitOptions                                      options{};
    // Recovered stack-frame slots, populated once at the start of emit()
    // by compute_frame_layout(). The body's existing format_mem() path
    // will name these slots `local_<hex>` / `arg_<hex>` to match the
    // declarations we emit at function entry.
    StackFrameLayout                                 frame_layout;
    // Number of recovered source arguments for the function being emitted.
    // self_arg_layout preserves mixed PPC GPR/FPR order; self_arity remains
    // the compact count used by the existing header/name passes.
    u8                                               self_arity = 0;
    std::vector<InferredArgument>                    self_arg_layout;
    std::map<SsaKey, const IrInst*>                  defs;
    std::map<SsaKey, std::pair<std::size_t, std::size_t>> def_pos;
    std::map<SsaKey, u32>                            uses;
    std::set<std::pair<std::size_t, std::size_t>>    hidden;
    // Precomputed counts populated once `hidden` and ABI-noise filters
    // have been applied. `visible_uses[k]` matches what `visible_use_count`
    // would return on demand; `flag_assign_uses[k]` counts the subset of
    // those uses that are Assign-to-Flag (the discriminator
    // `every_use_is_flag_assign` was scanning the function for). Without
    // these, those queries each O(N)-walked the IR per leaf-render, which
    // turned the emitter into O(N²) for any function with thousands of
    // instructions - the brain crackme's 160KB hand-written `main`
    // bottomed out at >2 minutes purely on those scans.
    std::map<SsaKey, u32>                            visible_uses;
    std::map<SsaKey, u32>                            flag_assign_uses;
    // (block, inst) positions of every visible use of a given key, so
    // is_flag_feeder_temp can iterate users in O(uses) instead of
    // re-walking the whole function each call.
    std::map<SsaKey, std::vector<std::pair<u32, u32>>> visible_user_positions;
    std::map<SsaKey, std::vector<std::pair<u32, u32>>> all_user_positions;
    // Loads whose value survives a possible memory mutation or leaves its
    // defining block. These must be materialized where they execute; inlining
    // them at a later use would re-read memory and can turn a real save/restore
    // into the false source statement `work->field = work->field`.
    std::set<SsaKey>                                    memory_snapshot_loads;
    // Stack-slot offsets (per stack_offset()) that have at least one Load
    // somewhere in the function. A Store to an offset NOT in this set is a
    // dead spill - common for -O0 spill-arg-to-slot prologues whose slot is
    // never reloaded - and should be suppressed by format_store.
    std::set<i64>                                    loaded_stack_slots;
    // Minimum byte extent proven by bounded library calls such as
    // memset(dst, ..., n), fgets(dst, n, ...), and fread(dst, size, count).
    // This prevents an address-only stack slot from staying a scalar when a
    // call demonstrably writes a buffer beginning there.
    mutable std::map<i64, u32>                       stack_required_extents;
    // Stack slots written exactly once in the entry block before any
    // conditional branch, where the stored value is the unmodified live-in
    // arg-register (rdi/rsi/...). Loads from these slots forward to the
    // arg name (a1, a2, ...) directly: -O0 spill-arg-then-reload becomes
    // a single use of the parameter, the way the user wrote it.
    std::map<i64, IrValue>                           init_only_slot_value;
    // Stack slots written exactly once, regardless of the value's origin.
    // Used to recognise phi merges where one path still has the just-stored
    // value and another path reloads the same slot.
    std::map<i64, IrValue>                           single_write_slot_value;
    mutable std::map<u64, std::optional<std::string>> string_cache;
    // Call sites whose return value flows straight into a Return(rax). The
    // Call statement is suppressed and its rendered expression is stashed in
    // `fold_return_expr`, keyed on the rax SSA key; the Return handler then
    // emits `return foo(args);` instead of `foo(args); return rax;`.
    std::set<std::pair<std::size_t, std::size_t>>    fold_call_positions;
    std::map<std::pair<std::size_t, std::size_t>, SsaKey> fold_call_ssa_key;
    mutable std::map<SsaKey, std::string>            fold_return_expr;
    mutable std::map<SsaKey, std::string>            fold_void_call_stmt;
    std::set<std::pair<std::size_t, std::size_t>>    inline_call_positions;
    std::map<std::pair<std::size_t, std::size_t>, SsaKey> inline_call_ssa_key;
    mutable std::map<SsaKey, std::string>            inline_call_expr;
    mutable std::map<std::string, std::string>       global_decls;
    mutable std::map<std::string, std::size_t>       ppc_navigation_tables;
    struct PpcStridedTable {
        std::string type_name;
        std::size_t stride = 0;
        std::map<i64, IrType> fields;
    };
    mutable std::map<std::string, PpcStridedTable>   ppc_strided_tables;
    mutable std::set<std::string>                    address_taken_function_decls;
    // rax/xmm0 SSA key → bound local name for Call returns whose result is
    // read downstream. Makes `fopen(...); if (rax == 0)` render as
    // `u64 r_fopen = fopen(...); if (r_fopen == 0)`.
    std::map<SsaKey, std::string>                    call_return_names;
    std::map<std::pair<std::size_t, std::size_t>, SsaKey> bound_call_key;
    // A do-while tail can also appear as a duplicated inner continue/break
    // region. Only the canonical tail spelling may consume PPC CTR.
    mutable std::set<SsaKey>                         deferred_ctr_conditions;
    mutable std::set<SsaKey>                         active_ctr_tail_conditions;
    // Direct callee address -> return type recovered from the union of its
    // call sites in this function. One dereferenced return is enough to keep
    // sibling calls from falling back to an integer ABI-width declaration.
    std::map<addr_t, std::string>                    inferred_call_return_types;
    // ARC claim helpers consume an autoreleased return purely for ownership
    // bookkeeping. When the claimed value has no real uses, render the
    // producer call as the statement and suppress the helper.
    std::set<std::pair<std::size_t, std::size_t>>    arc_claim_producer_positions;
    std::set<std::pair<std::size_t, std::size_t>>    suppressed_call_positions;
    // MSVC emits __security_check_cookie as a special epilogue helper that
    // preserves the source-level return value in RAX. Generic Win64 call
    // clobbers lose that fact, so remember the pre-cookie return lane and
    // substitute it for the synthetic post-call Clobber at Return sites.
    std::set<SsaKey>                                msvc_cookie_return_clobbers;
    std::map<SsaKey, IrValue>                       msvc_cookie_preserved_returns;
    // Bound-call positions whose binding name reuses a phi merge-value
    // name (e.g. `v0`). Such call statements skip the type prefix because
    // the merge declaration is already emitted at the function head.
    std::set<std::pair<std::size_t, std::size_t>>    merge_bound_calls;
    std::map<SsaKey, std::string>                    merge_value_names;
    std::map<std::string, SsaMergeLocal>             merge_locals;
    std::set<SsaKey>                                 structured_return_values;
    std::set<std::string>                            definitely_assigned_merge_locals;
    std::map<addr_t, std::vector<std::pair<std::string, IrValue>>>
                                                    merge_edge_assignments;
    // Block addresses referenced by some `RegionKind::Goto` in the
    // structured tree. emit_block prepends a C `bb_<addr>:` label at
    // these blocks so the gotos resolve. Without this the structurer's
    // gotos point at comments and the C is ill-formed.
    std::set<addr_t>                                 goto_targets;
    // SSA values whose C binding has already been emitted in this function
    // body. Used by the materializer to avoid exposing fallback names like
    // `rax_3` / `t17` when a structured condition or return reads a value
    // whose defining IR statement was otherwise suppressed as single-use.
    mutable std::set<SsaKey>                          emitted_bindings;

    // Try to resolve an integer immediate as a pointer to a NUL-terminated
    // printable string in the binary image. Results are cached.
    [[nodiscard]] std::optional<std::string> try_string_at(
        u64 addr, std::size_t min_printable = 2) const;

    // Cached per-target arity via infer_arity().
    mutable std::map<u64, u8> arity_cache;

    [[nodiscard]] u8 cached_arity(addr_t target) const;

    mutable std::map<u64, std::vector<InferredArgument>> argument_layout_cache;

    [[nodiscard]] const std::vector<InferredArgument>&
    cached_argument_layout(addr_t target) const;

    // Drop ELF `@GLIBC_*` / `@@GLIBC_*` version suffix that clutters import
    // names in pseudo-C (e.g. "puts@GLIBC_2.2.5" → "puts").
    [[nodiscard]] static std::string clean_import_name(std::string_view n);

    // For `call <abs_target>`: if the target is a PLT stub, return the
    // import's name. Nullopt means "render as sub_XXXX".
    [[nodiscard]] std::optional<std::string>
    import_name_for_direct_call(addr_t target) const;

    // Exact code/data address used as an immediate. This catches cases such
    // as returning a function pointer or materializing a global address, where
    // a bare 0x40xxxx obscures information the loader already knows.
    [[nodiscard]] std::optional<std::string>
    named_address_for_imm(addr_t target) const;

    // Walk Assign copies until we hit something that's plausibly the
    // address of a string (an Imm, or a Reg). For an Imm, try to read the
    // NUL-terminated string at that address.
    [[nodiscard]] std::optional<std::string>
    resolve_string_value(const IrValue& v) const;

    // Compute arity for a printf/scanf family call given its format-arg
    // index in `args`. Falls back to `format_index + 1` (emit format, drop
    // the rest) when the format isn't a literal string.
    [[nodiscard]] u8 variadic_arity(const std::vector<IrValue>& args,
                                    u8 format_index) const;

    [[nodiscard]] bool variadic_scanf_arg_is_charp(
        std::string_view name, const std::vector<IrValue>& args,
        std::size_t argument_index) const;

    [[nodiscard]] static bool is_generic_sub_name(std::string_view name) noexcept;

    [[nodiscard]] static bool is_unresolved_function_name(std::string_view name) noexcept;

    [[nodiscard]] std::optional<u8>
    printf_like_arity_from_literal_args(const std::vector<IrValue>& args) const;

    // Receiver-shape virtual-method dispatch: if the call target traces
    // as `Load(Add(Load(<recv>), K))` - load vptr from receiver, add
    // slot offset, load method pointer - render as
    // `<recv>->vfn_<K/8>`. Doesn't need IPA / receiver type info; just
    // recognises the canonical Itanium / MSVC vtable shape every C++
    // `obj->method()` compiles to. K must be a constant divisible by
    // sizeof(void*); slot 0 (`Load(Load(<recv>))`) renders as `vfn_0`.
    [[nodiscard]] std::optional<std::string>
    try_render_vfn_dispatch(const IrValue& target) const;

    // For `call.ind <expr>`: if `expr` traces back to a Load of a constant
    // address that matches a known GOT slot, return the import's name.
    [[nodiscard]] std::optional<std::string>
    import_name_for_indirect_call(const IrValue& v) const;

    // Map a declared signature parameter to a canonical argument register.
    // The register file an argument lands in depends on the ABI:
    //
    //   SysV / AAPCS64: int and FP args draw from two independent sequences
    //       (rdi,rsi,... and xmm0,xmm1,...), so each kind advances its own
    //       counter and an int arg never consumes an FP slot.
    //
    //   Win64: argument slots are positional and shared - the Nth argument
    //       occupies the Nth slot in whichever file matches its type, and
    //       an int arg still skips the matching xmm slot (and vice versa).
    //       So f(int, double, int) is rcx, xmm1, r8 - not rcx, xmm0, rdx.
    //
    // Win64 passes only 4 args in regs; the 5th+ sit on the stack and are
    // named separately via incoming_stack_arg_name().
    [[nodiscard]] static bool is_declared_fp_scalar(std::string_view type) noexcept;

    [[nodiscard]] static std::optional<u32>
    ppc_known_aggregate_size(std::string_view type) noexcept;

    [[nodiscard]] static bool
    ppc_return_uses_hidden_sret(std::string_view type) noexcept;

    [[nodiscard]] bool is_ppc_abi() const noexcept;

    [[nodiscard]] i64 ppc_parameter_area_base() const noexcept;

    [[nodiscard]] i64 ppc_parameter_word_size() const noexcept;

    [[nodiscard]] i64 ppc_advance_parameter_slot(i64& cursor,
                                                  IrType type,
                                                  u32 byte_width = 0) const noexcept;

    [[nodiscard]] const std::string*
    abi_param_for(const FunctionSig& sig, Reg r) const noexcept;

    [[nodiscard]] std::vector<InferredArgument>
    abi_layout_for(const FunctionSig& sig) const;

    [[nodiscard]] std::vector<InferredArgument>
    abi_layout_for_import(std::string_view name) const;

    // Resolve a stack offset to the name of an incoming stack-passed
    // argument, if it is one. Only meaningful for positional-slot ABIs
    // (Win64) where arguments past the register file spill to the caller's
    // stack frame above the 32-byte register home area.
    //
    // stack_offset() is entry-RSP-relative (the return address sits at 0;
    // the lifter already folds the prologue's RSP adjustment, which is why
    // locals come out negative and caller slots positive). The home/stack
    // slot for 0-based argument k therefore sits at 0x08 + k * 8:
    //   k=0..3  -> register-arg home slots (named via the register path)
    //   k>=4    -> genuine stack arguments (the 5th+ argument)
    // Returns the annotated parameter name when the signature declares that
    // slot, else a generic `aN`.
    [[nodiscard]] std::optional<std::string>
    incoming_stack_arg_name(const IrValue& addr, i64 off) const;

    // If `r` is an int-arg register for the current ABI and the current
    // function actually takes that arg (per annotations or inferred
    // arity), return the param's display name. Otherwise nullopt.
    [[nodiscard]] std::optional<std::string>
    arg_name_for_live_in(Reg r) const;

    [[nodiscard]] IrType abi_word_type() const noexcept;

    [[nodiscard]] std::string_view abi_word_c_type() const noexcept;

    // Render a Reg IrValue's leaf name. Resolution order:
    //   1. A Call-return binding for this (canonical reg, version).
    //   2. Chase Assign aliases:
    //        - reg = reg              → keep chasing
    //        - reg = non-reg          → render the rvalue expression (this is
    //          what turns `r12` into `*(u64*)((a2 + 0x8))` when the compiler
    //          stashed a computed pointer into a callee-saved reg at prologue)
    //        - version 0 + arg-reg    → parameter name
    //   3. Raw register mnemonic.
    [[nodiscard]] std::optional<IrValue>
    preserved_call_arg_for_clobber(Reg r, u32 version) const;

    // Recover the value chosen by a one-arm CFG diamond as a C conditional
    // expression.  The SSA cleanup used to name these Phis as locals without
    // emitting either edge assignment, which produced uninitialized
    // `value_N` variables in otherwise well-structured PPC output.
    [[nodiscard]] std::optional<std::string>
    render_selection_phi(const IrInst& phi, int depth) const;

    [[nodiscard]] std::string render_reg_leaf(Reg r, u32 version,
                                              int depth = 0,
                                              int min_prec = 0) const;

    // For a raw code address, pick a display name. Priority (highest first):
    //   1. User rename (from the annotations sidecar).
    //   2. Named defined function symbol from the binary itself.
    //   3. Fallback `sub_<hex>`.
    [[nodiscard]] std::string function_display_name(addr_t target) const;

    [[nodiscard]] std::string observed_targets_comment(addr_t site) const;

    [[nodiscard]] static std::string escape_string(const std::string& s);

    [[nodiscard]] bool same_value_key(const IrValue& a,
                                      const IrValue& b) const noexcept;

    [[nodiscard]] std::optional<i64>
    single_write_slot_alias_for_value(const IrValue& v) const;

    [[nodiscard]] std::optional<IrValue>
    alias_root_for_value(const IrValue& v, int depth = 0) const;

    // An arg reg is "stale" if the caller never deliberately set it before the
    // call: either it's still the function's live-in (version 0) and no user
    // signature claims it, or its most recent def is a Clobber from a prior
    // call. Both cases look like `strlen(... rsi, rdx, r8, r9)` noise.
    //
    // A live-in reg that maps to one of OUR own inferred int-arg slots
    // (i.e. the function takes that reg as a parameter) is NOT stale -
    // it's a forwarded argument. Without this guard, a wrapper like
    // `u64 wrap(u64 a1) { return add7(a1); }` decompiles to `add7()`
    // because is_stale_arg_reg treats `a1` as uninitialised live-in
    // when the caller has no annotation file pinning the signature.
    [[nodiscard]] bool is_stale_arg_reg(const IrValue& a, int depth = 0) const;

    // Arity for a known routine by name - user signature at its address beats
    // the typed built-in table, which beats the legacy name and mangling
    // fallbacks. The typed table also carries stable platform SDK prototypes.
    // The mangled-name path lets C++ stdlib calls (`std::istream::get`,
    // `std::ofstream::write`, …) size correctly without hand-maintaining
    // a table for every member function.
    [[nodiscard]] std::optional<u8>
    import_arity(addr_t plt_addr, std::string_view name) const;

    [[nodiscard]] static bool is_objc_msgsend_name(std::string_view name) noexcept;

    [[nodiscard]] static bool is_objc_super_msgsend_name(std::string_view name) noexcept;

    [[nodiscard]] static bool is_objc_stret_msgsend_name(std::string_view name) noexcept;

    [[nodiscard]] static std::optional<u8>
    objc_runtime_fixed_arity(std::string_view name) noexcept;

    [[nodiscard]] static u8 selector_argument_count(std::string_view selector) noexcept;

    [[nodiscard]] static bool objc_selector_takes_format_varargs(
        std::string_view selector) noexcept;

    [[nodiscard]] static u8 count_objc_format_specifiers(std::string_view fmt) noexcept;

    [[nodiscard]] std::optional<std::string>
    objc_selector_for_value(const IrValue& v) const;

    [[nodiscard]] std::optional<std::string>
    objc_selector_for_rendered_value(const IrValue& v) const;

    [[nodiscard]] std::optional<u8>
    objc_call_arity(std::string_view name,
                    const std::vector<IrValue>& args) const;

    [[nodiscard]] static std::string simplify_objc_class_receiver(std::string s);

    [[nodiscard]] static std::vector<std::string_view>
    objc_selector_pieces(std::string_view selector);

    [[nodiscard]] static std::string objc_stret_assignment_target(std::string s);

    [[nodiscard]] static std::string objc_address_arg_text(std::string s);

    [[nodiscard]] std::string objc_address_arg(const IrValue& v) const;

    [[nodiscard]] std::optional<std::string>
    try_render_objc_self_ivar_at_offset(const IrValue& receiver,
                                        const IrValue& offset) const;

    [[nodiscard]] static bool is_objc_property_setter_runtime(
        std::string_view name) noexcept;

    [[nodiscard]] std::optional<std::string>
    render_objc_property_runtime_call(std::string_view name,
                                      const std::vector<IrValue>& args) const;

    [[nodiscard]] std::optional<std::string>
    render_objc_address_runtime_call(std::string_view name,
                                     const std::vector<IrValue>& args) const;

    [[nodiscard]] bool objc_selector_arg_is_usable(const IrValue& v) const;

    [[nodiscard]] bool objc_selector_arg_looks_like_stack_gap(
        const IrValue& v) const;

    [[nodiscard]] static bool objc_selector_piece_likely_stack_aggregate(
        std::string_view piece) noexcept;

    [[nodiscard]] std::optional<std::string>
    render_objc_message_call(std::string_view name,
                             const std::vector<IrValue>& args) const;

    [[nodiscard]] std::optional<std::string>
    render_objc_runtime_call(std::string_view name,
                             const std::vector<IrValue>& args) const;

    [[nodiscard]] std::optional<std::string>
    objc_return_base_for_call(const IrInst& call_inst,
                              const std::vector<IrValue>& args) const;

    [[nodiscard]] std::optional<std::string>
    call_import_name(const IrInst& inst) const;

    [[nodiscard]] const FunctionSig*
    call_annotation_signature(const IrInst& inst) const noexcept;

    [[nodiscard]] const InferredSig*
    call_inferred_signature(const IrInst& inst) const noexcept;

    [[nodiscard]] bool call_has_inferred_signature(const IrInst& inst) const;

    [[nodiscard]] std::optional<std::string>
    call_known_name(const IrInst& inst) const;

    [[nodiscard]] std::optional<CallReturnLane>
    known_call_return_lane(const IrInst& inst) const;

    [[nodiscard]] Reg call_result_reg(const IrInst& inst) const;

    [[nodiscard]] std::optional<std::string>
    known_call_return_c_type(const IrInst& inst) const;

    [[nodiscard]] bool is_ppc_abi_helper_call(const IrInst& inst) const;

    [[nodiscard]] bool call_inst_returns_void(const IrInst& inst) const;

    [[nodiscard]] static bool is_call_arg_barrier(const IrInst& inst) noexcept;

    [[nodiscard]] static bool is_callee_saved(Reg r) noexcept;

    [[nodiscard]] static bool is_stack_base_reg(Reg r) noexcept;

    [[nodiscard]] static std::string normalize_c_type_alias(std::string_view t);

    [[nodiscard]] static std::optional<std::string_view>
    standard_global_type(std::string_view name) noexcept;

    [[nodiscard]] std::string global_display_name(const Symbol& symbol) const;

    void note_global_decl(const Symbol& s, std::string type_name) const;

    // Render an IPA-arena TypeRef as a C type name. Returns empty if the
    // ref is Top or no arena is supplied - caller should fall back.
    [[nodiscard]] std::string ipa_type_name(TypeRef r) const;

    // Local type inference deliberately treats conflicting Int/Ptr evidence
    // as Bottom. That is sound for the lattice, but it used to make a value
    // seeded as an ABI-width integer render as `uint32_t` even after the body
    // proved it was dereferenced. Recover the stronger presentation type from
    // visible address flow, including the register copies and constant-offset
    // arithmetic common in PPC code.
    [[nodiscard]] std::optional<std::string>
    pointer_type_from_memory_uses(const IrValue& value) const;

    // Render the C type for an SSA value, consulting Phase 2 inference
    // results in `fn->value_types`. Falls back to the bit-width-only
    // `c_type_name(IrType)` when no refined type exists, which keeps
    // every untyped value rendering exactly as before.
    [[nodiscard]] std::string c_type_name_for(const IrValue& v) const;

    [[nodiscard]] addr_t normalized_address(i64 value) const noexcept;

    void record_x86_string_intrinsic_extents(const IrInst& inst);

    void analyze_msvc_security_cookie_calls();

    void analyze(const IrFunction& f);

    [[nodiscard]] bool phi_value_feeds_step(const SsaKey& k,
                                            bool* non_unit_accum = nullptr) const;

    [[nodiscard]] bool value_flows_to_memory_address(const SsaKey& k,
                                                     std::set<SsaKey>& seen,
                                                     int depth = 0,
                                                     bool follow_assigns = false) const;

    [[nodiscard]] bool phi_value_feeds_indexing(const SsaKey& k) const;

    [[nodiscard]] SsaMergeLocalRole merge_role_for_phi(const IrInst& inst) const;

    [[nodiscard]] std::optional<IrValue>
    merge_initializer_candidate(const IrValue& op) const;

    void name_merge_values();

    void bump_arity_from_merge_initializers();

    void analyze_merge_definite_assignment();

    // Self-arg slots (a1..aN) known to flow into a libc char* parameter.
    // Populated by infer_charp_args(); consumed by the header builder.
    std::array<bool, kMaxAbiArgs> charp_arg = {};
    // Generated display names for self-arg slots when the body reveals a
    // stronger role than `aN`, e.g. a live-in register used as a function
    // pointer call target.
    std::array<std::string, kMaxAbiArgs> self_arg_names = {};
    std::array<std::string, kMaxAbiArgs> self_arg_type_names = {};
    std::array<std::optional<IrType>, kMaxAbiArgs> self_arg_type_overrides = {};
    std::array<std::optional<u8>, kMaxAbiArgs> self_funcptr_arity = {};
    std::array<std::optional<IrType>, kMaxAbiArgs> self_funcptr_return_type = {};
    std::array<std::vector<IrType>, kMaxAbiArgs> self_funcptr_arg_types = {};
    // Stack-slot offsets (per stack_offset()) whose address has been
    // observed flowing into a libc char* parameter. The local-decl
    // emitter renders these as `char <name>[N]` instead of the default
    // `u64 <name>[N/8]` recovered from access widths alone.
    mutable std::set<i64> charp_local_slots;

    // Mach-O Obj-C method table, keyed by IMP address. Populated lazily in
    // PseudoCEmitter::emit when the binary carries __objc_classlist; used
    // by function_display_name to render `-[Class sel]` for any call
    // target that matches a known IMP.
    std::map<addr_t, const ObjcMethod*> objc_by_imp;
    const ObjcMethod* current_objc_method = nullptr;
    std::map<addr_t, const ObjcIvar*> objc_ivar_by_slot;
    std::map<std::pair<std::string, u64>, const ObjcIvar*> objc_ivar_by_class_offset;
    std::map<std::pair<std::string, std::string>, const ObjcProperty*> objc_property_by_ivar;
    std::map<addr_t, const ObjcBlock*> objc_block_by_literal;
    std::map<addr_t, const ObjcBlock*> objc_block_by_invoke;
    std::map<addr_t, const ObjcStackBlockInvoke*> objc_stack_block_by_invoke;
    std::map<u64, std::string> objc_block_capture_names;
    std::string objc_block_self_class;
    bool current_return_is_void = false;

    // Mach-O __DATA,__cfstring section bounds. When set, any Imm that falls
    // inside this range is decoded as a Core Foundation string literal via
    // the standard 32-byte CFString-in-cfstring layout.
    addr_t cfstring_lo = 0;
    addr_t cfstring_hi = 0;

    static void append_utf8(std::string& out, u32 cp);

    [[nodiscard]] std::optional<std::string>
    try_decode_cfstring(u64 addr) const;

    // For-loop update-instruction positions, pulled from every RegionKind::For
    // in the structured body. emit_block skips these so the increment doesn't
    // double-render: once in the body, once in the for-header. Keyed by
    // (block_index, inst_index) to match the `hidden` bookkeeping.
    std::set<std::pair<std::size_t, std::size_t>> for_update_positions;

    // Walk the structured body, populate for_update_positions.
    // Only suppress the body inst if render_update_inst would actually emit
    // it in the for-header - otherwise the For→While fallback in
    // emit_region_for would silently drop the update from the output.
    void collect_for_updates(const Region& r);

    // Collect every block targeted by a `RegionKind::Goto` so emit_block
    // can prepend a matching `bb_<addr>:` C label. Without this the
    // structurer's `goto bb_<addr>;` references resolve to nothing -
    // there's no destination, just a `// bb_<addr>` comment.
    void collect_goto_targets(const Region& r);

    // Render a single instruction at (block_addr, inst_idx) as its compound-
    // assign form - e.g. `i++`, `i += 2`, `x <<= 1`. Used for the update
    // clause of a for-loop. Returns empty on no-match; caller falls back to
    // suppressing the For and emitting as a While.
    [[nodiscard]] std::string
    render_update_inst(addr_t block_addr, u32 inst_idx,
                       u32* resolved_inst = nullptr) const;

    // Trace `v` back through Assign copies and trivial phis to a version-0
    // register in the current mixed argument layout. Returns the source-level
    // slot, not the register-bank index.
    [[nodiscard]] std::optional<u8>
    trace_to_self_arg_slot(const IrValue& v, int depth = 0) const;

    [[nodiscard]] const Symbol*
    global_object_for_load(const IrValue& v) const;

    [[nodiscard]] std::optional<addr_t>
    constant_fnptr_slot_for_call_target(const IrValue& v) const;

    [[nodiscard]] IrType call_arg_display_type(const IrValue& v) const;

    void record_funcptr_arg_types(u8 slot, const std::vector<IrValue>& args,
                                  u8 arity);

    void record_self_arg_type(u8 slot, IrType type);

    void record_funcptr_return_type(u8 slot, IrType type);

    // For each call-to-libc in the body, consult the call.args.* packing
    // to recover per-arg IrValues; if an arg is a self live-in reg and the
    // callee takes a `char*` at that position, tag the caller's own slot.
    void infer_charp_args();

    void infer_typed_stack_slots_from_calls();

    void infer_import_pointer_stack_values();

    void infer_function_pointer_args();

    [[nodiscard]] std::optional<u8>
    known_call_arity_for_arg_names(const IrInst& inst,
                                   const std::vector<IrValue>& args) const;

    void infer_call_value_arg_names();

    // Raise self_arity when the body reads a live-in argument register
    // that the inferred arity didn't cover. Without this, raw register
    // names leak into the emitted C as e.g. `fputs(rdx, stdout)`. Call
    // only when the caller hasn't pinned an explicit signature.
    void bump_arity_from_body_reads();

    void bump_arity_from_call_sites();

    // If an unannotated live-in argument is only ever consumed through the
    // same truncation, surface that in the header. This turns common
    // compiler shapes like `trunc i32 rdi; test eax,eax` into `u32 a1`
    // rather than keeping a `u64 a1` header and sprinkling `(u32)a1`
    // through every condition/return. We deliberately require every visible
    // use to be a Trunc to the same width; a single direct 64-bit use means
    // the wider type is intentional and the cast should stay in the body.
    void infer_narrow_arg_types_from_uses();

    // A live-in used as a load/store base is pointer-shaped even when local
    // type inference cannot propagate the pointee type backwards through a
    // register copy plus offset arithmetic. This is common in PPC prologues:
    // r3 is copied into r31, then every field access is based on r31. Keep the
    // inferred type deliberately opaque because mixed-width field accesses
    // describe a struct, not an array of whichever width happened to appear
    // first.
    void infer_pointer_arg_types_from_memory_uses();

    void infer_synthetic_self_arg_types();

    // Metrowerks emits calls to _savegpr_N/_savefpr_N before it copies
    // incoming parameters into callee-saved registers. SSA correctly models
    // an ordinary call as clobbering r3-r10, but these compiler helpers are
    // special: they preserve those registers. Carry any refined type learned
    // on the post-helper SSA value (most importantly pointer evidence from a
    // later load/store) back to the source-level parameter.
    void infer_ppc_helper_preserved_arg_types();

    // Give unannotated PPC parameters a conservative source-level role.
    // These names intentionally describe evidence visible in the current
    // function rather than guessing game-specific nouns: pointer-shaped
    // memory bases become `state`, pass-through pointers become `context`,
    // and bit-mask inputs become `flags`.
    void infer_ppc_role_arg_names();

    [[nodiscard]] bool is_void_call_result(const IrValue& v) const;

    [[nodiscard]] bool is_unbound_clobber_result(const IrValue& v) const;

    [[nodiscard]] bool is_msvc_cookie_return_clobber(const IrValue& value) const;

    [[nodiscard]] std::optional<IrValue>
    return_value_before_msvc_cookie(const IrValue& value) const;

    // Once x86 calls model their real XMM clobber set, a shared epilogue can
    // acquire an XMM0 Phi made entirely from call-clobber values and the
    // incoming register. That is ABI transport state, not evidence that an
    // ordinary integer/void function returns a vector or double. Preserve a
    // directly returned live-in FP argument, but reject merge webs containing
    // no actual FP computation/load/constant.
    [[nodiscard]] bool is_incidental_x86_fp_return(const IrValue& value) const;

    // PPC has no distinct `return void` instruction: blr simply leaves
    // whatever happens to be in r3. At a shared epilogue SSA therefore
    // creates a return-register Phi even for a void callback. Two narrow
    // patterns are strong enough to suppress that incidental ABI state:
    //
    //   * a large merge of the entry r3 and several call clobbers; or
    //   * a small merge of an unbound clobber/live-in with explicit values
    //     that are already consumed by real side effects (usually a store).
    //
    // A normal `return cond ? a1 : callee()` has no side-effect use for its
    // explicit return operand and remains value-returning.
    [[nodiscard]] bool has_incidental_ppc_return_merge() const;

    // Optimized PPC void initializers commonly leave the last replicated
    // store value in r3/f1 when they reach `blr`. When the exact returned SSA
    // value was written to two or more object fields, that register is an
    // implementation leftover rather than a credible source-level return.
    // Requiring replicated stores avoids changing ordinary set-and-return
    // helpers that intentionally write and return one value.
    [[nodiscard]] bool has_incidental_ppc_stored_return() const;

    // Find Return regions whose value is the ABI integer return register
    // coming directly from a call's Clobber - record the Call position and
    // the SSA key so emit_block
    // suppresses the statement and the Return handler folds the expression.
    void analyze_return_folds(const Region& r);

    void collect_structured_return_values(const Region& region);

    void analyze_return_expr_call_folds(const Region& r);

    // For each Call with a downstream-used ABI return value, pick a display
    // name and record (call position → return SsaKey). `analyze_return_folds` must
    // run first so calls whose return folds straight into a Return are
    // skipped here.
    void bind_call_returns();

    void infer_shared_call_return_types();

    [[nodiscard]] u32 use_count_by_key(const SsaKey& k) const;

    [[nodiscard]] u32 count_uses_with_call_args(const SsaKey& k) const;

    [[nodiscard]] std::optional<std::pair<std::size_t, std::size_t>>
    call_position_for_return_key(const SsaKey& k) const;

    void analyze_arc_claim_folds();

    [[nodiscard]] std::optional<u8>
    self_funcptr_slot_for_call_pos(std::pair<std::size_t, std::size_t> pos) const;

    [[nodiscard]] std::optional<IrType>
    narrowed_call_return_type_in_expr(const IrValue& v,
                                      const SsaKey& ret_key,
                                      int depth = 0) const;

    [[nodiscard]] std::optional<SsaKey>
    single_call_return_key_in_expr(const IrValue& v, int depth = 0) const;

    // A short identifier derived from the callee's display name, sanitized
    // to valid C identifier chars. For C++ qualified names like
    // `std::istream::get` we keep only the last `::`-segment so the binding
    // reads as `r_get` instead of `r_stdistreamget` - the qualified prefix
    // is already visible at the call site.
    [[nodiscard]] std::string callee_display_short(const IrInst& call_inst) const;

    // Detect prologue/epilogue noise: saves/restores of callee-saved regs, rsp/rbp
    // frame manipulation, plus any temps whose uses are entirely within hidden insts.
    void analyze_abi_noise();

    [[nodiscard]] bool is_stack_chk_guard_got_load(const IrInst& inst) const;

    [[nodiscard]] bool is_canary_load(const IrInst& inst) const;

    [[nodiscard]] bool is_canary_value_load(const IrInst& inst) const;

    // Walk Assigns back to a real producer and return its def (or null).
    [[nodiscard]] const IrInst* def_through_assigns(const IrValue& v) const;

    [[nodiscard]] bool traces_to_canary_load(const IrValue& v) const;

    [[nodiscard]] bool renders_stack_chk_guard_load(const IrInst& inst) const;

    [[nodiscard]] bool renders_stack_chk_guard_value(const IrValue& v) const;

    [[nodiscard]] bool is_abi_noise(const IrInst& inst) const;

    // The canary check is a compare/sub/xor whose operands are:
    //   - a Load from fs:[0x28]  AND
    //   - a Load from a stack slot (the saved cookie).
    [[nodiscard]] bool is_canary_compare_inst(const IrInst& inst) const;

    // Chase a branch condition back until we hit a Sub/Xor/CmpEq/CmpNe between
    // the canary cookie and fs:[0x28]. Handles the typical `zf = cmp.eq(x,0)`
    // followed by `not` wrapper that x86 condition codes produce.
    [[nodiscard]] bool is_canary_condition(const IrValue& cond) const;

    [[nodiscard]] bool region_calls_stack_chk_fail(const Region& r) const;

    // Rewrite If/IfElse regions whose condition is a canary check: replace the
    // region with its non-fail branch so the canary guard vanishes entirely.
    void suppress_canary_regions(Region& r) const;

    [[nodiscard]] bool return_matches(const Region& r,
                                      const IrValue& value) const noexcept;

    [[nodiscard]] bool always_returns_value(const Region& r,
                                            const IrValue& value) const noexcept;

    void strip_matching_tail_returns(Region& r, const IrValue& value) const;

    void fold_common_tail_returns(Region& r) const;

    [[nodiscard]] const IrInst* def_of(const IrValue& v) const;

    [[nodiscard]] u32 use_count(const IrValue& v) const;

    // Uses that actually survive into emitted output: skip hidden insts
    // (ABI noise), call.args barriers, AND phi instructions (phis aren't
    // emitted as statements, so their operand reads don't count toward
    // whether we need to materialize a local). A temp with visible_use_count
    // <= 1 can be inlined / its declaration dropped.
    [[nodiscard]] u32 visible_use_count(const IrValue& v) const;

    [[nodiscard]] static bool inlinable_op(IrOp op) noexcept;

    // Every visible use of `v` is the source of an Assign-to-Flag.
    // Used to detect the trailing layer of a flag-set fan-out: the cmp result
    // (cmp.eq, cmp.slt, etc.) typically feeds straight into `assign zf, …`
    // and `assign sf, …`, never into general dataflow.
    [[nodiscard]] bool every_use_is_flag_assign(const IrValue& v) const;

    // The cmp result (`a - b` from a `cmp` lifted as Sub) typically has
    // multiple uses - one per flag-set computation (zf and sf each take it
    // as srcs[0] of cmp.eq / cmp.slt). Each of *those* temps then flows into
    // exactly one Assign-to-Flag. The reader doesn't want to see the explicit
    // `s64 t8 = a - b;` declaration when it's only there to feed flag math
    // that itself dissolves into an inline jcc/setcc/cmov predicate.
    [[nodiscard]] bool is_flag_feeder_temp(const IrValue& v) const;

    [[nodiscard]] bool should_inline(const IrValue& v) const;

    [[nodiscard]] std::optional<std::string> fallback_ssa_name(const IrValue& v) const;

    void mark_binding_emitted(const IrValue& v) const;

    [[nodiscard]] bool renders_raw_arch_reg_name(const IrValue& v) const;

    [[nodiscard]] std::optional<std::string>
    merge_assignment_name_for(const IrInst& inst) const;

    [[nodiscard]] std::string
    format_merge_assignment(const IrInst& inst, std::string_view name) const;

    void emit_materializations_for_value(const IrValue& v,
                                         int depth,
                                         std::string& out,
                                         std::string_view ind) const;

    void emit_materializations_for_inst(const IrInst& inst,
                                        std::string& out,
                                        std::string_view ind) const;

    void emit_raw_temp_binding(u32 temp, std::string& out,
                               std::string_view ind) const;

    void emit_materializations_for_raw_temps(std::string_view rendered,
                                             std::string& out,
                                             std::string_view ind) const;

    void emit_materializations_for_rendered_value(const IrValue& v,
                                                  std::string_view rendered,
                                                  std::string& out,
                                                  std::string_view ind) const;

    // Trace a PPC stack address back to the entry value of r1. Unlike
    // stack_offset(), this follows versioned r1 assignments through `stwu`
    // so a callee load at current-r1 + frame-size + 0x28 resolves to the
    // ABI's entry-r1 + 0x28 overflow slot.
    [[nodiscard]] std::optional<i64>
    entry_stack_offset(const IrValue& v, int depth = 0) const;

    // Trace a value back through Add/Sub/Assign chains to see if it's stack-relative.
    [[nodiscard]] std::optional<i64> stack_offset(const IrValue& v, int depth = 0) const;

    [[nodiscard]] static std::string stack_name(i64 off);

    [[nodiscard]] std::string format_imm(const IrValue& v) const;

    [[nodiscard]] std::string format_numeric_imm(const IrValue& v) const;

    [[nodiscard]] std::string format_imm_impl(const IrValue& v,
                                              bool allow_string_literals) const;

    // Hard depth cap for recursive expression expansion. The emitter
    // inlines SSA defs during render - a long def-use chain without a
    // cap recurses until the stack (or kernel OOM-killer) stops it.
    // Deep PPC address/rotate idioms can legitimately need many hops; the
    // remaining cap still prevents cyclic or pathological expansion.
    static constexpr int kMaxExprDepth = 24;

    [[nodiscard]] std::string expr(const IrValue& v, int depth = 0,
                                   int min_prec = 0) const;
    [[nodiscard]] std::string expand(const IrInst& d, int depth,
                                     int min_prec = 0) const;
    [[nodiscard]] std::string format_load_rhs(const IrInst& d,
                                              int depth = 0,
                                              int min_prec = 0) const;
    [[nodiscard]] std::optional<std::string>
    try_render_ppc_int_to_float(const IrInst& subtraction,
                                int depth = 0) const;

    // Try to resolve an address IrValue to a concrete immediate address,
    // drilling through single-assign copies. Returns nullopt for any
    // non-constant address.
    [[nodiscard]] std::optional<i64>
    try_resolve_imm_addr(const IrValue& v, int depth = 0) const;

    // If `addr` resolves to an absolute address inside a named global
    // object, render the access in terms of that symbol's name. Covers
    // exact-match (→ `name`), symbol-start cast mismatch (→ `*(T*)&name`),
    // and offsets (→ `*(T*)(&name + off)`). Returns nullopt when no global
    // matches.
    [[nodiscard]] std::optional<std::string>
    render_global_mem(const IrValue& addr, IrType t) const;

    // Chase Assigns/Imm to resolve a value to a constant integer, if one exists.
    [[nodiscard]] std::optional<i64> resolve_imm(const IrValue& v) const;

    // For an address value, decompose into (base, offset) where base is a
    // Reg or Temp and offset is a signed immediate. If the address is just a
    // bare base, offset is 0. Returns nullopt on anything we can't flatten.
    [[nodiscard]] std::optional<std::pair<IrValue, i64>>
    try_base_plus_offset(const IrValue& addr) const;

    // Collected during analyze(): for each pointer-like SSA value, the set of
    // distinct offsets at which loads/stores occurred. When a base has >=2
    // distinct offsets we treat it as a struct pointer and render accesses
    // as `base->field_<offset>` instead of `*(T*)(base + off)`.
    std::map<SsaKey, std::set<i64>> struct_offsets;
    std::map<SsaKey, std::map<i64, std::set<unsigned>>> struct_access_widths;
    std::map<SsaKey, std::map<i64, std::set<IrType>>> struct_access_types;
    std::map<SsaKey, IrValue> struct_root_values;
    std::map<SsaKey, std::string> struct_type_names;
    std::map<std::string, std::map<i64, std::set<IrType>>> struct_type_members;
    std::map<std::string, std::map<i64, std::string>> struct_member_type_names;

    void assign_synthetic_struct_types();

    void refine_synthetic_member_types_from_stores();

    [[nodiscard]] std::optional<std::string>
    synthetic_member_type(const IrValue& base, i64 offset) const;

    [[nodiscard]] std::string
    synthetic_member_name(std::string_view struct_name, i64 offset,
                          IrType storage_type) const;

    [[nodiscard]] std::string
    synthetic_member_name(const IrValue& base, i64 offset,
                          IrType storage_type) const;

    [[nodiscard]] std::string
    synthetic_struct_declarations(std::string_view rendered_function) const;

    [[nodiscard]] std::string
    imported_record_declarations(std::string_view rendered_function) const;

    // Collapse copies and chains of constant pointer adjustments to one
    // structure root. PPC commonly keeps the same work object in several
    // nonvolatile GPRs; without canonicalization each alias sees only one
    // member and none of them accumulate enough evidence for a record shape.
    [[nodiscard]] std::optional<std::pair<IrValue, i64>>
    canonical_struct_access(const IrValue& addr) const;

    [[nodiscard]] std::string fallback_field_name(i64 off, IrType t) const;

    [[nodiscard]] bool is_struct_pointer(const IrValue& base) const;

    [[nodiscard]] bool is_strong_struct_pointer(const IrValue& base) const;

    [[nodiscard]] const std::string*
    annotated_field_name(const IrValue& base, i64 off) const;

    [[nodiscard]] static std::string imported_record_base(std::string type);

    [[nodiscard]] static std::optional<std::string>
    imported_field_expression(const ImportedRecordLayout& record, i64 offset);

    [[nodiscard]] std::optional<std::string>
    imported_field_expression_typed(const ImportedRecordLayout& record,
                                    i64 offset, IrType access_type) const;

    [[nodiscard]] std::optional<std::size_t>
    pointer_pointee_size(const IrValue& pointer) const;

    [[nodiscard]] bool pointer_step_matches(const IrValue& pointer,
                                            i64 byte_step) const;

    [[nodiscard]] std::optional<std::string>
    imported_stack_field(i64 offset, IrType access_type) const;

    // Header types attached to pointer-valued globals need to survive the
    // load of the pointer slot.  This is what turns `*(u32*)(gp + 0x44)` into
    // `gp->mapName` and avoids the array heuristic inventing `gp[17]`.
    [[nodiscard]] std::optional<std::string>
    imported_global_pointer_field(const IrValue& base, i64 off,
                                  std::optional<IrType> access_type = std::nullopt) const;

    [[nodiscard]] std::optional<std::string>
    imported_global_object_field(const IrValue& base, i64 off,
                                 std::optional<IrType> access_type = std::nullopt) const;

    [[nodiscard]] std::optional<std::string>
    imported_call_result_field(const IrValue& base, i64 off, int depth,
                               std::optional<IrType> access_type = std::nullopt) const;

    [[nodiscard]] std::optional<std::string>
    imported_typed_pointer_field(const IrValue& base, i64 off, int depth,
                                 std::optional<IrType> access_type = std::nullopt) const;

    [[nodiscard]] std::optional<std::string>
    imported_enum_value(const IrValue& value, std::string type) const;

    [[nodiscard]] static bool objc_ivar_name_is_safe(std::string_view s) noexcept;

    [[nodiscard]] std::optional<addr_t>
    objc_ivar_slot_loaded_by(const IrValue& v) const;

    struct ObjcReceiverContext {
        std::string cls;
        std::string display;
    };

    [[nodiscard]] std::optional<u64>
    objc_block_capture_index_loaded_by(const IrValue& v) const;

    [[nodiscard]] std::optional<ObjcReceiverContext>
    objc_receiver_context(const IrValue& receiver, int depth = 0) const;

    [[nodiscard]] std::string objc_ivar_display_name(const ObjcIvar& iv) const;

    [[nodiscard]] std::optional<std::string>
    try_render_objc_ivar_addr_pair(const IrValue& maybe_self,
                                   const IrValue& maybe_slot) const;

    [[nodiscard]] std::optional<std::string>
    try_render_objc_ivar_access(const IrValue& addr, int depth = 0) const;

    // Three-pointer-at-{0,8,16} pattern matches every flavour of
    // std::vector<T> on x86_64 - libstdc++ (`_M_start / _M_finish /
    // _M_end_of_storage`), libc++ (`__begin_ / __end_ / __end_cap_`),
    // and MSVC STL (`_Myfirst / _Mylast / _Myend`) all lay them out
    // at the same offsets. Any other 24-byte three-pointer struct
    // renders the same way, which is fine - these names read better
    // than `field_0 / field_8 / field_10` for *any* struct shaped
    // like a contiguous container.
    [[nodiscard]] bool looks_like_vector(const IrValue& base) const;

    [[nodiscard]] bool looks_like_objc_block_capture_base(const IrValue& base) const;

    [[nodiscard]] std::optional<std::string>
    try_render_objc_block_capture_access(const IrValue& addr, IrType t,
                                         int depth = 0) const;

    [[nodiscard]] bool first_arg_has_block_capture_accesses() const;

    void promote_block_like_first_arg();

    [[nodiscard]] static std::optional<std::string>
    objc_class_from_bracket_name(std::string_view s);

    [[nodiscard]] std::optional<std::string>
    objc_class_from_block_literal_captures(addr_t literal, u64 size) const;

    [[nodiscard]] std::optional<std::string>
    objc_class_from_block_function_name() const;

    void infer_objc_block_capture_names();

    void record_struct_access(const IrValue& addr, IrType t);

    // Pointer-indexing fold: `*(T*)(base + stride*N)` renders as `base[N]`
    // when base isn't stack- or global-relative. The stride must equal the
    // load width (so `*(u32*)(p + 4*N)` → `p[N]`); other strides keep their
    // explicit `*(T*)(addr)` form so the reader sees the actual byte arithmetic.
    // Negative offsets are accepted - backward array walks are common in
    // string scanners and trailing-byte readers, and `p[-1]` reads better
    // than `*(T*)(p - 8)`.
    [[nodiscard]] std::optional<std::string>
    try_render_array_index(const IrValue& addr, IrType t, int depth = 0,
                           std::string_view loaded_type = {}) const;

    // Runtime-indexed array form: `*(T*)(base + idx * stride)` and the
    // shift-encoded `*(T*)(base + (idx << k))` (compilers emit
    // `idx << 3` for stride-8 access). Renders as `base[idx]` when
    // the scale factor matches the access width - the same property
    // try_render_array_index uses for the constant-index case.
    // Foundation for STL-container recognition: `*(*v + i*4)` becomes
    // `(*v)[i]` once the inner deref is rendered cleanly.
    [[nodiscard]] std::optional<std::string>
    try_render_runtime_array_index(const IrValue& addr, IrType t,
                                    int depth = 0) const;

    struct PpcScaledIndex {
        IrValue index;
        i64 scale = 0;
    };

    // CodeWarrior commonly spells a byte offset as rlwinm rather than a
    // literal shift. For the bounded index forms used in C array access,
    // `rotl32(x, k) & (~0u << k)` is exactly `x << k`: the wrapped bits are
    // discarded by the mask. Keep this matcher on the IR, before C pointer
    // scaling can accidentally turn a byte count into a count of records.
    [[nodiscard]] std::optional<PpcScaledIndex>
    match_ppc_scaled_index(const IrValue& value) const;

    struct ImportedPointerRecord {
        IrValue base;
        std::string expression;
        std::string type_name;
        const ImportedRecordLayout* layout = nullptr;
    };

    [[nodiscard]] std::optional<ImportedPointerRecord>
    imported_pointer_record(const IrValue& value, int depth) const;

    // Recover both important indexed-record shapes before generic pointer
    // rendering:
    //   base + i*sizeof(Record) + field -> base[i].field
    //   object + i*sizeof(T) + array_off -> object->array[i]
    // The second form is what turns PluswinWork + (button << 2) + 4 into
    // `work->entryIds[button]` instead of scaling by sizeof(PluswinWork).
    [[nodiscard]] std::optional<std::string>
    try_render_imported_indexed_field(const IrValue& addr, IrType access_type,
                                      int depth) const;

    [[nodiscard]] std::optional<std::string>
    try_render_ppc_strided_table_access(const IrValue& addr, IrType access_type,
                                        int depth) const;

    [[nodiscard]] std::optional<std::string>
    try_render_ppc_strided_table_address(const IrValue& addr, int depth) const;

    [[nodiscard]] std::optional<std::string>
    try_render_ppc_navigation_table_access(const IrValue& addr, IrType access_type,
                                           int depth) const;

    [[nodiscard]] std::optional<std::string>
    try_render_ppc_navigation_table_address(const IrValue& addr, int depth) const;

    [[nodiscard]] std::string format_mem(const IrValue& addr, IrType t, Reg seg,
                                          int depth = 0,
                                          std::string_view loaded_type = {}) const;

    [[nodiscard]] std::string format_binop(const IrInst& d, std::string_view op,
                                            int depth, int min_prec,
                                            Prec self_prec,
                                            bool commutative) const;

    // Bitwise &/|/^ rendering with mask-friendly imm handling:
    // negative power-of-2 boundary values render as `~0xN` (the
    // C-natural mask form) instead of `-0x{N+1}`, which is opaque
    // in a bitwise context. Always commutative - both operands
    // share the binop's precedence.
    [[nodiscard]] std::string format_bitop(const IrInst& d, std::string_view op,
                                            int depth, int min_prec,
                                            Prec self_prec) const;

    [[nodiscard]] std::string format_stmt(const IrInst& inst) const;
    [[nodiscard]] std::string format_store(const IrInst& inst) const;
    [[nodiscard]] std::string try_compound_store(std::string_view lhs_text,
                                                 const IrValue& addr,
                                                 const IrValue& val) const;

    void emit_region(const Region& r, int depth, std::string& out) const;
    void emit_region_if_then  (const Region& r, int depth, std::string& out) const;
    void emit_region_if_else  (const Region& r, int depth, std::string& out) const;

    // True when every code path through `r` ends in an explicit terminator
    // (Return / Break / Continue / Unreachable / Goto), so anything emitted
    // *after* `r` at the same scope is unreachable. The IfElse early-return
    // collapse uses this to drop the `else` wrapper when the then arm
    // always exits.
    [[nodiscard]] static bool region_always_exits(const Region& r) noexcept;

    [[nodiscard]] static bool rendered_region_empty(std::string_view s) noexcept;
    void emit_region_while    (const Region& r, int depth, std::string& out) const;
    void emit_region_do_while (const Region& r, int depth, std::string& out) const;
    void emit_region_for      (const Region& r, int depth, std::string& out) const;
    void emit_region_return   (const Region& r, int depth, std::string& out) const;
    void emit_region_switch   (const Region& r, int depth, std::string& out) const;

    // Call rendering inside emit_block (emitter_block.cpp).
    struct CallArgPack {
        std::vector<IrValue> ints;   // call.args.N packs, in order
        std::vector<IrValue> fps;    // call.fp_args.N packs
        bool have_pending = false;
        void clear() { ints.clear(); fps.clear(); have_pending = false; }
    };
    struct PpcOutgoingStackArgs {
        // call inst index -> parameter-area offset -> stored value
        std::map<std::size_t, std::map<i64, IrValue>> by_call;
        std::set<std::size_t> stores;   // inst indices of the paired stores
    };
    struct RenderedCall {
        std::string          expr;
        std::vector<IrValue> used_args;
    };
    struct DirectCallArity {
        std::optional<u8> arity;
        bool              objc_sized = false;
    };
    [[nodiscard]] PpcOutgoingStackArgs
    collect_ppc_outgoing_stack_args(const IrBlock& bb) const;
    [[nodiscard]] std::vector<IrValue>
    args_for_layout(const std::vector<InferredArgument>& layout,
                    std::size_t call_index, const CallArgPack& pack,
                    const PpcOutgoingStackArgs& ppc_args,
                    std::vector<std::string>* rendered = nullptr) const;
    [[nodiscard]] std::string
    format_call_args_fallback(const std::vector<IrValue>& args,
                              std::vector<IrValue>* used = nullptr) const;
    [[nodiscard]] std::string
    fallback_call_arg_types(const std::vector<IrValue>& args) const;
    [[nodiscard]] std::string
    format_call_args_with_arity(const std::vector<IrValue>& args, u8 arity,
                                bool trim_raw_arch_regs = true,
                                std::vector<IrValue>* used = nullptr,
                                const std::vector<std::string>* rendered = nullptr) const;
    void refine_rendered_call_args(const std::string& direct_name,
                                   const FunctionSig* annotated_sig,
                                   const std::vector<IrValue>& call_args,
                                   std::vector<std::string>& rendered_call_args) const;
    [[nodiscard]] DirectCallArity
    direct_call_arity(const IrInst& inst,
                      const std::optional<std::string>& import_name,
                      const std::string& direct_name,
                      const std::vector<IrValue>& call_args,
                      const FunctionSig* annotated_sig) const;
    void note_buffer_extents(std::string_view callee,
                             const std::vector<IrValue>& used_args) const;
    [[nodiscard]] std::optional<std::string>
    memset_aggregate_args(std::string_view callee,
                          const std::vector<IrValue>& used_args) const;
    [[nodiscard]] std::string
    ppc_unresolved_signature_comment(const IrInst& inst,
                                     const std::vector<IrValue>& used_args) const;
    [[nodiscard]] RenderedCall
    render_direct_call(const IrInst& inst, std::size_t call_index,
                       const CallArgPack& pack,
                       const PpcOutgoingStackArgs& ppc_args) const;
    [[nodiscard]] RenderedCall
    render_indirect_call(const IrInst& inst, std::size_t call_index,
                         const CallArgPack& pack,
                         const PpcOutgoingStackArgs& ppc_args) const;
    void emit_merge_edge_assignments(addr_t block_start, std::string_view ind,
                                     std::string& out) const;
    void emit_block(addr_t block_addr, int depth, std::string& out) const;
    // Render the binding tail for a call statement. Three modes,
    // selected by what other passes recorded against this call's
    // (block, inst) position:
    //   fold-fixed: result is consumed by exactly one downstream use;
    //               cache `call_expr` for inline substitution there.
    //   bound:      result is referenced multiple times; emit a
    //               `T r_NAME = call_expr;` declaration.
    //   bare:       result is unused; emit `call_expr;` as a statement.
    void emit_call_binding(std::string& out, std::string_view ind,
                           std::pair<std::size_t, std::size_t> pos,
                           const std::string& call_expr,
                           bool result_is_void) const;
    // Renders the trailing summary line for a block when its kind
    // implies one - the conditional / switch test, the return value,
    // or an explicit `goto *...` for indirect jumps. Plain
    // unconditional / fallthrough blocks emit nothing here; their
    // successor edge is enough for the consumer.
    void emit_block_terminator(const IrBlock& bb, int depth, std::string& out) const;

    // ===== Flag-pattern simplification =====
    // Maps compiler idioms from CMP/SUB + Jcc into direct C compare expressions.
    //   zf from sub(a,b)            → a == b
    //   !zf                         → a != b
    //   cf from sub(a,b)            → a < b   (unsigned)
    //   !cf                         → a >= b  (unsigned)
    //   cf | zf                     → a <= b  (unsigned)
    //   !zf & !cf                   → a > b   (unsigned)
    //   sf ^ of (same sub)          → a < b   (signed)
    //   !(sf ^ of)                  → a >= b  (signed)
    //   zf | (sf ^ of)              → a <= b  (signed)
    //   !zf & !(sf ^ of)            → a > b   (signed)
    struct SubOps { IrValue a; IrValue b; };

    [[nodiscard]] const IrInst* def_stripped(const IrValue& v) const noexcept;

    [[nodiscard]] bool same_ssa(const IrValue& a, const IrValue& b) const noexcept;

    [[nodiscard]] std::optional<SubOps> match_sub_result(const IrValue& v) const;

    [[nodiscard]] std::optional<SubOps> match_zf(const IrValue& v) const;

    [[nodiscard]] std::optional<SubOps> match_sf(const IrValue& v) const;

    [[nodiscard]] std::optional<SubOps> match_cf(const IrValue& v) const;

    [[nodiscard]] std::optional<SubOps> match_of(const IrValue& v) const;

    [[nodiscard]] bool same_ops(const SubOps& x, const SubOps& y) const;

    [[nodiscard]] std::optional<SubOps> match_sf_xor_of(const IrValue& v) const;

    [[nodiscard]] std::optional<SubOps> match_or_cf_zf(const IrValue& v) const;

    [[nodiscard]] std::optional<SubOps> match_or_zf_sfxorof(const IrValue& v) const;

    // Matches Not(v) and returns the inner operand (via def chain).
    [[nodiscard]] const IrInst* match_not(const IrValue& v) const;

    [[nodiscard]] std::optional<SubOps> match_and_notzf_notcf(const IrValue& v) const;

    [[nodiscard]] std::optional<SubOps> match_and_notzf_not_sfxorof(const IrValue& v) const;

    [[nodiscard]] std::optional<IrValue> match_eq_zero_value(const IrValue& v) const;

    [[nodiscard]] std::optional<IrValue> match_slt_zero_value(const IrValue& v) const;

    [[nodiscard]] std::optional<IrValue> match_or_eq_zero_slt_zero(const IrValue& v) const;

    [[nodiscard]] std::optional<IrValue>
    match_low_byte_setcc_merge(const IrValue& v, int depth = 0) const;

    [[nodiscard]] std::optional<IrValue>
    low_byte_return_payload(const IrValue& value, int depth = 0) const;

    [[nodiscard]] bool low_byte_merge_has_raw_carrier(
        const IrValue& value) const;

    [[nodiscard]] std::optional<std::string>
    render_bool_byte_value(const IrValue& v, int depth, bool negate,
                           int min_prec) const;

    [[nodiscard]] std::string render_cmp(std::string_view op, const IrValue& a,
                                         const IrValue& b, int depth,
                                         bool signed_cmp,
                                         bool in_bool_ctx = false,
                                         int min_prec = 0) const;

    [[nodiscard]] std::string render_bool_operand(const IrValue& v, int depth,
                                                  bool negate, int min_prec) const;

    // `negate`: emit the semantic NOT of the matched compare (e.g., Je → ==, with negate → !=).
    // This cleanly cancels double-negation when the structurer wraps a CondBranch that
    // was itself a Not-of-flag.
    // `in_bool_ctx`: caller is rendering an `if`/`while` condition, so `x != 0`
    // can collapse to `x` and `x == 0` to `!x`.
    [[nodiscard]] std::optional<std::string>
    try_simplify_flag(const IrValue& v, int depth, bool negate = false,
                      bool in_bool_ctx = false, int min_prec = 0) const;

    [[nodiscard]] std::optional<std::string>
    render_ppc_ctr_condition(const IrValue& v, bool invert) const;

    [[nodiscard]] std::optional<std::string>
    imported_i64_field_from_low_word(const IrValue& value) const;

    [[nodiscard]] bool match_ppc_ticks_per_millisecond(
        const IrValue& value) const;

    [[nodiscard]] bool value_depends_on_any(
        const IrValue& value, const std::set<SsaKey>& wanted,
        std::set<SsaKey>& seen, int depth = 0) const;

    [[nodiscard]] bool value_contains_immediate(const IrValue& value, i64 wanted,
                                                std::set<SsaKey>& seen,
                                                int depth = 0) const;

    [[nodiscard]] std::optional<std::string>
    try_render_ppc_tick_elapsed_condition(const IrValue& condition,
                                          bool invert) const;

    [[nodiscard]] std::string render_condition(const IrValue& v, bool invert) const;
};

struct EmitterMetadataStorage {
    std::map<addr_t, std::string> local_selrefs;
    std::map<addr_t, std::string> local_classrefs;
    std::vector<ObjcMethod>       local_objc_methods;
    std::vector<ObjcIvar>         local_objc_ivars;
    std::vector<ObjcProperty>     local_objc_properties;
    std::vector<ObjcBlock>        local_objc_blocks;
    std::vector<ObjcStackBlockInvoke> local_objc_stack_blocks;
    std::map<addr_t, std::string> local_rtti_methods;
};

struct SignatureContext {
    bool has_user_sig = false;
    bool has_metadata_sig = false;
};

[[nodiscard]] bool is_incomplete_decomp_signature(const FunctionSig& signature);

void setup_emitter_metadata(Emitter& e,
                            const StructuredFunction& sf,
                            const Binary* binary,
                            EmitterMetadataStorage& storage);

SignatureContext setup_signature_context(Emitter& e,
                                         const StructuredFunction& sf,
                                         const Binary* binary,
                                         const Annotations* annotations);

}  // namespace ember::emit
