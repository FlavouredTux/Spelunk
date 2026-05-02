#include <ember/decompile/emitter.hpp>

#include <array>
#include <cctype>
#include <cstddef>
#include <cstring>
#include <format>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <tuple>
#include <vector>

#include <ember/analysis/arity.hpp>
#include <ember/analysis/cfg_util.hpp>
#include <ember/analysis/demangle.hpp>
#include <ember/analysis/frame.hpp>
#include <ember/analysis/objc.hpp>
#include <ember/analysis/msvc_rtti.hpp>
#include <ember/analysis/rtti.hpp>
#include <ember/common/types.hpp>
#include <ember/disasm/x64_decoder.hpp>
#include <ember/ir/abi.hpp>
#include <ember/ir/ssa.hpp>

#include "emitter_helpers.hpp"
#include "emitter_tables.hpp"

namespace ember {

namespace {

// SsaKey and ssa_key() live in <ember/ir/ssa.hpp>.

// Pull tables/predicates out of detail:: into the file's anonymous
// namespace so call sites stay unqualified.
using detail::variadic_format_index;
using detail::count_printf_specifiers;
using detail::libc_arity_by_name;
using detail::import_returns_void;
using detail::libc_arg_is_charp;
using detail::c_type_name;
using detail::eh_pattern_hint;

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
    Postfix = 14,   // a[i] a->b a.b f(x) — binds tighter than unary
    Primary = 15,   // ident, literal
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
    // legitimately clobber. Defaults to SysV — back-compat with the
    // pre-Win64 world — and is set by the driver when the binary carries
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
    // Number of int-register args for the function being emitted. Set once
    // at the start of emit() from infer_arity() or the declared sig, and
    // used to name raw rdi/rsi/... reads as a1/a2/... when no annotation
    // overrides them.
    u8                                               self_arity = 0;
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
    // instructions — the brain crackme's 160KB hand-written `main`
    // bottomed out at >2 minutes purely on those scans.
    std::map<SsaKey, u32>                            visible_uses;
    std::map<SsaKey, u32>                            flag_assign_uses;
    // (block, inst) positions of every visible use of a given key, so
    // is_flag_feeder_temp can iterate users in O(uses) instead of
    // re-walking the whole function each call.
    std::map<SsaKey, std::vector<std::pair<u32, u32>>> visible_user_positions;
    // Stack-slot offsets (per stack_offset()) that have at least one Load
    // somewhere in the function. A Store to an offset NOT in this set is a
    // dead spill — common for -O0 spill-arg-to-slot prologues whose slot is
    // never reloaded — and should be suppressed by format_store.
    std::set<i64>                                    loaded_stack_slots;
    // Stack slots written exactly once in the entry block before any
    // conditional branch, where the stored value is the unmodified live-in
    // arg-register (rdi/rsi/...). Loads from these slots forward to the
    // arg name (a1, a2, ...) directly: -O0 spill-arg-then-reload becomes
    // a single use of the parameter, the way the user wrote it.
    std::map<i64, IrValue>                           init_only_slot_value;
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
    // rax/xmm0 SSA key → bound local name for Call returns whose result is
    // read downstream. Makes `fopen(...); if (rax == 0)` render as
    // `u64 r_fopen = fopen(...); if (r_fopen == 0)`.
    std::map<SsaKey, std::string>                    call_return_names;
    std::map<std::pair<std::size_t, std::size_t>, SsaKey> bound_call_key;
    std::map<SsaKey, std::string>                    merge_value_names;
    // SSA values whose C binding has already been emitted in this function
    // body. Used by the materializer to avoid exposing fallback names like
    // `rax_3` / `t17` when a structured condition or return reads a value
    // whose defining IR statement was otherwise suppressed as single-use.
    mutable std::set<SsaKey>                          emitted_bindings;

    // Try to resolve an integer immediate as a pointer to a NUL-terminated
    // printable string in the binary image. Results are cached.
    [[nodiscard]] std::optional<std::string> try_string_at(u64 addr) const {
        if (!binary) return std::nullopt;
        auto it = string_cache.find(addr);
        if (it != string_cache.end()) return it->second;

        std::optional<std::string> result;
        auto span = binary->bytes_at(static_cast<addr_t>(addr));
        const std::size_t max_len = 512;
        if (!span.empty()) {
            std::string s;
            s.reserve(64);
            bool terminated = false;
            std::size_t printable_count = 0;
            std::size_t escaped_count   = 0;
            const std::size_t limit = std::min(span.size(), max_len);
            for (std::size_t i = 0; i < limit; ++i) {
                const auto c = static_cast<unsigned char>(span[i]);
                if (c == 0) { terminated = true; break; }
                // Common whitespace escapes — these are legitimate string
                // content, count toward the printable-threshold heuristic.
                if (c == '\t')      { s += "\\t";  ++printable_count; continue; }
                if (c == '\n')      { s += "\\n";  ++printable_count; continue; }
                if (c == '\r')      { s += "\\r";  ++printable_count; continue; }
                if (c == '\\')      { s += "\\\\"; ++printable_count; continue; }
                if (c == '"')       { s += "\\\""; ++printable_count; continue; }
                if (c >= 0x20 && c <= 0x7e) {
                    s.push_back(static_cast<char>(c));
                    ++printable_count;
                    continue;
                }
                // High-bit / control bytes: hex-escape so a single rogue
                // byte doesn't nuke the entire literal back to a bare
                // address. UTF-8 round-trips byte-for-byte here.
                s += std::format("\\x{:02x}", c);
                ++escaped_count;
            }
            // Heuristic for "this is actually a string": at least 3
            // printable characters (excluding hex-escapes), and printable
            // bytes outnumber escaped ones. Three-char keywords like
            // "add", "sub", "nop", "%s\n" are real string content in
            // codegen tables; the printable-vs-escaped tiebreak still
            // keeps `*(u64*)(" ")`-style noise out.
            if (terminated && printable_count >= 3 &&
                printable_count > escaped_count) {
                result = std::move(s);
            }
        }
        string_cache.emplace(addr, result);
        return result;
    }

    // Cached per-target arity via infer_arity().
    mutable std::map<u64, u8> arity_cache;

    [[nodiscard]] u8 cached_arity(addr_t target) const {
        auto it = arity_cache.find(static_cast<u64>(target));
        if (it != arity_cache.end()) return it->second;
        const u8 a = binary ? infer_arity(*binary, target) : u8{6};
        arity_cache.emplace(static_cast<u64>(target), a);
        return a;
    }

    // Drop ELF `@GLIBC_*` / `@@GLIBC_*` version suffix that clutters import
    // names in pseudo-C (e.g. "puts@GLIBC_2.2.5" → "puts").
    [[nodiscard]] static std::string clean_import_name(std::string_view n) {
        auto pos = n.find('@');
        std::string bare = (pos != std::string_view::npos)
            ? std::string(n.substr(0, pos))
            : std::string(n);
        if (bare.starts_with("__imp_")) bare.erase(0, 6);
        // C++ names come out of the linker mangled. For use at the call site
        // we only want the qualified identifier, not the parenthesized arg
        // list from the demangler (the emitter will render the actual args).
        return pretty_symbol_base(bare);
    }

    // For `call <abs_target>`: if the target is a PLT stub, return the
    // import's name. Nullopt means "render as sub_XXXX".
    [[nodiscard]] std::optional<std::string>
    import_name_for_direct_call(addr_t target) const {
        if (!binary) return std::nullopt;
        if (const Symbol* s = binary->import_at_plt(target); s) {
            return clean_import_name(s->name);
        }
        return std::nullopt;
    }

    // Walk Assign copies until we hit something that's plausibly the
    // address of a string (an Imm, or a Reg). For an Imm, try to read the
    // NUL-terminated string at that address.
    [[nodiscard]] std::optional<std::string>
    resolve_string_value(const IrValue& v) const {
        IrValue cur = v;
        for (int step = 0; step < 8; ++step) {
            if (cur.kind == IrValueKind::Imm) {
                return try_string_at(static_cast<u64>(cur.imm));
            }
            const IrInst* d = def_of(cur);
            if (!d) return std::nullopt;
            if (d->op == IrOp::Assign && d->src_count >= 1) {
                cur = d->srcs[0];
                continue;
            }
            return std::nullopt;
        }
        return std::nullopt;
    }

    // Compute arity for a printf/scanf family call given its format-arg
    // index in `args`. Falls back to `format_index + 1` (emit format, drop
    // the rest) when the format isn't a literal string.
    [[nodiscard]] u8 variadic_arity(const std::vector<IrValue>& args,
                                    u8 format_index) const {
        if (format_index >= args.size()) return format_index;
        auto fmt = resolve_string_value(args[format_index]);
        if (!fmt) return static_cast<u8>(format_index + 1);
        return static_cast<u8>(format_index + 1 + count_printf_specifiers(*fmt));
    }

    // Receiver-shape virtual-method dispatch: if the call target traces
    // as `Load(Add(Load(<recv>), K))` — load vptr from receiver, add
    // slot offset, load method pointer — render as
    // `<recv>->vfn_<K/8>`. Doesn't need IPA / receiver type info; just
    // recognises the canonical Itanium / MSVC vtable shape every C++
    // `obj->method()` compiles to. K must be a constant divisible by
    // sizeof(void*); slot 0 (`Load(Load(<recv>))`) renders as `vfn_0`.
    [[nodiscard]] std::optional<std::string>
    try_render_vfn_dispatch(const IrValue& target) const {
        const IrInst* td = def_stripped(target);
        if (!td || td->op != IrOp::Load || td->src_count < 1) return std::nullopt;
        const IrValue& slot_addr = td->srcs[0];

        // Walk through Assigns to land on the underlying expression.
        auto strip_assigns = [&](IrValue v) -> IrValue {
            for (int hop = 0; hop < 8; ++hop) {
                const IrInst* d = def_of(v);
                if (!d || d->op != IrOp::Assign || d->src_count < 1) return v;
                v = d->srcs[0];
            }
            return v;
        };

        // Two shapes: slot_addr = Add(vptr_load, K), or slot_addr = vptr_load (slot 0).
        IrValue vptr_expr;
        i64 slot_off = 0;
        if (const IrInst* sd = def_stripped(slot_addr);
            sd && sd->op == IrOp::Add && sd->src_count >= 2) {
            const IrValue& a = sd->srcs[0];
            const IrValue& b = sd->srcs[1];
            const IrValue* base_v = nullptr;
            if (b.kind == IrValueKind::Imm) { base_v = &a; slot_off = b.imm; }
            else if (a.kind == IrValueKind::Imm) { base_v = &b; slot_off = a.imm; }
            if (!base_v) return std::nullopt;
            vptr_expr = *base_v;
        } else {
            vptr_expr = slot_addr;
        }

        // vptr_expr should be a Load of the receiver — the vtable pointer
        // sits at offset 0 of every object, so we expect a plain Load(reg).
        const IrInst* vd = def_stripped(strip_assigns(vptr_expr));
        if (!vd || vd->op != IrOp::Load || vd->src_count < 1) return std::nullopt;
        const IrValue& recv = vd->srcs[0];

        // Slot must be pointer-aligned (8 bytes on x64) and non-negative.
        if (slot_off < 0 || (slot_off & 7) != 0) return std::nullopt;
        const i64 slot_idx = slot_off / 8;

        // Render the receiver expression. Keep it tight by binding at
        // Postfix so the resulting `<recv>->vfn_N` doesn't need extra
        // parens on either side. Skip when the receiver doesn't render
        // as a simple expression — better to fall back to `(*…)(…)`
        // than to ship a syntactically iffy `<garbage>->vfn_3(…)`.
        std::string recv_text =
            expr(recv, 0, std::to_underlying(Prec::Postfix));
        if (recv_text.empty()) return std::nullopt;
        return std::format("{}->vfn_{}", recv_text, slot_idx);
    }

    // For `call.ind <expr>`: if `expr` traces back to a Load of a constant
    // address that matches a known GOT slot, return the import's name.
    [[nodiscard]] std::optional<std::string>
    import_name_for_indirect_call(const IrValue& v) const {
        if (!binary) return std::nullopt;
        const IrInst* d = def_stripped(v);
        if (!d || d->op != IrOp::Load || d->src_count < 1) return std::nullopt;

        IrValue addr_v = d->srcs[0];
        // Drill through Assign copies and also direct immediates.
        for (int step = 0; step < 8; ++step) {
            if (addr_v.kind == IrValueKind::Imm) break;
            const IrInst* d2 = def_of(addr_v);
            if (!d2) return std::nullopt;
            if (d2->op != IrOp::Assign || d2->src_count < 1) return std::nullopt;
            addr_v = d2->srcs[0];
        }
        if (addr_v.kind != IrValueKind::Imm) return std::nullopt;

        const addr_t got = static_cast<addr_t>(addr_v.imm);
        if (const Symbol* s = binary->import_at_got(got); s) {
            return clean_import_name(s->name);
        }
        return std::nullopt;
    }

    // Integer/pointer params consume the ABI's int-arg sequence in order;
    // float/double params consume xmm0..xmm7 on both SysV and Win64.
    // Given a declared signature and a canonical register, return the
    // matching param's name (or null if nothing matches).
    //
    // Win64 passes only 4 int args in regs (rcx, rdx, r8, r9); the 5th+
    // sit on the stack — we can't name those from a register here, so
    // they render as raw rsp-relative loads. That's a v1 limitation,
    // consistent with how SysV 7th+ args already render.
    [[nodiscard]] const std::string*
    abi_param_for(const FunctionSig& sig, Reg r) const noexcept {
        static constexpr Reg kFpRegs[8] = {
            Reg::Xmm0, Reg::Xmm1, Reg::Xmm2, Reg::Xmm3,
            Reg::Xmm4, Reg::Xmm5, Reg::Xmm6, Reg::Xmm7,
        };
        const auto int_regs = int_arg_regs(abi);
        const Reg canon = canonical_reg(r);
        std::size_t int_idx = 0;
        std::size_t fp_idx  = 0;
        for (const auto& p : sig.params) {
            const bool is_fp =
                p.type.find("double") != std::string::npos ||
                p.type.find("float")  != std::string::npos;
            if (is_fp) {
                if (fp_idx < 8 && kFpRegs[fp_idx] == canon) return &p.name;
                ++fp_idx;
            } else {
                if (int_idx < int_regs.size() && int_regs[int_idx] == canon) return &p.name;
                ++int_idx;
            }
        }
        return nullptr;
    }

    // If `r` is an int-arg register for the current ABI and the current
    // function actually takes that arg (per annotations or inferred
    // arity), return the param's display name. Otherwise nullopt.
    [[nodiscard]] std::optional<std::string>
    arg_name_for_live_in(Reg r) const {
        if (annotations && fn) {
            if (const FunctionSig* sig = annotations->signature_for(fn->start); sig) {
                if (const std::string* nm = abi_param_for(*sig, r); nm && !nm->empty()) {
                    return *nm;
                }
            }
        }
        const auto int_args = int_arg_regs(abi);
        const Reg canon = canonical_reg(r);
        for (u8 i = 0; i < int_args.size() && i < self_arity; ++i) {
            if (int_args[i] == canon) {
                if (i < self_arg_names.size() && !self_arg_names[i].empty()) {
                    return self_arg_names[i];
                }
                return std::format("a{}", i + 1);
            }
        }
        return std::nullopt;
    }

    // Render a Reg IrValue's leaf name. Resolution order:
    //   1. A Call-return binding for this (canonical reg, version).
    //   2. Chase Assign aliases:
    //        - reg = reg              → keep chasing
    //        - reg = non-reg          → render the rvalue expression (this is
    //          what turns `r12` into `*(u64*)((a2 + 0x8))` when the compiler
    //          stashed a computed pointer into a callee-saved reg at prologue)
    //        - version 0 + arg-reg    → parameter name
    //   3. Raw register mnemonic.
    [[nodiscard]] std::string render_reg_leaf(Reg r, u32 version, int depth = 0) const {
        Reg cur_reg = r;
        u32 cur_ver = version;
        for (int hop = 0; hop < 8; ++hop) {
            SsaKey k{u8{0}, static_cast<u32>(canonical_reg(cur_reg)), cur_ver};
            if (auto it = inline_call_expr.find(k); it != inline_call_expr.end()) {
                return it->second;
            }
            if (auto it = call_return_names.find(k); it != call_return_names.end()) {
                return it->second;
            }
            if (cur_ver == 0) {
                if (auto n = arg_name_for_live_in(cur_reg)) return *n;
                break;
            }
            IrValue v{};
            v.kind = IrValueKind::Reg;
            v.reg = cur_reg;
            v.version = cur_ver;
            const IrInst* d = def_of(v);
            if (!d) break;
            if (d->op == IrOp::Assign && d->src_count >= 1) {
                const auto& src = d->srcs[0];
                if (src.kind == IrValueKind::Reg) {
                    cur_reg = src.reg;
                    cur_ver = src.version;
                    continue;
                }
                if (depth < kMaxExprDepth) return expr(src, depth + 1);
                break;
            }
            // Phi-merged reg: if every incoming operand renders to the
            // same expression (common for `rax = phi(rax_v1, t17)` where
            // t17 traces back to the same call's return), emit that.
            if (d->op == IrOp::Phi && depth < kMaxExprDepth && !d->phi_operands.empty()) {
                std::string unified;
                bool all_match = true;
                for (const auto& op : d->phi_operands) {
                    auto opk = ssa_key(op);
                    if (opk && *opk == k) continue;  // self-reference
                    const std::string s = expr(op, depth + 1);
                    if (s.empty()) { all_match = false; break; }
                    if (unified.empty()) unified = s;
                    else if (s != unified) { all_match = false; break; }
                }
                if (all_match && !unified.empty()) return unified;
            }
            break;
        }
        // Phi/merged value with divergent incoming edges or a non-inlinable
        // producer: render a stable name rather than a raw register so the
        // output never mentions architectural names like `rax`, `rdx`.
        if (version > 0) {
            SsaKey k{u8{0}, static_cast<u32>(canonical_reg(r)), version};
            if (auto it = merge_value_names.find(k); it != merge_value_names.end()) {
                return it->second;
            }
            return std::format("{}_{}", reg_name(r), version);
        }
        return std::string(reg_name(r));
    }

    // For a raw code address, pick a display name. Priority (highest first):
    //   1. User rename (from the annotations sidecar).
    //   2. Named defined function symbol from the binary itself.
    //   3. Fallback `sub_<hex>`.
    [[nodiscard]] std::string function_display_name(addr_t target) const {
        if (annotations) {
            if (const std::string* n = annotations->name_for(target); n) return *n;
        }
        // Obj-C IMPs outrank the ELF / Mach-O symbol table — a class method
        // with `-[Foo bar:]` shape reads at the call site better than any
        // mangled function-pointer name.
        if (auto it = objc_by_imp.find(target); it != objc_by_imp.end()) {
            return std::format("{}[{} {}]",
                               it->second->is_class ? '+' : '-',
                               it->second->cls,
                               it->second->selector);
        }
        // Itanium RTTI-derived virtual-method label: `Class::vfn_<idx>`.
        // Beats the generic symbol-table lookup for stripped C++ binaries
        // where only typeinfos survive.
        if (options.rtti_methods) {
            auto it = options.rtti_methods->find(target);
            if (it != options.rtti_methods->end()) return it->second;
        }
        if (binary) {
            if (const Symbol* s = binary->defined_object_at(target); s) {
                if (s->kind == SymbolKind::Function && s->addr == target &&
                    !s->name.empty()) {
                    return pretty_symbol_base(s->name);
                }
            }
        }
        return std::format("sub_{:x}", target);
    }

    [[nodiscard]] std::string observed_targets_comment(addr_t site) const {
        if (!binary || site == 0) return {};
        auto targets = binary->indirect_edges_from(site);
        if (targets.size() <= 1) return {};
        std::string out = " /* observed targets: ";
        for (std::size_t i = 0; i < targets.size(); ++i) {
            if (i > 0) out += ", ";
            out += function_display_name(targets[i]);
        }
        out += " */";
        return out;
    }

    [[nodiscard]] static std::string escape_string(const std::string& s) {
        std::string out;
        out.reserve(s.size() + 2);
        out += '"';
        for (char c : s) {
            switch (c) {
                case '\\': out += "\\\\"; break;
                case '"':  out += "\\\""; break;
                case '\n': out += "\\n";  break;
                case '\r': out += "\\r";  break;
                case '\t': out += "\\t";  break;
                default:   out += c;      break;
            }
        }
        out += '"';
        return out;
    }

    // An arg reg is "stale" if the caller never deliberately set it before the
    // call: either it's still the function's live-in (version 0) and no user
    // signature claims it, or its most recent def is a Clobber from a prior
    // call. Both cases look like `strlen(... rsi, rdx, r8, r9)` noise.
    //
    // A live-in reg that maps to one of OUR own inferred int-arg slots
    // (i.e. the function takes that reg as a parameter) is NOT stale —
    // it's a forwarded argument. Without this guard, a wrapper like
    // `u64 wrap(u64 a1) { return add7(a1); }` decompiles to `add7()`
    // because is_stale_arg_reg treats `a1` as uninitialised live-in
    // when the caller has no annotation file pinning the signature.
    [[nodiscard]] bool is_stale_arg_reg(const IrValue& a) const {
        if (a.kind != IrValueKind::Reg) return false;
        if (a.version == 0) {
            if (annotations && fn) {
                if (const FunctionSig* sig = annotations->signature_for(fn->start); sig) {
                    if (abi_param_for(*sig, a.reg)) return false;
                }
            }
            // Fall back to inferred self-arity: if a is within the first
            // `self_arity` int-arg regs, treat it as a forwarded param.
            const auto int_args = int_arg_regs(abi);
            const Reg canon = canonical_reg(a.reg);
            for (u8 i = 0; i < int_args.size() && i < self_arity; ++i) {
                if (int_args[i] == canon) return false;
            }
            return true;
        }
        if (const IrInst* d = def_of(a); d && d->op == IrOp::Clobber) {
            // Bound call returns (rax → r_strlen, etc.) are real values
            // even though their def is a Clobber — the binding name
            // proves a downstream reader picked the value up.
            if (auto k = ssa_key(a); k &&
                call_return_names.find(*k) != call_return_names.end()) {
                return false;
            }
            return true;
        }
        return false;
    }

    // Arity for an import by name — user signature at its PLT address beats
    // the baked-in libc table, which beats Itanium-mangled-name parsing.
    // The mangled-name path lets C++ stdlib calls (`std::istream::get`,
    // `std::ofstream::write`, …) size correctly without hand-maintaining
    // a table for every member function.
    [[nodiscard]] std::optional<u8>
    import_arity(addr_t plt_addr, std::string_view name) const {
        if (annotations) {
            if (const FunctionSig* sig = annotations->signature_for(plt_addr); sig) {
                return static_cast<u8>(sig->params.size());
            }
        }
        if (auto a = libc_arity_by_name(name); a) return a;
        if (binary) {
            if (const Symbol* s = binary->import_at_plt(plt_addr); s) {
                if (auto a = arity_from_mangled(s->name); a) {
                    return static_cast<u8>(*a);
                }
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] static bool is_call_arg_barrier(const IrInst& inst) noexcept {
        return inst.op == IrOp::Intrinsic &&
               (inst.name == "call.args.1" ||
                inst.name == "call.args.2" ||
                inst.name == "call.args.3");
    }

    [[nodiscard]] static bool is_callee_saved(Reg r) noexcept {
        const Reg c = canonical_reg(r);
        return c == Reg::Rbx || c == Reg::Rbp ||
               c == Reg::R12 || c == Reg::R13 ||
               c == Reg::R14 || c == Reg::R15;
    }

    // Render an IPA-arena TypeRef as a C type name. Returns empty if the
    // ref is Top or no arena is supplied — caller should fall back.
    [[nodiscard]] std::string ipa_type_name(TypeRef r) const {
        if (!options.type_arena) return {};
        if (r.is_top() || r.is_bottom()) return {};
        const auto& n = options.type_arena->node(r);
        switch (n.kind) {
            case TypeKind::Void: return "void";
            case TypeKind::Int:
                if (n.i.sign_known && n.i.is_signed) {
                    return std::format("s{}", n.i.bits);
                }
                return std::format("u{}", n.i.bits);
            case TypeKind::Float:
                return n.f.bits == 32 ? "float" : "double";
            case TypeKind::Ptr: {
                const auto& pn = options.type_arena->node(n.p.pointee);
                if (pn.kind == TypeKind::Int && pn.i.bits == 8) {
                    return "char*";  // canonical char* rendering
                }
                if (pn.kind == TypeKind::Int) {
                    return std::format("u{}*", pn.i.bits);
                }
                return "void*";
            }
            default: return {};
        }
    }

    // Render the C type for an SSA value, consulting Phase 2 inference
    // results in `fn->value_types`. Falls back to the bit-width-only
    // `c_type_name(IrType)` when no refined type exists, which keeps
    // every untyped value rendering exactly as before.
    [[nodiscard]] std::string c_type_name_for(const IrValue& v) const {
        if (!fn) return std::string(c_type_name(v.type));
        const TypeRef t = fn->type_of(v);
        if (t.is_top()) return std::string(c_type_name(v.type));
        const auto& node = fn->types.node(t);
        switch (node.kind) {
            case TypeKind::Ptr: {
                const auto& pn = fn->types.node(node.p.pointee);
                if (pn.kind == TypeKind::Int) {
                    if (pn.i.bits == 8) return "char*";
                    return std::format("u{}*", pn.i.bits);
                }
                return "void*";
            }
            case TypeKind::Int:
                if (node.i.sign_known && node.i.is_signed) {
                    return std::format("s{}", node.i.bits);
                }
                return std::string(c_type_name(v.type));
            default:
                return std::string(c_type_name(v.type));
        }
    }

    void analyze(const IrFunction& f) {
        fn = &f;
        for (std::size_t bi = 0; bi < f.blocks.size(); ++bi) {
            const auto& bb = f.blocks[bi];
            for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
                const auto& inst = bb.insts[ii];
                if (auto k = ssa_key(inst.dst); k) {
                    defs[*k] = &inst;
                    def_pos[*k] = {bi, ii};
                }
                // Skip uses from call.args.* intrinsics — they get absorbed into the
                // following Call, so they shouldn't keep their operand-feeding assignments alive.
                if (is_call_arg_barrier(inst)) continue;
                if (inst.op == IrOp::Phi) {
                    for (const auto& op : inst.phi_operands)
                        if (auto k = ssa_key(op); k) uses[*k]++;
                } else {
                    for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i)
                        if (auto k = ssa_key(inst.srcs[i]); k) uses[*k]++;
                }
            }
        }
        analyze_abi_noise();
        // Single sweep populating the visible-use caches. Mirrors the
        // filter the on-demand functions used to apply (skip hidden,
        // call-arg barriers, Phi operands), so visible_use_count and
        // every_use_is_flag_assign collapse to map lookups instead of
        // O(N) scans per query.
        for (u32 bi = 0; bi < f.blocks.size(); ++bi) {
            const auto& bb = f.blocks[bi];
            for (u32 ii = 0; ii < bb.insts.size(); ++ii) {
                if (hidden.contains({bi, ii})) continue;
                const auto& inst = bb.insts[ii];
                if (is_call_arg_barrier(inst)) continue;
                if (inst.op == IrOp::Phi) continue;
                const bool is_flag_assign =
                    inst.op == IrOp::Assign &&
                    inst.dst.kind == IrValueKind::Flag;
                for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                    auto k = ssa_key(inst.srcs[i]);
                    if (!k) continue;
                    visible_uses[*k]++;
                    if (is_flag_assign) flag_assign_uses[*k]++;
                    visible_user_positions[*k].emplace_back(bi, ii);
                }
            }
        }
        // Stack slots that are loaded from somewhere in the function. A
        // store whose address resolves to a slot NOT in this set is a dead
        // spill — at -O0 the compiler routinely emits `mov [rbp-N], reg`
        // for an arg even when the slot is never read, and we want those
        // suppressed in the pseudo-C output. The set is keyed by the slot
        // offset returned by `stack_offset(addr)` so it lines up with the
        // emitter's own naming for `local_<hex>` lvalues.
        for (const auto& bb : f.blocks) {
            for (const auto& inst : bb.insts) {
                if (inst.op != IrOp::Load || inst.src_count < 1) continue;
                if (inst.segment != Reg::None) continue;
                if (auto off = stack_offset(inst.srcs[0]); off) {
                    loaded_stack_slots.insert(*off);
                }
            }
        }
        // Init-only slot detection. A slot is "init-only" if it has exactly
        // one Store across the whole function and the stored value is an
        // unmodified arg-reg live-in (version 0). All loads of that slot
        // forward to the live-in name (a1, a2, …) directly, so an -O0
        // `mov [rbp-N], rdi; ... mov reg, [rbp-N]; use reg` collapses to
        // a single use of the parameter — the way the user wrote it.
        //
        // The store's block doesn't have to be the entry: a spill that
        // sits inside the only conditional path that ever reads the slot
        // is just as safe (any path that bypasses the write would be
        // reading uninitialised storage, which is undefined-behaviour
        // territory we don't owe the user a friendly rendering for).
        std::map<i64, int>     slot_write_count;
        std::map<i64, IrValue> slot_first_write_value;
        for (const auto& bb : f.blocks) {
            for (const auto& inst : bb.insts) {
                if (inst.op != IrOp::Store || inst.src_count < 2) continue;
                if (inst.segment != Reg::None) continue;
                auto off = stack_offset(inst.srcs[0]);
                if (!off) continue;
                if (++slot_write_count[*off] == 1) {
                    slot_first_write_value[*off] = inst.srcs[1];
                }
            }
        }
        for (const auto& [off, count] : slot_write_count) {
            if (count != 1) continue;
            const IrValue& v = slot_first_write_value[off];
            // Forward live-in args (rdi/rsi/...) and SSA temps directly:
            // both have a single dominating def that survives unchanged
            // from the store to any later load. Skip clobbers (call-
            // returns) — those represent post-call register state and
            // re-rendering them at every load would duplicate the call
            // expression where the user wrote a single named local.
            const bool is_live_in_arg =
                v.kind == IrValueKind::Reg && v.version == 0;
            const bool is_temp = v.kind == IrValueKind::Temp;
            if (!is_live_in_arg && !is_temp) continue;
            if (is_temp) {
                auto k = ssa_key(v);
                if (!k) continue;
                auto dit = defs.find(*k);
                if (dit == defs.end()) continue;
                if (dit->second->op == IrOp::Clobber) continue;
            }
            init_only_slot_value.emplace(off, v);
        }
        // Second scan: after defs/uses are populated (so def_stripped works),
        // collect offsets for every pointer that participates in loads/stores.
        // A base observed at multiple distinct offsets is treated as a struct
        // pointer in format_mem.
        for (const auto& bb : f.blocks) {
            for (const auto& inst : bb.insts) {
                if (inst.op == IrOp::Load && inst.src_count >= 1 &&
                    inst.segment == Reg::None) {
                    record_struct_access(inst.srcs[0]);
                } else if (inst.op == IrOp::Store && inst.src_count >= 1 &&
                           inst.segment == Reg::None) {
                    record_struct_access(inst.srcs[0]);
                }
            }
        }
    }

    void name_merge_values() {
        std::set<std::string> used;
        u32 n = 0;
        for (const auto& bb : fn->blocks) {
            for (const auto& inst : bb.insts) {
                if (inst.op != IrOp::Phi) continue;
                auto k = ssa_key(inst.dst);
                if (!k || use_count_by_key(*k) == 0) continue;
                std::string name;
                do {
                    name = std::format("v{}", n++);
                } while (used.contains(name));
                used.insert(name);
                merge_value_names.emplace(*k, std::move(name));
            }
        }
    }

    // Self-arg slots (a1..aN) known to flow into a libc char* parameter.
    // Populated by infer_charp_args(); consumed by the header builder.
    std::array<bool, kMaxAbiIntArgs> charp_arg = {};
    // Generated display names for self-arg slots when the body reveals a
    // stronger role than `aN`, e.g. a live-in register used as a function
    // pointer call target.
    std::array<std::string, kMaxAbiIntArgs> self_arg_names = {};
    std::array<std::optional<IrType>, kMaxAbiIntArgs> self_arg_type_overrides = {};
    std::array<std::optional<u8>, kMaxAbiIntArgs> self_funcptr_arity = {};
    std::array<std::optional<IrType>, kMaxAbiIntArgs> self_funcptr_return_type = {};
    std::array<std::vector<IrType>, kMaxAbiIntArgs> self_funcptr_arg_types = {};
    // Stack-slot offsets (per stack_offset()) whose address has been
    // observed flowing into a libc char* parameter. The local-decl
    // emitter renders these as `char <name>[N]` instead of the default
    // `u64 <name>[N/8]` recovered from access widths alone.
    std::set<i64> charp_local_slots;

    // Mach-O Obj-C method table, keyed by IMP address. Populated lazily in
    // PseudoCEmitter::emit when the binary carries __objc_classlist; used
    // by function_display_name to render `-[Class sel]` for any call
    // target that matches a known IMP.
    std::map<addr_t, const ObjcMethod*> objc_by_imp;

    // Mach-O __DATA,__cfstring section bounds. When set, any Imm that falls
    // inside this range is decoded as a Core Foundation string literal via
    // the standard 32-byte CFString-in-cfstring layout.
    addr_t cfstring_lo = 0;
    addr_t cfstring_hi = 0;

    [[nodiscard]] std::optional<std::string>
    try_decode_cfstring(u64 addr) const {
        if (!binary) return std::nullopt;
        if (cfstring_lo == 0 || addr < cfstring_lo || addr >= cfstring_hi)
            return std::nullopt;
        // Each entry is 32 bytes: u64 isa; u32 flags; u32 pad; u64 data;
        // u64 length. Offsets: data at +16, length at +24.
        auto bytes = binary->bytes_at(static_cast<addr_t>(addr));
        if (bytes.size() < 32) return std::nullopt;
        u64 data_ptr = 0, length = 0;
        std::memcpy(&data_ptr, bytes.data() + 16, 8);
        std::memcpy(&length,   bytes.data() + 24, 8);
        if (data_ptr == 0 || length == 0 || length > 1'000'000) return std::nullopt;
        auto strb = binary->bytes_at(static_cast<addr_t>(data_ptr));
        if (strb.size() < length) return std::nullopt;
        std::string s;
        s.reserve(static_cast<std::size_t>(length));
        for (u64 i = 0; i < length; ++i) {
            const auto c = static_cast<unsigned char>(strb[i]);
            if (c == 0) break;
            // CFString can be UTF-8 or UTF-16; be generous and accept any
            // UTF-8 byte. Escape non-printable for display.
            if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') return std::nullopt;
            s.push_back(static_cast<char>(c));
        }
        return s;
    }

    // For-loop update-instruction positions, pulled from every RegionKind::For
    // in the structured body. emit_block skips these so the increment doesn't
    // double-render: once in the body, once in the for-header. Keyed by
    // (block_index, inst_index) to match the `hidden` bookkeeping.
    std::set<std::pair<std::size_t, std::size_t>> for_update_positions;

    // Walk the structured body, populate for_update_positions.
    // Only suppress the body inst if render_update_inst would actually emit
    // it in the for-header — otherwise the For→While fallback in
    // emit_region_for would silently drop the update from the output.
    void collect_for_updates(const Region& r) {
        if (r.kind == RegionKind::For && r.has_update) {
            auto it = fn->block_at.find(r.update_block);
            if (it != fn->block_at.end() &&
                !render_update_inst(r.update_block, r.update_inst).empty()) {
                for_update_positions.emplace(it->second, r.update_inst);
            }
        }
        for (const auto& c : r.children) if (c) collect_for_updates(*c);
    }

    // Render a single instruction at (block_addr, inst_idx) as its compound-
    // assign form — e.g. `i++`, `i += 2`, `x <<= 1`. Used for the update
    // clause of a for-loop. Returns empty on no-match; caller falls back to
    // suppressing the For and emitting as a While.
    [[nodiscard]] std::string
    render_update_inst(addr_t block_addr, u32 inst_idx) const {
        auto it = fn->block_at.find(block_addr);
        if (it == fn->block_at.end()) return {};
        const auto& bb = fn->blocks[it->second];
        if (inst_idx >= bb.insts.size()) return {};
        const auto& inst = bb.insts[inst_idx];
        if (inst.op != IrOp::Store || inst.src_count < 2) return {};
        const auto& addr = inst.srcs[0];
        const auto& val  = inst.srcs[1];
        std::string lhs;
        if (auto off = stack_offset(addr); off) lhs = stack_name(*off);
        if (lhs.empty()) lhs = format_mem(addr, val.type, inst.segment);
        std::string stmt = try_compound_store(lhs, addr, val);
        if (stmt.empty()) return {};
        // Strip the trailing ';' so it fits in a for-header slot.
        while (!stmt.empty() && (stmt.back() == ';' || stmt.back() == '\n')) {
            stmt.pop_back();
        }
        return stmt;
    }

    // Trace `v` back through Assign copies and trivial phis to a version-0
    // int-arg register for the current ABI. Returns the 0-based slot, or
    // nullopt if the value isn't live-in from a self arg.
    [[nodiscard]] std::optional<u8>
    trace_to_self_arg_slot(const IrValue& v, int depth = 0) const {
        if (depth > 8) return std::nullopt;
        const auto args = int_arg_regs(abi);
        IrValue cur = v;
        for (int hop = 0; hop < 8; ++hop) {
            if (cur.kind == IrValueKind::Temp) {
                auto k = ssa_key(cur);
                if (!k) return std::nullopt;
                auto it = defs.find(*k);
                if (it == defs.end()) return std::nullopt;
                const IrInst* d = it->second;
                if ((d->op == IrOp::Assign || d->op == IrOp::Trunc ||
                     d->op == IrOp::ZExt   || d->op == IrOp::SExt) &&
                    d->src_count == 1) {
                    cur = d->srcs[0];
                    continue;
                }
                return std::nullopt;
            }
            if (cur.kind != IrValueKind::Reg) return std::nullopt;
            const Reg canon = canonical_reg(cur.reg);
            if (cur.version == 0) {
                for (u8 i = 0; i < args.size(); ++i) if (args[i] == canon) return i;
                return std::nullopt;
            }
            const IrInst* d = def_of(cur);
            if (!d) return std::nullopt;
            if (d->op == IrOp::Assign && d->src_count == 1) {
                cur = d->srcs[0];
                continue;
            }
            if (d->op == IrOp::Phi && !d->phi_operands.empty()) {
                std::optional<u8> common;
                for (const auto& op : d->phi_operands) {
                    auto opk = ssa_key(op);
                    if (opk && *opk == ssa_key(cur)) continue;  // self-ref
                    auto slot = trace_to_self_arg_slot(op, depth + 1);
                    if (!slot) return std::nullopt;
                    if (!common) common = *slot;
                    else if (*common != *slot) return std::nullopt;
                }
                return common;
            }
            return std::nullopt;
        }
        return std::nullopt;
    }

    [[nodiscard]] IrType call_arg_display_type(const IrValue& v) const {
        if (auto k = ssa_key(v); k) {
            auto it = defs.find(*k);
            if (it != defs.end()) {
                const IrInst* d = it->second;
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

    void record_funcptr_arg_types(u8 slot, const std::vector<IrValue>& args,
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

    void record_self_arg_type(u8 slot, IrType type) {
        if (slot >= self_arg_type_overrides.size()) return;
        auto& existing = self_arg_type_overrides[slot];
        if (!existing) {
            existing = type;
        } else if (*existing != type) {
            existing.reset();
        }
    }

    void record_funcptr_return_type(u8 slot, IrType type) {
        if (slot >= self_funcptr_return_type.size()) return;
        auto& existing = self_funcptr_return_type[slot];
        if (!existing) {
            existing = type;
        } else if (*existing != type) {
            existing.reset();
        }
    }

    // For each call-to-libc in the body, consult the call.args.* packing
    // to recover per-arg IrValues; if an arg is a self live-in reg and the
    // callee takes a `char*` at that position, tag the caller's own slot.
    void infer_charp_args() {
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
                    // Callee-side char*-slot bitset: for a libc import, look
                    // up the direct-sink table; for an internal function,
                    // consult the pre-computed IPA map when one was passed.
                    std::array<bool, kMaxAbiIntArgs> callee_charp{};
                    bool have_info = false;
                    if (inst.op == IrOp::Call) {
                        if (const Symbol* s = binary->import_at_plt(inst.target1); s) {
                            const std::string callee = clean_import_name(s->name);
                            for (u8 i = 0; i < callee_charp.size(); ++i) {
                                callee_charp[i] = libc_arg_is_charp(
                                    callee, static_cast<u8>(i + 1));
                                if (callee_charp[i]) have_info = true;
                            }
                        } else if (options.signatures) {
                            auto it = options.signatures->find(inst.target1);
                            if (it != options.signatures->end()) {
                                callee_charp = it->second.charp;
                                for (bool v : callee_charp) if (v) { have_info = true; break; }
                            }
                        }
                    } else if (inst.src_count >= 1) {
                        if (auto callee = import_name_for_indirect_call(inst.srcs[0])) {
                            for (u8 i = 0; i < callee_charp.size(); ++i) {
                                callee_charp[i] = libc_arg_is_charp(
                                    *callee, static_cast<u8>(i + 1));
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

    void infer_function_pointer_args() {
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

    [[nodiscard]] std::optional<u8>
    known_call_arity_for_arg_names(const IrInst& inst,
                                   const std::vector<IrValue>& args) const {
        std::optional<u8> arity;
        if (inst.op == IrOp::CallIndirect && inst.src_count >= 1 &&
            options.call_resolutions && inst.source_addr != 0) {
            auto res_it = options.call_resolutions->find(inst.source_addr);
            if (res_it != options.call_resolutions->end()) {
                const addr_t target = res_it->second;
                if (auto direct_import = import_name_for_direct_call(target)) {
                    arity = import_arity(target, *direct_import);
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

    void infer_call_value_arg_names() {
        static constexpr std::array<std::string_view, 4> kNames{
            "x", "y", "z", "arg"
        };
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
                if (inst.op != IrOp::Call && inst.op != IrOp::CallIndirect) continue;

                auto arity = known_call_arity_for_arg_names(inst, args);
                if (!arity) {
                    args.clear();
                    continue;
                }
                const std::size_t limit = std::min<std::size_t>(*arity, args.size());
                for (std::size_t i = 0; i < limit; ++i) {
                    auto slot = trace_to_self_arg_slot(args[i]);
                    if (!slot || *slot >= self_arg_names.size()) continue;
                    if (!self_arg_names[*slot].empty()) continue;
                    self_arg_names[*slot] = i < kNames.size() - 1
                        ? std::string{kNames[i]}
                        : std::format("arg{}", i + 1);
                    record_self_arg_type(*slot, call_arg_display_type(args[i]));
                }
                args.clear();
            }
        }
    }

    // Raise self_arity when the body reads a live-in int-arg register
    // that the inferred arity didn't cover. Without this, raw register
    // names leak into the emitted C as e.g. `fputs(rdx, stdout)`. Call
    // only when the caller hasn't pinned an explicit signature.
    void bump_arity_from_body_reads() {
        const auto int_args = int_arg_regs(abi);
        u8 need = self_arity;
        auto check = [&](const IrValue& v) {
            if (v.kind != IrValueKind::Reg) return;
            if (v.version != 0) return;
            const Reg canon = canonical_reg(v.reg);
            for (u8 i = 0; i < int_args.size(); ++i) {
                if (int_args[i] == canon) {
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
        self_arity = need;
    }

    void bump_arity_from_call_sites() {
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
                        arity = import_arity(inst.target1, *import_name);
                    } else {
                        arity = cached_arity(inst.target1);
                    }
                } else if (inst.op == IrOp::CallIndirect && inst.src_count >= 1) {
                    if (auto import_name = import_name_for_indirect_call(inst.srcs[0])) {
                        arity = libc_arity_by_name(*import_name);
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

    [[nodiscard]] bool is_void_call_result(const IrValue& v) const {
        if (v.kind != IrValueKind::Reg) return false;
        if (canonical_reg(v.reg) != int_return_reg(abi)) return false;
        const IrInst* def = def_of(v);
        if (!def || def->op != IrOp::Clobber) return false;
        auto k = ssa_key(v);
        if (!k) return false;
        auto pos_it = def_pos.find(*k);
        if (pos_it == def_pos.end()) return false;
        auto [bi, ii] = pos_it->second;
        const auto& bb = fn->blocks[bi];
        while (ii > 0) {
            --ii;
            const IrInst& prev = bb.insts[ii];
            if (prev.op == IrOp::Clobber || prev.op == IrOp::Nop) continue;
            if (prev.op == IrOp::Call) {
                if (auto name = import_name_for_direct_call(prev.target1)) {
                    return import_returns_void(*name);
                }
            } else if (prev.op == IrOp::CallIndirect && prev.src_count >= 1) {
                if (auto name = import_name_for_indirect_call(prev.srcs[0])) {
                    return import_returns_void(*name);
                }
            }
            return false;
        }
        return false;
    }

    [[nodiscard]] bool is_unbound_clobber_result(const IrValue& v) const {
        if (v.kind != IrValueKind::Reg) return false;
        const IrInst* def = def_of(v);
        if (!def || def->op != IrOp::Clobber) return false;
        auto k = ssa_key(v);
        if (!k) return false;
        if (call_return_names.contains(*k) ||
            fold_return_expr.contains(*k) ||
            fold_void_call_stmt.contains(*k)) {
            return false;
        }
        auto pos_it = def_pos.find(*k);
        if (pos_it == def_pos.end()) return true;
        auto [bi, ii] = pos_it->second;
        const auto& bb = fn->blocks[bi];
        while (ii > 0) {
            --ii;
            const IrInst& prev = bb.insts[ii];
            if (prev.op == IrOp::Clobber || prev.op == IrOp::Nop) continue;
            return prev.op != IrOp::Call && prev.op != IrOp::CallIndirect;
        }
        return true;
    }

    // Find Return regions whose value is the ABI integer return register
    // coming directly from a call's Clobber — record the Call position and
    // the SSA key so emit_block
    // suppresses the statement and the Return handler folds the expression.
    void analyze_return_folds(const Region& r) {
        for (const auto& c : r.children) analyze_return_folds(*c);
        if (r.kind != RegionKind::Return) return;
        const IrValue& cond = r.condition;
        if (cond.kind != IrValueKind::Reg) return;
        if (canonical_reg(cond.reg) != int_return_reg(abi)) return;
        auto cond_key = ssa_key(cond);
        if (!cond_key) return;
        const IrInst* def = def_of(cond);
        if (!def || def->op != IrOp::Clobber) return;
        // Folding `return foo(args);` requires that the call's return value
        // has no other readers — otherwise we'd silently re-emit the call
        // expression at the return site and unbind the only name the other
        // readers had to refer to it. Phi resolution at the structurer can
        // surface a return whose value the surrounding `if` already tested,
        // creating exactly this hazard.
        if (count_uses_with_call_args(*cond_key) > 1) return;
        auto pos_it = def_pos.find(*cond_key);
        if (pos_it == def_pos.end()) return;
        auto [bi, ii] = pos_it->second;
        const auto& bb = fn->blocks[bi];
        // Walk back past the clobber sequence the lifter emits after a call.
        while (ii > 0) {
            --ii;
            const IrInst& prev = bb.insts[ii];
            if (prev.op == IrOp::Clobber || prev.op == IrOp::Nop) continue;
            if (prev.op == IrOp::Call || prev.op == IrOp::CallIndirect) {
                fold_call_positions.insert({bi, ii});
                fold_call_ssa_key.emplace(std::pair{bi, ii}, *cond_key);
            }
            return;  // first non-clobber: either the Call we want, or abort
        }
    }

    void analyze_return_expr_call_folds(const Region& r) {
        for (const auto& c : r.children) analyze_return_expr_call_folds(*c);
        if (r.kind != RegionKind::Return) return;
        if (r.condition.kind == IrValueKind::None) return;
        auto ret_key = single_call_return_key_in_expr(r.condition);
        if (!ret_key) return;
        if (fold_return_expr.contains(*ret_key) ||
            fold_void_call_stmt.contains(*ret_key)) {
            return;
        }
        if (count_uses_with_call_args(*ret_key) != 1) return;
        auto pos = call_position_for_return_key(*ret_key);
        if (!pos) return;
        if (fold_call_positions.contains(*pos)) return;
        if (auto slot = self_funcptr_slot_for_call_pos(*pos); slot) {
            if (auto ty = narrowed_call_return_type_in_expr(r.condition, *ret_key); ty) {
                record_funcptr_return_type(*slot, *ty);
            }
        }
        inline_call_positions.insert(*pos);
        inline_call_ssa_key.emplace(*pos, *ret_key);
    }

    // For each Call with a downstream-used ABI return value, pick a display
    // name and record (call position → return SsaKey). `analyze_return_folds` must
    // run first so calls whose return folds straight into a Return are
    // skipped here.
    void bind_call_returns() {
        std::set<std::string> used;
        const Reg ret_reg = int_return_reg(abi);
        for (std::size_t bi = 0; bi < fn->blocks.size(); ++bi) {
            const auto& bb = fn->blocks[bi];
            for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
                const auto& inst = bb.insts[ii];
                if (inst.op != IrOp::Call && inst.op != IrOp::CallIndirect) continue;
                if (fold_call_positions.contains({bi, ii})) continue;
                if (inline_call_positions.contains({bi, ii})) continue;

                // The return-register clobber for this call is the next inst
                // (Clobbers
                // run immediately post-Call in the lifter's output).
                std::optional<SsaKey> ret_key;
                for (std::size_t jj = ii + 1; jj < bb.insts.size(); ++jj) {
                    const auto& c = bb.insts[jj];
                    if (c.op != IrOp::Clobber) break;
                    if (c.dst.kind != IrValueKind::Reg) continue;
                    if (canonical_reg(c.dst.reg) != ret_reg) continue;
                    ret_key = ssa_key(c.dst);
                    break;
                }
                if (!ret_key) continue;
                // Always bind a name for the return-register clobber when the call wasn't
                // folded into a Return. Reads that happen only through
                // structured-region conditions (e.g. `return r3;`) don't
                // appear in IR srcs and so can't be counted up-front; the
                // dead-decl pass at the end strips any binding nothing ended
                // up referencing.

                std::string base = callee_display_short(inst);
                std::string name = "r_" + base;
                for (int n = 2; used.contains(name); ++n) {
                    name = std::format("r_{}_{}", base, n);
                }
                used.insert(name);
                call_return_names.emplace(*ret_key, name);
                bound_call_key.emplace(std::pair{bi, ii}, *ret_key);
            }
        }
    }

    [[nodiscard]] u32 use_count_by_key(const SsaKey& k) const {
        auto it = uses.find(k);
        return it != uses.end() ? it->second : 0u;
    }

    [[nodiscard]] u32 count_uses_with_call_args(const SsaKey& k) const {
        u32 n = 0;
        for (const auto& bb : fn->blocks) {
            for (const auto& inst : bb.insts) {
                if (inst.op == IrOp::Phi) {
                    for (const auto& op : inst.phi_operands) {
                        if (auto ok = ssa_key(op); ok && *ok == k) ++n;
                    }
                } else {
                    for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                        if (auto ok = ssa_key(inst.srcs[i]); ok && *ok == k) ++n;
                    }
                }
            }
        }
        return n;
    }

    [[nodiscard]] std::optional<std::pair<std::size_t, std::size_t>>
    call_position_for_return_key(const SsaKey& k) const {
        auto pos_it = def_pos.find(k);
        if (pos_it == def_pos.end()) return std::nullopt;
        auto [bi, ii] = pos_it->second;
        const auto& bb = fn->blocks[bi];
        while (ii > 0) {
            --ii;
            const IrInst& prev = bb.insts[ii];
            if (prev.op == IrOp::Clobber || prev.op == IrOp::Nop) continue;
            if (prev.op == IrOp::Call || prev.op == IrOp::CallIndirect) {
                return std::pair{bi, ii};
            }
            return std::nullopt;
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<u8>
    self_funcptr_slot_for_call_pos(std::pair<std::size_t, std::size_t> pos) const {
        if (pos.first >= fn->blocks.size()) return std::nullopt;
        const auto& bb = fn->blocks[pos.first];
        if (pos.second >= bb.insts.size()) return std::nullopt;
        const IrInst& inst = bb.insts[pos.second];
        if (inst.op != IrOp::CallIndirect || inst.src_count < 1) return std::nullopt;
        auto slot = trace_to_self_arg_slot(inst.srcs[0]);
        if (!slot || *slot >= self_funcptr_return_type.size()) return std::nullopt;
        return slot;
    }

    [[nodiscard]] std::optional<IrType>
    narrowed_call_return_type_in_expr(const IrValue& v,
                                      const SsaKey& ret_key,
                                      int depth = 0) const {
        if (depth > 8) return std::nullopt;
        if (auto k = ssa_key(v); k) {
            const IrInst* d = def_of(v);
            if (d && d->op == IrOp::Clobber && *k == ret_key) return v.type;
            if (!d) return std::nullopt;
            if ((d->op == IrOp::Trunc || d->op == IrOp::ZExt || d->op == IrOp::SExt) &&
                d->src_count >= 1) {
                if (auto sk = ssa_key(d->srcs[0]); sk && *sk == ret_key) {
                    return d->dst.type;
                }
            }
            for (u8 i = 0; i < d->src_count && i < d->srcs.size(); ++i) {
                if (auto t = narrowed_call_return_type_in_expr(d->srcs[i],
                                                               ret_key,
                                                               depth + 1)) {
                    return t;
                }
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<SsaKey>
    single_call_return_key_in_expr(const IrValue& v, int depth = 0) const {
        if (depth > 8) return std::nullopt;
        std::optional<SsaKey> found;
        auto merge = [&](std::optional<SsaKey> k) {
            if (!k) return true;
            if (!found) {
                found = *k;
                return true;
            }
            return *found == *k;
        };

        if (auto k = ssa_key(v); k) {
            const IrInst* d = def_of(v);
            if (d && d->op == IrOp::Clobber &&
                v.kind == IrValueKind::Reg &&
                canonical_reg(v.reg) == int_return_reg(abi) &&
                call_position_for_return_key(*k)) {
                return *k;
            }
            if (!d) return std::nullopt;
            switch (d->op) {
                case IrOp::Assign:
                case IrOp::Add:
                case IrOp::Sub:
                case IrOp::Mul:
                case IrOp::And:
                case IrOp::Or:
                case IrOp::Xor:
                case IrOp::Shl:
                case IrOp::Lshr:
                case IrOp::Ashr:
                case IrOp::Trunc:
                case IrOp::ZExt:
                case IrOp::SExt:
                    for (u8 i = 0; i < d->src_count && i < d->srcs.size(); ++i) {
                        if (!merge(single_call_return_key_in_expr(d->srcs[i],
                                                                  depth + 1))) {
                            return std::nullopt;
                        }
                    }
                    return found;
                default:
                    return std::nullopt;
            }
        }
        return std::nullopt;
    }

    // A short identifier derived from the callee's display name, sanitized
    // to valid C identifier chars. For C++ qualified names like
    // `std::istream::get` we keep only the last `::`-segment so the binding
    // reads as `r_get` instead of `r_stdistreamget` — the qualified prefix
    // is already visible at the call site.
    [[nodiscard]] std::string callee_display_short(const IrInst& call_inst) const {
        std::string raw;
        if (call_inst.op == IrOp::Call) {
            if (auto n = import_name_for_direct_call(call_inst.target1)) raw = *n;
            else raw = std::format("sub_{:x}", call_inst.target1);
        } else if (call_inst.op == IrOp::CallIndirect && call_inst.src_count >= 1) {
            if (auto n = import_name_for_indirect_call(call_inst.srcs[0])) raw = *n;
            else raw = "ind";
        } else {
            raw = "call";
        }
        // Keep only the last `::`-separated segment for qualified names.
        // Operators (`operator+`, `operator new`) and destructors (`~T`)
        // are kept whole on the right side — they're already short.
        if (auto pos = raw.rfind("::"); pos != std::string::npos) {
            raw.erase(0, pos + 2);
        }
        std::string out;
        out.reserve(raw.size());
        for (char c : raw) {
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '_') {
                out += c;
            }
        }
        return out.empty() ? std::string("call") : out;
    }

    // Detect prologue/epilogue noise: saves/restores of callee-saved regs, rsp/rbp
    // frame manipulation, plus any temps whose uses are entirely within hidden insts.
    void analyze_abi_noise() {
        // Pass 0: PE UNWIND_INFO-driven prologue suppression. The byte range
        // [entry, prologue_end) from .xdata is authoritative — every inst
        // whose source_addr falls there is prologue. The matching epilogue
        // is the trailing run of insts in the function whose source_addr
        // lies in [end - prologue_size, end); Win64 ABI requires epilogues
        // mirror the prologue ops in reverse and never exceed its length.
        if (options.prologue_ranges) {
            auto it = options.prologue_ranges->find(fn->start);
            if (it != options.prologue_ranges->end()) {
                const addr_t prologue_end = it->second;
                const addr_t prologue_len = prologue_end - fn->start;
                const addr_t epilogue_lo  = fn->end > prologue_len
                    ? fn->end - prologue_len : fn->start;
                for (std::size_t bi = 0; bi < fn->blocks.size(); ++bi) {
                    const auto& bb = fn->blocks[bi];
                    for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
                        const addr_t sa = bb.insts[ii].source_addr;
                        if (sa == 0) continue;
                        if (sa >= fn->start && sa < prologue_end) {
                            hidden.insert({bi, ii});
                        } else if (sa >= epilogue_lo && sa < fn->end) {
                            hidden.insert({bi, ii});
                        }
                    }
                }
            }
        }
        // Pass 1: direct pattern matches.
        for (std::size_t bi = 0; bi < fn->blocks.size(); ++bi) {
            const auto& bb = fn->blocks[bi];
            for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
                if (is_abi_noise(bb.insts[ii])) hidden.insert({bi, ii});
            }
        }
        // Pass 2: propagate. A pure temp whose every use is in a hidden inst is itself dead.
        //
        // We build a one-shot user-list per SsaKey up front so each fixpoint
        // iteration touches O(uses) instead of re-walking the entire IR.
        // The previous shape was O(N) outer × O(N) inner × up-to-16 iters,
        // which on a 50 k-inst function turns into tens of billions of
        // ssa_key comparisons.
        std::map<SsaKey, std::vector<std::pair<u32, u32>>> users_of;
        for (u32 bi = 0; bi < fn->blocks.size(); ++bi) {
            const auto& bb = fn->blocks[bi];
            for (u32 ii = 0; ii < bb.insts.size(); ++ii) {
                const auto& inst = bb.insts[ii];
                auto record = [&](const IrValue& v) {
                    if (auto k = ssa_key(v); k) {
                        users_of[*k].emplace_back(bi, ii);
                    }
                };
                if (inst.op == IrOp::Phi) {
                    for (const auto& op : inst.phi_operands) record(op);
                } else {
                    for (u8 k = 0; k < inst.src_count && k < inst.srcs.size(); ++k) {
                        record(inst.srcs[k]);
                    }
                }
            }
        }
        bool changed = true;
        int guard = 0;
        while (changed && guard++ < 16) {
            changed = false;
            for (u32 bi = 0; bi < fn->blocks.size(); ++bi) {
                const auto& bb = fn->blocks[bi];
                for (u32 ii = 0; ii < bb.insts.size(); ++ii) {
                    if (hidden.contains({bi, ii})) continue;
                    const auto& inst = bb.insts[ii];
                    if (inst.dst.kind != IrValueKind::Temp) continue;
                    if (!inlinable_op(inst.op)) continue;
                    auto target_key = ssa_key(inst.dst);
                    if (!target_key) continue;
                    auto uit = users_of.find(*target_key);
                    if (uit == users_of.end() || uit->second.empty()) continue;
                    bool all_hidden = true;
                    for (const auto& [bj, ij] : uit->second) {
                        if (hidden.contains({bj, ij})) continue;
                        if (is_call_arg_barrier(fn->blocks[bj].insts[ij])) continue;
                        all_hidden = false;
                        break;
                    }
                    if (all_hidden) {
                        hidden.insert({bi, ii});
                        changed = true;
                    }
                }
            }
        }
    }

    [[nodiscard]] static bool is_canary_load(const IrInst& inst) noexcept {
        return inst.op == IrOp::Load && inst.segment == Reg::Fs &&
               inst.src_count >= 1 &&
               inst.srcs[0].kind == IrValueKind::Imm &&
               inst.srcs[0].imm == 0x28;
    }

    // Walk Assigns back to a real producer and return its def (or null).
    [[nodiscard]] const IrInst* def_through_assigns(const IrValue& v) const {
        const IrInst* d = def_of(v);
        while (d && d->op == IrOp::Assign && d->src_count == 1) {
            d = def_of(d->srcs[0]);
        }
        return d;
    }

    [[nodiscard]] bool traces_to_canary_load(const IrValue& v) const {
        if (const IrInst* d = def_through_assigns(v); d) return is_canary_load(*d);
        return false;
    }

    [[nodiscard]] bool is_abi_noise(const IrInst& inst) const {
        // rsp/rbp = <anything>  → frame manipulation
        if (inst.op == IrOp::Assign && inst.dst.kind == IrValueKind::Reg) {
            const Reg c = canonical_reg(inst.dst.reg);
            if (c == Reg::Rsp || c == Reg::Rbp) return true;
        }
        // Prologue canary: Store of fs:[0x28] into a stack slot.
        if (inst.op == IrOp::Store && inst.src_count >= 2) {
            if (stack_offset(inst.srcs[0]).has_value() &&
                traces_to_canary_load(inst.srcs[1])) {
                return true;
            }
        }
        // Store of a live-in callee-saved reg into a stack slot → prologue save
        if (inst.op == IrOp::Store && inst.src_count >= 2) {
            const auto& val = inst.srcs[1];
            if (val.kind == IrValueKind::Reg && val.version == 0 &&
                is_callee_saved(val.reg) && stack_offset(inst.srcs[0]).has_value())
                return true;
        }
        // callee-saved = <Load [stack]>  → epilogue restore
        if (inst.op == IrOp::Assign && inst.dst.kind == IrValueKind::Reg &&
            is_callee_saved(inst.dst.reg) && inst.src_count >= 1) {
            const IrInst* src_def = def_of(inst.srcs[0]);
            while (src_def && src_def->op == IrOp::Assign && src_def->src_count == 1)
                src_def = def_of(src_def->srcs[0]);
            if (src_def && src_def->op == IrOp::Load && src_def->src_count >= 1 &&
                stack_offset(src_def->srcs[0]).has_value())
                return true;
        }
        return false;
    }

    // The canary check is a compare/sub/xor whose operands are:
    //   - a Load from fs:[0x28]  AND
    //   - a Load from a stack slot (the saved cookie).
    [[nodiscard]] bool is_canary_compare_inst(const IrInst& inst) const {
        if (inst.src_count < 2) return false;
        switch (inst.op) {
            case IrOp::Sub: case IrOp::Xor:
            case IrOp::CmpEq: case IrOp::CmpNe:
                break;
            default:
                return false;
        }
        const IrInst* a = def_through_assigns(inst.srcs[0]);
        const IrInst* b = def_through_assigns(inst.srcs[1]);
        if (!a || !b) return false;
        auto is_stack_load = [&](const IrInst* d) {
            return d && d->op == IrOp::Load && d->src_count >= 1 &&
                   stack_offset(d->srcs[0]).has_value() && d->segment == Reg::None;
        };
        auto is_fs28 = [&](const IrInst* d) { return d && is_canary_load(*d); };
        return (is_stack_load(a) && is_fs28(b)) ||
               (is_stack_load(b) && is_fs28(a));
    }

    // Chase a branch condition back until we hit a Sub/Xor/CmpEq/CmpNe between
    // the canary cookie and fs:[0x28]. Handles the typical `zf = cmp.eq(x,0)`
    // followed by `not` wrapper that x86 condition codes produce.
    [[nodiscard]] bool is_canary_condition(const IrValue& cond) const {
        IrValue cur = cond;
        for (int step = 0; step < 10; ++step) {
            const IrInst* d = def_of(cur);
            if (!d) return false;
            if (is_canary_compare_inst(*d)) return true;
            // Follow Assign, Not, and Cmp chains.
            if (d->op == IrOp::Assign && d->src_count >= 1) { cur = d->srcs[0]; continue; }
            if (d->op == IrOp::Not && d->src_count >= 1)    { cur = d->srcs[0]; continue; }
            if ((d->op == IrOp::CmpEq || d->op == IrOp::CmpNe) && d->src_count >= 1) {
                // Compare against a constant (`cmp.eq(x, 0)` / zf). Peek through
                // to x and try again — the real canary compare is one step up.
                if (d->src_count >= 2 &&
                    d->srcs[1].kind == IrValueKind::Imm && d->srcs[1].imm == 0) {
                    cur = d->srcs[0];
                    continue;
                }
                return false;
            }
            return false;
        }
        return false;
    }

    [[nodiscard]] bool region_calls_stack_chk_fail(const Region& r) const {
        // Find a Block/Seq whose body contains a Call to __stack_chk_fail.
        auto block_matches = [&](addr_t block_addr) {
            auto it = fn->block_at.find(block_addr);
            if (it == fn->block_at.end()) return false;
            const auto& bb = fn->blocks[it->second];
            for (const auto& inst : bb.insts) {
                if (inst.op != IrOp::Call) continue;
                if (!binary) continue;
                if (const Symbol* s = binary->import_at_plt(inst.target1); s) {
                    if (clean_import_name(s->name) == "__stack_chk_fail") return true;
                }
            }
            return false;
        };
        if (r.kind == RegionKind::Block) return block_matches(r.block_start);
        for (const auto& c : r.children) {
            if (c && region_calls_stack_chk_fail(*c)) return true;
        }
        return false;
    }

    // Rewrite If/IfElse regions whose condition is a canary check: replace the
    // region with its non-fail branch so the canary guard vanishes entirely.
    void suppress_canary_regions(Region& r) const {
        for (auto& c : r.children) {
            if (c) suppress_canary_regions(*c);
        }
        if (r.kind != RegionKind::IfThen && r.kind != RegionKind::IfElse) return;
        if (!is_canary_condition(r.condition)) return;

        const bool has_else = r.kind == RegionKind::IfElse;
        auto* then_branch = r.children.empty() ? nullptr : r.children[0].get();
        auto* else_branch = (has_else && r.children.size() >= 2) ? r.children[1].get() : nullptr;

        const bool then_fails = then_branch && region_calls_stack_chk_fail(*then_branch);
        const bool else_fails = else_branch && region_calls_stack_chk_fail(*else_branch);
        if (!then_fails && !else_fails) return;

        // Pull the surviving branch up; if neither survives, collapse to Empty.
        std::unique_ptr<Region> keep;
        if (then_fails && else_branch) keep = std::move(r.children[1]);
        else if (else_fails && !r.children.empty()) keep = std::move(r.children[0]);

        if (keep) {
            r = std::move(*keep);
        } else {
            r.kind = RegionKind::Empty;
            r.children.clear();
            r.condition = {};
        }
    }

    [[nodiscard]] const IrInst* def_of(const IrValue& v) const {
        auto k = ssa_key(v);
        if (!k) return nullptr;
        auto it = defs.find(*k);
        return it != defs.end() ? it->second : nullptr;
    }

    [[nodiscard]] u32 use_count(const IrValue& v) const {
        auto k = ssa_key(v);
        if (!k) return 0;
        auto it = uses.find(*k);
        return it != uses.end() ? it->second : 0u;
    }

    // Uses that actually survive into emitted output: skip hidden insts
    // (ABI noise), call.args barriers, AND phi instructions (phis aren't
    // emitted as statements, so their operand reads don't count toward
    // whether we need to materialize a local). A temp with visible_use_count
    // <= 1 can be inlined / its declaration dropped.
    [[nodiscard]] u32 visible_use_count(const IrValue& v) const {
        auto key = ssa_key(v);
        if (!key) return 0u;
        auto it = visible_uses.find(*key);
        return it != visible_uses.end() ? it->second : 0u;
    }

    [[nodiscard]] static bool inlinable_op(IrOp op) noexcept {
        switch (op) {
            case IrOp::Load:
            case IrOp::Assign:
            case IrOp::Add: case IrOp::Sub: case IrOp::Mul:
            case IrOp::Div: case IrOp::Mod:
            case IrOp::And: case IrOp::Or:  case IrOp::Xor:
            case IrOp::Neg: case IrOp::Not:
            case IrOp::Shl: case IrOp::Lshr: case IrOp::Ashr:
            case IrOp::Select:
            case IrOp::CmpEq: case IrOp::CmpNe:
            case IrOp::CmpSlt: case IrOp::CmpSle:
            case IrOp::CmpSgt: case IrOp::CmpSge:
            case IrOp::CmpUlt: case IrOp::CmpUle:
            case IrOp::CmpUgt: case IrOp::CmpUge:
            case IrOp::ZExt:  case IrOp::SExt:  case IrOp::Trunc:
            case IrOp::AddCarry:    case IrOp::SubBorrow:
            case IrOp::AddOverflow: case IrOp::SubOverflow:
                return true;
            default:
                return false;
        }
    }

    // Every visible use of `v` is the source of an Assign-to-Flag.
    // Used to detect the trailing layer of a flag-set fan-out: the cmp result
    // (cmp.eq, cmp.slt, etc.) typically feeds straight into `assign zf, …`
    // and `assign sf, …`, never into general dataflow.
    [[nodiscard]] bool every_use_is_flag_assign(const IrValue& v) const {
        if (v.kind != IrValueKind::Temp) return false;
        auto k = ssa_key(v);
        if (!k) return false;
        auto vit = visible_uses.find(*k);
        if (vit == visible_uses.end() || vit->second == 0) return false;
        auto fit = flag_assign_uses.find(*k);
        const u32 fa = fit == flag_assign_uses.end() ? 0u : fit->second;
        return fa == vit->second;
    }

    // The cmp result (`a - b` from a `cmp` lifted as Sub) typically has
    // multiple uses — one per flag-set computation (zf and sf each take it
    // as srcs[0] of cmp.eq / cmp.slt). Each of *those* temps then flows into
    // exactly one Assign-to-Flag. The reader doesn't want to see the explicit
    // `s64 t8 = a - b;` declaration when it's only there to feed flag math
    // that itself dissolves into an inline jcc/setcc/cmov predicate.
    [[nodiscard]] bool is_flag_feeder_temp(const IrValue& v) const {
        if (v.kind != IrValueKind::Temp) return false;
        auto k = ssa_key(v);
        if (!k) return false;
        auto pit = visible_user_positions.find(*k);
        if (pit == visible_user_positions.end() || pit->second.empty()) {
            return false;
        }
        for (const auto& [bi, ii] : pit->second) {
            const auto& inst = fn->blocks[bi].insts[ii];
            if (inst.dst.kind != IrValueKind::Temp) return false;
            if (!every_use_is_flag_assign(inst.dst)) return false;
        }
        return true;
    }

    [[nodiscard]] bool should_inline(const IrValue& v) const {
        if (v.kind != IrValueKind::Temp) return false;
        const auto* d = def_of(v);
        if (!d) return false;
        if (!inlinable_op(d->op)) return false;
        if (visible_use_count(v) > 1) {
            // Flag-feeder temps are an exception: their multiple uses are
            // all flag-set computations that themselves render inline.
            // Duplicating the underlying expression at each flag-set site
            // is a small textual cost for a much cleaner output.
            if (is_flag_feeder_temp(v)) return true;
            // A Load whose address is a stack slot just renders as the
            // slot's `local_X` name — duplicating that string at each use
            // is no worse than the original `tN = local_X; ... use tN ...`
            // pair, and lets compound flag-set patterns (sub.overflow +
            // sub feeding the same slt rendering) collapse cleanly without
            // leaving a dangling `tN = local_X;` line. Skip if the slot
            // has an unknown segment (fs:[…] etc.) — those carry side
            // effects we shouldn't replay.
            if (d->op == IrOp::Load && d->src_count >= 1 &&
                d->segment == Reg::None && stack_offset(d->srcs[0]).has_value()) {
                return true;
            }
            return false;
        }
        return true;
    }

    [[nodiscard]] std::optional<std::string> fallback_ssa_name(const IrValue& v) const {
        if (auto k = ssa_key(v); k) {
            if (auto it = merge_value_names.find(*k); it != merge_value_names.end()) {
                return it->second;
            }
        }
        switch (v.kind) {
            case IrValueKind::Reg:
                if (v.version == 0) return std::nullopt;
                return std::format("{}_{}", reg_name(v.reg), v.version);
            case IrValueKind::Temp:
                return std::format("t{}", v.temp);
            default:
                return std::nullopt;
        }
    }

    void mark_binding_emitted(const IrValue& v) const {
        if (auto k = ssa_key(v); k) emitted_bindings.insert(*k);
    }

    [[nodiscard]] bool renders_raw_arch_reg_name(const IrValue& v) const {
        if (v.kind != IrValueKind::Reg || v.version == 0) return false;
        const std::string raw = std::format("{}_{}", reg_name(v.reg), v.version);
        return expr(v, 1, 0) == raw;
    }

    void emit_materializations_for_value(const IrValue& v,
                                         int depth,
                                         std::string& out,
                                         std::string_view ind) const {
        if (depth > 12) return;
        if (v.kind != IrValueKind::Reg && v.kind != IrValueKind::Temp) return;
        auto k = ssa_key(v);
        if (!k || emitted_bindings.contains(*k)) return;
        const IrInst* d = def_of(v);
        if (!d) return;

        // If the regular expression renderer can produce anything better
        // than the raw SSA fallback name, use that at the use site instead
        // of inventing a redundant binding.
        const auto fallback = fallback_ssa_name(v);
        if (!fallback) return;
        if (expr(v, depth + 1, 0) != *fallback) {
            return;
        }

        // Phi and clobber defs need path/call-site context. Calls should be
        // handled by call_return_names; divergent phis are better left as a
        // stable SSA name than rendered as a misleading unconditional assign.
        if (d->op == IrOp::Phi || d->op == IrOp::Clobber) return;
        if (d->op != IrOp::Assign && d->op != IrOp::Load &&
            d->op != IrOp::Intrinsic && !inlinable_op(d->op)) {
            return;
        }

        for (u8 i = 0; i < d->src_count && i < d->srcs.size(); ++i) {
            emit_materializations_for_value(d->srcs[i], depth + 1, out, ind);
        }

        std::string rhs;
        if (d->op == IrOp::Intrinsic) {
            std::string args;
            for (u8 i = 0; i < d->src_count && i < d->srcs.size(); ++i) {
                if (i > 0) args += ", ";
                args += expr(d->srcs[i]);
            }
            rhs = std::format("{}({})", d->name, args);
        } else if (d->op == IrOp::Load) {
            if (d->src_count < 1) return;
            rhs = format_mem(d->srcs[0], d->dst.type, d->segment);
        } else if (d->op == IrOp::Assign) {
            if (d->src_count < 1) return;
            rhs = expr(d->srcs[0]);
        } else {
            rhs = expand(*d, 0);
        }
        if (rhs.empty()) return;
        out += std::format("{}{} {} = {};\n",
                           ind, c_type_name_for(v), *fallback, rhs);
        emitted_bindings.insert(*k);
    }

    void emit_materializations_for_inst(const IrInst& inst,
                                        std::string& out,
                                        std::string_view ind) const {
        if (inst.op == IrOp::Phi || is_call_arg_barrier(inst)) return;
        for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
            emit_materializations_for_value(inst.srcs[i], 0, out, ind);
        }
    }

    // Trace a value back through Add/Sub/Assign chains to see if it's rsp/rbp-relative.
    [[nodiscard]] std::optional<i64> stack_offset(const IrValue& v, int depth = 0) const {
        if (depth > 16) return std::nullopt;
        if (v.kind == IrValueKind::Reg) {
            const Reg canon = canonical_reg(v.reg);
            if (canon == Reg::Rsp || canon == Reg::Rbp) return 0;
            return std::nullopt;
        }
        if (v.kind != IrValueKind::Temp) return std::nullopt;
        const auto* d = def_of(v);
        if (!d) return std::nullopt;
        switch (d->op) {
            case IrOp::Assign:
                return d->src_count >= 1
                    ? stack_offset(d->srcs[0], depth + 1)
                    : std::nullopt;
            case IrOp::Add: {
                if (d->src_count < 2) return std::nullopt;
                auto base = stack_offset(d->srcs[0], depth + 1);
                if (base && d->srcs[1].kind == IrValueKind::Imm) {
                    return *base + d->srcs[1].imm;
                }
                auto base2 = stack_offset(d->srcs[1], depth + 1);
                if (base2 && d->srcs[0].kind == IrValueKind::Imm) {
                    return *base2 + d->srcs[0].imm;
                }
                return std::nullopt;
            }
            case IrOp::Sub: {
                if (d->src_count < 2) return std::nullopt;
                auto base = stack_offset(d->srcs[0], depth + 1);
                if (base && d->srcs[1].kind == IrValueKind::Imm) {
                    return *base - d->srcs[1].imm;
                }
                return std::nullopt;
            }
            default:
                return std::nullopt;
        }
    }

    [[nodiscard]] static std::string stack_name(i64 off) {
        if (off < 0) {
            return std::format("local_{:x}", static_cast<u64>(-off));
        }
        if (off == 0) return "stack_top";
        return std::format("arg_{:x}", static_cast<u64>(off));
    }

    [[nodiscard]] std::string format_imm(const IrValue& v) const {
        return format_imm_impl(v, /*allow_string_literals=*/true);
    }

    [[nodiscard]] std::string format_numeric_imm(const IrValue& v) const {
        return format_imm_impl(v, /*allow_string_literals=*/false);
    }

    [[nodiscard]] std::string format_imm_impl(const IrValue& v,
                                              bool allow_string_literals) const {
        // Annotated constant? Lets users name a hash, magic value, or
        // sentinel without touching the binary. The original hex stays
        // in a trailing comment so the user can audit the substitution.
        // Skip for tiny values where the name would be misleading
        // (loop bounds, struct offsets etc. are not worth annotating).
        if (annotations && v.kind == IrValueKind::Imm &&
            v.imm >= 0 && static_cast<u64>(v.imm) >= 0x10) {
            const u64 uv = static_cast<u64>(v.imm);
            if (const std::string* nm = annotations->constant_name_for(uv); nm) {
                return std::format("{} /* {:#x} */", *nm, uv);
            }
        }
        // Float-typed immediates arrive as an i64 bit pattern; decode into
        // a decimal literal so `xmm0 = 0x40490fdb` becomes `3.141593f`.
        if (v.type == IrType::F32) {
            float f;
            const u32 bits = static_cast<u32>(static_cast<u64>(v.imm));
            std::memcpy(&f, &bits, sizeof(f));
            return std::format("{}f", f);
        }
        if (v.type == IrType::F64) {
            double d;
            const u64 bits = static_cast<u64>(v.imm);
            std::memcpy(&d, &bits, sizeof(d));
            return std::format("{}", d);
        }
        // Core Foundation string literal? `__DATA,__cfstring` holds 32-byte
        // `{isa, flags, data, length}` records for compile-time NSString/
        // CFString constants. Rendering as `@"..."` matches what the
        // source-level code actually wrote.
        if (allow_string_literals &&
            binary && v.imm > 0 && static_cast<u64>(v.imm) >= 0x100) {
            if (auto s = try_decode_cfstring(static_cast<u64>(v.imm)); s) {
                return "@" + escape_string(*s);
            }
        }
        // If the immediate points into the binary and resolves to a NUL-terminated
        // printable string, render as a C string literal.
        if (allow_string_literals &&
            binary && v.imm > 0 && static_cast<u64>(v.imm) >= 0x100) {
            if (auto s = try_string_at(static_cast<u64>(v.imm)); s) {
                return escape_string(*s);
            }
        }
        // Small single-digit ints read much better as decimal; larger values
        // are generally addresses, masks, or byte counts where hex carries
        // information.
        if (v.imm >= 0 && v.imm <= 9) return std::format("{}", v.imm);
        if (v.imm < 0 && v.imm >= -9) return std::format("{}", v.imm);
        // Sub-i64 values whose bit pattern is "clearly a small negative"
        // when interpreted in their declared type (e.g. an i32 holding
        // 0xFFFFFFFF that's actually -1) render as signed decimal. Limit
        // to small magnitudes so genuine bitmasks and addresses keep their
        // hex form; -1..-32 covers the common return-error sentinels and
        // signed-imm constants without false-positiving on masks.
        if (v.type != IrType::I64 && v.imm > 0) {
            const unsigned bits = type_bits(v.type);
            if (bits > 0 && bits < 64) {
                const u64 mask = (u64(1) << bits) - 1;
                const u64 sign_bit = u64(1) << (bits - 1);
                const u64 u = static_cast<u64>(v.imm) & mask;
                if (u & sign_bit) {
                    const i64 as_signed = static_cast<i64>(u | ~mask);
                    if (as_signed >= -32) {
                        return std::format("{}", as_signed);
                    }
                }
            }
        }
        // i64 imms in the small-negative-as-i32 range come from `mov eax,
        // -1; ret`-style returns the lifter widened into rax — the high
        // 32 bits are zero, the low 32 are the signed value. Render those
        // as their signed form too. Same -32 threshold as above so genuine
        // 32-bit bitmasks (0xFFFFFFFE used as ~1, etc.) keep their hex.
        if (v.type == IrType::I64) {
            const u64 u = static_cast<u64>(v.imm);
            if ((u >> 32) == 0 && (u & 0x80000000u)) {
                const i64 as_signed =
                    static_cast<i64>(u | 0xFFFFFFFF00000000ull);
                if (as_signed >= -32) {
                    return std::format("{}", as_signed);
                }
            }
        }
        if (v.imm < 0) {
            const u64 abs_v = static_cast<u64>(0) - static_cast<u64>(v.imm);
            return std::format("-{:#x}", abs_v);
        }
        return std::format("{:#x}", static_cast<u64>(v.imm));
    }

    // Hard depth cap for recursive expression expansion. The emitter
    // inlines SSA defs during render — a long def-use chain without a
    // cap recurses until the stack (or kernel OOM-killer) stops it.
    // Deeply-nested expressions past ~6 levels are illegible anyway;
    // we stop inlining and render the raw register/temp instead.
    static constexpr int kMaxExprDepth = 6;

    [[nodiscard]] std::string expr(const IrValue& v, int depth = 0,
                                   int min_prec = 0) const;
    [[nodiscard]] std::string expand(const IrInst& d, int depth,
                                     int min_prec = 0) const;

    // Try to resolve an address IrValue to a concrete immediate address,
    // drilling through single-assign copies. Returns nullopt for any
    // non-constant address.
    [[nodiscard]] std::optional<i64>
    try_resolve_imm_addr(const IrValue& v) const {
        if (v.kind == IrValueKind::Imm) return v.imm;
        const IrInst* d = def_stripped(v);
        if (d && d->op == IrOp::Assign && d->src_count == 1 &&
            d->srcs[0].kind == IrValueKind::Imm) {
            return d->srcs[0].imm;
        }
        return std::nullopt;
    }

    // If `addr` resolves to an absolute address inside a named global
    // object, render the access in terms of that symbol's name. Covers
    // exact-match (→ `name`), symbol-start cast mismatch (→ `*(T*)&name`),
    // and offsets (→ `*(T*)(&name + off)`). Returns nullopt when no global
    // matches.
    [[nodiscard]] std::optional<std::string>
    render_global_mem(const IrValue& addr, IrType t) const {
        if (!binary) return std::nullopt;
        auto imm = try_resolve_imm_addr(addr);
        if (!imm) return std::nullopt;
        const addr_t a = static_cast<addr_t>(*imm);
        const Symbol* s = binary->defined_object_at(a);
        if (!s || s->kind != SymbolKind::Object) return std::nullopt;
        if (s->name.empty()) return std::nullopt;

        const unsigned t_bytes = type_bits(t) / 8;
        const i64 off = static_cast<i64>(a) - static_cast<i64>(s->addr);

        if (off == 0 && s->size == t_bytes) {
            return s->name;
        }
        if (off == 0) {
            return std::format("*({}*)&{}", c_type_name(t), s->name);
        }
        return std::format("*({}*)(&{} + {:#x})",
                           c_type_name(t), s->name,
                           static_cast<u64>(off));
    }

    // Chase Assigns/Imm to resolve a value to a constant integer, if one exists.
    [[nodiscard]] std::optional<i64> resolve_imm(const IrValue& v) const {
        if (v.kind == IrValueKind::Imm) return v.imm;
        IrValue cur = v;
        for (int hop = 0; hop < 8; ++hop) {
            const IrInst* d = def_of(cur);
            if (!d || d->op != IrOp::Assign || d->src_count < 1) return std::nullopt;
            if (d->srcs[0].kind == IrValueKind::Imm) return d->srcs[0].imm;
            cur = d->srcs[0];
        }
        return std::nullopt;
    }

    // For an address value, decompose into (base, offset) where base is a
    // Reg or Temp and offset is a signed immediate. If the address is just a
    // bare base, offset is 0. Returns nullopt on anything we can't flatten.
    [[nodiscard]] std::optional<std::pair<IrValue, i64>>
    try_base_plus_offset(const IrValue& addr) const {
        // Direct base with implicit 0 offset.
        if (addr.kind == IrValueKind::Reg || addr.kind == IrValueKind::Temp) {
            if (const IrInst* d = def_stripped(addr);
                d && d->op == IrOp::Add && d->src_count >= 2) {
                if (auto r = resolve_imm(d->srcs[1])) {
                    return std::pair{d->srcs[0], *r};
                }
                if (auto l = resolve_imm(d->srcs[0])) {
                    return std::pair{d->srcs[1], *l};
                }
            }
            return std::pair{addr, static_cast<i64>(0)};
        }
        return std::nullopt;
    }

    // Collected during analyze(): for each pointer-like SSA value, the set of
    // distinct offsets at which loads/stores occurred. When a base has >=2
    // distinct offsets we treat it as a struct pointer and render accesses
    // as `base->field_<offset>` instead of `*(T*)(base + off)`.
    std::map<SsaKey, std::set<i64>> struct_offsets;

    [[nodiscard]] bool is_struct_pointer(const IrValue& base) const {
        auto k = ssa_key(base);
        if (!k) return false;
        auto it = struct_offsets.find(*k);
        return it != struct_offsets.end() && it->second.size() >= 2;
    }

    // Three-pointer-at-{0,8,16} pattern matches every flavour of
    // std::vector<T> on x86_64 — libstdc++ (`_M_start / _M_finish /
    // _M_end_of_storage`), libc++ (`__begin_ / __end_ / __end_cap_`),
    // and MSVC STL (`_Myfirst / _Mylast / _Myend`) all lay them out
    // at the same offsets. Any other 24-byte three-pointer struct
    // renders the same way, which is fine — these names read better
    // than `field_0 / field_8 / field_10` for *any* struct shaped
    // like a contiguous container.
    [[nodiscard]] bool looks_like_vector(const IrValue& base) const {
        auto k = ssa_key(base);
        if (!k) return false;
        auto it = struct_offsets.find(*k);
        if (it == struct_offsets.end()) return false;
        const auto& offs = it->second;
        // The full vector shape is exactly the three {ptr, end, capacity}
        // 8-byte slots — nothing else. The previous "contains" check fired
        // on any pointer whose accesses *included* {0, 8, 16}, so a 4 KB
        // jump-table initialised with `tbl[0]/[1]/[2]/[3]/...` got named
        // `tbl->begin/end/capacity/field_18/field_20/...` instead of
        // `tbl[0]/[1]/[2]/[3]/...`. Tightening to subset-equality blocks
        // that misfire while still recognising the genuine three-slot shape.
        if (offs.size() > 3) return false;
        for (i64 o : offs) {
            if (o != 0 && o != 8 && o != 16) return false;
        }
        return offs.contains(0) && offs.contains(8) && offs.contains(16);
    }

    void record_struct_access(const IrValue& addr) {
        auto bo = try_base_plus_offset(addr);
        if (!bo) return;
        // Skip stack-relative and global bases — those have richer rendering
        // paths already.
        if (stack_offset(bo->first).has_value()) return;
        if (auto k = ssa_key(bo->first); k) {
            struct_offsets[*k].insert(bo->second);
        }
    }

    // Pointer-indexing fold: `*(T*)(base + stride*N)` renders as `base[N]`
    // when base isn't stack- or global-relative. The stride must equal the
    // load width (so `*(u32*)(p + 4*N)` → `p[N]`); other strides keep their
    // explicit `*(T*)(addr)` form so the reader sees the actual byte arithmetic.
    // Negative offsets are accepted — backward array walks are common in
    // string scanners and trailing-byte readers, and `p[-1]` reads better
    // than `*(T*)(p - 8)`.
    [[nodiscard]] std::optional<std::string>
    try_render_array_index(const IrValue& addr, IrType t, int depth = 0) const {
        if (is_float_type(t)) return std::nullopt;
        const i64 stride = static_cast<i64>(type_bits(t) / 8);
        if (stride == 0) return std::nullopt;

        IrValue base = addr;
        i64     off  = 0;
        if (const IrInst* d = def_stripped(addr);
            d && (d->op == IrOp::Add || d->op == IrOp::Sub) && d->src_count >= 2) {
            const bool sub = (d->op == IrOp::Sub);
            if (auto r = resolve_imm(d->srcs[1])) {
                base = d->srcs[0];
                off  = sub ? -*r : *r;
            } else if (!sub) {
                if (auto l = resolve_imm(d->srcs[0])) {
                    base = d->srcs[1];
                    off  = *l;
                } else {
                    return std::nullopt;
                }
            } else {
                return std::nullopt;
            }
        }
        if (off % stride != 0) return std::nullopt;
        if (stack_offset(base).has_value()) return std::nullopt;
        if (base.kind != IrValueKind::Reg && base.kind != IrValueKind::Temp) {
            return std::nullopt;
        }
        // Reject when the base is itself an arithmetic combination — that's
        // the runtime-index pattern (`Add(Mul(idx, stride), Imm)` and friends),
        // not a real pointer base. Without this guard, `Load(Add(idx*8, &tbl))`
        // would render as the malformed `(idx*8)[&tbl/8]`. Let the runtime-
        // array path handle scaled indexing instead.
        if (const IrInst* bd = def_stripped(base);
            bd && (bd->op == IrOp::Mul || bd->op == IrOp::Shl ||
                   bd->op == IrOp::Add || bd->op == IrOp::Sub)) {
            return std::nullopt;
        }
        // Vector-shape pointer: defer to the struct-field path so the
        // 3 canonical offsets render as begin/end/capacity instead of
        // an array slice. argv-style ptr-to-ptr accesses don't touch
        // exactly {0, 8, 16} so they continue rendering as `a[i]`.
        if (looks_like_vector(base)) return std::nullopt;
        return std::format("{}[{}]", expr(base, depth + 1), off / stride);
    }

    // Runtime-indexed array form: `*(T*)(base + idx * stride)` and the
    // shift-encoded `*(T*)(base + (idx << k))` (compilers emit
    // `idx << 3` for stride-8 access). Renders as `base[idx]` when
    // the scale factor matches the access width — the same property
    // try_render_array_index uses for the constant-index case.
    // Foundation for STL-container recognition: `*(*v + i*4)` becomes
    // `(*v)[i]` once the inner deref is rendered cleanly.
    [[nodiscard]] std::optional<std::string>
    try_render_runtime_array_index(const IrValue& addr, IrType t,
                                    int depth = 0) const {
        if (is_float_type(t)) return std::nullopt;
        const i64 stride = static_cast<i64>(type_bits(t) / 8);
        if (stride <= 0) return std::nullopt;

        const IrInst* d = def_stripped(addr);
        if (!d || d->op != IrOp::Add || d->src_count < 2) return std::nullopt;

        // Try to spot a scaled-by-stride sub-expression on either side
        // of the Add. Returns (base, idx) on match.
        auto try_scale = [&](const IrValue& maybe_base,
                             const IrValue& maybe_scaled)
            -> std::optional<std::pair<IrValue, IrValue>> {
            const IrInst* m = def_stripped(maybe_scaled);
            if (!m) return std::nullopt;
            if (m->op == IrOp::Mul && m->src_count >= 2) {
                for (std::size_t i = 0; i < 2; ++i) {
                    if (auto r = resolve_imm(m->srcs[i]); r && *r == stride) {
                        return std::pair{maybe_base, m->srcs[1 - i]};
                    }
                }
            } else if (m->op == IrOp::Shl && m->src_count >= 2) {
                if (auto r = resolve_imm(m->srcs[1]);
                    r && *r >= 0 && *r < 63 && (i64{1} << *r) == stride) {
                    return std::pair{maybe_base, m->srcs[0]};
                }
            }
            return std::nullopt;
        };

        auto pair = try_scale(d->srcs[0], d->srcs[1]);
        if (!pair) pair = try_scale(d->srcs[1], d->srcs[0]);
        if (!pair) return std::nullopt;

        const IrValue& base = pair->first;
        const IrValue& idx  = pair->second;

        // Imm base: global pointer-table at a fixed address. Look up the
        // defining symbol; fall back to a typed hex cast. Without this,
        // `call qword ptr [idx*8 + 0x404020]` renders as garbage.
        if (base.kind == IrValueKind::Imm) {
            const auto a = static_cast<addr_t>(base.imm);
            if (binary) {
                if (const Symbol* s = binary->defined_object_at(a);
                    s && s->kind == SymbolKind::Object &&
                    !s->name.empty() &&
                    static_cast<addr_t>(s->addr) == a) {
                    return std::format("{}[{}]", s->name,
                                       expr(idx, depth + 1));
                }
            }
            return std::format("(({}*){:#x})[{}]", c_type_name(t),
                               static_cast<u64>(base.imm),
                               expr(idx, depth + 1));
        }

        if (stack_offset(base).has_value()) return std::nullopt;
        if (base.kind != IrValueKind::Reg && base.kind != IrValueKind::Temp) {
            return std::nullopt;
        }
        return std::format("{}[{}]",
            expr(base, depth + 1, std::to_underlying(Prec::Unary)),
            expr(idx,  depth + 1));
    }

    [[nodiscard]] std::string format_mem(const IrValue& addr, IrType t, Reg seg,
                                          int depth = 0) const {
        if (seg == Reg::None) {
            if (auto off = stack_offset(addr); off) {
                // Prefer the merged frame-layout name when one's been
                // resolved (PDB-derived); fall back to the synthetic
                // `local_<hex>` / `arg_<hex>` form otherwise.
                if (auto it = frame_layout.slots.find(*off);
                    it != frame_layout.slots.end() && !it->second.name.empty()) {
                    return it->second.name;
                }
                return stack_name(*off);
            }
            // Selref / classref loads: renders `*(u64*)(addr)` as its
            // source-level equivalent when the address lives in
            // __objc_selrefs / __objc_classrefs.
            if (t == IrType::I64) {
                if (auto imm = try_resolve_imm_addr(addr); imm) {
                    const addr_t a = static_cast<addr_t>(*imm);
                    if (options.objc_selrefs) {
                        auto it = options.objc_selrefs->find(a);
                        if (it != options.objc_selrefs->end()) {
                            return std::format("@selector({})", it->second);
                        }
                    }
                    if (options.objc_classrefs) {
                        auto it = options.objc_classrefs->find(a);
                        if (it != options.objc_classrefs->end()) {
                            return std::format("[{} class]", it->second);
                        }
                    }
                    // Pointer-to-string table entry: the bytes at this
                    // address form a u64 that itself points at a
                    // NUL-terminated printable string in the image (e.g.
                    // an R_X86_64_RELATIVE-relocated entry in .data.rel.ro
                    // pointing at .rodata). Surface the string content so
                    // crackme-style hex-table indirections read as their
                    // resolved literal.
                    if (binary) {
                        auto raw = binary->bytes_at(a);
                        if (raw.size() >= 8) {
                            u64 ptr = 0;
                            std::memcpy(&ptr, raw.data(), 8);
                            if (ptr >= 0x100) {
                                if (auto s = try_string_at(ptr); s) {
                                    return escape_string(*s);
                                }
                            }
                        }
                    }
                }
            }
            if (auto g = render_global_mem(addr, t); g) {
                return *g;
            }
            // Array-indexing form takes priority over the struct-field
            // rendering when both apply — u64 stride-8 accesses usually mean
            // "argv-style pointer-to-pointer", which reads more naturally
            // as `a[i]` than `a->field_N`.
            if (auto s = try_render_array_index(addr, t, depth); s) {
                return *s;
            }
            if (auto s = try_render_runtime_array_index(addr, t, depth); s) {
                return *s;
            }
            // Struct-field form: if this base has been observed at multiple
            // distinct offsets, render as base->field_<hex>. Width cast goes
            // inside the member expression so the reader still sees the
            // access type (`*(u32*)&obj->field_18`) when it differs from the
            // presumed u64 field default.
            if (auto bo = try_base_plus_offset(addr);
                bo && is_struct_pointer(bo->first)) {
                const IrValue& base = bo->first;
                const i64 off = bo->second;
                const std::string base_expr =
                    expr(base, depth + 1, std::to_underlying(Prec::Unary));
                // Vector-shape: i64 loads at the canonical {0, 8, 16}
                // offsets render as begin / end / capacity.
                if (t == IrType::I64 && looks_like_vector(base)) {
                    if (off == 0)  return std::format("{}->begin",    base_expr);
                    if (off == 8)  return std::format("{}->end",      base_expr);
                    if (off == 16) return std::format("{}->capacity", base_expr);
                }
                // Negative offsets (pointer adjusted above its struct base,
                // e.g. vtable slots at base-8) don't have clean C syntax;
                // fall back to the explicit cast form so we don't emit
                // garbage like `field_fffffffffffffff4`.
                if (off < 0) {
                    return std::format("*({}*)({} - {:#x})",
                                       c_type_name(t), base_expr,
                                       static_cast<u64>(-off));
                }
                if (t == IrType::I64) {
                    return std::format("{}->field_{:x}", base_expr,
                                       static_cast<u64>(off));
                }
                return std::format("*({}*)&{}->field_{:x}",
                                   c_type_name(t), base_expr,
                                   static_cast<u64>(off));
            }
            return std::format("*({}*)({})", c_type_name(t),
                               expr(addr, depth + 1));
        }
        // Well-known TIB/PEB constants: gs:[0x60] on x64 is the PEB pointer
        // and fs:[0x28] is the stack canary. PEB-walking malware,
        // anti-debug, and exception-handling crackmes lean on these
        // heavily; surfacing the names lets a reader recognise the
        // technique on sight instead of mentally re-mapping every load.
        if (auto imm = try_resolve_imm_addr(addr); imm) {
            const u64 off = static_cast<u64>(*imm);
            if (seg == Reg::Gs && t == IrType::I64) {
                if (off == 0x60) return "NtCurrentTeb()->ProcessEnvironmentBlock";
                if (off == 0x30) return "NtCurrentTeb()";
                if (off == 0x40) return "NtCurrentTeb()->ClientId.UniqueProcess";
                if (off == 0x48) return "NtCurrentTeb()->ClientId.UniqueThread";
                if (off == 0x18) return "NtCurrentTeb()->StackBase";
            }
            if (seg == Reg::Fs && t == IrType::I64 && off == 0x28) {
                return "__stack_chk_guard";
            }
        }
        return std::format("*({}*){}:[{}]",
                           c_type_name(t), reg_name(seg),
                           expr(addr, depth + 1));
    }

    [[nodiscard]] std::string format_binop(const IrInst& d, std::string_view op,
                                            int depth, int min_prec,
                                            Prec self_prec,
                                            bool commutative) const {
        const int p = static_cast<int>(self_prec);
        // Left operand can share our precedence (left-assoc). Right operand
        // of a non-commutative op must bind strictly tighter to avoid
        // reassociation — e.g. `a - (b - c)` must stay parenthesized.
        std::string L = expr(d.srcs[0], depth, p);
        std::string R = expr(d.srcs[1], depth, commutative ? p : p + 1);
        std::string result = std::format("{} {} {}", L, op, R);
        return wrap_if_lt(std::move(result), self_prec, min_prec);
    }

    // Bitwise &/|/^ rendering with mask-friendly imm handling:
    // negative power-of-2 boundary values render as `~0xN` (the
    // C-natural mask form) instead of `-0x{N+1}`, which is opaque
    // in a bitwise context. Always commutative — both operands
    // share the binop's precedence.
    [[nodiscard]] std::string format_bitop(const IrInst& d, std::string_view op,
                                            int depth, int min_prec,
                                            Prec self_prec) const {
        const int p = static_cast<int>(self_prec);
        auto render = [&](const IrValue& v) -> std::string {
            if (v.kind == IrValueKind::Imm && v.imm < 0) {
                const u64 absv =
                    static_cast<u64>(0) - static_cast<u64>(v.imm);
                if (absv >= 2 && (absv & (absv - 1)) == 0) {
                    return std::format("~{:#x}", absv - 1);
                }
            }
            return expr(v, depth, p);
        };
        std::string L = render(d.srcs[0]);
        std::string R = render(d.srcs[1]);
        return wrap_if_lt(std::format("{} {} {}", L, op, R),
                          self_prec, min_prec);
    }

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
    [[nodiscard]] static bool region_always_exits(const Region& r) noexcept {
        const Region* cur = &r;
        while (cur && cur->kind == RegionKind::Seq && !cur->children.empty()) {
            cur = cur->children.back().get();
        }
        if (!cur) return false;
        switch (cur->kind) {
            case RegionKind::Return:
            case RegionKind::Break:
            case RegionKind::Continue:
            case RegionKind::Unreachable:
            case RegionKind::Goto:
                return true;
            case RegionKind::IfElse:
                // Both arms must always exit for the if to always exit.
                return cur->children.size() >= 2 &&
                       cur->children[0] && cur->children[1] &&
                       region_always_exits(*cur->children[0]) &&
                       region_always_exits(*cur->children[1]);
            default:
                return false;
        }
    }
    void emit_region_while    (const Region& r, int depth, std::string& out) const;
    void emit_region_do_while (const Region& r, int depth, std::string& out) const;
    void emit_region_for      (const Region& r, int depth, std::string& out) const;
    void emit_region_return   (const Region& r, int depth, std::string& out) const;
    void emit_region_switch   (const Region& r, int depth, std::string& out) const;

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
    // implies one — the conditional / switch test, the return value,
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

    [[nodiscard]] const IrInst* def_stripped(const IrValue& v) const noexcept {
        const IrInst* d = def_of(v);
        while (d && d->op == IrOp::Assign && d->src_count == 1) {
            const IrInst* n = def_of(d->srcs[0]);
            if (!n) return d;
            d = n;
        }
        return d;
    }

    [[nodiscard]] bool same_ssa(const IrValue& a, const IrValue& b) const noexcept {
        if (a.kind != b.kind) return false;
        if (a.kind == IrValueKind::Imm) return a.imm == b.imm && a.type == b.type;
        return ssa_key(a) == ssa_key(b);
    }

    [[nodiscard]] std::optional<SubOps> match_sub_result(const IrValue& v) const {
        const IrInst* d = def_stripped(v);
        if (!d || d->op != IrOp::Sub || d->src_count < 2) return std::nullopt;
        return SubOps{d->srcs[0], d->srcs[1]};
    }

    [[nodiscard]] std::optional<SubOps> match_zf(const IrValue& v) const {
        const IrInst* d = def_stripped(v);
        if (!d || d->op != IrOp::CmpEq || d->src_count < 2) return std::nullopt;
        if (d->srcs[1].kind != IrValueKind::Imm || d->srcs[1].imm != 0) return std::nullopt;
        return match_sub_result(d->srcs[0]);
    }

    [[nodiscard]] std::optional<SubOps> match_sf(const IrValue& v) const {
        const IrInst* d = def_stripped(v);
        if (!d || d->op != IrOp::CmpSlt || d->src_count < 2) return std::nullopt;
        if (d->srcs[1].kind != IrValueKind::Imm || d->srcs[1].imm != 0) return std::nullopt;
        return match_sub_result(d->srcs[0]);
    }

    [[nodiscard]] std::optional<SubOps> match_cf(const IrValue& v) const {
        const IrInst* d = def_stripped(v);
        if (!d || d->op != IrOp::SubBorrow || d->src_count < 2) return std::nullopt;
        return SubOps{d->srcs[0], d->srcs[1]};
    }

    [[nodiscard]] std::optional<SubOps> match_of(const IrValue& v) const {
        const IrInst* d = def_stripped(v);
        if (!d || d->op != IrOp::SubOverflow || d->src_count < 2) return std::nullopt;
        return SubOps{d->srcs[0], d->srcs[1]};
    }

    [[nodiscard]] bool same_ops(const SubOps& x, const SubOps& y) const {
        return same_ssa(x.a, y.a) && same_ssa(x.b, y.b);
    }

    [[nodiscard]] std::optional<SubOps> match_sf_xor_of(const IrValue& v) const {
        const IrInst* d = def_stripped(v);
        if (!d || d->op != IrOp::Xor || d->src_count < 2) return std::nullopt;
        auto sf1 = match_sf(d->srcs[0]);
        auto of1 = match_of(d->srcs[1]);
        if (sf1 && of1 && same_ops(*sf1, *of1)) return *sf1;
        auto sf2 = match_sf(d->srcs[1]);
        auto of2 = match_of(d->srcs[0]);
        if (sf2 && of2 && same_ops(*sf2, *of2)) return *sf2;
        return std::nullopt;
    }

    [[nodiscard]] std::optional<SubOps> match_or_cf_zf(const IrValue& v) const {
        const IrInst* d = def_stripped(v);
        if (!d || d->op != IrOp::Or || d->src_count < 2) return std::nullopt;
        auto c1 = match_cf(d->srcs[0]); auto z1 = match_zf(d->srcs[1]);
        if (c1 && z1 && same_ops(*c1, *z1)) return *c1;
        auto c2 = match_cf(d->srcs[1]); auto z2 = match_zf(d->srcs[0]);
        if (c2 && z2 && same_ops(*c2, *z2)) return *c2;
        return std::nullopt;
    }

    [[nodiscard]] std::optional<SubOps> match_or_zf_sfxorof(const IrValue& v) const {
        const IrInst* d = def_stripped(v);
        if (!d || d->op != IrOp::Or || d->src_count < 2) return std::nullopt;
        auto z1 = match_zf(d->srcs[0]); auto x1 = match_sf_xor_of(d->srcs[1]);
        if (z1 && x1 && same_ops(*z1, *x1)) return *z1;
        auto z2 = match_zf(d->srcs[1]); auto x2 = match_sf_xor_of(d->srcs[0]);
        if (z2 && x2 && same_ops(*z2, *x2)) return *z2;
        return std::nullopt;
    }

    // Matches Not(v) and returns the inner operand (via def chain).
    [[nodiscard]] const IrInst* match_not(const IrValue& v) const {
        return def_stripped(v);
    }

    [[nodiscard]] std::optional<SubOps> match_and_notzf_notcf(const IrValue& v) const {
        const IrInst* d = def_stripped(v);
        if (!d || d->op != IrOp::And || d->src_count < 2) return std::nullopt;
        // Each operand should be Not(zf) or Not(cf)
        auto try_match = [&](const IrValue& left, const IrValue& right) -> std::optional<SubOps> {
            const IrInst* ld = def_stripped(left);
            const IrInst* rd = def_stripped(right);
            if (!ld || !rd) return std::nullopt;
            if (ld->op != IrOp::Not || rd->op != IrOp::Not) return std::nullopt;
            auto zf = match_zf(ld->srcs[0]);
            auto cf = match_cf(rd->srcs[0]);
            if (zf && cf && same_ops(*zf, *cf)) return *zf;
            return std::nullopt;
        };
        if (auto r = try_match(d->srcs[0], d->srcs[1]); r) return r;
        if (auto r = try_match(d->srcs[1], d->srcs[0]); r) return r;
        return std::nullopt;
    }

    [[nodiscard]] std::optional<SubOps> match_and_notzf_not_sfxorof(const IrValue& v) const {
        const IrInst* d = def_stripped(v);
        if (!d || d->op != IrOp::And || d->src_count < 2) return std::nullopt;
        auto try_match = [&](const IrValue& left, const IrValue& right) -> std::optional<SubOps> {
            const IrInst* ld = def_stripped(left);
            const IrInst* rd = def_stripped(right);
            if (!ld || !rd) return std::nullopt;
            if (ld->op != IrOp::Not || rd->op != IrOp::Not) return std::nullopt;
            auto zf = match_zf(ld->srcs[0]);
            auto xr = match_sf_xor_of(rd->srcs[0]);
            if (zf && xr && same_ops(*zf, *xr)) return *zf;
            return std::nullopt;
        };
        if (auto r = try_match(d->srcs[0], d->srcs[1]); r) return r;
        if (auto r = try_match(d->srcs[1], d->srcs[0]); r) return r;
        return std::nullopt;
    }

    [[nodiscard]] std::string render_cmp(std::string_view op, const IrValue& a,
                                         const IrValue& b, int depth,
                                         bool signed_cmp,
                                         bool in_bool_ctx = false,
                                         int min_prec = 0) const {
        // In boolean context, `x != 0` is spelled `x` and `x == 0` is `!x`.
        // Applies to either operand being an Imm(0). Strip casts on the
        // nonzero operand and recognise `xor(y, 1)` as a boolean negation
        // of `y`, so the compiler's `xor eax, 1; test al, al; jnz` lowering
        // of `if (!flag)` collapses from `if (!(u8)((u32)flag ^ 1))` back
        // to a plain `if (flag)` instead of leaving the bitwise-xor noise
        // visible at every is_open / is_eof / has_X check.
        if (in_bool_ctx && (op == "!=" || op == "==")) {
            const IrValue* nonzero = nullptr;
            if (a.kind == IrValueKind::Imm && a.imm == 0) nonzero = &b;
            else if (b.kind == IrValueKind::Imm && b.imm == 0) nonzero = &a;
            if (nonzero) {
                // Strip surrounding cast chain to find a `xor(y, 1)` core.
                IrValue core = *nonzero;
                for (int hop = 0; hop < 6; ++hop) {
                    const IrInst* d = def_stripped(core);
                    if (!d) break;
                    if (d->op == IrOp::ZExt || d->op == IrOp::SExt ||
                        d->op == IrOp::Trunc) {
                        if (d->src_count < 1) break;
                        core = d->srcs[0];
                        continue;
                    }
                    break;
                }
                if (const IrInst* dx = def_stripped(core);
                    dx && dx->op == IrOp::Xor && dx->src_count == 2) {
                    const IrValue& a2 = dx->srcs[0];
                    const IrValue& b2 = dx->srcs[1];
                    const IrValue* y = nullptr;
                    if (a2.kind == IrValueKind::Imm && a2.imm == 1) y = &b2;
                    else if (b2.kind == IrValueKind::Imm && b2.imm == 1) y = &a2;
                    if (y) {
                        // `(xor(y, 1) == 0)` ⇔ `y` (truthy when bit 0 set).
                        // `(xor(y, 1) != 0)` ⇔ `!y`. The conclusion holds
                        // exactly when y ∈ {0, 1}; any other value would
                        // never have led the compiler to emit the
                        // `xor reg, 1` idiom in the first place.
                        if (op == "==") {
                            return expr(*y, depth + 1, min_prec);
                        }
                        std::string rendered = expr(*y, depth + 1,
                                                    std::to_underlying(Prec::Unary));
                        return wrap_if_lt("!" + rendered, Prec::Unary, min_prec);
                    }
                }
                if (op == "!=") {
                    return expr(*nonzero, depth + 1, min_prec);
                }
                std::string rendered = expr(*nonzero, depth + 1,
                                            std::to_underlying(Prec::Unary));
                return wrap_if_lt("!" + rendered, Prec::Unary, min_prec);
            }
        }
        const Prec own = (op == "==" || op == "!=") ? Prec::Eq : Prec::Rel;
        const int p = std::to_underlying(own);
        const std::string_view c = "i64";
        const bool cast_l = signed_cmp && a.kind != IrValueKind::Imm;
        const bool cast_r = signed_cmp && b.kind != IrValueKind::Imm;
        // If we're going to wrap in `(i64)`, the inner must bind at Unary;
        // otherwise the compare's own precedence is enough.
        const int lp = cast_l ? std::to_underlying(Prec::Unary) : p;
        const int rp = cast_r ? std::to_underlying(Prec::Unary) : p + 1;
        auto cmp_expr = [&](const IrValue& v, int prec) {
            return v.kind == IrValueKind::Imm
                ? format_numeric_imm(v)
                : expr(v, depth + 1, prec);
        };
        std::string left  = cmp_expr(a, lp);
        std::string right = cmp_expr(b, rp);
        if (cast_l) left  = std::format("({}){}", c, left);
        if (cast_r) right = std::format("({}){}", c, right);
        return wrap_if_lt(std::format("{} {} {}", left, op, right), own, min_prec);
    }

    // `negate`: emit the semantic NOT of the matched compare (e.g., Je → ==, with negate → !=).
    // This cleanly cancels double-negation when the structurer wraps a CondBranch that
    // was itself a Not-of-flag.
    // `in_bool_ctx`: caller is rendering an `if`/`while` condition, so `x != 0`
    // can collapse to `x` and `x == 0` to `!x`.
    [[nodiscard]] std::optional<std::string>
    try_simplify_flag(const IrValue& v, int depth, bool negate = false,
                      bool in_bool_ctx = false, int min_prec = 0) const {
        if (depth >= 12) return std::nullopt;
        if (v.type != IrType::I1) return std::nullopt;

        auto emit_sub = [&](std::string_view op, std::string_view neg_op,
                            const SubOps& s, bool sign_cmp) {
            return render_cmp(negate ? neg_op : op, s.a, s.b, depth, sign_cmp,
                              in_bool_ctx, min_prec);
        };
        auto emit_cmp = [&](std::string_view op, std::string_view neg_op,
                            const IrValue& a, const IrValue& b, bool sign_cmp) {
            return render_cmp(negate ? neg_op : op, a, b, depth, sign_cmp,
                              in_bool_ctx, min_prec);
        };

        // Compound sub-flag patterns (most specific first)
        if (auto s = match_sf_xor_of(v); s)              return emit_sub("<",  ">=", *s, true);
        if (auto s = match_or_cf_zf(v); s)               return emit_sub("<=", ">",  *s, false);
        if (auto s = match_or_zf_sfxorof(v); s)          return emit_sub("<=", ">",  *s, true);
        if (auto s = match_and_notzf_notcf(v); s)        return emit_sub(">",  "<=", *s, false);
        if (auto s = match_and_notzf_not_sfxorof(v); s)  return emit_sub(">",  "<=", *s, true);

        const IrInst* d = def_stripped(v);

        // Not(x): recurse with flipped negate (cancels double-negation cleanly).
        if (d && d->op == IrOp::Not && d->src_count == 1) {
            if (auto r = try_simplify_flag(d->srcs[0], depth + 1, !negate,
                                           in_bool_ctx, min_prec);
                r) return r;
        }

        // Atomic sub-flag patterns
        if (auto s = match_zf(v); s) return emit_sub("==", "!=", *s, false);
        if (auto s = match_cf(v); s) return emit_sub("<",  ">=", *s, false);

        // Direct Cmp* ops (with negate, emit complementary)
        if (d && d->src_count >= 2) {
            switch (d->op) {
                case IrOp::CmpEq:  return emit_cmp("==", "!=", d->srcs[0], d->srcs[1], false);
                case IrOp::CmpNe:  return emit_cmp("!=", "==", d->srcs[0], d->srcs[1], false);
                case IrOp::CmpSlt: return emit_cmp("<",  ">=", d->srcs[0], d->srcs[1], true);
                case IrOp::CmpSle: return emit_cmp("<=", ">",  d->srcs[0], d->srcs[1], true);
                case IrOp::CmpSgt: return emit_cmp(">",  "<=", d->srcs[0], d->srcs[1], true);
                case IrOp::CmpSge: return emit_cmp(">=", "<",  d->srcs[0], d->srcs[1], true);
                case IrOp::CmpUlt: return emit_cmp("<",  ">=", d->srcs[0], d->srcs[1], false);
                case IrOp::CmpUle: return emit_cmp("<=", ">",  d->srcs[0], d->srcs[1], false);
                case IrOp::CmpUgt: return emit_cmp(">",  "<=", d->srcs[0], d->srcs[1], false);
                case IrOp::CmpUge: return emit_cmp(">=", "<",  d->srcs[0], d->srcs[1], false);
                default: break;
            }
        }

        return std::nullopt;
    }

    [[nodiscard]] std::string render_condition(const IrValue& v, bool invert) const {
        // Condition is rendered into `if (...)`, so no outer wrapping needed.
        if (auto s = try_simplify_flag(v, 0, invert, /*in_bool_ctx=*/true, 0); s) return *s;
        if (invert) {
            std::string base = expr(v, 0, std::to_underlying(Prec::Unary));
            return std::format("!{}", base);
        }
        return expr(v, 0, 0);
    }
};

std::string Emitter::expr(const IrValue& v, int depth, int min_prec) const {
    // Recognize compiler flag-based compare idioms and emit direct C comparisons.
    if (v.type == IrType::I1 &&
        (v.kind == IrValueKind::Temp || v.kind == IrValueKind::Flag)) {
        if (auto s = try_simplify_flag(v, depth, false, false, min_prec); s) return *s;
    }
    switch (v.kind) {
        case IrValueKind::None:
            return "";
        case IrValueKind::Reg: {
            // For versioned regs, inline a trivial Imm assignment — lets the
            // absorbed call() show the actual constant instead of an orphan reg name.
            if (v.version > 0 && depth < kMaxExprDepth) {
                const IrInst* d = def_of(v);
                while (d && d->op == IrOp::Assign && d->src_count == 1) {
                    const auto& src = d->srcs[0];
                    if (src.kind == IrValueKind::Imm) return expr(src, depth + 1, min_prec);
                    if (src.kind == IrValueKind::Reg && src.version == 0) {
                        return render_reg_leaf(src.reg, src.version, depth + 1);
                    }
                    break;
                }
            }
            return render_reg_leaf(v.reg, v.version, depth);
        }
        case IrValueKind::Flag:
            return std::string(flag_name(v.flag));
        case IrValueKind::Imm:
            return format_imm(v);
        case IrValueKind::Temp: {
            // A temp whose value is a stack-relative address renders as &local_X
            // at every use, so we don't need a named def line like "u64 tN = &local_X;".
            if (auto off = stack_offset(v); off) {
                return std::format("&{}", stack_name(*off));
            }
            if (depth < kMaxExprDepth && should_inline(v)) {
                if (const auto* d = def_of(v)) return expand(*d, depth + 1, min_prec);
            }
            return std::format("t{}", v.temp);
        }
    }
    return "";
}

std::string Emitter::expand(const IrInst& d, int depth, int min_prec) const {
    switch (d.op) {
        case IrOp::Assign:
            return d.src_count >= 1 ? expr(d.srcs[0], depth, min_prec) : "";

        case IrOp::Add: {
            if (auto off = stack_offset(IrValue::make_temp(d.dst.temp, d.dst.type)); off) {
                return std::format("&{}", stack_name(*off));
            }
            // `Add(x, negative_imm)` reads cleaner as `Sub(x, |imm|)`:
            // `a - 7` beats `a + -7`. Skip INT64_MIN (no safe negation).
            if (d.src_count >= 2 && d.srcs[1].kind == IrValueKind::Imm &&
                d.srcs[1].imm < 0 &&
                d.srcs[1].imm > std::numeric_limits<i64>::min()) {
                IrInst rebuilt = d;
                rebuilt.op           = IrOp::Sub;
                rebuilt.srcs[1].imm  = -d.srcs[1].imm;
                return format_binop(rebuilt, "-", depth, min_prec,
                                    Prec::Add, /*commutative=*/false);
            }
            return format_binop(d, "+", depth, min_prec, Prec::Add, /*commutative=*/true);
        }
        case IrOp::Sub: {
            if (auto off = stack_offset(IrValue::make_temp(d.dst.temp, d.dst.type)); off) {
                return std::format("&{}", stack_name(*off));
            }
            return format_binop(d, "-", depth, min_prec, Prec::Add, /*commutative=*/false);
        }
        case IrOp::Mul:  return format_binop(d, "*", depth, min_prec, Prec::Mul,   true);
        case IrOp::Div:  return format_binop(d, "/", depth, min_prec, Prec::Mul,   false);
        case IrOp::Mod:  return format_binop(d, "%", depth, min_prec, Prec::Mul,   false);
        case IrOp::And:  return format_bitop(d, "&", depth, min_prec, Prec::BitAnd);
        case IrOp::Or:   return format_bitop(d, "|", depth, min_prec, Prec::BitOr);
        case IrOp::Xor:  return format_bitop(d, "^", depth, min_prec, Prec::BitXor);
        case IrOp::Shl:  return format_binop(d, "<<", depth, min_prec, Prec::Shift, false);
        case IrOp::Lshr: return format_binop(d, ">>", depth, min_prec, Prec::Shift, false);
        case IrOp::Ashr: return format_binop(d, ">>", depth, min_prec, Prec::Shift, false);

        case IrOp::Neg: {
            std::string inner = expr(d.srcs[0], depth, std::to_underlying(Prec::Unary));
            return wrap_if_lt("-" + inner, Prec::Unary, min_prec);
        }
        case IrOp::Not: {
            const char* op = (d.dst.type == IrType::I1) ? "!" : "~";
            std::string inner = expr(d.srcs[0], depth, std::to_underlying(Prec::Unary));
            return wrap_if_lt(std::string(op) + inner, Prec::Unary, min_prec);
        }

        case IrOp::CmpEq:  return format_binop(d, "==", depth, min_prec, Prec::Eq,  true);
        case IrOp::CmpNe:  return format_binop(d, "!=", depth, min_prec, Prec::Eq,  true);
        case IrOp::CmpSlt:
        case IrOp::CmpUlt: return format_binop(d, "<",  depth, min_prec, Prec::Rel, false);
        case IrOp::CmpSle:
        case IrOp::CmpUle: return format_binop(d, "<=", depth, min_prec, Prec::Rel, false);
        case IrOp::CmpSgt:
        case IrOp::CmpUgt: return format_binop(d, ">",  depth, min_prec, Prec::Rel, false);
        case IrOp::CmpSge:
        case IrOp::CmpUge: return format_binop(d, ">=", depth, min_prec, Prec::Rel, false);

        case IrOp::ZExt:
        case IrOp::SExt:
        case IrOp::Trunc: {
            const IrValue& src = d.srcs[0];
            // No-op: cast to the same type the value already has.
            if (src.type == d.dst.type) {
                return expr(src, depth, min_prec);
            }
            // A generated source-level parameter name is already a semantic
            // value, not an architectural register width. When a call
            // argument was packed as zext(trunc(param)), render the param
            // directly instead of `(u32)x`.
            if ((d.op == IrOp::ZExt || d.op == IrOp::SExt) &&
                (type_bits(d.dst.type) > type_bits(src.type))) {
                if (const IrInst* inner = def_stripped(src);
                    inner && inner->op == IrOp::Trunc && inner->src_count >= 1) {
                    if (auto slot = trace_to_self_arg_slot(inner->srcs[0]);
                        slot && *slot < self_arg_names.size() &&
                        !self_arg_names[*slot].empty()) {
                        return expr(inner->srcs[0], depth, min_prec);
                    }
                }
            }
            // The call-result inliner already proved this call has exactly
            // one use inside this return expression. If the compiler then
            // narrows it for a 32-bit add, prefer `foo(x) + 1` over
            // `(u32)foo(x) + 1`; the source-level call carries the intent.
            if (d.op == IrOp::Trunc) {
                if (auto k = ssa_key(src); k && inline_call_expr.contains(*k)) {
                    return expr(src, depth, min_prec);
                }
            }
            // `zext(trunc(x, T))` → `(T)x`. The trunc already produces the
            // observable value; widening back to a bigger type is redundant
            // for the reader.
            if (d.op == IrOp::ZExt) {
                if (const IrInst* inner = def_stripped(src);
                    inner && inner->op == IrOp::Trunc && inner->src_count >= 1 &&
                    type_bits(inner->dst.type) <= type_bits(d.dst.type)) {
                    std::string casted = std::format(
                        "({}){}",
                        c_type_name(inner->dst.type),
                        expr(inner->srcs[0], depth, std::to_underlying(Prec::Unary)));
                    return wrap_if_lt(std::move(casted), Prec::Unary, min_prec);
                }
            }
            std::string casted = std::format(
                "({}){}",
                c_type_name(d.dst.type),
                expr(src, depth, std::to_underlying(Prec::Unary)));
            return wrap_if_lt(std::move(casted), Prec::Unary, min_prec);
        }

        case IrOp::Load: {
            // Init-only stack slot: forward to the live-in value the entry
            // prologue stored. Lets `local_28 = a2; ... use local_28 ...`
            // collapse to the user-level `... use a2 ...` directly.
            if (d.segment == Reg::None && d.src_count >= 1) {
                if (auto off = stack_offset(d.srcs[0]); off) {
                    if (auto it = init_only_slot_value.find(*off);
                        it != init_only_slot_value.end()) {
                        return expr(it->second, depth, min_prec);
                    }
                }
            }
            return format_mem(d.srcs[0], d.dst.type, d.segment, depth);
        }

        case IrOp::AddCarry:
            return std::format("carry_add({}, {})",
                               expr(d.srcs[0], depth, 0), expr(d.srcs[1], depth, 0));
        case IrOp::SubBorrow:
            return std::format("borrow_sub({}, {})",
                               expr(d.srcs[0], depth, 0), expr(d.srcs[1], depth, 0));
        case IrOp::AddOverflow:
            return std::format("overflow_add({}, {})",
                               expr(d.srcs[0], depth, 0), expr(d.srcs[1], depth, 0));
        case IrOp::SubOverflow:
            return std::format("overflow_sub({}, {})",
                               expr(d.srcs[0], depth, 0), expr(d.srcs[1], depth, 0));

        case IrOp::Intrinsic: {
            std::string args;
            for (u8 i = 0; i < d.src_count && i < d.srcs.size(); ++i) {
                if (i > 0) args += ", ";
                args += expr(d.srcs[i], depth, 0);
            }
            return std::format("{}({})", d.name, args);
        }

        case IrOp::Select: {
            if (d.src_count < 3) return std::format("t{}", d.dst.temp);
            // C's `?:` precedence sits above assignment but below most other
            // operators; wrap in parens whenever the surrounding context isn't
            // already paren-bounded so the reader doesn't have to think.
            std::string c = expr(d.srcs[0], depth, std::to_underlying(Prec::LogOr));
            std::string a = expr(d.srcs[1], depth, std::to_underlying(Prec::Cond));
            std::string b = expr(d.srcs[2], depth, std::to_underlying(Prec::Cond));
            return wrap_if_lt(std::format("{} ? {} : {}", c, a, b),
                              Prec::Cond, min_prec);
        }

        default:
            return std::format("t{}", d.dst.temp);
    }
}

// Peephole: `store addr, (op load(addr), K)` → `<name> += K;` / `--name;` etc.
// `lhs_text` is the already-rendered name of the storage location (stack,
// global, or `*(T*)…`). Returns empty if no idiom match; caller falls back
// to `lhs = expr;`.
std::string Emitter::try_compound_store(std::string_view lhs_text,
                                        const IrValue& addr,
                                        const IrValue& val) const {
    // val must be a binary op we know how to compound-assign.
    const IrInst* d = def_stripped(val);
    if (!d || d->src_count < 2) return {};

    std::string_view op_text;
    switch (d->op) {
        case IrOp::Add:  op_text = "+"; break;
        case IrOp::Sub:  op_text = "-"; break;
        case IrOp::Mul:  op_text = "*"; break;
        case IrOp::And:  op_text = "&"; break;
        case IrOp::Or:   op_text = "|"; break;
        case IrOp::Xor:  op_text = "^"; break;
        case IrOp::Shl:  op_text = "<<"; break;
        case IrOp::Lshr: op_text = ">>"; break;
        case IrOp::Ashr: op_text = ">>"; break;
        default: return {};
    }

    // LHS of the binop must be a Load of the same storage as `addr`. For
    // commutative ops we also accept the RHS as the load.
    const bool commutative = d->op == IrOp::Add || d->op == IrOp::Mul ||
                             d->op == IrOp::And || d->op == IrOp::Or  ||
                             d->op == IrOp::Xor;

    auto is_load_of_same_addr = [&](const IrValue& v) {
        const IrInst* ld = def_stripped(v);
        if (!ld || ld->op != IrOp::Load || ld->src_count < 1) return false;
        return same_ssa(ld->srcs[0], addr);
    };

    const IrValue* delta = nullptr;
    if (is_load_of_same_addr(d->srcs[0])) {
        delta = &d->srcs[1];
    } else if (commutative && is_load_of_same_addr(d->srcs[1])) {
        delta = &d->srcs[0];
    } else {
        return {};
    }

    // Integer +/- 1 collapses further to ++/--.
    if ((d->op == IrOp::Add || d->op == IrOp::Sub) &&
        delta->kind == IrValueKind::Imm && delta->imm == 1 &&
        !is_float_type(val.type)) {
        const char* sym = (d->op == IrOp::Add) ? "++" : "--";
        return std::format("{}{};", lhs_text, sym);
    }
    return std::format("{} {}= {};", lhs_text, op_text, expr(*delta));
}

std::string Emitter::format_store(const IrInst& inst) const {
    if (inst.src_count < 2) return "";
    const auto& addr = inst.srcs[0];
    const auto& val  = inst.srcs[1];
    std::string lhs;
    if (inst.segment == Reg::None) {
        if (auto off = stack_offset(addr); off) {
            // Dead-spill suppression: drop the store when the slot has no
            // observable reader in the rendered output. Two cases collapse
            // here: (1) no Load anywhere reads the slot (common -O0 spill-
            // and-forget prologue noise), and (2) every load is an init-
            // only forward to the original arg-reg, so the slot's name
            // never appears in the body. Exception: slots whose name came
            // from an external source (PDB S_REGREL32, sidecar annotation)
            // carry source-level intent — keep their stores so the user's
            // named locals don't silently disappear.
            const bool has_reader = loaded_stack_slots.contains(*off);
            const bool init_only  = init_only_slot_value.contains(*off);
            if (!has_reader || init_only) {
                auto it = frame_layout.slots.find(*off);
                const bool user_named =
                    it != frame_layout.slots.end() &&
                    !it->second.type_override.empty();
                if (!user_named) return "";
            }
            if (auto it = frame_layout.slots.find(*off);
                it != frame_layout.slots.end() && !it->second.name.empty()) {
                lhs = it->second.name;
            } else {
                lhs = stack_name(*off);
            }
        }
    }
    if (lhs.empty()) {
        lhs = format_mem(addr, val.type, inst.segment);
    }
    if (auto compound = try_compound_store(lhs, addr, val); !compound.empty()) {
        return compound;
    }
    return std::format("{} = {};", lhs, expr(val));
}

std::string Emitter::format_stmt(const IrInst& inst) const {
    switch (inst.op) {
        case IrOp::Store:
            return format_store(inst);

        case IrOp::Assign: {
            if (inst.src_count < 1) return "";
            if (inst.dst.kind == IrValueKind::Reg) {
                // With rvalue forwarding in render_reg_leaf, a single reader
                // inlines the source expression directly. The `reg = expr;`
                // line becomes redundant in that case.
                //
                // Exception: a Reg assign whose only readers are Phi
                // operands is the per-iteration update of a loop induction
                // variable — visible_use_count excludes phi reads, so the
                // count looks like 0 even though the value drives the loop.
                // Without surfacing the assign, accumulator loops decompile
                // to `do { } while (cond)` with the body work invisible.
                // Detect by comparing visible_uses (excludes phi) to the
                // broader uses-table count (includes phi).
                if (visible_use_count(inst.dst) <= 1) {
                    auto k = ssa_key(inst.dst);
                    const u32 vis = visible_use_count(inst.dst);
                    const u32 all = k ? use_count_by_key(*k) : 0u;
                    if (all <= vis) return "";
                }
                return std::format("{} = {};",
                                   reg_name(inst.dst.reg), expr(inst.srcs[0]));
            }
            if (inst.dst.kind == IrValueKind::Flag) {
                if (use_count(inst.dst) == 0) return "";
                return std::format("{} = {};",
                                   flag_name(inst.dst.flag), expr(inst.srcs[0]));
            }
            if (inst.dst.kind == IrValueKind::Temp) {
                if (use_count(inst.dst) <= 1) return "";
                return std::format("{} t{} = {};",
                                   c_type_name_for(inst.dst),
                                   inst.dst.temp,
                                   expr(inst.srcs[0]));
            }
            return "";
        }

        case IrOp::Load: {
            if (use_count(inst.dst) == 0) return "";
            if (use_count(inst.dst) == 1) return "";  // will be inlined
            // A multi-use load that should_inline accepts (stack-slot
            // reads, init-only forwards) renders inline at every use site
            // — no need to bind a name for it here.
            if (should_inline(inst.dst)) return "";
            return std::format("{} t{} = {};",
                               c_type_name_for(inst.dst),
                               inst.dst.temp,
                               format_mem(inst.srcs[0], inst.dst.type, inst.segment));
        }

        case IrOp::Intrinsic: {
            // CET markers are emitted at every function entry on toolchains
            // with -fcf-protection (Ubuntu 24.04's gcc-14 defaults to it).
            // They're NOPs semantically, so suppress them from the output.
            if (inst.name == "endbr64" || inst.name == "endbr32") return "";
            std::string args;
            for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                if (i > 0) args += ", ";
                args += expr(inst.srcs[i], 0, 0);
            }
            // `x64.*` tags a raw x86 mnemonic the lifter couldn't model
            // in the IR (SIMD, FPU, system ops). Render it as a block
            // comment so the reader sees the elision rather than an
            // imaginary C call. The rest — explicit intrinsics like
            // `sqrtss(x)` that the lifter emits deliberately — stay as
            // calls because they carry real dataflow.
            if (inst.name.starts_with("x64.")) {
                return std::format("/* {}({}) */", inst.name, args);
            }
            // If the intrinsic produces a value that survives downstream,
            // bind it to a named temp so subsequent reads have something
            // to refer to. Otherwise emit as a void statement.
            if (inst.dst.kind == IrValueKind::Temp &&
                visible_use_count(inst.dst) > 0) {
                return std::format("{} t{} = {}({});",
                                   c_type_name_for(inst.dst),
                                   inst.dst.temp,
                                   inst.name, args);
            }
            return std::format("{}({});", inst.name, args);
        }

        default:
            if (inlinable_op(inst.op) && inst.dst.kind == IrValueKind::Temp) {
                if (visible_use_count(inst.dst) <= 1) return "";
                if (stack_offset(inst.dst).has_value()) return "";
                // Suppress the declaration when this temp's only consumers
                // are flag-set instructions — those will inline the
                // expression when they themselves render.
                if (is_flag_feeder_temp(inst.dst)) return "";
                return std::format("{} t{} = {};",
                                   c_type_name_for(inst.dst),
                                   inst.dst.temp,
                                   expand(inst, 0));
            }
            return "";
    }
}

void Emitter::emit_call_binding(std::string& out, std::string_view ind,
                                std::pair<std::size_t, std::size_t> pos,
                                const std::string& call_expr,
                                bool result_is_void) const {
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
        std::string type_name = "u64";
        if (auto df = defs.find(bk->second); df != defs.end()) {
            type_name = c_type_name_for(df->second->dst);
        }
        if (options.line_map) {
            options.line_map->hits.push_back({out.size(), src});
        }
        out += std::format("{}{} {} = {};\n", ind, type_name,
                           call_return_names.at(bk->second), call_expr);
        return;
    }
    if (options.line_map) {
        options.line_map->hits.push_back({out.size(), src});
    }
    out += std::format("{}{};\n", ind, call_expr);
}

void Emitter::emit_block(addr_t block_addr, int depth, std::string& out) const {
    auto it = fn->block_at.find(block_addr);
    if (it == fn->block_at.end()) return;
    const auto& bb = fn->blocks[it->second];

    const std::string ind(static_cast<std::size_t>(depth) * 2u, ' ');
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

    std::vector<IrValue> pending_args;
    bool                 have_pending = false;

    auto flush_args_as_intrinsics = [&]() {
        if (have_pending) {
            out += std::format("{}// stray call.args: {} values\n",
                               ind, pending_args.size());
            pending_args.clear();
            have_pending = false;
        }
    };

    // Fallback for callees with no known arity: drop args that look stale
    // (live-in regs the caller never set, or regs whose most recent def is
    // a Clobber from an earlier call).
    auto format_call_args_fallback = [&](const std::vector<IrValue>& args) {
        std::string s;
        bool first = true;
        for (const auto& a : args) {
            if (is_stale_arg_reg(a)) continue;
            if (!first) s += ", ";
            s += expr(a);
            first = false;
        }
        return s;
    };

    // When we know the callee's arity, show up to that many args. Trim
    // trailing args that are provably stale ABI register pass-throughs:
    // live-ins the caller never set, or values whose only local def is a
    // call-clobber marker. This used to happen only for max-arity guesses,
    // but stripped callees can infer a smaller concrete arity from noisy
    // register reads; printing `foo(a1, rdx_4, rcx_3)` is worse than
    // admitting the trailing values were not real caller-provided args.
    auto format_call_args_with_arity = [&](const std::vector<IrValue>& args, u8 arity) {
        std::size_t limit = std::min<std::size_t>(arity, args.size());
        while (limit > 0 &&
               (is_stale_arg_reg(args[limit - 1]) ||
                renders_raw_arch_reg_name(args[limit - 1]))) {
            --limit;
        }
        std::string s;
        for (std::size_t i = 0; i < limit; ++i) {
            if (i > 0) s += ", ";
            s += expr(args[i]);
        }
        return s;
    };

    for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
        const auto& inst = bb.insts[ii];
        // Skip ABI-noise prologue/epilogue insts detected during analysis.
        if (hidden.contains({it->second, ii})) continue;
        // Skip the for-loop update statement; it'll render in the for-header.
        if (for_update_positions.contains({it->second, ii})) continue;
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

        if (inst.op == IrOp::Intrinsic && inst.name == "call.args.1") {
            pending_args.clear();
            for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                pending_args.push_back(inst.srcs[i]);
            }
            have_pending = true;
            continue;
        }
        if (inst.op == IrOp::Intrinsic &&
            (inst.name == "call.args.2" || inst.name == "call.args.3")) {
            for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                pending_args.push_back(inst.srcs[i]);
            }
            continue;
        }

        if (inst.op == IrOp::Call) {
            for (const auto& a : pending_args) {
                emit_materializations_for_value(a, 0, out, ind);
            }
            auto import_name = import_name_for_direct_call(inst.target1);
            // Arity sources: imports → user sig at PLT / baked-in libc table;
            // printf/scanf family → parse format string to count args;
            // defined functions → infer_sysv_arity. No arity known → fallback
            // drops stale-looking args.
            std::optional<u8> arity;
            if (import_name) {
                arity = import_arity(inst.target1, *import_name);
                if (!arity) {
                    if (auto fi = variadic_format_index(*import_name); fi) {
                        arity = variadic_arity(pending_args, *fi);
                    }
                }
            } else {
                arity = cached_arity(inst.target1);
            }
            const std::string args = arity
                ? format_call_args_with_arity(pending_args, *arity)
                : format_call_args_fallback(pending_args);
            pending_args.clear();
            have_pending = false;
            const std::string callee = import_name
                ? *import_name
                : function_display_name(inst.target1);
            const std::string call_expr = std::format("{}({})", callee, args);
            emit_call_binding(out, ind, std::pair{it->second, ii}, call_expr,
                              import_returns_void(callee));
            continue;
        }
        if (inst.op == IrOp::CallIndirect) {
            if (inst.src_count < 1) {
                pending_args.clear();
                have_pending = false;
                out += std::format("{}(*?)();\n", ind);
                continue;
            }
            emit_materializations_for_value(inst.srcs[0], 0, out, ind);
            for (const auto& a : pending_args) {
                emit_materializations_for_value(a, 0, out, ind);
            }
            std::string call_expr;
            if (auto name = import_name_for_indirect_call(inst.srcs[0]); name) {
                // No PLT address here, so user-sig lookup can't key off one.
                auto arity = libc_arity_by_name(*name);
                if (!arity) {
                    if (auto fi = variadic_format_index(*name); fi) {
                        arity = variadic_arity(pending_args, *fi);
                    }
                }
                const std::string args = arity
                    ? format_call_args_with_arity(pending_args, *arity)
                    : format_call_args_fallback(pending_args);
                call_expr = std::format("{}({})", *name, args);
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
                    const auto direct_import = import_name_for_direct_call(target);
                    if (direct_import) {
                        arity = import_arity(target, *direct_import);
                        if (!arity) {
                            if (auto fi = variadic_format_index(*direct_import); fi) {
                                arity = variadic_arity(pending_args, *fi);
                            }
                        }
                    } else if (annotations) {
                        if (const FunctionSig* sig = annotations->signature_for(target); sig) {
                            arity = static_cast<u8>(sig->params.size());
                        }
                    }
                    if (!arity && !direct_import) {
                        arity = cached_arity(target);
                    }
                    const std::string args = arity
                        ? format_call_args_with_arity(pending_args, *arity)
                        : format_call_args_fallback(pending_args);
                    call_expr = std::format("{}({}){}",
                                            fname, args,
                                            observed_targets_comment(inst.source_addr));
                }
            }
            if (call_expr.empty()) {
                const std::string args = format_call_args_fallback(pending_args);
                // Virtual-method-dispatch shape recognition: when the
                // call target traces back as `Load(Add(Load(<recv>), K))`
                // — i.e., load vptr from receiver, add slot offset,
                // load method pointer — render as `<recv>->vfn_<K/8>(args)`.
                // This is what every C++ `obj->method()` compiles to,
                // and IPA isn't required to recognise the shape; type
                // info would only refine the slot to a real class
                // method name. Fixed-base `Load(Add(<rip-rel-vtable>, K))`
                // is already covered by the call_resolutions path above
                // (--resolve-calls); this handles the per-instance case.
                if (auto vt = try_render_vfn_dispatch(inst.srcs[0]); vt) {
                    call_expr = std::format("{}({})", *vt, args);
                } else {
                    // Fall back to the textual `(*expr)(args)` form. When
                    // expr already starts with `*`, paren-wrap to avoid
                    // a double-deref read.
                    const std::string tgt =
                        expr(inst.srcs[0], 0, std::to_underlying(Prec::Postfix));
                    if (!tgt.empty() && tgt.front() == '*') {
                        call_expr = std::format("(*{})({})", expr(inst.srcs[0]), args);
                    } else {
                        call_expr = std::format("{}({})", tgt, args);
                    }
                }
            }
            pending_args.clear();
            have_pending = false;
            const auto resolved_name = import_name_for_indirect_call(inst.srcs[0]);
            const bool is_void = resolved_name && import_returns_void(*resolved_name);
            emit_call_binding(out, ind, std::pair{it->second, ii}, call_expr,
                              is_void);
            continue;
        }

        emit_materializations_for_inst(inst, out, ind);
        const std::string stmt = format_stmt(inst);
        if (!stmt.empty()) {
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
                    auto has_local_def = [&](const IrValue& v) {
                        auto k = ssa_key(v);
                        return k && defs.find(*k) != defs.end();
                    };
                    if (!has_local_def(term->srcs[0]) &&
                        has_local_def(term->srcs[1])) {
                        pick = 1;
                    }
                }
                const IrValue& rv = term->srcs[pick];

                if (auto k = ssa_key(rv); k) {
                    auto s = fold_void_call_stmt.find(*k);
                    if (s != fold_void_call_stmt.end()) {
                        out += std::format("{}{};\n", ind, s->second);
                        out += std::format("{}return;\n", ind);
                        break;
                    }
                }
                if (is_void_call_result(rv)) {
                    out += std::format("{}return;\n", ind);
                    break;
                }
                // Reuse the return-fold table populated during region
                // analysis — when a call directly feeds the return,
                // `fold_return_expr` carries the rendered call expr.
                if (auto k = ssa_key(rv); k) {
                    auto f = fold_return_expr.find(*k);
                    if (f != fold_return_expr.end()) {
                        out += std::format("{}return {};\n", ind, f->second);
                        break;
                    }
                }
                out += std::format("{}return {};\n", ind, expr(rv));
            } else {
                out += std::format("{}return;\n", ind);
            }
            break;
        }
        case BlockKind::Conditional: {
            if (term && term->op == IrOp::CondBranch && term->src_count > 0) {
                out += std::format("{}if ({})\n", ind, expr(term->srcs[0]));
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

void Emitter::emit_region(const Region& r, int depth, std::string& out) const {
    const std::string ind(static_cast<std::size_t>(depth) * 2u, ' ');

    switch (r.kind) {
        case RegionKind::Empty:                                              return;
        case RegionKind::Block:        emit_block(r.block_start, depth, out); return;
        case RegionKind::Seq:
            for (const auto& c : r.children) emit_region(*c, depth, out);
            return;
        case RegionKind::IfThen:       emit_region_if_then  (r, depth, out); return;
        case RegionKind::IfElse:       emit_region_if_else  (r, depth, out); return;
        case RegionKind::While:        emit_region_while    (r, depth, out); return;
        case RegionKind::Loop:
            out += std::format("{}for (;;) {{\n", ind);
            for (const auto& c : r.children) emit_region(*c, depth + 1, out);
            out += std::format("{}}}\n", ind);
            return;
        case RegionKind::DoWhile:      emit_region_do_while (r, depth, out); return;
        case RegionKind::For:          emit_region_for      (r, depth, out); return;
        case RegionKind::Return:       emit_region_return   (r, depth, out); return;
        case RegionKind::Unreachable:  out += std::format("{}__unreachable();\n",   ind); return;
        case RegionKind::Break:        out += std::format("{}break;\n",             ind); return;
        case RegionKind::Continue:     out += std::format("{}continue;\n",          ind); return;
        case RegionKind::Goto:         out += std::format("{}goto bb_{:x};\n", ind, r.target); return;
        case RegionKind::Switch:       emit_region_switch   (r, depth, out); return;
    }
}

void Emitter::emit_region_if_then(const Region& r, int depth, std::string& out) const {
    // Pre-render the body and skip the whole if when nothing survived. The
    // body can collapse to empty after store/decl suppression (e.g. an
    // -O0 prologue's xmm spill block that becomes literally `if (rax) {}`)
    // — emitting the dead conditional is just visual noise, since the
    // condition itself has no observable effect.
    std::string body;
    const auto bindings_before_body = emitted_bindings;
    if (!r.children.empty()) emit_region(*r.children[0], depth + 1, body);
    const auto bindings_after_body = emitted_bindings;
    emitted_bindings = bindings_before_body;
    if (body.empty()) return;
    const std::string ind(static_cast<std::size_t>(depth) * 2u, ' ');
    emit_materializations_for_value(r.condition, 0, out, ind);
    const std::string cond = render_condition(r.condition, r.invert);
    out += std::format("{}if ({}) {{\n", ind, cond);
    out += body;
    emitted_bindings.insert(bindings_after_body.begin(), bindings_after_body.end());
    out += std::format("{}}}\n", ind);
}

void Emitter::emit_region_if_else(const Region& r, int depth, std::string& out) const {
    const std::string ind(static_cast<std::size_t>(depth) * 2u, ' ');
    const auto bindings_before_children = emitted_bindings;
    std::string then_buf;
    if (r.children.size() > 0) emit_region(*r.children[0], depth + 1, then_buf);
    auto bindings_after_then = emitted_bindings;
    emitted_bindings = bindings_before_children;
    std::string else_buf;
    if (r.children.size() > 1) emit_region(*r.children[1], depth + 1, else_buf);
    auto bindings_after_else = emitted_bindings;
    emitted_bindings = bindings_before_children;
    // If only the else arm has content, invert the condition and drop the
    // dead then. Reads much cleaner than `if (!x) {} else {…}`.
    bool invert_effective = r.invert;
    if (then_buf.empty() && !else_buf.empty()) {
        invert_effective = !invert_effective;
        std::swap(then_buf, else_buf);
        std::swap(bindings_after_then, bindings_after_else);
    }
    emit_materializations_for_value(r.condition, 0, out, ind);
    const std::string cond = render_condition(r.condition, invert_effective);
    // Early-return collapse: when the then arm always exits (last statement
    // is `return …;` or `goto …;`), the else arm is unreachable AFTER the
    // if, so we can drop the `else` wrapper and let the else body run at
    // the surrounding indent. Cascaded across nested if/elses this turns
    // a goto-fail ladder back into an early-return chain — the same shape
    // the user originally wrote. Re-emit the else at the outer depth so
    // the indentation matches the new flat layout.
    if (r.children.size() > 1 && r.children[0] && r.children[1] &&
        region_always_exits(*r.children[0])) {
        std::string else_outer;
        const auto bindings_before_else_outer = emitted_bindings;
        emit_region(*r.children[1], depth, else_outer);
        const auto bindings_after_else_outer = emitted_bindings;
        emitted_bindings = bindings_before_else_outer;
        if (!else_outer.empty()) {
            out += std::format("{}if ({}) {{\n", ind, cond);
            out += then_buf;
            emitted_bindings.insert(bindings_after_then.begin(), bindings_after_then.end());
            out += std::format("{}}}\n", ind);
            out += else_outer;
            emitted_bindings.insert(bindings_after_else_outer.begin(),
                                   bindings_after_else_outer.end());
            return;
        }
    }
    out += std::format("{}if ({}) {{\n", ind, cond);
    out += then_buf;
    emitted_bindings.insert(bindings_after_then.begin(), bindings_after_then.end());
    if (!else_buf.empty()) {
        out += std::format("{}}} else {{\n", ind);
        out += else_buf;
        emitted_bindings.insert(bindings_after_else.begin(), bindings_after_else.end());
    }
    out += std::format("{}}}\n", ind);
}

void Emitter::emit_region_while(const Region& r, int depth, std::string& out) const {
    // Two render shapes for a top-tested loop:
    //
    //   `while (cond) { body }`     — preferred, source-shape.
    //   `for (;;) { header; if (!cond) break; body }`
    //          — fallback when the header block has live statements that
    //            need to stay in the loop's scope (typically a Load or
    //            Call whose result the condition reads).
    //
    // We pre-render the header into a buffer and pick by emptiness. The
    // common case at -O2 is an empty header — the cond uses live-in args
    // or pre-loop locals — and the cleaner `while (cond)` reads as the
    // user originally wrote.
    const std::string ind(static_cast<std::size_t>(depth) * 2u, ' ');
    const std::string inner_ind(static_cast<std::size_t>(depth + 1) * 2u, ' ');

    std::string header_buf;
    const auto bindings_before_header = emitted_bindings;
    if (!r.children.empty()) {
        emit_region(*r.children[0], depth + 1, header_buf);
    }
    const auto bindings_after_header = emitted_bindings;
    emitted_bindings = bindings_before_header;
    if (header_buf.empty()) {
        emit_materializations_for_value(r.condition, 0, out, ind);
        const std::string cond = render_condition(r.condition, r.invert);
        out += std::format("{}while ({}) {{\n", ind, cond);
        for (std::size_t i = 1; i < r.children.size(); ++i) {
            emit_region(*r.children[i], depth + 1, out);
        }
        out += std::format("{}}}\n", ind);
        return;
    }
    const std::string break_cond = render_condition(r.condition, !r.invert);
    out += std::format("{}for (;;) {{\n", ind);
    out += header_buf;
    emitted_bindings.insert(bindings_after_header.begin(), bindings_after_header.end());
    emit_materializations_for_value(r.condition, 0, out, inner_ind);
    out += std::format("{}if ({}) break;\n", inner_ind, break_cond);
    for (std::size_t i = 1; i < r.children.size(); ++i) {
        emit_region(*r.children[i], depth + 1, out);
    }
    out += std::format("{}}}\n", ind);
}

void Emitter::emit_region_do_while(const Region& r, int depth, std::string& out) const {
    // Body runs at least once, condition tested at the tail. r.invert is
    // set when the decoded back-edge is a "loop-on-false" test — mirror it
    // here so the rendered `while (...)` expresses the actual continue
    // condition.
    const std::string ind(static_cast<std::size_t>(depth) * 2u, ' ');
    out += std::format("{}do {{\n", ind);
    for (const auto& c : r.children) emit_region(*c, depth + 1, out);
    const std::string cond = render_condition(r.condition, r.invert);
    out += std::format("{}}} while ({});\n", ind, cond);
}

void Emitter::emit_region_for(const Region& r, int depth, std::string& out) const {
    // The update slot renders the increment inst. If rendering fails
    // (pattern didn't reduce), degrade gracefully to a plain while — the
    // body will include the update statement at its natural spot.
    const std::string ind(static_cast<std::size_t>(depth) * 2u, ' ');
    const std::string update = r.has_update
        ? render_update_inst(r.update_block, r.update_inst)
        : std::string{};
    emit_materializations_for_value(r.condition, 0, out, ind);
    const std::string cond = render_condition(r.condition, r.invert);
    if (update.empty()) {
        out += std::format("{}while ({}) {{\n", ind, cond);
    } else {
        out += std::format("{}for (; {}; {}) {{\n", ind, cond, update);
    }
    for (const auto& c : r.children) emit_region(*c, depth + 1, out);
    out += std::format("{}}}\n", ind);
}

void Emitter::emit_region_return(const Region& r, int depth, std::string& out) const {
    const std::string ind(static_cast<std::size_t>(depth) * 2u, ' ');
    if (r.condition.kind == IrValueKind::None) {
        out += std::format("{}return;\n", ind);
        return;
    }
    if (auto k = ssa_key(r.condition); k) {
        auto s = fold_void_call_stmt.find(*k);
        if (s != fold_void_call_stmt.end()) {
            out += std::format("{}{};\n", ind, s->second);
            out += std::format("{}return;\n", ind);
            return;
        }
    }
    if (is_void_call_result(r.condition)) {
        out += std::format("{}return;\n", ind);
        return;
    }
    if (is_unbound_clobber_result(r.condition)) {
        out += std::format("{}return;\n", ind);
        return;
    }
    if (auto k = ssa_key(r.condition); k) {
        auto f = fold_return_expr.find(*k);
        if (f != fold_return_expr.end()) {
            out += std::format("{}return {};\n", ind, f->second);
            return;
        }
    }
    // Strip a redundant outer widen: in a return context the caller's
    // declared type already coerces, so `return (u64)x;` where `x` has the
    // return type reads as noise. One hop only — deeper casts are
    // semantically real.
    IrValue v = r.condition;
    if (const IrInst* d = def_of(v); d && d->src_count >= 1
            && (d->op == IrOp::ZExt || d->op == IrOp::SExt)
            && type_bits(d->srcs[0].type) <= type_bits(d->dst.type)) {
        v = d->srcs[0];
    }
    emit_materializations_for_value(v, 0, out, ind);
    out += std::format("{}return {};\n", ind, expr(v));
}

void Emitter::emit_region_switch(const Region& r, int depth, std::string& out) const {
    const std::string ind(static_cast<std::size_t>(depth) * 2u, ' ');
    const std::string_view rn = reg_name(r.switch_index);
    out += std::format("{}switch ({}) {{\n", ind,
                       rn.empty() ? std::string("<idx>") : std::string(rn));
    const std::string cind(static_cast<std::size_t>(depth + 1) * 2u, ' ');
    const std::size_t n_cases = r.case_values.size();

    auto ends_in_terminator = [](const Region& body) {
        const Region* cur = &body;
        while (cur && cur->kind == RegionKind::Seq && !cur->children.empty()) {
            cur = cur->children.back().get();
        }
        if (!cur) return false;
        switch (cur->kind) {
            case RegionKind::Return:
            case RegionKind::Break:
            case RegionKind::Continue:
            case RegionKind::Unreachable:
                return true;
            default:
                return false;
        }
    };

    for (std::size_t i = 0; i < n_cases; ++i) {
        out += std::format("{}case {}:", cind, r.case_values[i]);
        const Region* child = i < r.children.size() ? r.children[i].get() : nullptr;
        const bool is_empty_child =
            !child || child->kind == RegionKind::Empty ||
            (child->kind == RegionKind::Seq && child->children.empty());
        if (is_empty_child) {
            out += "\n";
            continue;
        }
        out += "\n";
        emit_region(*child, depth + 2, out);
        if (!ends_in_terminator(*child)) {
            out += std::format("{}  break;\n", cind);
        }
    }
    if (r.has_default && r.children.size() > n_cases) {
        out += std::format("{}default:\n", cind);
        const Region& dflt = *r.children.back();
        emit_region(dflt, depth + 2, out);
        if (!ends_in_terminator(dflt)) {
            out += std::format("{}  break;\n", cind);
        }
    }
    out += std::format("{}}}\n", ind);
}

}  // anonymous namespace

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
    // Opportunistic selref lookup for Mach-O binaries when the caller
    // didn't supply one — cheap enough to parse per emit (one section
    // walk, a few hundred cstring reads on typical Cocoa-linked code).
    std::map<addr_t, std::string> local_selrefs;
    std::map<addr_t, std::string> local_classrefs;
    if (binary && binary->format() == Format::MachO) {
        if (!e.options.objc_selrefs) {
            local_selrefs = parse_objc_selrefs(*binary);
            if (!local_selrefs.empty()) e.options.objc_selrefs = &local_selrefs;
        }
        if (!e.options.objc_classrefs) {
            local_classrefs = parse_objc_classrefs(*binary);
            if (!local_classrefs.empty()) e.options.objc_classrefs = &local_classrefs;
        }
    }
    // Same deal for the classlist method table: parse once per emit, then
    // render any call target whose IMP matches as `-[Class selector]`.
    // Storage lives on the Emitter so pointers into it stay stable.
    std::vector<ObjcMethod> local_objc_methods;
    std::map<addr_t, std::string> local_rtti_methods;
    if (binary && binary->format() == Format::MachO) {
        local_objc_methods = parse_objc_methods(*binary);
        for (const auto& m : local_objc_methods) {
            if (m.imp != 0) e.objc_by_imp.emplace(m.imp, &m);
        }
        // Itanium RTTI: names virtual methods on stripped C++ binaries.
        if (!e.options.rtti_methods) {
            local_rtti_methods = rtti_method_names(parse_itanium_rtti(*binary));
            if (!local_rtti_methods.empty()) {
                e.options.rtti_methods = &local_rtti_methods;
            }
        }
        // Cache the __cfstring section bounds for constant-NSString
        // decoding in format_imm.
        for (const auto& s : binary->sections()) {
            const std::string_view n = s.name;
            if (n == "__cfstring" || n.ends_with(",__cfstring")) {
                e.cfstring_lo = static_cast<addr_t>(s.vaddr);
                e.cfstring_hi = static_cast<addr_t>(s.vaddr + s.size);
                break;
            }
        }
    } else if (binary && binary->format() == Format::Pe) {
        // MSVC RTTI on PE: same rtti_method_names API the Mach-O path
        // uses, so the emitter's `options.rtti_methods` consumer stays
        // format-agnostic. Itanium RTTI calls would emit nothing on
        // a PE since the typeinfo structure layout differs, so skip it.
        if (!e.options.rtti_methods) {
            local_rtti_methods = rtti_method_names(parse_msvc_rtti(*binary));
            if (!local_rtti_methods.empty()) {
                e.options.rtti_methods = &local_rtti_methods;
            }
        }
    }
    bool has_user_sig = false;
    if (annotations) {
        if (const FunctionSig* sig = annotations->signature_for(sf.ir->start); sig) {
            e.self_arity = static_cast<u8>(std::min(sig->params.size(), int_arg_regs(e.abi).size()));
            has_user_sig = true;
        }
    }
    if (e.self_arity == 0) {
        e.self_arity = binary ? infer_arity(*binary, sf.ir->start) : u8{0};
    }
    e.analyze(*sf.ir);
    e.name_merge_values();
    e.frame_layout = compute_frame_layout(*sf.ir, binary);
    if (sf.body) {
        e.suppress_canary_regions(*sf.body);
        e.analyze_return_folds(*sf.body);
        e.analyze_return_expr_call_folds(*sf.body);
        e.collect_for_updates(*sf.body);
    }
    if (!has_user_sig) e.bump_arity_from_call_sites();
    if (!has_user_sig) e.bump_arity_from_body_reads();
    e.infer_function_pointer_args();
    e.infer_call_value_arg_names();
    if (!has_user_sig) e.infer_charp_args();
    e.bind_call_returns();

    std::string out;
    out += std::format("// {}\n", sf.ir->name.empty()
                                    ? std::string("<unknown>") : sf.ir->name);

    // Infer return type from body: any Return region carrying a non-None
    // condition means the function yields a value. We use the condition's
    // IrType to pick an appropriate C type rather than always saying `u64`.
    auto inferred_return_type = [&](const Emitter&, const StructuredFunction& s) -> std::string {
        // IPA wins outright when it has concrete evidence — the typed
        // return came from harvesting Return-operand types after Phase 2
        // local inference, which sees more than this lambda's
        // bit-width-only fallback.
        if (e.options.signatures && e.options.type_arena && s.ir) {
            auto it = e.options.signatures->find(s.ir->start);
            if (it != e.options.signatures->end()) {
                std::string n = e.ipa_type_name(it->second.return_type);
                if (!n.empty()) return n;
            }
        }
        if (!s.body) return "void";
        bool narrow_return_from_indirect_evidence = false;
        for (const auto& a : e.self_funcptr_arity) {
            if (a) {
                narrow_return_from_indirect_evidence = true;
                break;
            }
        }
        std::optional<IrType> t;
        std::function<void(const Region&)> walk = [&](const Region& r) {
            if (r.kind == RegionKind::Return &&
                r.condition.kind != IrValueKind::None) {
                if (e.is_void_call_result(r.condition)) return;
                if (e.is_unbound_clobber_result(r.condition)) return;
                IrValue v = r.condition;
                if (narrow_return_from_indirect_evidence) {
                    if (const IrInst* d = e.def_of(v); d && d->src_count >= 1
                            && (d->op == IrOp::ZExt || d->op == IrOp::SExt)
                            && type_bits(d->srcs[0].type) <= type_bits(d->dst.type)) {
                        v = d->srcs[0];
                    }
                }
                if (!t) t = v.type;
            }
            for (const auto& c : r.children) if (c) walk(*c);
        };
        walk(*s.body);
        if (!t) return "void";
        switch (*t) {
            case IrType::F32:  return "float";
            case IrType::F64:  return "double";
            case IrType::I1:   return "bool";
            case IrType::I8:   return "u8";
            case IrType::I16:  return "u16";
            case IrType::I32:  return "u32";
            case IrType::I64:  return "u64";
            case IrType::I128: return "__m128i";
        }
        return "u64";
    };

    // Pick a display name: user rename beats binary symbol beats the
    // sub_<hex> fallback. Used below for the header so named functions
    // (e.g. `main` from LC_MAIN) don't render as `sub_<entry>`.
    auto display_name = [&]() -> std::string {
        if (annotations) {
            if (const std::string* n = annotations->name_for(sf.ir->start); n)
                return *n;
        }
        // Obj-C IMP match — the function header gets `-[Class sel]` directly.
        if (auto it = e.objc_by_imp.find(sf.ir->start);
            it != e.objc_by_imp.end()) {
            return std::format("{}[{} {}]",
                               it->second->is_class ? '+' : '-',
                               it->second->cls,
                               it->second->selector);
        }
        // Itanium RTTI-derived virtual-method name — usable as the header
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
    };

    // Build the function header. A declared signature wins outright;
    // otherwise we fall back to arity-inferred u64 params.
    std::string header;
    if (annotations) {
        if (const FunctionSig* sig = annotations->signature_for(sf.ir->start); sig) {
            std::string params;
            if (sig->params.empty()) {
                params = "void";
            } else {
                for (std::size_t i = 0; i < sig->params.size(); ++i) {
                    if (i > 0) params += ", ";
                    params += std::format("{} {}",
                                          sig->params[i].type,
                                          sig->params[i].name);
                }
            }
            const std::string ret = sig->return_type.empty()
                ? inferred_return_type(e, sf)
                : sig->return_type;
            header = std::format("{} {}({}) {{\n", ret, display_name(), params);
        }
    }
    if (header.empty()) {
        // Obj-C IMP: derive the header from the method's ObjC type
        // encoding. Gives us proper self / _cmd / typed args instead of
        // u64 placeholders — for a method with encoding "v40@0:8@16i32"
        // we get `void -[Foo bar:](Foo* self, SEL _cmd, id arg0, int arg1)`.
        auto objc_it = e.objc_by_imp.find(sf.ir->start);
        if (objc_it != e.objc_by_imp.end() &&
            !objc_it->second->type_encoding.empty()) {
            const auto& meth  = *objc_it->second;
            const auto parts  = decode_objc_type_parts(meth.type_encoding);
            if (!parts.empty()) {
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
                    for (std::size_t i = 3; i < parts.size(); ++i) {
                        params += std::format(", {} arg{}",
                                              parts[i], i - 3);
                    }
                }
                header = std::format("{} {}({}) {{\n",
                                     ret_ty, display_name(), params);
            }
        }
    }
    if (header.empty()) {
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
            const auto int_args = int_arg_regs(e.abi);
            for (u8 i = 0; i < arity; ++i) {
                if (i > 0) params += ", ";
                std::string t;
                if (ipa_sig && i < ipa_sig->params.size()) {
                    t = e.ipa_type_name(ipa_sig->params[i]);
                }
                // No IPA: consult the per-function value_types side table
                // (populated by seed_call_return_types + infer_local_types
                // ahead of emit). This is what surfaces import-derived
                // arg types in non-IPA mode — `char*`, `void*`, etc.
                if (t.empty() && i < int_args.size()) {
                    IrValue probe = IrValue::make_reg(int_args[i], IrType::I64);
                    probe.version = 0;
                    const auto local = e.c_type_name_for(probe);
                    if (local != "u64") t = local;
                }
                if (t.empty()) {
                    t = (i < e.charp_arg.size() && e.charp_arg[i])
                        ? std::string{"char*"} : std::string{"u64"};
                }
                if (ipa_sig == nullptr && i < e.self_arg_type_overrides.size() &&
                    e.self_arg_type_overrides[i]) {
                    t = c_type_name(*e.self_arg_type_overrides[i]);
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
                                fn_params += "u64";
                            }
                        }
                    }
                    const std::string fn_ret =
                        (i < e.self_funcptr_return_type.size() &&
                         e.self_funcptr_return_type[i])
                            ? std::string{c_type_name(*e.self_funcptr_return_type[i])}
                            : std::string{"u64"};
                    params += std::format("{} (*{})({})", fn_ret, name, fn_params);
                } else {
                    params += std::format("{} {}", t, name);
                }
            }
        }
        header = std::format("{} {}({}) {{\n",
                             inferred_return_type(e, sf),
                             display_name(), params);
    }
    // When the header name is a long RTTI `Class::vfn_N` — especially for
    // templates — advertise a shorter alias the user can type with `-s`.
    // Purely a discoverability comment; the resolver accepts the short form
    // via the same class_aliases machinery used here.
    if (e.options.rtti_methods) {
        auto it = e.options.rtti_methods->find(sf.ir->start);
        if (it != e.options.rtti_methods->end()) {
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
                    out += std::format("// alias: {}{}\n",
                                       short_sv,
                                       std::string_view{full}.substr(vfn_pos));
                }
            }
        }
    }
    out += header;

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
    for (const auto& [k, name] : e.merge_value_names) {
        if (body_buf.find(name) == std::string::npos) continue;
        auto dit = e.defs.find(k);
        if (dit == e.defs.end()) continue;
        out += std::format("  {} {};\n", e.c_type_name_for(dit->second->dst), name);
    }
    // Slot extent → array recovery: if a slot's footprint (the gap to the
    // next slot above it in the frame) is bigger than its observed access
    // width, the user wrote `T arr[N]`, not a single scalar. Render it as
    // such so a 128-byte `fgets` buffer doesn't read as `u64 local_208;`.
    // The map iterates in ascending offset order; for stack locals (negative
    // offsets) that means deepest-first, so each slot's "next" entry sits
    // closer to entry rsp and gives us the slot's upper edge directly.
    auto next_slot_offset = [&](i64 off) -> std::optional<i64> {
        auto it = e.frame_layout.slots.upper_bound(off);
        if (it == e.frame_layout.slots.end()) return std::nullopt;
        return it->second.offset;
    };
    for (const auto& [_, slot] : e.frame_layout.slots) {
        if (slot.name.empty()) continue;
        if (body_buf.find(slot.name) == std::string::npos) continue;
        // char* type propagation overrides the access-width-derived type
        // when an inferred libc-char* call observed `&local_X` flowing in.
        const bool charp = slot.type_override.empty() &&
                           e.charp_local_slots.contains(slot.offset);
        std::string ty;
        u32 elem_size = slot.size_bytes;
        if (!slot.type_override.empty()) {
            ty = slot.type_override;
        } else if (charp) {
            ty = "char";
            elem_size = 1;
        } else {
            ty = std::string(c_type_name(slot.type));
        }
        std::string suffix;
        if (slot.type_override.empty() && elem_size > 0) {
            if (auto next_off = next_slot_offset(slot.offset)) {
                const i64 span = *next_off - slot.offset;
                if (span > 0 &&
                    static_cast<u32>(span) > elem_size &&
                    span % elem_size == 0) {
                    const u32 n = static_cast<u32>(span) / elem_size;
                    suffix = std::format("[{}]", n);
                }
            }
        }
        out += std::format("  {} {}{};\n", ty, slot.name, suffix);
    }
    const std::size_t body_offset = out.size();
    out += body_buf;
    if (options.line_map) {
        for (std::size_t i = lm_first_body_hit;
             i < options.line_map->hits.size(); ++i) {
            options.line_map->hits[i].byte_offset += body_offset;
        }
    }

    out += "}\n";

    // Dead-temp pass: drop `T tN = ...;` lines whose `tN` doesn't appear
    // anywhere else in the output. visible_use_count can over-count when
    // the sole reader folds the value through a register-assign chain.
    //
    // Skipped when a LineMap is being collected: deleting lines would
    // invalidate the byte_offset values already recorded (the debugger
    // can live with a slightly noisier function listing in exchange
    // for accurate PC-to-line mapping).
    if (!options.line_map) {
        std::vector<std::string> lines;
        {
            std::string buf;
            for (char c : out) {
                if (c == '\n') { lines.push_back(std::move(buf)); buf.clear(); }
                else { buf.push_back(c); }
            }
            if (!buf.empty()) lines.push_back(std::move(buf));
        }
        auto ident_char = [](char c) {
            return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
        };
        auto is_decl = [&](const std::string& line, std::string& name) {
            std::size_t i = 0;
            while (i < line.size() && line[i] == ' ') ++i;
            // Type token (one word like u32, u64, bool, double).
            const std::size_t type_start = i;
            while (i < line.size() && line[i] != ' ') ++i;
            if (i == type_start || i >= line.size()) return false;
            while (i < line.size() && line[i] == ' ') ++i;
            // Identifier token.
            const std::size_t name_start = i;
            if (i >= line.size()) return false;
            const char c0 = line[i];
            if (!(std::isalpha(static_cast<unsigned char>(c0)) || c0 == '_')) return false;
            ++i;
            while (i < line.size() && ident_char(line[i])) ++i;
            const std::size_t name_end = i;
            while (i < line.size() && line[i] == ' ') ++i;
            if (i >= line.size() || line[i] != '=') return false;
            name = line.substr(name_start, name_end - name_start);
            return true;
        };
        auto name_appears_elsewhere = [&](const std::string& name,
                                          std::size_t skip_idx) {
            for (std::size_t li = 0; li < lines.size(); ++li) {
                if (li == skip_idx) continue;
                std::size_t pos = 0;
                const std::string& l = lines[li];
                while ((pos = l.find(name, pos)) != std::string::npos) {
                    const bool left_ok  = pos == 0 ||
                        !(std::isalnum(static_cast<unsigned char>(l[pos-1])) || l[pos-1] == '_');
                    const std::size_t end = pos + name.size();
                    const bool right_ok = end >= l.size() ||
                        !(std::isalnum(static_cast<unsigned char>(l[end])) || l[end] == '_');
                    if (left_ok && right_ok) return true;
                    pos = end;
                }
            }
            return false;
        };

        std::string cleaned;
        cleaned.reserve(out.size());
        for (std::size_t li = 0; li < lines.size(); ++li) {
            std::string name;
            if (is_decl(lines[li], name) &&
                !name_appears_elsewhere(name, li)) {
                continue;  // dead declaration
            }
            cleaned += lines[li];
            cleaned += '\n';
        }
        out = std::move(cleaned);
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

    // Setup mirrors emit() — same ABI plumbing, same ObjC / RTTI lookup,
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

    std::map<addr_t, std::string> local_selrefs;
    std::map<addr_t, std::string> local_classrefs;
    std::vector<ObjcMethod>       local_objc_methods;
    std::map<addr_t, std::string> local_rtti_methods;
    if (binary && binary->format() == Format::MachO) {
        if (!e.options.objc_selrefs) {
            local_selrefs = parse_objc_selrefs(*binary);
            if (!local_selrefs.empty()) e.options.objc_selrefs = &local_selrefs;
        }
        if (!e.options.objc_classrefs) {
            local_classrefs = parse_objc_classrefs(*binary);
            if (!local_classrefs.empty()) e.options.objc_classrefs = &local_classrefs;
        }
        local_objc_methods = parse_objc_methods(*binary);
        for (const auto& m : local_objc_methods) {
            if (m.imp != 0) e.objc_by_imp.emplace(m.imp, &m);
        }
        if (!e.options.rtti_methods) {
            local_rtti_methods = rtti_method_names(parse_itanium_rtti(*binary));
            if (!local_rtti_methods.empty()) {
                e.options.rtti_methods = &local_rtti_methods;
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
            local_rtti_methods = rtti_method_names(parse_msvc_rtti(*binary));
            if (!local_rtti_methods.empty()) {
                e.options.rtti_methods = &local_rtti_methods;
            }
        }
    }

    bool has_user_sig = false;
    if (annotations) {
        if (const FunctionSig* sig = annotations->signature_for(sf.ir->start); sig) {
            e.self_arity = static_cast<u8>(std::min(sig->params.size(), int_arg_regs(e.abi).size()));
            has_user_sig = true;
        }
    }
    if (e.self_arity == 0) {
        e.self_arity = binary ? infer_arity(*binary, sf.ir->start) : u8{0};
    }
    e.analyze(*sf.ir);
    e.name_merge_values();
    if (!has_user_sig) e.bump_arity_from_body_reads();
    e.infer_function_pointer_args();
    e.infer_call_value_arg_names();
    if (!has_user_sig) e.infer_charp_args();
    e.bind_call_returns();

    // Output mirrors format_cfg's framing — same `bb_<addr>` headers,
    // same `<-` predecessor list, same `-> bb_xxx (label)` arrows — so
    // any consumer parsing the asm CFG view (UI, scripts) parses this
    // identically up to the body content swap.
    std::string out;
    out += std::format("// {}\n", sf.ir->name.empty()
                                    ? std::string("<unknown>") : sf.ir->name);
    out += std::format("//   per-block pseudo-C ({} blocks)\n",
                       sf.ir->blocks.size());
    for (const auto& [k, name] : e.merge_value_names) {
        auto dit = e.defs.find(k);
        if (dit == e.defs.end()) continue;
        out += std::format("//   {} {};\n", e.c_type_name_for(dit->second->dst), name);
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

        // Successor arrows — copy the format used by append_function_text
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
