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
#include <ember/analysis/import_sigs.hpp>
#include <ember/analysis/name_resolver.hpp>
#include <ember/analysis/objc.hpp>
#include <ember/analysis/msvc_rtti.hpp>
#include <ember/analysis/pipeline.hpp>
#include <ember/analysis/rtti.hpp>
#include <ember/analysis/ssa_cleanup.hpp>
#include <ember/common/types.hpp>
#include <ember/disasm/x64_decoder.hpp>
#include <ember/ir/abi.hpp>
#include <ember/ir/ssa.hpp>

#include "emitter_helpers.hpp"
#include "emitter_tables.hpp"

namespace ember {

namespace {

[[nodiscard]] std::string_view trim_line_view(std::string_view line) noexcept {
    while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) {
        line.remove_prefix(1);
    }
    while (!line.empty() && (line.back() == ' ' || line.back() == '\t' ||
                             line.back() == '\r')) {
        line.remove_suffix(1);
    }
    return line;
}

[[nodiscard]] bool is_bb_label_line(std::string_view line) noexcept {
    line = trim_line_view(line);
    if (!line.starts_with("// bb_")) return false;
    auto rest = line.substr(6);
    if (rest.empty()) return false;
    for (char c : rest) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

[[nodiscard]] bool line_semantically_empty(std::string_view line) noexcept {
    line = trim_line_view(line);
    return line.empty() || is_bb_label_line(line);
}

[[nodiscard]] bool c_ident_char(char c) noexcept {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
}

[[nodiscard]] bool text_contains_identifier(std::string_view text,
                                            std::string_view name) noexcept {
    if (name.empty()) return false;
    std::size_t pos = 0;
    while ((pos = text.find(name, pos)) != std::string_view::npos) {
        const bool left_ok = pos == 0 || !c_ident_char(text[pos - 1]);
        const std::size_t end = pos + name.size();
        const bool right_ok = end >= text.size() || !c_ident_char(text[end]);
        if (left_ok && right_ok) return true;
        pos = end;
    }
    return false;
}

[[nodiscard]] bool text_contains_identifier_in_code(std::string_view text,
                                                    std::string_view name) noexcept {
    bool in_block_comment = false;
    std::size_t start = 0;
    while (start <= text.size()) {
        std::size_t end = text.find('\n', start);
        if (end == std::string_view::npos) end = text.size();
        std::string_view line = text.substr(start, end - start);
        if (const std::size_t comment = line.find("//");
            comment != std::string_view::npos) {
            line = line.substr(0, comment);
        }
        std::string code;
        code.reserve(line.size());
        for (std::size_t i = 0; i < line.size(); ) {
            if (in_block_comment) {
                const std::size_t close = line.find("*/", i);
                if (close == std::string_view::npos) break;
                in_block_comment = false;
                i = close + 2;
                continue;
            }
            const std::size_t open = line.find("/*", i);
            if (open == std::string_view::npos) {
                code.append(line.substr(i));
                break;
            }
            code.append(line.substr(i, open - i));
            in_block_comment = true;
            i = open + 2;
        }
        if (text_contains_identifier(code, name)) return true;
        if (end == text.size()) break;
        start = end + 1;
    }
    return false;
}

[[nodiscard]] bool line_starts_empty_if(std::string_view line) noexcept {
    line = trim_line_view(line);
    return line.starts_with("if (") && line.ends_with("{");
}

[[nodiscard]] std::string lower_first_ascii(std::string s) {
    if (!s.empty()) {
        s.front() = static_cast<char>(
            std::tolower(static_cast<unsigned char>(s.front())));
    }
    return s;
}

[[nodiscard]] std::string sanitize_ident(std::string_view s,
                                         std::string_view fallback) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        const bool ok = (c >= 'A' && c <= 'Z') ||
                        (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') ||
                        c == '_';
        if (ok) out.push_back(c);
    }
    if (out.empty() || (out.front() >= '0' && out.front() <= '9')) {
        out = std::string(fallback);
    }
    return out;
}

[[nodiscard]] std::vector<std::string>
objc_selector_arg_names(std::string_view selector) {
    std::vector<std::string> names;
    std::size_t start = 0;
    while (start < selector.size()) {
        const std::size_t colon = selector.find(':', start);
        if (colon == std::string_view::npos) break;
        std::string piece(selector.substr(start, colon - start));
        if (names.empty()) {
            if (piece.starts_with("set") && piece.size() > 3) {
                piece = lower_first_ascii(piece.substr(3));
            } else if (piece.starts_with("with") && piece.size() > 4) {
                piece = lower_first_ascii(piece.substr(4));
            } else if (auto with = piece.rfind("With");
                       with != std::string::npos && with + 4 < piece.size()) {
                piece = lower_first_ascii(piece.substr(with + 4));
            }
        }
        if (piece.empty()) piece = std::format("arg{}", names.size());
        names.push_back(sanitize_ident(piece, std::format("arg{}", names.size())));
        start = colon + 1;
    }
    return names;
}

[[nodiscard]] std::string objc_block_literal_name(addr_t literal) {
    return std::format("__block_literal_{:x}", static_cast<u64>(literal));
}

[[nodiscard]] std::string objc_block_invoke_name(addr_t invoke) {
    return std::format("__block_invoke_{:x}", static_cast<u64>(invoke));
}

[[nodiscard]] std::string block_param_type(std::string_view ty) {
    if (ty == "block") return "void*";
    return std::string(ty);
}

[[nodiscard]] bool line_is_close_brace(std::string_view line) noexcept {
    return trim_line_view(line) == "}";
}

[[nodiscard]] bool line_is_else_open(std::string_view line) noexcept {
    return trim_line_view(line) == "} else {";
}

[[nodiscard]] std::string strip_outer_parens(std::string_view s) {
    s = trim_line_view(s);
    if (s.size() < 2 || s.front() != '(' || s.back() != ')') {
        return std::string(s);
    }
    int depth = 0;
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '(') {
            ++depth;
        } else if (s[i] == ')') {
            --depth;
            if (depth == 0 && i + 1 != s.size()) return std::string(s);
        }
        if (depth < 0) return std::string(s);
    }
    return std::string(trim_line_view(s.substr(1, s.size() - 2)));
}

[[nodiscard]] std::string invert_condition_text(std::string_view cond) {
    cond = trim_line_view(cond);
    if (cond.starts_with("!") &&
        (cond.size() == 1 || cond[1] != '=')) {
        return strip_outer_parens(cond.substr(1));
    }
    return std::format("!({})", cond);
}

[[nodiscard]] std::optional<std::string>
inverted_if_line(std::string_view line) {
    const std::string_view trimmed = trim_line_view(line);
    if (!trimmed.starts_with("if (") || !trimmed.ends_with("{")) {
        return std::nullopt;
    }
    const std::size_t open = line.find("if (");
    if (open == std::string_view::npos) return std::nullopt;
    const std::size_t close = line.rfind(") {");
    if (close == std::string_view::npos || close < open + 4) {
        return std::nullopt;
    }
    const std::string_view indent = line.substr(0, open);
    const std::string cond = invert_condition_text(
        line.substr(open + 4, close - (open + 4)));
    return std::format("{}if ({}) {{", indent, cond);
}

[[nodiscard]] std::string collapse_empty_then_else_blocks(std::string_view text) {
    std::vector<std::string_view> lines;
    std::size_t start = 0;
    while (start <= text.size()) {
        std::size_t end = text.find('\n', start);
        if (end == std::string_view::npos) end = text.size();
        lines.push_back(text.substr(start, end - start));
        if (end == text.size()) break;
        start = end + 1;
    }

    std::string out;
    out.reserve(text.size());
    for (std::size_t i = 0; i < lines.size(); ++i) {
        if (auto inverted = inverted_if_line(lines[i]); inverted) {
            std::size_t j = i + 1;
            while (j < lines.size() && line_semantically_empty(lines[j])) {
                ++j;
            }
            if (j < lines.size() && line_is_else_open(lines[j])) {
                out += *inverted;
                out += '\n';
                i = j;
                continue;
            }
            if (j + 1 < lines.size() &&
                line_is_close_brace(lines[j]) &&
                line_is_else_open(lines[j + 1])) {
                out += *inverted;
                out += '\n';
                i = j + 1;
                continue;
            }
        }
        if (!lines[i].empty() || i + 1 < lines.size()) {
            out += lines[i];
            out += '\n';
        }
    }
    return out;
}

[[nodiscard]] std::string strip_label_only_if_blocks(std::string_view text) {
    std::vector<std::string_view> lines;
    std::size_t start = 0;
    while (start <= text.size()) {
        std::size_t end = text.find('\n', start);
        if (end == std::string_view::npos) end = text.size();
        lines.push_back(text.substr(start, end - start));
        if (end == text.size()) break;
        start = end + 1;
    }

    std::string out;
    out.reserve(text.size());
    for (std::size_t i = 0; i < lines.size(); ++i) {
        if (line_starts_empty_if(lines[i])) {
            std::size_t j = i + 1;
            bool saw_label = false;
            while (j < lines.size() && line_semantically_empty(lines[j])) {
                if (is_bb_label_line(lines[j])) saw_label = true;
                ++j;
            }
            if (saw_label && j < lines.size() && line_is_close_brace(lines[j])) {
                i = j;
                continue;
            }
        }
        if (!lines[i].empty() || i + 1 < lines.size()) {
            out += lines[i];
            out += '\n';
        }
    }
    return out;
}

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
    // Stack-slot offsets (per stack_offset()) that have at least one Load
    // somewhere in the function. A Store to an offset NOT in this set is a
    // dead spill - common for -O0 spill-arg-to-slot prologues whose slot is
    // never reloaded - and should be suppressed by format_store.
    std::set<i64>                                    loaded_stack_slots;
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
    // rax/xmm0 SSA key → bound local name for Call returns whose result is
    // read downstream. Makes `fopen(...); if (rax == 0)` render as
    // `u64 r_fopen = fopen(...); if (r_fopen == 0)`.
    std::map<SsaKey, std::string>                    call_return_names;
    std::map<std::pair<std::size_t, std::size_t>, SsaKey> bound_call_key;
    // ARC claim helpers consume an autoreleased return purely for ownership
    // bookkeeping. When the claimed value has no real uses, render the
    // producer call as the statement and suppress the helper.
    std::set<std::pair<std::size_t, std::size_t>>    arc_claim_producer_positions;
    std::set<std::pair<std::size_t, std::size_t>>    suppressed_call_positions;
    // Bound-call positions whose binding name reuses a phi merge-value
    // name (e.g. `v0`). Such call statements skip the type prefix because
    // the merge declaration is already emitted at the function head.
    std::set<std::pair<std::size_t, std::size_t>>    merge_bound_calls;
    std::map<SsaKey, std::string>                    merge_value_names;
    std::map<std::string, SsaMergeLocal>             merge_locals;
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
                // Common whitespace escapes - these are legitimate string
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
            // Heuristic for "this is actually a string": at least 2
            // printable characters (excluding hex-escapes), and printable
            // bytes outnumber escaped ones. Two-char format specifiers like
            // "%d", "%s", "%c" and short keywords like "OK", "No" are real
            // string content in codegen tables; the printable-vs-escaped
            // tiebreak still keeps `*(u64*)(" ")`-style noise out.
            if (terminated && printable_count >= 2 &&
                printable_count >= escaped_count) {
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

    mutable std::map<u64, std::vector<InferredArgument>> argument_layout_cache;

    [[nodiscard]] const std::vector<InferredArgument>&
    cached_argument_layout(addr_t target) const {
        const u64 key = static_cast<u64>(target);
        auto it = argument_layout_cache.find(key);
        if (it != argument_layout_cache.end()) return it->second;
        std::vector<InferredArgument> layout;
        bool declared = false;
        if (annotations) {
            if (const FunctionSig* sig = annotations->signature_for(target); sig) {
                layout = abi_layout_for(*sig);
                declared = true;
            }
        }
        if (!declared) {
            TypeArena arena;
            if (lookup_import_sig(function_display_name(target), arena)) {
                layout = abi_layout_for_import(function_display_name(target));
                declared = true;
            }
        }
        if (!declared && binary) {
            layout = infer_arguments(*binary, target, abi);
        }
        auto inserted = argument_layout_cache.emplace(key, std::move(layout));
        return inserted.first->second;
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

    // Exact code/data address used as an immediate. This catches cases such
    // as returning a function pointer or materializing a global address, where
    // a bare 0x40xxxx obscures information the loader already knows.
    [[nodiscard]] std::optional<std::string>
    named_address_for_imm(addr_t target) const {
        if (!binary) return std::nullopt;
        auto resolved = resolve_address_name(*binary, target);
        if (!resolved) return std::nullopt;
        if (resolved->addr != resolved->base &&
            resolved->kind != ResolvedNameKind::Object &&
            resolved->kind != ResolvedNameKind::Got) {
            return std::nullopt;
        }
        if (resolved->kind == ResolvedNameKind::Object || resolved->kind == ResolvedNameKind::Got) {
            if (const Symbol* s = binary->defined_object_at(target);
                s && s->kind == SymbolKind::Object) {
                note_global_decl(*s, resolved->addr == resolved->base
                    ? std::string{"uint64_t"}
                    : std::string{"uint64_t[]"});
            }
        }
        return format_address_expr(*resolved);
    }

    // Walk Assign copies until we hit something that's plausibly the
    // address of a string (an Imm, or a Reg). For an Imm, try to read the
    // NUL-terminated string at that address.
    [[nodiscard]] std::optional<std::string>
    resolve_string_value(const IrValue& v) const {
        IrValue cur = v;
        for (int step = 0; step < 8; ++step) {
            if (cur.kind == IrValueKind::Imm) {
                const auto addr = static_cast<u64>(cur.imm);
                if (auto s = try_decode_cfstring(addr); s) return s;
                return try_string_at(addr);
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

    [[nodiscard]] static bool is_generic_sub_name(std::string_view name) noexcept {
        if (!name.starts_with("sub_") || name.size() <= 4) return false;
        for (char c : name.substr(4)) {
            if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
        }
        return true;
    }

    [[nodiscard]] std::optional<u8>
    printf_like_arity_from_literal_args(const std::vector<IrValue>& args) const {
        const std::size_t limit = std::min<std::size_t>(args.size(), 6);
        for (std::size_t i = 0; i < limit; ++i) {
            auto fmt = resolve_string_value(args[i]);
            if (!fmt) continue;
            const u8 specs = count_printf_specifiers(*fmt);
            if (specs > 0) {
                return static_cast<u8>(i + 1u + specs);
            }
            // Stripped logging helpers often take metadata first, then a
            // literal format string. If the format has no conversions, any
            // trailing live-in registers are almost certainly stale ABI noise.
            if (i >= 2 && i + 1 < args.size() &&
                fmt->find("FLog::") != std::string::npos) {
                return static_cast<u8>(i + 1u);
            }
        }
        return std::nullopt;
    }

    // Receiver-shape virtual-method dispatch: if the call target traces
    // as `Load(Add(Load(<recv>), K))` - load vptr from receiver, add
    // slot offset, load method pointer - render as
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

        // vptr_expr should be a Load of the receiver - the vtable pointer
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
        // as a simple expression - better to fall back to `(*…)(…)`
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
    [[nodiscard]] static bool is_declared_fp_scalar(std::string_view type) noexcept {
        if (type.find('*') != std::string_view::npos ||
            type.find('&') != std::string_view::npos ||
            type.find('[') != std::string_view::npos) {
            return false;
        }
        return type.find("double") != std::string_view::npos ||
               type.find("float") != std::string_view::npos;
    }

    [[nodiscard]] static std::optional<u32>
    ppc_known_aggregate_size(std::string_view type) noexcept {
        type = trim_line_view(type);
        if (type.find('*') != std::string_view::npos ||
            type.find('&') != std::string_view::npos ||
            type.find('[') != std::string_view::npos) {
            return std::nullopt;
        }
        constexpr std::array<std::string_view, 3> qualifiers = {
            "const ", "volatile ", "struct "
        };
        bool changed = true;
        while (changed) {
            changed = false;
            for (std::string_view q : qualifiers) {
                if (type.starts_with(q)) {
                    type.remove_prefix(q.size());
                    type = trim_line_view(type);
                    changed = true;
                }
            }
        }
        if (type == "GXColor" || type == "GXColorS10") return 4;
        if (type == "CXParsedHeader") return 8;
        if (type == "Vec" || type == "Vec3") return 12;
        if (type == "Quaternion" || type == "Quat") return 16;
        return std::nullopt;
    }

    [[nodiscard]] static bool
    ppc_return_uses_hidden_sret(std::string_view type) noexcept {
        auto size = ppc_known_aggregate_size(type);
        return size && *size > 8;
    }

    [[nodiscard]] bool is_ppc_abi() const noexcept {
        return abi == Abi::Ppc32Sysv || abi == Abi::Ppc64ElfV1Be ||
               abi == Abi::Ppc64ElfV2Le;
    }

    [[nodiscard]] i64 ppc_parameter_area_base() const noexcept {
        return abi == Abi::Ppc32Sysv ? 0x08 : 0x30;
    }

    [[nodiscard]] i64 ppc_parameter_word_size() const noexcept {
        return abi == Abi::Ppc32Sysv ? 4 : 8;
    }

    [[nodiscard]] i64 ppc_advance_parameter_slot(i64& cursor,
                                                  IrType type,
                                                  u32 byte_width = 0) const noexcept {
        const i64 word = ppc_parameter_word_size();
        i64 width = byte_width != 0
            ? static_cast<i64>(byte_width)
            : static_cast<i64>(type_bits(type) / 8);
        width = std::max<i64>(word, width);
        i64 align = std::min<i64>(width, 8);
        cursor = (cursor + align - 1) / align * align;
        const i64 result = cursor;
        cursor += (width + word - 1) / word * word;
        return result;
    }

    [[nodiscard]] const std::string*
    abi_param_for(const FunctionSig& sig, Reg r) const noexcept {
        const auto int_regs   = int_arg_regs(abi);
        const auto fp_regs    = fp_arg_regs(abi);
        const bool positional = abi_positional_arg_slots(abi);
        const Reg canon = canonical_reg(r);
        std::size_t int_idx = is_ppc_abi() &&
            ppc_return_uses_hidden_sret(sig.return_type) ? 1u : 0u;
        std::size_t fp_idx  = 0;
        std::size_t slot    = 0;
        for (const auto& p : sig.params) {
            const bool is_fp = is_declared_fp_scalar(p.type);
            const auto aggregate_size = is_ppc_abi()
                ? ppc_known_aggregate_size(p.type)
                : std::nullopt;
            if (is_fp) {
                const std::size_t idx = positional ? slot : fp_idx;
                if (idx < fp_regs.size() && fp_regs[idx] == canon) return &p.name;
                ++fp_idx;
            } else {
                const std::size_t idx = positional ? slot : int_idx;
                if (idx < int_regs.size() && int_regs[idx] == canon) return &p.name;
                const std::size_t words = aggregate_size
                    ? std::max<std::size_t>(1, (*aggregate_size +
                        static_cast<u32>(ppc_parameter_word_size()) - 1) /
                        static_cast<u32>(ppc_parameter_word_size()))
                    : 1;
                int_idx += words;
            }
            ++slot;
        }
        return nullptr;
    }

    [[nodiscard]] std::vector<InferredArgument>
    abi_layout_for(const FunctionSig& sig) const {
        const auto int_regs = int_arg_regs(abi);
        const auto fp_regs = fp_arg_regs(abi);
        const bool positional = abi_positional_arg_slots(abi);
        const bool hidden_sret = is_ppc_abi() &&
            ppc_return_uses_hidden_sret(sig.return_type);
        std::size_t int_idx = hidden_sret ? 1u : 0u;
        std::size_t fp_idx = 0;
        std::size_t slot = 0;
        i64 ppc_cursor = is_ppc_abi() ? ppc_parameter_area_base() : 0;
        if (hidden_sret) {
            (void)ppc_advance_parameter_slot(ppc_cursor, abi_word_type());
        }
        std::vector<InferredArgument> result;
        result.reserve(std::min<std::size_t>(sig.params.size(), kMaxAbiArgs));
        for (const auto& param : sig.params) {
            if (result.size() >= kMaxAbiArgs) break;
            const bool is_fp = is_declared_fp_scalar(param.type);
            const auto aggregate_size = is_ppc_abi()
                ? ppc_known_aggregate_size(param.type)
                : std::nullopt;
            const std::size_t index = positional ? slot : (is_fp ? fp_idx : int_idx);
            Reg reg = Reg::None;
            std::size_t int_words = 1;
            const IrType ir_type = is_fp
                ? (param.type.find("float") != std::string::npos
                       ? IrType::F32 : IrType::F64)
                : abi_word_type();
            std::optional<i64> stack_slot;
            const i64 ppc_slot = is_ppc_abi()
                ? ppc_advance_parameter_slot(ppc_cursor, ir_type,
                                             aggregate_size.value_or(0))
                : 0;
            if (is_fp) {
                if (index < fp_regs.size()) reg = fp_regs[index];
                ++fp_idx;
            } else {
                int_words = aggregate_size
                    ? std::max<std::size_t>(1, (*aggregate_size +
                        static_cast<u32>(ppc_parameter_word_size()) - 1) /
                        static_cast<u32>(ppc_parameter_word_size()))
                    : 1;
                if (index < int_regs.size() && index + int_words <= int_regs.size()) {
                    reg = int_regs[index];
                }
                int_idx += int_words;
            }
            if (is_ppc_abi() && reg == Reg::None) stack_slot = ppc_slot;
            result.push_back({reg, ir_type, false, stack_slot,
                              static_cast<u8>(int_words),
                              aggregate_size.value_or(0),
                              aggregate_size
                                  ? normalize_c_type_alias(param.type)
                                  : std::string{}});
            ++slot;
        }
        return result;
    }

    [[nodiscard]] std::vector<InferredArgument>
    abi_layout_for_import(std::string_view name) const {
        TypeArena arena;
        auto spec = lookup_import_sig(name, arena);
        if (!spec) return {};
        const auto int_regs = int_arg_regs(abi);
        const auto fp_regs = fp_arg_regs(abi);
        const bool positional = abi_positional_arg_slots(abi);
        std::size_t int_idx = 0;
        std::size_t fp_idx = 0;
        i64 ppc_cursor = is_ppc_abi() ? ppc_parameter_area_base() : 0;
        if (is_ppc_abi() && arena.kind(spec->ret) == TypeKind::Struct &&
            arena.node(spec->ret).s.size > 8) {
            int_idx = 1;
            (void)ppc_advance_parameter_slot(ppc_cursor, abi_word_type());
        }
        std::vector<InferredArgument> result;
        result.reserve(std::min<std::size_t>(spec->params.size(), kMaxAbiArgs));
        for (std::size_t slot = 0;
             slot < spec->params.size() && result.size() < kMaxAbiArgs; ++slot) {
            const TypeRef type = spec->params[slot];
            const bool is_fp = arena.kind(type) == TypeKind::Float;
            const u32 aggregate_size = arena.kind(type) == TypeKind::Struct
                ? arena.node(type).s.size
                : 0;
            const std::size_t index = positional ? slot : (is_fp ? fp_idx : int_idx);
            Reg reg = Reg::None;
            IrType ir_type = abi_word_type();
            std::size_t int_words = 1;
            std::optional<i64> stack_slot;
            if (is_fp) {
                if (index < fp_regs.size()) reg = fp_regs[index];
                ir_type = arena.node(type).f.bits <= 32 ? IrType::F32 : IrType::F64;
                ++fp_idx;
            } else {
                int_words = aggregate_size != 0
                    ? std::max<std::size_t>(1, (aggregate_size +
                        static_cast<u32>(ppc_parameter_word_size()) - 1) /
                        static_cast<u32>(ppc_parameter_word_size()))
                    : 1;
                if (index < int_regs.size() && index + int_words <= int_regs.size()) {
                    reg = int_regs[index];
                }
                int_idx += int_words;
            }
            const i64 ppc_slot = is_ppc_abi()
                ? ppc_advance_parameter_slot(ppc_cursor, ir_type, aggregate_size)
                : 0;
            if (is_ppc_abi() && reg == Reg::None) stack_slot = ppc_slot;
            result.push_back({reg, ir_type, false, stack_slot,
                              static_cast<u8>(int_words), aggregate_size,
                              aggregate_size != 0 ? arena.node(type).s.name
                                                  : std::string{}});
        }
        return result;
    }

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
    incoming_stack_arg_name(const IrValue& addr, i64 off) const {
        if (!fn) return std::nullopt;
        if (is_ppc_abi()) {
            auto entry_off = entry_stack_offset(addr);
            if (!entry_off) return std::nullopt;
            for (std::size_t i = 0; i < self_arg_layout.size(); ++i) {
                const auto& arg = self_arg_layout[i];
                if (!arg.stack_offset || *arg.stack_offset != *entry_off) continue;
                if (i < self_arg_names.size() && !self_arg_names[i].empty()) {
                    return self_arg_names[i];
                }
                if (annotations) {
                    if (const FunctionSig* sig = annotations->signature_for(fn->start);
                        sig && i < sig->params.size() && !sig->params[i].name.empty()) {
                        return sig->params[i].name;
                    }
                }
                return std::format("a{}", i + 1);
            }
            return std::nullopt;
        }
        if (!abi_positional_arg_slots(abi)) return std::nullopt;
        if (off < 0x08 || (off - 0x08) % 8 != 0) return std::nullopt;
        const std::size_t k = static_cast<std::size_t>((off - 0x08) / 8);
        if (k < int_arg_regs(abi).size()) return std::nullopt;  // register-arg home

        if (annotations) {
            if (const FunctionSig* sig = annotations->signature_for(fn->start); sig) {
                if (k < sig->params.size() && !sig->params[k].name.empty()) {
                    return sig->params[k].name;
                }
            }
        }
        return std::format("a{}", k + 1);
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
        const Reg canon = canonical_reg(r);
        for (u8 i = 0; i < self_arg_layout.size() && i < self_arity; ++i) {
            if (canonical_reg(self_arg_layout[i].reg) == canon) {
                if (i < self_arg_names.size() && !self_arg_names[i].empty()) {
                    return self_arg_names[i];
                }
                return std::format("a{}", i + 1);
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] IrType abi_word_type() const noexcept {
        return abi == Abi::Ppc32Sysv ? IrType::I32 : IrType::I64;
    }

    [[nodiscard]] std::string_view abi_word_c_type() const noexcept {
        return abi_word_type() == IrType::I32 ? "uint32_t" : "uint64_t";
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
    [[nodiscard]] std::optional<IrValue>
    preserved_call_arg_for_clobber(Reg r, u32 version) const {
        if (!binary || !fn || version == 0) return std::nullopt;
        const Reg canon = canonical_reg(r);

        const auto int_regs = int_arg_regs(abi);
        const auto fp_regs = fp_arg_regs(abi);
        std::optional<std::size_t> slot;
        bool fp_bank = false;
        for (std::size_t i = 0; i < int_regs.size(); ++i) {
            if (int_regs[i] == canon) {
                slot = i;
                break;
            }
        }
        if (!slot) {
            for (std::size_t i = 0; i < fp_regs.size(); ++i) {
                if (fp_regs[i] == canon) {
                    slot = i;
                    fp_bank = true;
                    break;
                }
            }
        }
        if (!slot) return std::nullopt;

        IrValue v = IrValue::make_reg(canon, fp_bank ? IrType::F64
                                                     : abi_word_type());
        v.version = version;
        auto key = ssa_key(v);
        if (!key) return std::nullopt;
        const IrInst* def = def_of(v);
        if (!def || def->op != IrOp::Clobber) return std::nullopt;
        auto pos_it = def_pos.find(*key);
        if (pos_it == def_pos.end()) return std::nullopt;
        const auto [bi, clobber_ii] = pos_it->second;
        if (bi >= fn->blocks.size()) return std::nullopt;
        const auto& bb = fn->blocks[bi];

        std::optional<std::size_t> call_ii;
        bool abi_helper = false;
        for (std::size_t ii = clobber_ii; ii > 0; ) {
            --ii;
            const IrInst& prev = bb.insts[ii];
            if (prev.op == IrOp::Clobber || prev.op == IrOp::Nop) continue;
            if (prev.op == IrOp::Call) {
                if (binary->import_at_plt(prev.target1)) return std::nullopt;
                call_ii = ii;
                abi_helper = is_ppc_abi_helper_call(prev);
            }
            break;
        }
        if (!call_ii) return std::nullopt;
        const bool ppc_fp_return =
            (abi == Abi::Ppc32Sysv || abi == Abi::Ppc64ElfV1Be ||
             abi == Abi::Ppc64ElfV2Le) && canon == Reg::PpcF1;
        if ((canon == int_return_reg(abi) || canon == fp_return_reg(abi) ||
             ppc_fp_return) && !abi_helper) {
            return std::nullopt;
        }

        std::vector<IrValue> args;
        args.reserve(fp_bank ? fp_regs.size() : int_regs.size());
        const std::string_view prefix = fp_bank ? "call.fp_args."
                                                : "call.args.";
        for (std::size_t ii = 0; ii < *call_ii; ++ii) {
            const IrInst& inst = bb.insts[ii];
            if (inst.op == IrOp::Intrinsic && inst.name.starts_with(prefix)) {
                if (inst.name == std::string(prefix) + "1") args.clear();
                for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                    args.push_back(inst.srcs[i]);
                }
                continue;
            }
            if (inst.op == IrOp::Call || inst.op == IrOp::CallIndirect) {
                args.clear();
            }
        }
        if (*slot >= args.size()) return std::nullopt;
        if (is_stale_arg_reg(args[*slot])) return std::nullopt;
        return args[*slot];
    }

    [[nodiscard]] std::string render_reg_leaf(Reg r, u32 version,
                                              int depth = 0,
                                              int min_prec = 0) const {
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
            if (auto arg = preserved_call_arg_for_clobber(cur_reg, cur_ver); arg) {
                return expr(*arg, 0);
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
                if (depth < kMaxExprDepth) return expr(src, depth + 1, min_prec);
                break;
            }
            // Phi-merged reg: if every incoming operand renders to the
            // same expression (common for `rax = phi(rax_v1, t17)` where
            // t17 traces back to the same call's return), emit that.
            if (d->op == IrOp::Phi && depth < kMaxExprDepth && !d->phi_operands.empty()) {
                std::optional<u8> common_self_arg;
                bool all_self_arg_aliases = true;
                for (const auto& op : d->phi_operands) {
                    auto opk = ssa_key(op);
                    if (opk && *opk == k) continue;  // self-reference
                    auto slot = trace_to_self_arg_slot(op, depth + 1);
                    if (!slot) { all_self_arg_aliases = false; break; }
                    if (!common_self_arg) common_self_arg = *slot;
                    else if (*common_self_arg != *slot) {
                        all_self_arg_aliases = false;
                        break;
                    }
                }
                if (all_self_arg_aliases && common_self_arg) {
                    const std::size_t slot = *common_self_arg;
                    if (slot < self_arg_names.size() && !self_arg_names[slot].empty()) {
                        return self_arg_names[slot];
                    }
                    return std::format("a{}", slot + 1);
                }

                std::optional<i64> common_slot;
                bool all_slot_aliases = true;
                for (const auto& op : d->phi_operands) {
                    auto opk = ssa_key(op);
                    if (opk && *opk == k) continue;  // self-reference
                    auto off = single_write_slot_alias_for_value(op);
                    if (!off) { all_slot_aliases = false; break; }
                    if (!common_slot) common_slot = *off;
                    else if (*common_slot != *off) {
                        all_slot_aliases = false;
                        break;
                    }
                }
                if (all_slot_aliases && common_slot) return stack_name(*common_slot);

                std::optional<IrValue> common_root;
                bool all_same_root = true;
                for (const auto& op : d->phi_operands) {
                    auto opk = ssa_key(op);
                    if (opk && *opk == k) continue;  // self-reference
                    auto root = alias_root_for_value(op);
                    if (!root) { all_same_root = false; break; }
                    if (!common_root) common_root = *root;
                    else if (!same_value_key(*common_root, *root)) {
                        all_same_root = false;
                        break;
                    }
                }
                if (all_same_root && common_root) return expr(*common_root, depth + 1);

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
        // Obj-C IMPs outrank the ELF / Mach-O symbol table - a class method
        // with `-[Foo bar:]` shape reads at the call site better than any
        // mangled function-pointer name.
        if (auto it = objc_by_imp.find(target); it != objc_by_imp.end()) {
            return std::format("{}[{} {}]",
                               it->second->is_class ? '+' : '-',
                               it->second->cls,
                               it->second->selector);
        }
        if (auto it = objc_block_by_invoke.find(target);
            it != objc_block_by_invoke.end()) {
            return objc_block_invoke_name(target);
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

    [[nodiscard]] bool same_value_key(const IrValue& a,
                                      const IrValue& b) const noexcept {
        auto ak = ssa_key(a);
        auto bk = ssa_key(b);
        return ak && bk && *ak == *bk;
    }

    [[nodiscard]] std::optional<i64>
    single_write_slot_alias_for_value(const IrValue& v) const {
        if (const IrInst* d = def_stripped(v);
            d && d->op == IrOp::Load && d->segment == Reg::None &&
            d->src_count >= 1) {
            if (auto off = stack_offset(d->srcs[0]); off) return off;
        }
        for (const auto& [off, stored] : single_write_slot_value) {
            if (same_value_key(v, stored)) return off;
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<IrValue>
    alias_root_for_value(const IrValue& v, int depth = 0) const {
        if (depth > 12) return std::nullopt;
        const IrInst* d = def_stripped(v);
        if (!d) return v;
        if (d->op == IrOp::Assign && d->src_count >= 1) {
            return alias_root_for_value(d->srcs[0], depth + 1);
        }
        if (d->op == IrOp::Load && d->segment == Reg::None && d->src_count >= 1) {
            if (auto off = stack_offset(d->srcs[0]); off) {
                if (auto it = single_write_slot_value.find(*off);
                    it != single_write_slot_value.end()) {
                    return alias_root_for_value(it->second, depth + 1);
                }
            }
        }
        if (d->op == IrOp::Phi && !d->phi_operands.empty()) {
            auto self_key = ssa_key(v);
            std::optional<IrValue> common;
            for (const auto& op : d->phi_operands) {
                auto opk = ssa_key(op);
                if (self_key && opk && *self_key == *opk) continue;
                auto root = alias_root_for_value(op, depth + 1);
                if (!root) return std::nullopt;
                if (!common) common = *root;
                else if (!same_value_key(*common, *root)) return std::nullopt;
            }
            return common;
        }
        return v;
    }

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
    [[nodiscard]] bool is_stale_arg_reg(const IrValue& a, int depth = 0) const {
        if (depth > 8) return false;
        if (a.kind != IrValueKind::Reg) return false;
        if (a.version == 0) {
            if (annotations && fn) {
                if (const FunctionSig* sig = annotations->signature_for(fn->start); sig) {
                    if (abi_param_for(*sig, a.reg)) return false;
                }
            }
            // Fall back to the inferred mixed-register layout: a live-in FPR
            // forwarded by a PPC wrapper is just as real as a GPR argument.
            const Reg canon = canonical_reg(a.reg);
            for (u8 i = 0; i < self_arg_layout.size() && i < self_arity; ++i) {
                if (canonical_reg(self_arg_layout[i].reg) == canon) return false;
            }
            return true;
        }
        if (const IrInst* d = def_of(a); d && d->op == IrOp::Clobber) {
            // Bound call returns (rax → r_strlen, etc.) are real values
            // even though their def is a Clobber - the binding name
            // proves a downstream reader picked the value up.
            if (auto k = ssa_key(a); k &&
                call_return_names.find(*k) != call_return_names.end()) {
                return false;
            }
            return true;
        }
        if (const IrInst* d = def_stripped(a);
            d && d->op == IrOp::Phi && !d->phi_operands.empty()) {
            bool saw_operand = false;
            const auto self = ssa_key(a);
            for (const auto& op : d->phi_operands) {
                if (auto ok = ssa_key(op); self && ok && *ok == *self) {
                    continue;
                }
                saw_operand = true;
                if (!is_stale_arg_reg(op, depth + 1)) return false;
            }
            return saw_operand;
        }
        return false;
    }

    // Arity for a known routine by name - user signature at its address beats
    // the typed built-in table, which beats the legacy name and mangling
    // fallbacks. The typed table also carries stable platform SDK prototypes.
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
        {
            TypeArena arena;
            if (auto spec = lookup_import_sig(name, arena); spec) {
                // Variadic call width comes from the existing format-string
                // parser. Returning only the fixed prototype prefix here
                // would truncate printf/scanf payload arguments.
                if (spec->variadic) return std::nullopt;
                return static_cast<u8>(std::min<std::size_t>(
                    spec->params.size(), std::numeric_limits<u8>::max()));
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

    [[nodiscard]] static bool is_objc_msgsend_name(std::string_view name) noexcept {
        return name == "objc_msgSend" ||
               name == "objc_msgSend_fpret" ||
               name == "objc_msgSend_fp2ret" ||
               name == "objc_msgSendSuper" ||
               name == "objc_msgSendSuper2" ||
               name == "objc_msgSendSuper2_stret" ||
               name == "objc_msgSend_stret";
    }

    [[nodiscard]] static bool is_objc_super_msgsend_name(std::string_view name) noexcept {
        return name == "objc_msgSendSuper" ||
               name == "objc_msgSendSuper2" ||
               name == "objc_msgSendSuper2_stret";
    }

    [[nodiscard]] static bool is_objc_stret_msgsend_name(std::string_view name) noexcept {
        return name == "objc_msgSend_stret" ||
               name == "objc_msgSendSuper2_stret";
    }

    [[nodiscard]] static std::optional<u8>
    objc_runtime_fixed_arity(std::string_view name) noexcept {
        static const std::pair<std::string_view, unsigned> kTable[] = {
            {"objc_alloc", 1},
            {"objc_allocWithZone", 1},
            {"objc_autoreleasePoolPop", 1},
            {"objc_autoreleasePoolPush", 0},
            {"objc_autorelease", 1},
            {"objc_autoreleaseReturnValue", 1},
            {"objc_begin_catch", 1},
            {"objc_claimAutoreleasedReturnValue", 1},
            {"objc_copyWeak", 2},
            {"objc_destroyWeak", 1},
            {"objc_end_catch", 0},
            {"objc_getProperty", 4},
            {"objc_initWeak", 2},
            {"objc_enumerationMutation", 1},
            {"objc_loadWeak", 1},
            {"objc_loadWeakRetained", 1},
            {"objc_moveWeak", 2},
            {"objc_release", 1},
            {"objc_retain", 1},
            {"objc_retainAutorelease", 1},
            {"objc_retainAutoreleaseReturnValue", 1},
            {"objc_retainAutoreleasedReturnValue", 1},
            {"objc_retainBlock", 1},
            {"objc_setAssociatedObject", 4},
            {"objc_setProperty_atomic", 4},
            {"objc_setProperty_atomic_copy", 4},
            {"objc_setProperty_nonatomic", 4},
            {"objc_setProperty_nonatomic_copy", 4},
            {"objc_storeStrong", 2},
            {"objc_storeWeak", 2},
            {"objc_sync_enter", 1},
            {"objc_sync_exit", 1},
            {"objc_unsafeClaimAutoreleasedReturnValue", 1},
        };
        for (const auto& [n, arity] : kTable) {
            if (n == name) return static_cast<u8>(arity);
        }
        return std::nullopt;
    }

    [[nodiscard]] static u8 selector_argument_count(std::string_view selector) noexcept {
        u8 n = 0;
        for (char c : selector) {
            if (c == ':' && n < kMaxAbiIntArgs) ++n;
        }
        return n;
    }

    [[nodiscard]] static bool objc_selector_takes_format_varargs(
        std::string_view selector) noexcept {
        return selector == "stringWithFormat:" ||
               selector == "localizedStringWithFormat:" ||
               selector == "initWithFormat:" ||
               selector == "appendFormat:";
    }

    [[nodiscard]] static u8 count_objc_format_specifiers(std::string_view fmt) noexcept {
        u8 count = 0;
        for (std::size_t i = 0; i < fmt.size(); ) {
            if (fmt[i] != '%') { ++i; continue; }
            ++i;
            if (i >= fmt.size()) break;
            if (fmt[i] == '%') { ++i; continue; }
            while (i < fmt.size()) {
                const char c = fmt[i];
                if (c == '*') {
                    if (count < 255) ++count;
                    ++i;
                    continue;
                }
                const bool is_conv =
                    c == '@' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
                if (is_conv && c != 'l' && c != 'h' && c != 'L' && c != 'z' &&
                    c != 'j' && c != 't' && c != 'q') {
                    if (count < 255) ++count;
                    ++i;
                    break;
                }
                ++i;
            }
        }
        return count;
    }

    [[nodiscard]] std::optional<std::string>
    objc_selector_for_value(const IrValue& v) const {
        if (!options.objc_selrefs) return std::nullopt;
        const IrInst* d = def_stripped(v);
        if (!d || d->op != IrOp::Load || d->src_count < 1) return std::nullopt;
        auto imm = try_resolve_imm_addr(d->srcs[0]);
        if (!imm) return std::nullopt;
        auto it = options.objc_selrefs->find(static_cast<addr_t>(*imm));
        if (it == options.objc_selrefs->end()) return std::nullopt;
        return it->second;
    }

    [[nodiscard]] std::optional<std::string>
    objc_selector_for_rendered_value(const IrValue& v) const {
        auto sel = objc_selector_for_value(v);
        if (sel) return sel;
        const std::string rendered = expr(v);
        static constexpr std::string_view kPrefix = "@selector(";
        if (!rendered.starts_with(kPrefix) || !rendered.ends_with(")")) {
            return std::nullopt;
        }
        return rendered.substr(kPrefix.size(),
                               rendered.size() - kPrefix.size() - 1);
    }

    [[nodiscard]] std::optional<u8>
    objc_call_arity(std::string_view name,
                    const std::vector<IrValue>& args) const {
        if (auto fixed = objc_runtime_fixed_arity(name)) return fixed;
        if (!is_objc_msgsend_name(name)) return std::nullopt;
        const bool stret = is_objc_stret_msgsend_name(name);
        const std::size_t sel_index = stret ? 2u : 1u;
        if (args.size() <= sel_index) {
            return static_cast<u8>(stret ? 3 : 2);
        }
        auto sel = objc_selector_for_rendered_value(args[sel_index]);
        if (!sel) return std::nullopt;
        const u8 base = static_cast<u8>(stret ? 3 : 2);
        unsigned arity = static_cast<unsigned>(base + selector_argument_count(*sel));
        if (objc_selector_takes_format_varargs(*sel)) {
            const std::size_t fmt_index = static_cast<std::size_t>(base);
            if (fmt_index < args.size()) {
                if (auto fmt = resolve_string_value(args[fmt_index]); fmt) {
                    arity += count_objc_format_specifiers(*fmt);
                }
            }
        }
        return static_cast<u8>(std::min<unsigned>(kMaxAbiIntArgs, arity));
    }

    [[nodiscard]] static std::string simplify_objc_class_receiver(std::string s) {
        static constexpr std::string_view kSuffix = " class]";
        if (s.starts_with("[") && s.ends_with(kSuffix)) {
            return s.substr(1, s.size() - kSuffix.size() - 1);
        }
        return s;
    }

    [[nodiscard]] static std::vector<std::string_view>
    objc_selector_pieces(std::string_view selector) {
        std::vector<std::string_view> pieces;
        std::size_t start = 0;
        while (start < selector.size()) {
            const std::size_t colon = selector.find(':', start);
            if (colon == std::string_view::npos) break;
            pieces.push_back(selector.substr(start, colon - start));
            start = colon + 1;
        }
        return pieces;
    }

    [[nodiscard]] static std::string objc_stret_assignment_target(std::string s) {
        s = strip_outer_parens(s);
        s = std::string(trim_line_view(s));
        if (s.starts_with("&")) {
            return std::string(trim_line_view(s.substr(1)));
        }
        return std::format("*({})", s);
    }

    [[nodiscard]] static std::string objc_address_arg_text(std::string s) {
        s = strip_outer_parens(s);
        s = std::string(trim_line_view(s));
        if (s.empty() || s.starts_with("&")) return s;
        return std::format("&{}", s);
    }

    [[nodiscard]] std::string objc_address_arg(const IrValue& v) const {
        if (auto off = stack_offset(v); off) {
            return std::format("&{}", stack_name(*off));
        }
        if (auto ivar = try_render_objc_ivar_access(v); ivar) {
            return std::format("&{}", *ivar);
        }
        return objc_address_arg_text(
            expr(v, 0, std::to_underlying(Prec::Unary)));
    }

    [[nodiscard]] std::optional<std::string>
    try_render_objc_self_ivar_at_offset(const IrValue& receiver,
                                        const IrValue& offset) const {
        if (!fn) return std::nullopt;
        auto ctx = objc_receiver_context(receiver);
        if (!ctx || ctx->cls.empty() || ctx->display.empty()) return std::nullopt;
        auto off = resolve_imm(offset);
        if (!off || *off < 0) return std::nullopt;
        auto it = objc_ivar_by_class_offset.find(
            {ctx->cls, static_cast<u64>(*off)});
        if (it == objc_ivar_by_class_offset.end()) return std::nullopt;
        const ObjcIvar& iv = *it->second;
        if (iv.cls != ctx->cls) return std::nullopt;
        if (!objc_ivar_name_is_safe(iv.name)) return std::nullopt;
        return std::format("{}->{}", ctx->display, objc_ivar_display_name(iv));
    }

    [[nodiscard]] static bool is_objc_property_setter_runtime(
        std::string_view name) noexcept {
        return name == "objc_setProperty_atomic" ||
               name == "objc_setProperty_atomic_copy" ||
               name == "objc_setProperty_nonatomic" ||
               name == "objc_setProperty_nonatomic_copy";
    }

    [[nodiscard]] std::optional<std::string>
    render_objc_property_runtime_call(std::string_view name,
                                      const std::vector<IrValue>& args) const {
        if (name == "objc_getProperty" && args.size() >= 4) {
            if (auto ivar = try_render_objc_self_ivar_at_offset(args[0], args[2])) {
                return ivar;
            }
        }
        if (is_objc_property_setter_runtime(name) && args.size() >= 4) {
            if (auto ivar = try_render_objc_self_ivar_at_offset(args[0], args[3])) {
                return std::format("{}(&{}, {})",
                                   name, *ivar,
                                   expr(args[2], 0, std::to_underlying(Prec::Unary)));
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<std::string>
    render_objc_address_runtime_call(std::string_view name,
                                     const std::vector<IrValue>& args) const {
        auto arg = [&](std::size_t i) {
            return expr(args[i], 0, std::to_underlying(Prec::Unary));
        };
        auto addr_arg = [&](std::size_t i) {
            return objc_address_arg(args[i]);
        };
        if ((name == "objc_storeStrong" || name == "objc_storeWeak" ||
             name == "objc_initWeak") && args.size() >= 2) {
            return std::format("{}({}, {})", name, addr_arg(0), arg(1));
        }
        if ((name == "objc_copyWeak" || name == "objc_moveWeak") &&
            args.size() >= 2) {
            return std::format("{}({}, {})", name, addr_arg(0), addr_arg(1));
        }
        if ((name == "objc_destroyWeak" || name == "objc_loadWeak" ||
             name == "objc_loadWeakRetained") && !args.empty()) {
            return std::format("{}({})", name, addr_arg(0));
        }
        return std::nullopt;
    }

    [[nodiscard]] bool objc_selector_arg_is_usable(const IrValue& v) const {
        return !is_stale_arg_reg(v);
    }

    [[nodiscard]] bool objc_selector_arg_looks_like_stack_gap(
        const IrValue& v) const {
        return is_stale_arg_reg(v) || renders_raw_arch_reg_name(v);
    }

    [[nodiscard]] static bool objc_selector_piece_likely_stack_aggregate(
        std::string_view piece) noexcept {
        return piece.ends_with("Frame") || piece.ends_with("Rect") ||
               piece.ends_with("Range") || piece.ends_with("Size") ||
               piece.ends_with("Point");
    }

    [[nodiscard]] std::optional<std::string>
    render_objc_message_call(std::string_view name,
                             const std::vector<IrValue>& args) const {
        const bool stret = is_objc_stret_msgsend_name(name);
        if (!is_objc_msgsend_name(name)) return std::nullopt;
        const bool super = is_objc_super_msgsend_name(name);
        const std::size_t out_index = 0;
        const std::size_t recv_index = stret ? 1u : 0u;
        const std::size_t sel_index = stret ? 2u : 1u;
        const std::size_t arg_base = stret ? 3u : 2u;
        if (args.size() <= sel_index) return std::nullopt;
        auto selector = objc_selector_for_rendered_value(args[sel_index]);
        if (!selector) return std::nullopt;
        std::string receiver = super
            ? std::string{"super"}
            : simplify_objc_class_receiver(
                  expr(args[recv_index], 0, std::to_underlying(Prec::Postfix)));
        if (receiver.empty()) return std::nullopt;
        const u8 selector_args = selector_argument_count(*selector);
        if (args.size() < static_cast<std::size_t>(arg_base + selector_args)) {
            return std::nullopt;
        }
        std::string out = std::format("[{} ", receiver);
        if (selector_args == 0) {
            out += *selector;
        } else {
            auto pieces = objc_selector_pieces(*selector);
            if (pieces.size() != selector_args) return std::nullopt;
            const bool first_arg_is_stack_aggregate =
                selector_args >= 2 &&
                objc_selector_piece_likely_stack_aggregate(pieces[0]) &&
                objc_selector_arg_is_usable(args[arg_base]) &&
                objc_selector_arg_looks_like_stack_gap(args[arg_base + 1]);
            for (std::size_t i = 0; i < pieces.size(); ++i) {
                if (i > 0) out += " ";
                out += pieces[i];
                out += ":";
                if (first_arg_is_stack_aggregate) {
                    if (i == 0) {
                        out += "/* stack arg */";
                        continue;
                    }
                    const std::size_t shifted = arg_base + i - 1;
                    if (!objc_selector_arg_is_usable(args[shifted])) {
                        return std::nullopt;
                    }
                    out += expr(args[shifted]);
                    continue;
                }
                if (!objc_selector_arg_is_usable(args[arg_base + i])) {
                    return std::nullopt;
                }
                out += expr(args[arg_base + i]);
            }
        }
        if (objc_selector_takes_format_varargs(*selector)) {
            const std::size_t fmt_index = arg_base;
            if (fmt_index < args.size()) {
                if (auto fmt = resolve_string_value(args[fmt_index]); fmt) {
                    const std::size_t n_extra = count_objc_format_specifiers(*fmt);
                    for (std::size_t i = 0; i < n_extra &&
                         fmt_index + 1 + i < args.size(); ++i) {
                        if (!objc_selector_arg_is_usable(args[fmt_index + 1 + i])) {
                            return std::nullopt;
                        }
                        out += ", ";
                        out += expr(args[fmt_index + 1 + i]);
                    }
                }
            }
        }
        out += "]";
        if (stret) {
            const std::string target = objc_stret_assignment_target(
                expr(args[out_index], 0, std::to_underlying(Prec::Unary)));
            if (target.empty()) return std::nullopt;
            out = std::format("{} = {}", target, out);
        }
        return out;
    }

    [[nodiscard]] std::optional<std::string>
    render_objc_runtime_call(std::string_view name,
                             const std::vector<IrValue>& args) const {
        if (auto msg = render_objc_message_call(name, args)) return msg;
        if (auto prop = render_objc_property_runtime_call(name, args)) {
            return prop;
        }
        if (auto addr_call = render_objc_address_runtime_call(name, args)) {
            return addr_call;
        }
        if ((name == "objc_alloc" || name == "objc_allocWithZone") &&
            !args.empty()) {
            std::string receiver = simplify_objc_class_receiver(
                expr(args[0], 0, std::to_underlying(Prec::Postfix)));
            if (!receiver.empty()) return std::format("[{} alloc]", receiver);
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<std::string>
    objc_return_base_for_call(const IrInst& call_inst,
                              const std::vector<IrValue>& args) const {
        std::string name = call_import_name(call_inst).value_or("");
        if (call_inst.op == IrOp::Call) {
            if (name.empty()) name = function_display_name(call_inst.target1);
        }
        if (name.empty()) return std::nullopt;
        if (name == "objc_alloc" || name == "objc_allocWithZone") {
            return std::string{"alloc"};
        }
        if (!is_objc_msgsend_name(name)) return std::nullopt;
        const bool stret = is_objc_stret_msgsend_name(name);
        const std::size_t sel_index = stret ? 2u : 1u;
        if (args.size() <= sel_index) return std::nullopt;
        auto selector = objc_selector_for_rendered_value(args[sel_index]);
        if (!selector || selector->empty()) return std::nullopt;
        const std::size_t colon = selector->find(':');
        std::string_view base = colon == std::string::npos
            ? std::string_view{*selector}
            : std::string_view{*selector}.substr(0, colon);
        if (base.empty()) return std::nullopt;
        return sanitize_ident(base, "msg");
    }

    [[nodiscard]] std::optional<std::string>
    call_import_name(const IrInst& inst) const {
        if (inst.op == IrOp::Call) {
            return import_name_for_direct_call(inst.target1);
        }
        if (inst.op == IrOp::CallIndirect && inst.src_count >= 1) {
            return import_name_for_indirect_call(inst.srcs[0]);
        }
        return std::nullopt;
    }

    [[nodiscard]] const FunctionSig*
    call_annotation_signature(const IrInst& inst) const noexcept {
        if (!annotations) return nullptr;
        if (inst.op == IrOp::Call) {
            return annotations->signature_for(inst.target1);
        }
        if (inst.op == IrOp::CallIndirect && options.call_resolutions &&
            inst.source_addr != 0) {
            auto it = options.call_resolutions->find(inst.source_addr);
            if (it != options.call_resolutions->end()) {
                return annotations->signature_for(it->second);
            }
        }
        return nullptr;
    }

    [[nodiscard]] std::optional<std::string>
    call_known_name(const IrInst& inst) const {
        if (auto imported = call_import_name(inst); imported) return imported;
        if (inst.op == IrOp::Call) return function_display_name(inst.target1);
        if (inst.op == IrOp::CallIndirect && options.call_resolutions &&
            inst.source_addr != 0) {
            auto it = options.call_resolutions->find(inst.source_addr);
            if (it != options.call_resolutions->end()) {
                return function_display_name(it->second);
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<CallReturnLane>
    known_call_return_lane(const IrInst& inst) const {
        if (const FunctionSig* sig = call_annotation_signature(inst); sig) {
            const std::string normalized = normalize_c_type_alias(sig->return_type);
            const std::string_view ret = trim_line_view(normalized);
            if (ret == "void") return CallReturnLane::Void;
            if (is_declared_fp_scalar(ret)) return CallReturnLane::Floating;
            if (!ret.empty()) return CallReturnLane::Integer;
        }
        auto name = call_known_name(inst);
        if (!name) return std::nullopt;
        TypeArena arena;
        auto spec = lookup_import_sig(*name, arena);
        if (!spec || spec->ret.is_top() || spec->ret.is_bottom()) {
            return std::nullopt;
        }
        switch (arena.kind(spec->ret)) {
            case TypeKind::Void:  return CallReturnLane::Void;
            case TypeKind::Float: return CallReturnLane::Floating;
            default:              return CallReturnLane::Integer;
        }
    }

    [[nodiscard]] Reg call_result_reg(const IrInst& inst) const {
        const auto lane = known_call_return_lane(inst);
        if (lane == CallReturnLane::Void) return Reg::None;
        if (lane == CallReturnLane::Floating) return fp_return_reg(abi);
        // Preserve the established behavior for an unknown call: its used
        // integer lane is still a plausible return, while f1 requires proof.
        return int_return_reg(abi);
    }

    [[nodiscard]] std::optional<std::string>
    known_call_return_c_type(const IrInst& inst) const {
        if (const FunctionSig* sig = call_annotation_signature(inst); sig &&
            !sig->return_type.empty()) {
            return normalize_c_type_alias(sig->return_type);
        }
        auto name = call_known_name(inst);
        if (!name) return std::nullopt;
        TypeArena arena;
        auto spec = lookup_import_sig(*name, arena);
        if (!spec || spec->ret.is_top() || spec->ret.is_bottom()) {
            return std::nullopt;
        }
        const TypeNode& ret = arena.node(spec->ret);
        if (ret.kind == TypeKind::Void) return std::string{"void"};
        if (ret.kind == TypeKind::Float) {
            return ret.f.bits <= 32 ? std::string{"float"}
                                    : std::string{"double"};
        }
        if (ret.kind == TypeKind::Struct && !ret.s.name.empty()) {
            return ret.s.name;
        }
        if (ret.kind == TypeKind::Int) {
            const std::string_view prefix = ret.i.sign_known && ret.i.is_signed
                ? "int" : "uint";
            return std::format("{}{}_t", prefix, ret.i.bits);
        }
        return std::nullopt;
    }

    [[nodiscard]] bool is_ppc_abi_helper_call(const IrInst& inst) const {
        if (!binary || inst.op != IrOp::Call ||
            (abi != Abi::Ppc32Sysv && abi != Abi::Ppc64ElfV1Be &&
             abi != Abi::Ppc64ElfV2Le)) {
            return false;
        }
        const Symbol* sym = binary->defined_object_at(inst.target1);
        if (!sym) return false;
        const std::string_view name = sym->name;
        return name.starts_with("_savegpr_") || name.starts_with("_restgpr_") ||
               name.starts_with("_savefpr_") || name.starts_with("_restfpr_") ||
               name.starts_with("__save_gpr") || name.starts_with("__rest_gpr") ||
               name.starts_with("__save_fpr") || name.starts_with("__rest_fpr");
    }

    [[nodiscard]] bool call_inst_returns_void(const IrInst& inst) const {
        if (is_ppc_abi_helper_call(inst)) return true;
        if (auto lane = known_call_return_lane(inst); lane) {
            return *lane == CallReturnLane::Void;
        }
        auto name = call_import_name(inst);
        return name && import_returns_void(*name);
    }

    [[nodiscard]] static bool is_call_arg_barrier(const IrInst& inst) noexcept {
        return inst.op == IrOp::Intrinsic &&
               (inst.name.starts_with("call.args.") ||
                inst.name.starts_with("call.fp_args."));
    }

    [[nodiscard]] static bool is_callee_saved(Reg r) noexcept {
        const Reg c = canonical_reg(r);
        return c == Reg::Rbx || c == Reg::Rbp ||
               c == Reg::R12 || c == Reg::R13 ||
               c == Reg::R14 || c == Reg::R15 ||
               (c >= Reg::PpcR14 && c <= Reg::PpcR31);
    }

    [[nodiscard]] static bool is_stack_base_reg(Reg r) noexcept {
        const Reg c = canonical_reg(r);
        return c == Reg::Rsp || c == Reg::Rbp ||
               c == Reg::PpcR1;
    }

    [[nodiscard]] static std::string normalize_c_type_alias(std::string_view t) {
        auto map_base = [](std::string_view base) -> std::string_view {
            if (base == "u8")  return "uint8_t";
            if (base == "u16") return "uint16_t";
            if (base == "u32") return "uint32_t";
            if (base == "u64") return "uint64_t";
            if (base == "s8" || base == "i8")   return "int8_t";
            if (base == "s16" || base == "i16") return "int16_t";
            if (base == "s32" || base == "i32") return "int32_t";
            if (base == "s64" || base == "i64") return "int64_t";
            return {};
        };

        std::string out(t);
        std::size_t star = out.find('*');
        std::string_view base = star == std::string::npos
            ? std::string_view(out)
            : std::string_view(out).substr(0, star);
        while (!base.empty() && base.back() == ' ') base.remove_suffix(1);
        if (auto mapped = map_base(base); !mapped.empty()) {
            std::string suffix = star == std::string::npos
                ? std::string{}
                : out.substr(star);
            return std::string(mapped) + suffix;
        }
        return out;
    }

    [[nodiscard]] static std::optional<std::string_view>
    standard_global_type(std::string_view name) noexcept {
        if (name == "stdin" || name == "stdout" || name == "stderr") {
            return "FILE*";
        }
        return std::nullopt;
    }

    void note_global_decl(const Symbol& s, std::string type_name) const {
        if (s.name.empty()) return;
        type_name = normalize_c_type_alias(type_name);
        if (type_name.find("(*") == std::string::npos &&
            !type_name.ends_with("[]")) {
            if (auto standard = standard_global_type(s.name); standard) {
                type_name = *standard;
            }
        }
        auto [it, inserted] = global_decls.emplace(s.name, type_name);
        if (inserted || it->second == type_name) return;

        const bool old_funcptr = it->second.find("(*") != std::string::npos;
        const bool new_funcptr = type_name.find("(*") != std::string::npos;
        if (old_funcptr) return;
        if (new_funcptr) {
            it->second = std::move(type_name);
            return;
        }

        const bool old_array = it->second.ends_with("[]");
        const bool new_array = type_name.ends_with("[]");
        if (old_array && !new_array) return;
        if (new_array && !old_array) {
            it->second = std::move(type_name);
            return;
        }
        it->second = "uint64_t";
    }

    // Render an IPA-arena TypeRef as a C type name. Returns empty if the
    // ref is Top or no arena is supplied - caller should fall back.
    [[nodiscard]] std::string ipa_type_name(TypeRef r) const {
        if (!options.type_arena) return {};
        if (r.is_top() || r.is_bottom()) return {};
        const auto& n = options.type_arena->node(r);
        switch (n.kind) {
            case TypeKind::Void: return "void";
            case TypeKind::Int:
                if (n.i.sign_known && n.i.is_signed) {
                    return std::format("int{}_t", n.i.bits);
                }
                return std::format("uint{}_t", n.i.bits);
            case TypeKind::Float:
                return n.f.bits == 32 ? "float" : "double";
            case TypeKind::Ptr: {
                const auto& pn = options.type_arena->node(n.p.pointee);
                if (pn.kind == TypeKind::Int && pn.i.bits == 8) {
                    return "char*";  // canonical char* rendering
                }
                if (pn.kind == TypeKind::Int) {
                    return std::format("uint{}_t*", pn.i.bits);
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
                    return std::format("uint{}_t*", pn.i.bits);
                }
                return "void*";
            }
            case TypeKind::Int:
                if (node.i.sign_known && node.i.is_signed) {
                    return std::format("int{}_t", node.i.bits);
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
                // Skip uses from call.args.* intrinsics - they get absorbed into the
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
        // spill - at -O0 the compiler routinely emits `mov [rbp-N], reg`
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
        // a single use of the parameter - the way the user wrote it.
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
            single_write_slot_value.emplace(off, v);
            // Forward live-in args (rdi/rsi/...) and SSA temps directly:
            // both have a single dominating def that survives unchanged
            // from the store to any later load. Skip clobbers (call-
            // returns) - those represent post-call register state and
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
                    record_struct_access(inst.srcs[0], inst.dst.type);
                } else if (inst.op == IrOp::Store && inst.src_count >= 1 &&
                           inst.segment == Reg::None) {
                    const IrType store_type = inst.src_count >= 2
                        ? inst.srcs[1].type
                        : IrType::I64;
                    record_struct_access(inst.srcs[0], store_type);
                }
            }
        }
    }

    [[nodiscard]] bool phi_value_feeds_step(const SsaKey& k,
                                            bool* non_unit_accum = nullptr) const {
        if (non_unit_accum) *non_unit_accum = false;
        auto uses_it = visible_user_positions.find(k);
        if (uses_it == visible_user_positions.end()) return false;
        bool unit_step = false;
        for (const auto& [bi, ii] : uses_it->second) {
            if (bi >= fn->blocks.size() || ii >= fn->blocks[bi].insts.size()) continue;
            const IrInst& inst = fn->blocks[bi].insts[ii];
            if (inst.src_count < 2) continue;
            if (inst.op != IrOp::Add && inst.op != IrOp::Sub) continue;
            const auto lhs = ssa_key(inst.srcs[0]);
            const auto rhs = ssa_key(inst.srcs[1]);
            const bool lhs_is_phi = lhs && *lhs == k;
            const bool rhs_is_phi = rhs && *rhs == k;
            if (!lhs_is_phi && !rhs_is_phi) continue;
            const IrValue& other = lhs_is_phi ? inst.srcs[1] : inst.srcs[0];
            if (other.kind == IrValueKind::Imm && (other.imm == 1 || other.imm == -1)) {
                unit_step = true;
            } else if (non_unit_accum) {
                *non_unit_accum = true;
            }
        }
        return unit_step;
    }

    [[nodiscard]] bool value_flows_to_memory_address(const SsaKey& k,
                                                     std::set<SsaKey>& seen,
                                                     int depth = 0,
                                                     bool follow_assigns = false) const {
        if (depth > 6 || !seen.insert(k).second) return false;
        auto uses_it = visible_user_positions.find(k);
        if (uses_it == visible_user_positions.end()) return false;
        for (const auto& [bi, ii] : uses_it->second) {
            if (bi >= fn->blocks.size() || ii >= fn->blocks[bi].insts.size()) continue;
            const IrInst& inst = fn->blocks[bi].insts[ii];
            if ((inst.op == IrOp::Load || inst.op == IrOp::Store) &&
                inst.src_count >= 1 && ssa_key(inst.srcs[0]) == k) {
                return true;
            }
            const bool address_arith =
                inst.op == IrOp::Add || inst.op == IrOp::Sub ||
                inst.op == IrOp::Mul || inst.op == IrOp::Shl ||
                inst.op == IrOp::ZExt || inst.op == IrOp::SExt ||
                (follow_assigns && inst.op == IrOp::Assign);
            if (!address_arith) continue;
            auto dk = ssa_key(inst.dst);
            if (!dk) continue;
            if (value_flows_to_memory_address(*dk, seen, depth + 1,
                                              follow_assigns)) return true;
        }
        return false;
    }

    [[nodiscard]] bool phi_value_feeds_indexing(const SsaKey& k) const {
        std::set<SsaKey> seen;
        return value_flows_to_memory_address(k, seen);
    }

    [[nodiscard]] SsaMergeLocalRole merge_role_for_phi(const IrInst& inst) const {
        auto k = ssa_key(inst.dst);
        bool accumulator = false;
        const bool unit_step = k && phi_value_feeds_step(*k, &accumulator);
        if (unit_step && k && phi_value_feeds_indexing(*k)) {
            return SsaMergeLocalRole::Index;
        }
        if (unit_step) return SsaMergeLocalRole::Induction;
        if (inst.dst.kind == IrValueKind::Reg &&
            canonical_reg(inst.dst.reg) == int_return_reg(abi)) {
            return SsaMergeLocalRole::Result;
        }
        const std::string type_name = c_type_name_for(inst.dst);
        if (type_name == "char*") return SsaMergeLocalRole::String;
        if (!type_name.empty() && type_name.ends_with("*")) return SsaMergeLocalRole::Pointer;
        if (inst.dst.type == IrType::I1) return SsaMergeLocalRole::Flag;
        if (accumulator) return SsaMergeLocalRole::Accumulator;
        return SsaMergeLocalRole::Value;
    }

    [[nodiscard]] std::optional<IrValue>
    merge_initializer_candidate(const IrValue& op) const {
        if (op.kind == IrValueKind::Imm) return op;
        if (auto slot = trace_to_self_arg_slot(op); slot) {
            if (*slot < self_arg_layout.size() &&
                self_arg_layout[*slot].reg != Reg::None) {
                return IrValue::make_reg(self_arg_layout[*slot].reg,
                                         self_arg_layout[*slot].type);
            }
        }
        return std::nullopt;
    }

    void name_merge_values() {
        SsaMergeLocalRecoveryCallbacks callbacks;
        callbacks.use_count = [&](const SsaKey& k) { return use_count_by_key(k); };
        callbacks.def_of = [&](const IrValue& v) { return def_of(v); };
        callbacks.type_name = [&](const IrValue& v) { return c_type_name_for(v); };
        callbacks.role_for_phi = [&](const IrInst& inst) {
            return merge_role_for_phi(inst);
        };
        callbacks.initializer_candidate = [&](const IrValue& v) {
            return merge_initializer_candidate(v);
        };
        auto recovered = recover_ssa_merge_locals(*fn, callbacks);
        merge_value_names = std::move(recovered.value_names);
        merge_locals = std::move(recovered.locals);
    }

    void bump_arity_from_merge_initializers() {
        u8 need = self_arity;
        for (const auto& [_, local] : merge_locals) {
            if (!local.initializer) continue;
            bool has_visible_use = false;
            for (const auto& k : local.keys) {
                auto it = visible_uses.find(k);
                if (it != visible_uses.end() && it->second > 0) {
                    has_visible_use = true;
                    break;
                }
            }
            if (!has_visible_use) continue;
            if (auto slot = trace_to_self_arg_slot(*local.initializer); slot) {
                if (*slot < self_arg_layout.size() && *slot + 1 > need) {
                    need = static_cast<u8>(*slot + 1);
                }
            }
        }
        self_arity = need;
    }

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
    std::set<i64> charp_local_slots;

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

    static void append_utf8(std::string& out, u32 cp) {
        if (cp <= 0x7f) {
            out.push_back(static_cast<char>(cp));
        } else if (cp <= 0x7ff) {
            out.push_back(static_cast<char>(0xc0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
        } else if (cp <= 0xffff) {
            out.push_back(static_cast<char>(0xe0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
        } else {
            out.push_back(static_cast<char>(0xf0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
        }
    }

    [[nodiscard]] std::optional<std::string>
    try_decode_cfstring(u64 addr) const {
        if (!binary) return std::nullopt;
        if (cfstring_lo == 0 || addr < cfstring_lo || addr >= cfstring_hi)
            return std::nullopt;
        // Each entry is 32 bytes: u64 isa; u32 flags; u32 pad; u64 data;
        // u64 length. Offsets: data at +16, length at +24.
        auto bytes = binary->bytes_at(static_cast<addr_t>(addr));
        if (bytes.size() < 32) return std::nullopt;
        u32 flags = 0;
        u64 data_ptr = 0, length = 0;
        std::memcpy(&flags,    bytes.data() + 8,  4);
        std::memcpy(&data_ptr, bytes.data() + 16, 8);
        std::memcpy(&length,   bytes.data() + 24, 8);
        if (data_ptr == 0 || length == 0 || length > 1'000'000) return std::nullopt;
        auto strb = binary->bytes_at(static_cast<addr_t>(data_ptr));
        if (strb.size() < length) return std::nullopt;
        const bool maybe_utf16 = length * 2 <= strb.size() && [&] {
            bool saw_wide_marker = false;
            for (u64 i = 0; i < length; ++i) {
                const auto hi = static_cast<unsigned char>(strb[i * 2 + 1]);
                if (hi == 0 || (hi >= 0xd8 && hi <= 0xdf)) {
                    saw_wide_marker = true;
                    continue;
                }
                return false;
            }
            return saw_wide_marker;
        }();
        if (maybe_utf16) {
            std::string s;
            for (u64 i = 0; i < length; ++i) {
                u16 w1 = static_cast<u16>(
                    static_cast<unsigned char>(strb[i * 2]) |
                    (static_cast<u16>(static_cast<unsigned char>(strb[i * 2 + 1])) << 8));
                if (w1 >= 0xd800 && w1 <= 0xdbff) {
                    if (i + 1 >= length) return std::nullopt;
                    ++i;
                    const u16 w2 = static_cast<u16>(
                        static_cast<unsigned char>(strb[i * 2]) |
                        (static_cast<u16>(static_cast<unsigned char>(strb[i * 2 + 1])) << 8));
                    if (w2 < 0xdc00 || w2 > 0xdfff) return std::nullopt;
                    append_utf8(s, 0x10000u +
                        (((static_cast<u32>(w1) - 0xd800u) << 10) |
                         (static_cast<u32>(w2) - 0xdc00u)));
                    continue;
                }
                if (w1 >= 0xdc00 && w1 <= 0xdfff) return std::nullopt;
                if (w1 < 0x20 && w1 != '\t' && w1 != '\n' && w1 != '\r') {
                    return std::nullopt;
                }
                append_utf8(s, w1);
            }
            (void)flags;
            return s;
        }
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
    // it in the for-header - otherwise the For→While fallback in
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

    // Collect every block targeted by a `RegionKind::Goto` so emit_block
    // can prepend a matching `bb_<addr>:` C label. Without this the
    // structurer's `goto bb_<addr>;` references resolve to nothing -
    // there's no destination, just a `// bb_<addr>` comment.
    void collect_goto_targets(const Region& r) {
        if (r.kind == RegionKind::Goto) {
            goto_targets.insert(r.target);
        }
        for (const auto& c : r.children) if (c) collect_goto_targets(*c);
    }

    // Render a single instruction at (block_addr, inst_idx) as its compound-
    // assign form - e.g. `i++`, `i += 2`, `x <<= 1`. Used for the update
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
    // register in the current mixed argument layout. Returns the source-level
    // slot, not the register-bank index.
    [[nodiscard]] std::optional<u8>
    trace_to_self_arg_slot(const IrValue& v, int depth = 0) const {
        if (depth > 8) return std::nullopt;
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
                if (d->op == IrOp::Load && d->segment == Reg::None &&
                    d->src_count >= 1) {
                    if (auto off = stack_offset(d->srcs[0]); off) {
                        if (auto init = init_only_slot_value.find(*off);
                            init != init_only_slot_value.end()) {
                            cur = init->second;
                            continue;
                        }
                    }
                }
                return std::nullopt;
            }
            if (cur.kind != IrValueKind::Reg) return std::nullopt;
            const Reg canon = canonical_reg(cur.reg);
            if (cur.version == 0) {
                for (u8 i = 0; i < self_arg_layout.size(); ++i) {
                    if (canonical_reg(self_arg_layout[i].reg) == canon) return i;
                }
                return std::nullopt;
            }
            if (auto preserved = preserved_call_arg_for_clobber(cur.reg, cur.version);
                preserved) {
                return trace_to_self_arg_slot(*preserved, depth + 1);
            }
            const IrInst* d = def_of(cur);
            if (!d) return std::nullopt;
            if (d->op == IrOp::Assign && d->src_count == 1) {
                cur = d->srcs[0];
                continue;
            }
            if (d->op == IrOp::Load && d->segment == Reg::None &&
                d->src_count >= 1) {
                if (auto off = stack_offset(d->srcs[0]); off) {
                    if (auto init = init_only_slot_value.find(*off);
                        init != init_only_slot_value.end()) {
                        cur = init->second;
                        continue;
                    }
                }
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

    [[nodiscard]] const Symbol*
    global_object_for_load(const IrValue& v) const {
        if (!binary) return nullptr;
        const IrInst* d = def_stripped(v);
        if (!d || d->op != IrOp::Load || d->src_count < 1) return nullptr;
        auto imm = try_resolve_imm_addr(d->srcs[0]);
        if (!imm) return nullptr;
        const Symbol* s = binary->defined_object_at(static_cast<addr_t>(*imm));
        if (!s || s->kind != SymbolKind::Object || s->name.empty()) return nullptr;
        return s;
    }

    [[nodiscard]] std::optional<addr_t>
    constant_fnptr_slot_for_call_target(const IrValue& v) const {
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

    // Raise self_arity when the body reads a live-in argument register
    // that the inferred arity didn't cover. Without this, raw register
    // names leak into the emitted C as e.g. `fputs(rdx, stdout)`. Call
    // only when the caller hasn't pinned an explicit signature.
    void bump_arity_from_body_reads() {
        u8 need = self_arity;
        auto check = [&](const IrValue& v) {
            if (v.kind != IrValueKind::Reg) return;
            if (v.version != 0) return;
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

    // If an unannotated live-in argument is only ever consumed through the
    // same truncation, surface that in the header. This turns common
    // compiler shapes like `trunc i32 rdi; test eax,eax` into `u32 a1`
    // rather than keeping a `u64 a1` header and sprinkling `(u32)a1`
    // through every condition/return. We deliberately require every visible
    // use to be a Trunc to the same width; a single direct 64-bit use means
    // the wider type is intentional and the cast should stay in the body.
    void infer_narrow_arg_types_from_uses() {
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

    // A live-in used as a load/store base is pointer-shaped even when local
    // type inference cannot propagate the pointee type backwards through a
    // register copy plus offset arithmetic. This is common in PPC prologues:
    // r3 is copied into r31, then every field access is based on r31. Keep the
    // inferred type deliberately opaque because mixed-width field accesses
    // describe a struct, not an array of whichever width happened to appear
    // first.
    void infer_pointer_arg_types_from_memory_uses() {
        if (abi != Abi::Ppc32Sysv && abi != Abi::Ppc64ElfV1Be &&
            abi != Abi::Ppc64ElfV2Le) {
            return;
        }
        const u8 limit = std::min<u8>(self_arity,
            static_cast<u8>(self_arg_layout.size()));
        for (u8 slot = 0; slot < limit; ++slot) {
            const auto& layout = self_arg_layout[slot];
            if (layout.reg == Reg::None || is_ppc_fpr(layout.reg)) continue;

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

    // Metrowerks emits calls to _savegpr_N/_savefpr_N before it copies
    // incoming parameters into callee-saved registers. SSA correctly models
    // an ordinary call as clobbering r3-r10, but these compiler helpers are
    // special: they preserve those registers. Carry any refined type learned
    // on the post-helper SSA value (most importantly pointer evidence from a
    // later load/store) back to the source-level parameter.
    void infer_ppc_helper_preserved_arg_types() {
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

    [[nodiscard]] bool is_void_call_result(const IrValue& v) const {
        if (v.kind != IrValueKind::Reg) return false;
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
            if (prev.op == IrOp::Call || prev.op == IrOp::CallIndirect) {
                return call_inst_returns_void(prev);
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
    [[nodiscard]] bool has_incidental_ppc_return_merge() const {
        if (!fn || (abi != Abi::Ppc32Sysv && abi != Abi::Ppc64ElfV1Be &&
                    abi != Abi::Ppc64ElfV2Le)) {
            return false;
        }
        const Reg ret_reg = int_return_reg(abi);
        for (const auto& bb : fn->blocks) {
            for (const auto& inst : bb.insts) {
                if (inst.op != IrOp::Return || inst.src_count == 0) continue;
                const IrValue& rv = inst.srcs[0];
                if (rv.kind != IrValueKind::Reg ||
                    canonical_reg(rv.reg) != ret_reg) {
                    continue;
                }
                const IrInst* phi = def_of(rv);
                if (!phi || phi->op != IrOp::Phi || phi->phi_operands.size() < 2) continue;
                bool saw_live_in = false;
                std::size_t clobbers = 0;
                bool saw_side_effect_value = false;
                bool small_merge_is_incidental = true;
                for (std::size_t op_index = 0;
                     op_index < phi->phi_operands.size(); ++op_index) {
                    IrValue op = phi->phi_operands[op_index];
                    if (auto key = ssa_key(op); key) {
                        auto uses_it = visible_uses.find(*key);
                        if (uses_it != visible_uses.end() && uses_it->second > 0) {
                            saw_side_effect_value = true;
                        }
                    }
                    bool classified = false;
                    if (op.kind == IrValueKind::Imm &&
                        op_index < phi->phi_preds.size()) {
                        auto pred_it = fn->block_at.find(phi->phi_preds[op_index]);
                        if (pred_it != fn->block_at.end()) {
                            const auto& pred = fn->blocks[pred_it->second];
                            for (const auto& pred_inst : pred.insts) {
                                if (pred_inst.op != IrOp::Store ||
                                    pred_inst.src_count < 2) {
                                    continue;
                                }
                                const IrValue& stored = pred_inst.srcs[1];
                                if (stored.kind == IrValueKind::Imm &&
                                    stored.imm == op.imm && stored.type == op.type) {
                                    saw_side_effect_value = true;
                                    classified = true;
                                    break;
                                }
                            }
                        }
                    }
                    for (int depth = 0; depth < 6; ++depth) {
                        if (classified) break;
                        if (op.kind == IrValueKind::Reg && op.version == 0 &&
                            canonical_reg(op.reg) == ret_reg) {
                            saw_live_in = true;
                            classified = true;
                            break;
                        }
                        const IrInst* d = def_of(op);
                        if (!d) break;
                        if (d->op == IrOp::Clobber) {
                            auto key = ssa_key(op);
                            const auto uses_it = key ? visible_uses.find(*key)
                                                     : visible_uses.end();
                            // bind_call_returns gives every unknown call a
                            // provisional name, even if the trailing dead-
                            // declaration pass later removes it. A real
                            // non-Phi use is the stronger evidence that this
                            // clobber is an intentional return value.
                            if (!key || uses_it == visible_uses.end() ||
                                uses_it->second == 0) {
                                ++clobbers;
                                classified = true;
                            }
                            break;
                        }
                        if (d->op == IrOp::Assign && d->src_count == 1) {
                            // The assigned register can feed a store while its
                            // source is an immediate with no SSA key.
                            if (auto key = ssa_key(op); key) {
                                auto uses_it = visible_uses.find(*key);
                                if (uses_it != visible_uses.end() && uses_it->second > 0) {
                                    classified = true;
                                    break;
                                }
                            }
                            op = d->srcs[0];
                            continue;
                        }
                        break;
                    }
                    if (!classified) small_merge_is_incidental = false;
                }
                if (phi->phi_operands.size() >= 6 && saw_live_in && clobbers >= 2) {
                    return true;
                }
                if (small_merge_is_incidental && clobbers + (saw_live_in ? 1u : 0u) > 0 &&
                    saw_side_effect_value) {
                    return true;
                }
            }
        }
        return false;
    }

    // Find Return regions whose value is the ABI integer return register
    // coming directly from a call's Clobber - record the Call position and
    // the SSA key so emit_block
    // suppresses the statement and the Return handler folds the expression.
    void analyze_return_folds(const Region& r) {
        for (const auto& c : r.children) analyze_return_folds(*c);
        if (r.kind != RegionKind::Return) return;
        const IrValue& cond = r.condition;
        if (cond.kind != IrValueKind::Reg) return;
        auto cond_key = ssa_key(cond);
        if (!cond_key) return;
        const IrInst* def = def_of(cond);
        if (!def || def->op != IrOp::Clobber) return;
        // Folding `return foo(args);` requires that the call's return value
        // has no other readers - otherwise we'd silently re-emit the call
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
                if (canonical_reg(cond.reg) !=
                    canonical_reg(call_result_reg(prev))) {
                    return;
                }
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
        // When a call's return-register clobber flows into a Phi that
        // name_merge_values has labelled (`v0`, `v1`, …) AND the merge
        // name will actually be read by the body, bind the call to that
        // merge name instead of inventing `r_<callee>`. The call statement
        // then becomes `v0 = sub_X(...);`, which:
        //   - actually defines the merge variable declared at the function
        //     head (otherwise `v0` is uninitialized, and every read prints
        //     `v0` with no producer in sight),
        //   - escapes the trailing dead-decl pass, which only strips lines
        //     of the `TYPE NAME = ...;` shape - `v0 = ...` has no type
        //     prefix, so it stays.
        // Without this, calls whose result fans out through a phi got
        // emitted as `u64 r_sub_X = ...;`, the use site rendered the phi
        // as `v0`, `r_sub_X` appeared nowhere else, and the dead-decl pass
        // silently deleted the call statement (side effect and all).
        //
        // The "merge name will be read by body" gate matters: when the
        // phi's only readers are Return regions, the structurer folds each
        // path's return value independently and the merge name is never
        // referenced. In that case the original `r_<callee>` binding
        // reads better - e.g. `char* r_getenv = getenv("HOME"); if
        // (r_getenv) ...; return r_getenv;` instead of an arbitrary `v5`.
        const auto phi_has_non_return_user = [&](SsaKey pk) {
            std::set<SsaKey> seen;
            const auto walk = [&](SsaKey cur, auto& self) -> bool {
                if (!seen.insert(cur).second) return false;
                for (const auto& bb : fn->blocks) {
                    for (const auto& inst : bb.insts) {
                        if (inst.op == IrOp::Return) continue;
                        if (inst.op == IrOp::Phi) {
                            for (const auto& op : inst.phi_operands) {
                                if (auto ok = ssa_key(op); ok && *ok == cur) {
                                    if (auto dpk = ssa_key(inst.dst); dpk) {
                                        if (self(*dpk, self)) return true;
                                    }
                                }
                            }
                            continue;
                        }
                        for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                            if (auto ok = ssa_key(inst.srcs[i]); ok && *ok == cur) {
                                return true;
                            }
                        }
                    }
                }
                return false;
            };
            return walk(pk, walk);
        };

        std::map<SsaKey, std::string> ret_key_to_merge_name;
        std::map<std::pair<std::size_t, std::size_t>, std::string> objc_return_base;
        for (const auto& bb : fn->blocks) {
            for (const auto& inst : bb.insts) {
                if (inst.op != IrOp::Phi) continue;
                auto pk = ssa_key(inst.dst);
                if (!pk) continue;
                auto mit = merge_value_names.find(*pk);
                if (mit == merge_value_names.end()) continue;
                if (!phi_has_non_return_user(*pk)) continue;
                for (const auto& op : inst.phi_operands) {
                    if (auto ok = ssa_key(op); ok) {
                        ret_key_to_merge_name.emplace(*ok, mit->second);
                    }
                }
            }
        }

        for (std::size_t bi = 0; bi < fn->blocks.size(); ++bi) {
            const auto& bb = fn->blocks[bi];
            std::vector<IrValue> args;
            args.reserve(kMaxAbiIntArgs);
            for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
                const auto& inst = bb.insts[ii];
                if (inst.op == IrOp::Intrinsic && inst.name == "call.args.1") {
                    args.clear();
                    for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                        args.push_back(inst.srcs[i]);
                    }
                    continue;
                }
                if (inst.op == IrOp::Intrinsic &&
                    (inst.name == "call.args.2" || inst.name == "call.args.3")) {
                    for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                        args.push_back(inst.srcs[i]);
                    }
                    continue;
                }
                if (inst.op == IrOp::Call || inst.op == IrOp::CallIndirect) {
                    if (auto base = objc_return_base_for_call(inst, args); base) {
                        objc_return_base.emplace(std::pair{bi, ii}, *base);
                    }
                    args.clear();
                }
            }
        }

        std::set<std::string> used;
        for (std::size_t bi = 0; bi < fn->blocks.size(); ++bi) {
            const auto& bb = fn->blocks[bi];
            for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
                const auto& inst = bb.insts[ii];
                if (inst.op != IrOp::Call && inst.op != IrOp::CallIndirect) continue;
                if (hidden.contains({bi, ii})) continue;
                if (fold_call_positions.contains({bi, ii})) continue;
                if (inline_call_positions.contains({bi, ii})) continue;
                if (arc_claim_producer_positions.contains({bi, ii})) continue;
                if (call_inst_returns_void(inst)) continue;
                const Reg ret_reg = call_result_reg(inst);
                if (ret_reg == Reg::None) continue;

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

                std::string name;
                if (auto mit = ret_key_to_merge_name.find(*ret_key);
                    mit != ret_key_to_merge_name.end()) {
                    name = mit->second;
                    merge_bound_calls.insert({bi, ii});
                } else {
                    std::string base = callee_display_short(inst);
                    if (auto oit = objc_return_base.find({bi, ii});
                        oit != objc_return_base.end()) {
                        base = oit->second;
                    }
                    name = "r_" + base;
                    for (int n = 2; used.contains(name); ++n) {
                        name = std::format("r_{}_{}", base, n);
                    }
                    used.insert(name);
                }
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

    void analyze_arc_claim_folds() {
        if (!fn) return;
        for (std::size_t bi = 0; bi < fn->blocks.size(); ++bi) {
            const auto& bb = fn->blocks[bi];
            std::vector<IrValue> args;
            args.reserve(kMaxAbiIntArgs);
            for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
                const auto& inst = bb.insts[ii];
                if (inst.op == IrOp::Intrinsic && inst.name == "call.args.1") {
                    args.clear();
                    for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                        args.push_back(inst.srcs[i]);
                    }
                    continue;
                }
                if (inst.op == IrOp::Intrinsic &&
                    (inst.name == "call.args.2" || inst.name == "call.args.3")) {
                    for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                        args.push_back(inst.srcs[i]);
                    }
                    continue;
                }
                if (inst.op != IrOp::Call && inst.op != IrOp::CallIndirect) continue;
                auto name = call_import_name(inst);
                if (name && *name == "objc_unsafeClaimAutoreleasedReturnValue" &&
                    !args.empty()) {
                    if (auto key = ssa_key(args[0]);
                        key && count_uses_with_call_args(*key) == 1) {
                        if (auto producer = call_position_for_return_key(*key); producer) {
                            arc_claim_producer_positions.insert(*producer);
                            suppressed_call_positions.insert({bi, ii});
                        }
                    }
                }
                args.clear();
            }
        }
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
                call_position_for_return_key(*k)) {
                auto pos = call_position_for_return_key(*k);
                if (pos && pos->first < fn->blocks.size() &&
                    pos->second < fn->blocks[pos->first].insts.size()) {
                    const IrInst& call = fn->blocks[pos->first].insts[pos->second];
                    if (canonical_reg(v.reg) == canonical_reg(call_result_reg(call))) {
                        return *k;
                    }
                }
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
                case IrOp::FpToInt:
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
    // reads as `r_get` instead of `r_stdistreamget` - the qualified prefix
    // is already visible at the call site.
    [[nodiscard]] std::string callee_display_short(const IrInst& call_inst) const {
        std::string raw = call_import_name(call_inst).value_or("");
        if (call_inst.op == IrOp::Call) {
            if (raw.empty()) raw = function_display_name(call_inst.target1);
        } else if (call_inst.op == IrOp::CallIndirect && call_inst.src_count >= 1) {
            if (raw.empty()) raw = "ind";
        } else {
            raw = "call";
        }
        // Keep only the last `::`-separated segment for qualified names.
        // Operators (`operator+`, `operator new`) and destructors (`~T`)
        // are kept whole on the right side - they're already short.
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
        // [entry, prologue_end) from .xdata is authoritative - every inst
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
                if (is_abi_noise(bb.insts[ii]) ||
                    is_ppc_abi_helper_call(bb.insts[ii])) {
                    hidden.insert({bi, ii});
                }
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

    [[nodiscard]] bool is_stack_chk_guard_got_load(const IrInst& inst) const {
        if (!binary) return false;
        if (inst.op != IrOp::Load || inst.segment != Reg::None ||
            inst.src_count < 1 || inst.srcs[0].kind != IrValueKind::Imm) {
            return false;
        }
        const auto slot = static_cast<addr_t>(inst.srcs[0].imm);
        const Symbol* s = binary->import_at_got(slot);
        return s && clean_import_name(s->name) == "__stack_chk_guard";
    }

    [[nodiscard]] bool is_canary_load(const IrInst& inst) const {
        if (is_stack_chk_guard_got_load(inst)) return true;
        return inst.op == IrOp::Load && inst.segment == Reg::Fs &&
               inst.src_count >= 1 &&
               inst.srcs[0].kind == IrValueKind::Imm &&
               inst.srcs[0].imm == 0x28;
    }

    [[nodiscard]] bool is_canary_value_load(const IrInst& inst) const {
        if (is_canary_load(inst)) return true;
        if (inst.op != IrOp::Load || inst.segment != Reg::None ||
            inst.src_count < 1) {
            return false;
        }
        const IrInst* ptr = def_through_assigns(inst.srcs[0]);
        return ptr && is_stack_chk_guard_got_load(*ptr);
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
        if (const IrInst* d = def_through_assigns(v); d) return is_canary_value_load(*d);
        return false;
    }

    [[nodiscard]] bool renders_stack_chk_guard_load(const IrInst& inst) const {
        if (inst.op != IrOp::Load || inst.src_count < 1) return false;
        return format_mem(inst.srcs[0], inst.dst.type, inst.segment)
            .find("__stack_chk_guard") != std::string::npos;
    }

    [[nodiscard]] bool renders_stack_chk_guard_value(const IrValue& v) const {
        if (traces_to_canary_load(v)) return true;
        const IrInst* d = def_through_assigns(v);
        return d && renders_stack_chk_guard_load(*d);
    }

    [[nodiscard]] bool is_abi_noise(const IrInst& inst) const {
        // Stack-base register writes → frame manipulation.
        if (inst.op == IrOp::Assign && inst.dst.kind == IrValueKind::Reg) {
            if (is_stack_base_reg(inst.dst.reg)) return true;
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
        auto is_guard = [&](const IrInst* d) {
            return d && (is_canary_value_load(*d) ||
                         renders_stack_chk_guard_load(*d));
        };
        const bool ag = is_guard(a);
        const bool bg = is_guard(b);
        return (is_stack_load(a) && bg) ||
               (is_stack_load(b) && ag) ||
               (ag && bg);
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
                // to x and try again - the real canary compare is one step up.
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

    [[nodiscard]] bool return_matches(const Region& r,
                                      const IrValue& value) const noexcept {
        return r.kind == RegionKind::Return &&
               r.condition.kind != IrValueKind::None &&
               same_ssa(r.condition, value);
    }

    [[nodiscard]] bool always_returns_value(const Region& r,
                                            const IrValue& value) const noexcept {
        switch (r.kind) {
            case RegionKind::Return:
                return return_matches(r, value);
            case RegionKind::Seq:
                return !r.children.empty() &&
                       r.children.back() &&
                       always_returns_value(*r.children.back(), value);
            case RegionKind::IfElse:
                return r.children.size() >= 2 &&
                       r.children[0] && r.children[1] &&
                       always_returns_value(*r.children[0], value) &&
                       always_returns_value(*r.children[1], value);
            default:
                return false;
        }
    }

    void strip_matching_tail_returns(Region& r, const IrValue& value) const {
        if (return_matches(r, value)) {
            r.kind = RegionKind::Empty;
            r.condition = {};
            r.children.clear();
            return;
        }
        for (auto& c : r.children) {
            if (c) strip_matching_tail_returns(*c, value);
        }
        if (r.kind == RegionKind::Seq) {
            while (!r.children.empty()) {
                auto& last = r.children.back();
                if (!last || last->kind == RegionKind::Empty ||
                    return_matches(*last, value)) {
                    r.children.pop_back();
                    continue;
                }
                break;
            }
            if (r.children.empty()) {
                r.kind = RegionKind::Empty;
            }
        }
    }

    void fold_common_tail_returns(Region& r) const {
        for (auto& c : r.children) {
            if (c) fold_common_tail_returns(*c);
        }
        if (r.kind != RegionKind::Seq || r.children.size() < 3) return;
        Region* tail = r.children.back().get();
        if (!tail || tail->kind != RegionKind::Return ||
            tail->condition.kind == IrValueKind::None) {
            return;
        }
        const IrValue tail_value = tail->condition;
        for (std::size_t i = 0; i + 2 < r.children.size(); ++i) {
            Region* cur = r.children[i].get();
            if (!cur || cur->kind != RegionKind::IfThen ||
                cur->children.empty() || !cur->children[0]) {
                continue;
            }
            if (!always_returns_value(*cur->children[0], tail_value)) continue;

            auto rewritten = std::make_unique<Region>();
            rewritten->kind = RegionKind::IfElse;
            rewritten->condition = cur->condition;
            rewritten->invert = cur->invert;
            rewritten->target = cur->target;
            rewritten->block_start = cur->block_start;
            rewritten->children.push_back(std::move(cur->children[0]));
            strip_matching_tail_returns(*rewritten->children[0], tail_value);

            auto else_seq = std::make_unique<Region>();
            else_seq->kind = RegionKind::Seq;
            for (std::size_t j = i + 1; j + 1 < r.children.size(); ++j) {
                else_seq->children.push_back(std::move(r.children[j]));
            }
            rewritten->children.push_back(std::move(else_seq));

            std::vector<std::unique_ptr<Region>> next;
            next.reserve(i + 2);
            for (std::size_t j = 0; j < i; ++j) {
                next.push_back(std::move(r.children[j]));
            }
            next.push_back(std::move(rewritten));
            next.push_back(std::move(r.children.back()));
            r.children = std::move(next);
            fold_common_tail_returns(r);
            return;
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
            case IrOp::FpToInt:
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
    // multiple uses - one per flag-set computation (zf and sf each take it
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
            // slot's `local_X` name - duplicating that string at each use
            // is no worse than the original `tN = local_X; ... use tN ...`
            // pair, and lets compound flag-set patterns (sub.overflow +
            // sub feeding the same slt rendering) collapse cleanly without
            // leaving a dangling `tN = local_X;` line. Skip if the slot
            // has an unknown segment (fs:[…] etc.) - those carry side
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

    [[nodiscard]] std::optional<std::string>
    merge_assignment_name_for(const IrInst& inst) const {
        if (inst.op == IrOp::Phi || inst.op == IrOp::Clobber ||
            inst.op == IrOp::Call || inst.op == IrOp::CallIndirect ||
            inst.op == IrOp::Store || is_terminator(inst.op)) {
            return std::nullopt;
        }
        auto k = ssa_key(inst.dst);
        if (!k) return std::nullopt;
        auto it = merge_value_names.find(*k);
        if (it == merge_value_names.end()) return std::nullopt;
        auto local_it = merge_locals.find(it->second);
        if (local_it == merge_locals.end()) return std::nullopt;
        bool has_non_return_reader = false;
        for (const auto& local_key : local_it->second.keys) {
            auto pos_it = visible_user_positions.find(local_key);
            if (pos_it == visible_user_positions.end()) continue;
            for (const auto& [bi, ii] : pos_it->second) {
                if (!fn || bi >= fn->blocks.size()) continue;
                const auto& bb = fn->blocks[bi];
                if (ii >= bb.insts.size()) continue;
                if (bb.insts[ii].op != IrOp::Return) {
                    has_non_return_reader = true;
                    break;
                }
            }
            if (has_non_return_reader) break;
        }
        if (!has_non_return_reader) return std::nullopt;
        return it->second;
    }

    [[nodiscard]] std::string
    format_merge_assignment(const IrInst& inst, std::string_view name) const {
        if (inst.src_count >= 2) {
            const bool commutative =
                inst.op == IrOp::Add || inst.op == IrOp::Mul ||
                inst.op == IrOp::And || inst.op == IrOp::Or ||
                inst.op == IrOp::Xor;
            std::string_view op_text;
            switch (inst.op) {
                case IrOp::Add:  op_text = "+"; break;
                case IrOp::Sub:  op_text = "-"; break;
                case IrOp::Mul:  op_text = "*"; break;
                case IrOp::And:  op_text = "&"; break;
                case IrOp::Or:   op_text = "|"; break;
                case IrOp::Xor:  op_text = "^"; break;
                case IrOp::Shl:  op_text = "<<"; break;
                case IrOp::Lshr: op_text = ">>"; break;
                case IrOp::Ashr: op_text = ">>"; break;
                default: break;
            }
            auto is_same_merge_local = [&](const IrValue& v) {
                auto k = ssa_key(v);
                if (!k) return false;
                auto it = merge_value_names.find(*k);
                return it != merge_value_names.end() && it->second == name;
            };
            const IrValue* delta = nullptr;
            if (!op_text.empty() && is_same_merge_local(inst.srcs[0])) {
                delta = &inst.srcs[1];
            } else if (!op_text.empty() && commutative &&
                       is_same_merge_local(inst.srcs[1])) {
                delta = &inst.srcs[0];
            }
            if (delta) {
                if ((inst.op == IrOp::Add || inst.op == IrOp::Sub) &&
                    delta->kind == IrValueKind::Imm && delta->imm == 1 &&
                    !is_float_type(inst.dst.type)) {
                    const char* sym = (inst.op == IrOp::Add) ? "++" : "--";
                    return std::format("{}{};", name, sym);
                }
                return std::format("{} {}= {};", name, op_text, expr(*delta));
            }
        }

        std::string rhs;
        if (inst.op == IrOp::Assign) {
            if (inst.src_count < 1) return "";
            rhs = expr(inst.srcs[0]);
        } else if (inst.op == IrOp::Load) {
            if (inst.src_count < 1) return "";
            rhs = format_load_rhs(inst);
        } else if (inst.op == IrOp::Intrinsic) {
            std::string args;
            for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                if (i > 0) args += ", ";
                args += expr(inst.srcs[i]);
            }
            rhs = std::format("{}({})", inst.name, args);
        } else if (inlinable_op(inst.op)) {
            rhs = expand(inst, 0);
        }
        if (rhs.empty()) return "";
        return std::format("{} = {};", name, rhs);
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
        if (renders_stack_chk_guard_value(v)) {
            emitted_bindings.insert(*k);
            return;
        }

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
            rhs = format_load_rhs(*d);
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

    void emit_raw_temp_binding(u32 temp, std::string& out,
                               std::string_view ind) const {
        const SsaKey key{u8{2}, temp, 0};
        if (emitted_bindings.contains(key)) return;
        auto it = defs.find(key);
        if (it == defs.end()) return;
        const IrInst* d = it->second;
        if (!d || d->dst.kind != IrValueKind::Temp || d->dst.temp != temp) return;
        if (d->op == IrOp::Phi || d->op == IrOp::Clobber) return;
        if (d->op != IrOp::Assign && d->op != IrOp::Load &&
            d->op != IrOp::Intrinsic && !inlinable_op(d->op)) {
            return;
        }

        for (u8 i = 0; i < d->src_count && i < d->srcs.size(); ++i) {
            emit_materializations_for_value(d->srcs[i], 0, out, ind);
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
            rhs = format_load_rhs(*d);
        } else if (d->op == IrOp::Assign) {
            if (d->src_count < 1) return;
            rhs = expr(d->srcs[0]);
        } else {
            rhs = expand(*d, 0);
        }
        if (rhs.empty()) return;
        out += std::format("{}{} t{} = {};\n",
                           ind, c_type_name_for(d->dst), temp, rhs);
        emitted_bindings.insert(key);
    }

    void emit_materializations_for_raw_temps(std::string_view rendered,
                                             std::string& out,
                                             std::string_view ind) const {
        for (std::size_t i = 0; i + 1 < rendered.size(); ++i) {
            if (rendered[i] != 't' ||
                (i > 0 && c_ident_char(rendered[i - 1])) ||
                !std::isdigit(static_cast<unsigned char>(rendered[i + 1]))) {
                continue;
            }
            std::size_t j = i + 1;
            u32 temp = 0;
            while (j < rendered.size() &&
                   std::isdigit(static_cast<unsigned char>(rendered[j]))) {
                temp = temp * 10u + static_cast<u32>(rendered[j] - '0');
                ++j;
            }
            if (j < rendered.size() && c_ident_char(rendered[j])) {
                i = j;
                continue;
            }
            emit_raw_temp_binding(temp, out, ind);
            i = j;
        }
    }

    void emit_materializations_for_rendered_value(const IrValue& v,
                                                  std::string_view rendered,
                                                  std::string& out,
                                                  std::string_view ind) const {
        if (const auto fallback = fallback_ssa_name(v);
            fallback && text_contains_identifier(rendered, *fallback)) {
            emit_materializations_for_value(v, 0, out, ind);
        }
        emit_materializations_for_raw_temps(rendered, out, ind);
    }

    // Trace a PPC stack address back to the entry value of r1. Unlike
    // stack_offset(), this follows versioned r1 assignments through `stwu`
    // so a callee load at current-r1 + frame-size + 0x28 resolves to the
    // ABI's entry-r1 + 0x28 overflow slot.
    [[nodiscard]] std::optional<i64>
    entry_stack_offset(const IrValue& v, int depth = 0) const {
        if (depth > 16 || !is_ppc_abi()) return std::nullopt;
        if (v.kind == IrValueKind::Reg) {
            if (canonical_reg(v.reg) != Reg::PpcR1) return std::nullopt;
            if (v.version == 0) return i64{0};
            const IrInst* d = def_of(v);
            if (!d || d->op != IrOp::Assign || d->src_count < 1) {
                return std::nullopt;
            }
            return entry_stack_offset(d->srcs[0], depth + 1);
        }
        if (v.kind != IrValueKind::Temp) return std::nullopt;
        const IrInst* d = def_of(v);
        if (!d) return std::nullopt;
        if (d->op == IrOp::Assign && d->src_count >= 1) {
            return entry_stack_offset(d->srcs[0], depth + 1);
        }
        if ((d->op == IrOp::Add || d->op == IrOp::Sub) &&
            d->src_count >= 2 && d->srcs[1].kind == IrValueKind::Imm) {
            auto base = entry_stack_offset(d->srcs[0], depth + 1);
            if (!base) return std::nullopt;
            return d->op == IrOp::Add
                ? *base + d->srcs[1].imm
                : *base - d->srcs[1].imm;
        }
        if (d->op == IrOp::Add && d->src_count >= 2 &&
            d->srcs[0].kind == IrValueKind::Imm) {
            auto base = entry_stack_offset(d->srcs[1], depth + 1);
            if (base) return *base + d->srcs[0].imm;
        }
        return std::nullopt;
    }

    // Trace a value back through Add/Sub/Assign chains to see if it's stack-relative.
    [[nodiscard]] std::optional<i64> stack_offset(const IrValue& v, int depth = 0) const {
        if (depth > 16) return std::nullopt;
        if (v.kind == IrValueKind::Reg) {
            if (is_stack_base_reg(v.reg)) return 0;
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
        if (allow_string_literals &&
            binary && v.imm > 0 && static_cast<u64>(v.imm) >= 0x100) {
            const addr_t a = static_cast<addr_t>(v.imm);
            if (auto it = objc_block_by_literal.find(a);
                it != objc_block_by_literal.end()) {
                std::string out = objc_block_literal_name(a);
                out += std::format(" /* invoke: {}", function_display_name(it->second->invoke));
                if (!it->second->signature.empty()) {
                    out += std::format(", sig: {}", it->second->signature);
                }
                out += " */";
                return out;
            }
        }
        if (allow_string_literals &&
            binary && v.imm > 0 && static_cast<u64>(v.imm) >= 0x100) {
            if (auto n = named_address_for_imm(static_cast<addr_t>(v.imm)); n) {
                return std::format("{} /* {:#x} */", *n, static_cast<u64>(v.imm));
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
        // -1; ret`-style returns the lifter widened into rax - the high
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
    // inlines SSA defs during render - a long def-use chain without a
    // cap recurses until the stack (or kernel OOM-killer) stops it.
    // Deeply-nested expressions past ~6 levels are illegible anyway;
    // we stop inlining and render the raw register/temp instead.
    static constexpr int kMaxExprDepth = 6;

    [[nodiscard]] std::string expr(const IrValue& v, int depth = 0,
                                   int min_prec = 0) const;
    [[nodiscard]] std::string expand(const IrInst& d, int depth,
                                     int min_prec = 0) const;
    [[nodiscard]] std::string format_load_rhs(const IrInst& d,
                                              int depth = 0,
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

        if (off == 0 && (s->size == 0 || s->size == t_bytes)) {
            note_global_decl(*s, std::string(c_type_name(t)));
            return s->name;
        }
        if (s->size == 0 && t_bytes != 0 && off > 0 &&
            (off % static_cast<i64>(t_bytes)) == 0) {
            note_global_decl(*s, std::format("{}[]", c_type_name(t)));
            return std::format("{}[{}]", s->name,
                               off / static_cast<i64>(t_bytes));
        }
        if (off == 0) {
            note_global_decl(*s, std::string(c_type_name(t)));
            return std::format("*({}*)&{}", c_type_name(t), s->name);
        }
        note_global_decl(*s, std::format("{}[]", c_type_name(t)));
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
    std::map<SsaKey, std::map<i64, std::set<unsigned>>> struct_access_widths;

    [[nodiscard]] bool is_struct_pointer(const IrValue& base) const {
        auto k = ssa_key(base);
        if (!k) return false;
        auto it = struct_offsets.find(*k);
        return it != struct_offsets.end() && it->second.size() >= 2;
    }

    [[nodiscard]] bool is_strong_struct_pointer(const IrValue& base) const {
        auto k = ssa_key(base);
        if (!k || !is_struct_pointer(base)) return false;
        const auto wit = struct_access_widths.find(*k);
        if (wit == struct_access_widths.end()) return false;

        std::set<unsigned> widths;
        for (const auto& [off, ws] : wit->second) {
            (void)off;
            widths.insert(ws.begin(), ws.end());
        }
        if (widths.size() >= 2) return true;

        const auto oit = struct_offsets.find(*k);
        if (oit == struct_offsets.end() || oit->second.size() < 2) return false;
        if (widths.size() != 1 || *widths.begin() == 0) return false;

        const i64 stride = static_cast<i64>(*widths.begin());
        for (i64 off : oit->second) {
            if (off < 0 || (off % stride) != 0) return true;
        }
        return false;
    }

    [[nodiscard]] const std::string*
    annotated_field_name(const IrValue& base, i64 off) const {
        if (!annotations || !fn) return nullptr;
        auto slot = trace_to_self_arg_slot(base);
        if (!slot) return nullptr;
        return annotations->field_name_for(fn->start, *slot, off);
    }

    [[nodiscard]] static bool objc_ivar_name_is_safe(std::string_view s) noexcept {
        if (s.empty()) return false;
        auto ok_first = [](char c) {
            return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_';
        };
        auto ok_rest = [&](char c) {
            return ok_first(c) || (c >= '0' && c <= '9');
        };
        if (!ok_first(s.front())) return false;
        for (char c : s) if (!ok_rest(c)) return false;
        return true;
    }

    [[nodiscard]] std::optional<addr_t>
    objc_ivar_slot_loaded_by(const IrValue& v) const {
        const IrInst* d = def_stripped(v);
        if (!d || d->op != IrOp::Load || d->src_count < 1) return std::nullopt;
        auto imm = try_resolve_imm_addr(d->srcs[0]);
        if (!imm) return std::nullopt;
        return static_cast<addr_t>(*imm);
    }

    struct ObjcReceiverContext {
        std::string cls;
        std::string display;
    };

    [[nodiscard]] std::optional<u64>
    objc_block_capture_index_loaded_by(const IrValue& v) const {
        const IrInst* d = def_stripped(v);
        if (!d || d->op != IrOp::Load || d->src_count < 1) return std::nullopt;
        auto bo = try_base_plus_offset(d->srcs[0]);
        if (!bo) return std::nullopt;
        const i64 off = bo->second;
        if (off < 0x20 || (off % 8) != 0) return std::nullopt;
        auto slot = trace_to_self_arg_slot(bo->first);
        if (!slot || *slot != 0) return std::nullopt;
        return static_cast<u64>((off - 0x20) / 8);
    }

    [[nodiscard]] std::optional<ObjcReceiverContext>
    objc_receiver_context(const IrValue& receiver, int depth = 0) const {
        if (current_objc_method) {
            auto self_slot = trace_to_self_arg_slot(receiver);
            if (self_slot && *self_slot == 0) {
                return ObjcReceiverContext{current_objc_method->cls, "self"};
            }
        }
        auto cap = objc_block_capture_index_loaded_by(receiver);
        if (cap && !objc_block_self_class.empty()) {
            auto it = objc_block_capture_names.find(*cap);
            if (it != objc_block_capture_names.end() && it->second == "self") {
                return ObjcReceiverContext{
                    objc_block_self_class,
                    expr(receiver, depth + 1, std::to_underlying(Prec::Unary))
                };
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] std::string objc_ivar_display_name(const ObjcIvar& iv) const {
        auto find_prop = [&](std::string_view ivar_name) -> const ObjcProperty* {
            auto it = objc_property_by_ivar.find({iv.cls, std::string(ivar_name)});
            return it == objc_property_by_ivar.end() ? nullptr : it->second;
        };
        if (const ObjcProperty* p = find_prop(iv.name);
            p && objc_ivar_name_is_safe(p->name)) {
            return p->name;
        }
        if (iv.name.starts_with("_")) {
            if (const ObjcProperty* p = find_prop(std::string_view{iv.name}.substr(1));
                p && objc_ivar_name_is_safe(p->name)) {
                return p->name;
            }
        } else {
            const std::string underscored = "_" + iv.name;
            if (const ObjcProperty* p = find_prop(underscored);
                p && objc_ivar_name_is_safe(p->name)) {
                return p->name;
            }
        }
        return iv.name;
    }

    [[nodiscard]] std::optional<std::string>
    try_render_objc_ivar_addr_pair(const IrValue& maybe_self,
                                   const IrValue& maybe_slot) const {
        if (!fn) return std::nullopt;
        auto ctx = objc_receiver_context(maybe_self);
        if (!ctx || ctx->cls.empty() || ctx->display.empty()) return std::nullopt;
        auto slot = objc_ivar_slot_loaded_by(maybe_slot);
        const ObjcIvar* ivar = nullptr;
        if (slot) {
            auto it = objc_ivar_by_slot.find(*slot);
            if (it != objc_ivar_by_slot.end()) ivar = it->second;
        } else if (auto off = resolve_imm(maybe_slot); off && *off >= 0) {
            auto it = objc_ivar_by_class_offset.find(
                {ctx->cls, static_cast<u64>(*off)});
            if (it != objc_ivar_by_class_offset.end()) ivar = it->second;
        }
        if (!ivar) return std::nullopt;
        const ObjcIvar& iv = *ivar;
        if (iv.cls != ctx->cls) return std::nullopt;
        if (!objc_ivar_name_is_safe(iv.name)) return std::nullopt;
        return std::format("{}->{}", ctx->display, objc_ivar_display_name(iv));
    }

    [[nodiscard]] std::optional<std::string>
    try_render_objc_ivar_access(const IrValue& addr, int depth = 0) const {
        (void)depth;
        const IrInst* d = def_stripped(addr);
        if (!d || d->op != IrOp::Add || d->src_count < 2) return std::nullopt;

        if (auto r = try_render_objc_ivar_addr_pair(d->srcs[0], d->srcs[1])) return r;
        if (auto r = try_render_objc_ivar_addr_pair(d->srcs[1], d->srcs[0])) return r;
        return std::nullopt;
    }

    // Three-pointer-at-{0,8,16} pattern matches every flavour of
    // std::vector<T> on x86_64 - libstdc++ (`_M_start / _M_finish /
    // _M_end_of_storage`), libc++ (`__begin_ / __end_ / __end_cap_`),
    // and MSVC STL (`_Myfirst / _Mylast / _Myend`) all lay them out
    // at the same offsets. Any other 24-byte three-pointer struct
    // renders the same way, which is fine - these names read better
    // than `field_0 / field_8 / field_10` for *any* struct shaped
    // like a contiguous container.
    [[nodiscard]] bool looks_like_vector(const IrValue& base) const {
        auto k = ssa_key(base);
        if (!k) return false;
        auto it = struct_offsets.find(*k);
        if (it == struct_offsets.end()) return false;
        const auto& offs = it->second;
        // The full vector shape is exactly the three {ptr, end, capacity}
        // 8-byte slots - nothing else. The previous "contains" check fired
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

    [[nodiscard]] bool looks_like_objc_block_capture_base(const IrValue& base) const {
        auto slot = trace_to_self_arg_slot(base);
        if (!slot || *slot != 0) return false;

        if (self_arg_names[0] == "block") return true;
        if (fn && objc_block_by_invoke.contains(fn->start)) return true;
        if (current_objc_method || objc_block_by_invoke.empty()) return false;

        auto k = ssa_key(base);
        if (!k) return false;
        auto it = struct_offsets.find(*k);
        if (it == struct_offsets.end()) return false;

        bool has_capture_offset = false;
        for (i64 off : it->second) {
            if (off > 0 && off < 0x20) return false;
            if (off >= 0x20 && (off % 8) == 0) has_capture_offset = true;
        }
        return has_capture_offset;
    }

    [[nodiscard]] std::optional<std::string>
    try_render_objc_block_capture_access(const IrValue& addr, IrType t,
                                         int depth = 0) const {
        auto bo = try_base_plus_offset(addr);
        if (!bo) return std::nullopt;
        const IrValue& base = bo->first;
        const i64 off = bo->second;
        if (off < 0x20 || (off % 8) != 0) return std::nullopt;
        if (!looks_like_objc_block_capture_base(base)) return std::nullopt;

        const std::string base_expr =
            expr(base, depth + 1, std::to_underlying(Prec::Unary));
        const u64 capture_idx = static_cast<u64>((off - 0x20) / 8);
        const std::string capture_name = [&] {
            auto it = objc_block_capture_names.find(capture_idx);
            if (it != objc_block_capture_names.end() && objc_ivar_name_is_safe(it->second)) {
                return it->second;
            }
            return std::format("capture_{}", capture_idx);
        }();
        if (t == IrType::I64) {
            return std::format("{}->{}", base_expr, capture_name);
        }
        return std::format("*({}*)&{}->{}",
                           c_type_name(t), base_expr, capture_name);
    }

    [[nodiscard]] bool first_arg_has_block_capture_accesses() const {
        if (!fn) return false;
        bool has_capture_offset = false;
        bool has_small_positive_offset = false;
        auto check_addr = [&](const IrValue& addr) {
            auto bo = try_base_plus_offset(addr);
            if (!bo) return;
            auto slot = trace_to_self_arg_slot(bo->first);
            if (!slot || *slot != 0) return;
            const i64 off = bo->second;
            if (off > 0 && off < 0x20) has_small_positive_offset = true;
            if (off >= 0x20 && (off % 8) == 0) has_capture_offset = true;
        };
        for (const auto& bb : fn->blocks) {
            for (const auto& inst : bb.insts) {
                if (inst.segment != Reg::None) continue;
                if ((inst.op == IrOp::Load || inst.op == IrOp::Store) &&
                    inst.src_count >= 1) {
                    check_addr(inst.srcs[0]);
                }
            }
        }
        return has_capture_offset && !has_small_positive_offset;
    }

    void promote_block_like_first_arg() {
        if (!binary || binary->format() != Format::MachO) return;
        if (current_objc_method) return;
        if (self_arg_names[0] == "block") {
            self_arg_type_names[0] = "void*";
            return;
        }
        if (!self_arg_names[0].empty()) return;

        const auto int_args = int_arg_regs(abi);
        if (int_args.empty()) return;
        IrValue first = IrValue::make_reg(int_args[0], abi_word_type());
        first.version = 0;
        if (!looks_like_objc_block_capture_base(first) &&
            !first_arg_has_block_capture_accesses()) return;

        self_arg_names[0] = "block";
        self_arg_type_names[0] = "void*";
        if (self_arity == 0) self_arity = 1;
    }

    [[nodiscard]] static std::optional<std::string>
    objc_class_from_bracket_name(std::string_view s) {
        const std::size_t open = s.find('[');
        if (open == std::string_view::npos || open == 0) return std::nullopt;
        if (s[open - 1] != '-' && s[open - 1] != '+') return std::nullopt;
        const std::size_t space = s.find(' ', open + 1);
        if (space == std::string_view::npos || space <= open + 1) return std::nullopt;
        std::string cls(s.substr(open + 1, space - open - 1));
        return objc_ivar_name_is_safe(cls) ? std::optional<std::string>{std::move(cls)}
                                          : std::nullopt;
    }

    [[nodiscard]] std::optional<std::string>
    objc_class_from_block_literal_captures(addr_t literal, u64 size) const {
        if (!binary || literal == 0 || size < 0x28 || size > 0x4000) {
            return std::nullopt;
        }
        for (u64 off = 0x20; off + 8 <= size; off += 8) {
            auto bytes = binary->bytes_at(static_cast<addr_t>(literal + off));
            if (bytes.size() < 8) break;
            u64 ptr = 0;
            std::memcpy(&ptr, bytes.data(), 8);
            if (ptr < 0x100) continue;
            auto s = try_string_at(ptr);
            if (!s) continue;
            if (auto cls = objc_class_from_bracket_name(*s); cls) return cls;
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<std::string>
    objc_class_from_block_function_name() const {
        if (!fn) return std::nullopt;
        if (auto cls = objc_class_from_bracket_name(fn->name); cls) return cls;
        for (const auto& [key, iv] : objc_ivar_by_class_offset) {
            (void)iv;
            const std::string& cls = key.first;
            if (cls.empty()) continue;
            if (fn->name == cls || fn->name.starts_with(cls + "_")) {
                return cls;
            }
        }
        auto next = objc_by_imp.upper_bound(fn->start);
        if (next != objc_by_imp.begin()) {
            auto prev = std::prev(next);
            if (prev->second && fn->start > prev->first &&
                fn->start - prev->first <= 0x8000 &&
                !prev->second->cls.empty()) {
                return prev->second->cls;
            }
        }
        return std::nullopt;
    }

    void infer_objc_block_capture_names() {
        if (!fn || current_objc_method) return;
        const bool is_known_block = objc_block_by_invoke.contains(fn->start) ||
                                    objc_stack_block_by_invoke.contains(fn->start) ||
                                    first_arg_has_block_capture_accesses();
        if (!is_known_block) return;

        if (auto it = objc_stack_block_by_invoke.find(fn->start);
            it != objc_stack_block_by_invoke.end()) {
            for (const auto& [idx, name] : it->second->captures) {
                if (objc_ivar_name_is_safe(name)) {
                    objc_block_capture_names.emplace(idx, name);
                }
            }
            if (!it->second->captured_self_class.empty()) {
                objc_block_self_class = it->second->captured_self_class;
            }
        }

        if (auto it = objc_block_by_invoke.find(fn->start);
            it != objc_block_by_invoke.end()) {
            if (auto cls = objc_class_from_block_literal_captures(
                    it->second->literal, it->second->size); cls) {
                objc_block_self_class = *cls;
            }
        }
        if (objc_block_self_class.empty()) {
            if (auto cls = objc_class_from_block_function_name(); cls) {
                objc_block_self_class = *cls;
            }
        }
        if (objc_block_self_class.empty()) return;

        bool capture0_is_referenced = false;
        bool capture0_is_objc_receiver = false;
        for (const auto& bb : fn->blocks) {
            for (const auto& inst : bb.insts) {
                if ((inst.op != IrOp::Load && inst.op != IrOp::Store) ||
                    inst.src_count < 1 || inst.segment != Reg::None) {
                    continue;
                }
                if (inst.op == IrOp::Load) {
                    auto load_addr = try_base_plus_offset(inst.srcs[0]);
                    if (load_addr && load_addr->second == 0x20) {
                        auto slot = trace_to_self_arg_slot(load_addr->first);
                        if (slot && *slot == 0) capture0_is_referenced = true;
                    }
                }
                const IrInst* d = def_stripped(inst.srcs[0]);
                if (!d || d->op != IrOp::Add || d->src_count < 2) continue;
                auto cap = objc_block_capture_index_loaded_by(d->srcs[0]);
                if (!cap || *cap != 0) continue;
                capture0_is_referenced = true;
                if (objc_ivar_slot_loaded_by(d->srcs[1]) ||
                    (resolve_imm(d->srcs[1]) && *resolve_imm(d->srcs[1]) >= 0)) {
                    capture0_is_objc_receiver = true;
                    break;
                }
            }
            if (capture0_is_objc_receiver) break;
        }
        if (capture0_is_referenced || capture0_is_objc_receiver) {
            objc_block_capture_names.emplace(0, "self");
        }
    }

    void record_struct_access(const IrValue& addr, IrType t) {
        auto bo = try_base_plus_offset(addr);
        if (!bo) return;
        // Skip stack-relative and global bases - those have richer rendering
        // paths already.
        if (stack_offset(bo->first).has_value()) return;
        if (auto k = ssa_key(bo->first); k) {
            struct_offsets[*k].insert(bo->second);
            const unsigned bytes = type_bits(t) / 8;
            if (bytes != 0) {
                struct_access_widths[*k][bo->second].insert(bytes);
            }
        }
    }

    // Pointer-indexing fold: `*(T*)(base + stride*N)` renders as `base[N]`
    // when base isn't stack- or global-relative. The stride must equal the
    // load width (so `*(u32*)(p + 4*N)` → `p[N]`); other strides keep their
    // explicit `*(T*)(addr)` form so the reader sees the actual byte arithmetic.
    // Negative offsets are accepted - backward array walks are common in
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
        // Reject when the base is itself an arithmetic combination - that's
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
        std::string rendered_base = expr(base, depth + 1);
        // A pointer loaded from memory still has an integer-width Load in
        // IR, even when local type inference has proved that the assigned
        // value is a pointer. Indexing the raw rendered load would produce
        // invalid C (`*(uint64_t*)slot[0]`) and lose the pointee width.
        // Reapply the refined pointer type at this expression boundary.
        if (const IrInst* bd = def_stripped(base);
            bd && bd->op == IrOp::Load && fn &&
            fn->types.kind(fn->type_of(base)) == TypeKind::Ptr &&
            rendered_base.starts_with("*(")) {
            rendered_base = std::format("(({}){})",
                                        c_type_name_for(base), rendered_base);
        }
        return std::format("{}[{}]", rendered_base, off / stride);
    }

    // Runtime-indexed array form: `*(T*)(base + idx * stride)` and the
    // shift-encoded `*(T*)(base + (idx << k))` (compilers emit
    // `idx << 3` for stride-8 access). Renders as `base[idx]` when
    // the scale factor matches the access width - the same property
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
                    note_global_decl(*s, std::format("{}[]", c_type_name(t)));
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
                // A real (PDB / user-supplied) frame-layout name wins over
                // everything. A recovered incoming stack-argument name beats
                // the synthetic `arg_<hex>` slot name. Otherwise fall back to
                // the synthetic `local_<hex>` / `arg_<hex>` form.
                auto it = frame_layout.slots.find(*off);
                const bool has_name =
                    it != frame_layout.slots.end() && !it->second.name.empty();
                const bool synthetic = has_name && it->second.name == stack_name(*off);
                if (has_name && !synthetic) return it->second.name;
                if (auto arg = incoming_stack_arg_name(addr, *off)) return *arg;
                if (has_name) return it->second.name;
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
            if (auto ivar = try_render_objc_ivar_access(addr, depth)) {
                return *ivar;
            }
            if (auto capture = try_render_objc_block_capture_access(addr, t, depth)) {
                return *capture;
            }
            // User-supplied struct field names beat array heuristics. This
            // lets annotations turn ambiguous fixed-stride accesses like
            // `a1[1]` back into source-level members such as `hdr->flags`.
            if (auto bo = try_base_plus_offset(addr)) {
                const IrValue& base = bo->first;
                const i64 off = bo->second;
                if (off >= 0) {
                    if (const std::string* field = annotated_field_name(base, off); field) {
                        const std::string base_expr =
                            expr(base, depth + 1, std::to_underlying(Prec::Unary));
                        return std::format("{}->{}", base_expr, *field);
                    }
                }
            }
            // Strong struct evidence beats array syntax. Mixed-width or
            // non-stride offset sets usually mean a record layout, not
            // argv-style indexing.
            if (auto bo = try_base_plus_offset(addr);
                bo && is_strong_struct_pointer(bo->first)) {
                const IrValue& base = bo->first;
                const i64 off = bo->second;
                const std::string base_expr =
                    expr(base, depth + 1, std::to_underlying(Prec::Unary));
                if (off < 0) {
                    return std::format("*({}*)({} - {:#x})",
                                       c_type_name(t), base_expr,
                                       static_cast<u64>(-off));
                }
                if (const std::string* field = annotated_field_name(base, off); field) {
                    return std::format("{}->{}", base_expr, *field);
                }
                return std::format("{}->field_{:x}", base_expr,
                                   static_cast<u64>(off));
            }
            // Array-indexing form takes priority over the struct-field
            // rendering when both apply - u64 stride-8 accesses usually mean
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
                if (const std::string* field = annotated_field_name(base, off); field) {
                    return std::format("{}->{}", base_expr, *field);
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
        const bool pointer_arith =
            (d.op == IrOp::Add || d.op == IrOp::Sub) &&
            (d.srcs[0].type == IrType::I64 || d.srcs[1].type == IrType::I64 ||
             d.dst.type == IrType::I64);
        auto render = [&](const IrValue& v, int operand_prec) {
            return pointer_arith && v.kind == IrValueKind::Imm
                ? format_numeric_imm(v)
                : expr(v, depth, operand_prec);
        };
        std::string L = render(d.srcs[0], p);
        std::string R = render(d.srcs[1], commutative ? p : p + 1);
        std::string result = std::format("{} {} {}", L, op, R);
        return wrap_if_lt(std::move(result), self_prec, min_prec);
    }

    // Bitwise &/|/^ rendering with mask-friendly imm handling:
    // negative power-of-2 boundary values render as `~0xN` (the
    // C-natural mask form) instead of `-0x{N+1}`, which is opaque
    // in a bitwise context. Always commutative - both operands
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

    [[nodiscard]] static bool rendered_region_empty(std::string_view s) noexcept {
        std::size_t line_start = 0;
        while (line_start <= s.size()) {
            std::size_t line_end = s.find('\n', line_start);
            if (line_end == std::string_view::npos) line_end = s.size();
            std::string_view line = trim_line_view(s.substr(line_start, line_end - line_start));
            if (!line.empty()) {
                if (!line_semantically_empty(line)) return false;
            }
            if (line_end == s.size()) break;
            line_start = line_end + 1;
        }
        return true;
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

    [[nodiscard]] std::optional<IrValue> match_eq_zero_value(const IrValue& v) const {
        const IrInst* d = def_stripped(v);
        if (!d || d->op != IrOp::CmpEq || d->src_count < 2) return std::nullopt;
        if (d->srcs[1].kind == IrValueKind::Imm && d->srcs[1].imm == 0) return d->srcs[0];
        if (d->srcs[0].kind == IrValueKind::Imm && d->srcs[0].imm == 0) return d->srcs[1];
        return std::nullopt;
    }

    [[nodiscard]] std::optional<IrValue> match_slt_zero_value(const IrValue& v) const {
        const IrInst* d = def_stripped(v);
        if (!d || d->op != IrOp::CmpSlt || d->src_count < 2) return std::nullopt;
        if (d->srcs[1].kind != IrValueKind::Imm || d->srcs[1].imm != 0) return std::nullopt;
        return d->srcs[0];
    }

    [[nodiscard]] std::optional<IrValue> match_or_eq_zero_slt_zero(const IrValue& v) const {
        const IrInst* d = def_stripped(v);
        if (!d || d->op != IrOp::Or || d->dst.type != IrType::I1 || d->src_count < 2) {
            return std::nullopt;
        }
        auto try_match = [&](const IrValue& eq_side,
                             const IrValue& lt_side) -> std::optional<IrValue> {
            auto eq = match_eq_zero_value(eq_side);
            auto lt = match_slt_zero_value(lt_side);
            if (eq && lt && same_ssa(*eq, *lt)) return *eq;
            return std::nullopt;
        };
        if (auto r = try_match(d->srcs[0], d->srcs[1]); r) return r;
        if (auto r = try_match(d->srcs[1], d->srcs[0]); r) return r;
        return std::nullopt;
    }

    [[nodiscard]] std::optional<IrValue>
    match_low_byte_setcc_merge(const IrValue& v, int depth = 0) const {
        if (depth > 8) return std::nullopt;
        const IrInst* d = def_stripped(v);
        if (!d) return std::nullopt;
        if ((d->op == IrOp::Trunc || d->op == IrOp::ZExt ||
             d->op == IrOp::SExt) && d->src_count >= 1) {
            if (d->srcs[0].type == IrType::I1) return d->srcs[0];
            return match_low_byte_setcc_merge(d->srcs[0], depth + 1);
        }
        if (d->op != IrOp::Or || d->src_count < 2) return std::nullopt;
        auto is_low_byte_clear = [&](const IrValue& x) {
            const IrInst* xd = def_stripped(x);
            if (!xd || xd->op != IrOp::And || xd->src_count < 2) return false;
            auto is_mask = [](const IrValue& m) {
                return m.kind == IrValueKind::Imm &&
                       static_cast<u64>(m.imm) == 0xffffffffffffff00ull;
            };
            return is_mask(xd->srcs[0]) || is_mask(xd->srcs[1]);
        };
        auto bool_cast_src = [&](const IrValue& x) -> std::optional<IrValue> {
            const IrInst* xd = def_stripped(x);
            if (!xd) return std::nullopt;
            if ((xd->op == IrOp::ZExt || xd->op == IrOp::SExt ||
                 xd->op == IrOp::Trunc || xd->op == IrOp::Assign) &&
                xd->src_count >= 1) {
                if (xd->srcs[0].type == IrType::I1 ||
                    xd->srcs[0].type == IrType::I8) {
                    return xd->srcs[0];
                }
            }
            if (x.type == IrType::I1 || x.type == IrType::I8) return x;
            return std::nullopt;
        };
        if (is_low_byte_clear(d->srcs[0])) return bool_cast_src(d->srcs[1]);
        if (is_low_byte_clear(d->srcs[1])) return bool_cast_src(d->srcs[0]);
        return std::nullopt;
    }

    [[nodiscard]] std::optional<std::string>
    render_bool_byte_value(const IrValue& v, int depth, bool negate,
                           int min_prec) const {
        if (depth > 8) return std::nullopt;
        if (auto b = match_low_byte_setcc_merge(v); b) {
            return render_bool_operand(*b, depth + 1, negate, min_prec);
        }
        const IrInst* d = def_stripped(v);
        if (!d) return std::nullopt;
        if ((d->op == IrOp::Trunc || d->op == IrOp::ZExt ||
             d->op == IrOp::SExt || d->op == IrOp::Assign) &&
            d->src_count >= 1) {
            return render_bool_byte_value(d->srcs[0], depth + 1, negate, min_prec);
        }
        if (d->op == IrOp::And && d->src_count >= 2) {
            const IrValue* masked = nullptr;
            if (d->srcs[0].kind == IrValueKind::Imm && d->srcs[0].imm == 1) {
                masked = &d->srcs[1];
            } else if (d->srcs[1].kind == IrValueKind::Imm && d->srcs[1].imm == 1) {
                masked = &d->srcs[0];
            }
            if (masked) {
                IrValue core = *masked;
                if (auto merged = match_low_byte_setcc_merge(core); merged) {
                    core = *merged;
                }
                if (core.type == IrType::I1) {
                    return render_bool_operand(core, depth + 1, negate, min_prec);
                }
                std::string inner = expr(core, depth + 1,
                                         std::to_underlying(Prec::BitAnd) + 1);
                std::string bit = inner + " & 1";
                if (negate) {
                    return wrap_if_lt("!(" + bit + ")", Prec::Unary, min_prec);
                }
                return wrap_if_lt(std::move(bit), Prec::BitAnd, min_prec);
            }
        }
        if ((d->op == IrOp::Or || d->op == IrOp::And) && d->src_count >= 2) {
            auto left = render_bool_byte_value(d->srcs[0], depth + 1, negate,
                                               std::to_underlying(negate
                                                   ? (d->op == IrOp::Or ? Prec::LogAnd : Prec::LogOr)
                                                   : (d->op == IrOp::Or ? Prec::LogOr : Prec::LogAnd)) + 1);
            auto right = render_bool_byte_value(d->srcs[1], depth + 1, negate,
                                                std::to_underlying(negate
                                                    ? (d->op == IrOp::Or ? Prec::LogAnd : Prec::LogOr)
                                                    : (d->op == IrOp::Or ? Prec::LogOr : Prec::LogAnd)) + 1);
            if (!left || !right) return std::nullopt;
            const bool or_op = d->op == IrOp::Or;
            const Prec own = negate
                ? (or_op ? Prec::LogAnd : Prec::LogOr)
                : (or_op ? Prec::LogOr : Prec::LogAnd);
            const std::string op = negate
                ? (or_op ? " && " : " || ")
                : (or_op ? " || " : " && ");
            return wrap_if_lt(*left + op + *right, own, min_prec);
        }
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
                if (auto byte_bool = render_bool_byte_value(
                        *nonzero, depth + 1, op == "==", min_prec);
                    byte_bool) {
                    return *byte_bool;
                }
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
        if (a.kind == IrValueKind::Imm && b.kind != IrValueKind::Imm) {
            if (op == "<")  return render_cmp(">",  b, a, depth, signed_cmp, in_bool_ctx, min_prec);
            if (op == "<=") return render_cmp(">=", b, a, depth, signed_cmp, in_bool_ctx, min_prec);
            if (op == ">")  return render_cmp("<",  b, a, depth, signed_cmp, in_bool_ctx, min_prec);
            if (op == ">=") return render_cmp("<=", b, a, depth, signed_cmp, in_bool_ctx, min_prec);
        }
        const Prec own = (op == "==" || op == "!=") ? Prec::Eq : Prec::Rel;
        const int p = std::to_underlying(own);
        const std::string_view c = "int64_t";
        const bool cast_l = signed_cmp && a.kind != IrValueKind::Imm;
        const bool cast_r = signed_cmp && b.kind != IrValueKind::Imm;
        // If we're going to wrap in `(int64_t)`, the inner must bind at Unary;
        // otherwise the compare's own precedence is enough.
        const int lp = cast_l ? std::to_underlying(Prec::Unary) : p;
        const int rp = cast_r ? std::to_underlying(Prec::Unary) : p + 1;
        auto cmp_expr = [&](const IrValue& v, int prec) {
            if (v.kind == IrValueKind::Imm) return format_numeric_imm(v);
            if (const IrInst* d = def_stripped(v);
                d && (d->op == IrOp::ZExt || d->op == IrOp::SExt ||
                      d->op == IrOp::Trunc)) {
                return expand(*d, depth + 1, prec);
            }
            return expr(v, depth + 1, prec);
        };
        std::string left  = cmp_expr(a, lp);
        std::string right = cmp_expr(b, rp);
        if (cast_l) left  = std::format("({}){}", c, left);
        if (cast_r) right = std::format("({}){}", c, right);
        return wrap_if_lt(std::format("{} {} {}", left, op, right), own, min_prec);
    }

    [[nodiscard]] std::string render_bool_operand(const IrValue& v, int depth,
                                                  bool negate, int min_prec) const {
        if (auto s = try_simplify_flag(v, depth + 1, negate,
                                       /*in_bool_ctx=*/true, min_prec);
            s) return *s;
        if (negate) {
            std::string inner = expr(v, depth + 1, std::to_underlying(Prec::Unary));
            return wrap_if_lt("!" + inner, Prec::Unary, min_prec);
        }
        return expr(v, depth + 1, min_prec);
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
        if (auto x = match_or_eq_zero_slt_zero(v); x) {
            IrValue zero = IrValue::make_imm(0, x->type);
            return render_cmp(negate ? ">" : "<=", *x, zero, depth, true,
                              in_bool_ctx, min_prec);
        }

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
        if (d && d->dst.type == IrType::I1 && d->src_count >= 2) {
            if (d->op == IrOp::Or) {
                const Prec own = negate ? Prec::LogAnd : Prec::LogOr;
                const std::string op = negate ? " && " : " || ";
                const int child_prec = std::to_underlying(own) + 1;
                return wrap_if_lt(
                    render_bool_operand(d->srcs[0], depth, negate, child_prec) + op +
                    render_bool_operand(d->srcs[1], depth, negate, child_prec),
                    own, min_prec);
            }
            if (d->op == IrOp::And) {
                const Prec own = negate ? Prec::LogOr : Prec::LogAnd;
                const std::string op = negate ? " || " : " && ";
                const int child_prec = std::to_underlying(own) + 1;
                return wrap_if_lt(
                    render_bool_operand(d->srcs[0], depth, negate, child_prec) + op +
                    render_bool_operand(d->srcs[1], depth, negate, child_prec),
                    own, min_prec);
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
        if (const FunctionSig* sig = annotations->signature_for(sf.ir->start); sig) {
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
            // For versioned regs, inline a trivial Imm assignment - lets the
            // absorbed call() show the actual constant instead of an orphan reg name.
            if (v.version > 0 && depth < kMaxExprDepth) {
                const IrInst* d = def_of(v);
                while (d && d->op == IrOp::Assign && d->src_count == 1) {
                    const auto& src = d->srcs[0];
                    if (src.kind == IrValueKind::Imm) return expr(src, depth + 1, min_prec);
                    if (src.kind == IrValueKind::Reg && src.version == 0) {
                        return render_reg_leaf(src.reg, src.version, depth + 1,
                                               min_prec);
                    }
                    break;
                }
            }
            return render_reg_leaf(v.reg, v.version, depth, min_prec);
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

std::string Emitter::format_load_rhs(const IrInst& d,
                                     int depth,
                                     int min_prec) const {
    if (d.op != IrOp::Load || d.src_count < 1) return "";
    // Init-only stack slot: forward to the live-in value the entry prologue
    // stored. Keeping this in one helper prevents merge-local materializers
    // from rendering the same load as a raw `local_X` while normal expr()
    // rendering correctly says `a2`.
    if (d.segment == Reg::None) {
        if (auto off = stack_offset(d.srcs[0]); off) {
            if (auto it = init_only_slot_value.find(*off);
                it != init_only_slot_value.end()) {
                return expr(it->second, depth, min_prec);
            }
        }
    }
    return format_mem(d.srcs[0], d.dst.type, d.segment, depth);
}

std::string Emitter::expand(const IrInst& d, int depth, int min_prec) const {
    switch (d.op) {
        case IrOp::Assign:
            return d.src_count >= 1 ? expr(d.srcs[0], depth, min_prec) : "";

        case IrOp::Add: {
            if (auto off = stack_offset(IrValue::make_temp(d.dst.temp, d.dst.type)); off) {
                return std::format("&{}", stack_name(*off));
            }
            if (d.src_count >= 2) {
                if (auto ivar = try_render_objc_ivar_addr_pair(d.srcs[0], d.srcs[1])) {
                    return wrap_if_lt(*ivar, Prec::Postfix, min_prec);
                }
                if (auto ivar = try_render_objc_ivar_addr_pair(d.srcs[1], d.srcs[0])) {
                    return wrap_if_lt(*ivar, Prec::Postfix, min_prec);
                }
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
            // If the header already narrowed this live-in arg to the cast's
            // destination type, repeating `(u32)a1` at every use just leaks
            // ABI width back into otherwise source-like output.
            if (auto slot = trace_to_self_arg_slot(src);
                slot && *slot < self_arg_type_overrides.size() &&
                self_arg_type_overrides[*slot] &&
                *self_arg_type_overrides[*slot] == d.dst.type) {
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
                if (d.dst.type == IrType::I8) {
                    if (auto b = match_low_byte_setcc_merge(src); b) {
                        std::string pred;
                        if (auto s = try_simplify_flag(*b, depth + 1,
                                                       /*negate=*/false,
                                                       /*in_bool_ctx=*/false,
                                                       std::to_underlying(Prec::Unary));
                            s) {
                            pred = *s;
                        } else {
                            pred = expr(*b, depth + 1, std::to_underlying(Prec::Unary));
                        }
                        return wrap_if_lt(std::format("({})({})",
                                                      c_type_name(IrType::I8),
                                                      pred),
                                          Prec::Unary, min_prec);
                    }
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

        case IrOp::FpToInt: {
            std::string casted = std::format(
                "(int32_t){}",
                expr(d.srcs[0], depth, std::to_underlying(Prec::Unary)));
            return wrap_if_lt(std::move(casted), Prec::Unary, min_prec);
        }

        case IrOp::Load: {
            return format_load_rhs(d, depth, min_prec);
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
            // carry source-level intent - keep their stores so the user's
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
    if (auto name = merge_assignment_name_for(inst)) {
        return format_merge_assignment(inst, *name);
    }
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
                // variable - visible_use_count excludes phi reads, so the
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
            if (is_canary_value_load(inst) || renders_stack_chk_guard_load(inst)) return "";
            if (use_count(inst.dst) == 0) return "";
            if (use_count(inst.dst) == 1) return "";  // will be inlined
            // A multi-use load that should_inline accepts (stack-slot
            // reads, init-only forwards) renders inline at every use site
            // - no need to bind a name for it here.
            if (should_inline(inst.dst)) return "";
            return std::format("{} t{} = {};",
                               c_type_name_for(inst.dst),
                               inst.dst.temp,
                               format_load_rhs(inst));
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
            // imaginary C call. The rest - explicit intrinsics like
            // `sqrtss(x)` that the lifter emits deliberately - stay as
            // calls because they carry real dataflow.
            if (inst.name.starts_with("x64.")) {
                return std::format("/* {}({}) */", inst.name, args);
            }
            if (inst.name.starts_with("ppc.ps_cmp") &&
                inst.dst.kind == IrValueKind::Flag && use_count(inst.dst) == 0) {
                // Paired-single compare helpers are pure value producers for
                // the four CR bits. Do not print unused LT/GT/EQ lanes as
                // misleading standalone calls when only one condition flows
                // into the structured branch.
                return "";
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
            if (inst.dst.kind == IrValueKind::Reg &&
                visible_use_count(inst.dst) > 0) {
                return std::format("{} = {}({});",
                                   reg_name(inst.dst.reg), inst.name, args);
            }
            if (inst.dst.kind == IrValueKind::Flag && use_count(inst.dst) > 0) {
                return std::format("{} = {}({});",
                                   flag_name(inst.dst.flag), inst.name, args);
            }
            return std::format("{}({});", inst.name, args);
        }

        default:
            if (inlinable_op(inst.op) && inst.dst.kind == IrValueKind::Temp) {
                if (visible_use_count(inst.dst) <= 1) return "";
                if (stack_offset(inst.dst).has_value()) return "";
                // Suppress the declaration when this temp's only consumers
                // are flag-set instructions - those will inline the
                // expression when they themselves render.
                if (is_flag_feeder_temp(inst.dst)) return "";
                // Low-byte boolean merges (`x & ~0xff | bool`) are usually
                // compiler plumbing before a byte test. Rendering the carrier
                // temp as `tN = ...` leaves dead-looking noise after the
                // condition itself has simplified.
                if (match_low_byte_setcc_merge(inst.dst)) return "";
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
                    type_name = *known;
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

    std::vector<IrValue> pending_args;
    std::vector<IrValue> pending_fp_args;
    bool                 have_pending = false;

    auto clear_pending_args = [&]() {
        pending_args.clear();
        pending_fp_args.clear();
        have_pending = false;
    };

    // Metrowerks writes overflow parameters into the outgoing parameter area
    // immediately before `bl`. Pair those stores with the following call so
    // the call can render the source argument and the raw stack assignment can
    // disappear. The scan is deliberately block-local and signature/layout-
    // gated; an arbitrary positive stack store is never hidden on its own.
    std::map<std::size_t, std::map<i64, IrValue>> ppc_outgoing_stack_args;
    std::set<std::size_t> ppc_outgoing_stack_stores;
    if (is_ppc_abi()) {
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

            std::vector<InferredArgument> layout;
            if (candidate.op == IrOp::Call) {
                if (auto import_name = import_name_for_direct_call(candidate.target1)) {
                    layout = abi_layout_for_import(*import_name);
                } else {
                    layout = cached_argument_layout(candidate.target1);
                }
            } else if (const FunctionSig* sig = call_annotation_signature(candidate); sig) {
                layout = abi_layout_for(*sig);
            }
            auto& values = ppc_outgoing_stack_args[scan];
            for (const auto& arg : layout) {
                if (!arg.stack_offset) continue;
                const i64 words = std::max<i64>(1, arg.register_count);
                for (i64 word_index = 0; word_index < words; ++word_index) {
                    const i64 off = *arg.stack_offset +
                        word_index * ppc_parameter_word_size();
                    auto store = recent_stores.find(off);
                    if (store == recent_stores.end()) continue;
                    values.emplace(off, store->second.second);
                    ppc_outgoing_stack_stores.insert(store->second.first);
                }
            }
            if (values.empty()) ppc_outgoing_stack_args.erase(scan);
            recent_stores.clear();
        }
    }

    auto args_for_layout = [&](const std::vector<InferredArgument>& layout,
                               std::size_t call_index,
                               std::vector<std::string>* rendered = nullptr) {
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
                auto call = ppc_outgoing_stack_args.find(call_index);
                if (call != ppc_outgoing_stack_args.end()) {
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
            if (append_from(int_regs, pending_args)) continue;
            (void)append_from(fp_regs, pending_fp_args);
        }
        return result;
    };

    auto flush_args_as_intrinsics = [&]() {
        if (have_pending) {
            out += std::format("{}// stray call.args: {} values\n",
                               ind, pending_args.size() + pending_fp_args.size());
            clear_pending_args();
        }
    };

    // Fallback for callees with no known arity: drop args that look stale
    // (live-in regs the caller never set, or regs whose most recent def is
    // a Clobber from an earlier call).
    auto format_call_args_fallback = [&](const std::vector<IrValue>& args,
                                         std::vector<IrValue>* used = nullptr) {
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
    };

    auto fallback_call_arg_types = [&](const std::vector<IrValue>& args) {
        std::string s;
        bool first = true;
        for (const auto& a : args) {
            if (is_stale_arg_reg(a)) continue;
            if (!first) s += ", ";
            s += c_type_name(call_arg_display_type(a));
            first = false;
        }
        return first ? std::string{"void"} : s;
    };

    // When we know the callee's arity, show up to that many args. Trim
    // trailing args that are provably stale ABI register pass-throughs:
    // live-ins the caller never set, or values whose only local def is a
    // call-clobber marker. This used to happen only for max-arity guesses,
    // but stripped callees can infer a smaller concrete arity from noisy
    // register reads; printing `foo(a1, rdx_4, rcx_3)` is worse than
    // admitting the trailing values were not real caller-provided args.
    auto format_call_args_with_arity = [&](const std::vector<IrValue>& args,
                                           u8 arity,
                                           bool trim_raw_arch_regs = true,
                                           std::vector<IrValue>* used = nullptr,
                                           const std::vector<std::string>* rendered = nullptr) {
        std::size_t limit = std::min<std::size_t>(arity, args.size());
        while (limit > 0 &&
               (is_stale_arg_reg(args[limit - 1]) ||
                (trim_raw_arch_regs &&
                 renders_raw_arch_reg_name(args[limit - 1])))) {
            --limit;
        }
        std::string s;
        for (std::size_t i = 0; i < limit; ++i) {
            if (used) used->push_back(args[i]);
            if (i > 0) s += ", ";
            if (rendered && i < rendered->size() && !(*rendered)[i].empty()) {
                s += (*rendered)[i];
            } else {
                s += expr(args[i]);
            }
        }
        return s;
    };

    for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
        const auto& inst = bb.insts[ii];
        if (ppc_outgoing_stack_stores.contains(ii)) continue;
        // Skip ABI-noise prologue/epilogue insts detected during analysis.
        // A hidden PPC save/restore helper still terminates the preceding
        // call.args pack; clear it so it cannot leak out as a stray marker or
        // become the arguments of the next source-level call.
        if (hidden.contains({it->second, ii})) {
            if (inst.op == IrOp::Call || inst.op == IrOp::CallIndirect) {
                clear_pending_args();
            }
            continue;
        }
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

        if (inst.op == IrOp::Intrinsic && inst.name.starts_with("call.args.")) {
            if (inst.name == "call.args.1") pending_args.clear();
            for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                pending_args.push_back(inst.srcs[i]);
            }
            have_pending = true;
            continue;
        }
        if (inst.op == IrOp::Intrinsic && inst.name.starts_with("call.fp_args.")) {
            if (inst.name == "call.fp_args.1") pending_fp_args.clear();
            for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                pending_fp_args.push_back(inst.srcs[i]);
            }
            have_pending = true;
            continue;
        }

        if (inst.op == IrOp::Call) {
            auto import_name = import_name_for_direct_call(inst.target1);
            std::vector<IrValue> call_args = pending_args;
            std::vector<std::string> rendered_call_args;
            const bool ppc_abi =
                abi == Abi::Ppc32Sysv || abi == Abi::Ppc64ElfV1Be ||
                abi == Abi::Ppc64ElfV2Le;
            if (ppc_abi) {
                const auto layout = import_name
                    ? abi_layout_for_import(*import_name)
                    : cached_argument_layout(inst.target1);
                if (!layout.empty() || !import_name) {
                    call_args = args_for_layout(layout, ii, &rendered_call_args);
                }
            }
            // Arity sources: imports → user sig at PLT / baked-in libc table;
            // printf/scanf family → parse format string to count args;
            // defined functions → infer_sysv_arity. No arity known → fallback
            // drops stale-looking args.
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
                const std::string direct_name = function_display_name(inst.target1);
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
            std::vector<IrValue> used_args;
            const std::string args = arity
                ? format_call_args_with_arity(call_args, *arity, !objc_sized,
                                              &used_args, &rendered_call_args)
                : format_call_args_fallback(call_args, &used_args);
            const std::string callee = import_name
                ? *import_name
                : function_display_name(inst.target1);
            const std::string call_expr =
                render_objc_runtime_call(callee, call_args)
                    .value_or(std::format("{}({})", callee, args));
            for (const auto& a : used_args) {
                emit_materializations_for_value(a, 0, out, ind);
            }
            clear_pending_args();
            emit_call_binding(out, ind, std::pair{it->second, ii}, call_expr,
                              call_inst_returns_void(inst));
            continue;
        }
        if (inst.op == IrOp::CallIndirect) {
            if (inst.src_count < 1) {
                clear_pending_args();
                out += std::format("{}(*?)();\n", ind);
                continue;
            }
            emit_materializations_for_value(inst.srcs[0], 0, out, ind);
            std::string call_expr;
            std::vector<IrValue> used_args;
            if (auto name = import_name_for_indirect_call(inst.srcs[0]); name) {
                std::vector<IrValue> indirect_args = pending_args;
                std::vector<std::string> rendered_indirect_args;
                if (abi == Abi::Ppc32Sysv || abi == Abi::Ppc64ElfV1Be ||
                    abi == Abi::Ppc64ElfV2Le) {
                    const auto layout = abi_layout_for_import(*name);
                    if (!layout.empty()) {
                        indirect_args = args_for_layout(layout, ii,
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
                    std::vector<IrValue> resolved_args = pending_args;
                    std::vector<std::string> rendered_resolved_args;
                    if (abi == Abi::Ppc32Sysv || abi == Abi::Ppc64ElfV1Be ||
                        abi == Abi::Ppc64ElfV2Le) {
                        const auto layout = direct_import
                            ? abi_layout_for_import(*direct_import)
                            : cached_argument_layout(target);
                        if (!layout.empty() || !direct_import) {
                            resolved_args = args_for_layout(layout, ii,
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
                            const bool ppc = abi == Abi::Ppc32Sysv ||
                                abi == Abi::Ppc64ElfV1Be ||
                                abi == Abi::Ppc64ElfV2Le;
                            arity = ppc
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
                const std::string args = format_call_args_fallback(pending_args,
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
                        fallback_call_arg_types(pending_args),
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
                        call_expr = std::format("{}({})", tgt, args);
                    }
                }
            }
            for (const auto& a : used_args) {
                emit_materializations_for_value(a, 0, out, ind);
            }
            clear_pending_args();
            emit_call_binding(out, ind, std::pair{it->second, ii}, call_expr,
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
                const IrValue& rv = term->srcs[pick];

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

#include "emitter_regions.inc"

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

    EmitterMetadataStorage metadata;
    setup_emitter_metadata(e, sf, binary, metadata);
    const SignatureContext sig_ctx =
        setup_signature_context(e, sf, binary, annotations);
    e.analyze(*sf.ir);
    e.name_merge_values();
    e.infer_objc_block_capture_names();
    e.frame_layout = compute_frame_layout(*sf.ir, binary);
    if (sf.body) {
        e.suppress_canary_regions(*sf.body);
        e.fold_common_tail_returns(*sf.body);
        e.analyze_return_folds(*sf.body);
        e.analyze_return_expr_call_folds(*sf.body);
        e.collect_for_updates(*sf.body);
        e.collect_goto_targets(*sf.body);
    }
    e.analyze_arc_claim_folds();
    if (!sig_ctx.has_user_sig && !sig_ctx.has_metadata_sig) e.bump_arity_from_call_sites();
    if (!sig_ctx.has_user_sig && !sig_ctx.has_metadata_sig) e.bump_arity_from_body_reads();
    if (!sig_ctx.has_user_sig && !sig_ctx.has_metadata_sig) e.bump_arity_from_merge_initializers();
    if (!sig_ctx.has_user_sig && !sig_ctx.has_metadata_sig) {
        e.infer_narrow_arg_types_from_uses();
    }
    if (!sig_ctx.has_user_sig && !sig_ctx.has_metadata_sig) {
        e.infer_pointer_arg_types_from_memory_uses();
    }
    if (!sig_ctx.has_user_sig && !sig_ctx.has_metadata_sig) {
        e.infer_ppc_helper_preserved_arg_types();
    }
    e.infer_function_pointer_args();
    e.infer_call_value_arg_names();
    if (!sig_ctx.has_user_sig && !sig_ctx.has_metadata_sig) e.infer_charp_args();
    if (!sig_ctx.has_user_sig) e.promote_block_like_first_arg();
    e.bind_call_returns();

    std::string out;
    out += std::format("// {}\n", sf.ir->name.empty()
                                    ? std::string("<unknown>") : sf.ir->name);

    // Optional provenance preamble: when --show-provenance is set and
    // the resolved annotations carry metadata for this function, surface
    // confidence + source + evidence as a comment block right under the
    // function name. Lets downstream consumers decide whether to trust
    // the rename without re-deriving it. Off by default - these lines
    // double the visible header for human readers.
    if (annotations && options.show_provenance) {
        if (const AnnotationMeta* m = annotations->meta_for_rename(sf.ir->start);
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
    }

    // Infer return type from body: any Return region carrying a non-None
    // condition means the function yields a value. We use the condition's
    // IrType to pick an appropriate C type rather than always saying `u64`.
    auto inferred_return_type = [&](const Emitter&, const StructuredFunction& s) -> std::string {
        if (e.has_incidental_ppc_return_merge()) return "void";
        // IPA wins outright when it has concrete evidence - the typed
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
                break;
            }
            return candidate;
        };

        std::vector<ReturnTypeCandidate> candidates;
        std::function<void(const Region&)> walk = [&](const Region& r) {
            if (r.kind == RegionKind::Return &&
                r.condition.kind != IrValueKind::None) {
                if (e.is_void_call_result(r.condition)) return;
                if (e.is_unbound_clobber_result(r.condition)) return;
                if (e.renders_stack_chk_guard_value(r.condition)) return;
                // ABI return registers are often wider than the source-level
                // value and usually appear behind an `Assign` to RAX. Prefer
                // the narrowed producer for return-type inference so
                // `return zext(i32)` becomes a `u32` function instead of a
                // `u64` function with casts.
                candidates.push_back(return_type_value(r.condition));
            }
            for (const auto& c : r.children) if (c) walk(*c);
        };
        walk(*s.body);
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
    };

    // Pick a display name: user rename beats binary symbol beats the
    // sub_<hex> fallback. Used below for the header so named functions
    // (e.g. `main` from LC_MAIN) don't render as `sub_<entry>`.
    auto display_name = [&]() -> std::string {
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
                                          Emitter::normalize_c_type_alias(sig->params[i].type),
                                          sig->params[i].name);
                }
            }
            const std::string ret = sig->return_type.empty()
                ? inferred_return_type(e, sf)
                : Emitter::normalize_c_type_alias(sig->return_type);
            e.current_return_is_void = ret == "void";
            header = std::format("{} {}({}) {{\n", ret, display_name(), params);
        }
    }
    if (header.empty()) {
        // Obj-C IMP: derive the header from the method's ObjC type
        // encoding. Gives us proper self / _cmd / typed args instead of
        // u64 placeholders - for a method with encoding "v40@0:8@16i32"
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
                    const auto arg_names = objc_selector_arg_names(meth.selector);
                    for (std::size_t i = 3; i < parts.size(); ++i) {
                        const std::size_t arg_idx = i - 3;
                        const std::string name = arg_idx < arg_names.size()
                            ? arg_names[arg_idx]
                            : std::format("arg{}", arg_idx);
                        params += std::format(", {} {}", parts[i], name);
                    }
                }
                e.current_return_is_void = ret_ty == "void";
                header = std::format("{} {}({}) {{\n",
                                     ret_ty, display_name(), params);
            }
        }
    }
    if (header.empty()) {
        auto blk_it = e.objc_block_by_invoke.find(sf.ir->start);
        if (blk_it != e.objc_block_by_invoke.end() &&
            !blk_it->second->signature.empty()) {
            const auto parts = decode_objc_type_parts(blk_it->second->signature);
            if (!parts.empty()) {
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
                const std::string ret = block_param_type(parts[0]);
                e.current_return_is_void = ret == "void";
                header = std::format("{} {}({}) {{\n",
                                     ret,
                                     display_name(),
                                     params);
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
        const std::string ret = inferred_return_type(e, sf);
        e.current_return_is_void = ret == "void";
        header = std::format("{} {}({}) {{\n",
                             ret, display_name(), params);
    }
    // When the header name is a long RTTI `Class::vfn_N` - especially for
    // templates - advertise a shorter alias the user can type with `-s`.
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
    if (sf.body && !sf.ir->blocks.empty()) {
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
            body_buf += std::format(
                "  // STRUCTURER_FAIL: {:#x}..{:#x} (see --disasm-at)\n",
                bb.start, bb.end);
        }
    }
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
    out += header;
    for (const auto& [name, local] : e.merge_locals) {
        if (!text_contains_identifier_in_code(body_buf, name)) continue;
        if (local.initializer) {
            out += std::format("  {} {} = {};\n",
                               e.c_type_name_for(local.type_value),
                               name,
                               e.expr(*local.initializer));
        } else {
            out += std::format("  {} {};\n",
                               e.c_type_name_for(local.type_value),
                               name);
        }
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
        if (!text_contains_identifier_in_code(body_buf, slot.name)) continue;
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
        out = strip_label_only_if_blocks(out);

        std::vector<std::string> lines;
        {
            std::string buf;
            for (char c : out) {
                if (c == '\n') { lines.push_back(std::move(buf)); buf.clear(); }
                else { buf.push_back(c); }
            }
            if (!buf.empty()) lines.push_back(std::move(buf));
        }
        auto is_decl = [&](const std::string& line, std::string& name) {
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
            for (std::size_t li = 0; li < lines.size(); ++li) {
                if (li == skip_idx) continue;
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
                if (is_decl(lines[li], name) &&
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
        out = std::move(cleaned);
        out = collapse_empty_then_else_blocks(out);
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
    if (!sig_ctx.has_user_sig && !sig_ctx.has_metadata_sig) e.infer_charp_args();
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
            out += std::format("//   {} {};\n",
                               e.c_type_name_for(local.type_value),
                               name);
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
