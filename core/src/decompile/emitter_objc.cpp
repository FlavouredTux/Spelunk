// Objective-C message sends, runtime helpers, ivars and block captures.
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <format>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <spelunk/analysis/objc.hpp>
#include <spelunk/binary/format.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/ir/abi.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/ir/ssa.hpp>

#include "emitter_internal.hpp"
#include "emitter_text.hpp"
#include "emitter_tables.hpp"

namespace spelunk::emit {

bool Emitter::is_objc_msgsend_name(std::string_view name) noexcept {
    return name == "objc_msgSend" ||
           name == "objc_msgSend_fpret" ||
           name == "objc_msgSend_fp2ret" ||
           name == "objc_msgSendSuper" ||
           name == "objc_msgSendSuper2" ||
           name == "objc_msgSendSuper2_stret" ||
           name == "objc_msgSend_stret";
}

bool Emitter::is_objc_super_msgsend_name(std::string_view name) noexcept {
    return name == "objc_msgSendSuper" ||
           name == "objc_msgSendSuper2" ||
           name == "objc_msgSendSuper2_stret";
}

bool Emitter::is_objc_stret_msgsend_name(std::string_view name) noexcept {
    return name == "objc_msgSend_stret" ||
           name == "objc_msgSendSuper2_stret";
}

std::optional<u8>
Emitter::objc_runtime_fixed_arity(std::string_view name) noexcept {
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

u8 Emitter::selector_argument_count(std::string_view selector) noexcept {
    u8 n = 0;
    for (char c : selector) {
        if (c == ':' && n < kMaxAbiIntArgs) ++n;
    }
    return n;
}

bool Emitter::objc_selector_takes_format_varargs(
    std::string_view selector) noexcept {
    return selector == "stringWithFormat:" ||
           selector == "localizedStringWithFormat:" ||
           selector == "initWithFormat:" ||
           selector == "appendFormat:";
}

bool Emitter::objc_selector_takes_nil_varargs(std::string_view selector) noexcept {
    return selector == "initWithObjectsAndKeys:" ||
           selector == "dictionaryWithObjectsAndKeys:" ||
           selector == "initWithObjects:" ||
           selector == "arrayWithObjects:" ||
           selector == "setWithObjects:" ||
           selector == "orderedSetWithObjects:";
}

u8 Emitter::count_objc_format_specifiers(std::string_view fmt) noexcept {
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

std::optional<std::string>
Emitter::objc_selector_for_value(const IrValue& v) const {
    if (!options.objc_selrefs) return std::nullopt;
    const IrInst* d = def_stripped(v);
    if (!d || d->op != IrOp::Load || d->src_count < 1) return std::nullopt;
    auto imm = try_resolve_imm_addr(d->srcs[0]);
    if (!imm) return std::nullopt;
    auto it = options.objc_selrefs->find(static_cast<addr_t>(*imm));
    if (it == options.objc_selrefs->end()) return std::nullopt;
    return it->second;
}

std::optional<std::string>
Emitter::objc_selector_for_rendered_value(const IrValue& v) const {
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

std::optional<u8>
Emitter::objc_call_arity(std::string_view name,
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
    if (objc_selector_takes_nil_varargs(*sel)) {
        for (std::size_t i = base; i < args.size() && i < kMaxAbiArgs; ++i) {
            if (!objc_selector_arg_is_usable(args[i])) break;
            arity = static_cast<unsigned>(i + 1);
            if (auto value = resolve_imm(args[i]); value && *value == 0) break;
        }
    }
    if (objc_selector_takes_format_varargs(*sel)) {
        const std::size_t fmt_index = static_cast<std::size_t>(base);
        if (fmt_index < args.size()) {
            if (auto fmt = resolve_string_value(args[fmt_index]); fmt) {
                arity += count_objc_format_specifiers(*fmt);
            }
        }
    }
    return static_cast<u8>(std::min<unsigned>(kMaxAbiArgs, arity));
}

std::string Emitter::simplify_objc_class_receiver(std::string s) {
    static constexpr std::string_view kSuffix = " class]";
    if (s.starts_with("[") && s.ends_with(kSuffix)) {
        return s.substr(1, s.size() - kSuffix.size() - 1);
    }
    return s;
}

std::vector<std::string_view>
Emitter::objc_selector_pieces(std::string_view selector) {
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

std::string Emitter::objc_stret_assignment_target(std::string s) {
    s = strip_outer_parens(s);
    s = std::string(trim_line_view(s));
    if (s.starts_with("&")) {
        return std::string(trim_line_view(s.substr(1)));
    }
    return std::format("*({})", s);
}

std::string Emitter::objc_address_arg_text(std::string s) {
    s = strip_outer_parens(s);
    s = std::string(trim_line_view(s));
    if (s.empty() || s.starts_with("&")) return s;
    return std::format("&{}", s);
}

std::string Emitter::objc_address_arg(const IrValue& v) const {
    if (auto off = stack_offset(v); off) {
        return std::format("&{}", stack_name(*off));
    }
    if (auto ivar = try_render_objc_ivar_access(v); ivar) {
        return std::format("&{}", *ivar);
    }
    return objc_address_arg_text(
        expr(v, 0, std::to_underlying(Prec::Unary)));
}

std::optional<std::string>
Emitter::try_render_objc_self_ivar_at_offset(const IrValue& receiver,
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

bool Emitter::is_objc_property_setter_runtime(
    std::string_view name) noexcept {
    return name == "objc_setProperty_atomic" ||
           name == "objc_setProperty_atomic_copy" ||
           name == "objc_setProperty_nonatomic" ||
           name == "objc_setProperty_nonatomic_copy";
}

std::optional<std::string>
Emitter::render_objc_property_runtime_call(std::string_view name,
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

std::optional<std::string>
Emitter::render_objc_address_runtime_call(std::string_view name,
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

bool Emitter::objc_selector_arg_is_usable(const IrValue& v) const {
    return !is_stale_arg_reg(v);
}

bool Emitter::objc_selector_arg_looks_like_stack_gap(
    const IrValue& v) const {
    return is_stale_arg_reg(v) || renders_raw_arch_reg_name(v);
}

bool Emitter::objc_selector_piece_likely_stack_aggregate(
    std::string_view piece) noexcept {
    return piece.ends_with("Frame") || piece.ends_with("Rect") ||
           piece.ends_with("Range") || piece.ends_with("Size") ||
           piece.ends_with("Point");
}

std::optional<std::string>
Emitter::render_objc_message_call(std::string_view name,
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
    if (objc_selector_takes_nil_varargs(*selector)) {
        const auto arity = objc_call_arity(name, args);
        if (!arity) return std::nullopt;
        for (std::size_t i = arg_base + selector_args; i < *arity; ++i) {
            if (!objc_selector_arg_is_usable(args[i])) return std::nullopt;
            out += ", " + expr(args[i]);
        }
    } else if (objc_selector_takes_format_varargs(*selector)) {
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

std::optional<std::string>
Emitter::render_objc_runtime_call(std::string_view name,
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

std::optional<std::string>
Emitter::objc_return_base_for_call(const IrInst& call_inst,
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

std::optional<std::string>
Emitter::call_import_name(const IrInst& inst) const {
    if (inst.op == IrOp::Call) {
        return import_name_for_direct_call(inst.target1);
    }
    if (inst.op == IrOp::CallIndirect && inst.src_count >= 1) {
        return import_name_for_indirect_call(inst.srcs[0]);
    }
    return std::nullopt;
}

bool Emitter::objc_ivar_name_is_safe(std::string_view s) noexcept {
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

std::optional<addr_t>
Emitter::objc_ivar_slot_loaded_by(const IrValue& v) const {
    const IrInst* d = def_stripped(v);
    if (!d || d->op != IrOp::Load || d->src_count < 1) return std::nullopt;
    auto imm = try_resolve_imm_addr(d->srcs[0]);
    if (!imm) return std::nullopt;
    return static_cast<addr_t>(*imm);
}

std::optional<u64>
Emitter::objc_block_capture_index_loaded_by(const IrValue& v) const {
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

std::optional<Emitter::ObjcReceiverContext>
Emitter::objc_receiver_context(const IrValue& receiver, int depth) const {
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

std::string Emitter::objc_ivar_display_name(const ObjcIvar& iv) const {
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

std::optional<std::string>
Emitter::try_render_objc_ivar_addr_pair(const IrValue& maybe_self,
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

std::optional<std::string>
Emitter::try_render_objc_ivar_access(const IrValue& addr, int depth) const {
    (void)depth;
    const IrInst* d = def_stripped(addr);
    if (!d || d->op != IrOp::Add || d->src_count < 2) return std::nullopt;

    if (auto r = try_render_objc_ivar_addr_pair(d->srcs[0], d->srcs[1])) return r;
    if (auto r = try_render_objc_ivar_addr_pair(d->srcs[1], d->srcs[0])) return r;
    return std::nullopt;
}

bool Emitter::looks_like_vector(const IrValue& base) const {
    auto access = canonical_struct_access(base);
    if (!access) return false;
    auto k = ssa_key(access->first);
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

bool Emitter::looks_like_objc_block_capture_base(const IrValue& base) const {
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

std::optional<std::string>
Emitter::try_render_objc_block_capture_access(const IrValue& addr, IrType t,
                                              int depth) const {
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

bool Emitter::first_arg_has_block_capture_accesses() const {
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

void Emitter::promote_block_like_first_arg() {
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

std::optional<std::string>
Emitter::objc_class_from_bracket_name(std::string_view s) {
    const std::size_t open = s.find('[');
    if (open == std::string_view::npos || open == 0) return std::nullopt;
    if (s[open - 1] != '-' && s[open - 1] != '+') return std::nullopt;
    const std::size_t space = s.find(' ', open + 1);
    if (space == std::string_view::npos || space <= open + 1) return std::nullopt;
    std::string cls(s.substr(open + 1, space - open - 1));
    return objc_ivar_name_is_safe(cls) ? std::optional<std::string>{std::move(cls)}
                                      : std::nullopt;
}

std::optional<std::string>
Emitter::objc_class_from_block_literal_captures(addr_t literal, u64 size) const {
    if (!binary || literal == 0 || size < 0x28 || size > 0x4000) {
        return std::nullopt;
    }
    for (u64 off = 0x20; off + 8 <= size; off += 8) {
        auto bytes = binary->bytes_at(static_cast<addr_t>(literal + off));
        if (bytes.size() < 8) break;
        u64 ptr = 0;
        std::memcpy(&ptr, bytes.data(), 8);
        if (ptr < 0x100) continue;
        auto s = string_literals.try_c_string_at(ptr);
        if (!s) continue;
        if (auto cls = objc_class_from_bracket_name(*s); cls) return cls;
    }
    return std::nullopt;
}

std::optional<std::string>
Emitter::objc_class_from_block_function_name() const {
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

void Emitter::infer_objc_block_capture_names() {
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

}  // namespace spelunk::emit
