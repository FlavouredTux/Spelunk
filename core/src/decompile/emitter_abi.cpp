// Calling-convention plumbing: arity lookups, import names, ABI parameter slots.

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <spelunk/analysis/arity.hpp>
#include <spelunk/analysis/demangle.hpp>
#include <spelunk/analysis/import_sigs.hpp>
#include <spelunk/analysis/name_resolver.hpp>
#include <spelunk/binary/symbol.hpp>
#include <spelunk/common/annotations.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/ir/abi.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/ir/ssa.hpp>
#include <spelunk/ir/types.hpp>

#include "emitter_internal.hpp"
#include "emitter_setup.hpp"
#include "emitter_text.hpp"
#include "emitter_tables.hpp"

namespace spelunk::emit {

namespace {

bool is_c_type_qualifier(std::string_view word) noexcept {
    return word == "const" || word == "volatile" || word == "restrict" ||
           word == "__restrict" || word == "__restrict__" ||
           word == "_Atomic";
}

std::optional<IrType>
declared_fp_ir_type(std::string_view type) noexcept {
    if (type.find('*') != std::string_view::npos ||
        type.find('&') != std::string_view::npos ||
        type.find('[') != std::string_view::npos) {
        return std::nullopt;
    }

    std::array<std::string_view, 2> base_words{};
    std::size_t base_count = 0;
    type = trim_line_view(type);
    for (std::size_t begin = 0; begin < type.size();) {
        while (begin < type.size() &&
               std::isspace(static_cast<unsigned char>(type[begin])) != 0) {
            ++begin;
        }
        if (begin == type.size()) break;
        std::size_t end = begin;
        while (end < type.size() &&
               std::isspace(static_cast<unsigned char>(type[end])) == 0) {
            ++end;
        }
        const std::string_view word = type.substr(begin, end - begin);
        if (!is_c_type_qualifier(word)) {
            if (base_count == base_words.size()) return std::nullopt;
            base_words[base_count++] = word;
        }
        begin = end;
    }

    if (base_count != 1) return std::nullopt;

    constexpr std::array f32_names{
        std::string_view{"f32"}, std::string_view{"float"},
        std::string_view{"float32_t"}, std::string_view{"std::float32_t"},
        std::string_view{"_Float32"},
    };
    constexpr std::array f64_names{
        std::string_view{"f64"}, std::string_view{"double"},
        std::string_view{"float64_t"}, std::string_view{"std::float64_t"},
        std::string_view{"_Float64"},
    };
    if (std::ranges::find(f32_names, base_words[0]) != f32_names.end()) {
        return IrType::F32;
    }
    if (std::ranges::find(f64_names, base_words[0]) != f64_names.end()) {
        return IrType::F64;
    }
    return std::nullopt;
}

struct DeclaredInteger {
    unsigned bits = 0;
    bool is_signed = false;
};

std::optional<DeclaredInteger>
declared_integer_type(std::string_view type, Abi abi) noexcept {
    if (type.find('*') != std::string_view::npos ||
        type.find('&') != std::string_view::npos ||
        type.find('[') != std::string_view::npos) {
        return std::nullopt;
    }

    type = trim_line_view(type);
    std::vector<std::string_view> words;
    for (std::size_t begin = 0; begin < type.size();) {
        while (begin < type.size() &&
               std::isspace(static_cast<unsigned char>(type[begin])) != 0) {
            ++begin;
        }
        if (begin == type.size()) break;
        std::size_t end = begin;
        while (end < type.size() &&
               std::isspace(static_cast<unsigned char>(type[end])) == 0) {
            ++end;
        }
        const std::string_view word = type.substr(begin, end - begin);
        if (!is_c_type_qualifier(word)) words.push_back(word);
        begin = end;
    }
    if (words.empty()) return std::nullopt;

    if (words.size() == 1) {
        constexpr std::array fixed_types{
            std::pair{std::string_view{"uint8_t"}, DeclaredInteger{8, false}},
            std::pair{std::string_view{"int8_t"}, DeclaredInteger{8, true}},
            std::pair{std::string_view{"uint16_t"}, DeclaredInteger{16, false}},
            std::pair{std::string_view{"int16_t"}, DeclaredInteger{16, true}},
            std::pair{std::string_view{"uint32_t"}, DeclaredInteger{32, false}},
            std::pair{std::string_view{"int32_t"}, DeclaredInteger{32, true}},
            std::pair{std::string_view{"uint64_t"}, DeclaredInteger{64, false}},
            std::pair{std::string_view{"int64_t"}, DeclaredInteger{64, true}},
            std::pair{std::string_view{"std::uint8_t"}, DeclaredInteger{8, false}},
            std::pair{std::string_view{"std::int8_t"}, DeclaredInteger{8, true}},
            std::pair{std::string_view{"std::uint16_t"}, DeclaredInteger{16, false}},
            std::pair{std::string_view{"std::int16_t"}, DeclaredInteger{16, true}},
            std::pair{std::string_view{"std::uint32_t"}, DeclaredInteger{32, false}},
            std::pair{std::string_view{"std::int32_t"}, DeclaredInteger{32, true}},
            std::pair{std::string_view{"std::uint64_t"}, DeclaredInteger{64, false}},
            std::pair{std::string_view{"std::int64_t"}, DeclaredInteger{64, true}},
        };
        for (const auto& [name, integer] : fixed_types) {
            if (words.front() == name) return integer;
        }

        const unsigned pointer_bits =
            abi == Abi::Ppc32Sysv || abi == Abi::AapcsArm32 ? 32u : 64u;
        if (words.front() == "size_t" || words.front() == "uintptr_t" ||
            words.front() == "std::size_t" ||
            words.front() == "std::uintptr_t") {
            return DeclaredInteger{pointer_bits, false};
        }
        if (words.front() == "ssize_t" || words.front() == "intptr_t" ||
            words.front() == "ptrdiff_t" ||
            words.front() == "std::intptr_t" ||
            words.front() == "std::ptrdiff_t") {
            return DeclaredInteger{pointer_bits, true};
        }
    }

    const auto has = [&](std::string_view word) {
        return std::ranges::find(words, word) != words.end();
    };
    const bool is_unsigned = has("unsigned");
    const bool explicitly_signed = has("signed");
    if (is_unsigned && explicitly_signed) return std::nullopt;

    const std::size_t long_count = static_cast<std::size_t>(
        std::ranges::count(words, std::string_view{"long"}));
    unsigned bits = 32;
    if (has("char")) {
        if (has("short") || has("int") || long_count != 0 ||
            (!is_unsigned && !explicitly_signed)) {
            return std::nullopt;
        }
        bits = 8;
    } else if (has("short")) {
        if (long_count != 0) return std::nullopt;
        bits = 16;
    } else if (long_count >= 2) {
        bits = 64;
    } else if (long_count == 1) {
        bits = (abi == Abi::Win64 || abi == Abi::Ppc32Sysv ||
                abi == Abi::AapcsArm32)
            ? 32u : 64u;
    } else if (!has("int") && !is_unsigned && !explicitly_signed) {
        return std::nullopt;
    }

    for (std::string_view word : words) {
        if (word != "unsigned" && word != "signed" && word != "char" &&
            word != "short" && word != "int" && word != "long") {
            return std::nullopt;
        }
    }
    return DeclaredInteger{bits, !is_unsigned};
}

}  // namespace

std::optional<std::size_t> Emitter::declared_scalar_size(std::string_view type) const {
    if (type == "bool" || type == "_Bool") return 1;
    if (auto integer = declared_integer_type(type, abi)) return integer->bits / 8;
    if (auto floating = declared_fp_ir_type(type)) return type_bits(*floating) / 8;
    return std::nullopt;
}

u8 Emitter::cached_arity(addr_t target) const {
    auto it = arity_cache.find(static_cast<u64>(target));
    if (it != arity_cache.end()) return it->second;
    const u8 a = binary ? infer_arity(*binary, target) : u8{6};
    arity_cache.emplace(static_cast<u64>(target), a);
    return a;
}

const std::vector<InferredArgument>&
Emitter::cached_argument_layout(addr_t target) const {
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

std::string Emitter::clean_import_name(std::string_view n) {
    // C++ names come out of the linker mangled. For use at the call site
    // we only want the qualified identifier, not the parenthesized arg
    // list from the demangler (the emitter will render the actual args).
    return pretty_symbol_base(strip_import_name_decorations(n));
}

std::optional<std::string>
Emitter::import_name_for_direct_call(addr_t target) const {
    if (!binary) return std::nullopt;
    if (const Symbol* s = binary->import_at_plt(target); s) {
        return clean_import_name(s->name);
    }
    return std::nullopt;
}

std::optional<std::string>
Emitter::named_address_for_imm(addr_t target) const {
    if (!binary) return std::nullopt;
    auto resolved = resolve_address_name(*binary, target);
    if (!resolved) return std::nullopt;
    if (resolved->addr != resolved->base &&
        resolved->kind != ResolvedNameKind::Object &&
        resolved->kind != ResolvedNameKind::Got) {
        return std::nullopt;
    }
    if (resolved->kind == ResolvedNameKind::Function &&
        resolved->addr == resolved->base &&
        resolved->name.find("::") == std::string::npos) {
        address_taken_function_decls.insert(resolved->name);
    }
    if (resolved->kind == ResolvedNameKind::Object || resolved->kind == ResolvedNameKind::Got) {
        if (const Symbol* s = binary->defined_object_at(target);
            s && s->kind == SymbolKind::Object) {
            note_global_decl(*s, resolved->addr == resolved->base
                ? std::string{"uint64_t"}
                : std::string{"uint64_t[]"});
            if (resolved->addr == resolved->base) {
                return "&" + global_display_name(*s);
            }
        }
    }
    if (options.c_source && resolved->kind == ResolvedNameKind::Got) {
        // `sym@GOT` is a linker spelling, not a C identifier. The slot itself
        // is a pointer-sized global, so name it and take its address.
        const std::string slot =
            std::format("{}_got", sanitize_ident(resolved->name, "got"));
        global_decls.try_emplace(slot, "void*");
        if (resolved->addr != resolved->base) {
            return std::format("(uint8_t*)&{} + {:#x}", slot,
                               resolved->addr - resolved->base);
        }
        return "&" + slot;
    }
    return format_address_expr(*resolved);
}

std::optional<std::string>
Emitter::resolve_string_value(const IrValue& v) const {
    // PPC materializes addresses with lis/addi chains, so the format
    // operand is commonly an Add tree rather than a bare Imm/Assign.
    if (auto resolved = try_resolve_imm_addr(v); resolved) {
        const auto addr = normalized_address(*resolved);
        if (auto s = string_literals.try_cfstring_at(addr); s) return s;
        if (auto s = string_literals.try_c_string_at(addr); s) return s;
    }
    IrValue cur = v;
    for (int step = 0; step < 8; ++step) {
        if (cur.kind == IrValueKind::Imm) {
            const auto addr = static_cast<u64>(cur.imm);
            if (auto s = string_literals.try_cfstring_at(addr); s) return s;
            return string_literals.try_c_string_at(addr);
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

u8 Emitter::variadic_arity(const std::vector<IrValue>& args,
                           u8 format_index) const {
    if (format_index >= args.size()) return format_index;
    auto fmt = resolve_string_value(args[format_index]);
    if (!fmt) return static_cast<u8>(format_index + 1);
    return static_cast<u8>(format_index + 1 + count_printf_specifiers(*fmt));
}

bool Emitter::variadic_scanf_arg_is_charp(
    std::string_view name, const std::vector<IrValue>& args,
    std::size_t argument_index) const {
    if (name.find("scanf") == std::string_view::npos ||
        name.find("vscanf") != std::string_view::npos ||
        name.find("vfscanf") != std::string_view::npos ||
        name.find("vsscanf") != std::string_view::npos) {
        return false;
    }
    const auto format_index = variadic_format_index(name);
    if (!format_index || *format_index >= args.size()) return false;
    const auto format = resolve_string_value(args[*format_index]);
    if (!format) return false;

    std::size_t destination = static_cast<std::size_t>(*format_index) + 1;
    for (std::size_t i = 0; i < format->size(); ++i) {
        if ((*format)[i] != '%') continue;
        if (++i >= format->size()) break;
        if ((*format)[i] == '%') continue;
        bool suppressed = false;
        if ((*format)[i] == '*') {
            suppressed = true;
            if (++i >= format->size()) break;
        }
        while (i < format->size() &&
               std::isdigit(static_cast<unsigned char>((*format)[i]))) ++i;
        bool wide = false;
        if (i < format->size() && ((*format)[i] == 'h' || (*format)[i] == 'l')) {
            wide = (*format)[i] == 'l';
            const char length = (*format)[i++];
            if (i < format->size() && (*format)[i] == length) ++i;
        } else if (i < format->size() &&
                   std::string_view{"jztL"}.find((*format)[i]) !=
                       std::string_view::npos) {
            ++i;
        }
        if (i >= format->size()) break;
        const char conversion = (*format)[i];
        if (!suppressed) {
            if (destination == argument_index) {
                return !wide &&
                    (conversion == 's' || conversion == 'c' || conversion == '[');
            }
            ++destination;
        }
        if (conversion == '[') {
            if (i + 1 < format->size() && (*format)[i + 1] == '^') ++i;
            if (i + 1 < format->size() && (*format)[i + 1] == ']') ++i;
            while (i + 1 < format->size() && (*format)[i + 1] != ']') ++i;
            if (i + 1 < format->size()) ++i;
        }
    }
    return false;
}

bool Emitter::is_generic_sub_name(std::string_view name) noexcept {
    if (!name.starts_with("sub_") || name.size() <= 4) return false;
    for (char c : name.substr(4)) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

bool Emitter::is_unresolved_function_name(std::string_view name) noexcept {
    const auto valid_suffix = [](std::string_view suffix) noexcept {
        if (suffix.empty())
            return false;
        for (char c : suffix) {
            if (!std::isxdigit(static_cast<unsigned char>(c)))
                return false;
        }
        return true;
    };
    if (name.starts_with("sub_"))
        return valid_suffix(name.substr(4));
    if (name.starts_with("func_"))
        return valid_suffix(name.substr(5));
    return false;
}

std::optional<u8>
Emitter::printf_like_arity_from_literal_args(const std::vector<IrValue>& args) const {
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

std::optional<std::string>
Emitter::try_render_vfn_dispatch(const IrValue& target) const {
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

std::optional<std::string>
Emitter::import_name_for_indirect_call(const IrValue& v) const {
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

bool Emitter::is_declared_fp_scalar(std::string_view type) noexcept {
    return declared_fp_ir_type(type).has_value();
}

std::optional<bool>
Emitter::declared_arg_signedness_for_width(u8 slot,
                                           IrType value_type) const noexcept {
    if (slot >= self_arg_type_names.size() ||
        self_arg_type_names[slot].empty() || is_float_type(value_type)) {
        return std::nullopt;
    }
    const auto declared = declared_integer_type(
        normalize_c_type_alias(self_arg_type_names[slot]), abi);
    if (!declared || declared->bits != type_bits(value_type)) {
        return std::nullopt;
    }
    return declared->is_signed;
}

std::optional<u32>
Emitter::ppc_known_aggregate_size(std::string_view type) noexcept {
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

bool
Emitter::ppc_return_uses_hidden_sret(std::string_view type) noexcept {
    auto size = ppc_known_aggregate_size(type);
    return size && *size > 8;
}

bool Emitter::is_ppc_abi() const noexcept {
    return abi == Abi::Ppc32Sysv || abi == Abi::Ppc64ElfV1Be ||
           abi == Abi::Ppc64ElfV2Le;
}

i64 Emitter::ppc_parameter_area_base() const noexcept {
    return abi == Abi::Ppc32Sysv ? 0x08 : 0x30;
}

i64 Emitter::ppc_parameter_word_size() const noexcept {
    return abi == Abi::Ppc32Sysv ? 4 : 8;
}

i64 Emitter::ppc_advance_parameter_slot(i64& cursor,
                                              IrType type,
                                              u32 byte_width) const noexcept {
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

const std::string*
Emitter::abi_param_for(const FunctionSig& sig, Reg r) const noexcept {
    if (const ParamSig* param = abi_param_signature_for(sig, r)) {
        return &param->name;
    }
    return nullptr;
}

const ParamSig*
Emitter::abi_param_signature_for(const FunctionSig& sig, Reg r) const noexcept {
    const auto int_regs   = int_arg_regs(abi);
    const auto fp_regs    = fp_arg_regs(abi);
    const bool positional = abi_positional_arg_slots(abi);
    const Reg canon = canonical_reg(r);
    std::size_t int_idx = is_ppc_abi() &&
        ppc_return_uses_hidden_sret(sig.return_type) ? 1u : 0u;
    std::size_t fp_idx  = 0;
    std::size_t slot    = 0;
    for (const auto& p : sig.params) {
        const bool uses_fp_bank =
            !fp_regs.empty() && is_declared_fp_scalar(p.type);
        const auto aggregate_size = is_ppc_abi()
            ? ppc_known_aggregate_size(p.type)
            : std::nullopt;
        if (uses_fp_bank) {
            const std::size_t idx = positional ? slot : fp_idx;
            if (idx < fp_regs.size() && fp_regs[idx] == canon) return &p;
            ++fp_idx;
        } else {
            const std::size_t idx = positional ? slot : int_idx;
            if (idx < int_regs.size() && int_regs[idx] == canon) return &p;
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

std::vector<InferredArgument>
Emitter::abi_layout_for(const FunctionSig& sig) const {
    const auto int_regs = int_arg_regs(abi);
    const auto fp_regs = fp_arg_regs(abi);
    const bool positional = abi_positional_arg_slots(abi);
    const bool hidden_sret = is_ppc_abi() &&
        ppc_return_uses_hidden_sret(sig.return_type);
    std::size_t int_idx = hidden_sret ? 1u : 0u;
    std::size_t fp_idx = 0;
    std::size_t slot = 0;
    i64 ppc_cursor = is_ppc_abi() ? ppc_parameter_area_base() : 0;
    const i64 stack_word = abi_word_type() == IrType::I32 ? 4 : 8;
    i64 stack_cursor = abi == Abi::SysVAmd64 ? 8 : 0;
    if (hidden_sret) {
        (void)ppc_advance_parameter_slot(ppc_cursor, abi_word_type());
    }
    std::vector<InferredArgument> result;
    result.reserve(std::min<std::size_t>(sig.params.size(), kMaxAbiArgs));
    for (const auto& param : sig.params) {
        if (result.size() >= kMaxAbiArgs) break;
        const auto declared_fp_type = declared_fp_ir_type(param.type);
        const bool uses_fp_bank =
            !fp_regs.empty() && declared_fp_type.has_value();
        const auto aggregate_size = is_ppc_abi()
            ? ppc_known_aggregate_size(param.type)
            : std::nullopt;
        const std::size_t index = positional
            ? slot : (uses_fp_bank ? fp_idx : int_idx);
        Reg reg = Reg::None;
        std::size_t int_words = 1;
        const IrType ir_type = declared_fp_type.value_or(abi_word_type());
        std::optional<i64> stack_slot;
        const i64 ppc_slot = is_ppc_abi()
            ? ppc_advance_parameter_slot(ppc_cursor, ir_type,
                                         aggregate_size.value_or(0))
            : 0;
        if (uses_fp_bank) {
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
        if (reg == Reg::None) {
            if (is_ppc_abi()) {
                stack_slot = ppc_slot;
            } else if (abi == Abi::Win64) {
                stack_slot = 8 + static_cast<i64>(slot) * 8;
            } else {
                const i64 value_size = std::max<i64>(
                    stack_word, static_cast<i64>(type_bits(ir_type) / 8u));
                const i64 alignment = std::min<i64>(value_size, 8);
                stack_cursor = (stack_cursor + alignment - 1) /
                               alignment * alignment;
                stack_slot = stack_cursor;
                stack_cursor += value_size;
            }
        }
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

std::vector<InferredArgument>
Emitter::abi_layout_for_import(std::string_view name) const {
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
        const bool declared_fp = arena.kind(type) == TypeKind::Float;
        const bool uses_fp_bank = !fp_regs.empty() && declared_fp;
        const u32 aggregate_size = arena.kind(type) == TypeKind::Struct
            ? arena.node(type).s.size
            : 0;
        const std::size_t index = positional
            ? slot : (uses_fp_bank ? fp_idx : int_idx);
        Reg reg = Reg::None;
        const IrType ir_type = declared_fp
            ? (arena.node(type).f.bits <= 32 ? IrType::F32 : IrType::F64)
            : abi_word_type();
        std::size_t int_words = 1;
        std::optional<i64> stack_slot;
        if (uses_fp_bank) {
            if (index < fp_regs.size()) reg = fp_regs[index];
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

std::optional<std::string>
Emitter::incoming_stack_arg_name(const IrValue& addr, i64 off) const {
    if (!fn) return std::nullopt;
    (void)off;
    const auto entry_off = entry_stack_offset(addr);
    if (!entry_off) return std::nullopt;
    for (std::size_t i = 0; i < self_arg_layout.size(); ++i) {
        const auto& argument = self_arg_layout[i];
        if (!argument.stack_offset || *argument.stack_offset != *entry_off) continue;
        if (i < self_arg_names.size() && !self_arg_names[i].empty()) {
            return self_arg_names[i];
        }
        if (annotations) {
            if (const FunctionSig* signature = annotations->signature_for(fn->start);
                signature && i < signature->params.size()) {
                return signature_parameter_name(signature->params[i], i);
            }
        }
        return std::format("a{}", i + 1);
    }
    if (is_ppc_abi()) return std::nullopt;
    if (!abi_positional_arg_slots(abi)) return std::nullopt;
    if (*entry_off < 0x08 || (*entry_off - 0x08) % 8 != 0) return std::nullopt;
    const std::size_t k = static_cast<std::size_t>((*entry_off - 0x08) / 8);
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

std::optional<std::string>
Emitter::arg_name_for_live_in(Reg r) const {
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

IrType Emitter::abi_word_type() const noexcept {
    return (abi == Abi::Ppc32Sysv || abi == Abi::AapcsArm32)
        ? IrType::I32 : IrType::I64;
}

std::string_view Emitter::abi_word_c_type() const noexcept {
    return abi_word_type() == IrType::I32 ? "uint32_t" : "uint64_t";
}

std::optional<IrValue>
Emitter::preserved_call_arg_for_clobber(Reg r, u32 version) const {
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
    const auto position = ssa_uses.definition_position(*key);
    if (!position) return std::nullopt;
    const auto [bi, clobber_ii] = *position;
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

}  // namespace spelunk::emit
