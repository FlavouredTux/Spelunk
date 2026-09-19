// Memory operand rendering: globals, arrays, struct fields, PPC tables.
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

#include <spelunk/binary/symbol.hpp>
#include <spelunk/common/annotations.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/ir/ssa.hpp>
#include <spelunk/ir/types.hpp>

#include "emitter_internal.hpp"
#include "emitter_tables.hpp"

namespace spelunk::emit {
namespace {
std::optional<std::string> cast_untyped_array_base(
    const Emitter& e, const IrValue& base, IrType access_type,
    int depth, std::string_view loaded_type = {}) {
    std::string declared = e.c_type_name_for(base);
    if (auto pointer = e.declared_pointer_type(base)) declared = *pointer;
    if (auto slot = e.trace_to_self_arg_slot(base);
        slot && *slot < e.self_arg_type_names.size() &&
        e.self_arg_type_names[*slot].ends_with('*')) {
        declared = Emitter::normalize_c_type_alias(e.self_arg_type_names[*slot]);
    }
    const std::string element = loaded_type.ends_with('*')
        ? std::string(loaded_type) : std::string(c_type_name(access_type));
    // Indexing is only valid when the rendered base really is a pointer
    // with the access width. Integer addresses and void pointers need a cast.
    if (declared.ends_with('*') && declared != "void*" && declared != "const void*") {
        const auto scalar_size = e.declared_scalar_size(Emitter::imported_record_base(declared));
        if (declared.find('*') == declared.rfind('*') && scalar_size &&
            *scalar_size == type_bits(access_type) / 8) return std::nullopt;
        if (auto size = e.pointer_pointee_size(base);
            size && *size == type_bits(access_type) / 8) return std::nullopt;
    }
    // Preserve the signature while giving the individual access a sized
    // lvalue. A stored pointer needs one more indirection than an integer.
    return std::format("(({}*){})", element, e.expr(base, depth + 1));
}
}  // namespace


std::optional<i64>
Emitter::try_resolve_imm_addr(const IrValue& v, int depth) const {
    if (depth >= 8) return std::nullopt;
    if (v.kind == IrValueKind::Imm) return v.imm;
    if (binary && v.kind == IrValueKind::Reg) {
        if (canonical_reg(v.reg) == Reg::PpcR13) {
            if (auto base = binary->ppc_small_data_base(false); base) {
                return static_cast<i64>(*base);
            }
        } else if (canonical_reg(v.reg) == Reg::PpcR2) {
            if (auto base = binary->ppc_small_data_base(true); base) {
                return static_cast<i64>(*base);
            }
        }
    }
    const IrInst* d = def_stripped(v);
    if (!d) return std::nullopt;
    if (d->op == IrOp::Assign && d->src_count == 1) {
        return try_resolve_imm_addr(d->srcs[0], depth + 1);
    }
    if ((d->op == IrOp::Add || d->op == IrOp::Sub) && d->src_count >= 2) {
        auto lhs = try_resolve_imm_addr(d->srcs[0], depth + 1);
        auto rhs = resolve_imm(d->srcs[1]);
        if (lhs && rhs) return d->op == IrOp::Add ? *lhs + *rhs : *lhs - *rhs;
        if (d->op == IrOp::Add) {
            lhs = try_resolve_imm_addr(d->srcs[1], depth + 1);
            rhs = resolve_imm(d->srcs[0]);
            if (lhs && rhs) return *lhs + *rhs;
        }
    }
    return std::nullopt;
}

std::optional<std::string>
Emitter::render_global_mem(const IrValue& addr, IrType t) const {
    if (!binary) return std::nullopt;
    auto imm = try_resolve_imm_addr(addr);
    if (!imm) return std::nullopt;
    const addr_t a = normalized_address(*imm);
    const Symbol* s = binary->defined_object_at(a);
    if (!s || s->kind != SymbolKind::Object) return std::nullopt;
    if (s->name.empty()) return std::nullopt;

    const unsigned t_bytes = type_bits(t) / 8;
    const i64 off = static_cast<i64>(a) - static_cast<i64>(s->addr);
    std::string display_name = global_display_name(*s);
    if (off >= 0) {
        const IrValue base = IrValue::make_imm(
            static_cast<i64>(s->addr), abi_word_type());
        if (auto field = imported_global_object_field(base, off, t); field) {
            return *field;
        }
    }

    if (off == 0 && (s->size == 0 || s->size == t_bytes)) {
        note_global_decl(*s, std::string(c_type_name(t)));
        return display_name;
    }
    if (s->size == 0 && t_bytes != 0 && off > 0 &&
        (off % static_cast<i64>(t_bytes)) == 0) {
        note_global_decl(*s, std::format("{}[]", c_type_name(t)));
        return std::format("{}[{}]", display_name,
                           off / static_cast<i64>(t_bytes));
    }
    if (off == 0) {
        note_global_decl(*s, std::string(c_type_name(t)));
        return std::format("*({}*)&{}", c_type_name(t), display_name);
    }
    note_global_decl(*s, std::format("{}[]", c_type_name(t)));
    return std::format("*({}*)((uint8_t*)&{} + {:#x})",
                       c_type_name(t), display_name,
                       static_cast<u64>(off));
}

std::optional<i64> Emitter::resolve_imm(const IrValue& v) const {
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

std::optional<std::pair<IrValue, i64>>
Emitter::try_base_plus_offset(const IrValue& addr) const {
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

void Emitter::record_struct_access(const IrValue& addr, IrType t) {
    auto bo = canonical_struct_access(addr);
    if (!bo) return;
    // Skip stack-relative and global bases - those have richer rendering
    // paths already.
    if (stack_offset(bo->first).has_value()) return;
    if (try_resolve_imm_addr(bo->first).has_value()) return;
    if (auto k = ssa_key(bo->first); k) {
        struct_root_values.try_emplace(*k, bo->first);
        struct_offsets[*k].insert(bo->second);
        struct_access_types[*k][bo->second].insert(t);
        const unsigned bytes = type_bits(t) / 8;
        if (bytes != 0) {
            struct_access_widths[*k][bo->second].insert(bytes);
        }
    }
}

std::optional<std::string>
Emitter::try_render_array_index(const IrValue& addr, IrType t, int depth,
                                std::string_view loaded_type) const {
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
    // A Temp/Reg that simply aliases an immediate is still an address,
    // not an array object.  Rendering it as `-2[-1071632328]` is both
    // misleading and invalid C; leave it to the explicit typed-memory
    // form (which can also resolve a PPC32 symbol).
    if (resolve_imm(base)) return std::nullopt;
    // Reject when the base is itself an arithmetic combination - that's
    // the runtime-index pattern (`Add(Mul(idx, stride), Imm)` and friends),
    // not a real pointer base. Without this guard, `Load(Add(idx*8, &tbl))`
    // would render as the malformed `(idx*8)[&tbl/8]`. Let the runtime-
    // array path handle scaled indexing instead.
    if (const IrInst* bd = def_stripped(base);
        bd && (bd->op == IrOp::Mul || bd->op == IrOp::Shl ||
               bd->op == IrOp::Lshr || bd->op == IrOp::Ashr ||
               bd->op == IrOp::And || bd->op == IrOp::Or ||
               bd->op == IrOp::Xor || bd->op == IrOp::Add ||
               bd->op == IrOp::Sub)) {
        return std::nullopt;
    }
    // Vector-shape pointer: defer to the struct-field path so the
    // 3 canonical offsets render as begin/end/capacity instead of
    // an array slice. argv-style ptr-to-ptr accesses don't touch
    // exactly {0, 8, 16} so they continue rendering as `a[i]`.
    if (looks_like_vector(base)) return std::nullopt;
    if (auto pointee_size = pointer_pointee_size(base);
        pointee_size && *pointee_size != static_cast<std::size_t>(stride)) {
        return std::nullopt;
    }
    if (off == 0) {
        if (auto field = imported_typed_pointer_field(base, 0, depth); field) {
            return field;
        }
    }
    std::string rendered_base = expr(base, depth + 1);
    if (auto typed = cast_untyped_array_base(*this, base, t, depth, loaded_type)) {
        return std::format("{}[{}]", *typed, off / stride);
    }
    // A pointer loaded from memory still has an integer-width Load in
    // IR, even when local type inference has proved that the assigned
    // value is a pointer. Indexing the raw rendered load would produce
    // invalid C (`*(uint64_t*)slot[0]`) and lose the pointee width.
    // Reapply the refined pointer type at this expression boundary.
    if (const IrInst* bd = def_stripped(base);
        bd && bd->op == IrOp::Load && fn &&
        fn->types.kind(fn->type_of(base)) == TypeKind::Ptr) {
        std::string base_type = c_type_name_for(base);
        bool unknown_pointer = base_type == "void*";
        if (base_type == "void*") {
            // A load result refined to T* proves that the address of
            // that load is T**. Preserve that extra pointer level at the
            // expression boundary even when the local lattice retained
            // only Ptr<Top> for the intermediate address.
            base_type = loaded_type.ends_with('*')
                ? std::string(loaded_type) + "*"
                : std::string(c_type_name(t)) + "*";
            if (annotations) {
                auto slot = trace_to_self_arg_slot(base);
                if (!slot) {
                    for (std::size_t index = 0;
                         index < self_arg_names.size(); ++index) {
                        if (!self_arg_names[index].empty() &&
                            self_arg_names[index] == rendered_base) {
                            slot = static_cast<u8>(index);
                            break;
                        }
                    }
                }
                if (slot) {
                    if (const FunctionSig* signature =
                            annotations->signature_for(fn->start);
                        signature && *slot < signature->params.size()) {
                        const std::string declared = normalize_c_type_alias(
                            signature->params[*slot].type);
                        const auto byte_pointer = [](std::string_view type) {
                            return type == "char*" || type == "uint8_t*" ||
                                   type == "int8_t*" || type == "const char*" ||
                                   type == "const uint8_t*" ||
                                   type == "const int8_t*";
                        };
                        if (declared == base_type ||
                            (byte_pointer(declared) && byte_pointer(base_type))) {
                            unknown_pointer = false;
                        }
                    }
                }
            }
        }
        if (unknown_pointer || rendered_base.starts_with("*(")) {
            rendered_base = std::format("(({}){})", base_type, rendered_base);
        }
    }
    return std::format("{}[{}]", rendered_base, off / stride);
}

std::optional<std::string>
Emitter::try_render_runtime_array_index(const IrValue& addr, IrType t,
                                int depth, std::string_view loaded_type) const {
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
                return std::format("{}[{}]", global_display_name(*s),
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
    const auto typed = cast_untyped_array_base(*this, base, t, depth, loaded_type);
    return std::format("{}[{}]",
        typed ? *typed : expr(base, depth + 1, std::to_underlying(Prec::Unary)),
        expr(idx, depth + 1));
}

std::optional<Emitter::PpcScaledIndex>
Emitter::match_ppc_scaled_index(const IrValue& value) const {
    const IrInst* definition = def_stripped(value);
    if (!definition || definition->src_count < 2) return std::nullopt;
    if (definition->op == IrOp::Mul) {
        for (u8 i = 0; i < 2; ++i) {
            if (auto factor = resolve_imm(definition->srcs[i]);
                factor && *factor > 0) {
                return PpcScaledIndex{definition->srcs[1 - i], *factor};
            }
        }
        return std::nullopt;
    }
    if (definition->op == IrOp::Shl) {
        auto shift = resolve_imm(definition->srcs[1]);
        if (!shift || *shift < 0 || *shift >= 31) return std::nullopt;
        return PpcScaledIndex{
            definition->srcs[0], i64{1} << static_cast<unsigned>(*shift)};
    }
    if (definition->op != IrOp::And) return std::nullopt;
    const IrValue* rotated = nullptr;
    std::optional<i64> mask;
    for (u8 i = 0; i < 2; ++i) {
        if (auto immediate = resolve_imm(definition->srcs[i]); immediate) {
            mask = immediate;
            rotated = &definition->srcs[1 - i];
            break;
        }
    }
    if (!rotated || !mask) return std::nullopt;
    const IrInst* joined = def_stripped(*rotated);
    if (!joined || joined->op != IrOp::Or || joined->src_count < 2) {
        return std::nullopt;
    }
    const IrInst* left = nullptr;
    const IrInst* right = nullptr;
    for (u8 i = 0; i < 2; ++i) {
        const IrInst* shifted = def_stripped(joined->srcs[i]);
        if (!shifted || shifted->src_count < 2) return std::nullopt;
        if (shifted->op == IrOp::Shl) left = shifted;
        else if (shifted->op == IrOp::Lshr) right = shifted;
    }
    if (!left || !right || !same_ssa(left->srcs[0], right->srcs[0])) {
        return std::nullopt;
    }
    const auto left_shift = resolve_imm(left->srcs[1]);
    const auto right_shift = resolve_imm(right->srcs[1]);
    if (!left_shift || !right_shift || *left_shift <= 0 ||
        *left_shift >= 31 || *right_shift != 32 - *left_shift) {
        return std::nullopt;
    }
    const u32 expected = 0xffffffffu << static_cast<unsigned>(*left_shift);
    if (static_cast<u32>(*mask) != expected) return std::nullopt;
    return PpcScaledIndex{
        left->srcs[0], i64{1} << static_cast<unsigned>(*left_shift)};
}

std::optional<Emitter::ImportedPointerRecord>
Emitter::imported_pointer_record(const IrValue& value, int depth) const {
    if (!annotations) return std::nullopt;
    std::string type;
    const Symbol* global_slot = binary ? global_object_for_load(value) : nullptr;
    if (global_slot) {
        if (const std::string* imported =
                annotations->global_type_for(global_slot->addr); imported) {
            type = *imported;
        } else if (auto found =
                       annotations->imported_global_types_by_name.find(
                           global_slot->name);
                   found != annotations->imported_global_types_by_name.end()) {
            type = found->second;
        }
    }
    // A pointer loaded from an imported record field (for example
    // PausewinWork::entries) may still carry only its ABI storage width
    // in the local type lattice. Recover the pointee from the owner
    // record before falling back to that integer-shaped local type.
    if (type.empty() || !normalize_c_type_alias(type).ends_with('*')) {
        const IrInst* load = def_stripped(value);
        if (load && load->op == IrOp::Load && load->src_count >= 1) {
            if (auto access = canonical_struct_access(load->srcs[0]); access) {
                const Symbol* owner_slot = binary
                    ? global_object_for_load(access->first) : nullptr;
                const std::string* owner_type = owner_slot
                    ? annotations->global_type_for(owner_slot->addr) : nullptr;
                if (owner_slot && !owner_type) {
                    auto found = annotations->imported_global_types_by_name.find(
                        owner_slot->name);
                    if (found != annotations->imported_global_types_by_name.end()) {
                        owner_type = &found->second;
                    }
                }
                if (owner_type) {
                    const std::string owner_name = imported_record_base(*owner_type);
                    auto owner = annotations->imported_records.find(owner_name);
                    if (owner != annotations->imported_records.end()) {
                        auto field = owner->second.fields.find(access->second);
                        if (field != owner->second.fields.end() &&
                            field->second.type.find('*') != std::string::npos) {
                            type = field->second.type;
                        }
                    }
                }
            }
        }
    }
    if (type.empty()) type = c_type_name_for(value);
    type = normalize_c_type_alias(std::move(type));
    if (!type.ends_with('*')) return std::nullopt;
    const std::string record_name = imported_record_base(type);
    auto record = annotations->imported_records.find(record_name);
    if (record == annotations->imported_records.end()) return std::nullopt;
    std::string rendered = expr(
        value, depth + 1, std::to_underlying(Prec::Postfix));
    if (global_slot) {
        note_global_decl(*global_slot, type);
        rendered = global_display_name(*global_slot);
    }
    return ImportedPointerRecord{
        value,
        std::move(rendered),
        record_name,
        &record->second,
    };
}

std::optional<std::string>
Emitter::try_render_imported_indexed_field(const IrValue& addr, IrType access_type,
                                           int depth) const {
    if (!is_ppc_abi() || !annotations) return std::nullopt;
    i64 constant = 0;
    std::vector<IrValue> terms;
    const auto flatten = [&](const auto& self, const IrValue& value,
                             int remaining) -> bool {
        if (remaining <= 0) return false;
        if (auto immediate = resolve_imm(value); immediate) {
            constant += *immediate;
            return true;
        }
        const IrInst* definition = def_stripped(value);
        if (definition && definition->op == IrOp::Add &&
            definition->src_count >= 2) {
            return self(self, definition->srcs[0], remaining - 1) &&
                   self(self, definition->srcs[1], remaining - 1);
        }
        terms.push_back(value);
        return true;
    };
    if (!flatten(flatten, addr, 12) || terms.size() != 2) {
        return std::nullopt;
    }

    for (u8 base_i = 0; base_i < 2; ++base_i) {
        auto base = imported_pointer_record(terms[base_i], depth);
        auto scaled = match_ppc_scaled_index(terms[1 - base_i]);
        if (!base || !scaled || scaled->scale <= 0 || constant < 0) continue;
        const std::size_t access_size = std::max<unsigned>(
            1, type_bits(access_type) / 8);

        if (static_cast<std::size_t>(scaled->scale) == base->layout->size) {
            auto field = imported_field_expression_typed(
                *base->layout, constant, access_type);
            if (!field) continue;
            return std::format("{}[{}].{}", base->expression,
                expr(scaled->index, depth + 1,
                     std::to_underlying(Prec::Postfix)), *field);
        }

        auto after = base->layout->fields.upper_bound(constant);
        if (after == base->layout->fields.begin()) continue;
        const ImportedRecordField& field = std::prev(after)->second;
        if (field.type.find('[') == std::string::npos || field.name.empty() ||
            constant < static_cast<i64>(field.offset) ||
            constant >= static_cast<i64>(field.offset + field.size) ||
            static_cast<std::size_t>(scaled->scale) < access_size) {
            continue;
        }
        const i64 within = constant - static_cast<i64>(field.offset);
        if (within % scaled->scale != 0) continue;
        std::string index = expr(scaled->index, depth + 1,
                                 std::to_underlying(Prec::Add));
        const i64 fixed_index = within / scaled->scale;
        if (fixed_index != 0) {
            index = std::format("{} + {}", index, fixed_index);
        }
        return std::format("{}->{}[{}]", base->expression, field.name, index);
    }
    return std::nullopt;
}

std::optional<std::string>
Emitter::try_render_ppc_strided_table_access(const IrValue& addr, IrType access_type,
                                             int depth) const {
    if (!is_ppc_abi() || !binary) return std::nullopt;
    i64 constant = 0;
    std::optional<PpcScaledIndex> scaled;
    const auto flatten = [&](const auto& self, const IrValue& value,
                             int remaining) -> bool {
        if (remaining <= 0) return false;
        if (auto immediate = resolve_imm(value); immediate) {
            constant += *immediate;
            return true;
        }
        if (auto candidate = match_ppc_scaled_index(value); candidate) {
            if (scaled) return false;
            scaled = *candidate;
            return true;
        }
        const IrInst* definition = def_stripped(value);
        if (!definition || definition->op != IrOp::Add ||
            definition->src_count < 2) return false;
        return self(self, definition->srcs[0], remaining - 1) &&
               self(self, definition->srcs[1], remaining - 1);
    };
    if (!flatten(flatten, addr, 12) || !scaled || scaled->scale <= 0) {
        return std::nullopt;
    }
    const addr_t absolute = normalized_address(constant);
    const Symbol* table = binary->defined_object_at(absolute);
    const std::size_t access_size = std::max<unsigned>(
        1, type_bits(access_type) / 8);
    if (!table || table->kind != SymbolKind::Object || table->name.empty() ||
        table->size == 0 || absolute < table->addr ||
        scaled->scale <= static_cast<i64>(access_size) ||
        table->size % static_cast<u64>(scaled->scale) != 0) {
        return std::nullopt;
    }
    const i64 field_offset = static_cast<i64>(absolute - table->addr);
    if (field_offset < 0 || field_offset + static_cast<i64>(access_size) >
                              scaled->scale) return std::nullopt;
    const std::string name = global_display_name(*table);
    auto [found, inserted] = ppc_strided_tables.try_emplace(name);
    if (inserted) {
        found->second.type_name = ppc_strided_tables.size() == 1
            ? "PpcDataEntry"
            : std::format("PpcDataEntry{}", ppc_strided_tables.size());
        found->second.stride = static_cast<std::size_t>(scaled->scale);
    }
    if (found->second.stride != static_cast<std::size_t>(scaled->scale)) {
        return std::nullopt;
    }
    found->second.fields[field_offset] = access_type;
    global_decls[name] = found->second.type_name + "[]";
    const std::string field = std::format("{}_{}",
        is_float_type(access_type) ? "float" : "word",
        field_offset == 0 ? "0" : std::format("{:x}", field_offset));
    return std::format("{}[{}].{}", name,
        expr(scaled->index, depth + 1, std::to_underlying(Prec::Postfix)),
        field);
}

std::optional<std::string>
Emitter::try_render_ppc_strided_table_address(const IrValue& addr, int depth) const {
    if (!is_ppc_abi() || !binary || ppc_strided_tables.empty()) {
        return std::nullopt;
    }
    i64 constant = 0;
    std::optional<PpcScaledIndex> scaled;
    const auto flatten = [&](const auto& self, const IrValue& value,
                             int remaining) -> bool {
        if (remaining <= 0) return false;
        if (auto immediate = resolve_imm(value); immediate) {
            constant += *immediate;
            return true;
        }
        if (auto candidate = match_ppc_scaled_index(value); candidate) {
            if (scaled) return false;
            scaled = *candidate;
            return true;
        }
        const IrInst* definition = def_stripped(value);
        if (!definition || definition->op != IrOp::Add ||
            definition->src_count < 2) return false;
        return self(self, definition->srcs[0], remaining - 1) &&
               self(self, definition->srcs[1], remaining - 1);
    };
    if (!flatten(flatten, addr, 12) || !scaled || scaled->scale <= 0) {
        return std::nullopt;
    }
    const addr_t absolute = normalized_address(constant);
    const Symbol* symbol = binary->defined_object_at(absolute);
    if (!symbol || symbol->addr != absolute || symbol->name.empty()) {
        return std::nullopt;
    }
    const std::string name = global_display_name(*symbol);
    auto table = ppc_strided_tables.find(name);
    if (table == ppc_strided_tables.end() ||
        table->second.stride != static_cast<std::size_t>(scaled->scale)) {
        return std::nullopt;
    }
    return std::format("&{}[{}]", name,
        expr(scaled->index, depth + 1, std::to_underlying(Prec::Postfix)));
}

std::optional<std::string>
Emitter::try_render_ppc_navigation_table_access(const IrValue& addr, IrType access_type,
                                                int depth) const {
    if (!is_ppc_abi() || !binary || !fn ||
        fn->name.find("pluswin") == std::string::npos) return std::nullopt;
    const auto scaled_index = [&](const auto& self,
                                  const IrValue& value) -> std::optional<IrValue> {
        const IrInst* definition = def_stripped(value);
        if (!definition) return std::nullopt;
        if (definition->op == IrOp::Mul && definition->src_count >= 2) {
            for (u8 i = 0; i < 2; ++i) {
                if (auto factor = resolve_imm(definition->srcs[i]); factor == 8) {
                    return definition->srcs[1 - i];
                }
            }
        }
        if (definition->op == IrOp::Shl && definition->src_count >= 2) {
            if (auto shift = resolve_imm(definition->srcs[1]); shift == 3) {
                return definition->srcs[0];
            }
        }
        if (definition->op == IrOp::And && definition->src_count >= 2) {
            return self(self, definition->srcs[0]);
        }
        if (definition->op == IrOp::Or && definition->src_count >= 2) {
            for (u8 i = 0; i < 2; ++i) {
                const IrInst* shifted = def_stripped(definition->srcs[i]);
                if (shifted && shifted->op == IrOp::Shl &&
                    shifted->src_count >= 2 &&
                    resolve_imm(shifted->srcs[1]) == 3) {
                    return shifted->srcs[0];
                }
            }
        }
        return std::nullopt;
    };

    i64 constant = 0;
    std::optional<IrValue> index;
    const auto flatten = [&](const auto& self, const IrValue& value) -> bool {
        if (auto immediate = resolve_imm(value); immediate) {
            constant += *immediate;
            return true;
        }
        if (auto scaled = scaled_index(scaled_index, value); scaled) {
            if (index) return false;
            index = *scaled;
            return true;
        }
        const IrInst* definition = def_stripped(value);
        if (!definition || definition->op != IrOp::Add ||
            definition->src_count < 2) return false;
        return self(self, definition->srcs[0]) &&
               self(self, definition->srcs[1]);
    };
    if (!flatten(flatten, addr) || !index) return std::nullopt;

    const addr_t absolute = normalized_address(constant);
    const Symbol* table = binary->defined_object_at(absolute);
    if (!table || table->kind != SymbolKind::Object || table->size == 0 ||
        absolute < table->addr) return std::nullopt;
    const i64 field_offset = static_cast<i64>(absolute - table->addr);
    if (field_offset < 0 || field_offset >= 8 || table->size % 8 != 0) {
        return std::nullopt;
    }
    const std::string name = global_display_name(*table);
    note_global_decl(*table, "PpcNavigationEntry[]");
    global_decls[name] = "PpcNavigationEntry[]";
    ppc_navigation_tables[name] = table->size / 8;
    const std::string entry = std::format("{}[{}]", name,
        expr(*index, depth + 1, std::to_underlying(Prec::Postfix)));
    if (field_offset >= 0 && field_offset <= 3 && access_type == IrType::I8) {
        return std::format("{}.neighbor_{}", entry, field_offset);
    }
    if (field_offset == 4 && access_type == IrType::I32) {
        return std::format("{}.callback", entry);
    }
    return std::nullopt;
}

std::optional<std::string>
Emitter::try_render_ppc_navigation_table_address(const IrValue& addr, int depth) const {
    auto first_field = try_render_ppc_navigation_table_access(
        addr, IrType::I8, depth);
    constexpr std::string_view suffix = ".neighbor_0";
    if (!first_field || !first_field->ends_with(suffix)) return std::nullopt;
    first_field->resize(first_field->size() - suffix.size());
    return "&" + *first_field;
}

std::optional<i64>
Emitter::stack_storage_base(i64 offset, u32 access_bytes) const noexcept {
    const u64 bytes = std::max<u32>(1u, access_bytes);
    for (const auto& [start, span] : stack_storage_ranges) {
        if (start > offset) break;
        const u64 displacement = static_cast<u64>(offset) -
                                 static_cast<u64>(start);
        if (displacement <= span && bytes <= span - displacement) {
            return start;
        }
    }
    return std::nullopt;
}

std::string Emitter::stack_address_expr(i64 offset,
                                        const IrValue* value) const {
    std::optional<i64> base;
    if (value) {
        if (auto key = ssa_key(*value); key) {
            auto provenance = stack_address_storage_base.find(*key);
            if (provenance != stack_address_storage_base.end()) {
                base = provenance->second;
            }
        }
    }
    if (!base) base = stack_storage_base(offset);
    const i64 storage = base.value_or(offset);
    const auto slot = frame_layout.slots.find(storage);
    const std::string name =
        slot != frame_layout.slots.end() && !slot->second.name.empty()
            ? slot->second.name
            : stack_name(storage);
    const bool byte_storage = base &&
        stack_byte_storage_ranges.contains(storage) &&
        (slot == frame_layout.slots.end() || slot->second.type_override.empty());
    if (!base || (!byte_storage && storage == offset)) return "&" + name;
    const bool after_base = offset >= storage;
    const u64 displacement = after_base
        ? static_cast<u64>(offset) - static_cast<u64>(storage)
        : static_cast<u64>(storage) - static_cast<u64>(offset);
    if (byte_storage) {
        if (displacement == 0) return name;
        return std::format("({} {} {:#x})", name,
                           after_base ? "+" : "-", displacement);
    }
    return std::format("((uint8_t*)&{} {} {:#x})", name,
                       after_base ? "+" : "-", displacement);
}

std::string Emitter::stack_storage_access(i64 offset, IrType type,
                                          std::string_view loaded_type) const {
    const u32 access_bytes = std::max(1u, type_bits(type) / 8u);
    const auto base = stack_storage_base(offset, access_bytes);
    if (!base) return {};
    const auto slot = frame_layout.slots.find(*base);
    const bool byte_storage = stack_byte_storage_ranges.contains(*base) &&
        (slot == frame_layout.slots.end() || slot->second.type_override.empty());
    if (!byte_storage && *base == offset) return {};
    const std::string name =
        slot != frame_layout.slots.end() && !slot->second.name.empty()
            ? slot->second.name
            : stack_name(*base);
    const u64 displacement = static_cast<u64>(offset) -
                             static_cast<u64>(*base);
    const std::string value_type = loaded_type.empty()
        ? std::string(c_type_name(type))
        : normalize_c_type_alias(loaded_type);
    if (byte_storage) {
        if (displacement == 0) {
            return std::format("*({}*){}", value_type, name);
        }
        return std::format("*({}*)({} + {:#x})",
                           value_type, name, displacement);
    }
    return std::format("*({}*)((uint8_t*)&{} + {:#x})",
                       value_type, name, displacement);
}

std::string Emitter::format_mem(const IrValue& addr, IrType t, Reg seg,
                                      int depth,
                                      std::string_view loaded_type) const {
    if (seg == Reg::None) {
        if (auto off = stack_offset(addr); off) {
            if (auto field = imported_stack_field(*off, t); field) {
                return *field;
            }
            if (auto interior = stack_storage_access(*off, t, loaded_type);
                !interior.empty()) {
                return interior;
            }
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
        if (auto navigation = try_render_ppc_navigation_table_access(
                addr, t, depth); navigation) return *navigation;
        if (auto field = try_render_imported_indexed_field(addr, t, depth);
            field) return *field;
        if (auto table = try_render_ppc_strided_table_access(addr, t, depth);
            table) return *table;
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
                            if (auto s = string_literals.try_c_string_at(ptr); s) {
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
                if (auto field = imported_global_object_field(base, off, t); field) {
                    return *field;
                }
                if (auto field = imported_global_pointer_field(base, off, t); field) {
                    return *field;
                }
                if (auto field = imported_call_result_field(base, off, depth, t); field) {
                    return *field;
                }
                if (auto field = imported_typed_pointer_field(base, off, depth, t); field) {
                    return *field;
                }
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
        if (auto bo = try_base_plus_offset(addr)) {
            const auto width = static_cast<i64>(type_bits(t) / 8);
            if (width && bo->second % width == 0 &&
                c_type_name_for(bo->first) == std::format("{}*", c_type_name(t))) {
                return std::format("{}[{}]",
                    expr(bo->first, depth + 1, std::to_underlying(Prec::Postfix)),
                    bo->second / width);
            }
        }
        if (auto bo = try_base_plus_offset(addr);
            bo && is_strong_struct_pointer(bo->first)) {
            auto shared = canonical_struct_access(addr);
            const IrValue& base = shared ? shared->first : bo->first;
            const i64 off = shared ? shared->second : bo->second;
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
            if (synthetic_member_type(base, off)) {
                return std::format("{}->{}", base_expr,
                                   synthetic_member_name(base, off, t));
            }
            return std::format("{}->{}", base_expr,
                               fallback_field_name(off, t));
        }
        // Array-indexing form takes priority over the struct-field
        // rendering when both apply - u64 stride-8 accesses usually mean
        // "argv-style pointer-to-pointer", which reads more naturally
        // as `a[i]` than `a->field_N`.
        if (auto s = try_render_array_index(addr, t, depth, loaded_type); s) {
            return *s;
        }
        if (auto s = try_render_runtime_array_index(addr, t, depth, loaded_type); s) {
            return *s;
        }
        // Struct-field form: if this base has been observed at multiple
        // distinct offsets, render as base->field_<hex>. Width cast goes
        // inside the member expression so the reader still sees the
        // access type (`*(u32*)&obj->field_18`) when it differs from the
        // presumed u64 field default.
        if (auto bo = try_base_plus_offset(addr);
            bo && is_struct_pointer(bo->first)) {
            auto shared = canonical_struct_access(addr);
            const IrValue& base = shared ? shared->first : bo->first;
            const i64 off = shared ? shared->second : bo->second;
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
            if (synthetic_member_type(base, off)) {
                return std::format("{}->{}", base_expr,
                                   synthetic_member_name(base, off, t));
            }
            if (t == IrType::I64) {
                return std::format("{}->{}", base_expr,
                                   fallback_field_name(off, t));
            }
            return std::format("*({}*)&{}->{}",
                               c_type_name(t), base_expr,
                               fallback_field_name(off, t));
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

}  // namespace spelunk::emit
