// Imported record layouts (headers/PDB) applied to field accesses.
#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <format>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <ember/binary/symbol.hpp>
#include <ember/common/annotations.hpp>
#include <ember/common/types.hpp>
#include <ember/ir/ir.hpp>
#include <ember/ir/ssa.hpp>

#include "emitter_internal.hpp"

namespace ember::emit {

std::optional<std::pair<IrValue, i64>>
Emitter::canonical_struct_access(const IrValue& addr) const {
    IrValue base = addr;
    i64 offset = 0;
    for (int depth = 0; depth < 12; ++depth) {
        auto bo = try_base_plus_offset(base);
        if (!bo) return std::nullopt;
        auto old_key = ssa_key(base);
        auto new_key = ssa_key(bo->first);
        if (bo->second == 0 && old_key && new_key && *old_key == *new_key) {
            break;
        }
        offset += bo->second;
        base = bo->first;
    }
    if (auto root = alias_root_for_value(base); root) base = *root;
    if (!ssa_key(base)) return std::nullopt;
    return std::pair{base, offset};
}

std::string Emitter::imported_record_base(std::string type) {
    auto erase_word = [&](std::string_view word) {
        for (;;) {
            const auto pos = type.find(word);
            if (pos == std::string::npos) break;
            type.erase(pos, word.size());
        }
    };
    erase_word("const ");
    erase_word("volatile ");
    erase_word("struct ");
    if (const auto array = type.find('['); array != std::string::npos) {
        type.resize(array);
    }
    while (!type.empty() &&
           (type.back() == '*' || type.back() == '&' ||
            std::isspace(static_cast<unsigned char>(type.back())))) {
        type.pop_back();
    }
    const auto ns = type.rfind("::");
    if (ns != std::string::npos) type.erase(0, ns + 2);
    return type;
}

std::optional<std::string>
Emitter::imported_field_expression(const ImportedRecordLayout& record, i64 offset) {
    auto after = record.fields.upper_bound(offset);
    if (after == record.fields.begin()) return std::nullopt;
    const auto field_it = std::prev(after);
    const ImportedRecordField& field = field_it->second;
    if (field.name.empty() || offset < static_cast<i64>(field.offset) ||
        offset >= static_cast<i64>(field.offset + field.size)) {
        return std::nullopt;
    }
    const i64 within = offset - static_cast<i64>(field.offset);
    const auto open = field.type.find('[');
    const auto close = open == std::string::npos
        ? std::string::npos : field.type.find(']', open + 1);
    if (open != std::string::npos && close != std::string::npos) {
        std::size_t count = 0;
        const std::string_view raw_count(
            field.type.data() + open + 1, close - open - 1);
        const auto parsed = std::from_chars(
            raw_count.data(), raw_count.data() + raw_count.size(), count, 10);
        if (parsed.ec == std::errc{} && count != 0 && field.size >= count) {
            const std::size_t stride = field.size / count;
            if (stride != 0 && within % static_cast<i64>(stride) == 0) {
                return std::format("{}[{}]", field.name,
                                   within / static_cast<i64>(stride));
            }
        }
    }
    return within == 0 ? std::optional<std::string>{field.name}
                       : std::nullopt;
}

std::optional<std::string>
Emitter::imported_field_expression_typed(const ImportedRecordLayout& record,
                                         i64 offset, IrType access_type) const {
    auto after = record.fields.upper_bound(offset);
    if (after == record.fields.begin()) return std::nullopt;
    const ImportedRecordField& field = std::prev(after)->second;
    if (field.name.empty() || offset < static_cast<i64>(field.offset) ||
        offset >= static_cast<i64>(field.offset + field.size)) {
        return std::nullopt;
    }
    const std::size_t access_size = std::max<unsigned>(
        1, type_bits(access_type) / 8);
    const i64 within = offset - static_cast<i64>(field.offset);
    const std::string nested_name = imported_record_base(field.type);
    if (field.type.find('*') == std::string::npos &&
        field.type.find('[') == std::string::npos &&
        field.size > access_size && annotations) {
        auto nested = annotations->imported_records.find(nested_name);
        if (nested != annotations->imported_records.end()) {
            if (auto member = imported_field_expression_typed(
                    nested->second, within, access_type); member) {
                return std::format("{}.{}", field.name, *member);
            }
        }
    }
    if (field.type.find('[') == std::string::npos &&
        field.size != access_size) return std::nullopt;
    return imported_field_expression(record, offset);
}

std::optional<std::size_t>
Emitter::pointer_pointee_size(const IrValue& pointer) const {
    std::string type = c_type_name_for(pointer);
    if (annotations && fn) {
        if (auto slot = trace_pointer_alias_to_self_arg_slot(pointer); slot) {
            if (const FunctionSig* signature = annotations->signature_for(fn->start);
                signature && *slot < signature->params.size()) {
                const std::string declared = normalize_c_type_alias(
                    signature->params[*slot].type);
                if (declared.ends_with('*')) type = declared;
            }
        }
    }
    if (type.ends_with('*')) {
        type = imported_record_base(std::move(type));
    } else {
        type.clear();
    }
    if (annotations && !type.empty()) {
        if (auto size = annotations->type_size_for(type); size && *size != 0) {
            return size;
        }
    }
    // A pointer loaded from an imported record field can remain `void*`
    // in the IR lattice. Recover the pointee from the field declaration
    // itself so `work->entries + id * sizeof(Entry)` scales as a typed
    // pointer rather than repeating the byte stride.
    if (annotations) {
        const IrInst* load = def_stripped(pointer);
        if (load && load->op == IrOp::Load && load->src_count >= 1) {
            if (auto access = try_base_plus_offset(load->srcs[0]); access) {
                if (const Symbol* slot = global_object_for_load(access->first); slot) {
                    const std::string* global_type =
                        annotations->global_type_for(slot->addr);
                    if (global_type && global_type->find('*') != std::string::npos) {
                        const std::string owner = imported_record_base(*global_type);
                        auto record = annotations->imported_records.find(owner);
                        if (record != annotations->imported_records.end()) {
                            auto after = record->second.fields.upper_bound(access->second);
                            if (after != record->second.fields.begin()) {
                                const ImportedRecordField& field = std::prev(after)->second;
                                if (access->second >= static_cast<i64>(field.offset) &&
                                    access->second < static_cast<i64>(field.offset + field.size) &&
                                    field.type.find('*') != std::string::npos) {
                                    const std::string pointee =
                                        imported_record_base(field.type);
                                    if (auto size = annotations->type_size_for(pointee);
                                        size && *size != 0) return size;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if (type.empty()) return std::nullopt;
    auto synthetic = struct_type_members.find(type);
    if (synthetic == struct_type_members.end()) return std::nullopt;
    std::optional<std::size_t> begin;
    std::size_t end = 0;
    for (const auto& [offset, types] : synthetic->second) {
        if (offset < 0) continue;
        begin = begin ? std::min(*begin, static_cast<std::size_t>(offset))
                      : std::optional<std::size_t>{static_cast<std::size_t>(offset)};
        for (IrType member : types) {
            end = std::max(end, static_cast<std::size_t>(offset) +
                                 std::max<unsigned>(1, type_bits(member) / 8));
        }
    }
    if (!begin || end <= *begin) return std::nullopt;
    return ((end - *begin) + 3u) & ~std::size_t{3};
}

bool Emitter::pointer_step_matches(const IrValue& pointer,
                                   i64 byte_step) const {
    if (byte_step <= 0) return false;
    auto size = pointer_pointee_size(pointer);
    if (!size) return false;
    if (static_cast<std::size_t>(byte_step) == *size) return true;
    const std::string type = imported_record_base(c_type_name_for(pointer));
    const bool synthetic = type.starts_with("PpcState") ||
                           type.starts_with("PpcObject") ||
                           type.starts_with("PpcGlobalState");
    return synthetic && static_cast<std::size_t>(byte_step) > *size &&
           static_cast<std::size_t>(byte_step) - *size <= 16u;
}

std::optional<std::string>
Emitter::imported_stack_field(i64 offset, IrType access_type) const {
    if (!annotations) return std::nullopt;
    for (const auto& [_, slot] : frame_layout.slots) {
        if (slot.name.empty() || slot.type_override.empty()) continue;
        const std::string record_name = imported_record_base(slot.type_override);
        auto record = annotations->imported_records.find(record_name);
        if (record == annotations->imported_records.end() ||
            offset < slot.offset) continue;
        const i64 within = offset - slot.offset;
        if (within < 0 || within >= static_cast<i64>(record->second.size)) continue;
        if (auto field = imported_field_expression_typed(
                record->second, within, access_type); field) {
            return std::format("{}.{}", slot.name, *field);
        }
    }
    return std::nullopt;
}

std::optional<std::string>
Emitter::imported_global_pointer_field(const IrValue& base, i64 off,
                                       std::optional<IrType> access_type) const {
    if (!annotations || !binary || off < 0) return std::nullopt;
    const Symbol* slot = global_object_for_load(base);
    if (!slot) return std::nullopt;
    const std::string* global_type = annotations->global_type_for(slot->addr);
    if (!global_type) {
        auto by_name = annotations->imported_global_types_by_name.find(slot->name);
        if (by_name != annotations->imported_global_types_by_name.end()) {
            global_type = &by_name->second;
        }
    }
    if (!global_type || global_type->find('*') == std::string::npos) {
        return std::nullopt;
    }
    const std::string record_name = imported_record_base(*global_type);
    auto record = annotations->imported_records.find(record_name);
    if (record == annotations->imported_records.end()) return std::nullopt;
    auto field = access_type
        ? imported_field_expression_typed(record->second, off, *access_type)
        : imported_field_expression(record->second, off);
    if (!field) return std::nullopt;
    note_global_decl(*slot, *global_type);
    return std::format("{}->{}", global_display_name(*slot),
                       *field);
}

std::optional<std::string>
Emitter::imported_global_object_field(const IrValue& base, i64 off,
                                      std::optional<IrType> access_type) const {
    if (!annotations || !binary || off < 0) return std::nullopt;
    auto resolved = try_resolve_imm_addr(base);
    if (!resolved) return std::nullopt;
    const addr_t address = normalized_address(*resolved);
    const Symbol* object = binary->defined_object_at(address);
    if (!object || object->kind != SymbolKind::Object || object->name.empty() ||
        address < object->addr) {
        return std::nullopt;
    }
    const std::string* global_type = annotations->global_type_for(object->addr);
    if (!global_type) {
        auto by_name = annotations->imported_global_types_by_name.find(object->name);
        if (by_name != annotations->imported_global_types_by_name.end()) {
            global_type = &by_name->second;
        }
    }
    if (!global_type || global_type->find('*') != std::string::npos) {
        return std::nullopt;
    }
    const std::string record_name = imported_record_base(*global_type);
    auto record = annotations->imported_records.find(record_name);
    if (record == annotations->imported_records.end()) return std::nullopt;
    const i64 field_offset = static_cast<i64>(address - object->addr) + off;
    auto field = access_type
        ? imported_field_expression_typed(
              record->second, field_offset, *access_type)
        : imported_field_expression(record->second, field_offset);
    if (!field) return std::nullopt;
    note_global_decl(*object, *global_type);
    return std::format("{}.{}", global_display_name(*object),
                       *field);
}

std::optional<std::string>
Emitter::imported_call_result_field(const IrValue& base, i64 off, int depth,
                                    std::optional<IrType> access_type) const {
    if (!annotations || !fn || off < 0) return std::nullopt;
    auto key = ssa_key(base);
    if (!key) return std::nullopt;
    const auto position = ssa_uses.definition_position(*key);
    if (!position || position->first >= fn->blocks.size()) {
        return std::nullopt;
    }
    const auto& block = fn->blocks[position->first];
    std::optional<addr_t> target;
    for (std::size_t i = position->second; i > 0;) {
        const IrInst& previous = block.insts[--i];
        if (previous.op == IrOp::Clobber || previous.op == IrOp::Nop) continue;
        if (previous.op == IrOp::Call) target = previous.target1;
        break;
    }
    if (!target) return std::nullopt;
    const FunctionSig* signature = annotations->signature_for(*target);
    if (!signature || signature->return_type.find('*') == std::string::npos) {
        return std::nullopt;
    }
    const std::string record_name = imported_record_base(signature->return_type);
    auto record = annotations->imported_records.find(record_name);
    if (record == annotations->imported_records.end()) return std::nullopt;
    auto field = access_type
        ? imported_field_expression_typed(record->second, off, *access_type)
        : imported_field_expression(record->second, off);
    if (!field) return std::nullopt;
    return std::format("{}->{}",
        expr(base, depth + 1, std::to_underlying(Prec::Postfix)),
        *field);
}

std::optional<std::string>
Emitter::imported_typed_pointer_field(const IrValue& base, i64 off, int depth,
                                      std::optional<IrType> access_type) const {
    if (!annotations || off < 0) return std::nullopt;
    std::string type = c_type_name_for(base);
    if (!type.ends_with('*')) {
        const IrInst* load = def_stripped(base);
        if (load && load->op == IrOp::Load && load->src_count >= 1) {
            if (auto access = canonical_struct_access(load->srcs[0]); access) {
                if (auto synthetic = synthetic_member_type(
                        access->first, access->second); synthetic) {
                    type = *synthetic;
                }
            }
        }
    }
    if (!type.ends_with('*')) return std::nullopt;
    const std::string record_name = imported_record_base(type);
    auto record = annotations->imported_records.find(record_name);
    if (record == annotations->imported_records.end()) return std::nullopt;
    auto field = access_type
        ? imported_field_expression_typed(record->second, off, *access_type)
        : imported_field_expression(record->second, off);
    if (!field) return std::nullopt;
    return std::format("{}->{}",
        expr(base, depth + 1, std::to_underlying(Prec::Postfix)), *field);
}

std::optional<std::string>
Emitter::imported_enum_value(const IrValue& value, std::string type) const {
    if (!annotations) return std::nullopt;
    const std::string enum_name = imported_record_base(std::move(type));
    auto enum_it = annotations->imported_enums.find(enum_name);
    if (enum_it == annotations->imported_enums.end()) return std::nullopt;
    auto raw = resolve_imm(value);
    if (!raw) return std::nullopt;
    auto value_it = enum_it->second.find(*raw);
    if (value_it == enum_it->second.end()) return std::nullopt;
    return value_it->second;
}

}  // namespace ember::emit
