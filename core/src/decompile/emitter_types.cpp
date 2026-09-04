// C type naming and synthetic struct recovery.
#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <format>
#include <map>
#include <optional>
#include <regex>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <ember/binary/symbol.hpp>
#include <ember/common/types.hpp>
#include <ember/ir/abi.hpp>
#include <ember/ir/ir.hpp>
#include <ember/ir/ssa.hpp>
#include <ember/ir/types.hpp>

#include "emitter_internal.hpp"
#include "emitter_tables.hpp"

namespace ember::emit {

std::string Emitter::normalize_c_type_alias(std::string_view t) {
    auto map_base = [](std::string_view base) -> std::string_view {
        if (base == "u8")  return "uint8_t";
        if (base == "u16") return "uint16_t";
        if (base == "u32") return "uint32_t";
        if (base == "u64") return "uint64_t";
        if (base == "s8" || base == "i8")   return "int8_t";
        if (base == "s16" || base == "i16") return "int16_t";
        if (base == "s32" || base == "i32") return "int32_t";
        if (base == "s64" || base == "i64") return "int64_t";
        if (base == "f32") return "float";
        if (base == "f64") return "double";
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

std::optional<std::string_view>
Emitter::standard_global_type(std::string_view name) noexcept {
    if (name == "stdin" || name == "stdout" || name == "stderr") {
        return "FILE*";
    }
    return std::nullopt;
}

std::string Emitter::global_display_name(const Symbol& symbol) const {
    if (annotations) {
        auto preferred = annotations->preferred_global_names.find(symbol.addr);
        if (preferred != annotations->preferred_global_names.end() &&
            !preferred->second.empty()) return preferred->second;
    }
    return symbol.name;
}

void Emitter::note_global_decl(const Symbol& s, std::string type_name) const {
    if (s.name.empty()) return;
    const std::string display_name = global_display_name(s);
    if (annotations) {
        if (const std::string* imported = annotations->global_type_for(s.addr))
            type_name = *imported;
        else if (auto by_name = annotations->imported_global_types_by_name.find(s.name);
                 by_name != annotations->imported_global_types_by_name.end())
            type_name = by_name->second;
    }
    type_name = normalize_c_type_alias(type_name);
    if (type_name.find("(*") == std::string::npos &&
        !type_name.ends_with("[]")) {
        if (auto standard = standard_global_type(display_name); standard) {
            type_name = *standard;
        }
    }
    auto [it, inserted] = global_decls.emplace(display_name, type_name);
    if (inserted || it->second == type_name) return;

    const bool old_funcptr = it->second.find("(*") != std::string::npos;
    const bool new_funcptr = type_name.find("(*") != std::string::npos;
    if (old_funcptr) return;
    if (new_funcptr) {
        it->second = std::move(type_name);
        return;
    }

    // A load from a pointer-valued global still has the ABI integer
    // width in IR.  Once downstream memory use proves the loaded value
    // is a pointer, keep that stronger declaration instead of resolving
    // the scalar/pointer disagreement to an unrelated uint64_t.
    const bool old_pointer = it->second.ends_with('*');
    const bool new_pointer = type_name.ends_with('*');
    if (old_pointer) return;
    if (new_pointer) {
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

std::string Emitter::ipa_type_name(TypeRef r) const {
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

std::optional<std::string>
Emitter::pointer_type_from_memory_uses(const IrValue& value) const {
    if (abi != Abi::Ppc32Sysv && abi != Abi::Ppc64ElfV1Be &&
        abi != Abi::Ppc64ElfV2Le) {
        return std::nullopt;
    }
    auto root = ssa_key(value);
    if (!root || !fn) return std::nullopt;
    if (auto access = canonical_struct_access(value); access) {
        if (auto key = ssa_key(access->first); key) {
            if (auto it = struct_type_names.find(*key);
                it != struct_type_names.end()) {
                return it->second + "*";
            }
        }
    }

    std::set<SsaKey> seen;
    std::set<IrType> pointees;
    bool has_field_offset = false;
    const auto visit = [&](auto&& self, const SsaKey& key, int depth) -> void {
        if (depth > 12 || !seen.insert(key).second) return;
        for (const auto& [bi, ii] :
             ssa_uses.visible_user_positions(key)) {
            if (bi >= fn->blocks.size() || ii >= fn->blocks[bi].insts.size()) {
                continue;
            }
            const IrInst& user = fn->blocks[bi].insts[ii];
            if ((user.op == IrOp::Load || user.op == IrOp::Store) &&
                user.src_count >= 1 && ssa_key(user.srcs[0]) == key) {
                const IrType pointee = user.op == IrOp::Load
                    ? user.dst.type
                    : (user.src_count >= 2 ? user.srcs[1].type : IrType::I8);
                pointees.insert(pointee);
                continue;
            }

            bool forwards_address = false;
            if (user.op == IrOp::Assign && user.src_count == 1 &&
                ssa_key(user.srcs[0]) == key) {
                forwards_address = true;
            } else if ((user.op == IrOp::Add || user.op == IrOp::Sub) &&
                       user.src_count == 2) {
                const auto lhs = ssa_key(user.srcs[0]);
                const auto rhs = ssa_key(user.srcs[1]);
                forwards_address =
                    (lhs && *lhs == key && user.srcs[1].kind == IrValueKind::Imm) ||
                    (user.op == IrOp::Add && rhs && *rhs == key &&
                     user.srcs[0].kind == IrValueKind::Imm);
                if (forwards_address) {
                    const IrValue& offset = lhs && *lhs == key
                        ? user.srcs[1] : user.srcs[0];
                    has_field_offset |= offset.imm != 0;
                }
            }
            if (forwards_address) {
                if (auto dst = ssa_key(user.dst); dst) self(self, *dst, depth + 1);
            }
        }
    };
    visit(visit, *root, 0);
    if (pointees.empty()) return std::nullopt;
    if (has_field_offset || pointees.size() != 1) return std::string("void*");
    return std::format("{}*", c_type_name(*pointees.begin()));
}

std::string Emitter::c_type_name_for(const IrValue& v) const {
    if (!fn) return std::string(c_type_name(v.type));
    if (auto access = canonical_struct_access(v); access) {
        if (auto key = ssa_key(access->first); key) {
            if (auto it = struct_type_names.find(*key);
                it != struct_type_names.end()) {
                return it->second + "*";
            }
        }
    }
    const TypeRef t = fn->type_of(v);
    if (!t.is_top()) {
        const auto& node = fn->types.node(t);
        // PPC floating-point registers are transport containers as well as
        // numeric values.  A conservative ABI seed can therefore leave a
        // genuinely floating IR value with an integer lattice type.  The
        // explicit IR opcode/type is stronger evidence for presentation:
        // do not turn an F32/F64/V2F32 phi web into an integer local.
        if (is_float_type(v.type) && node.kind == TypeKind::Int) {
            return std::string(c_type_name(v.type));
        }
        if (node.kind == TypeKind::Ptr) {
            if (const IrInst* definition = def_stripped(v); definition) {
                switch (definition->op) {
                    case IrOp::Mul:
                    case IrOp::And:
                    case IrOp::Or:
                    case IrOp::Xor:
                    case IrOp::Shl:
                    case IrOp::Lshr:
                    case IrOp::Ashr:
                        return std::string(c_type_name(v.type));
                    default:
                        break;
                }
            }
            const auto& pn = fn->types.node(node.p.pointee);
            if (pn.kind == TypeKind::Int) {
                if (pn.i.bits == 8) return "char*";
                return std::format("uint{}_t*", pn.i.bits);
            }
            return "void*";
        }
    }
    if (auto pointer = pointer_type_from_memory_uses(v); pointer) {
        return *pointer;
    }
    if (t.is_top()) return std::string(c_type_name(v.type));
    const auto& node = fn->types.node(t);
    switch (node.kind) {
        case TypeKind::Int:
            if (node.i.sign_known && node.i.is_signed) {
                return std::format("int{}_t", node.i.bits);
            }
            return std::string(c_type_name(v.type));
        default:
            return std::string(c_type_name(v.type));
    }
}

addr_t Emitter::normalized_address(i64 value) const noexcept {
    if (abi == Abi::Ppc32Sysv) {
        return static_cast<addr_t>(static_cast<u32>(value));
    }
    return static_cast<addr_t>(value);
}

void Emitter::assign_synthetic_struct_types() {
    if (!is_ppc_abi() || !fn) return;
    std::map<addr_t, std::string> call_type_names;
    std::map<std::string, u32> type_name_counts;
    const auto claim_type_name = [&](std::string base) {
        u32& count = type_name_counts[base];
        ++count;
        return count == 1 ? base : std::format("{}{}", base, count);
    };

    const auto call_target_for_root = [&](const SsaKey& key)
        -> std::optional<addr_t> {
        const auto position = ssa_uses.definition_position(key);
        if (!position) return std::nullopt;
        const auto [bi, definition_index] = *position;
        if (bi >= fn->blocks.size()) return std::nullopt;
        const auto& bb = fn->blocks[bi];
        std::size_t ii = definition_index;
        while (ii > 0) {
            --ii;
            const IrInst& previous = bb.insts[ii];
            if (previous.op == IrOp::Clobber || previous.op == IrOp::Nop) {
                continue;
            }
            if (previous.op == IrOp::Call) return previous.target1;
            if (previous.op == IrOp::CallIndirect &&
                options.call_resolutions && previous.source_addr != 0) {
                if (auto it = options.call_resolutions->find(previous.source_addr);
                    it != options.call_resolutions->end()) {
                    return it->second;
                }
            }
            break;
        }
        return std::nullopt;
    };

    for (const auto& [key, offsets] : struct_offsets) {
        if (offsets.size() < 2) continue;
        std::string name;
        if (auto target = call_target_for_root(key); target) {
            auto [it, inserted] = call_type_names.emplace(*target, std::string{});
            if (inserted) it->second = claim_type_name("PpcObject");
            name = it->second;
            inferred_call_return_types.insert_or_assign(*target, name + "*");
        } else {
            std::string base = "PpcState";
            if (auto root_it = struct_root_values.find(key);
                root_it != struct_root_values.end()) {
                const IrInst* root_def = def_stripped(root_it->second);
                if (root_def && root_def->op == IrOp::Load &&
                    root_def->src_count >= 1) {
                    base = try_resolve_imm_addr(root_def->srcs[0])
                        ? "PpcGlobalState"
                        : "PpcObject";
                }
            }
            name = claim_type_name(std::move(base));
        }
        struct_type_names.emplace(key, name);
        if (auto members = struct_access_types.find(key);
            members != struct_access_types.end()) {
            auto& merged = struct_type_members[name];
            for (const auto& [offset, types] : members->second) {
                merged[offset].insert(types.begin(), types.end());
            }
        }
    }

    // The memory access itself only carries the storage width. Refine a
    // member to T* when the loaded word is subsequently used as a memory
    // base. This keeps the synthetic declaration and its expressions
    // coherent (`state->buffer[0]`, not an integer `word_fc[0]`).
    for (const auto& bb : fn->blocks) {
        for (const IrInst& inst : bb.insts) {
            const bool load = inst.op == IrOp::Load && inst.src_count >= 1;
            const bool store = inst.op == IrOp::Store && inst.src_count >= 2;
            if (!load && !store) continue;
            const IrValue& address = inst.srcs[0];
            const IrValue& member_value = load ? inst.dst : inst.srcs[1];
            auto access = canonical_struct_access(address);
            if (!access) continue;
            auto key = ssa_key(access->first);
            if (!key) continue;
            auto type_it = struct_type_names.find(*key);
            if (type_it == struct_type_names.end()) continue;
            const std::string refined = c_type_name_for(member_value);
            if (!refined.ends_with('*')) continue;
            auto& member = struct_member_type_names[type_it->second][access->second];
            if (member.empty() || member == "void*") {
                member = refined;
            } else if (member != refined && refined != "void*") {
                member = "void*";
            }
        }
    }
}

void Emitter::refine_synthetic_member_types_from_stores() {
    if (!fn || !is_ppc_abi()) return;
    for (const auto& block : fn->blocks) {
        for (const IrInst& store : block.insts) {
            if (store.op != IrOp::Store || store.src_count < 2) continue;
            auto access = canonical_struct_access(store.srcs[0]);
            if (!access) continue;
            auto key = ssa_key(access->first);
            if (!key) continue;
            auto owner = struct_type_names.find(*key);
            if (owner == struct_type_names.end()) continue;
            std::string refined = c_type_name_for(store.srcs[1]);
            if (!refined.ends_with('*')) continue;
            auto& member = struct_member_type_names[owner->second][access->second];
            const std::string refined_base = imported_record_base(refined);
            const bool imported = annotations &&
                annotations->imported_records.contains(refined_base);
            if (member.empty() || member == "void*" || imported) {
                member = std::move(refined);
            }
        }
    }
}

std::optional<std::string>
Emitter::synthetic_member_type(const IrValue& base, i64 offset) const {
    auto access = canonical_struct_access(base);
    if (!access) return std::nullopt;
    auto key = ssa_key(access->first);
    if (!key) return std::nullopt;
    auto name_it = struct_type_names.find(*key);
    if (name_it == struct_type_names.end()) return std::nullopt;
    auto struct_it = struct_member_type_names.find(name_it->second);
    if (struct_it == struct_member_type_names.end()) return std::nullopt;
    auto member_it = struct_it->second.find(offset);
    if (member_it == struct_it->second.end()) return std::nullopt;
    return member_it->second;
}

std::string
Emitter::synthetic_member_name(std::string_view struct_name, i64 offset,
                               IrType storage_type) const {
    auto struct_it = struct_member_type_names.find(std::string(struct_name));
    if (struct_it != struct_member_type_names.end()) {
        auto member_it = struct_it->second.find(offset);
        if (member_it != struct_it->second.end() &&
            member_it->second.ends_with('*')) {
            const std::string_view prefix =
                member_it->second.starts_with("PpcObject")
                ? "object" : "data";
            return std::format("{}_{:x}", prefix,
                               static_cast<u64>(offset));
        }
    }
    return fallback_field_name(offset, storage_type);
}

std::string
Emitter::synthetic_member_name(const IrValue& base, i64 offset,
                               IrType storage_type) const {
    auto access = canonical_struct_access(base);
    if (!access) return fallback_field_name(offset, storage_type);
    auto key = ssa_key(access->first);
    if (!key) return fallback_field_name(offset, storage_type);
    auto name_it = struct_type_names.find(*key);
    if (name_it == struct_type_names.end()) {
        return fallback_field_name(offset, storage_type);
    }
    return synthetic_member_name(name_it->second, offset, storage_type);
}

std::string
Emitter::synthetic_struct_declarations(std::string_view rendered_function) const {
    std::string out;
    if (!ppc_navigation_tables.empty()) {
        out += "typedef struct PpcNavigationEntry {\n"
               "  uint8_t neighbor_0;\n"
               "  uint8_t neighbor_1;\n"
               "  uint8_t neighbor_2;\n"
               "  uint8_t neighbor_3;\n"
               "  uint32_t (*callback)(struct PpcNavigationEntry*, ...);\n"
               "} PpcNavigationEntry;\n\n";
    }
    for (const auto& [_, table] : ppc_strided_tables) {
        out += std::format("typedef struct {} {{\n", table.type_name);
        std::size_t cursor = 0;
        for (const auto& [offset, type] : table.fields) {
            if (offset < 0 || static_cast<std::size_t>(offset) < cursor) continue;
            if (static_cast<std::size_t>(offset) > cursor) {
                out += std::format("  uint8_t _pad_{:x}[{}];\n", cursor,
                    static_cast<std::size_t>(offset) - cursor);
            }
            const std::string field = std::format("{}_{}",
                is_float_type(type) ? "float" : "word",
                offset == 0 ? std::string("0") : std::format("{:x}", offset));
            out += std::format("  {} {};\n", c_type_name(type), field);
            cursor = static_cast<std::size_t>(offset) +
                std::max<unsigned>(1, type_bits(type) / 8);
        }
        if (cursor < table.stride) {
            out += std::format("  uint8_t _pad_{:x}[{}];\n", cursor,
                               table.stride - cursor);
        }
        out += std::format("}} {};\n\n", table.type_name);
    }
    const std::string rendered(rendered_function);
    std::map<std::string, std::string> pointer_local_types;
    const std::regex pointer_local(
        R"(\b([A-Za-z_][A-Za-z0-9_]*)\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*=)");
    for (std::sregex_iterator it(rendered.begin(), rendered.end(), pointer_local), end;
         it != end; ++it) {
        pointer_local_types.try_emplace((*it)[2].str(), (*it)[1].str() + "*");
    }
    std::set<std::string> used_names;
    for (const auto& [name, members] : struct_type_members) {
        bool used = text_contains_identifier(rendered_function, name);
        if (!used) {
            for (const auto& [_, type] : global_decls) {
                if (text_contains_identifier(type, name)) {
                    used = true;
                    break;
                }
            }
        }
        if (used && !members.empty()) used_names.insert(name);
    }

    // A nested type may appear only as a member of a directly rendered
    // parent. Pull those dependencies into the declaration set until the
    // graph closes, otherwise `parent->object_0->field` would reference an
    // incomplete synthetic type that was never emitted.
    bool added_dependency = true;
    while (added_dependency) {
        added_dependency = false;
        for (const auto& [owner, members] : struct_member_type_names) {
            if (!used_names.contains(owner)) continue;
            for (const auto& [_, member_type] : members) {
                for (const auto& [candidate, candidate_members] :
                     struct_type_members) {
                    if (candidate_members.empty() ||
                        used_names.contains(candidate)) continue;
                    if (text_contains_identifier(member_type, candidate)) {
                        used_names.insert(candidate);
                        added_dependency = true;
                    }
                }
            }
        }
    }

    bool needs_forward_declarations = false;
    for (const auto& [owner, members] : struct_member_type_names) {
        if (!used_names.contains(owner)) continue;
        for (const auto& [_, member_type] : members) {
            for (const std::string& candidate : used_names) {
                if (text_contains_identifier(member_type, candidate)) {
                    needs_forward_declarations = true;
                    break;
                }
            }
            if (needs_forward_declarations) break;
        }
        if (needs_forward_declarations) break;
    }
    if (needs_forward_declarations) {
        for (const std::string& name : used_names) {
            out += std::format("typedef union {} {};\n", name, name);
        }
        out += "\n";
    }

    for (const auto& [name, members] : struct_type_members) {
        if (!used_names.contains(name)) continue;
        out += needs_forward_declarations
            ? std::format("union {} {{\n", name)
            : std::format("typedef union {} {{\n", name);
        std::set<std::string> emitted_fields;
        for (const auto& [offset, types] : members) {
            if (offset < 0) continue;
            for (IrType type : types) {
                const std::string field =
                    synthetic_member_name(name, offset, type);
                if (!emitted_fields.insert(field).second) continue;
                out += "  struct { ";
                if (offset > 0) {
                    out += std::format("uint8_t _pad_{}[{}]; ",
                                       field, offset);
                }
                std::string member_type = std::string(c_type_name(type));
                if (auto struct_it = struct_member_type_names.find(name);
                    struct_it != struct_member_type_names.end()) {
                    if (auto member_it = struct_it->second.find(offset);
                        member_it != struct_it->second.end()) {
                        member_type = member_it->second;
                    }
                }
                for (const auto& [variable, variable_type] : pointer_local_types) {
                    if (rendered.find(std::format("->{} = {};", field, variable)) !=
                        std::string::npos) {
                        member_type = variable_type;
                        break;
                    }
                }
                out += std::format("{} {}; }};\n", member_type, field);
            }
        }
        out += needs_forward_declarations
            ? "};\n\n"
            : std::format("}} {};\n\n", name);
    }

    // A pointer can acquire a synthetic type late (for example after an
    // indexed table walk) without contributing to struct_type_members.
    // Recover the visible fallback fields from the rendered text so the
    // resulting pseudo-C never references an undeclared PpcState family.
    const std::regex pointer_decl(
        R"(\b(Ppc(?:GlobalState|Object|State)[0-9]*)\s*\*\s*([A-Za-z_][A-Za-z0-9_]*))");
    std::map<std::string, std::map<i64, std::pair<std::string, std::string>>>
        fallback_members;
    const auto collect_fields = [&](const std::string& type_name,
                                    const std::string& variable) {
        if (used_names.contains(type_name)) return;
        const std::regex field_use(std::format(
            R"(\b{}->((byte|half|word|qword|float|double|data)_([0-9a-fA-F]+)))",
            variable));
        for (std::sregex_iterator field_it(
                 rendered.begin(), rendered.end(), field_use), end;
             field_it != end; ++field_it) {
            i64 offset = 0;
            const std::string raw_offset = (*field_it)[3].str();
            const auto parsed = std::from_chars(
                raw_offset.data(), raw_offset.data() + raw_offset.size(),
                offset, 16);
            if (parsed.ec != std::errc{}) continue;
            fallback_members[type_name].try_emplace(
                offset, (*field_it)[2].str(), (*field_it)[1].str());
        }
    };
    for (std::sregex_iterator it(rendered.begin(), rendered.end(), pointer_decl), end;
         it != end; ++it) {
        collect_fields((*it)[1].str(), (*it)[2].str());
    }
    for (const auto& [variable, local] : merge_locals) {
        std::string type_name = c_type_name_for(local.type_value);
        if (!type_name.ends_with('*')) continue;
        type_name = imported_record_base(std::move(type_name));
        if (!type_name.starts_with("PpcState") &&
            !type_name.starts_with("PpcObject") &&
            !type_name.starts_with("PpcGlobalState")) continue;
        collect_fields(type_name, variable);
    }
    for (const auto& [name, members] : fallback_members) {
        if (members.empty()) continue;
        out += std::format("typedef union {} {{\n", name);
        for (const auto& [offset, info] : members) {
            const auto& [prefix, field] = info;
            std::string_view type = "uint32_t";
            if (prefix == "byte") type = "uint8_t";
            else if (prefix == "half") type = "uint16_t";
            else if (prefix == "qword") type = "uint64_t";
            else if (prefix == "float") type = "float";
            else if (prefix == "double") type = "double";
            else if (prefix == "data") type = "void*";
            out += "  struct { ";
            if (offset > 0) {
                out += std::format("uint8_t _pad_{}[{}]; ", field, offset);
            }
            out += std::format("{} {}; }};\n", type, field);
        }
        out += std::format("}} {};\n\n", name);
    }
    return out;
}

std::string
Emitter::imported_record_declarations(std::string_view rendered_function) const {
    if (!annotations || annotations->imported_records.empty()) return {};
    std::string out;
    for (const auto& [alias, underlying_raw] : annotations->imported_aliases) {
        if (annotations->imported_records.contains(alias)) continue;
        bool alias_used = text_contains_identifier(rendered_function, alias);
        for (const auto& [_, slot] : frame_layout.slots) {
            alias_used |= imported_record_base(slot.type_override) == alias;
        }
        if (!alias_used) continue;
        std::string underlying = underlying_raw;
        const auto array = underlying.find('[');
        std::string suffix;
        if (array != std::string::npos) {
            suffix = underlying.substr(array);
            underlying.resize(array);
        }
        while (!underlying.empty() && std::isspace(
                   static_cast<unsigned char>(underlying.back()))) {
            underlying.pop_back();
        }
        underlying = normalize_c_type_alias(underlying);
        if (!suffix.empty()) {
            out += std::format("typedef {} {}{};\n", underlying, alias, suffix);
        }
    }
    if (!out.empty()) out += "\n";
    std::set<std::string> used;
    for (const auto& [name, _] : annotations->imported_records) {
        if (text_contains_identifier(rendered_function, name)) used.insert(name);
        if (used.contains(name)) continue;
        for (const auto& [_, type] : global_decls) {
            if (text_contains_identifier(type, name)) {
                used.insert(name);
                break;
            }
        }
    }
    for (const auto& [_, slot] : frame_layout.slots) {
        if (slot.type_override.empty()) continue;
        const std::string name = imported_record_base(slot.type_override);
        if (annotations->imported_records.contains(name)) used.insert(name);
    }
    for (const auto& [_, local] : merge_locals) {
        const std::string name = imported_record_base(
            c_type_name_for(local.type_value));
        if (annotations->imported_records.contains(name)) used.insert(name);
    }
    if (used.empty()) return out;

    const std::string rendered(rendered_function);
    std::map<std::string, std::map<i64, std::pair<std::string, std::string>>>
        fallback_fields;
    for (const std::string& name : used) {
        const std::regex pointer_decl(std::format(
            R"(\b{}\s*\*\s*([A-Za-z_][A-Za-z0-9_]*))", name));
        for (std::sregex_iterator it(
                 rendered.begin(), rendered.end(), pointer_decl), end;
             it != end; ++it) {
            const std::string variable = (*it)[1].str();
            const std::regex field_use(std::format(
                R"(\b{}->((byte|half|word|qword|float|double|data)_([0-9a-fA-F]+)))",
                variable));
            for (std::sregex_iterator field_it(
                     rendered.begin(), rendered.end(), field_use);
                 field_it != end; ++field_it) {
                i64 offset = 0;
                const std::string raw_offset = (*field_it)[3].str();
                const auto parsed = std::from_chars(
                    raw_offset.data(), raw_offset.data() + raw_offset.size(),
                    offset, 16);
                if (parsed.ec != std::errc{}) continue;
                fallback_fields[name].try_emplace(
                    offset, (*field_it)[2].str(), (*field_it)[1].str());
            }
        }
    }
    for (const auto& [variable, type] : global_decls) {
        const std::string name = imported_record_base(type);
        if (!used.contains(name) ||
            !annotations->imported_records.contains(name)) continue;
        const std::regex field_use(std::format(
            R"(\b{}->((byte|half|word|qword|float|double|data)_([0-9a-fA-F]+)))",
            variable));
        for (std::sregex_iterator field_it(
                 rendered.begin(), rendered.end(), field_use), end;
             field_it != end; ++field_it) {
            i64 offset = 0;
            const std::string raw_offset = (*field_it)[3].str();
            const auto parsed = std::from_chars(
                raw_offset.data(), raw_offset.data() + raw_offset.size(),
                offset, 16);
            if (parsed.ec != std::errc{}) continue;
            fallback_fields[name].try_emplace(
                offset, (*field_it)[2].str(), (*field_it)[1].str());
        }
    }

    const auto field_is_used = [&](std::string_view field) {
        return rendered_function.find(std::string("->") + std::string(field)) !=
                   std::string_view::npos ||
               rendered_function.find(std::string(".") + std::string(field)) !=
                   std::string_view::npos;
    };
    const auto normalize_field_base = [&](std::string type) {
        while (!type.empty() && std::isspace(
                   static_cast<unsigned char>(type.front()))) type.erase(type.begin());
        const auto array = type.find('[');
        if (array != std::string::npos) type.resize(array);
        while (!type.empty() && std::isspace(
                   static_cast<unsigned char>(type.back()))) type.pop_back();
        if (type.find("(*") != std::string::npos) return std::string("void*");
        if (type.ends_with('*')) {
            const std::string pointee = imported_record_base(type);
            if (annotations->imported_records.contains(pointee)) {
                return pointee + "*";
            }
            return type.find("char") != std::string::npos
                ? normalize_c_type_alias(type)
                : std::string("void*");
        }
        return normalize_c_type_alias(type);
    };
    const auto scalar_bytes = [](std::string_view type) -> std::size_t {
        if (type == "uint8_t" || type == "int8_t" || type == "char" ||
            type == "bool") return 1;
        if (type == "uint16_t" || type == "int16_t") return 2;
        if (type == "uint64_t" || type == "int64_t" || type == "double") return 8;
        if (type == "uint32_t" || type == "int32_t" || type == "float") return 4;
        return 0;
    };

    // Pull in by-value record dependencies for the fields that actually
    // appear. Pointer fields remain void*/char* and need no declaration.
    std::vector<std::string> worklist(used.begin(), used.end());
    while (!worklist.empty()) {
        const std::string name = std::move(worklist.back());
        worklist.pop_back();
        const auto& record = annotations->imported_records.at(name);
        for (const auto& [_, field] : record.fields) {
            if (!field_is_used(field.name)) continue;
            const std::string base = imported_record_base(field.type);
            if (!annotations->imported_records.contains(base)) continue;
            bool needs_definition = field.type.find('*') == std::string::npos;
            if (!needs_definition) {
                const auto& pointee = annotations->imported_records.at(base);
                needs_definition = std::ranges::any_of(
                    pointee.fields, [&](const auto& member) {
                        return field_is_used(member.second.name);
                    });
            }
            if (needs_definition && used.insert(base).second) {
                worklist.push_back(base);
            }
        }
    }

    std::vector<std::string> ordered;
    std::set<std::string> visiting;
    std::set<std::string> emitted;
    const auto visit = [&](const auto& self, const std::string& name) -> void {
        if (emitted.contains(name) || !visiting.insert(name).second) return;
        const auto& record = annotations->imported_records.at(name);
        for (const auto& [_, field] : record.fields) {
            if (!field_is_used(field.name) || field.type.find('*') != std::string::npos) {
                continue;
            }
            const std::string dependency = imported_record_base(field.type);
            if (used.contains(dependency) &&
                annotations->imported_records.contains(dependency)) {
                self(self, dependency);
            }
        }
        visiting.erase(name);
        emitted.insert(name);
        ordered.push_back(name);
    };
    for (const std::string& name : used) visit(visit, name);

    std::set<std::string> forward_only;
    for (const std::string& name : used) {
        const auto& record = annotations->imported_records.at(name);
        for (const auto& [_, field] : record.fields) {
            if (!field_is_used(field.name) || field.type.find('*') == std::string::npos) {
                continue;
            }
            const std::string dependency = imported_record_base(field.type);
            if (!used.contains(dependency) &&
                annotations->imported_records.contains(dependency)) {
                forward_only.insert(dependency);
            }
        }
    }
    for (const std::string& name : forward_only) {
        const auto& record = annotations->imported_records.at(name);
        out += std::format(
            "typedef union {} {{ uint8_t _storage[{}]; }} {};\n",
            name, std::max<std::size_t>(record.size, 1), name);
    }
    if (!forward_only.empty()) out += "\n";

    for (const std::string& name : ordered) {
        const auto& record = annotations->imported_records.at(name);
        out += std::format("typedef union {} {{\n", name);
        if (record.size != 0) {
            out += std::format("  uint8_t _storage[{}];\n", record.size);
            if (record.size == 1) out += "  uint8_t _raw;\n";
            else if (record.size == 2) out += "  uint16_t _raw;\n";
            else if (record.size == 4) out += "  uint32_t _raw;\n";
            else if (record.size == 8) out += "  uint64_t _raw;\n";
        }
        for (const auto& [offset, field] : record.fields) {
            if (!field_is_used(field.name)) continue;
            std::string type = normalize_field_base(field.type);
            std::string suffix;
            if (const auto array = field.type.find('['); array != std::string::npos) {
                const std::size_t element_size = scalar_bytes(type);
                const std::size_t count = element_size != 0
                    ? field.size / element_size : field.size;
                if (element_size == 0) type = "uint8_t";
                suffix = std::format("[{}]", std::max<std::size_t>(count, 1));
            } else if (!annotations->imported_records.contains(
                           imported_record_base(type)) &&
                       scalar_bytes(type) == 0 && type != "void*" &&
                       type != "const char*" && type != "char*") {
                if (annotations->imported_enums.contains(
                        imported_record_base(type))) type = "int32_t";
                else if (field.size == 1) type = "uint8_t";
                else if (field.size == 2) type = "uint16_t";
                else if (field.size == 8) type = "uint64_t";
                else type = "uint32_t";
            }
            out += "  struct { ";
            if (offset > 0) {
                out += std::format("uint8_t _pad_{}[{}]; ",
                                   field.name, offset);
            }
            out += std::format("{} {}{}; }};\n", type, field.name, suffix);
        }
        if (auto extra = fallback_fields.find(name);
            extra != fallback_fields.end()) {
            for (const auto& [offset, info] : extra->second) {
                const auto& [prefix, field] = info;
                if (auto imported = record.fields.find(offset);
                    imported != record.fields.end() &&
                    field_is_used(imported->second.name)) continue;
                std::string_view type = "uint32_t";
                if (prefix == "byte") type = "uint8_t";
                else if (prefix == "half") type = "uint16_t";
                else if (prefix == "qword") type = "uint64_t";
                else if (prefix == "float") type = "float";
                else if (prefix == "double") type = "double";
                else if (prefix == "data") type = "void*";
                out += "  struct { ";
                if (offset > 0) {
                    out += std::format("uint8_t _pad_{}[{}]; ", field, offset);
                }
                out += std::format("{} {}; }};\n", type, field);
            }
        }
        out += std::format("}} {};\n\n", name);
    }
    return out;
}

std::string Emitter::fallback_field_name(i64 off, IrType t) const {
    if (!is_ppc_abi()) return std::format("field_{:x}", static_cast<u64>(off));
    std::string_view prefix = "field";
    switch (t) {
        case IrType::I8:    prefix = "byte"; break;
        case IrType::I16:   prefix = "half"; break;
        case IrType::I32:   prefix = "word"; break;
        case IrType::I64:   prefix = "qword"; break;
        case IrType::F32:   prefix = "float"; break;
        case IrType::F64:   prefix = "double"; break;
        case IrType::V2F32: prefix = "pair"; break;
        default: break;
    }
    return std::format("{}_{:x}", prefix, static_cast<u64>(off));
}

bool Emitter::is_struct_pointer(const IrValue& base) const {
    auto access = canonical_struct_access(base);
    if (!access) return false;
    auto k = ssa_key(access->first);
    if (!k) return false;
    auto it = struct_offsets.find(*k);
    return it != struct_offsets.end() && it->second.size() >= 2;
}

bool Emitter::is_strong_struct_pointer(const IrValue& base) const {
    auto access = canonical_struct_access(base);
    if (!access) return false;
    auto k = ssa_key(access->first);
    if (!k || !is_struct_pointer(base)) return false;
    const auto wit = struct_access_widths.find(*k);
    if (wit == struct_access_widths.end()) return false;

    std::set<unsigned> widths;
    for (const auto& [off, ws] : wit->second) {
        (void)off;
        widths.insert(ws.begin(), ws.end());
    }
    if (widths.size() >= 2) return true;

    bool has_integer = false;
    bool has_float = false;
    if (const auto tit = struct_access_types.find(*k);
        tit != struct_access_types.end()) {
        for (const auto& [off, types] : tit->second) {
            (void)off;
            for (IrType type : types) {
                has_float |= is_float_type(type);
                has_integer |= !is_float_type(type);
            }
        }
    }
    if (has_integer && has_float) return true;

    const auto oit = struct_offsets.find(*k);
    if (oit == struct_offsets.end() || oit->second.size() < 2) return false;
    if (widths.size() != 1 || *widths.begin() == 0) return false;

    const i64 stride = static_cast<i64>(*widths.begin());
    std::optional<i64> previous;
    for (i64 off : oit->second) {
        if (off < 0 || (off % stride) != 0) return true;
        if (previous && off - *previous != stride) return true;
        previous = off;
    }
    return false;
}

const std::string*
Emitter::annotated_field_name(const IrValue& base, i64 off) const {
    if (!annotations || !fn) return nullptr;
    auto slot = trace_to_self_arg_slot(base);
    if (!slot) return nullptr;
    return annotations->field_name_for(fn->start, *slot, off);
}

}  // namespace ember::emit
