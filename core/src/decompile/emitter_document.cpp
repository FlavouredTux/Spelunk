#include "emitter_document.hpp"

#include <cctype>
#include <cstddef>
#include <format>
#include <functional>
#include <map>
#include <optional>
#include <regex>
#include <set>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include <spelunk/binary/binary.hpp>
#include <spelunk/binary/symbol.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/ir/ssa.hpp>
#include <spelunk/structure/region.hpp>

#include "emitter_internal.hpp"
#include "emitter_text.hpp"
#include "emitter_tables.hpp"

namespace spelunk::emit {

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
[[nodiscard]] std::map<u32, FallbackMaterialization>
fallback_materializations(const Emitter& e, const std::string& body) {
    std::map<u32, FallbackMaterialization> out;
    // The old per-definition identifier query rescanned the complete body
    // for every SSA temporary. Mask comments/literals once and index tokens
    // before asking which definitions need a fallback declaration.
    const std::string code = code_only_text(body);
    std::unordered_set<std::string_view> identifiers;
    for (std::size_t pos = 0; pos < code.size();) {
        if (!c_ident_char(code[pos])) {
            ++pos;
            continue;
        }
        const std::size_t begin = pos;
        do { ++pos; } while (pos < code.size() && c_ident_char(code[pos]));
        identifiers.insert(std::string_view(code).substr(begin, pos - begin));
    }
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
    e.ssa_uses.for_each_definition([&](const SsaKey&, const IrInst* definition) {
        if (!definition || definition->dst.kind != IrValueKind::Temp) return;
        const std::string name = std::format("t{}", definition->dst.temp);
        if (!identifiers.contains(std::string_view(name)) ||
            text_declares_identifier(body, name)) return;
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
    });
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
        if (e.binary) {
            if (const auto* symbol = e.binary->find_by_name(function)) {
                const auto signature = e.binary->debug_signatures().find(symbol->addr);
                if (signature != e.binary->debug_signatures().end()) {
                    std::string params;
                    for (const auto& parameter : signature->second.params) {
                        if (!params.empty()) params += ", ";
                        params += parameter.type;
                    }
                    if (signature->second.variadic) params += params.empty() ? "..." : ", ...";
                    else if (params.empty()) params = "void";
                    out += std::format("extern {} {}({});\n", signature->second.return_type, function, params);
                    continue;
                }
            }
        }
        out += std::format("extern void {}(void);\n", function);
    }
    if (!e.address_taken_function_decls.empty()) out += "\n";
    bool have_globals = false;
    for (const auto& [name, ty] : e.global_decls) {
        // Inlining a read-only constant can remove the last use of a global
        // collected during analysis, including compiler-local dotted names.
        if (!text_contains_identifier(declaration_context, name)) continue;
        have_globals = true;
        if (ty.find("(*") != std::string::npos) {
            out += std::format("extern {};\n", ty);
        } else if (auto bracket = ty.find('['); bracket != std::string::npos && ty.ends_with(']')) {
            out += std::format("extern {} {}{};\n",
                               std::string_view(ty).substr(0, bracket), name,
                               std::string_view(ty).substr(bracket));
        } else {
            out += std::format("extern {} {};\n", ty, name);
        }
    }
    if (have_globals) out += "\n";
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
        const auto byte_storage =
            e.stack_byte_storage_ranges.find(slot.offset);
        if (byte_storage != e.stack_byte_storage_ranges.end() &&
            slot.type_override.empty()) {
            ty = "uint8_t";
            elem_size = 1;
            suffix = std::format("[{}]", byte_storage->second);
        }
        if (suffix.empty() && !matrix_locals.contains(slot.name) &&
            slot.type_override.empty()) {
            if (auto required = e.stack_required_extents.find(slot.offset);
                required != e.stack_required_extents.end() &&
                required->second > elem_size) {
                ty = charp ? "char" : "uint8_t";
                elem_size = 1;
                suffix = std::format("[{}]", required->second);
            }
        }
        if (!e.options.c_source && suffix.empty() && !matrix_locals.contains(slot.name) &&
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
strip_dead_declarations(const Emitter& emitter, const std::string& out,
                        const std::string& header) {
    // Call-result bindings carry an effectful initializer. If the result name
    // becomes dead after rendering, keep the initializer as a bare statement
    // instead of deleting the call along with its unused result.
    std::set<std::string> call_binding_names;
    for (const auto& [_, name] : emitter.call_return_names) {
        call_binding_names.insert(name);
    }

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
                if (call_binding_names.contains(name)) {
                    const std::size_t equals = lines[li].find('=');
                    if (equals != std::string::npos) {
                        const std::size_t indent_end =
                            lines[li].find_first_not_of(' ');
                        std::string statement = indent_end == std::string::npos
                            ? std::string{}
                            : lines[li].substr(0, indent_end);
                        statement += trim_line_view(
                            std::string_view(lines[li]).substr(equals + 1));
                        kept.push_back(std::move(statement));
                        continue;
                    }
                }
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

}  // namespace spelunk::emit
