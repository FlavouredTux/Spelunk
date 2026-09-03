// Function-name inference from string references: assertion, reflection,
// logging and engine-feature anchors that name their enclosing function.

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <format>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <ember/analysis/cfg_builder.hpp>
#include <ember/analysis/pipeline.hpp>
#include <ember/analysis/strings.hpp>
#include <ember/binary/binary.hpp>
#include <ember/binary/section.hpp>
#include <ember/binary/symbol.hpp>
#include <ember/common/timing.hpp>
#include <ember/common/types.hpp>
#include <ember/disasm/decoder.hpp>
#include <ember/ir/abi.hpp>
#include <ember/ir/ir.hpp>
#include <ember/ir/lifter.hpp>
#include <ember/ir/passes.hpp>
#include <ember/ir/ssa.hpp>

#include "string_names_internal.hpp"
#include "strings_internal.hpp"

namespace ember::string_names {

namespace {

[[nodiscard]] std::optional<std::size_t>
function_name_arg_index(std::string_view callee) noexcept {
    // glibc: __assert_fail(assertion, file, line, function)
    if (callee == "__assert_fail") return 3;
    // Darwin libc: __assert_rtn(function, file, line, expression)
    if (callee == "__assert_rtn") return 0;
    return std::nullopt;
}

[[nodiscard]] bool has_function_name_assert_import(const Binary& b) {
    for (const auto& sym : b.symbols()) {
        if (!sym.is_import) continue;
        if (function_name_arg_index(strip_import_name_decorations(sym.name))) return true;
    }
    return false;
}

[[nodiscard]] std::string read_cstring_local(const Binary& b, addr_t va) {
    auto bytes = b.bytes_at(va);
    std::string s;
    for (auto by : bytes) {
        const auto c = static_cast<unsigned char>(by);
        if (c == 0) break;
        if (!is_string_byte(c)) return {};
        s.push_back(static_cast<char>(c));
        if (s.size() > kMaxStringLen) return {};
    }
    return s.size() >= kMinStringLen ? s : std::string{};
}

[[nodiscard]] std::optional<u64>
read_u64_from_section(const Section& sec, std::size_t off) noexcept {
    if (off + 8 > sec.data.size()) return std::nullopt;
    const auto* p = reinterpret_cast<const unsigned char*>(sec.data.data() + off);
    u64 v = 0;
    for (unsigned i = 0; i < 8; ++i) v |= static_cast<u64>(p[i]) << (i * 8);
    return v;
}

[[nodiscard]] bool contains_executable_byte(const Binary& b, addr_t va) noexcept {
    for (const auto& sec : b.sections()) {
        if (!sec.flags.executable || sec.data.empty()) continue;
        if (va >= sec.vaddr && va < sec.vaddr + sec.data.size()) return true;
    }
    return false;
}

[[nodiscard]] bool looks_like_lua_reg_key(std::string_view s) noexcept {
    if (s.empty() || s.size() > 80) return false;
    bool useful = false;
    for (char c : s) {
        const auto u = static_cast<unsigned char>(c);
        if (std::isalpha(u) || c == '_') useful = true;
        if (!(std::isalnum(u) || c == '_' || c == '.' || c == ':')) {
            return false;
        }
    }
    return useful;
}

[[nodiscard]] std::string lua_cfunc_name(std::string_view key) {
    return sanitize_name(std::string{"lua_cfunc_"} + std::string{key});
}

void infer_lua_registration_names(const Binary& b,
                                  std::span<const StringEntry> strings,
                                  std::vector<StringNameCandidate>& out,
                                  std::set<std::pair<addr_t, std::string>>& seen) {
    if (strings.empty()) return;

    std::map<addr_t, std::string_view> strings_by_addr;
    for (const auto& s : strings) {
        if (looks_like_lua_reg_key(s.text)) {
            strings_by_addr.emplace(s.addr, std::string_view{s.text});
        }
    }
    if (strings_by_addr.empty()) return;

    struct RegEntry {
        std::string_view key;
        addr_t           fn = 0;
    };

    for (const auto& sec : b.sections()) {
        if (sec.data.size() < 32) continue;
        if (!sec.flags.readable || sec.flags.executable) continue;

        const std::size_t align_skip =
            static_cast<std::size_t>((8 - (sec.vaddr & 7)) & 7);
        for (std::size_t off = align_skip; off + 16 <= sec.data.size(); off += 8) {
            std::vector<RegEntry> entries;
            bool terminated = false;
            std::size_t pos = off;
            for (; pos + 16 <= sec.data.size() && entries.size() < 256; pos += 16) {
                const auto name_va = read_u64_from_section(sec, pos);
                const auto fn_va = read_u64_from_section(sec, pos + 8);
                if (!name_va || !fn_va) break;
                if (*name_va == 0 && *fn_va == 0) {
                    terminated = true;
                    break;
                }
                if (*name_va == 0 || *fn_va == 0) break;
                const auto str_it = strings_by_addr.find(static_cast<addr_t>(*name_va));
                if (str_it == strings_by_addr.end()) break;
                const addr_t fn = static_cast<addr_t>(*fn_va);
                if (!contains_executable_byte(b, fn)) break;
                if (b.import_at_plt(fn) != nullptr) break;
                entries.push_back({str_it->second, fn});
            }
            if (!terminated || entries.empty()) continue;

            for (const auto& e : entries) {
                auto name = lua_cfunc_name(e.key);
                if (name.empty()) continue;
                if (seen.emplace(e.fn, name).second) {
                    out.push_back({e.fn, std::move(name),
                                   std::string{"luaL_Reg:"} + std::string{e.key}});
                }
            }
            off = pos;
        }
    }
}

template <class EnclosingFunction>
void infer_reflection_member_names(
    std::span<const StringEntry> strings,
    EnclosingFunction enclosing_function,
    std::vector<StringNameCandidate>& out,
    std::set<std::pair<addr_t, std::string>>& seen) {
    struct DescriptorRef {
        const StringEntry* entry = nullptr;
        addr_t             xref = 0;
        ReflectionDescriptorNameParts parts;
    };
    struct MemberRef {
        const StringEntry* entry = nullptr;
        addr_t             xref = 0;
    };
    struct FunctionRefs {
        std::vector<DescriptorRef> descriptors;
        std::vector<MemberRef>     members;
    };

    std::map<addr_t, FunctionRefs> by_function;
    for (const auto& s : strings) {
        if (s.xrefs.empty()) continue;
        const auto parts = parse_reflection_descriptor_name_parts(s.text);
        const bool member = !parts && looks_like_reflection_member_name(s.text);
        if (!parts && !member) continue;

        for (addr_t xr : s.xrefs) {
            if (auto fn = enclosing_function(xr)) {
                auto& refs = by_function[*fn];
                if (parts) {
                    refs.descriptors.push_back({&s, xr, *parts});
                } else {
                    refs.members.push_back({&s, xr});
                }
            }
        }
    }

    for (auto& [fn, refs] : by_function) {
        if (refs.descriptors.empty() || refs.members.empty()) continue;
        std::sort(refs.members.begin(), refs.members.end(),
                  [](const MemberRef& a, const MemberRef& b) {
                      if (a.xref != b.xref) return a.xref < b.xref;
                      return a.entry->text.size() < b.entry->text.size();
                  });

        for (const auto& desc_ref : refs.descriptors) {
            if (!desc_ref.entry) continue;

            const StringEntry* best = nullptr;
            addr_t best_dist = std::numeric_limits<addr_t>::max();
            bool best_precedes_descriptor = false;
            const addr_t lo = desc_ref.xref > 256 ? desc_ref.xref - 256 : 0;
            const addr_t hi = desc_ref.xref + 256;
            auto it = std::lower_bound(
                refs.members.begin(), refs.members.end(), lo,
                [](const MemberRef& ref, addr_t needle) { return ref.xref < needle; });
            for (; it != refs.members.end() && it->xref <= hi; ++it) {
                const auto& candidate_ref = *it;
                if (!candidate_ref.entry) continue;
                const addr_t dist = candidate_ref.xref > desc_ref.xref
                    ? candidate_ref.xref - desc_ref.xref
                    : desc_ref.xref - candidate_ref.xref;
                const bool precedes_descriptor = candidate_ref.xref <= desc_ref.xref;
                if (best && precedes_descriptor != best_precedes_descriptor) {
                    if (!precedes_descriptor) continue;
                    best = candidate_ref.entry;
                    best_dist = dist;
                    best_precedes_descriptor = true;
                    continue;
                }
                if (dist < best_dist ||
                    (dist == best_dist && best &&
                     candidate_ref.entry->text.size() < best->text.size())) {
                    best = candidate_ref.entry;
                    best_dist = dist;
                    best_precedes_descriptor = precedes_descriptor;
                } else if (dist == best_dist && !best) {
                    best = candidate_ref.entry;
                    best_precedes_descriptor = precedes_descriptor;
                }
            }

            if (!best) continue;
            auto name = reflection_descriptor_candidate_name(
                desc_ref.parts, std::string_view{best->text});
            if (!name || name->empty()) continue;
            if (seen.emplace(fn, *name).second) {
                out.push_back({
                    fn,
                    std::move(*name),
                    std::format("reflection member {} near {}",
                                best->text, desc_ref.entry->text),
                });
            }
        }
    }
}

template <class EnclosingFunction>
void infer_role_identifier_anchors(
    std::span<const StringEntry> strings,
    EnclosingFunction enclosing_function,
    std::vector<StringNameCandidate>& out,
    std::set<std::pair<addr_t, std::string>>& seen) {
    std::map<std::string, std::set<addr_t>> functions_by_anchor;
    for (const auto& s : strings) {
        if (s.xrefs.empty()) continue;
        auto name = role_identifier_anchor_name(s.text);
        if (!name) continue;
        auto& functions = functions_by_anchor[*name];
        for (addr_t xr : s.xrefs) {
            if (auto fn = enclosing_function(xr)) functions.insert(*fn);
        }
    }

    std::map<addr_t, std::string> anchor_by_function;
    std::set<addr_t> ambiguous_functions;
    for (const auto& [name, functions] : functions_by_anchor) {
        if (functions.size() != 1) continue;
        const addr_t fn = *functions.begin();
        if (ambiguous_functions.contains(fn)) continue;
        auto [it, inserted] = anchor_by_function.emplace(fn, name);
        if (!inserted && it->second != name) {
            anchor_by_function.erase(it);
            ambiguous_functions.insert(fn);
        }
    }

    for (const auto& [fn, name] : anchor_by_function) {
        if (ambiguous_functions.contains(fn)) continue;
        if (seen.emplace(fn, name).second) {
            out.push_back({fn, name, name.substr(std::string_view{"string_anchor_"}.size())});
        }
    }
}

[[nodiscard]] std::optional<std::string>
collapse_script_vm_anchor_family(const std::set<std::string>& names) {
    if (names.empty()) return std::nullopt;

    bool all_lua_apps = true;
    bool all_heap_profiler = true;
    bool all_bytecode = true;
    bool all_caps = true;
    for (const auto& name : names) {
        all_lua_apps &= name.starts_with("script_vm_telemetry_lua_apps_") ||
                        name == "script_vm_telemetry_lua_shell_errors";
        all_heap_profiler &= name.find("heap_profiler") != std::string::npos;
        all_bytecode &= name.starts_with("script_vm_bytecode_");
        all_caps &= name.starts_with("script_vm_telemetry_caps_");
    }

    if (all_lua_apps) return std::string{"script_vm_telemetry_lua_apps_metrics"};
    if (all_heap_profiler) return std::string{"script_vm_telemetry_heap_profiler"};
    if (all_bytecode) return std::string{"script_vm_bytecode_metrics"};
    if (all_caps) return std::string{"script_vm_telemetry_caps_use"};
    return std::nullopt;
}

template <class EnclosingFunction>
void infer_script_vm_metadata_anchors(
    std::span<const StringEntry> strings,
    EnclosingFunction enclosing_function,
    std::vector<StringNameCandidate>& out,
    std::set<std::pair<addr_t, std::string>>& seen) {
    struct AnchorRefs {
        std::set<addr_t> functions;
        std::string      source;
    };

    std::map<std::string, AnchorRefs> refs_by_name;
    for (const auto& s : strings) {
        if (s.xrefs.empty()) continue;
        auto name = script_vm_anchor_name_from_string(s.text);
        if (!name) continue;
        auto& refs = refs_by_name[*name];
        if (refs.source.empty()) refs.source = s.text;
        for (addr_t xr : s.xrefs) {
            if (auto fn = enclosing_function(xr)) refs.functions.insert(*fn);
        }
    }

    std::map<addr_t, std::set<std::string>> names_by_function;
    std::map<std::string, std::string> source_by_name;
    for (const auto& [name, refs] : refs_by_name) {
        if (refs.functions.size() != 1) continue;
        const addr_t fn = *refs.functions.begin();
        names_by_function[fn].insert(name);
        source_by_name.emplace(name, refs.source);
    }

    for (const auto& [fn, names] : names_by_function) {
        std::string name;
        std::string source;
        if (names.size() == 1) {
            name = *names.begin();
            source = source_by_name[name];
        } else if (auto collapsed = collapse_script_vm_anchor_family(names)) {
            name = *collapsed;
            source = std::format("{} ScriptVM anchors", names.size());
        } else {
            continue;
        }
        if (seen.emplace(fn, name).second) {
            out.push_back({fn, std::move(name), std::move(source)});
        }
    }
}

template <class EnclosingFunction>
void infer_engine_feature_anchors(
    std::span<const StringEntry> strings,
    EnclosingFunction enclosing_function,
    const std::map<addr_t, std::size_t>& function_sizes,
    std::vector<StringNameCandidate>& out,
    std::set<std::pair<addr_t, std::string>>& seen) {
    std::map<std::string, std::set<addr_t>> functions_by_anchor;
    std::map<std::string, std::string> source_by_name;
    for (const auto& s : strings) {
        if (s.xrefs.empty()) continue;
        auto name = engine_feature_anchor_name(s.text);
        if (!name) continue;
        auto& functions = functions_by_anchor[*name];
        source_by_name.emplace(*name, s.text);
        for (addr_t xr : s.xrefs) {
            if (auto fn = enclosing_function(xr)) functions.insert(*fn);
        }
    }

    std::map<addr_t, std::string> anchor_by_function;
    std::set<addr_t> ambiguous_functions;
    for (const auto& [name, functions] : functions_by_anchor) {
        std::set<addr_t> candidates = functions;
        if (candidates.size() > 1) {
            std::erase_if(candidates, [&](addr_t fn) {
                const auto it = function_sizes.find(fn);
                return it != function_sizes.end() && it->second > 512;
            });
        }
        if (candidates.size() != 1) continue;
        const addr_t fn = *candidates.begin();
        if (ambiguous_functions.contains(fn)) continue;
        auto [it, inserted] = anchor_by_function.emplace(fn, name);
        if (!inserted && it->second != name) {
            anchor_by_function.erase(it);
            ambiguous_functions.insert(fn);
        }
    }

    for (const auto& [fn, name] : anchor_by_function) {
        if (ambiguous_functions.contains(fn)) continue;
        auto source_it = source_by_name.find(name);
        const std::string source =
            source_it == source_by_name.end() ? name : source_it->second;
        if (seen.emplace(fn, name).second) {
            out.push_back({fn, name, source});
        }
    }
}

[[nodiscard]] std::map<SsaKey, const IrInst*>
index_defs(const IrFunction& fn) {
    std::map<SsaKey, const IrInst*> out;
    for (const auto& bb : fn.blocks) {
        for (const auto& inst : bb.insts) {
            if (auto k = ssa_key(inst.dst)) out.emplace(*k, &inst);
        }
    }
    return out;
}

[[nodiscard]] std::optional<std::string>
resolve_string_value(const Binary& b,
                     const std::map<SsaKey, const IrInst*>& defs,
                     IrValue v,
                     int depth = 0) {
    if (depth > 10) return std::nullopt;
    for (int hop = 0; hop < 10; ++hop) {
        if (v.kind == IrValueKind::Imm) {
            auto s = read_cstring_local(b, static_cast<addr_t>(v.imm));
            if (!s.empty()) return s;
            return std::nullopt;
        }
        auto k = ssa_key(v);
        if (!k) return std::nullopt;
        auto it = defs.find(*k);
        if (it == defs.end()) return std::nullopt;
        const IrInst* d = it->second;
        if ((d->op == IrOp::Assign || d->op == IrOp::ZExt ||
             d->op == IrOp::SExt || d->op == IrOp::Trunc) &&
            d->src_count == 1) {
            v = d->srcs[0];
            continue;
        }
        return std::nullopt;
    }
    return std::nullopt;
}

void infer_assertion_function_names(const Binary& b,
                                    std::span<const DiscoveredFunction> fns,
                                    std::vector<StringNameCandidate>& out,
                                    std::set<std::pair<addr_t, std::string>>& seen) {
    if (!has_function_name_assert_import(b)) return;

    auto dec_r = make_decoder(b);
    if (!dec_r) return;
    auto lifter_r = make_lifter(b);
    if (!lifter_r) return;

    const Decoder& dec = **dec_r;
    const CfgBuilder builder(b, dec);
    const SsaBuilder ssa;

    for (const auto& fn : fns) {
        if (fn.size == 0 || b.import_at_plt(fn.addr) != nullptr) continue;
        auto cfg_r = builder.build(fn.addr, fn.name);
        if (!cfg_r) continue;
        auto ir_r = (*lifter_r)->lift(*cfg_r);
        if (!ir_r) continue;
        if (auto rv = ssa.convert(*ir_r); !rv) continue;
        if (auto rv = run_cleanup(*ir_r); !rv) continue;

        const auto defs = index_defs(*ir_r);
        for (const auto& bb : ir_r->blocks) {
            std::vector<IrValue> args;
            args.reserve(kMaxAbiIntArgs);
            for (const auto& inst : bb.insts) {
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
                if (inst.op != IrOp::Call) continue;
                const Symbol* s = b.import_at_plt(inst.target1);
                if (!s) {
                    args.clear();
                    continue;
                }
                auto idx = function_name_arg_index(
                    strip_import_name_decorations(s->name));
                if (!idx || *idx >= args.size()) {
                    args.clear();
                    continue;
                }
                auto raw = resolve_string_value(b, defs, args[*idx]);
                if (!raw) {
                    args.clear();
                    continue;
                }
                auto name = sanitize_name(*raw);
                if (!name.empty() && seen.emplace(fn.addr, name).second) {
                    out.push_back({fn.addr, std::move(name), *raw});
                }
                args.clear();
            }
        }
    }
}

}  // namespace

}  // namespace ember::string_names

namespace ember {

using namespace string_names;

std::vector<StringNameCandidate>
infer_function_names_from_strings(const Binary &b, StringNameInferenceOptions options) {
    ScopedTimer timer("strings.infer_names");
    std::vector<StringNameCandidate> out;
    std::set<std::pair<addr_t, std::string>> seen;
    std::vector<DiscoveredFunction> fns;
    {
        ScopedTimer phase("strings.enumerate_functions");
        fns = enumerate_functions(b, EnumerateMode::Cheap);
    }
    std::map<addr_t, std::size_t> function_sizes;
    for (const auto& fn : fns) function_sizes.emplace(fn.addr, fn.size);
    auto is_executable_section_addr = [&](addr_t addr) {
        for (const auto& sec : b.sections()) {
            if (!sec.flags.executable || sec.data.empty()) continue;
            if (addr < sec.vaddr) continue;
            const auto off = addr - sec.vaddr;
            if (off < sec.data.size()) return true;
        }
        return false;
    };
    auto enclosing_function = [&](addr_t addr) -> std::optional<addr_t> {
        auto it =
            std::upper_bound(fns.begin(), fns.end(), addr,
                             [](addr_t a, const DiscoveredFunction &d) { return a < d.addr; });
        if (it == fns.begin())
            return std::nullopt;
        --it;
        if (it->size != 0 && addr >= it->addr + it->size)
            return std::nullopt;
        if (it->size == 0) {
            auto next = it;
            ++next;
            if (next != fns.end() && addr >= next->addr)
                return std::nullopt;
        }
        if (!is_executable_section_addr(addr))
            return std::nullopt;
        if (b.bytes_at(it->addr).empty())
            return std::nullopt;
        return it->addr;
    };
    auto script_vm_enclosing_function = [&](addr_t addr) -> std::optional<addr_t> {
        constexpr std::size_t kMaxAnchorFunctionSize = 1u << 20;
        auto fn = enclosing_function(addr);
        if (!fn) return std::nullopt;
        const auto it = function_sizes.find(*fn);
        if (it != function_sizes.end() &&
            it->second > kMaxAnchorFunctionSize) {
            return std::nullopt;
        }
        return fn;
    };
    std::vector<StringEntry> strings;
    {
        ScopedTimer phase("strings.scan");
        strings = scan_strings_impl(b, {}, fns, true);
    }
    {
        ScopedTimer phase("strings.graphics_proc_loader");
        struct ProcVotes {
            std::set<std::string> gl;
            std::set<std::string> vk;
        };
        std::map<addr_t, ProcVotes> proc_votes;
        for (const auto &s : strings) {
            if (!s.xrefs.empty() && is_graphics_api_ident(s.text)) {
                for (addr_t xr : s.xrefs) {
                    if (auto fn = enclosing_function(xr)) {
                        auto &votes = proc_votes[*fn];
                        if (s.text.starts_with("gl"))
                            votes.gl.insert(s.text);
                        else if (s.text.starts_with("vk"))
                            votes.vk.insert(s.text);
                    }
                }
            }
        }
        for (const auto &[fn, votes] : proc_votes) {
            if (votes.gl.size() >= 12 && seen.emplace(fn, "graphics_gl_proc_loader").second) {
                out.push_back({fn, "graphics_gl_proc_loader",
                               std::format("{} OpenGL proc names", votes.gl.size())});
            } else if (votes.vk.size() >= 8 && seen.emplace(fn, "graphics_vk_proc_loader").second) {
                out.push_back({fn, "graphics_vk_proc_loader",
                               std::format("{} Vulkan proc names", votes.vk.size())});
            }
        }
    }
    {
        ScopedTimer phase("strings.lua_registration");
        infer_lua_registration_names(b, strings, out, seen);
    }
    {
        ScopedTimer phase("strings.reflection_members");
        infer_reflection_member_names(strings, enclosing_function, out, seen);
    }
    {
        ScopedTimer phase("strings.generic_candidates");
        for (const auto &s : strings) {
            if (s.xrefs.empty())
                continue;
            auto name = candidate_name_from_string(s.text);
            if (!name || name->empty())
                continue;
            std::set<addr_t> referencing_fns;
            for (addr_t xr : s.xrefs) {
                if (auto fn = enclosing_function(xr))
                    referencing_fns.insert(*fn);
            }
            for (addr_t fn : referencing_fns) {
                if (seen.emplace(fn, *name).second) {
                    out.push_back({fn, *name, s.text});
                }
            }
        }
    }
    if (options.assertion_names &&
        (options.max_assertion_functions == 0 || fns.size() <= options.max_assertion_functions)) {
        ScopedTimer phase("strings.assertion_names");
        infer_assertion_function_names(b, fns, out, seen);
    }
    {
        ScopedTimer phase("strings.script_metadata_anchors");
        infer_script_vm_metadata_anchors(strings, script_vm_enclosing_function, out, seen);
    }
    {
        ScopedTimer phase("strings.engine_feature_anchors");
        infer_engine_feature_anchors(strings, script_vm_enclosing_function,
                                     function_sizes, out, seen);
    }
    {
        ScopedTimer phase("strings.role_identifier_anchors");
        infer_role_identifier_anchors(strings, enclosing_function, out, seen);
    }
    return out;
}

}  // namespace ember
