// Call graph, callees, callers and containing-function lookup.

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <format>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include <ember/analysis/cfg_builder.hpp>
#include <ember/analysis/discovery.hpp>
#include <ember/analysis/pipeline.hpp>
#include <ember/analysis/rtti.hpp>
#include <ember/binary/arch.hpp>
#include <ember/binary/binary.hpp>
#include <ember/binary/format.hpp>
#include <ember/binary/symbol.hpp>
#include <ember/common/progress.hpp>
#include <ember/common/threads.hpp>
#include <ember/common/timing.hpp>
#include <ember/common/types.hpp>
#include <ember/disasm/decoder.hpp>
#include <ember/disasm/instruction.hpp>
#include <ember/disasm/register.hpp>
#include <ember/ir/ssa.hpp>

#include "pipeline_internal.hpp"

namespace ember::pipeline {

namespace {

// True when `target` is the entry of a defined function or a PLT stub -
// the same predicate the CFG builder uses to convert a `jmp` into a
// TailCall block. Duplicated here so the pipeline doesn't need to expose
// CFG-builder internals.
[[nodiscard]] bool callee_is_function_entry(const Binary& b, addr_t target) noexcept {
    if (const Symbol* s = b.defined_object_at(target);
        s && s->kind == SymbolKind::Function && s->addr == target) {
        return true;
    }
    if (b.import_at_plt(target) != nullptr) return true;
    return false;
}

[[nodiscard]] bool addr_in_executable_section(const Binary& b, addr_t a) noexcept {
    for (const auto& s : b.sections()) {
        if (!s.flags.executable) continue;
        if (a >= s.vaddr && a < s.vaddr + s.size) return true;
    }
    return false;
}

[[nodiscard]] std::optional<u64> read_u64_le(const Binary& b, addr_t a) noexcept {
    auto span = b.bytes_at(a);
    if (span.size() < 8) return std::nullopt;
    u64 v = 0;
    std::memcpy(&v, span.data(), 8);
    return v;
}

}  // namespace

}  // namespace ember::pipeline

namespace ember {

using namespace pipeline;

std::vector<CallEdge> compute_call_graph(const Binary& b,
                                         std::span<const addr_t> scope,
                                         CallGraphMode mode) {
    ScopedTimer total_timer("call_graph.total");
    auto dec_r = make_decoder(b);
    if (!dec_r) return {};
    const Decoder& dec = **dec_r;

    // Pre-collect work items so worker threads can binary-walk an
    // index instead of skipping over imports / data symbols.
    struct WorkItem {
        addr_t      addr;
        u64         size;
        std::string name;
    };
    // Always union named symbols with discovered functions. Earlier this
    // gated the discovery walk on `work.empty()`, which only fires on a
    // *fully* stripped binary - anything keeping even one named function
    // (partial strips are common: GNU `strip` leaves dynsym entries; some
    // distros retain a single anchor symbol) would skip discovery and the
    // call graph would contain edges from that handful of named functions
    // only. Symbols are pushed first so the symbol name wins on address
    // collisions with the `sub_<hex>` discovery name. Cheap mode avoids
    // recursing back into compute_call_graph.
    std::vector<WorkItem> work;
    work.reserve(b.symbols().size());
    std::unordered_set<addr_t> seen;
    const std::unordered_set<addr_t> scope_set(scope.begin(), scope.end());
    auto in_scope = [&](addr_t a) noexcept {
        return scope_set.empty() || scope_set.contains(a);
    };
    std::size_t raw_function_symbols = 0;
    for (const auto& s : b.symbols()) {
        if (s.is_import) continue;
        if (s.kind != SymbolKind::Function) continue;
        if (s.addr == 0 || s.name.empty()) continue;
        ++raw_function_symbols;
    }
    const bool distrust_huge_symbol_table =
        mode == CallGraphMode::Fast &&
        raw_function_symbols >= 100000;
    {
        ScopedTimer t("call_graph.worklist");
        for (const auto& s : b.symbols()) {
            if (s.is_import) continue;
            if (s.kind != SymbolKind::Function) continue;
            if (s.size == 0 || s.name.empty()) continue;
            if (distrust_huge_symbol_table) continue;
            if (!in_scope(s.addr)) continue;
            if (!seen.insert(s.addr).second) continue;
            work.push_back({s.addr, s.size, s.name});
        }
        if (distrust_huge_symbol_table && scope.empty()) {
            for (addr_t a : discover_from_prologues(b)) {
                if (b.import_at_plt(a)) continue;
                if (!seen.insert(a).second) continue;
                work.push_back({a, 0, std::format("sub_{:x}", a)});
            }
        } else {
            for (const auto& fn : enumerate_functions(b, EnumerateMode::Cheap)) {
                if (b.import_at_plt(fn.addr)) continue;
                if (!in_scope(fn.addr)) continue;
                if (!seen.insert(fn.addr).second) continue;
                work.push_back({fn.addr, fn.size, fn.name});
            }
        }
        std::ranges::sort(work, {}, [](const WorkItem& w) { return w.addr; });
        for (std::size_t i = 0; i < work.size(); ++i) {
            auto& w = work[i];
            addr_t section_end = 0;
            for (const auto& s : b.sections()) {
                if (!s.flags.executable) continue;
                if (w.addr < s.vaddr) continue;
                if (w.addr - s.vaddr < s.size) {
                    section_end = s.vaddr + s.size;
                    break;
                }
            }
            addr_t next_entry = section_end;
            for (std::size_t j = i + 1; j < work.size(); ++j) {
                if (section_end != 0 && work[j].addr >= section_end) break;
                if (work[j].addr > w.addr) {
                    next_entry = work[j].addr;
                    break;
                }
            }
            if (next_entry > w.addr) {
                const u64 gap = next_entry - w.addr;
                if (w.size == 0 || w.size > gap) w.size = gap;
            }
        }
    }
    if (work.empty()) return {};

    // CfgBuilder caches per-function unwind ranges in a mutable map
    // and isn't thread-safe; give each worker its own. The Binary +
    // Decoder are read-only and shared.
    const std::size_t total = work.size();
    // Cap at 8: local timings on a 104MB Blender binary showed no win
    // from 16 workers (the CFG walk stayed ~4.35s), while higher caps
    // risk oversubscribing cascades with many ember processes. EMBER_THREADS
    // can still lower this when many passes run concurrently.
    const std::size_t worker_count =
        std::min<std::size_t>(static_cast<std::size_t>(thread_pool_size(8)), total);
    if (timing_enabled()) {
        std::fprintf(stderr, "[timing] call_graph.functions: %zu\n", total);
        std::fprintf(stderr, "[timing] call_graph.threads: %zu\n", worker_count);
    }
    std::unordered_set<addr_t> known_entries;
    known_entries.reserve(work.size());
    for (const auto& w : work) known_entries.insert(w.addr);

    const bool force_cfg_call_graph = mode == CallGraphMode::FullCfg ||
        b.arch() != Arch::X86_64 || [] {
        const char* s = std::getenv("EMBER_CFG_CALL_GRAPH");
        return s != nullptr && *s != '\0' && *s != '0';
    }();

    auto scan_fast = [&](const WorkItem& w, std::vector<CallEdge>& sink) {
        auto span = b.bytes_at(w.addr);
        if (span.empty()) return;
        const std::size_t limit = w.size != 0
            ? std::min<std::size_t>(span.size(), static_cast<std::size_t>(w.size))
            : span.size();
        addr_t ip = w.addr;
        std::size_t off = 0;
        std::unordered_set<addr_t> seen_targets;
        while (off < limit) {
            if (b.is_data_in_code(ip)) {
                ++ip;
                ++off;
                continue;
            }
            auto remaining = span.subspan(off, limit - off);
            auto decoded = dec.decode(remaining, ip);
            if (!decoded) {
                const std::size_t skip = decode_failure_advance(b.arch(), remaining);
                ip += skip;
                off += skip;
                continue;
            }
            const Instruction& insn = *decoded;
            if (is_call(insn.mnemonic)) {
                if (auto target = branch_target(insn); target) {
                    if (seen_targets.insert(*target).second) {
                        sink.push_back({w.addr, *target});
                    }
                }
            } else if (is_unconditional_jmp(insn.mnemonic)) {
                if (auto target = branch_target(insn); target) {
                    if (known_entries.contains(*target) ||
                        b.import_at_plt(*target) != nullptr) {
                        if (seen_targets.insert(*target).second) {
                            sink.push_back({w.addr, *target});
                        }
                    }
                }
            }
            ip  += insn.length;
            off += insn.length;
        }
    };

    if (worker_count <= 1) {
        // Fall back to the simple serial loop. Avoids the thread-spawn
        // overhead on small binaries where it dominates.
        std::vector<CallEdge> out;
        const CfgBuilder builder(b, dec);
        const bool show = total >= 500 && progress_enabled();
        const auto tick = std::max<std::size_t>(1, total / 20);
        std::size_t done = 0;
        {
            ScopedTimer walk_timer(force_cfg_call_graph
                ? "call_graph.cfg_walk"
                : "call_graph.fast_scan");
            for (const auto& w : work) {
                if (force_cfg_call_graph) {
                    auto fn_r = builder.build(w.addr, w.name);
                    if (fn_r) {
                        for (auto target : fn_r->call_targets) out.push_back({w.addr, target});
                    }
                } else {
                    scan_fast(w, out);
                }
                ++done;
                if (show && (done % tick == 0 || done == total)) {
                    std::fprintf(stderr, "\r  call graph: [%zu/%zu]", done, total);
                    std::fflush(stderr);
                }
            }
        }
        if (show) std::fputc('\n', stderr);
        return out;
    }

    // Parallel worker pool - each worker pops indices from a shared
    // atomic counter and accumulates edges into its own buffer. The
    // CfgBuilder is per-thread because it lazily caches unwind ranges
    // in a map that isn't safe to populate concurrently.
    std::atomic<std::size_t> next{0};
    std::atomic<std::size_t> done{0};
    std::vector<std::vector<CallEdge>> per_thread(worker_count);

    const bool show = total >= 500 && progress_enabled();
    std::mutex log_mu;     // serialize the carriage-return progress line
    const auto tick = std::max<std::size_t>(1, total / 20);

    auto worker = [&](std::size_t idx) {
        CfgBuilder builder(b, dec);
        auto& sink = per_thread[idx];
        sink.reserve(total / worker_count + 16);
        while (true) {
            const std::size_t i = next.fetch_add(1, std::memory_order_relaxed);
            if (i >= total) break;
            const auto& w = work[i];
            if (force_cfg_call_graph) {
                auto fn_r = builder.build(w.addr, w.name);
                if (fn_r) {
                    for (auto t : fn_r->call_targets) sink.push_back({w.addr, t});
                }
            } else {
                scan_fast(w, sink);
            }
            const std::size_t d = done.fetch_add(1, std::memory_order_relaxed) + 1;
            if (show && (d % tick == 0 || d == total)) {
                std::lock_guard lk(log_mu);
                std::fprintf(stderr, "\r  call graph: [%zu/%zu]", d, total);
                std::fflush(stderr);
            }
        }
    };

    {
        ScopedTimer walk_timer(force_cfg_call_graph
            ? "call_graph.cfg_walk"
            : "call_graph.fast_scan");
        std::vector<std::thread> threads;
        threads.reserve(worker_count);
        for (std::size_t i = 0; i < worker_count; ++i) {
            threads.emplace_back(worker, i);
        }
        for (auto& thread : threads) thread.join();
    }
    if (show) std::fputc('\n', stderr);

    // Merge per-thread buffers into the output. Order isn't observable
    // by callers - every consumer sorts/dedupes - so a simple
    // concatenation works.
    std::vector<CallEdge> out;
    {
        ScopedTimer t("call_graph.merge");
        std::size_t total_edges = 0;
        for (const auto& v : per_thread) total_edges += v.size();
        out.reserve(total_edges);
        for (auto& v : per_thread) {
            out.insert(out.end(),
                       std::make_move_iterator(v.begin()),
                       std::make_move_iterator(v.end()));
        }
    }
    return out;
}

std::vector<addr_t> compute_callees(const Binary& b, addr_t fn) {
    auto dec_r = make_decoder(b);
    if (!dec_r) return {};
    const Decoder& dec = **dec_r;
    const CfgBuilder builder(b, dec);
    std::string name;
    for (const auto& s : b.symbols()) {
        if (s.is_import) continue;
        if (s.addr == fn && !s.name.empty()) { name = s.name; break; }
    }
    auto fn_r = builder.build(fn, name);
    if (!fn_r) return {};
    std::vector<addr_t> out = fn_r->call_targets;
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

std::vector<addr_t> compute_callers(const Binary& b, addr_t fn) {
    std::vector<addr_t> out;
    for (const auto& edge : compute_call_graph(b)) {
        if (edge.callee == fn) out.push_back(edge.caller);
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

std::vector<ClassifiedCallee>
compute_classified_callees(const Binary& b, addr_t fn,
                           const std::unordered_set<addr_t>* known_entries) {
    auto dec_r = make_decoder(b);
    if (!dec_r) return {};
    const Decoder& dec = **dec_r;
    const CfgBuilder builder(b, dec);
    if (known_entries) {
        builder.seed_known_entries(*known_entries);
    }

    std::string name;
    for (const auto& s : b.symbols()) {
        if (s.is_import) continue;
        if (s.addr == fn && !s.name.empty()) { name = s.name; break; }
    }
    auto fn_r = builder.build(fn, name);
    if (!fn_r) return {};

    // Vtable index for the back-trace. Itanium ABI covers both Mach-O
    // and ELF C++ binaries; `parse_itanium_rtti` already walks
    // `__const`, `.data.rel.ro`, and `.rodata`. PE is MSVC-RTTI shaped
    // differently - handled elsewhere, not yet wired here.
    //
    // Key subtlety: `RttiClass::vtable` is the *typeinfo slot* (offset
    // 8 inside the vtable struct). The ABI-defined vptr - the value
    // stored in every object's head and the value the compiler loads
    // when emitting `lea reg, [rip + K]` - points at `methods[0]`,
    // which sits at `vtable + 8`. We index by the vptr value the code
    // actually sees, so `call [reg + slot*8]` resolves directly with
    // no adjustment at the call site.
    std::map<addr_t, const RttiClass*> vtable_index;
    std::vector<RttiClass> rtti;
    if (b.format() == Format::MachO || b.format() == Format::Elf) {
        rtti = parse_itanium_rtti(b);
        for (const auto& c : rtti) {
            if (c.vtable != 0 && !c.methods.empty()) {
                vtable_index.emplace(c.vtable + 8, &c);
            }
        }
    }

    std::vector<ClassifiedCallee> out;
    out.reserve(fn_r->call_targets.size());

    // Resolve a `mov dst, [base_reg + disp]` vtable slot load. If
    // `base_reg` currently holds a known vptr, the loaded value is
    // the IMP at that slot.
    auto resolve_vptr_slot =
        [&](addr_t vptr, i64 disp) -> std::optional<addr_t> {
        auto it = vtable_index.find(vptr);
        if (it == vtable_index.end()) return std::nullopt;
        if (disp < 0 || (disp & 7) != 0) return std::nullopt;
        const std::size_t slot = static_cast<std::size_t>(disp) / 8;
        if (slot >= it->second->methods.size()) return std::nullopt;
        const addr_t imp = it->second->methods[slot];
        if (imp == 0 || !addr_in_executable_section(b, imp)) return std::nullopt;
        return imp;
    };

    for (const auto& bb : fn_r->blocks) {
        // Per-block register state for the vtable back-trace. Two
        // strata:
        //   vptr: register holds a vptr value (points to methods[0]
        //         of a known vtable). Reached by `lea r, [rip+K]`,
        //         `mov r, [rip+K]` where *K is a vptr, or reg-copy.
        //   imp:  register holds the resolved IMP of some slot, e.g.
        //         after `mov r, [vptr_reg + slot*8]`.
        // Keyed by canonical 64-bit reg so sub-register writes to the
        // same family correctly invalidate.
        std::map<Reg, addr_t> reg_vptr;
        std::map<Reg, addr_t> reg_imp;
        auto disarm = [&](Reg canon) {
            reg_vptr.erase(canon);
            reg_imp.erase(canon);
        };

        for (const auto& insn : bb.instructions) {
            const Mnemonic mn = insn.mnemonic;

            // `lea dst, [rip + K]` - arm dst as carrying a vptr when
            // K is exactly a known vptr address.
            if (mn == Mnemonic::Lea && insn.num_operands == 2 &&
                insn.operands[0].kind == Operand::Kind::Register) {
                const Reg dst   = insn.operands[0].reg;
                const Reg dst_c = canonical_reg(dst);
                const auto& src = insn.operands[1];
                bool armed = false;
                if (reg_size(dst) == 8 &&
                    src.kind == Operand::Kind::Memory &&
                    src.mem.base == Reg::Rip &&
                    src.mem.index == Reg::None &&
                    src.mem.has_disp) {
                    const addr_t k = insn.address + insn.length +
                                     static_cast<addr_t>(src.mem.disp);
                    if (vtable_index.count(k)) {
                        disarm(dst_c);
                        reg_vptr[dst_c] = k;
                        armed = true;
                    }
                }
                if (!armed) disarm(dst_c);
                continue;
            }

            // `mov dst, <src>` - multiple cases. See disarm() fallback
            // at the bottom.
            if (mn == Mnemonic::Mov && insn.num_operands == 2 &&
                insn.operands[0].kind == Operand::Kind::Register) {
                const Reg dst   = insn.operands[0].reg;
                const Reg dst_c = canonical_reg(dst);
                const auto& src = insn.operands[1];
                bool armed = false;
                if (reg_size(dst) == 8) {
                    // mov dst, [rip + K] - *K might be a stored vptr.
                    if (src.kind == Operand::Kind::Memory &&
                        src.mem.base == Reg::Rip &&
                        src.mem.index == Reg::None &&
                        src.mem.has_disp) {
                        const addr_t k = insn.address + insn.length +
                                         static_cast<addr_t>(src.mem.disp);
                        if (auto v = read_u64_le(b, k); v) {
                            const auto stored = static_cast<addr_t>(*v);
                            if (vtable_index.count(stored)) {
                                disarm(dst_c);
                                reg_vptr[dst_c] = stored;
                                armed = true;
                            }
                        }
                    }
                    // mov dst, [reg + disp] - slot load from an armed
                    // vptr-carrying register. Resolves to an IMP.
                    else if (src.kind == Operand::Kind::Memory &&
                             src.mem.base != Reg::None &&
                             src.mem.base != Reg::Rip &&
                             src.mem.index == Reg::None &&
                             src.mem.has_disp) {
                        const Reg base_c = canonical_reg(src.mem.base);
                        if (auto it = reg_vptr.find(base_c);
                            it != reg_vptr.end()) {
                            if (auto imp = resolve_vptr_slot(it->second, src.mem.disp)) {
                                disarm(dst_c);
                                reg_imp[dst_c] = *imp;
                                armed = true;
                            }
                        }
                    }
                    // mov dst, src_reg - one-hop reg→reg copy of any
                    // currently-armed state.
                    else if (src.kind == Operand::Kind::Register) {
                        const Reg src_c = canonical_reg(src.reg);
                        if (auto it = reg_vptr.find(src_c); it != reg_vptr.end()) {
                            disarm(dst_c);
                            reg_vptr[dst_c] = it->second;
                            armed = true;
                        } else if (auto it2 = reg_imp.find(src_c); it2 != reg_imp.end()) {
                            disarm(dst_c);
                            reg_imp[dst_c] = it2->second;
                            armed = true;
                        }
                    }
                }
                if (!armed) disarm(dst_c);
                continue;
            }

            if (is_call(mn)) {
                if (insn.num_operands == 0) {
                    reg_vptr.clear();
                    reg_imp.clear();
                    continue;
                }
                const auto& op = insn.operands[0];
                if (op.kind == Operand::Kind::Relative) {
                    out.push_back({op.rel.target, CalleeKind::Direct, insn.address});
                } else if (op.kind == Operand::Kind::Memory &&
                           op.mem.base == Reg::Rip &&
                           op.mem.has_disp &&
                           op.mem.index == Reg::None) {
                    // call qword ptr [rip + disp]: dereference the slot
                    // and emit indirect_const if it points into code.
                    const addr_t slot = insn.address + insn.length +
                                        static_cast<addr_t>(op.mem.disp);
                    if (auto v = read_u64_le(b, slot); v) {
                        const auto target = static_cast<addr_t>(*v);
                        if (target != 0 && addr_in_executable_section(b, target)) {
                            out.push_back({target, CalleeKind::IndirectConst,
                                           insn.address});
                        }
                    }
                } else if (op.kind == Operand::Kind::Memory &&
                           op.mem.base != Reg::None &&
                           op.mem.base != Reg::Rip &&
                           op.mem.index == Reg::None &&
                           op.mem.has_disp) {
                    // call [reg + disp]: resolve through the most
                    // recent vtable-pointer load into the same canon
                    // register.
                    const Reg base_c = canonical_reg(op.mem.base);
                    if (auto it = reg_vptr.find(base_c); it != reg_vptr.end()) {
                        if (auto imp = resolve_vptr_slot(it->second, op.mem.disp)) {
                            out.push_back({*imp, CalleeKind::IndirectConst,
                                           insn.address});
                        }
                    }
                } else if (op.kind == Operand::Kind::Register) {
                    // call reg: if the register already carries a
                    // resolved IMP (from a prior `mov rax, [vptr+slot]`),
                    // emit the edge directly.
                    const Reg r_c = canonical_reg(op.reg);
                    if (auto it = reg_imp.find(r_c); it != reg_imp.end()) {
                        out.push_back({it->second, CalleeKind::IndirectConst,
                                       insn.address});
                    }
                }
                // Any call clobbers the SysV caller-save set. Clearing
                // everything is cheaper than enumerating that set and
                // costs nothing in precision.
                reg_vptr.clear();
                reg_imp.clear();
                continue;
            }

            if (is_unconditional_jmp(mn)) {
                if (auto t = branch_target(insn); t && callee_is_function_entry(b, *t)) {
                    out.push_back({*t, CalleeKind::Tail, insn.address});
                    continue;
                }
                // Tail-call through a resolved IMP: `jmp *rax` where
                // rax carries a known slot IMP. Same edge kind as a
                // tail-call to a known symbol entry.
                if (insn.num_operands == 1) {
                    const auto& jop = insn.operands[0];
                    if (jop.kind == Operand::Kind::Register) {
                        const Reg r_c = canonical_reg(jop.reg);
                        if (auto it = reg_imp.find(r_c); it != reg_imp.end()) {
                            out.push_back({it->second, CalleeKind::Tail,
                                           insn.address});
                        }
                    } else if (jop.kind == Operand::Kind::Memory &&
                               jop.mem.base != Reg::None &&
                               jop.mem.base != Reg::Rip &&
                               jop.mem.index == Reg::None &&
                               jop.mem.has_disp) {
                        const Reg base_c = canonical_reg(jop.mem.base);
                        if (auto it = reg_vptr.find(base_c); it != reg_vptr.end()) {
                            if (auto imp = resolve_vptr_slot(it->second, jop.mem.disp)) {
                                out.push_back({*imp, CalleeKind::Tail,
                                               insn.address});
                            }
                        }
                    }
                }
                continue;
            }

            // Any other instruction that writes a register first-
            // operand invalidates our tracked state for that canon reg.
            // Conservative: arithmetic, lea-without-vtable, pop, etc.
            // Memory-dst instructions leave register state untouched.
            if (insn.num_operands >= 1 &&
                insn.operands[0].kind == Operand::Kind::Register) {
                disarm(canonical_reg(insn.operands[0].reg));
            }
        }
    }

    std::sort(out.begin(), out.end(),
              [](const ClassifiedCallee& a, const ClassifiedCallee& bb) {
                  if (a.target != bb.target) return a.target < bb.target;
                  if (a.kind != bb.kind)
                      return static_cast<u8>(a.kind) < static_cast<u8>(bb.kind);
                  return a.site < bb.site;
              });
    out.erase(std::unique(out.begin(), out.end(),
                          [](const ClassifiedCallee& a, const ClassifiedCallee& bb) {
                              return a.target == bb.target && a.kind == bb.kind;
                          }),
              out.end());
    return out;
}

std::optional<ContainingFn>
containing_function(const Binary& b, addr_t addr) {
    // Cheap mode: Pass 1 (defined symbols) + Pass 1.5 (vtable + x64
    // prologue sweep). On a non-packed 16 MB DLL with ~27 k entries
    // the full call-graph walk is ~2 minutes; the cheap subset takes
    // milliseconds and covers every entry that ships in PE .pdata
    // (already absorbed into the symbol table) plus every prologue-
    // shaped function start. The CLI's `--functions` pass still
    // populates the UI sidebar with the full call-graph result;
    // resolving a click back through here doesn't need to redo it.
    const auto fns = enumerate_functions(b, EnumerateMode::Cheap);
    if (fns.empty()) return std::nullopt;

    // `fns` is already sorted by addr ascending. upper_bound finds the
    // first entry strictly greater than `addr`; the one before it is
    // the candidate.
    auto it = std::upper_bound(fns.begin(), fns.end(), addr,
        [](addr_t a, const DiscoveredFunction& d) { return a < d.addr; });
    if (it == fns.begin()) return std::nullopt;
    --it;

    // Respect the known extent when the symbol gives us one. A symbol
    // with size=0 (stripped `sub_*` entries) is bounded implicitly by
    // the next function's start - without that, an addr that lands far
    // outside any real function would still be claimed by the
    // largest-start ≤ addr entry, surfacing absurd offsets like
    // `sub_53290+0x29586126579c` on backtrace frames pointing into
    // libc that the primary binary has no business labelling.
    if (it->size != 0 && addr >= it->addr + it->size) return std::nullopt;
    if (it->size == 0) {
        addr_t implied_end = 0;
        auto nxt = it; ++nxt;
        if (nxt != fns.end()) implied_end = nxt->addr;
        if (implied_end != 0 && addr >= implied_end) return std::nullopt;
        // Last function in the sorted set with size==0: cap by section
        // extent so a PC past the .text mapping doesn't get mislabelled.
        if (implied_end == 0) {
            for (const auto& s : b.sections()) {
                if (it->addr >= s.vaddr && it->addr < s.vaddr + s.size) {
                    if (addr >= s.vaddr + s.size) return std::nullopt;
                    break;
                }
            }
        }
    }
    if (b.bytes_at(it->addr).empty()) return std::nullopt;

    ContainingFn out;
    out.entry         = it->addr;
    out.size          = it->size;
    out.name          = it->name;
    out.offset_within = addr - it->addr;
    return out;
}

std::map<addr_t, addr_t>
compute_call_resolutions(const Binary& b, addr_t fn,
                         const std::unordered_set<addr_t>* known_entries) {
    std::map<addr_t, addr_t> out;
    for (const auto& e : compute_classified_callees(b, fn, known_entries)) {
        // First writer wins when two edges share a site - the
        // classifier already sorts by (target, kind, site), but a given
        // `call` instruction is only classified once in practice.
        out.emplace(e.site, e.target);
    }
    return out;
}

}  // namespace ember
