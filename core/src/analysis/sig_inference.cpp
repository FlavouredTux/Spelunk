#include <ember/analysis/sig_inference.hpp>

#include <array>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <ember/analysis/cfg_builder.hpp>
#include <ember/analysis/pipeline.hpp>
#include <ember/binary/symbol.hpp>
#include <ember/disasm/decoder.hpp>
#include <ember/disasm/register.hpp>
#include <ember/ir/abi.hpp>
#include <ember/ir/ir.hpp>
#include <ember/ir/lifter.hpp>
#include <ember/ir/passes.hpp>
#include <ember/ir/ssa.hpp>

namespace ember {

namespace {

// Libc/POSIX functions whose arg at the given 1-based slot is a
// NUL-terminated string. Duplicates the table in emitter.cpp on purpose:
// keeping the IPA independent of the emitter lets callers consume it
// without pulling the whole decompile pipeline along.
[[nodiscard]] bool libc_arg_is_charp(std::string_view name, u8 arg_idx_1) noexcept {
    struct Entry { std::string_view fn; u8 slot; };
    static const Entry kTable[] = {
        {"strlen", 1}, {"strnlen", 1},
        {"strdup", 1}, {"strndup", 1},
        {"strchr", 1}, {"strrchr", 1},
        {"strstr", 1}, {"strstr", 2},
        {"strcmp", 1}, {"strcmp", 2},
        {"strncmp", 1}, {"strncmp", 2},
        {"strcasecmp", 1}, {"strcasecmp", 2},
        {"strncasecmp", 1}, {"strncasecmp", 2},
        {"strcpy", 1}, {"strcpy", 2},
        {"strncpy", 1}, {"strncpy", 2},
        {"stpcpy", 1}, {"stpcpy", 2},
        {"stpncpy", 1}, {"stpncpy", 2},
        {"strcat", 1}, {"strcat", 2},
        {"strncat", 1}, {"strncat", 2},
        {"strpbrk", 1}, {"strpbrk", 2},
        {"strspn", 1}, {"strspn", 2},
        {"strcspn", 1}, {"strcspn", 2},
        {"strtok", 1}, {"strtok", 2},
        {"strtok_r", 1}, {"strtok_r", 2},
        {"strsep", 2},
        {"index", 1}, {"rindex", 1},
        {"basename", 1}, {"dirname", 1},
        {"puts", 1}, {"fputs", 1}, {"perror", 1}, {"gets", 1},
        {"lstrlenA", 1}, {"lstrlenW", 1},
        {"OutputDebugStringA", 1}, {"OutputDebugStringW", 1},
        {"GetModuleHandleA", 1}, {"GetModuleHandleW", 1},
        {"LoadLibraryA", 1}, {"LoadLibraryW", 1},
        {"GetProcAddress", 2}, {"CreateFileA", 1}, {"CreateFileW", 1},
        {"DeleteFileA", 1}, {"DeleteFileW", 1},
        {"fopen", 1}, {"fopen", 2},
        {"freopen", 1}, {"freopen", 2},
        {"fdopen", 2},
        {"getenv", 1}, {"secure_getenv", 1},
        {"setenv", 1}, {"setenv", 2},
        {"unsetenv", 1}, {"putenv", 1},
        {"atoi", 1}, {"atol", 1}, {"atoll", 1}, {"atof", 1},
        {"strtol", 1}, {"strtoul", 1}, {"strtoll", 1}, {"strtoull", 1},
        {"strtod", 1}, {"strtof", 1}, {"strtold", 1},
        {"remove", 1}, {"rename", 1}, {"rename", 2},
        {"unlink", 1}, {"mkdir", 1}, {"rmdir", 1},
        {"chdir", 1}, {"access", 1}, {"chmod", 1}, {"chown", 1},
        {"stat", 1}, {"lstat", 1},
        {"open", 1}, {"system", 1},
    };
    for (const auto& e : kTable) {
        if (e.fn == name && e.slot == arg_idx_1) return true;
    }
    return false;
}

[[nodiscard]] std::string clean_import_name(const std::string& n) {
    const auto at = n.find('@');
    std::string bare = at == std::string::npos ? n : n.substr(0, at);
    if (bare.starts_with("__imp_")) bare.erase(0, 6);
    return bare;
}

// Build the SSA+cleanup IR for one function, memoized. Returns nullptr if
// the function can't be lifted (decoder failure, bad bytes, etc.).
struct IrCache {
    std::map<addr_t, std::unique_ptr<IrFunction>> by_addr;
    std::set<addr_t> failed;
};

IrFunction* get_ir(IrCache& cache, const Binary& b, addr_t fn) {
    if (cache.failed.contains(fn)) return nullptr;
    auto it = cache.by_addr.find(fn);
    if (it != cache.by_addr.end()) return it->second.get();

    auto dec_r = make_decoder(b);
    if (!dec_r) { cache.failed.insert(fn); return nullptr; }
    const CfgBuilder cfg(b, **dec_r);
    auto fn_r = cfg.build(fn, {});
    if (!fn_r) { cache.failed.insert(fn); return nullptr; }
    auto lifter_r = make_lifter(b);
    if (!lifter_r) { cache.failed.insert(fn); return nullptr; }
    auto ir_r = (*lifter_r)->lift(*fn_r);
    if (!ir_r) { cache.failed.insert(fn); return nullptr; }
    const SsaBuilder ssa;
    if (auto rv = ssa.convert(*ir_r); !rv) { cache.failed.insert(fn); return nullptr; }
    if (auto rv = run_cleanup(*ir_r);  !rv) { cache.failed.insert(fn); return nullptr; }

    auto out = std::make_unique<IrFunction>(std::move(*ir_r));
    IrFunction* raw = out.get();
    cache.by_addr.emplace(fn, std::move(out));
    return raw;
}

// For an IrValue, trace through Assigns and trivial phis to a version-0
// int-arg register for the given ABI. Returns the 0-based arg slot or
// nullopt.
[[nodiscard]] std::optional<u8>
trace_to_arg_slot(const IrFunction& fn,
                  const std::map<SsaKey, const IrInst*>& defs,
                  Abi abi,
                  const IrValue& v, int depth = 0) {
    if (depth > 8) return std::nullopt;
    const auto args = int_arg_regs(abi);
    IrValue cur = v;
    for (int hop = 0; hop < 8; ++hop) {
        if (cur.kind != IrValueKind::Reg) return std::nullopt;
        const Reg canon = canonical_reg(cur.reg);
        if (cur.version == 0) {
            for (u8 i = 0; i < args.size(); ++i) if (args[i] == canon) return i;
            return std::nullopt;
        }
        auto k = ssa_key(cur);
        if (!k) return std::nullopt;
        auto it = defs.find(*k);
        if (it == defs.end()) return std::nullopt;
        const IrInst* d = it->second;
        if (d->op == IrOp::Assign && d->src_count == 1) {
            cur = d->srcs[0];
            continue;
        }
        if (d->op == IrOp::Phi && !d->phi_operands.empty()) {
            std::optional<u8> common;
            for (const auto& op : d->phi_operands) {
                auto opk = ssa_key(op);
                if (opk && *opk == *k) continue;
                auto slot = trace_to_arg_slot(fn, defs, abi, op, depth + 1);
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

// For one IR function, seed charp slots from direct libc calls AND from
// propagation via `caller_tags` (the current best-known sig for already-seen
// callees). Returns the new charp bitset for this function.
void scan_function(const Binary& b,
                   Abi abi,
                   const IrFunction& fn,
                   const std::map<addr_t, InferredSig>& known,
                   std::array<bool, kMaxAbiIntArgs>& charp) {
    // Index defs once per scan.
    std::map<SsaKey, const IrInst*> defs;
    for (const auto& bb : fn.blocks) {
        for (const auto& inst : bb.insts) {
            if (auto k = ssa_key(inst.dst); k) defs[*k] = &inst;
        }
    }

    // Walk each BB, buffering the call-args packing intrinsics so we know
    // which IrValues feed the following Call.
    for (const auto& bb : fn.blocks) {
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
            if (inst.op != IrOp::Call) continue;

            // What does the target tell us?
            std::array<bool, kMaxAbiIntArgs> callee_charp{};
            bool have_callee_info = false;
            if (const Symbol* s = b.import_at_plt(inst.target1); s) {
                const std::string name = clean_import_name(s->name);
                for (u8 k = 0; k < callee_charp.size(); ++k) {
                    callee_charp[k] = libc_arg_is_charp(name,
                                                        static_cast<u8>(k + 1));
                    if (callee_charp[k]) have_callee_info = true;
                }
            } else if (auto it = known.find(inst.target1); it != known.end()) {
                callee_charp = it->second.charp;
                for (bool v : callee_charp) if (v) { have_callee_info = true; break; }
            }
            if (!have_callee_info) { args.clear(); continue; }

            for (std::size_t i = 0; i < args.size() && i < callee_charp.size(); ++i) {
                if (!callee_charp[i]) continue;
                if (auto slot = trace_to_arg_slot(fn, defs, abi, args[i]);
                    slot && *slot < charp.size()) {
                    charp[*slot] = true;
                }
            }
            args.clear();
        }
    }
}

// Every function the CFG+call-graph can reach; called once at the top so
// the fixed-point loop can walk a stable set of entries.
std::set<addr_t> collect_entries(const Binary& b) {
    std::set<addr_t> out;
    for (const auto& s : b.symbols()) {
        if (s.is_import) continue;
        if (s.kind != SymbolKind::Function) continue;
        if (s.addr == 0 || s.name.empty()) continue;
        out.insert(s.addr);
    }
    for (const auto& e : compute_call_graph(b)) {
        if (!b.import_at_plt(e.callee)) out.insert(e.callee);
    }
    return out;
}

}  // namespace

std::map<addr_t, InferredSig> infer_signatures(const Binary& b) {
    std::map<addr_t, InferredSig> sigs;
    IrCache ir_cache;
    const auto entries = collect_entries(b);
    const Abi abi = abi_for(b.format(), b.arch(), b.endian());

    // Fixed-point: rescan every function until nobody's charp bitset grows.
    // Worst case is the diameter of the call graph; practical cases converge
    // in 3-5 iterations.
    bool changed = true;
    int guard = 0;
    while (changed && guard++ < 32) {
        changed = false;
        for (addr_t fn : entries) {
            IrFunction* ir = get_ir(ir_cache, b, fn);
            if (!ir) continue;
            auto& sig = sigs[fn];
            std::array<bool, kMaxAbiIntArgs> before = sig.charp;
            scan_function(b, abi, *ir, sigs, sig.charp);
            if (sig.charp != before) changed = true;
        }
    }
    return sigs;
}

}  // namespace ember
