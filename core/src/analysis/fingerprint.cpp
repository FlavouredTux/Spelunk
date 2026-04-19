#include <ember/analysis/fingerprint.hpp>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include <ember/analysis/cfg_builder.hpp>
#include <ember/analysis/cfg_util.hpp>
#include <ember/analysis/pipeline.hpp>
#include <ember/disasm/register.hpp>
#include <ember/disasm/x64_decoder.hpp>
#include <ember/ir/ir.hpp>
#include <ember/ir/passes.hpp>
#include <ember/ir/ssa.hpp>
#include <ember/ir/x64_lifter.hpp>

namespace ember {

namespace {

// FNV-1a 64. Avoids pulling a crypto hash for what's a cache-keyed identity.
constexpr u64 kFnvOffset = 0xcbf29ce484222325ULL;
constexpr u64 kFnvPrime  = 0x100000001b3ULL;

struct Hasher {
    u64 state = kFnvOffset;

    void byte(u8 b) noexcept {
        state ^= static_cast<u64>(b);
        state *= kFnvPrime;
    }
    void bytes(std::string_view s) noexcept {
        for (char c : s) byte(static_cast<u8>(c));
    }
    // Field separator so the hash of "ab" || "cd" differs from "a" || "bcd".
    void sep() noexcept { byte(0x01); }

    void token(std::string_view tok) noexcept {
        bytes(tok);
        sep();
    }
    void u32_tok(u32 v) noexcept {
        char buf[11];
        unsigned n = 0;
        if (v == 0) buf[n++] = '0';
        else {
            char tmp[11];
            unsigned t = 0;
            while (v) { tmp[t++] = static_cast<char>('0' + (v % 10)); v /= 10; }
            while (t) buf[n++] = tmp[--t];
        }
        bytes(std::string_view(buf, n));
        sep();
    }
};

[[nodiscard]] std::string_view operand_kind_name(IrValueKind k) noexcept {
    switch (k) {
        case IrValueKind::None: return "n";
        case IrValueKind::Reg:  return "r";
        case IrValueKind::Temp: return "t";
        case IrValueKind::Imm:  return "i";
        case IrValueKind::Flag: return "f";
    }
    return "?";
}

// Bucket an immediate into a stable category. Tiny values go in verbatim
// because they're usually semantic (struct offsets, flag bits, loop bounds).
// Anything big enough to be an address collapses to a size class — absolute
// addresses shift between PIE builds and would otherwise explode the hash.
[[nodiscard]] std::string imm_bucket(i64 v) noexcept {
    if (v >= -15 && v <= 15) {
        // Encode as a small token like "i#-3" or "i#7".
        char buf[8];
        int n = 0;
        i64 x = v;
        const bool neg = x < 0;
        if (neg) x = -x;
        do { buf[n++] = static_cast<char>('0' + (x % 10)); x /= 10; } while (x);
        if (neg) buf[n++] = '-';
        std::reverse(buf, buf + n);
        return "i#" + std::string(buf, buf + n);
    }
    const u64 u = static_cast<u64>(v < 0 ? -v : v);
    if (u < 0x100)     return "i:s8";
    if (u < 0x10000)   return "i:s16";
    if (u < 0x1000000) return "i:s24";
    return "i:large";
}

// String literal a function references, resolved through the binary if the
// immediate points at a printable NUL-terminated ASCII run. Strings are a
// very stable naming signal (error messages, format strings, class names).
[[nodiscard]] std::string try_string_at(const Binary& b, u64 addr) {
    auto span = b.bytes_at(static_cast<addr_t>(addr));
    if (span.empty()) return {};
    const std::size_t kMax = 128;
    const std::size_t lim = std::min(span.size(), kMax);
    std::string s;
    s.reserve(32);
    for (std::size_t i = 0; i < lim; ++i) {
        const auto c = static_cast<unsigned char>(span[i]);
        if (c == 0) return s.size() >= 4 ? s : std::string{};
        if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') return {};
        if (c > 0x7e) return {};
        s.push_back(static_cast<char>(c));
    }
    return {};  // unterminated within kMax: drop it
}

[[nodiscard]] std::string import_name_at(const Binary& b, addr_t target) {
    const Symbol* s = b.import_at_plt(target);
    if (!s) return {};
    const auto at = s->name.find('@');
    return at == std::string::npos ? s->name : s->name.substr(0, at);
}

// If `addr` resolves to a named defined-object symbol, return its name.
// Used to fold global-data references into the fingerprint — a function
// that writes to `g_current_player` is uniquely identified by that xref
// even if the surrounding code is otherwise shared with similar helpers.
[[nodiscard]] std::string data_global_name_at(const Binary& b, u64 addr) {
    const Symbol* s = b.defined_object_at(static_cast<addr_t>(addr));
    if (!s) return {};
    if (s->kind != SymbolKind::Object) return {};
    if (s->name.empty()) return {};
    const auto at = s->name.find('@');
    return at == std::string::npos ? s->name : s->name.substr(0, at);
}

// Append a token description of `v` to the hasher. Stable across SSA
// versions, temp ids, concrete immediate values (beyond the small bucket),
// and absolute addresses.
void hash_operand(Hasher& h, const IrValue& v) {
    h.token(operand_kind_name(v.kind));
    h.token(type_name(v.type));
    switch (v.kind) {
        case IrValueKind::Reg:
            h.token(reg_name(canonical_reg(v.reg)));
            break;
        case IrValueKind::Imm:
            h.token(imm_bucket(v.imm));
            break;
        case IrValueKind::Flag:
            h.token(flag_name(v.flag));
            break;
        case IrValueKind::Temp:
        case IrValueKind::None:
            break;
    }
}

void hash_inst(Hasher& h, const IrInst& inst, const Binary& b,
               std::set<std::string>& called_imports,
               std::set<std::string>& string_refs,
               std::set<std::string>& global_refs) {
    h.token(op_name(inst.op));
    if (inst.dst.kind != IrValueKind::None) {
        h.token("dst");
        hash_operand(h, inst.dst);
    }
    // Phi operands are set-like (order-sensitive only to their predecessor
    // block order, which is itself address-derived). Canonicalize by sorting
    // a flattened kind|type|reg serialization.
    if (inst.op == IrOp::Phi) {
        std::vector<std::string> ops;
        ops.reserve(inst.phi_operands.size());
        for (const auto& p : inst.phi_operands) {
            std::string s;
            s += operand_kind_name(p.kind);
            s += '|';
            s += type_name(p.type);
            if (p.kind == IrValueKind::Reg) {
                s += '|';
                s += reg_name(canonical_reg(p.reg));
            }
            ops.push_back(std::move(s));
        }
        std::ranges::sort(ops);
        for (const auto& s : ops) h.token(s);
    } else {
        for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
            hash_operand(h, inst.srcs[i]);
            // Any Imm operand that looks like it points at a string in the
            // image contributes the string content to the sorted side-set;
            // anything that resolves to a named global data symbol
            // contributes the symbol name. Both are stable across PIE slides
            // and reliable signals for function identity.
            const auto& s = inst.srcs[i];
            if (s.kind == IrValueKind::Imm && s.imm > 0 &&
                static_cast<u64>(s.imm) >= 0x100) {
                const auto v = static_cast<u64>(s.imm);
                if (auto str = try_string_at(b, v); !str.empty()) {
                    string_refs.insert(std::move(str));
                } else if (auto g = data_global_name_at(b, v); !g.empty()) {
                    global_refs.insert(std::move(g));
                }
            }
        }
    }
    if (inst.op == IrOp::Call) {
        if (auto n = import_name_at(b, inst.target1); !n.empty()) {
            called_imports.insert(std::move(n));
            h.token("call:import");
        } else {
            // Direct calls to unnamed addresses: we can't hash the address
            // without burning PIE stability. Tag as "local" — fuzzy match
            // for call-graph topology happens above this layer.
            h.token("call:local");
        }
    }
    if (inst.op == IrOp::Intrinsic) h.token(inst.name);
    if (inst.segment != Reg::None) {
        h.token("seg");
        h.token(reg_name(inst.segment));
    }
}

}  // namespace

FunctionFingerprint compute_fingerprint(const Binary& b, addr_t fn_start) {
    FunctionFingerprint out;

    // Run the same front half of the decompile pipeline but stop before
    // structuring. Fingerprinting cares about IR content, not structure.
    const X64Decoder  dec;
    const CfgBuilder  cfg(b, dec);
    auto fn_r = cfg.build(fn_start, {});
    if (!fn_r) return out;

    const X64Lifter lifter;
    auto ir_r = lifter.lift(*fn_r);
    if (!ir_r) return out;

    const SsaBuilder ssa;
    if (auto rv = ssa.convert(*ir_r); !rv) return out;
    if (auto rv = run_cleanup(*ir_r);  !rv) return out;

    const auto rpo = compute_rpo(*ir_r);

    Hasher h;
    std::set<std::string> called_imports;
    std::set<std::string> string_refs;
    std::set<std::string> global_refs;

    // Fingerprint schema — bump on any incompatible change. Previously
    // exported DBs stop matching when this changes. v2 added global-data
    // symbol references to the side-sets.
    h.token("v2");
    h.u32_tok(static_cast<u32>(ir_r->blocks.size()));
    h.sep();

    u32 insts = 0, calls = 0;

    for (addr_t ba : rpo) {
        auto it = ir_r->block_at.find(ba);
        if (it == ir_r->block_at.end()) continue;
        const auto& bb = ir_r->blocks[it->second];

        h.token("bb");
        h.u32_tok(static_cast<u32>(bb.successors.size()));
        h.u32_tok(static_cast<u32>(bb.predecessors.size()));

        for (const auto& inst : bb.insts) {
            if (inst.op == IrOp::Nop) continue;
            hash_inst(h, inst, b, called_imports, string_refs, global_refs);
            ++insts;
            if (inst.op == IrOp::Call || inst.op == IrOp::CallIndirect) ++calls;
        }
    }

    // Sorted side-sets folded in last. std::set is already sorted, but make
    // the intent explicit with tagged sections — future additions (e.g. a
    // global-data-reference set) slot in without perturbing hashes of old
    // categories.
    h.token("imports");
    for (const auto& s : called_imports) h.token(s);
    h.token("strings");
    for (const auto& s : string_refs) h.token(s);
    h.token("globals");
    for (const auto& s : global_refs) h.token(s);

    out.hash   = h.state;
    out.blocks = static_cast<u32>(ir_r->blocks.size());
    out.insts  = insts;
    out.calls  = calls;
    return out;
}

}  // namespace ember
