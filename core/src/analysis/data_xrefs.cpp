#include <ember/analysis/data_xrefs.hpp>

#include <algorithm>
#include <cstddef>
#include <unordered_set>

#include <ember/analysis/pipeline.hpp>
#include <ember/binary/section.hpp>
#include <ember/disasm/instruction.hpp>
#include <ember/disasm/x64_decoder.hpp>

namespace ember {

namespace {

// Simple section-resolution helper. Caching a flat (vaddr, size, flags)
// table avoids re-walking the section list for every operand — large
// binaries can have thousands of operands per function.
struct SectionTable {
    struct Row {
        addr_t beg;
        addr_t end;
        bool   executable;
        bool   allocated;
    };
    std::vector<Row> rows;

    explicit SectionTable(const Binary& b) {
        const auto secs = b.sections();
        rows.reserve(secs.size());
        for (const auto& s : secs) {
            if (s.size == 0) continue;
            rows.push_back({s.vaddr, s.vaddr + s.size,
                            s.flags.executable, s.flags.allocated});
        }
        std::ranges::sort(rows, [](const Row& a, const Row& bb) noexcept {
            return a.beg < bb.beg;
        });
    }

    enum class Class : u8 { Unmapped, Data, Code };

    [[nodiscard]] Class classify(addr_t a) const noexcept {
        auto it = std::ranges::upper_bound(rows, a,
            {}, [](const Row& r) noexcept { return r.beg; });
        if (it == rows.begin()) return Class::Unmapped;
        --it;
        if (a >= it->end || !it->allocated) return Class::Unmapped;
        return it->executable ? Class::Code : Class::Data;
    }
};

[[nodiscard]] DataXrefKind
classify(const Instruction& insn, u8 mem_op_idx) noexcept {
    if (insn.mnemonic == Mnemonic::Lea) return DataXrefKind::Lea;
    // CMP and TEST read both operands — memory operand is never a dest.
    if (insn.mnemonic == Mnemonic::Cmp ||
        insn.mnemonic == Mnemonic::Test) {
        return DataXrefKind::Read;
    }
    // x86 convention: operand 0 is the destination on writing mnemonics.
    // CALL/JMP with a memory operand read the slot (to get the indirect
    // target) — not a write.
    if (insn.mnemonic == Mnemonic::Call ||
        insn.mnemonic == Mnemonic::Jmp) {
        return DataXrefKind::Read;
    }
    return (mem_op_idx == 0) ? DataXrefKind::Write : DataXrefKind::Read;
}

}  // namespace

std::map<addr_t, std::vector<DataXref>>
compute_data_xrefs(const Binary& b) {
    std::map<addr_t, std::vector<DataXref>> out;
    const SectionTable sects(b);
    X64Decoder dec;

    // Build the work list: every named-symbol function + every discovered
    // function (deduped by address). Earlier this was symbol-only, which
    // on a 109 MB stripped binary (Roblox client) walked < 5% of code and
    // produced ~2k xrefs instead of the hundreds of thousands actually
    // present. Same union-with-discovered fix that compute_call_graph
    // needed.
    struct WorkItem { addr_t addr; u64 size; };
    std::vector<WorkItem> work;
    std::unordered_set<addr_t> seen;
    for (const auto& sym : b.symbols()) {
        if (sym.is_import) continue;
        if (sym.kind != SymbolKind::Function) continue;
        if (sym.size == 0) continue;
        if (!seen.insert(sym.addr).second) continue;
        work.push_back({sym.addr, sym.size});
    }
    for (const auto& fn : enumerate_functions(b, EnumerateMode::Cheap)) {
        if (b.import_at_plt(fn.addr) != nullptr) continue;
        if (fn.size == 0) continue;  // truly-unknown extent — skip rather
                                     // than guess wildly past the function
        if (!seen.insert(fn.addr).second) continue;
        work.push_back({fn.addr, fn.size});
    }

    for (const auto& w : work) {
        auto span = b.bytes_at(w.addr);
        if (span.empty()) continue;
        const std::size_t limit = std::min<std::size_t>(
            span.size(), static_cast<std::size_t>(w.size));

        addr_t ip = w.addr;
        std::size_t off = 0;
        while (off < limit) {
            auto remaining = span.subspan(off, limit - off);
            auto decoded = dec.decode(remaining, ip);
            if (!decoded) { ip += 1; off += 1; continue; }
            const auto& insn = *decoded;

            for (u8 j = 0; j < insn.num_operands; ++j) {
                const Operand& op = insn.operands[j];
                if (op.kind != Operand::Kind::Memory) continue;
                if (!op.mem.has_disp) continue;

                addr_t target = 0;
                if (op.mem.base == Reg::Rip && op.mem.index == Reg::None) {
                    target = ip + insn.length +
                             static_cast<addr_t>(op.mem.disp);
                } else if (op.mem.base == Reg::None &&
                           op.mem.index == Reg::None) {
                    target = static_cast<addr_t>(op.mem.disp);
                } else {
                    continue;
                }

                const auto cls = sects.classify(target);
                if (cls == SectionTable::Class::Unmapped) continue;

                DataXrefKind k = classify(insn, j);
                // LEA-to-code is a function-address-taken event — keep it
                // (with CodePtr kind so consumers can filter). Other
                // operand kinds against code sections are call/jmp
                // targets, which belong on the call graph, not here.
                if (cls == SectionTable::Class::Code) {
                    if (k != DataXrefKind::Lea) continue;
                    k = DataXrefKind::CodePtr;
                }

                auto& bucket = out[target];
                // Collapse the common case where one insn references the
                // same target twice (e.g. read-modify-write): take the
                // more specific kind (Write > Read).
                if (!bucket.empty() && bucket.back().from_pc == ip &&
                    bucket.back().to_addr == target) {
                    if (k == DataXrefKind::Write) bucket.back().kind = k;
                    continue;
                }
                bucket.push_back({ip, target, k});
            }

            ip  += insn.length;
            off += insn.length;
        }
    }

    for (auto& [_, bucket] : out) {
        std::ranges::sort(bucket, [](const DataXref& a, const DataXref& bb) noexcept {
            if (a.from_pc != bb.from_pc) return a.from_pc < bb.from_pc;
            return static_cast<u8>(a.kind) < static_cast<u8>(bb.kind);
        });
    }
    return out;
}

}  // namespace ember
