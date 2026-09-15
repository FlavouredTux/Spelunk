// Region printing and the Structurer entry point.

#include <spelunk/structure/structurer.hpp>

#include <cstddef>
#include <format>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <spelunk/common/error.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/structure/region.hpp>

#include "structurer_internal.hpp"

namespace spelunk::structurer {

namespace {

// ============================================================================
// Printer
// ============================================================================
void print_region(const Region& r, const IrFunction& fn,
                  int depth, std::string& out) {
    const std::string ind(static_cast<std::size_t>(depth) * 2u, ' ');

    switch (r.kind) {
        case RegionKind::Empty:
            return;

        case RegionKind::Block: {
            auto it = fn.block_at.find(r.block_start);
            if (it == fn.block_at.end()) return;
            const auto& bb = fn.blocks[it->second];
            out += std::format("{}; bb_{:x}\n", ind, bb.start);
            for (const auto& inst : bb.insts) {
                if (inst.op == IrOp::Branch ||
                    inst.op == IrOp::BranchIndirect ||
                    inst.op == IrOp::CondBranch ||
                    inst.op == IrOp::Return ||
                    inst.op == IrOp::Unreachable ||
                    inst.op == IrOp::Nop) {
                    continue;
                }
                out += std::format("{}{}\n", ind, format_ir_inst(inst));
            }
            return;
        }

        case RegionKind::Seq: {
            for (const auto& c : r.children) {
                print_region(*c, fn, depth, out);
            }
            return;
        }

        case RegionKind::IfThen: {
            const std::string cs = format_ir_value(r.condition);
            const std::string cond = r.invert ? std::format("!({})", cs) : cs;
            out += std::format("{}if ({}) {{\n", ind, cond);
            if (!r.children.empty()) {
                print_region(*r.children[0], fn, depth + 1, out);
            }
            out += std::format("{}}}\n", ind);
            return;
        }

        case RegionKind::IfElse: {
            const std::string cs = format_ir_value(r.condition);
            const std::string cond = r.invert ? std::format("!({})", cs) : cs;
            out += std::format("{}if ({}) {{\n", ind, cond);
            if (!r.children.empty()) print_region(*r.children[0], fn, depth + 1, out);
            out += std::format("{}}} else {{\n", ind);
            if (r.children.size() > 1) print_region(*r.children[1], fn, depth + 1, out);
            out += std::format("{}}}\n", ind);
            return;
        }

        case RegionKind::While: {
            const std::string cs = format_ir_value(r.condition);
            const std::string cond = r.invert ? std::format("!({})", cs) : cs;
            out += std::format("{}while ({}) {{\n", ind, cond);
            for (const auto& c : r.children) {
                print_region(*c, fn, depth + 1, out);
            }
            out += std::format("{}}}\n", ind);
            return;
        }

        case RegionKind::Loop: {
            out += std::format("{}loop {{\n", ind);
            for (const auto& c : r.children) {
                print_region(*c, fn, depth + 1, out);
            }
            out += std::format("{}}}\n", ind);
            return;
        }

        case RegionKind::DoWhile: {
            out += std::format("{}do {{\n", ind);
            for (const auto& c : r.children) {
                print_region(*c, fn, depth + 1, out);
            }
            const std::string cs = format_ir_value(r.condition);
            const std::string cond = r.invert ? std::format("!({})", cs) : cs;
            out += std::format("{}}} while ({});\n", ind, cond);
            return;
        }

        case RegionKind::For: {
            const std::string cs = format_ir_value(r.condition);
            const std::string cond = r.invert ? std::format("!({})", cs) : cs;
            out += std::format("{}for (; {}; update@{:x}:{}) {{\n",
                               ind, cond, r.update_block, r.update_inst);
            for (const auto& c : r.children) {
                print_region(*c, fn, depth + 1, out);
            }
            out += std::format("{}}}\n", ind);
            return;
        }

        case RegionKind::Return:
            out += std::format("{}return;\n", ind);
            return;

        case RegionKind::Unreachable:
            out += std::format("{}unreachable;\n", ind);
            return;

        case RegionKind::Break:
            out += std::format("{}break;\n", ind);
            return;

        case RegionKind::Continue:
            out += std::format("{}continue;\n", ind);
            return;

        case RegionKind::Goto:
            out += std::format("{}goto bb_{:x};\n", ind, r.target);
            return;

        case RegionKind::Switch: {
            const std::string_view rn = reg_name(r.switch_index);
            out += std::format("{}switch ({}) {{\n", ind,
                               rn.empty() ? std::string("<idx>") : std::string(rn));
            const std::size_t n_cases = r.case_values.size();
            const std::string cind((static_cast<std::size_t>(depth) + 1) * 2u, ' ');
            for (std::size_t i = 0; i < n_cases; ++i) {
                out += std::format("{}case {}:\n", cind, r.case_values[i]);
                if (i < r.children.size()) {
                    print_region(*r.children[i], fn, depth + 2, out);
                }
            }
            if (r.has_default && r.children.size() > n_cases) {
                out += std::format("{}default:\n", cind);
                print_region(*r.children.back(), fn, depth + 2, out);
            }
            out += std::format("{}}}\n", ind);
            return;
        }
    }
}

}  // namespace

}  // namespace spelunk::structurer

namespace spelunk {

using namespace structurer;

Result<StructuredFunction> Structurer::structure(const IrFunction& fn) const {
    StructuredFunction sf;
    sf.ir = &fn;

    if (fn.blocks.empty()) {
        sf.body = make_empty();
        return sf;
    }

    const CfgInfo info = analyze_cfg(fn);
    Builder b(fn, info);
    sf.body = b.build_sequence(fn.start, /*stop=*/kNoAddr);
    if (const Error* error = b.error()) {
        return std::unexpected(*error);
    }

    return sf;
}

std::string format_structured(const StructuredFunction& sf) {
    std::string out;
    const std::string name = sf.ir->name.empty() ? std::string("<unknown>") : sf.ir->name;
    out += std::format("function {} @ {:#x} {{\n", name, sf.ir->start);
    if (sf.body) {
        print_region(*sf.body, *sf.ir, 1, out);
    }
    // Mirror PseudoCEmitter::emit: any IR block not referenced by a
    // RegionKind::Block in the structured tree was dropped by the
    // structurer. Surface it as an explicit marker so the omission
    // is visible to the reader.
    if (sf.body && !sf.ir->blocks.empty()) {
        std::set<addr_t> rendered_blocks;
        std::function<void(const Region&)> collect = [&](const Region& r) {
            if (r.kind == RegionKind::Block) rendered_blocks.insert(r.block_start);
            for (const auto& c : r.children) if (c) collect(*c);
        };
        collect(*sf.body);
        for (const auto& bb : sf.ir->blocks) {
            if (bb.end <= bb.start) continue;
            if (rendered_blocks.contains(bb.start)) continue;
            out += std::format(
                "  ; STRUCTURER_FAIL: {:#x}..{:#x} (see --disasm-at)\n",
                bb.start, bb.end);
        }
    }
    out += "}\n";
    return out;
}

}  // namespace spelunk
