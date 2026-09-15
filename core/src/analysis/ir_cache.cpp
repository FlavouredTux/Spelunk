#include <spelunk/analysis/ir_cache.hpp>

#include <memory>
#include <utility>

#include <spelunk/analysis/cfg_builder.hpp>
#include <spelunk/analysis/pipeline.hpp>
#include <spelunk/binary/binary.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/disasm/decoder.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/ir/lifter.hpp>
#include <spelunk/ir/passes.hpp>
#include <spelunk/ir/ssa.hpp>

namespace spelunk {

IrFunction* lift_cached(IrCache& cache, const Binary& b, addr_t fn) {
    if (cache.failed.contains(fn)) return nullptr;
    auto it = cache.by_addr.find(fn);
    if (it != cache.by_addr.end()) return it->second.get();

    auto dec_r = make_decoder(b);
    if (!dec_r) { cache.failed.insert(fn); return nullptr; }
    const CfgBuilder cfgb(b, **dec_r);
    if (!cache.known_entries) {
        cache.known_entries.emplace();
        for (const auto& symbol : b.symbols()) {
            if (!symbol.is_import && symbol.kind == SymbolKind::Function && symbol.addr != 0)
                cache.known_entries->insert(symbol.addr);
        }
        for (const auto& function : enumerate_functions(b, EnumerateMode::Cheap))
            cache.known_entries->insert(function.addr);
    }
    cfgb.seed_known_entries(*cache.known_entries);
    auto fn_r = cfgb.build(fn, {});
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

}  // namespace spelunk
