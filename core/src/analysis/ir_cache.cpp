#include <ember/analysis/ir_cache.hpp>

#include <ember/analysis/cfg_builder.hpp>
#include <ember/binary/binary.hpp>
#include <ember/disasm/decoder.hpp>
#include <ember/ir/lifter.hpp>
#include <ember/ir/passes.hpp>
#include <ember/ir/ssa.hpp>

namespace ember {

IrFunction* lift_cached(IrCache& cache, const Binary& b, addr_t fn) {
    if (cache.failed.contains(fn)) return nullptr;
    auto it = cache.by_addr.find(fn);
    if (it != cache.by_addr.end()) return it->second.get();

    auto dec_r = make_decoder(b);
    if (!dec_r) { cache.failed.insert(fn); return nullptr; }
    const CfgBuilder cfgb(b, **dec_r);
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

}  // namespace ember
