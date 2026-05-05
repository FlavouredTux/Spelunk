#include <ember/analysis/name_resolver.hpp>

#include <format>

#include <ember/analysis/demangle.hpp>
#include <ember/binary/binary.hpp>
#include <ember/binary/symbol.hpp>

namespace ember {

std::optional<ResolvedName>
resolve_address_name(const Binary& b, addr_t addr) {
    if (const Symbol* s = b.import_at_plt(addr); s && !s->name.empty()) {
        return ResolvedName{
            .name = pretty_symbol_base(s->name),
            .base = s->addr,
            .addr = addr,
            .kind = ResolvedNameKind::Import,
        };
    }
    if (const Symbol* s = b.import_at_got(addr); s && !s->name.empty()) {
        return ResolvedName{
            .name = pretty_symbol_base(s->name),
            .base = s->got_addr,
            .addr = addr,
            .kind = ResolvedNameKind::Got,
        };
    }
    if (const Symbol* s = b.defined_object_at(addr); s && !s->name.empty()) {
        return ResolvedName{
            .name = pretty_symbol_base(s->name),
            .base = s->addr,
            .addr = addr,
            .kind = ResolvedNameKind::Object,
        };
    }
    for (const auto& s : b.symbols()) {
        if (s.is_import || s.name.empty()) continue;
        if (s.kind != SymbolKind::Function) continue;
        if (s.addr == addr || (s.size != 0 && addr > s.addr && addr < s.addr + s.size)) {
            return ResolvedName{
                .name = pretty_symbol_base(s.name),
                .base = s.addr,
                .addr = addr,
                .kind = ResolvedNameKind::Function,
            };
        }
    }
    return std::nullopt;
}

std::string format_address_comment(const ResolvedName& r) {
    std::string out = r.name;
    if (r.kind == ResolvedNameKind::Got) out += "@GOT";
    if (r.addr != r.base) out += std::format("+{:#x}", r.addr - r.base);
    return out;
}

std::string format_address_expr(const ResolvedName& r) {
    switch (r.kind) {
        case ResolvedNameKind::Object:
            return "&" + format_address_comment(r);
        case ResolvedNameKind::Function:
        case ResolvedNameKind::Import:
        case ResolvedNameKind::Got:
            return format_address_comment(r);
    }
    return format_address_comment(r);
}

}  // namespace ember
