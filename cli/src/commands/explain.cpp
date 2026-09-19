#include <spelunk/common/diagnostic.hpp>
// Address explanation, containing function, callees, collisions.

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <optional>
#include <print>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <spelunk/analysis/data_xrefs.hpp>
#include <spelunk/analysis/identify.hpp>
#include <spelunk/analysis/pipeline.hpp>
#include <spelunk/analysis/rtti.hpp>
#include <spelunk/common/annotations.hpp>
#include <spelunk/common/cache.hpp>
#include <spelunk/common/timing.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/ir/lifter.hpp>

#include "../fingerprint.hpp"
#include "../subcommands.hpp"
#include "../util.hpp"
#include "common.hpp"

namespace spelunk::cli {

namespace {

[[nodiscard]] std::string pointer_classification(const Binary& b, addr_t v) {
    if (v == 0) return "null";
    if (addr_in_executable_section_cli(b, v)) return "code";
    if (auto s = read_c_string(b, v); s) return "string";
    if (address_is_mapped(b, v)) return "data";
    return "unmapped";
}

}  // namespace

int run_explain_address(const Args& args, const Binary& b) {
    ScopedTimer total_timer("explain_address.total");
    auto va = parse_cli_addr(args.explain_address);
    if (!va) {
        spelunk::diagnostic::print("spelunk: --explain-address: bad address '{}'",
                     args.explain_address);
        return EXIT_FAILURE;
    }

    const bool mapped = address_is_mapped(b, *va);
    const bool is_code = addr_in_executable_section_cli(b, *va);
    const auto section = section_name_containing(b, *va);
    const auto fn = containing_function(b, *va);
    const auto ptr = is_code ? std::optional<addr_t>{} : read_pointer_value(b, *va);
    const auto xrefs = compute_data_xrefs_to(b, *va);
    const auto direct_callers = is_code ? compute_callers_to_fast(b, *va)
                                        : std::vector<addr_t>{};
    auto count_kind = [&](DataXrefKind k) {
        return std::ranges::count_if(xrefs, [&](const DataXref& xr) {
            return xr.kind == k;
        });
    };
    const auto reads = count_kind(DataXrefKind::Read);
    const auto writes = count_kind(DataXrefKind::Write);
    const auto leas = count_kind(DataXrefKind::Lea);
    const auto codeptrs = count_kind(DataXrefKind::CodePtr);

    std::string kind = "unknown";
    if (is_code) {
        kind = fn && fn->entry == *va ? "function" : "code";
    } else if (ptr) {
        kind = "pointer";
    } else if (mapped && (reads || writes || leas || codeptrs)) {
        kind = "state";
    } else if (mapped) {
        kind = "data";
    }

    if (args.json) {
        std::string out = std::format(
            "{{\"address\":\"{:#x}\",\"mapped\":{},\"kind\":\"{}\"",
            *va, mapped ? "true" : "false", json_escape(kind));
        if (!section.empty()) {
            out += std::format(",\"section\":\"{}\"", json_escape(std::string(section)));
        }
        if (fn) {
            out += std::format(
                ",\"containing_function\":{{\"entry\":\"{:#x}\",\"size\":\"{:#x}\","
                "\"name\":\"{}\",\"offset\":\"{:#x}\"}}",
                fn->entry, fn->size, json_escape(fn->name), fn->offset_within);
        } else {
            out += ",\"containing_function\":null";
        }
        if (ptr) {
            out += std::format(
                ",\"pointer\":{{\"value\":\"{:#x}\",\"classification\":\"{}\"}}",
                *ptr, pointer_classification(b, *ptr));
        } else {
            out += ",\"pointer\":null";
        }
        out += std::format(
            ",\"state_summary\":{{\"reads\":{},\"writes\":{},\"lea\":{},\"code_ptr\":{}}}",
            reads, writes, leas, codeptrs);
        out += std::format(
            ",\"refs_summary\":{{\"direct\":{},\"code_ptr\":{},\"lea\":{}}}",
            direct_callers.size(), codeptrs, leas);
        if (is_code) {
            auto probe = decode_disasm_probe(b, *va, 8);
            if (probe) {
                out += std::format(
                    ",\"patch_summary\":{{\"recommended_steal_len\":{},"
                    "\"needs_relocation\":{},\"first_basic_block_end\":\"{:#x}\","
                    "\"safe_absolute_jump_trampoline\":{}}}",
                    probe->steal_len,
                    probe->needs_relocation ? "true" : "false",
                    probe->first_bb_end,
                    probe->safe_abs_trampoline ? "true" : "false");
            }
        }
        out += "}\n";
        std::fwrite(out.data(), 1, out.size(), stdout);
        return EXIT_SUCCESS;
    }

    std::println("address\t{:#x}", *va);
    std::println("mapped\t{}", mapped ? "yes" : "no");
    if (!section.empty()) std::println("section\t{}", section);
    std::println("kind\t{}", kind);
    if (fn) {
        std::println("function\t{:#x}\t{:#x}\t{}\t+{:#x}",
                     fn->entry, fn->size, fn->name, fn->offset_within);
    }
    if (ptr) {
        std::println("pointer\t{:#x}\t{}", *ptr, pointer_classification(b, *ptr));
    }
    std::println("state\treads={}\twrites={}\tlea={}\tcode-ptr={}",
                 reads, writes, leas, codeptrs);
    std::println("refs\tdirect={}\tcode-ptr={}\tlea={}",
                 direct_callers.size(), codeptrs, leas);
    if (is_code) {
        auto probe = decode_disasm_probe(b, *va, 8);
        if (probe) {
            std::println("patch\tsteal_len={}\tneeds_relocation={}\tfirst_bb_end={:#x}\tsafe_abs_jump={}",
                         probe->steal_len,
                         probe->needs_relocation ? "yes" : "no",
                         probe->first_bb_end,
                         probe->safe_abs_trampoline ? "yes" : "no");
        }
        if (auto dis = format_disasm_range(b, *va, *va + 32); dis) {
            std::string_view sv(*dis);
            if (const auto nl = sv.find('\n'); nl != std::string_view::npos) {
                sv = sv.substr(0, nl);
            }
            std::println("disasm\t{}", sv);
        }
    }
    return EXIT_SUCCESS;
}

int run_explain_vcall(const Args& args, const Binary& b) {
    const auto spec = parse_obj_off_spec(args.explain_vcall);
    if (!spec) {
        spelunk::diagnostic::print("spelunk: --explain-vcall: expected OBJ:OFF, got '{}'",
            args.explain_vcall);
        return EXIT_FAILURE;
    }
    const auto [obj, slot_off] = *spec;
    const auto vptr = read_pointer_value(b, obj);
    if (!vptr) {
        spelunk::diagnostic::print("spelunk: --explain-vcall: cannot read object vptr at {:#x}", obj);
        return EXIT_FAILURE;
    }
    const addr_t slot_addr = *vptr + slot_off;
    const auto target = read_pointer_value(b, slot_addr);
    if (!target) {
        spelunk::diagnostic::print("spelunk: --explain-vcall: cannot read vtable slot {:#x}", slot_addr);
        return EXIT_FAILURE;
    }

    const Annotations ann = load_annotations_quiet(args);
    auto cf = containing_function(b, *target);
    std::string target_name = std::format("sub_{:x}", *target);
    u64 target_off = 0;
    if (cf) {
        target_name = cf->name;
        target_off = cf->offset_within;
    }

    if (args.json) {
        std::string out = std::format(
            "{{\"object\":\"{:#x}\",\"slot_offset\":\"{:#x}\","
            "\"vptr\":\"{:#x}\",\"slot\":\"{:#x}\","
            "\"target\":\"{:#x}\",\"target_name\":\"{}\",\"target_offset\":\"{:#x}\"}}\n",
            obj, slot_off, *vptr, slot_addr, *target,
            json_escape(target_name), target_off);
        std::fwrite(out.data(), 1, out.size(), stdout);
        return EXIT_SUCCESS;
    }

    std::println("object\t{:#x}", obj);
    std::println("vptr\t{:#x}", *vptr);
    std::println("slot\t{:#x}\t+{:#x}", slot_addr, slot_off);
    std::println("target\t{:#x}\t{}+{:#x}", *target, target_name, target_off);
    if (const auto sec = section_name_containing(b, slot_addr); !sec.empty()) {
        std::println("slot_section\t{}", sec);
    }
    if (const auto sec = section_name_containing(b, *target); !sec.empty()) {
        std::println("target_section\t{}", sec);
    }
    if (const auto line = first_disasm_line_at(b, *target); !line.empty()) {
        std::println("disasm\t{}", line);
    }
    const auto summary = compact_pseudo_summary(b, *target, &ann);
    if (!summary.empty()) {
        std::println("pseudo:");
        std::print("{}", summary);
    }
    return EXIT_SUCCESS;
}

int run_dump_object(const Args& args, const Binary& b) {
    auto obj = parse_cli_addr(args.dump_object);
    auto size = parse_cli_addr(args.object_size);
    if (!obj) {
        spelunk::diagnostic::print("spelunk: --dump-object: bad address '{}'", args.dump_object);
        return EXIT_FAILURE;
    }
    if (!size || *size == 0) {
        spelunk::diagnostic::print("spelunk: --dump-object requires --size <hex>");
        return EXIT_FAILURE;
    }
    const auto rows = classify_object_fields(b, static_cast<addr_t>(*obj),
                                             static_cast<addr_t>(*size));
    if (args.json) {
        std::string out = std::format("{{\"object\":\"{:#x}\",\"size\":\"{:#x}\",\"fields\":[",
                                     static_cast<addr_t>(*obj), static_cast<addr_t>(*size));
        for (std::size_t i = 0; i < rows.size(); ++i) {
            if (i) out += ',';
            const auto& r = rows[i];
            out += std::format(
                "{{\"offset\":\"{:#x}\",\"addr\":\"{:#x}\",\"value\":\"{:#x}\",\"kind\":\"{}\"",
                r.offset, r.addr, r.value, json_escape(r.kind));
            if (!r.detail.empty()) {
                out += std::format(",\"detail\":\"{}\"", json_escape(r.detail));
            }
            out += '}';
        }
        out += "]}\n";
        std::fwrite(out.data(), 1, out.size(), stdout);
        return EXIT_SUCCESS;
    }

    std::println("object\t{:#x}\tsize\t{:#x}", static_cast<addr_t>(*obj), static_cast<addr_t>(*size));
    std::println("offset\taddr\tvalue\tkind\tdetail");
    for (const auto& r : rows) {
        std::println("{:#x}\t{:#x}\t{:#x}\t{}\t{}",
                     r.offset, r.addr, r.value, r.kind,
                     r.detail.empty() ? "-" : r.detail);
    }
    return EXIT_SUCCESS;
}

int run_containing_fn(const Args& args, const Binary& b) {
    auto va = resolve_flag_target(b, args, args.containing_fn);
    if (!va) return EXIT_FAILURE;  // resolver reported the reason
    auto cf = containing_function(b, *va);
    if (!cf) {
        spelunk::diagnostic::print("spelunk: --containing-fn: no function covers {:#x}", *va);
        return EXIT_FAILURE;
    }
    if (args.json) {
        std::println(
            "{{\"entry\":\"{:#x}\",\"size\":{},\"name\":\"{}\",\"offset\":{}}}",
            cf->entry, cf->size, cf->name, cf->offset_within);
    } else {
        std::println("{:#x}\t{:#x}\t{}\t{:#x}",
                     cf->entry, cf->size, cf->name, cf->offset_within);
    }
    return EXIT_SUCCESS;
}

int run_validate_name(const Args& args, const Binary& b) {
    // Read the cached --fingerprints TSV (or build it once if cold). On
    // a 102MB / 500K-fn binary this takes the per-call cost from ~3
    // minutes (full lift+SSA per fn) to milliseconds when the cache is
    // warm.
    const auto fp_tsv = fingerprints_tsv_for(args, b);
    const auto rows   = fingerprint_rows_from_tsv(fp_tsv);
    const auto v = validate_name(b, args.validate_name, rows);
    const std::string_view verdict = verdict_name(v.verdict);

    // Pull annotations once for provenance lookup. Bound rows that
    // carry a meta record get an extra `confidence=` / `source=`
    // hint so a verifier knows whether the binding was cheap (a
    // symbol) or supplied as a high-confidence external claim.
    Annotations validate_ann;
    bool validate_ann_ready = false;
    {
        const auto adir = !args.cache_dir.empty()
            ? std::filesystem::path{args.cache_dir}
            : cache::default_dir();
        auto loc = resolve_annotation_location(args.binary, args.annotations_path, adir);
        if (args.no_cache && loc.source == AnnotationSource::Cache) loc = {};
        if (loc.source != AnnotationSource::None && !loc.path.empty()) {
            std::error_code ec;
            if (std::filesystem::exists(loc.path, ec) && !ec) {
                if (auto rv = Annotations::load(loc.path); rv) {
                    validate_ann = std::move(*rv);
                    validate_ann_ready = true;
                }
            }
        }
    }
    auto bound_meta = [&](addr_t a) -> const AnnotationMeta* {
        return validate_ann_ready ? validate_ann.meta_for_rename(a) : nullptr;
    };

    if (args.json) {
        std::string out = std::format(
            "{{\"name\":\"{}\",\"verdict\":\"{}\",\"bound\":[",
            json_escape(args.validate_name), verdict);
        for (std::size_t i = 0; i < v.bound.size(); ++i) {
            if (i) out += ',';
            const auto& fp = v.fps[i];
            out += std::format(
                "{{\"addr\":\"{:#x}\",\"hash\":\"{:#x}\","
                "\"blocks\":{},\"insts\":{},\"calls\":{},\"offset\":{}",
                v.bound[i], fp.hash, fp.blocks, fp.insts, fp.calls, v.offsets[i]);
            if (const auto* m = bound_meta(v.bound[i]); m) {
                if (m->confidence > 0.0f) {
                    out += std::format(",\"confidence\":{:.3g}", m->confidence);
                }
                if (!m->source.empty()) {
                    out += std::format(",\"source\":\"{}\"",
                                       json_escape(m->source));
                }
            }
            out += "}";
        }
        out += "],\"near_matches\":[";
        for (std::size_t i = 0; i < v.near_matches.size(); ++i) {
            if (i) out += ',';
            const auto& nm = v.near_matches[i];
            out += std::format(
                "{{\"addr\":\"{:#x}\",\"hash\":\"{:#x}\","
                "\"blocks\":{},\"insts\":{},\"calls\":{},\"name\":\"{}\"}}",
                nm.addr, nm.fp.hash, nm.fp.blocks, nm.fp.insts, nm.fp.calls,
                json_escape(nm.name));
        }
        out += "]}\n";
        std::fwrite(out.data(), 1, out.size(), stdout);
    } else {
        std::string out = std::format("verdict\t{}\n", verdict);
        for (std::size_t i = 0; i < v.bound.size(); ++i) {
            const auto& fp = v.fps[i];
            std::string row = std::format(
                "bound\t{:#x}\thash={:#x}\tblocks={}\tinsts={}\tcalls={}"
                "\tname={}\toffset_in_fn={:#x}",
                v.bound[i], fp.hash, fp.blocks, fp.insts, fp.calls,
                args.validate_name, v.offsets[i]);
            if (const auto* m = bound_meta(v.bound[i]); m) {
                if (m->confidence > 0.0f) {
                    row += std::format("\tconfidence={:.3g}", m->confidence);
                }
                if (!m->source.empty()) {
                    row += std::format("\tsource={}", m->source);
                }
            }
            out += row + "\n";
        }
        // Cap near-match output at 8 lines: a name with hundreds of shape
        // twins is uninformative, and the verdict label is what the
        // caller actually checks.
        constexpr std::size_t kNearCap = 8;
        const std::size_t shown = std::min(v.near_matches.size(), kNearCap);
        for (std::size_t i = 0; i < shown; ++i) {
            const auto& nm = v.near_matches[i];
            out += std::format(
                "near\t{:#x}\thash={:#x}\tblocks={}\tinsts={}\tcalls={}"
                "\tname={}\n",
                nm.addr, nm.fp.hash, nm.fp.blocks, nm.fp.insts, nm.fp.calls,
                nm.name);
        }
        if (v.near_matches.size() > shown) {
            out += std::format("near_truncated\t{}\n", v.near_matches.size() - shown);
        }
        std::fwrite(out.data(), 1, out.size(), stdout);
    }
    // Exit code conveys verdict to shell pipelines: 0 STRONG, 1 anything
    // ambiguous/weak/unknown - matches the grep-style "did you find what
    // you wanted" contract callers already use for --refs-to et al.
    return v.verdict == NameValidation::Verdict::Strong ? EXIT_SUCCESS : EXIT_FAILURE;
}

int run_collisions(const Args& args, const Binary& b) {
    const auto fp_tsv = fingerprints_tsv_for(args, b);
    const auto rows   = fingerprint_rows_from_tsv(fp_tsv);
    const auto c = collect_collisions(b, rows);
    if (args.json) {
        std::string out = "{\"by_name\":[";
        for (std::size_t i = 0; i < c.by_name.size(); ++i) {
            if (i) out += ',';
            const auto& g = c.by_name[i];
            out += std::format("{{\"name\":\"{}\",\"addrs\":[", json_escape(g.name));
            for (std::size_t j = 0; j < g.addrs.size(); ++j) {
                if (j) out += ',';
                out += std::format("\"{:#x}\"", g.addrs[j]);
            }
            out += "]}";
        }
        out += "],\"by_fingerprint\":[";
        for (std::size_t i = 0; i < c.by_fingerprint.size(); ++i) {
            if (i) out += ',';
            const auto& g = c.by_fingerprint[i];
            out += std::format("{{\"hash\":\"{:#x}\",\"addrs\":[", g.hash);
            for (std::size_t j = 0; j < g.addrs.size(); ++j) {
                if (j) out += ',';
                out += std::format("\"{:#x}\"", g.addrs[j]);
            }
            out += "]}";
        }
        out += "]}\n";
        std::fwrite(out.data(), 1, out.size(), stdout);
    } else {
        std::string out;
        for (const auto& g : c.by_name) {
            out += std::format("name\t{}\t", g.name);
            for (std::size_t j = 0; j < g.addrs.size(); ++j) {
                if (j) out += ',';
                out += std::format("{:#x}", g.addrs[j]);
            }
            out += std::format("\t{}\n", g.addrs.size());
        }
        for (const auto& g : c.by_fingerprint) {
            out += std::format("fingerprint\t{:#x}\t", g.hash);
            for (std::size_t j = 0; j < g.addrs.size(); ++j) {
                if (j) out += ',';
                out += std::format("{:#x}", g.addrs[j]);
            }
            out += std::format("\t{}\n", g.addrs.size());
        }
        std::fwrite(out.data(), 1, out.size(), stdout);
    }
    return EXIT_SUCCESS;
}

int run_callees(const Args& args, const Binary& b) {
    const Annotations callees_ann = load_annotations_quiet(args);
    auto win = resolve_function(b, args.callees, &callees_ann);
    if (!win) {
        spelunk::diagnostic::print("spelunk: --callees: could not resolve '{}'", args.callees);
        return EXIT_FAILURE;
    }
    const auto va = win->start;
    const auto cs = compute_classified_callees(b, va);
    if (args.json) {
        std::string out = std::format("{{\"va\":\"{:#x}\",\"callees\":[", va);
        for (std::size_t i = 0; i < cs.size(); ++i) {
            if (i) out += ',';
            out += std::format("{{\"va\":\"{:#x}\",\"kind\":\"{}\"}}",
                               cs[i].target, callee_kind_name(cs[i].kind));
        }
        out += "]}\n";
        std::fwrite(out.data(), 1, out.size(), stdout);
    } else {
        std::string out;
        for (const auto& c : cs) {
            out += std::format("{:#x}\n", c.target);
        }
        std::fwrite(out.data(), 1, out.size(), stdout);
    }
    return EXIT_SUCCESS;
}

int run_callees_class(const Args& args, const Binary& b) {
    const auto classes = parse_itanium_rtti(b);
    const RttiClass* match = nullptr;
    for (const auto& c : classes) {
        if (c.mangled_name == args.callees_class ||
            c.demangled_name == args.callees_class) {
            match = &c;
            break;
        }
    }
    if (!match) {
        spelunk::diagnostic::print("spelunk: --callees-class: no RTTI class matching '{}'",
                     args.callees_class);
        return EXIT_FAILURE;
    }
    std::string out = std::format(
        "{{\"class\":\"{}\",\"mangled\":\"{}\",\"vtable\":\"{:#x}\",\"slots\":{{",
        json_escape(match->demangled_name),
        json_escape(match->mangled_name),
        match->vtable);
    for (std::size_t i = 0; i < match->methods.size(); ++i) {
        if (i) out += ',';
        out += std::format("\"{}\":{{\"va\":", i);
        const auto imp = match->methods[i];
        if (imp == 0) {
            out += "null,\"callees\":[]}";
            continue;
        }
        out += std::format("\"{:#x}\",\"callees\":[", imp);
        const auto cs = compute_classified_callees(b, imp);
        for (std::size_t j = 0; j < cs.size(); ++j) {
            if (j) out += ',';
            out += std::format("{{\"va\":\"{:#x}\",\"kind\":\"{}\"}}",
                               cs[j].target, callee_kind_name(cs[j].kind));
        }
        out += "]}";
    }
    out += "}}\n";
    std::fwrite(out.data(), 1, out.size(), stdout);
    return EXIT_SUCCESS;
}

}  // namespace spelunk::cli
