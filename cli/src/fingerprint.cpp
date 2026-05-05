#include "fingerprint.hpp"
#include "subcommands.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <format>
#include <fstream>
#include <optional>
#include <print>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <ember/analysis/fingerprint.hpp>
#include <ember/analysis/pipeline.hpp>
#include <ember/binary/binary.hpp>
#include <ember/common/cache.hpp>
#include <ember/common/progress.hpp>

#include "args.hpp"
#include "util.hpp"

namespace ember::cli {

std::string fingerprints_cache_tag() {
    return std::format("fingerprints-{}-o3", kFingerprintSchema);
}

std::string build_fingerprints_output(const Binary& b) {
    const bool show = progress_enabled();
    // Build a one-shot addr -> name map; previously this was an O(n²) linear
    // rescan per function which took minutes on large stripped binaries.
    if (show) {
        std::println(stderr, "ember: collecting named functions...");
        std::fflush(stderr);
    }
    std::unordered_map<addr_t, std::string> name_by_addr;
    for (const auto& s : b.symbols()) {
        if (s.is_import) continue;
        if (s.kind != SymbolKind::Function) continue;
        if (s.addr == 0 || s.name.empty()) continue;
        name_by_addr.try_emplace(s.addr, s.name);
    }

    if (show) {
        std::println(stderr, "ember: {} named functions; walking call graph "
                             "(this is the slow first step on big binaries)...",
                             name_by_addr.size());
        std::fflush(stderr);
    }
    const auto edges = compute_call_graph(b);
    if (show) {
        std::println(stderr, "ember: {} call edges discovered", edges.size());
        std::fflush(stderr);
    }

    std::set<addr_t> fns;
    for (const auto& [a, _] : name_by_addr) fns.insert(a);
    for (const auto& e : edges) {
        if (!b.import_at_plt(e.callee)) fns.insert(e.callee);
    }
    // On stripped binaries the symbol table and call graph are both empty.
    // Fall back to enumerate_functions so we still fingerprint discovered subs.
    // Zero-sized discovered `sub_*` entries are deliberately non-fingerprintable:
    // they are usually interior prologue-shaped addresses inside a real symbol.
    std::unordered_set<addr_t> zero_sized_discovered_subs;
    for (const auto& fn : enumerate_functions(b, EnumerateMode::Auto)) {
        if (fn.kind == DiscoveredFunction::Kind::Sub && fn.size == 0) {
            zero_sized_discovered_subs.insert(fn.addr);
            continue;
        }
        if (!b.import_at_plt(fn.addr)) fns.insert(fn.addr);
    }
    for (addr_t a : zero_sized_discovered_subs) {
        if (!name_by_addr.contains(a)) fns.erase(a);
    }

    struct Row {
        addr_t addr;
        u64 hash;
        u32 blocks;
        u32 insts;
        u32 calls;
        std::string name;
    };
    std::vector<Row> rows;
    rows.reserve(fns.size());

    const auto total = fns.size();
    std::size_t done = 0;
    const auto tick = std::max<std::size_t>(1, total / 40);
    if (show) {
        std::println(stderr, "ember: fingerprinting {} functions...", total);
        std::fflush(stderr);
    }

    for (addr_t a : fns) {
        const auto fp = compute_fingerprint(b, a);
        ++done;
        if (show && (done % tick == 0 || done == total)) {
            std::fprintf(stderr, "\r  [%zu/%zu]", done, total);
            std::fflush(stderr);
        }
        if (fp.hash == 0) continue;
        std::string name;
        if (auto it = name_by_addr.find(a); it != name_by_addr.end()) {
            name = it->second;
        } else {
            name = std::format("sub_{:x}", a);
        }
        rows.push_back(Row{a, fp.hash, fp.blocks, fp.insts, fp.calls,
                           std::move(name)});
    }
    if (show) std::fputc('\n', stderr);

    std::unordered_map<u64, u32> hash_count;
    hash_count.reserve(rows.size());
    for (const auto& r : rows) ++hash_count[r.hash];

    std::string out;
    for (const auto& r : rows) {
        out += std::format("{:x}\t{:016x}\t{}\t{}\t{}\t{}\t{}\n",
                           r.addr, r.hash, r.blocks, r.insts, r.calls,
                           hash_count[r.hash], r.name);
    }
    return out;
}

std::string fingerprints_cached_or_compute(const std::filesystem::path& binary_path,
                                           const std::filesystem::path& cache_dir,
                                           bool no_cache) {
    const std::string tag = fingerprints_cache_tag();
    std::string key;
    if (!no_cache) {
        auto k = cache::key_for(binary_path);
        if (k) key = std::move(*k);
    }
    if (!key.empty()) {
        if (auto hit = cache::read(cache_dir, key, tag); hit) {
            return std::move(*hit);
        }
    }
    auto bin = load_binary(binary_path);
    if (!bin) {
        std::println(stderr, "ember: {}: {}",
                     bin.error().kind_name(), bin.error().message);
        std::exit(EXIT_FAILURE);
    }
    std::string out = build_fingerprints_output(**bin);
    if (!key.empty()) {
        if (auto rv = cache::write(cache_dir, key, tag, out); !rv) {
            std::println(stderr, "ember: warning: {}: {}",
                         rv.error().kind_name(), rv.error().message);
        }
    }
    return out;
}

std::string fingerprints_tsv_for(const Args& args, const Binary& b) {
    const auto dir = args.cache_dir.empty()
        ? cache::default_dir()
        : std::filesystem::path(args.cache_dir);
    const std::string tag = fingerprints_cache_tag();
    if (!args.no_cache) {
        if (auto k = cache::key_for(args.binary, cache_scope_tag(args)); k) {
            if (auto hit = cache::read(dir, *k, tag); hit) {
                return std::move(*hit);
            }
        }
    }
    std::string out = build_fingerprints_output(b);
    if (!args.no_cache) {
        if (auto k = cache::key_for(args.binary, cache_scope_tag(args)); k) {
            if (auto rv = cache::write(dir, *k, tag, out); !rv) {
                std::println(stderr, "ember: warning: {}: {}",
                             rv.error().kind_name(), rv.error().message);
            }
        }
    }
    return out;
}

namespace {

struct FpEntry {
    addr_t addr = 0;
    std::string fp;
    std::string name;
    // Shape metadata retained for fuzzy-matching: two functions with the
    // same (blocks, insts, calls) triple are very likely the same function
    // edited by a few instructions across versions.
    u32 blocks = 0;
    u32 insts  = 0;
    u32 calls  = 0;
};

struct ParsedFps {
    std::unordered_map<std::string, std::vector<FpEntry>> by_fp;
    std::size_t total = 0;
};

// Parse the TSV that build_fingerprints_output produces:
//   <addr>\t<fp>\t<blocks>\t<insts>\t<calls>\t<collisions>\t<name>
[[nodiscard]] ParsedFps parse_fingerprints_tsv(const std::string& tsv) {
    ParsedFps out;
    std::size_t pos = 0;
    while (pos < tsv.size()) {
        const auto nl = tsv.find('\n', pos);
        const std::size_t end = (nl == std::string::npos) ? tsv.size() : nl;
        const std::string_view line(tsv.data() + pos, end - pos);
        pos = (nl == std::string::npos) ? tsv.size() : nl + 1;
        if (line.empty() || line.front() == '#') continue;
        std::array<std::string_view, 7> f{};
        std::size_t s = 0, fi = 0;
        for (std::size_t i = 0; i <= line.size() && fi < f.size(); ++i) {
            if (i == line.size() || line[i] == '\t') {
                f[fi++] = line.substr(s, i - s);
                s = i + 1;
            }
        }
        if (fi < 7) continue;
        addr_t addr = 0;
        const auto r = std::from_chars(f[0].data(),
                                       f[0].data() + f[0].size(), addr, 16);
        if (r.ec != std::errc{}) continue;
        auto parse_u32 = [](std::string_view sv) -> u32 {
            u32 v = 0;
            std::from_chars(sv.data(), sv.data() + sv.size(), v, 10);
            return v;
        };
        out.by_fp[std::string{f[1]}].push_back(FpEntry{
            addr,
            std::string{f[1]},
            std::string{f[6]},
            parse_u32(f[2]),
            parse_u32(f[3]),
            parse_u32(f[4]),
        });
        ++out.total;
    }
    return out;
}

// Fuzzy-pair unmatched "removed" and "added" entries. Two heuristics,
// applied in order:
//   1. Exact-name match across versions — obvious case of "same named
//      function, body differs by a few instructions". Tagged `edited`.
//   2. Shape proximity — equal (blocks, insts, calls) tuple plus (sub_*
//      in both OR close hash-prefix). Tagged `fuzzy`.
struct FuzzyPair {
    FpEntry old_e;
    FpEntry new_e;
    const char* tag;  // "edited" or "fuzzy"
};

[[nodiscard]] std::vector<FuzzyPair>
fuzzy_pair(std::vector<FpEntry>& removed, std::vector<FpEntry>& added) {
    std::vector<FuzzyPair> out;
    auto is_sub = [](std::string_view n) {
        return n.starts_with("sub_");
    };
    std::vector<bool> rm_taken(removed.size(), false);
    std::vector<bool> ad_taken(added.size(),   false);
    // Pass 1: name equality.
    for (std::size_t i = 0; i < removed.size(); ++i) {
        if (is_sub(removed[i].name)) continue;
        for (std::size_t j = 0; j < added.size(); ++j) {
            if (ad_taken[j]) continue;
            if (added[j].name != removed[i].name) continue;
            out.push_back({removed[i], added[j], "edited"});
            rm_taken[i] = true;
            ad_taken[j] = true;
            break;
        }
    }
    // Pass 2: shape proximity on sub_* pairs. Both sides must be sub_*
    // (named collisions were handled in pass 1), same shape tuple, and a
    // shared 4-hex-char fingerprint prefix — that's a generous-but-sane
    // signal that they started as the same function.
    for (std::size_t i = 0; i < removed.size(); ++i) {
        if (rm_taken[i]) continue;
        if (!is_sub(removed[i].name)) continue;
        std::size_t best = std::size_t(-1);
        for (std::size_t j = 0; j < added.size(); ++j) {
            if (ad_taken[j]) continue;
            if (!is_sub(added[j].name)) continue;
            if (added[j].blocks != removed[i].blocks) continue;
            if (added[j].insts  != removed[i].insts)  continue;
            if (added[j].calls  != removed[i].calls)  continue;
            if (removed[i].fp.size() < 4 || added[j].fp.size() < 4) continue;
            if (removed[i].fp.substr(0, 4) != added[j].fp.substr(0, 4)) continue;
            best = j;
            break;
        }
        if (best != std::size_t(-1)) {
            out.push_back({removed[i], added[best], "fuzzy"});
            rm_taken[i] = true;
            ad_taken[best] = true;
        }
    }
    std::vector<FpEntry> rm_left, ad_left;
    rm_left.reserve(removed.size());
    ad_left.reserve(added.size());
    for (std::size_t i = 0; i < removed.size(); ++i)
        if (!rm_taken[i]) rm_left.push_back(std::move(removed[i]));
    for (std::size_t j = 0; j < added.size(); ++j)
        if (!ad_taken[j]) ad_left.push_back(std::move(added[j]));
    removed = std::move(rm_left);
    added   = std::move(ad_left);
    return out;
}

struct DiffBuckets {
    std::vector<std::pair<FpEntry, FpEntry>> kept;   // same addr + name
    std::vector<std::pair<FpEntry, FpEntry>> moved;  // same fp, different addr/name
    std::vector<FpEntry>                     added_left;
    std::vector<FpEntry>                     removed_left;
};

[[nodiscard]] DiffBuckets
bucket_exact(const ParsedFps& old_p, const ParsedFps& new_p) {
    DiffBuckets b;
    for (const auto& [fp, nvec] : new_p.by_fp) {
        const auto it = old_p.by_fp.find(fp);
        if (it == old_p.by_fp.end()) {
            for (const auto& ne : nvec) b.added_left.push_back(ne);
            continue;
        }
        const auto& ovec = it->second;
        const auto pairs = std::min(ovec.size(), nvec.size());
        for (std::size_t i = 0; i < pairs; ++i) {
            const auto& oe = ovec[i];
            const auto& ne = nvec[i];
            if (oe.addr == ne.addr && oe.name == ne.name) b.kept.emplace_back(oe, ne);
            else                                           b.moved.emplace_back(oe, ne);
        }
        for (std::size_t i = pairs; i < nvec.size(); ++i) b.added_left.push_back(nvec[i]);
        for (std::size_t i = pairs; i < ovec.size(); ++i) b.removed_left.push_back(ovec[i]);
    }
    for (const auto& [fp, ovec] : old_p.by_fp) {
        if (new_p.by_fp.contains(fp)) continue;
        for (const auto& oe : ovec) b.removed_left.push_back(oe);
    }
    return b;
}

// Diff two fingerprint maps. Output is one TSV row per function pairing:
//   kept     <fp> <old_addr> <new_addr> <old_name> <new_name>
//   moved    <fp> <old_addr> <new_addr> <old_name> <new_name>
//   added    <fp> -          <new_addr> -          <new_name>
//   removed  <fp> <old_addr> -          <old_name> -
//   edited   <fp_old>>< fp_new> <old>   <new>     <name>    <name>
//   fuzzy    <fp_old>>< fp_new> <old>   <new>     <name>    <name>
[[nodiscard]] std::string
format_diff(const ParsedFps& old_p, const ParsedFps& new_p,
            const std::string& old_label, const std::string& new_label) {
    auto b = bucket_exact(old_p, new_p);
    auto fuzzy = fuzzy_pair(b.removed_left, b.added_left);

    std::string body;
    auto emit = [&](std::string_view tag,
                    const FpEntry* oe, const FpEntry* ne,
                    std::string_view fp) {
        body += std::format("{}\t{}\t{}\t{}\t{}\t{}\n",
            tag, fp,
            oe ? std::format("{:x}", oe->addr) : std::string{"-"},
            ne ? std::format("{:x}", ne->addr) : std::string{"-"},
            oe ? oe->name                      : std::string{"-"},
            ne ? ne->name                      : std::string{"-"});
    };
    for (const auto& [oe, ne] : b.kept)   emit("kept",  &oe, &ne, oe.fp);
    for (const auto& [oe, ne] : b.moved)  emit("moved", &oe, &ne, oe.fp);
    for (const auto& p : fuzzy)           emit(p.tag, &p.old_e, &p.new_e,
                                               std::format("{}>{}", p.old_e.fp.substr(0, 4),
                                                           p.new_e.fp.substr(0, 4)));
    for (const auto& ne : b.added_left)   emit("added",   nullptr, &ne, ne.fp);
    for (const auto& oe : b.removed_left) emit("removed", &oe, nullptr, oe.fp);

    std::size_t edited = 0, fuz = 0;
    for (const auto& p : fuzzy) {
        if (std::string_view(p.tag) == "edited") ++edited; else ++fuz;
    }

    std::string out;
    out += std::format("# ember diff\n");
    out += std::format("# old: {} ({} functions)\n", old_label, old_p.total);
    out += std::format("# new: {} ({} functions)\n", new_label, new_p.total);
    out += std::format(
        "# summary: kept={} moved={} edited={} fuzzy={} added={} removed={}\n",
        b.kept.size(), b.moved.size(), edited, fuz,
        b.added_left.size(), b.removed_left.size());
    out += "# columns: tag\tfp\told_addr\tnew_addr\told_name\tnew_name\n";
    out += body;
    return out;
}

[[nodiscard]] std::string
format_diff_json(const ParsedFps& old_p, const ParsedFps& new_p,
                 const std::string& old_label, const std::string& new_label) {
    auto b = bucket_exact(old_p, new_p);
    auto fuzzy = fuzzy_pair(b.removed_left, b.added_left);

    std::string body;
    auto emit = [&](std::string_view tag, std::string_view fp,
                    std::optional<addr_t> old_addr,
                    std::optional<addr_t> new_addr,
                    std::string_view old_name, std::string_view new_name) {
        if (!body.empty()) body += ",\n";
        body += std::format(
            "  {{\"tag\":\"{}\",\"fp\":\"{}\","
            "\"old_addr\":{},\"new_addr\":{},"
            "\"old_name\":\"{}\",\"new_name\":\"{}\"}}",
            tag, fp,
            old_addr ? std::format("\"{:#x}\"", *old_addr) : std::string{"null"},
            new_addr ? std::format("\"{:#x}\"", *new_addr) : std::string{"null"},
            json_escape(old_name), json_escape(new_name));
    };
    for (const auto& [oe, ne] : b.kept)
        emit("kept",  oe.fp, oe.addr, ne.addr, oe.name, ne.name);
    for (const auto& [oe, ne] : b.moved)
        emit("moved", oe.fp, oe.addr, ne.addr, oe.name, ne.name);
    for (const auto& p : fuzzy) {
        const std::string fp_tag = std::format("{}>{}",
            p.old_e.fp.substr(0, 4), p.new_e.fp.substr(0, 4));
        emit(p.tag, fp_tag, p.old_e.addr, p.new_e.addr, p.old_e.name, p.new_e.name);
    }
    for (const auto& ne : b.added_left)
        emit("added",   ne.fp, std::nullopt, ne.addr, "",      ne.name);
    for (const auto& oe : b.removed_left)
        emit("removed", oe.fp, oe.addr, std::nullopt, oe.name, "");

    std::size_t edited = 0, fuz = 0;
    for (const auto& p : fuzzy) {
        if (std::string_view(p.tag) == "edited") ++edited; else ++fuz;
    }

    std::string out;
    out += "{\n";
    out += std::format("  \"old\": {{\"path\":\"{}\",\"functions\":{}}},\n",
                       json_escape(old_label), old_p.total);
    out += std::format("  \"new\": {{\"path\":\"{}\",\"functions\":{}}},\n",
                       json_escape(new_label), new_p.total);
    out += std::format(
        "  \"summary\": {{\"kept\":{},\"moved\":{},\"edited\":{},\"fuzzy\":{},\"added\":{},\"removed\":{}}},\n",
        b.kept.size(), b.moved.size(), edited, fuz,
        b.added_left.size(), b.removed_left.size());
    out += "  \"entries\": [\n";
    out += body;
    out += "\n  ]\n}\n";
    return out;
}

[[nodiscard]] std::string slurp_file(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return {};
    const auto n = f.tellg();
    if (n < 0) return {};
    f.seekg(0, std::ios::beg);
    std::string s;
    s.resize(static_cast<std::size_t>(n));
    if (!s.empty()) f.read(s.data(), static_cast<std::streamsize>(s.size()));
    if (!f && !f.eof()) return {};
    return s;
}

}  // namespace

std::vector<FingerprintRow>
fingerprint_rows_from_tsv(std::string_view tsv) {
    std::vector<FingerprintRow> out;
    std::size_t pos = 0;
    while (pos < tsv.size()) {
        const auto nl = tsv.find('\n', pos);
        const std::size_t end = (nl == std::string_view::npos) ? tsv.size() : nl;
        const std::string_view line = tsv.substr(pos, end - pos);
        pos = (nl == std::string_view::npos) ? tsv.size() : nl + 1;
        if (line.empty() || line.front() == '#') continue;

        std::array<std::string_view, 7> f{};
        std::size_t s = 0, fi = 0;
        for (std::size_t i = 0; i <= line.size() && fi < f.size(); ++i) {
            if (i == line.size() || line[i] == '\t') {
                f[fi++] = line.substr(s, i - s);
                s = i + 1;
            }
        }
        if (fi < 7) continue;
        addr_t addr = 0;
        if (auto r = std::from_chars(f[0].data(),
                                     f[0].data() + f[0].size(), addr, 16);
            r.ec != std::errc{}) continue;
        u64 hash = 0;
        if (auto r = std::from_chars(f[1].data(),
                                     f[1].data() + f[1].size(), hash, 16);
            r.ec != std::errc{}) continue;
        auto parse_u32 = [](std::string_view sv) -> u32 {
            u32 v = 0;
            std::from_chars(sv.data(), sv.data() + sv.size(), v, 10);
            return v;
        };
        FingerprintRow row;
        row.addr      = addr;
        row.fp.hash   = hash;
        row.fp.blocks = parse_u32(f[2]);
        row.fp.insts  = parse_u32(f[3]);
        row.fp.calls  = parse_u32(f[4]);
        row.name      = std::string{f[6]};
        out.push_back(std::move(row));
    }
    return out;
}

int run_diff(const Args& args) {
    const auto cache_dir = args.cache_dir.empty()
        ? cache::default_dir()
        : std::filesystem::path(args.cache_dir);

    // Pre-computed fingerprint TSVs via --fingerprint-old / --fingerprint-new
    // skip the lift-SSA-cleanup pipeline entirely. Useful for iterative
    // version diffs: export v717 once, then diff v717→v718 / v718→v719 /
    // … against that stored TSV without recomputing v717.
    std::string old_tsv, new_tsv;
    std::string old_label = args.diff_path;
    std::string new_label = args.binary;

    if (!args.fp_old_in.empty()) {
        old_tsv = slurp_file(args.fp_old_in);
        if (old_tsv.empty()) {
            std::println(stderr, "ember: --fingerprint-old: cannot read '{}'",
                         args.fp_old_in);
            return EXIT_FAILURE;
        }
        old_label = args.fp_old_in;
    }
    if (!args.fp_new_in.empty()) {
        new_tsv = slurp_file(args.fp_new_in);
        if (new_tsv.empty()) {
            std::println(stderr, "ember: --fingerprint-new: cannot read '{}'",
                         args.fp_new_in);
            return EXIT_FAILURE;
        }
        new_label = args.fp_new_in;
    }

    if (old_tsv.empty()) {
        if (args.diff_path.empty()) {
            std::println(stderr, "ember: --diff needs --fingerprint-old PATH or --diff OLD_BINARY");
            return EXIT_FAILURE;
        }
        std::println(stderr, "ember: diff OLD={}", args.diff_path);
        old_tsv = fingerprints_cached_or_compute(args.diff_path, cache_dir, args.no_cache);
    }
    if (new_tsv.empty()) {
        if (args.binary.empty()) {
            std::println(stderr, "ember: --diff needs --fingerprint-new PATH or a positional binary");
            return EXIT_FAILURE;
        }
        std::println(stderr, "ember: diff NEW={}", args.binary);
        new_tsv = fingerprints_cached_or_compute(args.binary, cache_dir, args.no_cache);
    }
    const auto old_p = parse_fingerprints_tsv(old_tsv);
    const auto new_p = parse_fingerprints_tsv(new_tsv);
    const std::string out = (args.diff_format == "json")
        ? format_diff_json(old_p, new_p, old_label, new_label)
        : format_diff     (old_p, new_p, old_label, new_label);
    std::fwrite(out.data(), 1, out.size(), stdout);
    return EXIT_SUCCESS;
}

}  // namespace ember::cli
