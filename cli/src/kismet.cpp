#include "kismet.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <optional>
#include <print>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <ember/analysis/kismet.hpp>
#include <ember/binary/kismet_bundle.hpp>
#include <ember/common/types.hpp>

#include "args.hpp"

namespace ember::cli {
namespace {

[[nodiscard]] std::string lower(std::string_view value) {
    std::string result(value);
    std::ranges::transform(result, result.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return result;
}

[[nodiscard]] std::string json_escape(std::string_view value) {
    std::string result;
    result.reserve(value.size() + 8);
    for (const char raw : value) {
        const auto c = static_cast<unsigned char>(raw);
        switch (c) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:
                if (c < 0x20) {
                    constexpr char hex[] = "0123456789abcdef";
                    result += "\\u00";
                    result += hex[c >> 4];
                    result += hex[c & 0x0f];
                } else {
                    result += static_cast<char>(c);
                }
        }
    }
    return result;
}

[[nodiscard]] std::vector<const KismetFunction*>
matching(const KismetBundle& bundle, std::string_view query) {
    std::vector<const KismetFunction*> result;
    const std::string needle = lower(query);
    for (const auto& function : bundle.functions()) {
        if (query.empty() || lower(function.function_path).contains(needle) ||
            lower(function.class_path).contains(needle) ||
            lower(function.id) == needle) {
            result.push_back(&function);
        }
    }
    return result;
}

}  // namespace

int run_kismet(const Args& args) {
    auto bundle = KismetBundle::load(args.kismet_bundle);
    if (!bundle) {
        std::println(stderr, "ember: --kismet: {}: {}",
                     bundle.error().kind_name(), bundle.error().message);
        return EXIT_FAILURE;
    }

    if (args.functions) {
        const auto matches = matching(*bundle, args.functions_pattern);
        if (args.json) {
            std::print("[\n");
            for (std::size_t i = 0; i < matches.size(); ++i) {
                const auto& function = *matches[i];
                std::print(
                    "  {{\"id\":\"{}\",\"bytes\":{},\"flags\":{},"
                    "\"class\":\"{}\",\"function\":\"{}\"}}{}\n",
                    json_escape(function.id), function.bytecode_size,
                    function.function_flags, json_escape(function.class_path),
                    json_escape(function.function_path),
                    i + 1 == matches.size() ? "" : ",");
            }
            std::print("]\n");
        } else {
            for (const KismetFunction* function : matches) {
                std::println("{}\t{}\t{}\t{}", function->id,
                             function->bytecode_size, function->class_path,
                             function->function_path);
            }
        }
        return EXIT_SUCCESS;
    }

    if (!args.disasm && !args.cfg && !args.cfg_pseudo && !args.pseudo &&
        !args.kismet_events) {
        std::println(stderr,
            "ember: --kismet requires --functions, -d/-c/-p, or --kismet-events");
        return EXIT_FAILURE;
    }
    if (args.symbol.empty()) {
        std::println(stderr, "ember: Kismet views require -s FUNCTION");
        return EXIT_FAILURE;
    }

    auto matches = matching(*bundle, args.symbol);
    if (matches.size() != 1) {
        std::println(stderr, "ember: --kismet: '{}' matched {} functions",
                     args.symbol, matches.size());
        for (std::size_t i = 0; i < std::min<std::size_t>(matches.size(), 12); ++i) {
            std::println(stderr, "  {}", matches[i]->function_path);
        }
        return EXIT_FAILURE;
    }

    const KismetFunction& function = *matches.front();
    auto bytecode = bundle->read_bytecode(function);
    if (!bytecode) {
        std::println(stderr, "ember: --kismet: {}: {}",
                     bytecode.error().kind_name(), bytecode.error().message);
        return EXIT_FAILURE;
    }
    auto disassembly = bundle->read_disassembly(function);
    if (!disassembly) {
        std::println(stderr, "ember: --kismet: {}: {}",
                     disassembly.error().kind_name(), disassembly.error().message);
        return EXIT_FAILURE;
    }

    auto cfg = parse_kismet_cfg(*disassembly);
    if (!cfg) {
        std::println(stderr, "ember: --kismet: {}: {}",
                     cfg.error().kind_name(), cfg.error().message);
        return EXIT_FAILURE;
    }

    std::vector<std::pair<std::string, std::string>> all_disassemblies;
    std::vector<KismetUbergraphEntry> entries;
    if (args.kismet_events || !args.kismet_event.empty()) {
        all_disassemblies.reserve(bundle->functions().size());
        for (const auto& candidate : bundle->functions()) {
            auto text = bundle->read_disassembly(candidate);
            if (!text) {
                std::println(stderr, "ember: --kismet: {}: {}",
                             text.error().kind_name(), text.error().message);
                return EXIT_FAILURE;
            }
            all_disassemblies.emplace_back(candidate.function_path, std::move(*text));
        }
        const std::string ubergraph_name = function.function_path.substr(
            function.function_path.rfind(':') + 1);
        entries = discover_kismet_ubergraph_entries(ubergraph_name, all_disassemblies);
    }

    if (args.kismet_events) {
        if (args.json) {
            std::print("[\n");
            for (std::size_t i = 0; i < entries.size(); ++i) {
                std::print("  {{\"offset\":{},\"offset_hex\":\"0x{:x}\","
                           "\"wrapper\":\"{}\"}}{}\n",
                           entries[i].offset, entries[i].offset,
                           json_escape(entries[i].wrapper_function),
                           i + 1 == entries.size() ? "" : ",");
            }
            std::print("]\n");
        } else {
            for (const auto& entry : entries) {
                std::println("0x{:x}\t{}", entry.offset, entry.wrapper_function);
            }
        }
        return EXIT_SUCCESS;
    }

    std::optional<ember::u64> selected_entry;
    std::string pseudo_name = function.function_path;
    if (!args.kismet_event.empty()) {
        const std::string needle = lower(args.kismet_event);
        std::vector<const KismetUbergraphEntry*> event_matches;
        for (const auto& entry : entries) {
            if (lower(entry.wrapper_function).contains(needle)) {
                event_matches.push_back(&entry);
            }
        }
        if (event_matches.size() != 1) {
            std::println(stderr, "ember: --kismet-event: '{}' matched {} wrappers",
                         args.kismet_event, event_matches.size());
            for (const auto* entry : event_matches) {
                std::println(stderr, "  0x{:x} {}", entry->offset,
                             entry->wrapper_function);
            }
            return EXIT_FAILURE;
        }
        selected_entry = event_matches.front()->offset;
        pseudo_name = event_matches.front()->wrapper_function;
    }

    if (args.cfg && !args.cfg_pseudo) {
        std::print("{}", emit_kismet_cfg(*cfg));
        return EXIT_SUCCESS;
    }
    if (args.pseudo || args.cfg_pseudo) {
        std::print("{}", emit_kismet_pseudocode(*cfg, pseudo_name, selected_entry));
        return EXIT_SUCCESS;
    }

    if (args.json) {
        std::println(
            "{{\"id\":\"{}\",\"bytes\":{},\"flags\":{},"
            "\"class\":\"{}\",\"function\":\"{}\","
            "\"engine\":\"{}\",\"pointer_size\":{},"
            "\"disassembly\":\"{}\"}}",
            json_escape(function.id), function.bytecode_size,
            function.function_flags, json_escape(function.class_path),
            json_escape(function.function_path),
            json_escape(bundle->engine_version()), bundle->pointer_size(),
            json_escape(*disassembly));
    } else {
        std::println("// Kismet {} ({} bytes, flags=0x{:x})",
                     function.function_path, function.bytecode_size,
                     function.function_flags);
        std::print("{}", *disassembly);
        if (disassembly->empty() || disassembly->back() != '\n') std::println();
    }
    return EXIT_SUCCESS;
}

}  // namespace ember::cli
