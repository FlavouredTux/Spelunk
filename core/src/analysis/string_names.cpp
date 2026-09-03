// Function-name inference from string references: assertion, reflection,
// logging and engine-feature anchors that name their enclosing function.

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <format>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <ember/analysis/cfg_builder.hpp>
#include <ember/analysis/demangle.hpp>
#include <ember/analysis/pipeline.hpp>
#include <ember/analysis/strings.hpp>
#include <ember/binary/binary.hpp>
#include <ember/binary/section.hpp>
#include <ember/binary/symbol.hpp>
#include <ember/common/timing.hpp>
#include <ember/common/types.hpp>
#include <ember/disasm/decoder.hpp>
#include <ember/ir/abi.hpp>
#include <ember/ir/ir.hpp>
#include <ember/ir/lifter.hpp>
#include <ember/ir/passes.hpp>
#include <ember/ir/ssa.hpp>

#include "string_names_internal.hpp"
#include "strings_internal.hpp"

namespace ember::string_names {

namespace {

[[nodiscard]] bool good_name(std::string_view s) noexcept {
    if (s.size() < 4 || s.size() > 192) return false;
    if (s.starts_with("sub_")) return false;
    bool has_alpha = false;
    for (char c : s) {
        const auto u = static_cast<unsigned char>(c);
        if (std::isalpha(u)) has_alpha = true;
        if (!(std::isalnum(u) || c == '_' || c == ':' || c == '[' || c == ']' ||
              c == '-' || c == '+' || c == ' ')) {
            return false;
        }
    }
    return has_alpha;
}

[[nodiscard]] bool
demangled_name_needs_itanium_special_fallback(std::string_view name) noexcept {
    if (name.find("::~") != std::string_view::npos) return true;
    const auto last = name.rfind("::");
    if (last == std::string_view::npos || last + 2 >= name.size()) return false;
    const auto prev = name.rfind("::", last == 0 ? 0 : last - 1);
    const auto owner_start = prev == std::string_view::npos ? 0 : prev + 2;
    const auto owner = name.substr(owner_start, last - owner_start);
    const auto leaf = name.substr(last + 2);
    return !owner.empty() && owner == leaf;
}

[[nodiscard]] bool is_known_c_type_token(std::string_view tok) noexcept {
    return tok == "void" || tok == "bool" || tok == "char" ||
           tok == "short" || tok == "int" || tok == "long" ||
           tok == "float" || tok == "double" || tok == "size_t" ||
           tok == "ssize_t" || tok == "auto" || tok == "static" ||
           tok == "const" || tok == "volatile" || tok == "signed" ||
           tok == "unsigned" || tok == "struct" || tok == "class" ||
           tok == "enum" || tok == "BOOL" || tok == "id" ||
           tok.starts_with("uint") || tok.starts_with("int");
}

[[nodiscard]] std::optional<std::string>
reflection_owner_component(std::string_view enc) {
    std::vector<std::string> parts;
    if (!enc.empty() && enc.front() == 'N') {
        std::size_t pos = 1;
        while (pos < enc.size() && enc[pos] != 'E') {
            if (enc.substr(pos).starts_with("S_")) {
                pos += 2;
                continue;
            }
            if (!std::isdigit(static_cast<unsigned char>(enc[pos]))) break;
            std::size_t len = 0;
            while (pos < enc.size() && std::isdigit(static_cast<unsigned char>(enc[pos]))) {
                len = len * 10 + static_cast<std::size_t>(enc[pos] - '0');
                ++pos;
                if (len > 256) return std::nullopt;
            }
            if (len == 0 || pos + len > enc.size()) return std::nullopt;
            parts.emplace_back(enc.substr(pos, len));
            pos += len;
        }
    } else if (!enc.empty() &&
               std::isdigit(static_cast<unsigned char>(enc.front()))) {
        std::size_t pos = 0;
        std::size_t len = 0;
        while (pos < enc.size() && std::isdigit(static_cast<unsigned char>(enc[pos]))) {
            len = len * 10 + static_cast<std::size_t>(enc[pos] - '0');
            ++pos;
            if (len > 256) return std::nullopt;
        }
        if (len == 0 || pos + len > enc.size()) return std::nullopt;
        parts.emplace_back(enc.substr(pos, len));
    }
    if (parts.empty()) return std::nullopt;
    auto owner = sanitize_name(parts.back());
    if (owner.empty()) return std::nullopt;
    return owner;
}

struct ReflectionDescriptorNameParts {
    std::string owner;
    std::string_view marker;
    std::string_view tag;
    std::string arity;
    bool include_arity = false;
};

[[nodiscard]] std::string reflection_descriptor_arity(std::string_view text) {
    if (const auto a = text.rfind("ELi"); a != std::string_view::npos) {
        std::size_t pos = a + 3;
        std::size_t end = pos;
        while (end < text.size() &&
               std::isdigit(static_cast<unsigned char>(text[end]))) {
            ++end;
        }
        if (end > pos && end < text.size() && text[end] == 'E') {
            return std::string{text.substr(pos, end - pos)};
        }
    }
    return "n";
}

[[nodiscard]] std::optional<ReflectionDescriptorNameParts>
parse_reflection_descriptor_name_parts(std::string_view text) {
    struct Marker {
        std::string_view token;
        std::string_view tag;
        bool include_arity;
    };
    for (const auto& marker : {
        Marker{"BoundYieldFuncDescI", "yield_func", true},
        Marker{"CustomBoundFuncDescI", "bound_func", true},
        Marker{"BoundFuncDescI", "bound_func", true},
        Marker{"RemoteEventDescI", "remote_event", false},
        Marker{"EventDescI", "event", false},
        Marker{"EnumPropDescriptorI", "enum_property", false},
        Marker{"RefPropDescriptorI", "ref_property", false},
        Marker{"PropDescriptorI", "property", false},
        Marker{"TypedPropertyDescriptorI", "typed_property", false},
        Marker{"EnumDescI", "enum", false},
        Marker{"TTypeI", "type", false},
    }) {
        const auto p = text.find(marker.token);
        if (p == std::string_view::npos) continue;
        auto owner = reflection_owner_component(text.substr(p + marker.token.size()));
        if (!owner) continue;
        return ReflectionDescriptorNameParts{
            .owner = std::move(*owner),
            .marker = marker.token,
            .tag = marker.tag,
            .arity = marker.include_arity ? reflection_descriptor_arity(text) : "",
            .include_arity = marker.include_arity,
        };
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::string>
reflection_descriptor_candidate_name(const ReflectionDescriptorNameParts& parts,
                                     std::optional<std::string_view> member) {
    std::string name = "reflection_" + parts.owner + "_";
    if (member && !member->empty()) {
        name += std::string{*member} + "_";
    }
    name += std::string{parts.tag};
    if (parts.include_arity) {
        name += "_argc_" + parts.arity;
    }
    if (auto n = sanitize_name(name); !n.empty()) return n;
    return std::nullopt;
}

[[nodiscard]] std::optional<std::string>
reflection_bound_descriptor_name(std::string_view text) {
    auto parts = parse_reflection_descriptor_name_parts(text);
    if (!parts) return std::nullopt;
    if (!parts->include_arity) return std::nullopt;
    return reflection_descriptor_candidate_name(*parts, std::nullopt);
}

[[nodiscard]] bool looks_like_reflection_member_name(std::string_view text) noexcept {
    if (text.size() < 2 || text.size() > 96) return false;
    if (!(std::isalpha(static_cast<unsigned char>(text.front())) ||
          text.front() == '_')) {
        return false;
    }
    if (text.starts_with("__")) return false;
    if (text.find("DescI") != std::string_view::npos ||
        text.find("Reflection") != std::string_view::npos ||
        text.find("::") != std::string_view::npos) {
        return false;
    }

    bool alpha = false;
    for (char c : text) {
        const auto u = static_cast<unsigned char>(c);
        if (std::isalpha(u)) alpha = true;
        if (!(std::isalnum(u) || c == '_')) return false;
    }
    return alpha;
}

[[nodiscard]] std::optional<std::string>
candidate_name_from_string(std::string_view text) {
    // Source-level block names often survive as strings even when the invoke
    // function itself is anonymous, e.g. "-[Cls doIt:]_block_invoke" or
    // "void Ns::Type::method(...)_block_invoke". Keep the suffix so these do
    // not collapse onto the enclosing method's name.
    if (const auto block_pos = text.find("_block_invoke");
        block_pos != std::string_view::npos) {
        std::string_view head = text.substr(0, block_pos);
        if (const auto objc_start = head.rfind("-[");
            objc_start != std::string_view::npos) {
            if (auto n = sanitize_name(head.substr(objc_start)); !n.empty()) {
                n += "_block_invoke";
                return n;
            }
        }
        if (const auto objc_start = head.rfind("+[");
            objc_start != std::string_view::npos) {
            if (auto n = sanitize_name(head.substr(objc_start)); !n.empty()) {
                n += "_block_invoke";
                return n;
            }
        }
        if (const auto scope = head.rfind("::");
            scope != std::string_view::npos) {
            std::size_t start = scope;
            while (start > 0) {
                const char c = head[start - 1];
                if (!(is_ident_char(c) || c == ':')) break;
                --start;
            }
            if (auto n = sanitize_name(head.substr(start)); !n.empty()) {
                n += "_block_invoke";
                return n;
            }
        }
    }

    // ObjC bracket form inside logs: "-[Class selector:]" or "+[Class sel]".
    for (std::size_t i = 0; i + 3 < text.size(); ++i) {
        if ((text[i] != '-' && text[i] != '+') || text[i + 1] != '[') continue;
        const auto end = text.find(']', i + 2);
        if (end == std::string_view::npos || end <= i + 3) continue;
        if (auto n = sanitize_name(text.substr(i, end - i + 1)); !n.empty()) return n;
    }

    if (auto n = reflection_bound_descriptor_name(text)) return n;
    if (auto n = graphics_api_name_from_string(text)) return n;
    if (auto n = graphics_phrase_name_from_string(text)) return n;

    // Itanium encodings embedded inside RTTI / std::function / lambda
    // metadata strings often carry a source function name even after the
    // symbol table is stripped. The common shape is a larger type encoding
    // containing `Z<function-encoding>`, for example
    // `...IZN7Example6Worker3runEvE...`.
    for (std::size_t i = 0; i + 2 < text.size(); ++i) {
        if (text[i] != 'Z') continue;
        if (text[i + 1] != 'N' &&
            text[i + 1] != 'L' &&
            !(i + 2 < text.size() && text[i + 1] == 'Z' && text[i + 2] == 'N') &&
            !(i + 2 < text.size() && text[i + 1] == 'Z' && text[i + 2] == 'L') &&
            !(i + 2 < text.size() && text[i + 1] == 'Z' &&
              std::isdigit(static_cast<unsigned char>(text[i + 2]))) &&
            !std::isdigit(static_cast<unsigned char>(text[i + 1]))) {
            continue;
        }
        std::string mangled = "_";
        mangled += text.substr(i);
        auto demangled = demangle_itanium(mangled);
        if (!demangled) {
            if (auto n = itanium_embedded_function_name_prefix(text.substr(i))) return n;
            continue;
        }
        auto base = strip_signature_suffix(*demangled);
        if (!base.contains("::")) {
            if (auto n = itanium_embedded_function_name_prefix(text.substr(i))) return n;
            continue;
        }
        if (base.starts_with("std::") || base.starts_with("__cxxabiv1::")) {
            if (auto n = itanium_embedded_function_name_prefix(text.substr(i))) return n;
            continue;
        }
        base = normalize_operator_name(base);
        if (demangled_name_needs_itanium_special_fallback(base)) {
            if (auto n = itanium_embedded_function_name_prefix(text.substr(i))) return n;
        }
        if (auto n = sanitize_name(base); !n.empty()) return n;
        if (auto n = itanium_embedded_function_name_prefix(text.substr(i))) return n;
    }

    // C++/namespace-ish tokens from logs: "Core::Player::step failed".
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (!is_ident_char(text[i])) continue;
        std::size_t j = i;
        while (j < text.size() &&
               (is_ident_char(text[j]) || (j + 1 < text.size() && text[j] == ':' && text[j + 1] == ':'))) {
            if (text[j] == ':') j += 2;
            else ++j;
        }
        const auto tok = text.substr(i, j - i);
        if (tok.find("::") != std::string_view::npos) {
            if (i > 0 && text[i - 1] == '[' &&
                j < text.size() && text[j] == ']') {
                i = j;
                continue;
            }
            if (tok.ends_with("::operator")) {
                if (auto suffix = operator_suffix_token(text, j)) {
                    if (auto n = sanitize_name(std::string(tok) + "_" + *suffix);
                        !n.empty()) {
                        return n;
                    }
                }
            }
            if (tok.ends_with("::") && j < text.size() && text[j] == '~') {
                const std::size_t name_start = j + 1;
                std::size_t name_end = name_start;
                while (name_end < text.size() && is_ident_char(text[name_end])) {
                    ++name_end;
                }
                if (name_end > name_start) {
                    std::string dtor = std::string(tok) + "dtor_" +
                                       std::string(text.substr(name_start,
                                                              name_end - name_start));
                    if (auto n = sanitize_name(dtor); !n.empty()) return n;
                }
            }
            if (auto n = sanitize_name(tok); !n.empty()) return n;
        }
        i = j;
    }

    // C/C++ compiler-provided function strings: `__PRETTY_FUNCTION__`,
    // assertion runtimes, and some logging macros preserve signatures such as
    // "static int recoverCachedValue(int)" even after symbols are stripped.
    if (auto n = c_pretty_function_name(text)) return n;

    // Prefix form: "recover_player_name: bad state" / "recover_player_name failed".
    const auto stop = text.find_first_of(":(");
    if (stop != std::string_view::npos && stop >= 4 && stop <= 80) {
        const auto prefix = text.substr(0, stop);
        bool all_ident = true;
        for (char c : prefix) {
            if (!is_ident_char(c)) { all_ident = false; break; }
        }
        if (all_ident) {
            if (auto n = sanitize_name(prefix); !n.empty()) return n;
        }
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::size_t>
function_name_arg_index(std::string_view callee) noexcept {
    // glibc: __assert_fail(assertion, file, line, function)
    if (callee == "__assert_fail") return 3;
    // Darwin libc: __assert_rtn(function, file, line, expression)
    if (callee == "__assert_rtn") return 0;
    return std::nullopt;
}

[[nodiscard]] bool has_function_name_assert_import(const Binary& b) {
    for (const auto& sym : b.symbols()) {
        if (!sym.is_import) continue;
        if (function_name_arg_index(strip_import_name_decorations(sym.name))) return true;
    }
    return false;
}

[[nodiscard]] std::string read_cstring_local(const Binary& b, addr_t va) {
    auto bytes = b.bytes_at(va);
    std::string s;
    for (auto by : bytes) {
        const auto c = static_cast<unsigned char>(by);
        if (c == 0) break;
        if (!is_string_byte(c)) return {};
        s.push_back(static_cast<char>(c));
        if (s.size() > kMaxStringLen) return {};
    }
    return s.size() >= kMinStringLen ? s : std::string{};
}

[[nodiscard]] std::optional<u64>
read_u64_from_section(const Section& sec, std::size_t off) noexcept {
    if (off + 8 > sec.data.size()) return std::nullopt;
    const auto* p = reinterpret_cast<const unsigned char*>(sec.data.data() + off);
    u64 v = 0;
    for (unsigned i = 0; i < 8; ++i) v |= static_cast<u64>(p[i]) << (i * 8);
    return v;
}

[[nodiscard]] bool contains_executable_byte(const Binary& b, addr_t va) noexcept {
    for (const auto& sec : b.sections()) {
        if (!sec.flags.executable || sec.data.empty()) continue;
        if (va >= sec.vaddr && va < sec.vaddr + sec.data.size()) return true;
    }
    return false;
}

[[nodiscard]] bool looks_like_lua_reg_key(std::string_view s) noexcept {
    if (s.empty() || s.size() > 80) return false;
    bool useful = false;
    for (char c : s) {
        const auto u = static_cast<unsigned char>(c);
        if (std::isalpha(u) || c == '_') useful = true;
        if (!(std::isalnum(u) || c == '_' || c == '.' || c == ':')) {
            return false;
        }
    }
    return useful;
}

[[nodiscard]] std::string lua_cfunc_name(std::string_view key) {
    return sanitize_name(std::string{"lua_cfunc_"} + std::string{key});
}

void infer_lua_registration_names(const Binary& b,
                                  std::span<const StringEntry> strings,
                                  std::vector<StringNameCandidate>& out,
                                  std::set<std::pair<addr_t, std::string>>& seen) {
    if (strings.empty()) return;

    std::map<addr_t, std::string_view> strings_by_addr;
    for (const auto& s : strings) {
        if (looks_like_lua_reg_key(s.text)) {
            strings_by_addr.emplace(s.addr, std::string_view{s.text});
        }
    }
    if (strings_by_addr.empty()) return;

    struct RegEntry {
        std::string_view key;
        addr_t           fn = 0;
    };

    for (const auto& sec : b.sections()) {
        if (sec.data.size() < 32) continue;
        if (!sec.flags.readable || sec.flags.executable) continue;

        const std::size_t align_skip =
            static_cast<std::size_t>((8 - (sec.vaddr & 7)) & 7);
        for (std::size_t off = align_skip; off + 16 <= sec.data.size(); off += 8) {
            std::vector<RegEntry> entries;
            bool terminated = false;
            std::size_t pos = off;
            for (; pos + 16 <= sec.data.size() && entries.size() < 256; pos += 16) {
                const auto name_va = read_u64_from_section(sec, pos);
                const auto fn_va = read_u64_from_section(sec, pos + 8);
                if (!name_va || !fn_va) break;
                if (*name_va == 0 && *fn_va == 0) {
                    terminated = true;
                    break;
                }
                if (*name_va == 0 || *fn_va == 0) break;
                const auto str_it = strings_by_addr.find(static_cast<addr_t>(*name_va));
                if (str_it == strings_by_addr.end()) break;
                const addr_t fn = static_cast<addr_t>(*fn_va);
                if (!contains_executable_byte(b, fn)) break;
                if (b.import_at_plt(fn) != nullptr) break;
                entries.push_back({str_it->second, fn});
            }
            if (!terminated || entries.empty()) continue;

            for (const auto& e : entries) {
                auto name = lua_cfunc_name(e.key);
                if (name.empty()) continue;
                if (seen.emplace(e.fn, name).second) {
                    out.push_back({e.fn, std::move(name),
                                   std::string{"luaL_Reg:"} + std::string{e.key}});
                }
            }
            off = pos;
        }
    }
}

template <class EnclosingFunction>
void infer_reflection_member_names(
    std::span<const StringEntry> strings,
    EnclosingFunction enclosing_function,
    std::vector<StringNameCandidate>& out,
    std::set<std::pair<addr_t, std::string>>& seen) {
    struct DescriptorRef {
        const StringEntry* entry = nullptr;
        addr_t             xref = 0;
        ReflectionDescriptorNameParts parts;
    };
    struct MemberRef {
        const StringEntry* entry = nullptr;
        addr_t             xref = 0;
    };
    struct FunctionRefs {
        std::vector<DescriptorRef> descriptors;
        std::vector<MemberRef>     members;
    };

    std::map<addr_t, FunctionRefs> by_function;
    for (const auto& s : strings) {
        if (s.xrefs.empty()) continue;
        const auto parts = parse_reflection_descriptor_name_parts(s.text);
        const bool member = !parts && looks_like_reflection_member_name(s.text);
        if (!parts && !member) continue;

        for (addr_t xr : s.xrefs) {
            if (auto fn = enclosing_function(xr)) {
                auto& refs = by_function[*fn];
                if (parts) {
                    refs.descriptors.push_back({&s, xr, *parts});
                } else {
                    refs.members.push_back({&s, xr});
                }
            }
        }
    }

    for (auto& [fn, refs] : by_function) {
        if (refs.descriptors.empty() || refs.members.empty()) continue;
        std::sort(refs.members.begin(), refs.members.end(),
                  [](const MemberRef& a, const MemberRef& b) {
                      if (a.xref != b.xref) return a.xref < b.xref;
                      return a.entry->text.size() < b.entry->text.size();
                  });

        for (const auto& desc_ref : refs.descriptors) {
            if (!desc_ref.entry) continue;

            const StringEntry* best = nullptr;
            addr_t best_dist = std::numeric_limits<addr_t>::max();
            bool best_precedes_descriptor = false;
            const addr_t lo = desc_ref.xref > 256 ? desc_ref.xref - 256 : 0;
            const addr_t hi = desc_ref.xref + 256;
            auto it = std::lower_bound(
                refs.members.begin(), refs.members.end(), lo,
                [](const MemberRef& ref, addr_t needle) { return ref.xref < needle; });
            for (; it != refs.members.end() && it->xref <= hi; ++it) {
                const auto& candidate_ref = *it;
                if (!candidate_ref.entry) continue;
                const addr_t dist = candidate_ref.xref > desc_ref.xref
                    ? candidate_ref.xref - desc_ref.xref
                    : desc_ref.xref - candidate_ref.xref;
                const bool precedes_descriptor = candidate_ref.xref <= desc_ref.xref;
                if (best && precedes_descriptor != best_precedes_descriptor) {
                    if (!precedes_descriptor) continue;
                    best = candidate_ref.entry;
                    best_dist = dist;
                    best_precedes_descriptor = true;
                    continue;
                }
                if (dist < best_dist ||
                    (dist == best_dist && best &&
                     candidate_ref.entry->text.size() < best->text.size())) {
                    best = candidate_ref.entry;
                    best_dist = dist;
                    best_precedes_descriptor = precedes_descriptor;
                } else if (dist == best_dist && !best) {
                    best = candidate_ref.entry;
                    best_precedes_descriptor = precedes_descriptor;
                }
            }

            if (!best) continue;
            auto name = reflection_descriptor_candidate_name(
                desc_ref.parts, std::string_view{best->text});
            if (!name || name->empty()) continue;
            if (seen.emplace(fn, *name).second) {
                out.push_back({
                    fn,
                    std::move(*name),
                    std::format("reflection member {} near {}",
                                best->text, desc_ref.entry->text),
                });
            }
        }
    }
}

template <class EnclosingFunction>
void infer_role_identifier_anchors(
    std::span<const StringEntry> strings,
    EnclosingFunction enclosing_function,
    std::vector<StringNameCandidate>& out,
    std::set<std::pair<addr_t, std::string>>& seen) {
    std::map<std::string, std::set<addr_t>> functions_by_anchor;
    for (const auto& s : strings) {
        if (s.xrefs.empty()) continue;
        auto name = role_identifier_anchor_name(s.text);
        if (!name) continue;
        auto& functions = functions_by_anchor[*name];
        for (addr_t xr : s.xrefs) {
            if (auto fn = enclosing_function(xr)) functions.insert(*fn);
        }
    }

    std::map<addr_t, std::string> anchor_by_function;
    std::set<addr_t> ambiguous_functions;
    for (const auto& [name, functions] : functions_by_anchor) {
        if (functions.size() != 1) continue;
        const addr_t fn = *functions.begin();
        if (ambiguous_functions.contains(fn)) continue;
        auto [it, inserted] = anchor_by_function.emplace(fn, name);
        if (!inserted && it->second != name) {
            anchor_by_function.erase(it);
            ambiguous_functions.insert(fn);
        }
    }

    for (const auto& [fn, name] : anchor_by_function) {
        if (ambiguous_functions.contains(fn)) continue;
        if (seen.emplace(fn, name).second) {
            out.push_back({fn, name, name.substr(std::string_view{"string_anchor_"}.size())});
        }
    }
}

[[nodiscard]] std::optional<std::string>
collapse_script_vm_anchor_family(const std::set<std::string>& names) {
    if (names.empty()) return std::nullopt;

    bool all_lua_apps = true;
    bool all_heap_profiler = true;
    bool all_bytecode = true;
    bool all_caps = true;
    for (const auto& name : names) {
        all_lua_apps &= name.starts_with("script_vm_telemetry_lua_apps_") ||
                        name == "script_vm_telemetry_lua_shell_errors";
        all_heap_profiler &= name.find("heap_profiler") != std::string::npos;
        all_bytecode &= name.starts_with("script_vm_bytecode_");
        all_caps &= name.starts_with("script_vm_telemetry_caps_");
    }

    if (all_lua_apps) return std::string{"script_vm_telemetry_lua_apps_metrics"};
    if (all_heap_profiler) return std::string{"script_vm_telemetry_heap_profiler"};
    if (all_bytecode) return std::string{"script_vm_bytecode_metrics"};
    if (all_caps) return std::string{"script_vm_telemetry_caps_use"};
    return std::nullopt;
}

template <class EnclosingFunction>
void infer_script_vm_metadata_anchors(
    std::span<const StringEntry> strings,
    EnclosingFunction enclosing_function,
    std::vector<StringNameCandidate>& out,
    std::set<std::pair<addr_t, std::string>>& seen) {
    struct AnchorRefs {
        std::set<addr_t> functions;
        std::string      source;
    };

    std::map<std::string, AnchorRefs> refs_by_name;
    for (const auto& s : strings) {
        if (s.xrefs.empty()) continue;
        auto name = script_vm_anchor_name_from_string(s.text);
        if (!name) continue;
        auto& refs = refs_by_name[*name];
        if (refs.source.empty()) refs.source = s.text;
        for (addr_t xr : s.xrefs) {
            if (auto fn = enclosing_function(xr)) refs.functions.insert(*fn);
        }
    }

    std::map<addr_t, std::set<std::string>> names_by_function;
    std::map<std::string, std::string> source_by_name;
    for (const auto& [name, refs] : refs_by_name) {
        if (refs.functions.size() != 1) continue;
        const addr_t fn = *refs.functions.begin();
        names_by_function[fn].insert(name);
        source_by_name.emplace(name, refs.source);
    }

    for (const auto& [fn, names] : names_by_function) {
        std::string name;
        std::string source;
        if (names.size() == 1) {
            name = *names.begin();
            source = source_by_name[name];
        } else if (auto collapsed = collapse_script_vm_anchor_family(names)) {
            name = *collapsed;
            source = std::format("{} ScriptVM anchors", names.size());
        } else {
            continue;
        }
        if (seen.emplace(fn, name).second) {
            out.push_back({fn, std::move(name), std::move(source)});
        }
    }
}

template <class EnclosingFunction>
void infer_engine_feature_anchors(
    std::span<const StringEntry> strings,
    EnclosingFunction enclosing_function,
    const std::map<addr_t, std::size_t>& function_sizes,
    std::vector<StringNameCandidate>& out,
    std::set<std::pair<addr_t, std::string>>& seen) {
    std::map<std::string, std::set<addr_t>> functions_by_anchor;
    std::map<std::string, std::string> source_by_name;
    for (const auto& s : strings) {
        if (s.xrefs.empty()) continue;
        auto name = engine_feature_anchor_name(s.text);
        if (!name) continue;
        auto& functions = functions_by_anchor[*name];
        source_by_name.emplace(*name, s.text);
        for (addr_t xr : s.xrefs) {
            if (auto fn = enclosing_function(xr)) functions.insert(*fn);
        }
    }

    std::map<addr_t, std::string> anchor_by_function;
    std::set<addr_t> ambiguous_functions;
    for (const auto& [name, functions] : functions_by_anchor) {
        std::set<addr_t> candidates = functions;
        if (candidates.size() > 1) {
            std::erase_if(candidates, [&](addr_t fn) {
                const auto it = function_sizes.find(fn);
                return it != function_sizes.end() && it->second > 512;
            });
        }
        if (candidates.size() != 1) continue;
        const addr_t fn = *candidates.begin();
        if (ambiguous_functions.contains(fn)) continue;
        auto [it, inserted] = anchor_by_function.emplace(fn, name);
        if (!inserted && it->second != name) {
            anchor_by_function.erase(it);
            ambiguous_functions.insert(fn);
        }
    }

    for (const auto& [fn, name] : anchor_by_function) {
        if (ambiguous_functions.contains(fn)) continue;
        auto source_it = source_by_name.find(name);
        const std::string source =
            source_it == source_by_name.end() ? name : source_it->second;
        if (seen.emplace(fn, name).second) {
            out.push_back({fn, name, source});
        }
    }
}

[[nodiscard]] std::map<SsaKey, const IrInst*>
index_defs(const IrFunction& fn) {
    std::map<SsaKey, const IrInst*> out;
    for (const auto& bb : fn.blocks) {
        for (const auto& inst : bb.insts) {
            if (auto k = ssa_key(inst.dst)) out.emplace(*k, &inst);
        }
    }
    return out;
}

[[nodiscard]] std::optional<std::string>
resolve_string_value(const Binary& b,
                     const std::map<SsaKey, const IrInst*>& defs,
                     IrValue v,
                     int depth = 0) {
    if (depth > 10) return std::nullopt;
    for (int hop = 0; hop < 10; ++hop) {
        if (v.kind == IrValueKind::Imm) {
            auto s = read_cstring_local(b, static_cast<addr_t>(v.imm));
            if (!s.empty()) return s;
            return std::nullopt;
        }
        auto k = ssa_key(v);
        if (!k) return std::nullopt;
        auto it = defs.find(*k);
        if (it == defs.end()) return std::nullopt;
        const IrInst* d = it->second;
        if ((d->op == IrOp::Assign || d->op == IrOp::ZExt ||
             d->op == IrOp::SExt || d->op == IrOp::Trunc) &&
            d->src_count == 1) {
            v = d->srcs[0];
            continue;
        }
        return std::nullopt;
    }
    return std::nullopt;
}

void infer_assertion_function_names(const Binary& b,
                                    std::span<const DiscoveredFunction> fns,
                                    std::vector<StringNameCandidate>& out,
                                    std::set<std::pair<addr_t, std::string>>& seen) {
    if (!has_function_name_assert_import(b)) return;

    auto dec_r = make_decoder(b);
    if (!dec_r) return;
    auto lifter_r = make_lifter(b);
    if (!lifter_r) return;

    const Decoder& dec = **dec_r;
    const CfgBuilder builder(b, dec);
    const SsaBuilder ssa;

    for (const auto& fn : fns) {
        if (fn.size == 0 || b.import_at_plt(fn.addr) != nullptr) continue;
        auto cfg_r = builder.build(fn.addr, fn.name);
        if (!cfg_r) continue;
        auto ir_r = (*lifter_r)->lift(*cfg_r);
        if (!ir_r) continue;
        if (auto rv = ssa.convert(*ir_r); !rv) continue;
        if (auto rv = run_cleanup(*ir_r); !rv) continue;

        const auto defs = index_defs(*ir_r);
        for (const auto& bb : ir_r->blocks) {
            std::vector<IrValue> args;
            args.reserve(kMaxAbiIntArgs);
            for (const auto& inst : bb.insts) {
                if (inst.op == IrOp::Intrinsic && inst.name == "call.args.1") {
                    args.clear();
                    for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                        args.push_back(inst.srcs[i]);
                    }
                    continue;
                }
                if (inst.op == IrOp::Intrinsic &&
                    (inst.name == "call.args.2" || inst.name == "call.args.3")) {
                    for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                        args.push_back(inst.srcs[i]);
                    }
                    continue;
                }
                if (inst.op != IrOp::Call) continue;
                const Symbol* s = b.import_at_plt(inst.target1);
                if (!s) {
                    args.clear();
                    continue;
                }
                auto idx = function_name_arg_index(
                    strip_import_name_decorations(s->name));
                if (!idx || *idx >= args.size()) {
                    args.clear();
                    continue;
                }
                auto raw = resolve_string_value(b, defs, args[*idx]);
                if (!raw) {
                    args.clear();
                    continue;
                }
                auto name = sanitize_name(*raw);
                if (!name.empty() && seen.emplace(fn.addr, name).second) {
                    out.push_back({fn.addr, std::move(name), *raw});
                }
                args.clear();
            }
        }
    }
}

}  // namespace

bool is_ident_char(char c) noexcept {
    const auto u = static_cast<unsigned char>(c);
    return std::isalnum(u) || c == '_';
}

std::string sanitize_name(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_') {
            out.push_back(c);
        } else if (c == ':' && i + 1 < s.size() && s[i + 1] == ':') {
            out += "::";
            ++i;
        } else if (c == '-' || c == '+' || c == '[' || c == ']' || c == ' ') {
            if (out.empty() || out.back() != '_') out.push_back('_');
        }
    }
    while (!out.empty() && out.front() == '_' &&
           !out.starts_with("_GLOBAL__N_")) {
        out.erase(out.begin());
    }
    while (!out.empty() && out.back() == '_') out.pop_back();
    return good_name(out) ? out : std::string{};
}

std::string_view trim_ascii(std::string_view s) noexcept {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) {
        s.remove_prefix(1);
    }
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) {
        s.remove_suffix(1);
    }
    return s;
}

bool has_c_signature_type_cue(std::string_view prefix) noexcept {
    prefix = trim_ascii(prefix);
    if (prefix.empty()) return false;
    if (prefix.find('*') != std::string_view::npos ||
        prefix.find('&') != std::string_view::npos) {
        return true;
    }
    for (std::size_t i = 0; i < prefix.size();) {
        while (i < prefix.size() && !is_ident_char(prefix[i])) ++i;
        const std::size_t start = i;
        while (i < prefix.size() && is_ident_char(prefix[i])) ++i;
        if (start != i && is_known_c_type_token(prefix.substr(start, i - start))) {
            return true;
        }
    }
    return false;
}

bool is_bad_plain_function_name(std::string_view name) noexcept {
    return name == "if" || name == "for" || name == "while" ||
           name == "switch" || name == "return" || name == "sizeof" ||
           name == "alignof" || name == "static_cast" ||
           name == "reinterpret_cast" || name == "const_cast" ||
           name == "dynamic_cast";
}

}  // namespace ember::string_names

namespace ember {

using namespace string_names;

std::vector<StringNameCandidate>
infer_function_names_from_strings(const Binary &b, StringNameInferenceOptions options) {
    ScopedTimer timer("strings.infer_names");
    std::vector<StringNameCandidate> out;
    std::set<std::pair<addr_t, std::string>> seen;
    std::vector<DiscoveredFunction> fns;
    {
        ScopedTimer phase("strings.enumerate_functions");
        fns = enumerate_functions(b, EnumerateMode::Cheap);
    }
    std::map<addr_t, std::size_t> function_sizes;
    for (const auto& fn : fns) function_sizes.emplace(fn.addr, fn.size);
    auto is_executable_section_addr = [&](addr_t addr) {
        for (const auto& sec : b.sections()) {
            if (!sec.flags.executable || sec.data.empty()) continue;
            if (addr < sec.vaddr) continue;
            const auto off = addr - sec.vaddr;
            if (off < sec.data.size()) return true;
        }
        return false;
    };
    auto enclosing_function = [&](addr_t addr) -> std::optional<addr_t> {
        auto it =
            std::upper_bound(fns.begin(), fns.end(), addr,
                             [](addr_t a, const DiscoveredFunction &d) { return a < d.addr; });
        if (it == fns.begin())
            return std::nullopt;
        --it;
        if (it->size != 0 && addr >= it->addr + it->size)
            return std::nullopt;
        if (it->size == 0) {
            auto next = it;
            ++next;
            if (next != fns.end() && addr >= next->addr)
                return std::nullopt;
        }
        if (!is_executable_section_addr(addr))
            return std::nullopt;
        if (b.bytes_at(it->addr).empty())
            return std::nullopt;
        return it->addr;
    };
    auto script_vm_enclosing_function = [&](addr_t addr) -> std::optional<addr_t> {
        auto fn = enclosing_function(addr);
        if (!fn) return std::nullopt;
        const auto it = function_sizes.find(*fn);
        if (it != function_sizes.end() && it->second > 1024 * 1024) return std::nullopt;
        return fn;
    };
    std::vector<StringEntry> strings;
    {
        ScopedTimer phase("strings.scan");
        strings = scan_strings_impl(b, {}, fns, true);
    }
    {
        ScopedTimer phase("strings.graphics_proc_loader");
        struct ProcVotes {
            std::set<std::string> gl;
            std::set<std::string> vk;
        };
        std::map<addr_t, ProcVotes> proc_votes;
        for (const auto &s : strings) {
            if (!s.xrefs.empty() && is_graphics_api_ident(s.text)) {
                for (addr_t xr : s.xrefs) {
                    if (auto fn = enclosing_function(xr)) {
                        auto &votes = proc_votes[*fn];
                        if (s.text.starts_with("gl"))
                            votes.gl.insert(s.text);
                        else if (s.text.starts_with("vk"))
                            votes.vk.insert(s.text);
                    }
                }
            }
        }
        for (const auto &[fn, votes] : proc_votes) {
            if (votes.gl.size() >= 12 && seen.emplace(fn, "graphics_gl_proc_loader").second) {
                out.push_back({fn, "graphics_gl_proc_loader",
                               std::format("{} OpenGL proc names", votes.gl.size())});
            } else if (votes.vk.size() >= 8 && seen.emplace(fn, "graphics_vk_proc_loader").second) {
                out.push_back({fn, "graphics_vk_proc_loader",
                               std::format("{} Vulkan proc names", votes.vk.size())});
            }
        }
    }
    {
        ScopedTimer phase("strings.lua_registration");
        infer_lua_registration_names(b, strings, out, seen);
    }
    {
        ScopedTimer phase("strings.reflection_members");
        infer_reflection_member_names(strings, enclosing_function, out, seen);
    }
    {
        ScopedTimer phase("strings.generic_candidates");
        for (const auto &s : strings) {
            if (s.xrefs.empty())
                continue;
            auto name = candidate_name_from_string(s.text);
            if (!name || name->empty())
                continue;
            std::set<addr_t> referencing_fns;
            for (addr_t xr : s.xrefs) {
                if (auto fn = enclosing_function(xr))
                    referencing_fns.insert(*fn);
            }
            for (addr_t fn : referencing_fns) {
                if (seen.emplace(fn, *name).second) {
                    out.push_back({fn, *name, s.text});
                }
            }
        }
    }
    if (options.assertion_names &&
        (options.max_assertion_functions == 0 || fns.size() <= options.max_assertion_functions)) {
        ScopedTimer phase("strings.assertion_names");
        infer_assertion_function_names(b, fns, out, seen);
    }
    {
        ScopedTimer phase("strings.script_metadata_anchors");
        infer_script_vm_metadata_anchors(strings, script_vm_enclosing_function, out, seen);
    }
    {
        ScopedTimer phase("strings.engine_feature_anchors");
        infer_engine_feature_anchors(strings, script_vm_enclosing_function,
                                     function_sizes, out, seen);
    }
    {
        ScopedTimer phase("strings.role_identifier_anchors");
        infer_role_identifier_anchors(strings, enclosing_function, out, seen);
    }
    return out;
}

}  // namespace ember
