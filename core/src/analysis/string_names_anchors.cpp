// Anchor heuristics: role identifiers, graphics APIs, script VMs, engine features.

#include <cctype>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

#include "string_names_internal.hpp"

namespace ember::string_names {

namespace {

[[nodiscard]] bool has_uppercase_transition(std::string_view text) noexcept {
    bool lower = false;
    bool upper = false;
    for (char c : text) {
        const auto u = static_cast<unsigned char>(c);
        lower = lower || std::islower(u) != 0;
        upper = upper || std::isupper(u) != 0;
    }
    return lower && upper;
}

[[nodiscard]] bool has_role_identifier_suffix(std::string_view text) noexcept {
    for (const std::string_view suffix : {
             std::string_view{"Callback"},
             std::string_view{"Callbacks"},
             std::string_view{"Job"},
             std::string_view{"Jobs"},
             std::string_view{"Telemetry"},
             std::string_view{"Report"},
             std::string_view{"Reporter"},
             std::string_view{"Event"},
             std::string_view{"Events"},
             std::string_view{"Protocol"},
         }) {
        if (text.ends_with(suffix)) return true;
    }
    return false;
}

[[nodiscard]] bool looks_like_role_identifier_anchor(std::string_view text) noexcept {
    if (text.size() < 8 || text.size() > 80) return false;
    if (!std::isupper(static_cast<unsigned char>(text.front()))) return false;
    if (!has_uppercase_transition(text)) return false;
    if (!has_role_identifier_suffix(text)) return false;
    if (text.starts_with("NSt") || text.starts_with("ZN") ||
        text.starts_with("ZZ") || text.starts_with("T_")) {
        return false;
    }
    for (char c : text) {
        if (!is_ident_char(c)) return false;
    }
    return true;
}

[[nodiscard]] std::string camel_tail_to_snake(std::string_view text) {
    std::string out;
    out.reserve(text.size() + 8);
    for (std::size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        if (std::isupper(static_cast<unsigned char>(c))) {
            const bool prev_lower_or_digit =
                i > 0 && (std::islower(static_cast<unsigned char>(text[i - 1])) ||
                          std::isdigit(static_cast<unsigned char>(text[i - 1])));
            const bool acronym_boundary =
                i > 0 && i + 1 < text.size() &&
                std::isupper(static_cast<unsigned char>(text[i - 1])) &&
                std::islower(static_cast<unsigned char>(text[i + 1]));
            if (!out.empty() && out.back() != '_' &&
                (prev_lower_or_digit || acronym_boundary)) {
                out.push_back('_');
            }
            out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        } else if (std::isalnum(static_cast<unsigned char>(c))) {
            out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        } else if (!out.empty() && out.back() != '_') {
            out.push_back('_');
        }
    }
    while (!out.empty() && out.back() == '_') out.pop_back();
    return out;
}

[[nodiscard]] std::string lower_ascii_copy(std::string_view text) {
    std::string out(text);
    for (char& c : out) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

[[nodiscard]] std::string remove_camel_word_copy(std::string_view text,
                                                 std::string_view word) {
    std::string out{text};
    std::size_t pos = 0;
    while ((pos = out.find(word, pos)) != std::string::npos) {
        out.erase(pos, word.size());
    }
    return out;
}

[[nodiscard]] std::optional<std::string>
sanitize_script_vm_anchor(std::string_view prefix, std::string_view tail) {
    auto snake = camel_tail_to_snake(tail);
    while (!snake.empty() && snake.front() == '_') snake.erase(snake.begin());
    while (!snake.empty() && snake.back() == '_') snake.pop_back();
    if (snake.empty()) return std::nullopt;
    auto name = sanitize_name(std::string{prefix} + snake);
    if (name.empty()) return std::nullopt;
    return name;
}

[[nodiscard]] bool looks_like_script_vm_opcode_token(std::string_view text) noexcept {
    if (text.empty() || text.size() > 40) return false;
    bool alpha = false;
    bool upper = false;
    for (char c : text) {
        const auto u = static_cast<unsigned char>(c);
        if (std::isalpha(u)) {
            alpha = true;
            if (!std::isupper(u)) return false;
            upper = true;
        } else if (!(std::isdigit(u) || c == '_')) {
            return false;
        }
    }
    if (!alpha || !upper) return false;
    for (const std::string_view needle : {
             std::string_view{"FASTCALL"},
             std::string_view{"NAMECALL"},
             std::string_view{"DUPCLOSURE"},
             std::string_view{"FORGPREP"},
             std::string_view{"FORGLOOP"},
             std::string_view{"JUMPIF"},
             std::string_view{"GETIMPORT"},
             std::string_view{"BYTECODE"},
         }) {
        if (text.find(needle) != std::string_view::npos) return true;
    }
    return false;
}

[[nodiscard]] bool looks_like_engine_feature_anchor(std::string_view text) noexcept {
    if (text.size() < 9 || text.size() > 96) return false;
    if (text == "SceneGraph") return false;
    if (!has_uppercase_transition(text)) return false;
    for (char c : text) {
        if (!is_ident_char(c)) return false;
    }
    std::string_view suffix;
    bool has_prefix = false;
    for (const std::string_view prefix : {
             std::string_view{"MarketplaceService"},
             std::string_view{"HighlightsPerSceneGraph"},
             std::string_view{"ExperienceService"},
             std::string_view{"ContentProvider"},
             std::string_view{"RemoveSceneGraph"},
             std::string_view{"SupportSceneGraph"},
             std::string_view{"JobScheduler"},
             std::string_view{"ScriptHost"},
             std::string_view{"VoiceChat"},
             std::string_view{"SAuthSceneGraph"},
             std::string_view{"SimSceneGraph"},
             std::string_view{"Marketplace"},
             std::string_view{"Replicator"},
             std::string_view{"RunService"},
             std::string_view{"Streaming"},
             std::string_view{"SceneGraph"},
             std::string_view{"Teleport"},
             std::string_view{"Network"},
             std::string_view{"Physics"},
             std::string_view{"Security"},
             std::string_view{"Avatar"},
             std::string_view{"Voice"},
             std::string_view{"Chat"},
         }) {
        if (text.starts_with(prefix)) {
            suffix = text.substr(prefix.size());
            has_prefix = true;
            break;
        }
    }
    if (!has_prefix || suffix.empty()) return false;
    if (suffix == "Mode" || suffix == "Queue" || suffix == "Stats" ||
        suffix == "Time") {
        return false;
    }
    bool has_feature_term = false;
    for (const std::string_view term : {
             std::string_view{"Allow"},
             std::string_view{"Annotation"},
             std::string_view{"Counter"},
             std::string_view{"Default"},
             std::string_view{"Disable"},
             std::string_view{"Enable"},
             std::string_view{"Enabled"},
             std::string_view{"Error"},
             std::string_view{"Fast"},
             std::string_view{"Fix"},
             std::string_view{"Flag"},
             std::string_view{"Limit"},
             std::string_view{"Max"},
             std::string_view{"Min"},
             std::string_view{"Mode"},
             std::string_view{"Percent"},
             std::string_view{"Percentage"},
             std::string_view{"Queue"},
             std::string_view{"Rate"},
             std::string_view{"Report"},
             std::string_view{"Retry"},
             std::string_view{"Rollout"},
             std::string_view{"Slow"},
             std::string_view{"Stats"},
             std::string_view{"Telemetry"},
             std::string_view{"Threshold"},
             std::string_view{"Throttle"},
             std::string_view{"Time"},
             std::string_view{"Timeout"},
             std::string_view{"Use"},
         }) {
        if (suffix.find(term) != std::string_view::npos) {
            has_feature_term = true;
            break;
        }
    }
    if (has_feature_term) return true;
    return text.starts_with("RemoveSceneGraph") && suffix.size() >= 4;
}

}  // namespace

std::optional<std::string>
role_identifier_anchor_name(std::string_view text) {
    if (!looks_like_role_identifier_anchor(text)) return std::nullopt;
    auto name = sanitize_name(std::string{"string_anchor_"} + std::string{text});
    if (name.empty()) return std::nullopt;
    return name;
}

bool is_graphics_api_ident(std::string_view tok) noexcept {
    if (tok.size() < 4 || tok.size() > 80) return false;
    if (!(tok.starts_with("gl") || tok.starts_with("vk"))) return false;
    if (!std::isupper(static_cast<unsigned char>(tok[2]))) return false;
    for (char c : tok) {
        if (!std::isalnum(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

std::optional<std::string>
graphics_api_name_from_string(std::string_view text) {
    for (std::size_t i = 0; i + 4 < text.size(); ++i) {
        if (i > 0 && is_ident_char(text[i - 1])) continue;
        if (!(text.substr(i).starts_with("gl") ||
              text.substr(i).starts_with("vk"))) {
            continue;
        }
        std::size_t j = i;
        while (j < text.size() &&
               std::isalnum(static_cast<unsigned char>(text[j]))) {
            ++j;
        }
        const auto tok = text.substr(i, j - i);
        if (!is_graphics_api_ident(tok)) continue;
        const bool call_expr = j < text.size() && text[j] == '(';
        const bool exact_name = i == 0 && j == text.size();
        if (!call_expr && !exact_name) continue;

        const auto api = tok.substr(0, 2);
        const auto tail = tok.substr(2);
        auto snake = camel_tail_to_snake(tail);
        if (snake.empty()) continue;
        auto name = std::string{"graphics_"} + std::string{api} + "_" + snake;
        if (exact_name) name += "_proc";
        if (auto n = sanitize_name(name); !n.empty()) return n;
    }

    if (text.find("#version") != std::string_view::npos &&
        (text.find("gl_Position") != std::string_view::npos ||
         text.find("layout(") != std::string_view::npos ||
         text.find("void main") != std::string_view::npos)) {
        if (auto n = sanitize_name("graphics_glsl_shader_source"); !n.empty()) return n;
    }
    if (text.find("SPIR-V") != std::string_view::npos ||
        text.find("SPIRV") != std::string_view::npos) {
        if (auto n = sanitize_name("graphics_spirv_shader_source"); !n.empty()) return n;
    }
    return std::nullopt;
}

std::optional<std::string>
script_vm_anchor_name_from_string(std::string_view text) {
    if (text.starts_with("script_vm-telemetry.")) {
        const auto tail = text.substr(std::string_view{"script_vm-telemetry."}.size());
        if (tail.size() < 3 || tail.size() > 96) return std::nullopt;
        for (char c : tail) {
            const auto u = static_cast<unsigned char>(c);
            if (!(std::isalnum(u) || c == '-' || c == '.' || c == '_')) {
                return std::nullopt;
            }
        }
        return sanitize_script_vm_anchor("script_vm_telemetry_", tail);
    }

    if (looks_like_script_vm_opcode_token(text)) {
        return sanitize_script_vm_anchor("script_vm_opcode_", text);
    }

    const auto lower = lower_ascii_copy(text);
    auto has = [&](std::string_view needle) {
        return lower.find(needle) != std::string::npos;
    };

    if (has("unexpected opcode in short circuit")) {
        return sanitize_name("script_vm_unexpected_opcode_short_circuit");
    }
    if (has("unexpected opcode")) {
        return sanitize_name("script_vm_unexpected_opcode");
    }
    if (has("unhandled opcode")) {
        return sanitize_name("script_vm_unhandled_opcode");
    }
    if (has("bytecode auth check")) {
        return sanitize_name("script_vm_bytecode_auth_check");
    }
    if (lower == "invalid bytecode.") {
        return sanitize_name("script_vm_invalid_bytecode");
    }
    if (has("additional script_vm stack reservation has failed")) {
        return sanitize_name("script_vm_stack_reservation_failed");
    }
    if (text.starts_with("Debugger is out of ScriptVM stack space in ")) {
        auto tail = text.substr(std::string_view{"Debugger is out of ScriptVM stack space in "}.size());
        if (tail.starts_with("a ")) tail.remove_prefix(2);
        if (tail.starts_with("an ")) tail.remove_prefix(3);
        return sanitize_script_vm_anchor("script_vm_debugger_stack_", tail);
    }

    if (text == "ScriptVMTelemetry") {
        return sanitize_name("script_vm_telemetry");
    }
    if (text.starts_with("ScriptVM") && text.find("Telemetry") != std::string_view::npos) {
        auto tail = std::string_view{text}.substr(4);
        const auto stripped = remove_camel_word_copy(tail, "Telemetry");
        return sanitize_script_vm_anchor("script_vm_telemetry_", stripped);
    }
    if (text.starts_with("LuaApps") || text.starts_with("LuaShell") ||
        text.starts_with("LuaErrors")) {
        return sanitize_script_vm_anchor("script_vm_telemetry_", text);
    }
    if (text.find("ScriptVMHeap") != std::string_view::npos) {
        return sanitize_script_vm_anchor("script_vm_heap_", text);
    }
    if (text.find("LuaBytecode") != std::string_view::npos ||
        text.find("Bytecode") != std::string_view::npos) {
        return sanitize_script_vm_anchor("script_vm_bytecode_", text);
    }
    return std::nullopt;
}

std::optional<std::string>
engine_feature_anchor_name(std::string_view text) {
    if (!looks_like_engine_feature_anchor(text)) return std::nullopt;
    auto snake = camel_tail_to_snake(text);
    if (snake.empty()) return std::nullopt;
    auto name = sanitize_name(std::string{"feature_"} + snake);
    if (name.empty()) return std::nullopt;
    return name;
}

std::optional<std::string>
graphics_phrase_name_from_string(std::string_view text) {
    const auto lower = lower_ascii_copy(text);
    auto has = [&](std::string_view needle) {
        return lower.find(needle) != std::string::npos;
    };

    if (has("vulkanbuggyrenderpass") || has("vulkan: error")) {
        if (auto n = sanitize_name("graphics_vulkan_backend_guard"); !n.empty()) return n;
    }
    if (has("opengl.framework")) {
        if (auto n = sanitize_name("graphics_gl_dlsym_resolver"); !n.empty()) return n;
    }
    if (has("failed to link shader program")) {
        if (auto n = sanitize_name("graphics_shader_program_link"); !n.empty()) return n;
    }
    if (has("failed to create shader")) {
        if (auto n = sanitize_name("graphics_shader_create"); !n.empty()) return n;
    }
    if (has("successfully compiled shader") || has("compiled {} shaders") ||
        has("compiled %d shaders")) {
        if (auto n = sanitize_name("graphics_shader_compile"); !n.empty()) return n;
    }
    if ((has("shader pack") || has("shaders from pack")) &&
        (has("opening") || has("loaded") || has("corrupted") ||
         has("outdated") || has("variant"))) {
        if (auto n = sanitize_name("graphics_shader_pack_load"); !n.empty()) return n;
    }
    if (has("deferred shader loading")) {
        if (auto n = sanitize_name("graphics_shader_deferred_loading"); !n.empty()) return n;
    }
    if (has("unknown shader type")) {
        if (auto n = sanitize_name("graphics_shader_type_dispatch"); !n.empty()) return n;
    }
    if (has("global instancing")) {
        if (auto n = sanitize_name("graphics_global_instancing"); !n.empty()) return n;
    }
    return std::nullopt;
}

}  // namespace ember::string_names
