#include <ember/analysis/app_surface.hpp>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include <ember/analysis/demangle.hpp>
#include <ember/analysis/objc.hpp>
#include <ember/analysis/pipeline.hpp>
#include <ember/analysis/rtti.hpp>
#include <ember/analysis/strings.hpp>
#include <ember/binary/binary.hpp>
#include <ember/binary/symbol.hpp>

namespace ember {

namespace {

struct SurfaceRule {
    std::string_view subsystem;
    std::string_view category;
    std::vector<std::string_view> needles;
};

struct ReflectionDescriptor {
    std::string kind;
    std::string category;
    std::string owner;
    std::string arity;
};

const std::vector<SurfaceRule>& rules() {
    static const std::vector<SurfaceRule> kRules = {
        {"script_vm", "vm_scripting", {
            "script_vm", "lua_state", "lua_debug", "luaapp", "scripthost",
            "modulescript", "luasource", "sharedtable", "weakthreadref",
            "parallel script_vm", "scriptvmheap", "lua callback"}},
        {"webview_auth", "web_auth", {
            "wkwebview", "webview", "webkit", "cookie", "authcookie",
            "securitycookie", "httpcookiestore", "nshttpcookiestorage",
            "embeddedwebview", "requestheaderfieldswithcookies",
            "webkit.framework"}},
        {"network_transport", "network", {
            "http", "https", "websocket", "network", "transport", "quic",
            "ngtcp2", "ssl", "tls", "certificate", "curl", "cdn"}},
        {"voice_video", "realtime_media", {
            "webrtc", "rtcvideo", "voicechat", "voice chat", "video",
            "capturer", "renderer", "camera", "audio", "screen capture",
            "videotoolbox", "avfoundation", "coremedia"}},
        {"audio_engine", "audio", {
            "coreaudio", "audiounit", "audiotoolbox", "audio device",
            "audio stream", "soundservice", "sound effect", "spatial audio",
            "voicechat", "voice chat", "microphone", "coreaudio.framework",
            "audiounit.framework", "audiotoolbox.framework"}},
        {"media_capture", "capture", {
            "avfoundation", "videotoolbox", "coremedia", "camera",
            "screen capture", "screencapture", "video capture", "rtcvideo",
            "pixel buffer", "cvpixelbuffer", "avfoundation.framework",
            "videotoolbox.framework", "coremedia.framework", "corevideo.framework"}},
        {"graphics_rendering", "rendering", {
            "opengl", "metal", "glsl", "shader", "render", "renderer",
            "texture", "framebuffer", "gpu", "mtl", "graphics", "mesh",
            "opengl.framework", "metal.framework", "default.metallib",
            "shaders_metal", "shaders_glsl"}},
        {"input_controller", "input", {
            "sdl", "gamecontroller", "gamepad", "controller", "joystick",
            "haptic", "rumble", "forcefeedback", "mouse", "keyboard",
            "gamecontroller.framework", "forcefeedback.framework",
            "corehaptics.framework"}},
        {"analytics_telemetry", "telemetry", {
            "analytics", "telemetry", "eventing", "eventingest", "gareporter",
            "ephemeralcounter", "counter", "measurement", "trace"}},
        {"crash_update", "crash_update", {
            "crashpad", "crash", "crashreport", "update", "updater",
            "launchatstartup", "startup", "managedupdate"}},
        {"anti_tamper", "protection", {
            "vmprotect", "vmprotectsdk", "libvmprotectsdk", "anti-tamper", "antitamper",
            "integrity check", "code signature", "anti-debug",
            "anti debug", "tamper", "obfuscation"}},
        {"memory_allocator", "memory", {
            "mimalloc", "libmimalloc", "mi_malloc", "jemalloc", "tcmalloc", "malloc_zone",
            "memorypool", "memory pool", "heap profiler",
            "heapprofile", "memory budget"}},
        {"storage_cache", "storage", {
            "sqlite", "storage", "datastore", "memorystore", "cache",
            "database", "assetcache", "flagcache", "blobstorage"}},
        {"security_qos", "security", {
            "security", "clientqos", "qos", "heartbeat", "devicecheck",
            "vmprotect", "sandbox", "permission", "authenticationchallenge",
            "security.framework", "devicecheck.framework"}},
        {"crypto_tls", "crypto", {
            "openssl", "boringssl", "ssl_ctx", "x509", "certificate",
            "public key", "private key", "hmac", "sha256", "sha1",
            "ecdsa", "chacha", "crypto"}},
        {"ml_inference", "ml", {
            "coreml", "mlmodel", "model inference", "neural", "classifier",
            "generated model", "generation job", "inference", "machine learning",
            "coreml.framework"}},
        {"commerce_payments", "commerce", {
            "credits", "purchase", "marketplace", "payment", "product",
            "price", "currency", "checkout", "receipt", "transaction"}},
        {"notifications_contacts", "notifications", {
            "notification", "usernotifications", "contacts", "addressbook",
            "friendservice", "connections count", "bulknoti", "push notification",
            "usernotifications.framework", "contacts.framework"}},
        {"physics_world", "physics", {
            "physics", "collision", "rigidbody", "rigid body",
            "character", "assembly", "joint", "solver", "worldroot"}},
        {"resources_localization", "resources", {
            "localizable", "localization", ".lproj", "locale", "translation",
            "resource bundle", "assets.car", "mainmenu.nib", "cacert.pem",
            "localizable.strings", "infoplist.strings", "resources/ssl"}},
        {"process_launch", "process", {
            "posix_spawn", "launchservices", "launch service", "servicemanagement",
            "servicemanagement.framework", "launch at startup", "login item", "helper tool", "openurl",
            "switchtosettings"}},
        {"avatar_content", "content", {
            "avatar", "animation", "character", "marketplace", "purchase",
            "currency", "mesh", "texture", "asset", "csg", "teleport",
            "photo2avatar"}},
        {"app_shell", "mac_app", {
            "menubar", "appconfiguration", "appstartup",
            "cocoa", "appkit", "cocoa.framework", "appkit.framework",
            "service management", "mainmenu", "window", "fullscreen"}},
        {"compiler_artifacts", "clang_closure_metadata", {
            "__function6__func", "E3$_", "ENK3$_", "_block_invoke"}},
        {"compiler_artifacts", "cxx_shared_ptr_emplace_metadata", {
            "__shared_ptr_emplace"}},
        {"compiler_artifacts", "cxx_bind_adapter_metadata", {
            "__bind"}},
        {"compiler_artifacts", "cxx_async_state_metadata", {
            "__async_assoc_state", "__deferred_assoc_state", "__async_func",
            "packaged_task", "promise"}},
        {"compiler_artifacts", "cxx_callable_traits_metadata", {
            "__weak_result_type", "__weak_result_type_imp"}},
        {"compiler_artifacts", "cxx_exception_clone_metadata", {
            "exception_detail", "error_info_injector", "clone_impl"}},
        {"compiler_artifacts", "llvm_instrumentation", {
            "__llvm_prf", "__llvm_cov", "llvm profile", "instrprof",
            "sancov", "__sanitizer", "__asan", "__ubsan", "__tsan", "__msan"}},
    };
    return kRules;
}

[[nodiscard]] std::string lower_ascii(std::string_view text) {
    std::string out(text);
    for (char& c : out) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

[[nodiscard]] bool contains_ci(std::string_view haystack, std::string_view needle) {
    if (needle.empty()) return true;
    return lower_ascii(haystack).find(lower_ascii(needle)) != std::string::npos;
}

[[nodiscard]] std::vector<const SurfaceRule*> classify(std::string_view text) {
    std::vector<const SurfaceRule*> out;
    std::set<std::pair<std::string_view, std::string_view>> seen;
    for (const auto& rule : rules()) {
        const bool hit = std::ranges::any_of(rule.needles, [&](std::string_view needle) {
            return contains_ci(text, needle);
        });
        const auto key = rule.subsystem == "compiler_artifacts"
            ? std::pair{rule.subsystem, rule.category}
            : std::pair{rule.subsystem, std::string_view{}};
        if (hit && seen.insert(key).second) out.push_back(&rule);
    }
    return out;
}

[[nodiscard]] std::optional<std::string> reflection_owner_component(std::string_view enc) {
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
    return parts.back();
}

[[nodiscard]] std::string reflection_arity(std::string_view text) {
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
    return "-";
}

[[nodiscard]] std::optional<ReflectionDescriptor>
parse_reflection_descriptor(std::string_view text) {
    struct Marker {
        std::string_view token;
        std::string_view kind;
        std::string_view category;
    };
    for (const auto& marker : {
        Marker{"BoundYieldFuncDescI", "yield_function", "reflection_yield_function"},
        Marker{"BoundFuncDescI", "bound_function", "reflection_bound_function"},
        Marker{"RemoteEventDescI", "remote_event", "reflection_remote_event"},
        Marker{"EventDescI", "event", "reflection_event"},
        Marker{"EnumPropDescriptorI", "enum_property", "reflection_property"},
        Marker{"RefPropDescriptorI", "ref_property", "reflection_property"},
        Marker{"PropDescriptorI", "property", "reflection_property"},
        Marker{"TypedPropertyDescriptorI", "typed_property", "reflection_property"},
        Marker{"EnumDescI", "enum", "reflection_enum"},
        Marker{"TTypeI", "type", "reflection_type"},
    }) {
        const auto p = text.find(marker.token);
        if (p == std::string_view::npos) continue;
        auto owner = reflection_owner_component(text.substr(p + marker.token.size()));
        if (!owner || owner->empty()) continue;
        return ReflectionDescriptor{
            .kind = std::string(marker.kind),
            .category = std::string(marker.category),
            .owner = std::move(*owner),
            .arity = reflection_arity(text),
        };
    }
    return std::nullopt;
}

[[nodiscard]] bool ends_with_ci(std::string_view text, std::string_view suffix) {
    if (suffix.size() > text.size()) return false;
    return lower_ascii(text.substr(text.size() - suffix.size())) == lower_ascii(suffix);
}

[[nodiscard]] std::string artifact_category(std::string_view artifact) {
    const std::string lower = lower_ascii(artifact);
    if (ends_with_ci(lower, ".metallib") ||
        lower.find("shaders_") != std::string::npos ||
        lower.find("/shaders/") != std::string::npos ||
        ends_with_ci(lower, ".spv") ||
        ends_with_ci(lower, ".spirv") ||
        ends_with_ci(lower, ".glsl") ||
        ends_with_ci(lower, ".hlsl") ||
        ends_with_ci(lower, ".metal")) {
        return "artifact_shader";
    }
    if (ends_with_ci(lower, ".dylib") ||
        ends_with_ci(lower, ".so") ||
        ends_with_ci(lower, ".dll") ||
        ends_with_ci(lower, ".framework")) {
        return "artifact_library";
    }
    if (ends_with_ci(lower, ".pem") ||
        ends_with_ci(lower, ".cer") ||
        ends_with_ci(lower, ".crt") ||
        ends_with_ci(lower, ".der") ||
        ends_with_ci(lower, ".p12")) {
        return "artifact_certificate";
    }
    if (lower.find(".lproj/") != std::string::npos ||
        ends_with_ci(lower, "localizable.strings") ||
        ends_with_ci(lower, "infoplist.strings") ||
        lower.find("/translations/") != std::string::npos ||
        lower.find("localization") != std::string::npos) {
        return "artifact_localization";
    }
    if (ends_with_ci(lower, ".car")) return "artifact_asset_catalog";
    if (lower.find("/scripts/") != std::string::npos ||
        ends_with_ci(lower, ".lua") ||
        ends_with_ci(lower, ".script_vm")) {
        return "artifact_script";
    }
    if (lower.find("luapackages") != std::string::npos) {
        return "artifact_lua_package";
    }
    if (lower.find("/textures/") != std::string::npos ||
        ends_with_ci(lower, ".png") ||
        ends_with_ci(lower, ".jpg") ||
        ends_with_ci(lower, ".jpeg") ||
        ends_with_ci(lower, ".webp") ||
        ends_with_ci(lower, ".dds") ||
        ends_with_ci(lower, ".ktx") ||
        ends_with_ci(lower, ".tga") ||
        ends_with_ci(lower, ".bmp")) {
        return "artifact_texture";
    }
    if (lower.find("/sounds/") != std::string::npos ||
        ends_with_ci(lower, ".wav") ||
        ends_with_ci(lower, ".ogg") ||
        ends_with_ci(lower, ".mp3") ||
        ends_with_ci(lower, ".m4a") ||
        ends_with_ci(lower, ".caf")) {
        return "artifact_audio";
    }
    if (lower.find("/models/") != std::string::npos ||
        ends_with_ci(lower, ".mesh") ||
        ends_with_ci(lower, ".fbx") ||
        ends_with_ci(lower, ".obj") ||
        ends_with_ci(lower, ".model") ||
        ends_with_ci(lower, ".modelx")) {
        return "artifact_model";
    }
    if (lower.find("/fonts/") != std::string::npos ||
        ends_with_ci(lower, ".ttf") ||
        ends_with_ci(lower, ".otf") ||
        ends_with_ci(lower, ".woff") ||
        ends_with_ci(lower, ".woff2")) {
        return "artifact_font";
    }
    if (ends_with_ci(lower, ".nib") ||
        lower.find(".nib/") != std::string::npos) {
        return "artifact_ui_resource";
    }
    if (lower.find("/configs/") != std::string::npos ||
        ends_with_ci(lower, ".json") ||
        ends_with_ci(lower, ".csv") ||
        ends_with_ci(lower, ".plist") ||
        ends_with_ci(lower, ".xml") ||
        ends_with_ci(lower, ".yaml") ||
        ends_with_ci(lower, ".yml")) {
        return "artifact_data";
    }
    if (ends_with_ci(lower, ".zip") ||
        ends_with_ci(lower, ".pack") ||
        ends_with_ci(lower, ".bundle") ||
        ends_with_ci(lower, ".pak")) {
        return "artifact_archive";
    }
    if (lower.find(".app/") != std::string::npos) return "artifact_nested_app";
    return "bundle_file";
}

void add_artifact_category_rules(std::vector<const SurfaceRule*>& matches,
                                 std::set<std::string_view>& seen,
                                 std::string_view category) {
    for (const auto& rule : rules()) {
        const bool hit =
            (category == "artifact_shader" && rule.subsystem == "graphics_rendering") ||
            ((category == "artifact_script" || category == "artifact_lua_package") &&
                rule.subsystem == "script_vm") ||
            (category == "artifact_certificate" &&
                (rule.subsystem == "network_transport" ||
                 rule.subsystem == "crypto_tls" ||
                 rule.subsystem == "resources_localization")) ||
            (category == "artifact_localization" && rule.subsystem == "resources_localization") ||
            (category == "artifact_asset_catalog" && rule.subsystem == "resources_localization") ||
            (category == "artifact_texture" &&
                (rule.subsystem == "graphics_rendering" ||
                 rule.subsystem == "avatar_content")) ||
            (category == "artifact_audio" && rule.subsystem == "audio_engine") ||
            (category == "artifact_model" && rule.subsystem == "avatar_content") ||
            (category == "artifact_font" && rule.subsystem == "resources_localization") ||
            (category == "artifact_ui_resource" &&
                (rule.subsystem == "app_shell" ||
                 rule.subsystem == "resources_localization")) ||
            (category == "artifact_data" &&
                (rule.subsystem == "storage_cache" ||
                 rule.subsystem == "resources_localization"));
        if (hit && seen.insert(rule.subsystem).second) matches.push_back(&rule);
    }
}

[[nodiscard]] std::vector<const SurfaceRule*> classify_artifact(std::string_view artifact,
                                                                std::string_view category) {
    std::vector<const SurfaceRule*> out;
    std::set<std::string_view> seen;
    for (const auto* rule : classify(artifact)) {
        if (seen.insert(rule->subsystem).second) out.push_back(rule);
    }
    add_artifact_category_rules(out, seen, category);
    return out;
}

template <class T>
void push_unique(std::vector<T>& values, const T& value) {
    if (std::ranges::find(values, value) == values.end()) values.push_back(value);
}

struct FunctionRange {
    addr_t begin = 0;
    addr_t end = 0;
};

[[nodiscard]] std::vector<FunctionRange> function_ranges(const Binary& b) {
    std::vector<FunctionRange> ranges;
    for (const auto& fn : enumerate_functions(b, EnumerateMode::Cheap)) {
        if (fn.size == 0) continue;
        if (b.import_at_plt(fn.addr) != nullptr) continue;
        ranges.push_back({fn.addr, fn.addr + fn.size});
    }
    std::ranges::sort(ranges, {}, &FunctionRange::begin);
    ranges.erase(std::unique(ranges.begin(), ranges.end(),
        [](const FunctionRange& lhs, const FunctionRange& rhs) {
            return lhs.begin == rhs.begin;
        }), ranges.end());
    return ranges;
}

[[nodiscard]] addr_t containing_function(const std::vector<FunctionRange>& ranges,
                                         addr_t addr) {
    auto it = std::ranges::upper_bound(ranges, addr, {}, &FunctionRange::begin);
    if (it == ranges.begin()) return 0;
    --it;
    if (addr >= it->begin && addr < it->end) return it->begin;
    return 0;
}

struct SummaryAcc {
    AppSurfaceSummary row;
    std::set<addr_t> functions;
    std::set<std::string> log_categories;
};

void add_summary_evidence(SummaryAcc& acc, const AppSurfaceEvidence& evidence) {
    push_unique(acc.row.categories, evidence.category);
    for (addr_t fn : evidence.functions) {
        if (fn != 0) acc.functions.insert(fn);
    }
    if (acc.row.evidence.size() < 8) {
        push_unique(acc.row.evidence, evidence.text);
    }
    if (evidence.kind == "string") ++acc.row.string_count;
    else if (evidence.kind == "image_string" || evidence.kind == "bundle_file") {
        ++acc.row.artifact_count;
    }
    else if (evidence.kind == "symbol") ++acc.row.symbol_count;
    else if (evidence.kind == "objc_method") ++acc.row.objc_method_count;
    else if (evidence.kind == "rtti_class") ++acc.row.rtti_class_count;
    else if (evidence.kind == "log_category") {
        acc.log_categories.insert(evidence.text);
        acc.row.log_category_count = acc.log_categories.size();
    }
}

struct FunctionAcc {
    AppSurfaceFunction row;
};

void add_function_evidence(std::map<std::pair<std::string, addr_t>, FunctionAcc>& functions,
                           const AppSurfaceEvidence& evidence) {
    for (addr_t fn : evidence.functions) {
        if (fn == 0) continue;
        auto& acc = functions[{evidence.subsystem, fn}];
        acc.row.subsystem = evidence.subsystem;
        acc.row.function = fn;
        ++acc.row.evidence_count;
        push_unique(acc.row.categories, evidence.category);
        if (acc.row.evidence.size() < 6) {
            push_unique(acc.row.evidence, evidence.text);
        }
    }
}

void add_evidence(AppSurfaceAnalysis& out,
                  std::map<std::string, SummaryAcc>& summaries,
                  std::map<std::pair<std::string, addr_t>, FunctionAcc>& functions,
                  AppSurfaceEvidence evidence) {
    auto& summary = summaries[evidence.subsystem];
    summary.row.subsystem = evidence.subsystem;
    add_summary_evidence(summary, evidence);
    add_function_evidence(functions, evidence);
    out.evidence.push_back(std::move(evidence));
}

void add_reflection_descriptor_evidence(
    AppSurfaceAnalysis& out,
    std::map<std::string, SummaryAcc>& summaries,
    std::map<std::pair<std::string, addr_t>, FunctionAcc>& functions,
    const ReflectionDescriptor& desc,
    addr_t addr,
    std::string_view text,
    std::vector<addr_t> xrefs,
    std::vector<addr_t> function_addrs,
    bool include_classified_subsystems = true) {
    std::vector<std::string> subsystems{"reflection_metadata"};
    if (include_classified_subsystems) {
        for (const auto* rule : classify(text)) {
            push_unique(subsystems, std::string(rule->subsystem));
        }
    }
    const std::string summary =
        desc.kind + " owner=" + desc.owner + " argc=" + desc.arity +
        " type=" + std::string(text);
    for (const auto& subsystem : subsystems) {
        AppSurfaceEvidence evidence;
        evidence.subsystem = subsystem;
        evidence.kind = "reflection_descriptor";
        evidence.category = desc.category;
        evidence.addr = addr;
        evidence.text = summary;
        evidence.xrefs = xrefs;
        evidence.functions = function_addrs;
        add_evidence(out, summaries, functions, std::move(evidence));
    }
}

[[nodiscard]] bool is_image_string_byte(unsigned char c) noexcept {
    return c >= 0x20 && c <= 0x7e;
}

[[nodiscard]] bool is_image_anchor(std::string_view text) {
    for (std::string_view anchor : {
        ".framework", ".dylib", ".metallib", ".pack", ".pem", ".lproj",
        "Resources/", "@rpath/", "/System/Library/Frameworks/",
        "Localizable.strings", "InfoPlist.strings", "Assets.car",
    }) {
        if (contains_ci(text, anchor)) return true;
    }
    return false;
}

[[nodiscard]] std::vector<AppSurfaceEvidence> scan_image_anchor_evidence(const Binary& b) {
    std::vector<AppSurfaceEvidence> out;
    const auto image = b.image();
    constexpr std::size_t kMinLen = 6;
    constexpr std::size_t kMaxLen = 512;
    std::size_t i = 0;
    while (i < image.size()) {
        const auto c = std::to_integer<unsigned char>(image[i]);
        if (!is_image_string_byte(c)) {
            ++i;
            continue;
        }
        const std::size_t start = i;
        std::string text;
        while (i < image.size() &&
               is_image_string_byte(std::to_integer<unsigned char>(image[i])) &&
               text.size() < kMaxLen) {
            text.push_back(static_cast<char>(std::to_integer<unsigned char>(image[i])));
            ++i;
        }
        const bool terminated = (i < image.size() && image[i] == std::byte{0});
        if (terminated && text.size() >= kMinLen && is_image_anchor(text)) {
            for (const auto* rule : classify(text)) {
                AppSurfaceEvidence evidence;
                evidence.subsystem = std::string(rule->subsystem);
                evidence.kind = "image_string";
                evidence.category = "binary_image";
                evidence.addr = static_cast<addr_t>(start);
                evidence.text = text;
                out.push_back(std::move(evidence));
            }
        }
        if (i < image.size()) ++i;
    }
    return out;
}

[[nodiscard]] std::vector<AppSurfaceEvidence>
classify_artifact_evidence(const std::vector<std::string>& artifacts) {
    std::vector<AppSurfaceEvidence> out;
    std::set<std::pair<std::string, std::string>> seen;
    for (const auto& artifact : artifacts) {
        if (artifact.empty()) continue;
        const std::string category = artifact_category(artifact);
        for (const auto* rule : classify_artifact(artifact, category)) {
            const std::string subsystem{rule->subsystem};
            if (!seen.insert({subsystem, artifact}).second) continue;
            AppSurfaceEvidence evidence;
            evidence.subsystem = subsystem;
            evidence.kind = "bundle_file";
            evidence.category = category;
            evidence.text = artifact;
            out.push_back(std::move(evidence));
        }
    }
    return out;
}

[[nodiscard]] std::vector<addr_t>
functions_for_xrefs(const std::vector<FunctionRange>& ranges,
                    const std::vector<addr_t>& xrefs) {
    std::vector<addr_t> functions;
    for (addr_t xref : xrefs) {
        const addr_t fn = containing_function(ranges, xref);
        if (fn != 0) push_unique(functions, fn);
    }
    std::ranges::sort(functions);
    return functions;
}

void finish_analysis(AppSurfaceAnalysis& out,
                     std::map<std::string, SummaryAcc>& summaries,
                     std::map<std::pair<std::string, addr_t>, FunctionAcc>& functions) {
    out.summaries.reserve(summaries.size());
    for (auto& [_, acc] : summaries) {
        acc.row.function_count = acc.functions.size();
        std::ranges::sort(acc.row.categories);
        std::ranges::sort(acc.row.evidence);
        out.summaries.push_back(std::move(acc.row));
    }
    std::ranges::sort(out.summaries, [](const auto& lhs, const auto& rhs) {
        const auto ltotal = lhs.string_count + lhs.artifact_count +
                            lhs.symbol_count + lhs.objc_method_count +
                            lhs.rtti_class_count + lhs.log_category_count;
        const auto rtotal = rhs.string_count + rhs.artifact_count +
                            rhs.symbol_count + rhs.objc_method_count +
                            rhs.rtti_class_count + rhs.log_category_count;
        if (ltotal != rtotal) return ltotal > rtotal;
        return lhs.subsystem < rhs.subsystem;
    });

    out.functions.reserve(functions.size());
    for (auto& [_, acc] : functions) {
        std::ranges::sort(acc.row.categories);
        std::ranges::sort(acc.row.evidence);
        out.functions.push_back(std::move(acc.row));
    }
    std::ranges::sort(out.functions, [](const auto& lhs, const auto& rhs) {
        if (lhs.evidence_count != rhs.evidence_count) {
            return lhs.evidence_count > rhs.evidence_count;
        }
        if (lhs.subsystem != rhs.subsystem) return lhs.subsystem < rhs.subsystem;
        return lhs.function < rhs.function;
    });

    std::ranges::sort(out.evidence, [](const auto& lhs, const auto& rhs) {
        if (lhs.subsystem != rhs.subsystem) return lhs.subsystem < rhs.subsystem;
        if (lhs.kind != rhs.kind) return lhs.kind < rhs.kind;
        if (lhs.addr != rhs.addr) return lhs.addr < rhs.addr;
        return lhs.text < rhs.text;
    });
}

}  // namespace

AppSurfaceAnalysis analyze_app_surface_artifacts(const std::vector<std::string>& artifacts) {
    AppSurfaceAnalysis out;
    std::map<std::string, SummaryAcc> summaries;
    std::map<std::pair<std::string, addr_t>, FunctionAcc> functions;
    for (auto& evidence : classify_artifact_evidence(artifacts)) {
        add_evidence(out, summaries, functions, std::move(evidence));
    }
    finish_analysis(out, summaries, functions);
    return out;
}

AppSurfaceAnalysis analyze_app_surfaces(const Binary& b,
                                        const AppSurfaceOptions& options) {
    AppSurfaceAnalysis out;
    std::map<std::string, SummaryAcc> summaries;
    std::map<std::pair<std::string, addr_t>, FunctionAcc> functions;

    if (!options.artifacts_only) {
        const auto ranges = function_ranges(b);

        if (options.reflection_only) {
            StringScanOptions scan_options;
            scan_options.any_substrings = {
                "BoundYieldFuncDescI",
                "BoundFuncDescI",
                "RemoteEventDescI",
                "EventDescI",
                "EnumPropDescriptorI",
                "RefPropDescriptorI",
                "PropDescriptorI",
                "TypedPropertyDescriptorI",
                "EnumDescI",
                "TTypeI",
            };
            for (const auto& s : scan_strings(b, scan_options)) {
                if (const auto desc = parse_reflection_descriptor(s.text)) {
                    add_reflection_descriptor_evidence(
                        out, summaries, functions, *desc, s.addr, s.text, s.xrefs,
                        functions_for_xrefs(ranges, s.xrefs), false);
                }
            }
            finish_analysis(out, summaries, functions);
            return out;
        }

        for (const auto& s : scan_strings(b)) {
            for (const auto* rule : classify(s.text)) {
                AppSurfaceEvidence evidence;
                evidence.subsystem = std::string(rule->subsystem);
                evidence.kind = "string";
                evidence.category = std::string(rule->category);
                evidence.addr = s.addr;
                evidence.text = s.text;
                evidence.xrefs = s.xrefs;
                evidence.functions = functions_for_xrefs(ranges, s.xrefs);
                add_evidence(out, summaries, functions, std::move(evidence));
            }
            if (const auto desc = parse_reflection_descriptor(s.text)) {
                add_reflection_descriptor_evidence(
                    out, summaries, functions, *desc, s.addr, s.text, s.xrefs,
                    functions_for_xrefs(ranges, s.xrefs));
            }
        }

        for (auto& evidence : scan_image_anchor_evidence(b)) {
            add_evidence(out, summaries, functions, std::move(evidence));
        }

        for (const auto& sym : b.symbols()) {
            if (sym.name.empty()) continue;
            const std::string text = pretty_symbol(sym.name);
            for (const auto* rule : classify(text)) {
                AppSurfaceEvidence evidence;
                evidence.subsystem = std::string(rule->subsystem);
                evidence.kind = "symbol";
                evidence.category = std::string(rule->category);
                evidence.addr = sym.addr;
                evidence.text = text;
                if (!sym.is_import && sym.kind == SymbolKind::Function && sym.addr != 0) {
                    evidence.functions.push_back(sym.addr);
                }
                add_evidence(out, summaries, functions, std::move(evidence));
            }
        }

        for (const auto& method : parse_objc_methods(b)) {
            std::string text = method.cls + " " + method.selector;
            if (!method.type_encoding.empty()) text += " " + decode_objc_type(method.type_encoding);
            for (const auto* rule : classify(text)) {
                AppSurfaceEvidence evidence;
                evidence.subsystem = std::string(rule->subsystem);
                evidence.kind = "objc_method";
                evidence.category = std::string(rule->category);
                evidence.addr = method.imp;
                evidence.text = (method.is_class ? "+" : "-") + method.cls + " " + method.selector;
                if (method.imp != 0) evidence.functions.push_back(method.imp);
                add_evidence(out, summaries, functions, std::move(evidence));
            }
        }

        for (const auto& cls : parse_itanium_rtti(b)) {
            const std::string& text = cls.demangled_name.empty() ? cls.mangled_name : cls.demangled_name;
            for (const auto* rule : classify(text)) {
                AppSurfaceEvidence evidence;
                evidence.subsystem = std::string(rule->subsystem);
                evidence.kind = "rtti_class";
                evidence.category = std::string(rule->category);
                evidence.addr = cls.typeinfo;
                evidence.text = text;
                for (addr_t method : cls.methods) {
                    if (method != 0) push_unique(evidence.functions, method);
                }
                add_evidence(out, summaries, functions, std::move(evidence));
            }
        }

        for (const auto& log : mine_log_categories(b)) {
            std::string text = log.category;
            for (const auto& example : log.examples) text += " " + example;
            for (const auto* rule : classify(text)) {
                AppSurfaceEvidence evidence;
                evidence.subsystem = std::string(rule->subsystem);
                evidence.kind = "log_category";
                evidence.category = "log_category";
                evidence.text = log.category;
                evidence.functions = log.functions;
                add_evidence(out, summaries, functions, std::move(evidence));
            }
        }
    }

    for (auto& evidence : classify_artifact_evidence(options.artifact_strings)) {
        add_evidence(out, summaries, functions, std::move(evidence));
    }

    finish_analysis(out, summaries, functions);
    return out;
}

}  // namespace ember
