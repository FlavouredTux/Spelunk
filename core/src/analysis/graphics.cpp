#include <spelunk/analysis/graphics.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <initializer_list>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#include <spelunk/analysis/discovery.hpp>
#include <spelunk/analysis/pipeline.hpp>
#include <spelunk/analysis/strings.hpp>
#include <spelunk/binary/binary.hpp>
#include <spelunk/binary/symbol.hpp>
#include <spelunk/common/types.hpp>

namespace spelunk {

namespace {

struct ClassifiedString {
    GraphicsBackend backend = GraphicsBackend::OpenGL;
    std::string     category;
    std::string     domain;
    std::string     api_name;
    std::string     canonical_api_name;
    std::string     api_extension;
};

struct ApiNameInfo {
    std::string canonical;
    std::string extension;
};

[[nodiscard]] std::string lower_ascii_copy(std::string_view text) {
    std::string out(text);
    for (char& c : out) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

[[nodiscard]] bool is_alnum_ascii(char c) noexcept {
    return std::isalnum(static_cast<unsigned char>(c));
}

[[nodiscard]] bool is_ident_char(char c) noexcept {
    return is_alnum_ascii(c) || c == '_';
}

[[nodiscard]] bool is_upper_ident(std::string_view tok) noexcept {
    bool has_letter = false;
    for (char c : tok) {
        if (!(std::isupper(static_cast<unsigned char>(c)) ||
              std::isdigit(static_cast<unsigned char>(c)) ||
              c == '_')) {
            return false;
        }
        if (std::isupper(static_cast<unsigned char>(c))) has_letter = true;
    }
    return has_letter;
}

[[nodiscard]] bool is_gl_ident(std::string_view tok) noexcept {
    if (tok.size() < 4 || tok.size() > 80) return false;
    if (!tok.starts_with("gl")) return false;
    if (!std::isupper(static_cast<unsigned char>(tok[2]))) return false;
    return std::ranges::all_of(tok, is_alnum_ascii);
}

[[nodiscard]] bool is_vk_ident(std::string_view tok) noexcept {
    if (tok.size() < 4 || tok.size() > 96) return false;
    if (!tok.starts_with("vk")) return false;
    if (!std::isupper(static_cast<unsigned char>(tok[2]))) return false;
    return std::ranges::all_of(tok, is_alnum_ascii);
}

[[nodiscard]] bool is_wgl_ident(std::string_view tok) noexcept {
    if (tok.size() < 5 || tok.size() > 96) return false;
    if (!tok.starts_with("wgl")) return false;
    if (!std::isupper(static_cast<unsigned char>(tok[3]))) return false;
    return std::ranges::all_of(tok, is_alnum_ascii);
}

[[nodiscard]] bool is_egl_ident(std::string_view tok) noexcept {
    if (tok.size() < 5 || tok.size() > 96) return false;
    if (!tok.starts_with("egl")) return false;
    if (!std::isupper(static_cast<unsigned char>(tok[3]))) return false;
    return std::ranges::all_of(tok, is_alnum_ascii);
}

[[nodiscard]] bool is_sdl_ident(std::string_view tok) noexcept {
    if (tok.size() < 5 || tok.size() > 96) return false;
    if (!tok.starts_with("SDL_")) return false;
    constexpr std::array prefixes = {
        "Add", "Alloc", "Atomic", "Audio", "Clear", "Close", "Cond",
        "Convert", "Create", "Del", "Delay", "Destroy", "Disable", "Enable",
        "Error", "Event", "Fill", "Free", "GameController", "Get", "GL_",
        "Haptic", "HID", "Init", "Joystick", "Load", "Lock", "Log", "Lower",
        "Map", "Mix", "Open", "Pause", "Peep", "Poll", "Pump", "Push", "Quit",
        "Raise", "Read", "Register", "Render", "RW", "Save", "Sem", "Set",
        "Show", "Surface", "Thread", "Try", "Unlock", "Update", "Upper",
        "Vulkan_", "Wait", "Window", "Write",
    };
    const auto rest = tok.substr(4);
    bool known_prefix = false;
    for (std::string_view prefix : prefixes) {
        if (rest.starts_with(prefix)) {
            known_prefix = true;
            break;
        }
    }
    if (!known_prefix) return false;
    for (char c : rest) {
        if (!is_ident_char(c)) return false;
    }
    return true;
}

[[nodiscard]] bool is_metal_ident(std::string_view tok) noexcept {
    if (tok.size() < 6 || tok.size() > 120) return false;
    if (tok.starts_with("MTL")) {
        return std::ranges::all_of(tok, is_ident_char);
    }
    return tok == "MTLCreateSystemDefaultDevice" ||
           tok == "newLibraryWithSource" ||
           tok == "newRenderPipelineStateWithDescriptor" ||
           tok == "newComputePipelineStateWithFunction";
}

[[nodiscard]] std::optional<GraphicsBackend>
backend_for_api_ident(std::string_view tok) noexcept {
    if (is_gl_ident(tok)) return GraphicsBackend::OpenGL;
    if (is_wgl_ident(tok)) return GraphicsBackend::OpenGL;
    if (is_egl_ident(tok)) return GraphicsBackend::OpenGL;
    if (is_vk_ident(tok)) return GraphicsBackend::Vulkan;
    if (is_sdl_ident(tok)) return GraphicsBackend::SDL;
    if (is_metal_ident(tok)) return GraphicsBackend::Metal;
    return std::nullopt;
}

void push_unique(std::vector<ClassifiedString>& out, ClassifiedString c) {
    for (const auto& e : out) {
        if (e.backend == c.backend && e.category == c.category &&
            e.domain == c.domain && e.api_name == c.api_name &&
            e.canonical_api_name == c.canonical_api_name &&
            e.api_extension == c.api_extension) {
            return;
        }
    }
    out.push_back(std::move(c));
}

[[nodiscard]] std::optional<std::string_view>
api_extension_suffix(GraphicsBackend backend, std::string_view api_name) {
    auto find_suffix = [&](const auto& suffixes) -> std::optional<std::string_view> {
        for (std::string_view suffix : suffixes) {
            if (api_name.size() <= suffix.size() + 3) continue;
            if (api_name.ends_with(suffix)) return suffix;
        }
        return std::nullopt;
    };
    constexpr std::array gl_suffixes = {
        "NVX", "APPLE", "ANGLE", "MESA", "INTEL", "AMD", "ATI", "ARB", "EXT",
        "KHR", "OES", "OVR", "QCOM", "IMG", "NV", "SGIX", "SGIS", "SGI", "IBM",
        "SUN", "S3TC", "GREMEDY",
    };
    constexpr std::array vk_suffixes = {
        "ANDROID", "FUCHSIA", "GOOGLE", "HUAWEI", "QCOM", "VALVE", "KHR", "EXT",
        "AMD", "NV", "NVX", "INTEL", "ARM", "IMG", "QNX", "NN", "SEC",
    };
    switch (backend) {
        case GraphicsBackend::OpenGL: return find_suffix(gl_suffixes);
        case GraphicsBackend::Vulkan: return find_suffix(vk_suffixes);
        case GraphicsBackend::Metal:
        case GraphicsBackend::SDL:
        case GraphicsBackend::GLSL:
        case GraphicsBackend::SPIRV:  return std::nullopt;
    }
    return std::nullopt;
}

[[nodiscard]] ApiNameInfo canonicalize_api_name(GraphicsBackend backend,
                                                std::string_view api_name) {
    ApiNameInfo info{std::string(api_name), {}};
    if (const auto ext = api_extension_suffix(backend, api_name)) {
        info.extension = std::string(*ext);
        info.canonical.resize(info.canonical.size() - ext->size());
    }
    return info;
}

[[nodiscard]] bool contains_any(std::string_view text,
                                std::initializer_list<std::string_view> needles) {
    for (std::string_view needle : needles) {
        if (text.find(needle) != std::string_view::npos) return true;
    }
    return false;
}

[[nodiscard]] bool contains_token_prefix(std::string_view text,
                                         std::string_view prefix) {
    std::size_t pos = 0;
    while ((pos = text.find(prefix, pos)) != std::string_view::npos) {
        const bool left_ok = pos == 0 || !is_ident_char(text[pos - 1]);
        if (left_ok) return true;
        pos += prefix.size();
    }
    return false;
}

[[nodiscard]] std::string api_domain(GraphicsBackend backend,
                                     std::string_view api_name) {
    switch (backend) {
        case GraphicsBackend::OpenGL: {
            std::string_view tail = api_name;
            if (api_name.starts_with("glX")) tail = api_name.substr(3);
            else if (api_name.starts_with("wgl") || api_name.starts_with("egl")) tail = api_name.substr(3);
            else if (api_name.starts_with("gl")) tail = api_name.substr(2);
            if (contains_any(tail, {"GetProcAddress", "GetProcAddressARB",
                                    "GetProcAddressEXT", "GetProcAddressOES"})) return "loader";
            if (contains_any(tail, {"Context", "MakeCurrent", "ChoosePixelFormat",
                                    "SwapBuffers", "Drawable", "Display"})) return "context";
            if (contains_any(tail, {"Surface", "Config", "Pixmap", "Pbuffer"})) return "surface";
            if (contains_any(tail, {"Buffer", "MapBuffer", "UnmapBuffer"})) return "buffer";
            if (contains_any(tail, {"Shader", "ShaderSource", "CompileShader"})) return "shader";
            if (contains_any(tail, {"Program", "AttachShader", "LinkProgram", "UseProgram"})) return "program";
            if (tail.starts_with("Uniform")) return "uniform";
            if (contains_any(tail, {"Framebuffer", "Renderbuffer", "DrawBuffers", "BlitFramebuffer"})) return "framebuffer";
            if (contains_any(tail, {"Texture", "Tex", "Sampler", "Mipmap"})) return "texture";
            if (contains_any(tail, {"Vertex", "Attrib", "VertexArray"})) return "vertex_input";
            if (tail.starts_with("Draw") || tail.starts_with("MultiDraw")) return "draw";
            if (contains_any(tail, {"Fence", "Sync", "Flush", "Finish"})) return "sync";
            if (contains_any(tail, {"ObjectLabel", "Debug", "Message"})) return "debug";
            if (tail.starts_with("Get") || tail.starts_with("Is") || contains_any(tail, {"Query"})) return "query";
            if (contains_any(tail, {"Enable", "Disable", "Blend", "Depth", "Cull", "Viewport",
                                    "Scissor", "Clear", "ColorMask", "DepthMask", "Stencil"})) {
                return "state";
            }
            return "general";
        }
        case GraphicsBackend::Vulkan: {
            std::string_view tail = api_name.starts_with("vk")
                ? api_name.substr(2)
                : api_name;
            if (contains_any(tail, {"Swapchain", "Surface", "Present", "Acquire"})) return "presentation";
            if (contains_any(tail, {"Instance", "Device", "PhysicalDevice", "Queue"})) return "device";
            if (contains_any(tail, {"Buffer", "Image", "Memory", "Allocation"})) return "memory_resource";
            if (contains_any(tail, {"Shader", "ShaderModule"})) return "shader";
            if (contains_any(tail, {"Pipeline"})) return "pipeline";
            if (contains_any(tail, {"Descriptor"})) return "descriptor";
            if (contains_any(tail, {"RenderPass", "Framebuffer"})) return "render_pass";
            if (tail.starts_with("CmdDraw") || tail.starts_with("Draw")) return "draw";
            if (contains_any(tail, {"Command"}) || tail.starts_with("Cmd")) return "command";
            if (contains_any(tail, {"Semaphore", "Fence", "Event"})) return "sync";
            if (contains_any(tail, {"Debug", "Validation"})) return "debug";
            return "general";
        }
        case GraphicsBackend::SDL: {
            if (contains_any(api_name, {"GL_", "Vulkan"})) return "graphics_bridge";
            if (api_name.find("Window") != std::string_view::npos) return "window";
            if (api_name.find("RW") != std::string_view::npos) return "io";
            if (contains_any(api_name, {"Joystick", "GameController", "Gamepad",
                                        "Haptic", "Rumble", "HID"})) return "input";
            if (api_name.find("Event") != std::string_view::npos) return "event";
            return "general";
        }
        case GraphicsBackend::Metal: {
            if (contains_any(api_name, {"Library", "Shader", "Function"})) return "shader";
            if (api_name.find("Pipeline") != std::string_view::npos) return "pipeline";
            if (contains_any(api_name, {"Texture", "Sampler"})) return "texture";
            if (contains_any(api_name, {"Buffer", "Heap"})) return "buffer";
            if (contains_any(api_name, {"Command", "Queue"})) return "command";
            if (api_name.find("Device") != std::string_view::npos) return "device";
            return "general";
        }
        case GraphicsBackend::GLSL:  return "shader";
        case GraphicsBackend::SPIRV: return "shader";
    }
    return "general";
}

[[nodiscard]] std::string gl_constant_domain(std::string_view tok) {
    if (contains_any(tok, {"GET_PROC_ADDRESS"})) return "loader";
    if (contains_any(tok, {"CONTEXT", "PIXEL_FORMAT", "MAKE_CURRENT", "DRAWABLE"})) return "context";
    if (contains_any(tok, {"SURFACE", "PBUFFER", "CONFIG"})) return "surface";
    if (contains_any(tok, {"BUFFER", "PIXEL_PACK", "PIXEL_UNPACK"})) return "buffer";
    if (contains_any(tok, {"FRAMEBUFFER", "RENDERBUFFER", "ATTACHMENT"})) return "framebuffer";
    if (contains_any(tok, {"TEXTURE", "SAMPLER", "MIPMAP", "COMPRESSED"})) return "texture";
    if (contains_any(tok, {"VERTEX", "ATTRIB", "ARRAY"})) return "vertex_input";
    if (contains_any(tok, {"SHADER", "COMPILE"})) return "shader";
    if (contains_any(tok, {"PROGRAM", "LINK"})) return "program";
    if (contains_any(tok, {"UNIFORM"})) return "uniform";
    if (contains_any(tok, {"DRAW", "TRIANGLES", "LINES", "POINTS", "ELEMENTS"})) return "draw";
    if (contains_any(tok, {"SYNC", "FENCE"})) return "sync";
    if (contains_any(tok, {"DEBUG", "MESSAGE"})) return "debug";
    if (contains_any(tok, {"QUERY", "VENDOR", "RENDERER", "VERSION", "EXTENSIONS"})) return "query";
    if (contains_any(tok, {"ENABLE", "BLEND", "DEPTH", "STENCIL", "CULL", "SCISSOR",
                           "VIEWPORT", "CLEAR", "COLOR", "MASK", "CAP"})) {
        return "state";
    }
    return "general";
}

[[nodiscard]] std::string vk_constant_domain(std::string_view tok) {
    if (contains_any(tok, {"SURFACE", "SWAPCHAIN", "PRESENT", "ACQUIRE"})) return "presentation";
    if (contains_any(tok, {"INSTANCE", "DEVICE", "QUEUE", "PHYSICAL_DEVICE"})) return "device";
    if (contains_any(tok, {"BUFFER", "IMAGE", "MEMORY", "FORMAT", "TILING"})) return "memory_resource";
    if (contains_any(tok, {"SHADER"})) return "shader";
    if (contains_any(tok, {"PIPELINE"})) return "pipeline";
    if (contains_any(tok, {"DESCRIPTOR"})) return "descriptor";
    if (contains_any(tok, {"RENDER_PASS", "FRAMEBUFFER", "SUBPASS"})) return "render_pass";
    if (contains_any(tok, {"COMMAND"})) return "command";
    if (contains_any(tok, {"SEMAPHORE", "FENCE", "EVENT"})) return "sync";
    if (contains_any(tok, {"DEBUG", "VALIDATION"})) return "debug";
    return "general";
}

[[nodiscard]] std::string sdl_constant_domain(std::string_view tok) {
    if (contains_any(tok, {"SDL_GL_", "SDL_WINDOW_OPENGL", "SDL_WINDOW_VULKAN",
                           "SDL_PIXELFORMAT", "SDL_RENDERER"})) return "graphics_bridge";
    if (tok.find("WINDOW") != std::string_view::npos) return "window";
    if (contains_any(tok, {"JOYSTICK", "GAMECONTROLLER", "GAMEPAD", "HAPTIC", "HID"})) return "input";
    if (tok.find("EVENT") != std::string_view::npos) return "event";
    if (tok.find("RW") != std::string_view::npos) return "io";
    return "general";
}

[[nodiscard]] std::optional<std::string_view>
constant_extension_suffix(GraphicsBackend backend, std::string_view tok) {
    auto second_component = [](std::string_view name) -> std::optional<std::string_view> {
        const auto first = name.find('_');
        if (first == std::string_view::npos) return std::nullopt;
        const auto second = name.find('_', first + 1);
        if (second == std::string_view::npos) return std::nullopt;
        return name.substr(first + 1, second - first - 1);
    };
    auto suffix_component = [](std::string_view name) -> std::optional<std::string_view> {
        const auto last = name.rfind('_');
        if (last == std::string_view::npos || last + 1 >= name.size()) return std::nullopt;
        return name.substr(last + 1);
    };
    constexpr std::array gl_exts = {
        "ARB", "EXT", "KHR", "OES", "NV", "NVX", "AMD", "ATI", "APPLE", "ANGLE",
        "MESA", "INTEL", "QCOM", "IMG", "SGIX", "SGIS", "GREMEDY",
    };
    constexpr std::array vk_exts = {
        "KHR", "EXT", "AMD", "NV", "NVX", "GOOGLE", "ANDROID", "QCOM", "HUAWEI",
        "VALVE", "INTEL", "ARM", "IMG", "FUCHSIA", "QNX",
    };
    std::array<std::optional<std::string_view>, 2> candidates{
        second_component(tok),
        suffix_component(tok),
    };
    if (backend == GraphicsBackend::Vulkan) {
        candidates[0] = suffix_component(tok);
        candidates[1] = std::nullopt;
    }
    const auto match_ext = [&](const auto& exts) -> std::optional<std::string_view> {
        for (const auto& candidate : candidates) {
            if (!candidate) continue;
            for (std::string_view ext : exts) {
                if (*candidate == ext) return *candidate;
            }
        }
        return std::nullopt;
    };
    if (backend == GraphicsBackend::OpenGL) {
        return match_ext(gl_exts);
    }
    return match_ext(vk_exts);
}

void classify_constant_tokens(std::string_view text,
                              std::vector<ClassifiedString>& out) {
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (i > 0 && is_ident_char(text[i - 1])) continue;
        if (!(text.substr(i).starts_with("GL_") ||
              text.substr(i).starts_with("GLX_") ||
              text.substr(i).starts_with("WGL_") ||
              text.substr(i).starts_with("EGL_") ||
              text.substr(i).starts_with("VK_") ||
              text.substr(i).starts_with("SDL_"))) {
            continue;
        }
        std::size_t j = i;
        while (j < text.size() && is_ident_char(text[j])) ++j;
        const auto tok = text.substr(i, j - i);
        if (tok.size() < 5 || tok.size() > 128) continue;

        GraphicsBackend backend = GraphicsBackend::OpenGL;
        std::string domain = "general";
        if (tok.starts_with("VK_")) {
            backend = GraphicsBackend::Vulkan;
            domain = vk_constant_domain(tok);
        } else if (tok.starts_with("SDL_")) {
            backend = GraphicsBackend::SDL;
            domain = sdl_constant_domain(tok);
        } else {
            domain = gl_constant_domain(tok);
        }

        const auto ext = (backend == GraphicsBackend::OpenGL ||
                          backend == GraphicsBackend::Vulkan)
            ? constant_extension_suffix(backend, tok)
            : std::nullopt;
        const bool extension_name =
            ext && (tok.find('_', tok.find('_') + 1) != std::string_view::npos);
        if (!extension_name && !is_upper_ident(tok)) continue;

        push_unique(out, {backend,
                          extension_name ? "extension_name" : "constant_name",
                          extension_name ? "extension" : domain,
                          std::string(tok),
                          std::string(tok),
                          ext ? std::string(*ext) : std::string{}});
    }
}

void classify_api_tokens(std::string_view text,
                         std::vector<ClassifiedString>& out,
                         bool symbol_mode = false) {
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (i > 0 && is_ident_char(text[i - 1])) continue;
        if (!(text.substr(i).starts_with("gl") ||
              text.substr(i).starts_with("wgl") ||
              text.substr(i).starts_with("egl") ||
              text.substr(i).starts_with("vk") ||
              text.substr(i).starts_with("SDL_") ||
              text.substr(i).starts_with("MTL") ||
              text.substr(i).starts_with("newLibraryWithSource") ||
              text.substr(i).starts_with("newRenderPipelineStateWithDescriptor") ||
              text.substr(i).starts_with("newComputePipelineStateWithFunction"))) {
            continue;
        }
        std::size_t j = i;
        while (j < text.size() && is_ident_char(text[j])) ++j;
        const auto tok = text.substr(i, j - i);
        const auto backend = backend_for_api_ident(tok);
        if (!backend) continue;
        const bool exact_name = i == 0 && j == text.size();
        const bool call_expr = j < text.size() && text[j] == '(';
        if (!symbol_mode && !exact_name && !call_expr) continue;
        const std::string api(tok);
        const auto canonical = canonicalize_api_name(*backend, api);
        push_unique(out, {*backend,
                          exact_name ? "api_proc_name" : "api_call_expr",
                          api_domain(*backend, canonical.canonical),
                          api,
                          canonical.canonical,
                          canonical.extension});
    }
}

[[nodiscard]] std::string_view trim_symbol_decoration(std::string_view text) {
    while (text.starts_with("_")) text.remove_prefix(1);
    if (text.starts_with("imp_")) text.remove_prefix(4);
    if (text.starts_with("stub_")) text.remove_prefix(5);
    if (const auto at = text.find('@'); at != std::string_view::npos) {
        text = text.substr(0, at);
    }
    return text;
}

[[nodiscard]] std::vector<ClassifiedString>
classify_graphics_string(std::string_view text) {
    std::vector<ClassifiedString> out;
    classify_api_tokens(text, out);
    classify_constant_tokens(text, out);

    const auto lower = lower_ascii_copy(text);
    auto has = [&](std::string_view needle) {
        return lower.find(needle) != std::string::npos;
    };

    if (has("opengl.framework") || has("cglgetprocaddress") ||
        has("glxgetprocaddress") || has("wglgetprocaddress") ||
        has("eglgetprocaddress") || has("sdl_gl_getprocaddress")) {
        push_unique(out, {GraphicsBackend::OpenGL, "proc_resolver", "loader", {}, {}, {}});
    }
    if (has("opengl") || has("nsopengl") || has("cgl") ||
        has("glx") || has("wgl") || has("egl") ||
        has("glsl3") || has("gl_")) {
        push_unique(out, {GraphicsBackend::OpenGL, "backend_marker", "backend", {}, {}, {}});
    }
    if (has("vkgetinstanceprocaddr") || has("vkgetdeviceprocaddr")) {
        push_unique(out, {GraphicsBackend::Vulkan, "proc_resolver", "loader", {}, {}, {}});
    }
    if ((has("vulkan") && !has("sdl_vulkan_")) ||
        has("vulkan_desktop") || has("vulkan_mobile") ||
        contains_token_prefix(lower, "vk_")) {
        push_unique(out, {GraphicsBackend::Vulkan, "backend_marker", "backend", {}, {}, {}});
    }
    if (has("sdl_gl_getprocaddress") || has("sdl_vulkan_getinstanceextensions") ||
        has("sdl_vulkan_createsurface")) {
        push_unique(out, {GraphicsBackend::SDL, "proc_resolver", "graphics_bridge", {}, {}, {}});
    }
    if (has("sdl_")) {
        push_unique(out, {GraphicsBackend::SDL, "backend_marker", "backend", {}, {}, {}});
    }
    const bool metal_marker =
        text == "Metal" || text == "metal" ||
        text.find("MTL") != std::string_view::npos ||
        has("metal_osx") || has("metal_ios") || has("metal_mobile") ||
        has("debuggraphicsprefermetal") ||
        has("newlibrarywithsource") ||
        has("newrenderpipelinestatewithdescriptor");
    if (metal_marker) {
        push_unique(out, {GraphicsBackend::Metal, "backend_marker", "backend", {}, {}, {}});
    }
    if (has("#version") || has("gl_position") || has("layout(location") ||
        has("precision mediump") || has("sampler2d")) {
        push_unique(out, {GraphicsBackend::GLSL, "shader_source", "shader", {}, {}, {}});
    }
    if (has("spir-v") || has("spirv") || has("spv_")) {
        push_unique(out, {GraphicsBackend::SPIRV, "shader_bytecode", "shader", {}, {}, {}});
    }
    if ((has("shader pack") || has("shaders from pack")) &&
        (has("loaded") || has("opening") || has("corrupted") ||
         has("outdated") || has("variant"))) {
        push_unique(out, {GraphicsBackend::GLSL, "shader_pack", "shader_pack", {}, {}, {}});
    }
    if (has("failed to link shader program") || has("failed to create shader") ||
        has("compiled shader") || has("shader compile") ||
        has("shader program")) {
        push_unique(out, {GraphicsBackend::GLSL, "shader_pipeline", "shader", {}, {}, {}});
    }
    return out;
}

[[nodiscard]] std::vector<ClassifiedString>
classify_graphics_symbol(std::string_view raw_name) {
    const auto name = trim_symbol_decoration(raw_name);
    std::vector<ClassifiedString> out;
    classify_api_tokens(name, out, true);

    const auto lower = lower_ascii_copy(name);
    auto has = [&](std::string_view needle) {
        return lower.find(needle) != std::string::npos;
    };
    if (has("opengl") || has("nsopengl") || has("cgl")) {
        push_unique(out, {GraphicsBackend::OpenGL, "symbol_marker", "backend", {}, {}, {}});
    }
    if (has("vulkan")) {
        push_unique(out, {GraphicsBackend::Vulkan, "symbol_marker", "backend", {}, {}, {}});
    }
    if (has("sdl")) {
        push_unique(out, {GraphicsBackend::SDL, "symbol_marker", "backend", {}, {}, {}});
    }
    if (name.find("MTL") != std::string_view::npos || has("metal")) {
        push_unique(out, {GraphicsBackend::Metal, "symbol_marker", "backend", {}, {}, {}});
    }
    return out;
}

[[nodiscard]] std::optional<addr_t>
enclosing_function_at(const Binary& b,
                      const std::vector<DiscoveredFunction>& fns,
                      addr_t addr) {
    if (!addr_in_code_section(b, addr)) return std::nullopt;
    auto it = std::upper_bound(fns.begin(), fns.end(), addr,
        [](addr_t a, const DiscoveredFunction& d) { return a < d.addr; });
    if (it == fns.begin()) return std::nullopt;
    --it;
    if (it->size != 0 && addr >= it->addr + it->size) return std::nullopt;
    if (it->size == 0) {
        auto next = it;
        ++next;
        if (next != fns.end() && addr >= next->addr) return std::nullopt;
    }
    if (b.bytes_at(it->addr).empty()) return std::nullopt;
    return it->addr;
}

struct FnAccumulator {
    std::set<addr_t>      string_addrs;
    std::set<std::string> symbol_names;
    std::set<std::string> api_names;
    std::set<std::string> extensions;
    std::set<std::string> categories;
    std::set<std::string> domains;
    std::vector<std::string> evidence;
};

struct ApiAccumulator {
    std::set<std::string> domains;
    std::set<std::string> categories;
    std::set<std::string> variants;
    std::set<std::string> extensions;
    std::set<addr_t>      string_addrs;
    std::set<addr_t>      xrefs;
    std::set<addr_t>      functions;
    std::set<std::string> symbols;
};

struct ExtensionAccumulator {
    std::set<std::string> apis;
    std::set<std::string> variants;
    std::set<std::string> domains;
    std::set<std::string> categories;
    std::set<addr_t>      string_addrs;
    std::set<addr_t>      xrefs;
    std::set<addr_t>      functions;
    std::set<std::string> symbols;
};

[[nodiscard]] std::string role_for(const FnAccumulator& acc,
                                   GraphicsBackend backend) {
    const std::size_t loader_threshold =
        backend == GraphicsBackend::OpenGL ? 12 :
        backend == GraphicsBackend::Vulkan ? 8 :
        backend == GraphicsBackend::SDL ? 4 : 6;
    if (acc.api_names.size() >= loader_threshold &&
        acc.categories.contains("api_proc_name")) {
        return "proc_loader";
    }
    if (acc.categories.contains("proc_resolver")) return "proc_resolver";
    if (acc.categories.contains("shader_pipeline") ||
        acc.categories.contains("shader_pack") ||
        acc.categories.contains("shader_source") ||
        acc.categories.contains("shader_bytecode")) {
        return "shader_pipeline";
    }
    if (!acc.api_names.empty()) return "api_user";
    if (acc.categories.contains("constant_name") ||
        acc.categories.contains("extension_name")) {
        return "constant_user";
    }
    return "backend_surface";
}

void add_evidence(FnAccumulator& acc, std::string text) {
    if (text.size() > 96) {
        text.resize(93);
        text += "...";
    }
    for (const auto& e : acc.evidence) {
        if (e == text) return;
    }
    if (acc.evidence.size() < 4) acc.evidence.push_back(std::move(text));
}

template <class T>
[[nodiscard]] std::vector<T> vector_from_set(const std::set<T>& values) {
    return {values.begin(), values.end()};
}

}  // namespace

std::string_view graphics_backend_name(GraphicsBackend b) noexcept {
    switch (b) {
        case GraphicsBackend::OpenGL: return "opengl";
        case GraphicsBackend::Vulkan: return "vulkan";
        case GraphicsBackend::SDL:    return "sdl";
        case GraphicsBackend::Metal:  return "metal";
        case GraphicsBackend::GLSL:   return "glsl";
        case GraphicsBackend::SPIRV:  return "spirv";
    }
    return "unknown";
}

GraphicsAnalysis analyze_graphics_surface(const Binary& b) {
    GraphicsAnalysis out;
    const auto fns = enumerate_functions(b, EnumerateMode::Cheap);
    const auto strings = scan_strings(b);

    std::map<std::pair<addr_t, GraphicsBackend>, FnAccumulator> by_fn;
    std::map<std::pair<GraphicsBackend, std::string>, ApiAccumulator> by_api;
    std::map<std::pair<GraphicsBackend, std::string>, ExtensionAccumulator> by_extension;
    std::map<GraphicsBackend, std::set<addr_t>> functions_by_backend;
    std::map<GraphicsBackend, std::set<std::string>> api_by_backend;
    std::map<GraphicsBackend, std::set<std::string>> domains_by_backend;
    std::map<GraphicsBackend, std::set<std::string>> evidence_by_backend;
    std::map<GraphicsBackend, std::size_t> string_count_by_backend;
    std::map<GraphicsBackend, std::size_t> symbol_count_by_backend;

    for (const auto& s : strings) {
        const auto classes = classify_graphics_string(s.text);
        if (classes.empty()) continue;

        std::set<addr_t> xref_functions;
        for (addr_t xr : s.xrefs) {
            if (auto fn = enclosing_function_at(b, fns, xr)) {
                xref_functions.insert(*fn);
            }
        }
        const auto string_functions = vector_from_set(xref_functions);

        for (const auto& c : classes) {
            out.strings.push_back({s.addr, c.backend, c.category, c.domain, c.api_name,
                                   c.canonical_api_name, c.api_extension, s.text,
                                   s.xrefs, string_functions});
            ++string_count_by_backend[c.backend];
            const bool contributes_api = c.category.starts_with("api_");
            const std::string api_key = !c.canonical_api_name.empty()
                ? (contributes_api ? c.canonical_api_name : std::string{})
                : (contributes_api ? c.api_name : std::string{});
            if (!api_key.empty()) api_by_backend[c.backend].insert(api_key);
            if (!c.domain.empty()) domains_by_backend[c.backend].insert(c.domain);
            ApiAccumulator* api_acc = nullptr;
            if (!api_key.empty()) {
                api_acc = &by_api[{c.backend, api_key}];
                api_acc->domains.insert(c.domain);
                api_acc->categories.insert(c.category);
                api_acc->variants.insert(c.api_name);
                if (!c.api_extension.empty()) api_acc->extensions.insert(c.api_extension);
                api_acc->string_addrs.insert(s.addr);
                for (addr_t xr : s.xrefs) api_acc->xrefs.insert(xr);
            }
            if (!c.api_extension.empty()) {
                auto& ext_acc = by_extension[{c.backend, c.api_extension}];
                if (!api_key.empty()) ext_acc.apis.insert(api_key);
                if (!c.api_name.empty()) ext_acc.variants.insert(c.api_name);
                if (!c.domain.empty()) ext_acc.domains.insert(c.domain);
                ext_acc.categories.insert(c.category);
                ext_acc.string_addrs.insert(s.addr);
                ext_acc.xrefs.insert(s.xrefs.begin(), s.xrefs.end());
                ext_acc.functions.insert(string_functions.begin(), string_functions.end());
            }
            if (evidence_by_backend[c.backend].size() < 6) {
                evidence_by_backend[c.backend].insert(c.api_name.empty() ? c.category
                                                                         : c.api_name);
            }

            for (addr_t xr : s.xrefs) {
                auto fn = enclosing_function_at(b, fns, xr);
                if (!fn) continue;
                functions_by_backend[c.backend].insert(*fn);
                if (api_acc) api_acc->functions.insert(*fn);
                auto& acc = by_fn[{*fn, c.backend}];
                acc.string_addrs.insert(s.addr);
                acc.categories.insert(c.category);
                acc.domains.insert(c.domain);
                if (!api_key.empty()) acc.api_names.insert(api_key);
                if (!c.api_extension.empty()) acc.extensions.insert(c.api_extension);
                add_evidence(acc, c.api_name.empty() ? s.text : c.api_name);
            }
        }
    }

    for (const auto& sym : b.symbols()) {
        if (sym.name.empty()) continue;
        const auto classes = classify_graphics_symbol(sym.name);
        if (classes.empty()) continue;
        const std::string linkage = sym.is_import
            ? "import"
            : (sym.is_export ? "export" : "defined");
        for (const auto& c : classes) {
            out.symbols.push_back({sym.addr, sym.got_addr, c.backend,
                                   c.api_name.empty() ? "symbol_marker" : "api_symbol",
                                   c.domain, c.api_name, c.canonical_api_name,
                                   c.api_extension, sym.name, linkage});
            ++symbol_count_by_backend[c.backend];
            const std::string api_key = !c.canonical_api_name.empty()
                ? c.canonical_api_name
                : c.api_name;
            if (!api_key.empty()) api_by_backend[c.backend].insert(api_key);
            if (!c.domain.empty()) domains_by_backend[c.backend].insert(c.domain);
            if (!api_key.empty()) {
                auto& api_acc = by_api[{c.backend, api_key}];
                api_acc.domains.insert(c.domain);
                api_acc.categories.insert("api_symbol");
                api_acc.variants.insert(c.api_name);
                if (!c.api_extension.empty()) api_acc.extensions.insert(c.api_extension);
                api_acc.symbols.insert(sym.name);
                if (sym.addr != 0 && !sym.is_import) api_acc.functions.insert(sym.addr);
            }
            if (evidence_by_backend[c.backend].size() < 6) {
                evidence_by_backend[c.backend].insert(c.api_name.empty() ? sym.name
                                                                         : c.api_name);
            }
            if (sym.addr != 0 && !sym.is_import) {
                functions_by_backend[c.backend].insert(sym.addr);
                auto& acc = by_fn[{sym.addr, c.backend}];
                acc.symbol_names.insert(sym.name);
                acc.categories.insert(api_key.empty() ? "symbol_marker" : "api_symbol");
                acc.domains.insert(c.domain);
                if (!api_key.empty()) acc.api_names.insert(api_key);
                if (!c.api_extension.empty()) acc.extensions.insert(c.api_extension);
                add_evidence(acc, c.api_name.empty() ? sym.name : c.api_name);
            }
        }
    }

    constexpr std::array backends = {
        GraphicsBackend::OpenGL,
        GraphicsBackend::Vulkan,
        GraphicsBackend::SDL,
        GraphicsBackend::Metal,
        GraphicsBackend::GLSL,
        GraphicsBackend::SPIRV,
    };
    for (GraphicsBackend backend : backends) {
        const auto strings_n = string_count_by_backend[backend];
        const auto symbols_n = symbol_count_by_backend[backend];
        const auto funcs_n = functions_by_backend[backend].size();
        const auto api_n = api_by_backend[backend].size();
        if (strings_n == 0 && symbols_n == 0 && funcs_n == 0 && api_n == 0) continue;
        GraphicsBackendSummary s;
        s.backend = backend;
        s.string_count = strings_n;
        s.symbol_count = symbols_n;
        s.function_count = funcs_n;
        s.api_name_count = api_n;
        for (const auto& d : domains_by_backend[backend]) {
            s.domains.push_back(d);
        }
        for (const auto& e : evidence_by_backend[backend]) {
            if (s.evidence.size() >= 6) break;
            s.evidence.push_back(e);
        }
        out.summaries.push_back(std::move(s));
    }

    for (const auto& [key, acc] : by_api) {
        const auto& [backend, api_name] = key;
        GraphicsApiFact api;
        api.backend = backend;
        api.api_name = api_name;
        api.variants = vector_from_set(acc.variants);
        api.extensions = vector_from_set(acc.extensions);
        api.domains = vector_from_set(acc.domains);
        api.categories = vector_from_set(acc.categories);
        api.string_count = acc.string_addrs.size();
        api.symbol_count = acc.symbols.size();
        api.xref_count = acc.xrefs.size();
        api.function_count = acc.functions.size();
        api.strings = vector_from_set(acc.string_addrs);
        api.xrefs = vector_from_set(acc.xrefs);
        api.functions = vector_from_set(acc.functions);
        api.symbols = vector_from_set(acc.symbols);
        for (const auto& ext : api.extensions) {
            auto& ext_acc = by_extension[{backend, ext}];
            ext_acc.apis.insert(api.api_name);
            ext_acc.variants.insert(api.variants.begin(), api.variants.end());
            ext_acc.domains.insert(api.domains.begin(), api.domains.end());
            ext_acc.categories.insert(api.categories.begin(), api.categories.end());
            ext_acc.string_addrs.insert(api.strings.begin(), api.strings.end());
            ext_acc.xrefs.insert(api.xrefs.begin(), api.xrefs.end());
            ext_acc.functions.insert(api.functions.begin(), api.functions.end());
            ext_acc.symbols.insert(api.symbols.begin(), api.symbols.end());
        }
        out.apis.push_back(std::move(api));
    }

    for (const auto& [key, acc] : by_extension) {
        const auto& [backend, extension] = key;
        GraphicsExtensionFact ext;
        ext.backend = backend;
        ext.extension = extension;
        ext.api_count = acc.apis.size();
        ext.variant_count = acc.variants.size();
        ext.string_count = acc.string_addrs.size();
        ext.symbol_count = acc.symbols.size();
        ext.xref_count = acc.xrefs.size();
        ext.function_count = acc.functions.size();
        ext.apis = vector_from_set(acc.apis);
        ext.variants = vector_from_set(acc.variants);
        ext.domains = vector_from_set(acc.domains);
        ext.categories = vector_from_set(acc.categories);
        ext.strings = vector_from_set(acc.string_addrs);
        ext.xrefs = vector_from_set(acc.xrefs);
        ext.functions = vector_from_set(acc.functions);
        ext.symbols = vector_from_set(acc.symbols);
        out.extensions.push_back(std::move(ext));
    }

    for (const auto& [key, acc] : by_fn) {
        const auto [fn, backend] = key;
        GraphicsFunctionFact f;
        f.function = fn;
        f.backend = backend;
        f.role = role_for(acc, backend);
        f.string_count = acc.string_addrs.size();
        f.symbol_count = acc.symbol_names.size();
        f.api_name_count = acc.api_names.size();
        f.extensions = vector_from_set(acc.extensions);
        f.categories = vector_from_set(acc.categories);
        for (const auto& d : acc.domains) f.domains.push_back(d);
        f.evidence = acc.evidence;
        out.functions.push_back(std::move(f));
    }

    std::ranges::sort(out.strings, {}, [](const GraphicsStringFact& f) {
        return std::tuple{f.addr, graphics_backend_name(f.backend),
                          f.category, f.domain, f.api_name};
    });
    std::ranges::sort(out.apis, {}, [](const GraphicsApiFact& a) {
        return std::tuple{graphics_backend_name(a.backend), a.api_name};
    });
    std::ranges::sort(out.extensions, {}, [](const GraphicsExtensionFact& e) {
        return std::tuple{graphics_backend_name(e.backend), e.extension};
    });
    std::ranges::sort(out.functions, {}, [](const GraphicsFunctionFact& f) {
        return std::tuple{f.function, graphics_backend_name(f.backend), f.role};
    });
    std::ranges::sort(out.symbols, {}, [](const GraphicsSymbolFact& s) {
        return std::tuple{graphics_backend_name(s.backend), s.linkage, s.name,
                          s.addr, s.got_addr};
    });
    return out;
}

}  // namespace spelunk
