#pragma once

#include <string>
#include <vector>

#include <spelunk/common/types.hpp>

namespace spelunk {

class Binary;

enum class GraphicsBackend {
    OpenGL,
    Vulkan,
    SDL,
    Metal,
    GLSL,
    SPIRV,
};

struct GraphicsStringFact {
    addr_t              addr = 0;
    GraphicsBackend     backend = GraphicsBackend::OpenGL;
    std::string         category;
    std::string         domain;
    std::string         api_name;
    std::string         canonical_api_name;
    std::string         api_extension;
    std::string         text;
    std::vector<addr_t> xrefs;
    std::vector<addr_t> functions;
};

struct GraphicsSymbolFact {
    addr_t              addr = 0;
    addr_t              got_addr = 0;
    GraphicsBackend     backend = GraphicsBackend::OpenGL;
    std::string         category;
    std::string         domain;
    std::string         api_name;
    std::string         canonical_api_name;
    std::string         api_extension;
    std::string         name;
    std::string         linkage;
};

struct GraphicsApiFact {
    GraphicsBackend     backend = GraphicsBackend::OpenGL;
    std::string         api_name;
    std::vector<std::string> variants;
    std::vector<std::string> extensions;
    std::vector<std::string> domains;
    std::vector<std::string> categories;
    std::size_t         string_count = 0;
    std::size_t         symbol_count = 0;
    std::size_t         xref_count = 0;
    std::size_t         function_count = 0;
    std::vector<addr_t> strings;
    std::vector<addr_t> xrefs;
    std::vector<addr_t> functions;
    std::vector<std::string> symbols;
};

struct GraphicsExtensionFact {
    GraphicsBackend     backend = GraphicsBackend::OpenGL;
    std::string         extension;
    std::size_t         api_count = 0;
    std::size_t         variant_count = 0;
    std::size_t         string_count = 0;
    std::size_t         symbol_count = 0;
    std::size_t         xref_count = 0;
    std::size_t         function_count = 0;
    std::vector<std::string> apis;
    std::vector<std::string> variants;
    std::vector<std::string> domains;
    std::vector<std::string> categories;
    std::vector<addr_t>      strings;
    std::vector<addr_t>      xrefs;
    std::vector<addr_t>      functions;
    std::vector<std::string> symbols;
};

struct GraphicsFunctionFact {
    addr_t              function = 0;
    GraphicsBackend     backend = GraphicsBackend::OpenGL;
    std::string         role;
    std::size_t         string_count = 0;
    std::size_t         symbol_count = 0;
    std::size_t         api_name_count = 0;
    std::vector<std::string> extensions;
    std::vector<std::string> categories;
    std::vector<std::string> domains;
    std::vector<std::string> evidence;
};

struct GraphicsBackendSummary {
    GraphicsBackend     backend = GraphicsBackend::OpenGL;
    std::size_t         string_count = 0;
    std::size_t         symbol_count = 0;
    std::size_t         function_count = 0;
    std::size_t         api_name_count = 0;
    std::vector<std::string> domains;
    std::vector<std::string> evidence;
};

struct GraphicsAnalysis {
    std::vector<GraphicsBackendSummary> summaries;
    std::vector<GraphicsApiFact>        apis;
    std::vector<GraphicsExtensionFact>  extensions;
    std::vector<GraphicsFunctionFact>   functions;
    std::vector<GraphicsStringFact>     strings;
    std::vector<GraphicsSymbolFact>     symbols;
};

[[nodiscard]] std::string_view graphics_backend_name(GraphicsBackend b) noexcept;

[[nodiscard]] GraphicsAnalysis analyze_graphics_surface(const Binary& b);

}  // namespace spelunk
