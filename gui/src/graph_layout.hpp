#pragma once

#include <cstddef>
#include <vector>

namespace spelunk::gui {

// Layered layout for a function's control-flow graph, in the spirit of
// IDA's graph view: the entry block on top, every forward edge pointing
// down, back edges routed around the side. Free of Qt so it can be
// checked on its own.
struct GraphLayoutInput {
    struct Node {
        double width  = 0;
        double height = 0;
    };
    struct Edge {
        std::size_t from = 0;
        std::size_t to   = 0;
    };
    std::vector<Node> nodes;
    std::vector<Edge> edges;
    std::size_t       entry = 0;
};

struct GraphLayout {
    struct Point {
        double x = 0;
        double y = 0;
    };
    std::vector<Point>              positions;   // top-left corner of each node
    std::vector<std::size_t>        layers;      // layer of each node, entry = 0
    std::vector<bool>               back_edge;   // per edge: it closes a loop
    std::vector<std::vector<Point>> routes;      // per edge: source bottom to target top
    double                          width  = 0;
    double                          height = 0;
};

[[nodiscard]] GraphLayout layout_graph(const GraphLayoutInput& in);

}  // namespace spelunk::gui
