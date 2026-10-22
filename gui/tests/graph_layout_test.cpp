// Invariants of the graph view's layered layout, without Qt.
#include <cstdio>
#include <cstdlib>

#include "../src/graph_layout.hpp"

using spelunk::gui::GraphLayout;
using spelunk::gui::GraphLayoutInput;
using spelunk::gui::layout_graph;

namespace {

int failures = 0;

void check(bool ok, const char* what) {
    std::fprintf(stderr, "%s %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++failures;
}

GraphLayoutInput graph(std::size_t nodes, std::initializer_list<GraphLayoutInput::Edge> edges) {
    GraphLayoutInput in;
    for (std::size_t i = 0; i < nodes; ++i) in.nodes.push_back({120.0 + 10.0 * static_cast<double>(i), 40});
    in.edges.assign(edges.begin(), edges.end());
    return in;
}

bool overlap_free(const GraphLayoutInput& in, const GraphLayout& out) {
    for (std::size_t a = 0; a < in.nodes.size(); ++a) {
        for (std::size_t b = a + 1; b < in.nodes.size(); ++b) {
            const auto& pa = out.positions[a];
            const auto& pb = out.positions[b];
            const bool apart_x = pa.x + in.nodes[a].width <= pb.x || pb.x + in.nodes[b].width <= pa.x;
            const bool apart_y = pa.y + in.nodes[a].height <= pb.y || pb.y + in.nodes[b].height <= pa.y;
            if (!apart_x && !apart_y) return false;
        }
    }
    return true;
}

// Every route leaves the bottom of its source and enters the top of its target.
bool routes_attach(const GraphLayoutInput& in, const GraphLayout& out) {
    for (std::size_t e = 0; e < in.edges.size(); ++e) {
        const auto& route = out.routes[e];
        if (route.size() < 2) return false;
        const auto& from = out.positions[in.edges[e].from];
        const auto& to = out.positions[in.edges[e].to];
        if (route.front().y != from.y + in.nodes[in.edges[e].from].height) return false;
        if (route.back().y != to.y) return false;
        if (route.front().x < from.x || route.front().x > from.x + in.nodes[in.edges[e].from].width) return false;
        if (route.back().x < to.x || route.back().x > to.x + in.nodes[in.edges[e].to].width) return false;
    }
    return true;
}

}  // namespace

int main() {
    {
        const auto in = graph(4, {{0, 1}, {0, 2}, {1, 3}, {2, 3}});
        const auto out = layout_graph(in);
        check(out.layers[0] == 0 && out.layers[1] == 1 && out.layers[2] == 1 && out.layers[3] == 2,
              "diamond: entry on top, the join below both arms");
        check(!out.back_edge[0] && !out.back_edge[1] && !out.back_edge[2] && !out.back_edge[3],
              "diamond: no back edges");
        check(overlap_free(in, out), "diamond: blocks do not overlap");
        check(routes_attach(in, out), "diamond: edges run bottom to top");
        check(out.positions[0].y < out.positions[1].y && out.positions[1].y < out.positions[3].y,
              "diamond: layers stack downward");
    }
    {
        // 0 -> 1 -> 2 -> 1 (loop), 2 -> 3 (exit)
        const auto in = graph(4, {{0, 1}, {1, 2}, {2, 1}, {2, 3}});
        const auto out = layout_graph(in);
        check(out.back_edge[2] && !out.back_edge[0] && !out.back_edge[1] && !out.back_edge[3],
              "loop: only the latch edge is a back edge");
        check(out.layers[1] < out.layers[2] && out.layers[2] < out.layers[3], "loop: body below header");
        bool lane_clear = true;
        for (const auto& p : out.routes[2]) {
            if (p.y <= out.positions[2].y + in.nodes[2].height && p.y >= out.positions[1].y)
                for (std::size_t v : {1u, 2u})
                    if (p.x > out.positions[v].x && p.x < out.positions[v].x + in.nodes[v].width &&
                        p.y > out.positions[v].y && p.y < out.positions[v].y + in.nodes[v].height)
                        lane_clear = false;
        }
        check(lane_clear, "loop: back edge routes around the blocks");
        check(overlap_free(in, out) && routes_attach(in, out), "loop: no overlaps, edges attach");
    }
    {
        // 0 -> 1 -> 2 and 0 -> 2: the long edge must pass beside block 1.
        const auto in = graph(3, {{0, 1}, {1, 2}, {0, 2}});
        const auto out = layout_graph(in);
        const auto& middle = out.positions[1];
        bool clear = true;
        for (const auto& p : out.routes[2])
            if (p.x > middle.x && p.x < middle.x + in.nodes[1].width && p.y > middle.y &&
                p.y < middle.y + in.nodes[1].height) clear = false;
        check(out.routes[2].size() == 6 && clear, "long edge routes around the block it skips");
        check(overlap_free(in, out) && routes_attach(in, out), "long edge: no overlaps, edges attach");
    }
    {
        const auto in = graph(2, {{0, 0}, {0, 1}});
        const auto out = layout_graph(in);
        check(out.back_edge[0] && !out.back_edge[1], "self loop is a back edge");
        check(routes_attach(in, out), "self loop attaches to its block");
    }
    {
        const auto in = graph(3, {{0, 1}});
        const auto out = layout_graph(in);
        check(out.positions.size() == 3 && overlap_free(in, out), "unreachable block still gets a place");
    }
    {
        const auto out = layout_graph(GraphLayoutInput{});
        check(out.positions.empty() && out.routes.empty(), "empty graph lays out to nothing");
    }
    std::fprintf(stderr, "%d failure(s)\n", failures);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
