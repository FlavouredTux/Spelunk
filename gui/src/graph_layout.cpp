#include "graph_layout.hpp"

#include <algorithm>
#include <limits>
#include <utility>

namespace spelunk::gui {

namespace {

constexpr double kLayerGap = 48;   // vertical space between layers
constexpr double kNodeGap  = 32;   // horizontal space between blocks in a layer
constexpr double kLaneGap  = 10;   // spacing between back-edge lanes
constexpr double kMargin   = 24;
constexpr double kStub     = 14;   // straight run leaving or entering a block
constexpr int    kSweeps   = 4;
constexpr double kDummyWidth = 8;   // a long edge's slot in the layers it crosses

}  // namespace

GraphLayout layout_graph(const GraphLayoutInput& in) {
    GraphLayout out;
    const std::size_t n = in.nodes.size();
    if (n == 0) return out;
    const std::size_t entry = in.entry < n ? in.entry : 0;
    const auto valid = [&](const GraphLayoutInput::Edge& e) { return e.from < n && e.to < n; };

    std::vector<std::vector<std::size_t>> out_edges(n), in_edges(n);
    for (std::size_t e = 0; e < in.edges.size(); ++e) {
        if (!valid(in.edges[e])) continue;
        out_edges[in.edges[e].from].push_back(e);
        in_edges[in.edges[e].to].push_back(e);
    }

    // Depth-first from the entry, then from anything it cannot reach: an
    // edge into a block still on the stack closes a loop.
    out.back_edge.assign(in.edges.size(), false);
    std::vector<int> state(n, 0);   // 0 unseen, 1 on the stack, 2 finished
    std::vector<std::size_t> preorder;
    preorder.reserve(n);
    std::vector<std::size_t> roots{entry};
    for (std::size_t v = 0; v < n; ++v)
        if (v != entry) roots.push_back(v);
    for (const std::size_t root : roots) {
        if (state[root] != 0) continue;
        state[root] = 1;
        preorder.push_back(root);
        std::vector<std::pair<std::size_t, std::size_t>> stack{{root, 0}};
        while (!stack.empty()) {
            const std::size_t v = stack.back().first;
            const std::size_t next = stack.back().second;
            if (next == out_edges[v].size()) {
                state[v] = 2;
                stack.pop_back();
                continue;
            }
            ++stack.back().second;
            const std::size_t e = out_edges[v][next];
            const std::size_t w = in.edges[e].to;
            if (state[w] == 1) {
                out.back_edge[e] = true;
            } else if (state[w] == 0) {
                state[w] = 1;
                preorder.push_back(w);
                stack.emplace_back(w, 0);
            }
        }
    }

    // Without the back edges the graph is acyclic: put every block one
    // layer below its lowest predecessor.
    std::vector<std::vector<std::size_t>> succs(n);
    std::vector<std::size_t> waiting(n, 0);
    for (std::size_t e = 0; e < in.edges.size(); ++e) {
        if (!valid(in.edges[e]) || out.back_edge[e]) continue;
        succs[in.edges[e].from].push_back(in.edges[e].to);
        ++waiting[in.edges[e].to];
    }
    out.layers.assign(n, 0);
    std::vector<std::size_t> ready;
    for (const std::size_t v : preorder)
        if (waiting[v] == 0) ready.push_back(v);
    for (std::size_t head = 0; head < ready.size(); ++head) {
        const std::size_t v = ready[head];
        for (const std::size_t w : succs[v]) {
            out.layers[w] = std::max(out.layers[w], out.layers[v] + 1);
            if (--waiting[w] == 0) ready.push_back(w);
        }
    }

    // A forward edge that skips layers runs through one virtual node per
    // layer it crosses. They take part in ordering and placement like
    // blocks, so the edge keeps clear of the blocks it passes.
    std::vector<std::size_t> layer = out.layers;
    std::vector<double> node_width(n);
    for (std::size_t v = 0; v < n; ++v) node_width[v] = in.nodes[v].width;
    std::vector<std::vector<std::size_t>> up(n), down(n);
    std::vector<std::vector<std::size_t>> via(in.edges.size());
    for (std::size_t e = 0; e < in.edges.size(); ++e) {
        if (!valid(in.edges[e]) || out.back_edge[e]) continue;
        std::size_t previous = in.edges[e].from;
        for (std::size_t level = layer[previous] + 1; level < layer[in.edges[e].to]; ++level) {
            const std::size_t dummy = layer.size();
            layer.push_back(level);
            node_width.push_back(kDummyWidth);
            up.emplace_back();
            down.emplace_back();
            down[previous].push_back(dummy);
            up[dummy].push_back(previous);
            via[e].push_back(dummy);
            previous = dummy;
        }
        down[previous].push_back(in.edges[e].to);
        up[in.edges[e].to].push_back(previous);
    }
    const std::size_t total = layer.size();

    // Order each layer by the mean position of its neighbours, sweeping
    // down and up a few times to untangle crossings.
    const std::size_t layer_count = *std::max_element(layer.begin(), layer.end()) + 1;
    std::vector<std::vector<std::size_t>> rows(layer_count);
    for (const std::size_t v : preorder) rows[layer[v]].push_back(v);
    for (std::size_t v = n; v < total; ++v) rows[layer[v]].push_back(v);
    std::vector<double> rank(total, 0);
    for (const auto& row : rows)
        for (std::size_t i = 0; i < row.size(); ++i) rank[row[i]] = static_cast<double>(i);
    const auto sort_row = [&](std::vector<std::size_t>& row,
                              const std::vector<std::vector<std::size_t>>& adjacent) {
        std::vector<std::pair<double, std::size_t>> keyed;
        keyed.reserve(row.size());
        for (const std::size_t v : row) {
            double key = rank[v];
            if (!adjacent[v].empty()) {
                double sum = 0;
                for (const std::size_t w : adjacent[v]) sum += rank[w];
                key = sum / static_cast<double>(adjacent[v].size());
            }
            keyed.emplace_back(key, v);
        }
        std::stable_sort(keyed.begin(), keyed.end(),
                         [](const auto& a, const auto& b) { return a.first < b.first; });
        for (std::size_t i = 0; i < row.size(); ++i) {
            row[i] = keyed[i].second;
            rank[row[i]] = static_cast<double>(i);
        }
    };
    for (int sweep = 0; sweep < kSweeps; ++sweep) {
        for (std::size_t level = 1; level < layer_count; ++level) sort_row(rows[level], up);
        for (std::size_t level = layer_count - 1; level-- > 0;) sort_row(rows[level], down);
    }

    // Rows stack top to bottom; within a row, each node wants to sit
    // under (or over) the centre of its neighbours. Packing toward those
    // targets from the left and from the right gives two placements that
    // both keep the spacing; their average keeps it too and does not drift.
    std::vector<double> x(total, 0);
    std::vector<double> row_top(layer_count, 0), row_height(layer_count, 0);
    const auto width = [&](std::size_t v) { return node_width[v]; };
    double top = kMargin;
    for (std::size_t level = 0; level < layer_count; ++level) {
        for (const std::size_t v : rows[level])
            if (v < n) row_height[level] = std::max(row_height[level], in.nodes[v].height);
        row_top[level] = top;
        double cursor = 0;
        for (const std::size_t v : rows[level]) {
            x[v] = cursor;
            cursor += width(v) + kNodeGap;
        }
        top += row_height[level] + kLayerGap;
    }
    const auto y = [&](std::size_t v) { return row_top[layer[v]]; };
    const auto center = [&](std::size_t v) { return x[v] + width(v) / 2; };
    const auto place = [&](const std::vector<std::size_t>& row,
                           const std::vector<std::vector<std::size_t>>& adjacent) {
        if (row.empty()) return;
        const std::size_t m = row.size();
        std::vector<double> wanted(m), rightward(m), leftward(m);
        for (std::size_t i = 0; i < m; ++i) {
            const std::size_t v = row[i];
            double target = center(v);
            if (!adjacent[v].empty()) {
                double sum = 0;
                for (const std::size_t w : adjacent[v]) sum += center(w);
                target = sum / static_cast<double>(adjacent[v].size());
            }
            wanted[i] = target - width(v) / 2;
        }
        rightward[0] = wanted[0];
        for (std::size_t i = 1; i < m; ++i)
            rightward[i] = std::max(wanted[i], rightward[i - 1] + width(row[i - 1]) + kNodeGap);
        leftward[m - 1] = wanted[m - 1];
        for (std::size_t i = m - 1; i-- > 0;)
            leftward[i] = std::min(wanted[i], leftward[i + 1] - width(row[i]) - kNodeGap);
        for (std::size_t i = 0; i < m; ++i) x[row[i]] = (rightward[i] + leftward[i]) / 2;
    };
    for (int sweep = 0; sweep < kSweeps; ++sweep) {
        for (std::size_t level = 1; level < layer_count; ++level) place(rows[level], up);
        for (std::size_t level = layer_count - 1; level-- > 0;) place(rows[level], down);
    }

    // Edge ends spread across the block's width, ordered by where the
    // edge's next hop sits so neighbouring edges do not cross at the block.
    const auto first_hop = [&](std::size_t e) { return via[e].empty() ? in.edges[e].to : via[e].front(); };
    const auto last_hop = [&](std::size_t e) { return via[e].empty() ? in.edges[e].from : via[e].back(); };
    std::vector<double> start_x(in.edges.size(), 0), end_x(in.edges.size(), 0);
    for (std::size_t v = 0; v < n; ++v) {
        auto outgoing = out_edges[v];
        std::stable_sort(outgoing.begin(), outgoing.end(), [&](std::size_t a, std::size_t b) -> bool {
            if (out.back_edge[a] != out.back_edge[b]) return !out.back_edge[a];
            return center(first_hop(a)) < center(first_hop(b));
        });
        for (std::size_t k = 0; k < outgoing.size(); ++k)
            start_x[outgoing[k]] = x[v] + width(v) * static_cast<double>(k + 1) /
                                              static_cast<double>(outgoing.size() + 1);
        auto incoming = in_edges[v];
        std::stable_sort(incoming.begin(), incoming.end(), [&](std::size_t a, std::size_t b) -> bool {
            if (out.back_edge[a] != out.back_edge[b]) return !out.back_edge[a];
            return center(last_hop(a)) < center(last_hop(b));
        });
        for (std::size_t k = 0; k < incoming.size(); ++k)
            end_x[incoming[k]] = x[v] + width(v) * static_cast<double>(k + 1) /
                                            static_cast<double>(incoming.size() + 1);
    }
    std::vector<double> row_left(layer_count, std::numeric_limits<double>::max());
    for (std::size_t v = 0; v < total; ++v) row_left[layer[v]] = std::min(row_left[layer[v]], x[v]);

    out.routes.assign(in.edges.size(), {});
    std::size_t lanes = 0;
    for (std::size_t e = 0; e < in.edges.size(); ++e) {
        if (!valid(in.edges[e])) continue;
        const std::size_t from = in.edges[e].from;
        const std::size_t to = in.edges[e].to;
        const double sx = start_x[e];
        const double sy = y(from) + in.nodes[from].height;
        const double tx = end_x[e];
        const double ty = y(to);
        auto& route = out.routes[e];
        if (!out.back_edge[e]) {
            // Vertical runs in pairs: out of the block, through each layer
            // crossed, into the target.
            route = {{sx, sy}, {sx, sy + kStub}};
            for (const std::size_t dummy : via[e]) {
                route.push_back({center(dummy), y(dummy)});
                route.push_back({center(dummy), y(dummy) + row_height[layer[dummy]]});
            }
            route.push_back({tx, ty - kStub});
            route.push_back({tx, ty});
            continue;
        }
        // Loops go up the left side, one lane per back edge, clear of
        // every row they pass.
        const std::size_t low = std::min(layer[from], layer[to]);
        const std::size_t high = std::max(layer[from], layer[to]);
        double lane = std::numeric_limits<double>::max();
        for (std::size_t level = low; level <= high; ++level) lane = std::min(lane, row_left[level]);
        lane -= kNodeGap / 2 + kLaneGap * static_cast<double>(lanes++);
        route = {{sx, sy}, {sx, sy + kStub}, {lane, sy + kStub},
                 {lane, ty - kStub}, {tx, ty - kStub}, {tx, ty}};
    }

    // Shift everything so the leftmost block or lane sits at the margin.
    double min_x = std::numeric_limits<double>::max();
    for (std::size_t v = 0; v < n; ++v) min_x = std::min(min_x, x[v]);
    for (const auto& route : out.routes)
        for (const auto& p : route) min_x = std::min(min_x, p.x);
    const double shift = kMargin - min_x;
    out.positions.resize(n);
    for (std::size_t v = 0; v < n; ++v) {
        out.positions[v] = {x[v] + shift, y(v)};
        out.width = std::max(out.width, x[v] + shift + width(v));
        out.height = std::max(out.height, y(v) + in.nodes[v].height);
    }
    for (auto& route : out.routes) {
        for (auto& p : route) {
            p.x += shift;
            out.width = std::max(out.width, p.x);
        }
    }
    out.width += kMargin;
    out.height += kMargin;
    return out;
}

}  // namespace spelunk::gui
