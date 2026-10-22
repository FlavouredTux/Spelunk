#pragma once

#include <QGraphicsView>
#include <QString>
#include <QStringList>
#include <optional>
#include <vector>

#include <spelunk/common/types.hpp>

class QGraphicsRectItem;
class QGraphicsTextItem;

namespace spelunk::gui {

// IDA's graph view: one box per basic block, conditional edges green
// (taken) and red (not taken), everything else blue. Clicking a line
// selects it like the cursor in the text views; Enter or a double-click
// follows the name under it, Esc goes back. Drag to pan, Ctrl+wheel to
// zoom, W to fit the window, 1 for 100%. Space (bound by the main window)
// flips back to the text listing.
class GraphView : public QGraphicsView {
    Q_OBJECT
public:
    struct Block {
        QStringList         lines;
        std::vector<addr_t> line_addrs;   // one per line, 0 = none
    };
    enum class EdgeKind { Taken, NotTaken, Always };
    struct Edge {
        std::size_t from = 0;
        std::size_t to   = 0;
        EdgeKind    kind = EdgeKind::Always;
    };

    explicit GraphView(QWidget* parent = nullptr);

    void set_graph(const std::vector<Block>& blocks, const std::vector<Edge>& edges,
                   std::size_t entry);
    // Replaces the graph with a one-line explanation (too large, no CFG).
    void show_message(const QString& text);

    // Select the line for `va`, or the closest line before it in its block.
    bool go_to_address(addr_t va, bool center = true);
    [[nodiscard]] std::optional<addr_t> current_line_address() const;
    [[nodiscard]] QString current_token() const { return token_; }
    [[nodiscard]] std::size_t block_count() const noexcept { return nodes_.size(); }
    [[nodiscard]] std::size_t edge_count() const noexcept { return edge_count_; }
    // IDA's W and 1: the whole graph in the window, or back to 100%.
    void fit_to_window();
    void zoom_to_actual_size();

signals:
    void jump_requested(const QString& token);
    void back_requested();
    void line_address_changed(spelunk::addr_t va);

protected:
    void keyPressEvent(QKeyEvent* e) override;
    void mousePressEvent(QMouseEvent* e) override;
    void mouseDoubleClickEvent(QMouseEvent* e) override;
    void wheelEvent(QWheelEvent* e) override;

private:
    struct Node {
        QGraphicsRectItem*  frame = nullptr;
        QGraphicsTextItem*  text  = nullptr;
        std::vector<addr_t> line_addrs;
    };

    // Node and line under a scene position, when it hits block text.
    [[nodiscard]] std::optional<std::pair<std::size_t, int>> hit(const QPointF& scene_pos,
                                                                  qsizetype* column) const;
    void select(std::size_t node, int line, const QString& token, bool center);

    std::vector<Node>  nodes_;
    std::size_t        edge_count_ = 0;
    QGraphicsRectItem* line_highlight_ = nullptr;
    std::optional<std::size_t> current_node_;
    int                current_line_ = -1;
    QString            token_;
};

}  // namespace spelunk::gui
