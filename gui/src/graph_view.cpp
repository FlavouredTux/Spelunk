#include "graph_view.hpp"

#include <QAbstractTextDocumentLayout>
#include <QGraphicsPathItem>
#include <QGraphicsRectItem>
#include <QGraphicsScene>
#include <QGraphicsSimpleTextItem>
#include <QGraphicsTextItem>
#include <QKeyEvent>
#include <QMouseEvent>
#include <QPainterPath>
#include <QTextBlock>
#include <QTextDocument>
#include <QWheelEvent>
#include <algorithm>
#include <cmath>

#include "code_view.hpp"
#include "graph_layout.hpp"
#include "highlighters.hpp"
#include "theme.hpp"

namespace spelunk::gui {

namespace {

constexpr qreal kPadding = 6;   // between a block's frame and its text
constexpr qreal kArrow   = 7;
constexpr qreal kMinZoom = 0.1;
constexpr qreal kMaxZoom = 3.0;

QColor edge_colour(GraphView::EdgeKind kind) {
    switch (kind) {
        case GraphView::EdgeKind::Taken:    return theme::kEdgeTaken;
        case GraphView::EdgeKind::NotTaken: return theme::kEdgeNotTaken;
        case GraphView::EdgeKind::Always:   return theme::kEdgeAlways;
    }
    return theme::kEdgeAlways;
}

}  // namespace

GraphView::GraphView(QWidget* parent) : QGraphicsView(parent) {
    setScene(new QGraphicsScene(this));
    setBackgroundBrush(theme::kGraphBackground);
    setRenderHints(QPainter::Antialiasing | QPainter::TextAntialiasing);
    setDragMode(QGraphicsView::ScrollHandDrag);
    setTransformationAnchor(QGraphicsView::AnchorUnderMouse);
    setFocusPolicy(Qt::StrongFocus);
}

void GraphView::set_graph(const std::vector<Block>& blocks, const std::vector<Edge>& edges,
                          std::size_t entry) {
    scene()->clear();
    nodes_.clear();
    line_highlight_ = nullptr;
    current_node_.reset();
    current_line_ = -1;
    token_.clear();
    edge_count_ = edges.size();
    resetTransform();

    GraphLayoutInput input;
    input.entry = entry;
    const QFont font = theme::code_font();
    for (const Block& block : blocks) {
        auto* frame = new QGraphicsRectItem;
        auto* text = new QGraphicsTextItem(frame);
        text->setFont(font);
        text->document()->setDocumentMargin(0);
        text->setPlainText(block.lines.join(QLatin1Char('\n')));
        new AsmHighlighter(text->document(), /*prefixed=*/false);
        text->setPos(kPadding, kPadding);
        text->setZValue(1);
        const QRectF bounds = text->boundingRect();
        frame->setRect(0, 0, bounds.width() + 2 * kPadding, bounds.height() + 2 * kPadding);
        frame->setBrush(theme::kGraphNode);
        frame->setPen(QPen(theme::kGraphNodeBorder, 1));
        frame->setZValue(1);
        scene()->addItem(frame);
        nodes_.push_back({frame, text, block.line_addrs});
        input.nodes.push_back({frame->rect().width(), frame->rect().height()});
    }
    for (const Edge& e : edges) input.edges.push_back({e.from, e.to});

    const GraphLayout layout = layout_graph(input);
    for (std::size_t i = 0; i < nodes_.size(); ++i)
        nodes_[i].frame->setPos(layout.positions[i].x, layout.positions[i].y);
    for (std::size_t i = 0; i < edges.size(); ++i) {
        const auto& route = layout.routes[i];
        if (route.size() < 2) continue;
        const auto at = [&](std::size_t k) { return QPointF(route[k].x, route[k].y); };
        QPainterPath path(at(0));
        if (!layout.back_edge[i] && route.size() % 2 == 0) {
            // Forward edges come as straight vertical runs (out of the
            // block, through each layer crossed, into the target) joined
            // by S-curves.
            path.lineTo(at(1));
            for (std::size_t k = 2; k + 1 < route.size(); k += 2) {
                const qreal middle = (route[k - 1].y + route[k].y) / 2;
                path.cubicTo(QPointF(route[k - 1].x, middle), QPointF(route[k].x, middle), at(k));
                path.lineTo(at(k + 1));
            }
        } else {
            for (std::size_t k = 1; k < route.size(); ++k) path.lineTo(at(k));
        }
        const QColor colour = edge_colour(edges[i].kind);
        scene()->addPath(path, QPen(colour, 1.4))->setZValue(0);
        // Every route ends with a short downward run into the block's top.
        const QPointF tip = at(route.size() - 1);
        QPolygonF head;
        head << tip << QPointF(tip.x() - kArrow / 2, tip.y() - kArrow)
             << QPointF(tip.x() + kArrow / 2, tip.y() - kArrow);
        scene()->addPolygon(head, QPen(colour), QBrush(colour))->setZValue(2);
    }
    scene()->setSceneRect(0, 0, layout.width, layout.height);
    if (!nodes_.empty()) select(entry < nodes_.size() ? entry : 0, 0, {}, true);
}

void GraphView::show_message(const QString& text) {
    scene()->clear();
    nodes_.clear();
    line_highlight_ = nullptr;
    current_node_.reset();
    current_line_ = -1;
    token_.clear();
    edge_count_ = 0;
    resetTransform();
    auto* item = scene()->addSimpleText(text, theme::code_font());
    item->setBrush(theme::kComment);
    scene()->setSceneRect(item->boundingRect().adjusted(-24, -24, 24, 24));
}

bool GraphView::go_to_address(addr_t va, bool center) {
    std::optional<std::pair<std::size_t, int>> best;
    addr_t best_addr = 0;
    for (std::size_t i = 0; i < nodes_.size(); ++i) {
        const auto& addrs = nodes_[i].line_addrs;
        for (std::size_t line = 0; line < addrs.size(); ++line) {
            const addr_t a = addrs[line];
            if (a == 0 || a > va) continue;
            if (a == va) {
                select(i, static_cast<int>(line), {}, center);
                return true;
            }
            if (!best || a > best_addr) {
                best = std::pair{i, static_cast<int>(line)};
                best_addr = a;
            }
        }
    }
    if (!best) return false;
    select(best->first, best->second, {}, center);
    return true;
}

std::optional<addr_t> GraphView::current_line_address() const {
    if (!current_node_ || *current_node_ >= nodes_.size()) return std::nullopt;
    const auto& addrs = nodes_[*current_node_].line_addrs;
    for (int i = std::min(current_line_, static_cast<int>(addrs.size()) - 1); i >= 0; --i)
        if (addrs[static_cast<std::size_t>(i)] != 0) return addrs[static_cast<std::size_t>(i)];
    for (const addr_t a : addrs)
        if (a != 0) return a;
    return std::nullopt;
}

std::optional<std::pair<std::size_t, int>> GraphView::hit(const QPointF& scene_pos,
                                                          qsizetype* column) const {
    for (std::size_t i = 0; i < nodes_.size(); ++i) {
        const Node& node = nodes_[i];
        if (!node.frame->contains(node.frame->mapFromScene(scene_pos))) continue;
        QPointF local = node.text->mapFromScene(scene_pos);
        const QRectF bounds = node.text->boundingRect();
        local.setY(std::clamp(local.y(), bounds.top(), bounds.bottom() - 1));
        QTextDocument* doc = node.text->document();
        const int position = doc->documentLayout()->hitTest(local, Qt::FuzzyHit);
        if (position < 0) return std::pair{i, 0};
        const QTextBlock block = doc->findBlock(position);
        if (column) *column = position - block.position();
        return std::pair{i, block.blockNumber()};
    }
    return std::nullopt;
}

void GraphView::select(std::size_t node, int line, const QString& token, bool center) {
    current_node_ = node;
    current_line_ = line;
    token_ = token;
    for (std::size_t i = 0; i < nodes_.size(); ++i) {
        const bool active = i == node;
        nodes_[i].frame->setPen(QPen(active ? theme::kGraphNodeActive : theme::kGraphNodeBorder,
                                     active ? 2 : 1));
    }
    const Node& n = nodes_[node];
    const QTextBlock block = n.text->document()->findBlockByNumber(line);
    QRectF line_rect = n.frame->rect();
    if (block.isValid()) {
        const QRectF r = n.text->document()->documentLayout()->blockBoundingRect(block);
        line_rect = QRectF(1, kPadding + r.top(), n.frame->rect().width() - 2, r.height());
        if (!line_highlight_) {
            line_highlight_ = new QGraphicsRectItem;
            line_highlight_->setBrush(theme::kCurrentLine);
            line_highlight_->setPen(Qt::NoPen);
        }
        line_highlight_->setParentItem(n.frame);
        line_highlight_->setRect(line_rect);
        line_highlight_->setZValue(0);
    }
    if (center) centerOn(n.frame->mapToScene(line_rect.center()));
    if (const auto va = current_line_address()) emit line_address_changed(*va);
}

void GraphView::fit_to_window() {
    fitInView(sceneRect(), Qt::KeepAspectRatio);
    // Fitting never magnifies past 100%, as in IDA.
    const qreal zoom = std::clamp(transform().m11(), kMinZoom, qreal{1});
    setTransform(QTransform::fromScale(zoom, zoom));
}

void GraphView::zoom_to_actual_size() {
    resetTransform();
    if (current_node_) centerOn(nodes_[*current_node_].frame);
}

void GraphView::keyPressEvent(QKeyEvent* e) {
    if (e->modifiers() == Qt::NoModifier && e->key() == Qt::Key_W) {
        fit_to_window();
        return;
    }
    if (e->modifiers() == Qt::NoModifier && e->key() == Qt::Key_1) {
        zoom_to_actual_size();
        return;
    }
    switch (e->key()) {
        case Qt::Key_Escape:
            emit back_requested();
            return;
        case Qt::Key_Return:
        case Qt::Key_Enter:
            if (!token_.isEmpty()) emit jump_requested(token_);
            return;
        case Qt::Key_Up:
        case Qt::Key_Down:
            if (current_node_) {
                const int lines = nodes_[*current_node_].text->document()->blockCount();
                const int next = current_line_ + (e->key() == Qt::Key_Down ? 1 : -1);
                if (next >= 0 && next < lines) select(*current_node_, next, {}, false);
            }
            return;
        default:
            break;
    }
    QGraphicsView::keyPressEvent(e);
}

void GraphView::mousePressEvent(QMouseEvent* e) {
    if (e->button() == Qt::LeftButton) {
        qsizetype column = 0;
        if (const auto at = hit(mapToScene(e->pos()), &column)) {
            const QTextBlock block =
                nodes_[at->first].text->document()->findBlockByNumber(at->second);
            select(at->first, at->second, token_in_text(block.text(), column), false);
        }
    }
    setFocus();
    QGraphicsView::mousePressEvent(e);
}

void GraphView::mouseDoubleClickEvent(QMouseEvent* e) {
    qsizetype column = 0;
    if (const auto at = hit(mapToScene(e->pos()), &column)) {
        const QTextBlock block = nodes_[at->first].text->document()->findBlockByNumber(at->second);
        const QString token = token_in_text(block.text(), column);
        select(at->first, at->second, token, false);
        if (!token.isEmpty()) emit jump_requested(token);
        return;
    }
    QGraphicsView::mouseDoubleClickEvent(e);
}

void GraphView::wheelEvent(QWheelEvent* e) {
    if (!(e->modifiers() & Qt::ControlModifier)) {
        QGraphicsView::wheelEvent(e);
        return;
    }
    const qreal factor = std::pow(1.0015, e->angleDelta().y());
    const qreal zoom = std::clamp(transform().m11() * factor, kMinZoom, kMaxZoom);
    setTransform(QTransform::fromScale(zoom, zoom));
    e->accept();
}

}  // namespace spelunk::gui
