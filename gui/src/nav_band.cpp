#include "nav_band.hpp"

#include <QMouseEvent>
#include <QPainter>
#include <QToolTip>

#include "session.hpp"
#include "theme.hpp"

namespace ember::gui {

NavBand::NavBand(QWidget* parent) : QWidget(parent) {
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    setMouseTracking(true);
}

QSize NavBand::sizeHint() const { return {400, 22}; }

void NavBand::set_session(const Session* s) {
    session_ = s;
    current_.reset();
    spans_.clear();
    total_ = 0;
    if (session_) {
        for (const auto& sec : session_->binary->sections()) {
            if (sec.size == 0 || sec.vaddr == 0) continue;
            spans_.push_back(Span{sec.vaddr, sec.size, total_});
            total_ += sec.size;
        }
    }
    rebuild();
    update();
}

void NavBand::set_current(addr_t va) {
    current_ = va;
    update();
}

void NavBand::rebuild() {
    columns_.assign(static_cast<std::size_t>(std::max(width(), 0)), theme::kBandUnexplored);
    if (!session_ || total_ == 0) return;
    for (int x = 0; x < width(); ++x)
        if (auto va = address_at_x(x)) columns_[static_cast<std::size_t>(x)] = colour_for(*va);
}

std::optional<addr_t> NavBand::address_at_x(int x) const {
    if (total_ == 0 || width() <= 0 || x < 0 || x >= width()) return std::nullopt;
    const u64 off = total_ * static_cast<u64>(x) / static_cast<u64>(width());
    for (const auto& s : spans_)
        if (off >= s.offset && off < s.offset + s.size) return s.vaddr + (off - s.offset);
    return std::nullopt;
}

std::optional<int> NavBand::x_for_address(addr_t va) const {
    if (total_ == 0 || width() <= 0) return std::nullopt;
    for (const auto& s : spans_)
        if (va >= s.vaddr && va < s.vaddr + s.size) {
            const u64 off = s.offset + (va - s.vaddr);
            return static_cast<int>(off * static_cast<u64>(width()) / total_);
        }
    return std::nullopt;
}

QColor NavBand::colour_for(addr_t va) const {
    const Section* sec = session_->section_at(va);
    if (!sec) return theme::kBandUnexplored;
    if (const auto* fn = session_->function_at(va)) {
        if (session_->binary->import_at_plt(fn->addr)) return theme::kBandExtern;
        return theme::kBandRegular;
    }
    if (sec->flags.executable) return theme::kBandUnexplored;
    return theme::kBandData;
}

void NavBand::paintEvent(QPaintEvent*) {
    QPainter p(this);
    const int top = kMarkerHeight;
    const int h   = height() - top;
    p.fillRect(0, top, width(), h, theme::kBandUnexplored);
    for (int x = 0; x < width() && static_cast<std::size_t>(x) < columns_.size(); ++x)
        p.fillRect(x, top, 1, h, columns_[static_cast<std::size_t>(x)]);
    p.setPen(theme::kBandFrame);
    p.drawRect(0, top, width() - 1, h - 1);

    if (current_) {
        if (auto x = x_for_address(*current_)) {
            p.setRenderHint(QPainter::Antialiasing);
            p.setPen(Qt::NoPen);
            p.setBrush(theme::kBandMarker);
            const QPointF tri[3] = {
                QPointF(*x - 4.0, 0.0), QPointF(*x + 4.0, 0.0), QPointF(*x, top),
            };
            p.drawPolygon(tri, 3);
            p.fillRect(*x, top, 1, h, theme::kBandMarker);
        }
    }
}

void NavBand::resizeEvent(QResizeEvent* e) {
    QWidget::resizeEvent(e);
    rebuild();
}

void NavBand::mousePressEvent(QMouseEvent* e) {
    if (e->button() != Qt::LeftButton) return;
    if (auto va = address_at_x(e->position().toPoint().x())) emit address_clicked(*va);
}

void NavBand::mouseMoveEvent(QMouseEvent* e) {
    if (!session_) return;
    const auto va = address_at_x(e->position().toPoint().x());
    if (!va) { QToolTip::hideText(); return; }
    QString tip = QStringLiteral("%1:%2")
                      .arg(QString::fromStdString(session_->segment_name(*va)))
                      .arg(*va, 16, 16, QChar('0'));
    if (const auto* fn = session_->function_at(*va))
        tip += QStringLiteral("  %1").arg(QString::fromStdString(display_name(fn->name)));
    QToolTip::showText(e->globalPosition().toPoint(), tip, this);
}

}  // namespace ember::gui
