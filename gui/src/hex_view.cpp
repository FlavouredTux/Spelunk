#include "hex_view.hpp"

#include <QKeyEvent>
#include <QMouseEvent>
#include <QSignalBlocker>
#include <QTextBlock>

#include "session.hpp"
#include "theme.hpp"

namespace spelunk::gui {

namespace {

QString hex16(addr_t va) {
    return QStringLiteral("%1").arg(va, 16, 16, QChar('0'));
}

}  // namespace

HexView::HexView(QWidget* parent) : QPlainTextEdit(parent) {
    setReadOnly(true);
    setLineWrapMode(QPlainTextEdit::NoWrap);
    setFont(theme::code_font());
    setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
    setCursorWidth(2);
    setTabStopDistance(fontMetrics().horizontalAdvance(QLatin1Char(' ')) * 4);

    QPalette p = palette();
    p.setColor(QPalette::Base, theme::kViewBackground);
    p.setColor(QPalette::Text, theme::kViewText);
    setPalette(p);

    connect(this, &QPlainTextEdit::cursorPositionChanged, this, &HexView::on_cursor_moved);
}

void HexView::set_session(const Session* s) {
    session_  = s;
    has_base_ = false;
    line_addrs_.clear();
    clear();
    if (session_ && !session_->functions.empty()) {
        // Park on the first function so an empty view never greets the user;
        // MainWindow will re-aim at the entry point right after.
        show_address(session_->functions.front().addr, /*center=*/false);
    } else if (session_) {
        for (const auto& sec : session_->binary->sections()) {
            if (sec.size == 0) continue;
            show_address(sec.vaddr, /*center=*/false);
            break;
        }
    }
}

bool HexView::show_address(addr_t va, bool center) {
    if (!session_) return false;
    const addr_t span = static_cast<addr_t>(kRows) * static_cast<addr_t>(kBytesPerRow);
    if (has_base_ && va >= base_ && va < base_ + span) return go_to_address(va, center);

    const addr_t aligned = va & ~static_cast<addr_t>(0xF);
    const addr_t ctx     = static_cast<addr_t>(kContextRows) * static_cast<addr_t>(kBytesPerRow);
    addr_t base          = aligned >= ctx ? aligned - ctx : 0;
    // Clamp the window into the containing section so the first rows are
    // real bytes rather than a wall of `??` when targeting a section head.
    if (const auto* sec = session_->section_at(va); sec && sec->size != 0) {
        const addr_t sec_start = (sec->vaddr / static_cast<addr_t>(kBytesPerRow)) *
                                 static_cast<addr_t>(kBytesPerRow);
        if (base < sec_start) base = sec_start;
    }
    base_     = base;
    has_base_ = true;
    render();
    return go_to_address(va, center);
}

std::optional<addr_t> HexView::current_line_address() const {
    const int line = textCursor().blockNumber();
    if (line < 0 || static_cast<std::size_t>(line) >= line_addrs_.size()) return std::nullopt;
    return line_addrs_[static_cast<std::size_t>(line)];
}

void HexView::render() {
    line_addrs_.assign(static_cast<std::size_t>(kRows), 0);
    if (!session_) {
        setPlainText(QString());
        return;
    }
    QString out;
    out.reserve(static_cast<qsizetype>(kRows) * 80);
    for (int row = 0; row < kRows; ++row) {
        const addr_t row_va = base_ + static_cast<addr_t>(row) * static_cast<addr_t>(kBytesPerRow);
        line_addrs_[static_cast<std::size_t>(row)] = row_va;
        if (row > 0) out += QLatin1Char('\n');
        out += QString::fromStdString(session_->segment_name(row_va));
        out += QLatin1Char(':');
        out += hex16(row_va);
        out += QStringLiteral("  ");
        char ascii[kBytesPerRow];
        for (int i = 0; i < kBytesPerRow; ++i) {
            if (i == 8) out += QLatin1Char(' ');
            const auto bytes = session_->binary->bytes_at(row_va + static_cast<addr_t>(i));
            if (bytes.empty()) {
                out += QStringLiteral("??");
                ascii[i] = ' ';
            } else {
                const unsigned b = static_cast<unsigned char>(bytes.front());
                out += QStringLiteral("%1").arg(b, 2, 16, QChar('0'));
                ascii[i] = (b >= 0x20 && b < 0x7F) ? static_cast<char>(b) : '.';
            }
            out += QLatin1Char(' ');
        }
        out += QLatin1Char(' ');
        for (char c : ascii) out += QLatin1Char(c);
    }
    const QSignalBlocker block(this);
    setPlainText(out);
}

bool HexView::go_to_address(addr_t va, bool center) {
    if (!has_base_ || line_addrs_.empty()) return false;
    const addr_t span = static_cast<addr_t>(line_addrs_.size()) * static_cast<addr_t>(kBytesPerRow);
    if (va < base_ || va >= base_ + span) return false;
    const int line = static_cast<int>((va - base_) / static_cast<addr_t>(kBytesPerRow));
    QTextCursor c(document()->findBlockByNumber(line));
    {
        const QSignalBlocker block(this);
        setTextCursor(c);
        if (center) centerCursor();
    }
    on_cursor_moved();
    return true;
}

void HexView::on_cursor_moved() {
    QTextEdit::ExtraSelection sel;
    sel.format.setBackground(theme::kCurrentLine);
    sel.format.setProperty(QTextFormat::FullWidthSelection, true);
    sel.cursor = textCursor();
    sel.cursor.clearSelection();
    setExtraSelections({sel});

    if (auto a = current_line_address()) emit line_address_changed(*a);
}

QString HexView::address_token(addr_t va) const {
    return QStringLiteral("0x%1").arg(va, 0, 16);
}

void HexView::keyPressEvent(QKeyEvent* e) {
    const addr_t span = static_cast<addr_t>(kRows) * static_cast<addr_t>(kBytesPerRow);
    const addr_t step = span > 64 ? span - 4 * static_cast<addr_t>(kBytesPerRow) : span;
    switch (e->key()) {
        case Qt::Key_PageUp:
            if (has_base_) {
                const addr_t cur = current_line_address().value_or(base_);
                base_ = base_ >= step ? base_ - step : 0;
                base_ &= ~static_cast<addr_t>(0xF);
                render();
                go_to_address(std::min(cur, base_ + step), /*center=*/true);
            }
            return;
        case Qt::Key_PageDown:
            if (has_base_) {
                const addr_t cur = current_line_address().value_or(base_);
                base_ += step;
                render();
                const addr_t window = static_cast<addr_t>(kRows) * static_cast<addr_t>(kBytesPerRow);
                const addr_t want = cur < base_ ? base_ : (cur >= base_ + window ? base_ + window - 16 : cur);
                go_to_address(want, /*center=*/true);
            }
            return;
        case Qt::Key_Return:
        case Qt::Key_Enter:
            if (e->modifiers() == Qt::NoModifier) {
                if (auto a = current_line_address()) emit jump_requested(address_token(*a));
                return;
            }
            break;
        default:
            break;
    }
    QPlainTextEdit::keyPressEvent(e);
}

void HexView::mouseDoubleClickEvent(QMouseEvent* e) {
    QPlainTextEdit::mouseDoubleClickEvent(e);
    QTextCursor c = cursorForPosition(e->pos());
    const int line = c.blockNumber();
    if (line >= 0 && static_cast<std::size_t>(line) < line_addrs_.size())
        emit jump_requested(address_token(line_addrs_[static_cast<std::size_t>(line)]));
}

}  // namespace spelunk::gui
