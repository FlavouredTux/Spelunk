#include "code_view.hpp"

#include <QKeyEvent>
#include <QMouseEvent>
#include <QTextBlock>

#include "theme.hpp"

namespace ember::gui {

CodeView::CodeView(Kind kind, QWidget* parent)
    : QPlainTextEdit(parent), kind_(kind) {
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

    connect(this, &QPlainTextEdit::cursorPositionChanged, this, &CodeView::on_cursor_moved);
}

void CodeView::set_content(const QString& text, std::vector<addr_t> line_addrs) {
    line_addrs_ = std::move(line_addrs);
    setPlainText(text);
    on_cursor_moved();
}

bool CodeView::go_to_address(addr_t va, bool center) {
    // Exact line first; otherwise the last line at or below `va`, so a
    // mid-statement address in pseudocode lands on its statement.
    int best = -1;
    for (std::size_t i = 0; i < line_addrs_.size(); ++i) {
        const addr_t a = line_addrs_[i];
        if (a == 0) continue;
        if (a == va) { best = static_cast<int>(i); break; }
        if (a < va && (best < 0 || a > line_addrs_[static_cast<std::size_t>(best)]))
            best = static_cast<int>(i);
    }
    if (best < 0) return false;
    QTextCursor c(document()->findBlockByNumber(best));
    setTextCursor(c);
    if (center) centerCursor();
    return true;
}

std::optional<addr_t> CodeView::current_line_address() const {
    const int line = textCursor().blockNumber();
    if (line < 0 || static_cast<std::size_t>(line) >= line_addrs_.size()) return std::nullopt;
    // Walk upward to the nearest addressed line: pseudocode braces and
    // blank lines carry no address of their own.
    for (int i = line; i >= 0; --i)
        if (const addr_t a = line_addrs_[static_cast<std::size_t>(i)]; a != 0) return a;
    for (std::size_t i = static_cast<std::size_t>(line); i < line_addrs_.size(); ++i)
        if (line_addrs_[i] != 0) return line_addrs_[i];
    return std::nullopt;
}

void CodeView::keyPressEvent(QKeyEvent* e) {
    switch (e->key()) {
        case Qt::Key_Return:
        case Qt::Key_Enter:
            if (e->modifiers() == Qt::NoModifier) {
                if (const QString tok = token_at(textCursor()); !tok.isEmpty())
                    emit jump_requested(tok);
                return;
            }
            break;
        case Qt::Key_Escape:
            emit back_requested();
            return;
        default:
            break;
    }
    QPlainTextEdit::keyPressEvent(e);
}

void CodeView::mouseDoubleClickEvent(QMouseEvent* e) {
    QPlainTextEdit::mouseDoubleClickEvent(e);
    if (const QString tok = token_at(cursorForPosition(e->pos())); !tok.isEmpty())
        emit jump_requested(tok);
}

void CodeView::on_cursor_moved() {
    QTextEdit::ExtraSelection sel;
    sel.format.setBackground(theme::kCurrentLine);
    sel.format.setProperty(QTextFormat::FullWidthSelection, true);
    sel.cursor = textCursor();
    sel.cursor.clearSelection();
    setExtraSelections({sel});

    if (auto a = current_line_address()) emit line_address_changed(*a);
}

QString CodeView::token_at(const QTextCursor& c) const {
    const QString text = c.block().text();
    const auto    n    = text.size();
    auto is_tok = [](QChar ch) {
        return ch.isLetterOrNumber() || ch == QLatin1Char('_') ||
               ch == QLatin1Char('$') || ch == QLatin1Char('@');
    };
    qsizetype pos = c.positionInBlock();
    if (pos >= n || !is_tok(text[pos])) {
        if (pos > 0 && is_tok(text[pos - 1])) --pos;
        else return {};
    }
    qsizetype a = pos, b = pos;
    while (a > 0 && is_tok(text[a - 1])) --a;
    while (b < n && is_tok(text[b])) ++b;
    return text.mid(a, b - a);
}

}  // namespace ember::gui
