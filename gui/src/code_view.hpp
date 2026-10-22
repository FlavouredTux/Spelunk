#pragma once

#include <QPlainTextEdit>
#include <optional>
#include <vector>

#include <spelunk/common/types.hpp>

namespace spelunk::gui {

// Identifier or number around column `pos` of `text`, empty when none.
// Shared by the text and graph views so both select the same words.
[[nodiscard]] QString token_in_text(const QString& text, qsizetype pos);

// Read-only code listing with IDA's navigation feel: a highlighted
// current line, Enter / double-click on a name or address to follow it,
// Esc to go back. The view is dumb about what the text means; the owner
// supplies one address per line so the cursor can be positioned and the
// status bar / navigation band can track it.
class CodeView : public QPlainTextEdit {
    Q_OBJECT
public:
    enum class Kind { Disassembly, Pseudocode };

    explicit CodeView(Kind kind, QWidget* parent = nullptr);

    // `line_addrs[i]` is the address for document line i, 0 when none.
    void set_content(const QString& text, std::vector<addr_t> line_addrs);
    bool go_to_address(addr_t va, bool center = true);
    [[nodiscard]] std::optional<addr_t> current_line_address() const;
    [[nodiscard]] Kind kind() const noexcept { return kind_; }
    // Identifier or number under the text cursor, empty when none.
    [[nodiscard]] QString current_token() const { return token_at(textCursor()); }
    // Case-insensitive search starting after the cursor. Moves the cursor
    // onto the match and returns true when one exists.
    bool find_next(const QString& needle);

signals:
    void jump_requested(const QString& token);
    void back_requested();
    // Tab: flip between the disassembly and pseudocode of this address.
    void toggle_view_requested();
    void line_address_changed(spelunk::addr_t va);

protected:
    void keyPressEvent(QKeyEvent* e) override;
    void mouseDoubleClickEvent(QMouseEvent* e) override;
    // Keep Tab for the view toggle instead of focus traversal.
    bool focusNextPrevChild(bool) override { return false; }

private:
    void on_cursor_moved();
    [[nodiscard]] QString token_at(const QTextCursor& c) const;

    Kind                kind_;
    std::vector<addr_t> line_addrs_;
};

}  // namespace spelunk::gui
