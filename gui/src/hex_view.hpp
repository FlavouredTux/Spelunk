#pragma once

#include <QPlainTextEdit>
#include <optional>
#include <vector>

#include <spelunk/common/types.hpp>

namespace spelunk::gui {

struct Session;

// Read-only hex dump of the loaded image, IDA Hex-View style:
//   .text:0000000000401000  48 85 f6 48 89 ...  H..H...
// Windowed: renders kRows 16-byte rows around the requested address so
// multi-megabyte sections never materialize as text. The view follows
// the disassembly cursor (MainWindow drives show_address) but never
// steers it; Enter / double-click emits jump_requested so code bytes
// can be followed back into the disassembly.
class HexView : public QPlainTextEdit {
    Q_OBJECT
public:
    static constexpr int kBytesPerRow = 16;
    static constexpr int kRows = 256;          // 4 KiB window
    static constexpr int kContextRows = 3;     // rows above target on rebase

    explicit HexView(QWidget* parent = nullptr);

    void set_session(const Session* s);
    // Ensures `va` is visible, recentering the window when it is outside.
    // Returns false with no session.
    bool show_address(addr_t va, bool center = true);
    [[nodiscard]] std::optional<addr_t> current_line_address() const;
    [[nodiscard]] addr_t base_address() const { return base_; }

signals:
    void jump_requested(const QString& token);
    void line_address_changed(spelunk::addr_t va);

protected:
    void keyPressEvent(QKeyEvent* e) override;
    void mouseDoubleClickEvent(QMouseEvent* e) override;

private:
    void render();
    bool go_to_address(addr_t va, bool center);
    void on_cursor_moved();
    [[nodiscard]] QString address_token(addr_t va) const;

    const Session*        session_ = nullptr;
    addr_t                base_    = 0;
    bool                  has_base_ = false;
    std::vector<addr_t>   line_addrs_;
};

}  // namespace spelunk::gui
