#pragma once

#include <QColor>
#include <QWidget>
#include <optional>
#include <vector>

#include <spelunk/common/types.hpp>

namespace spelunk::gui {

struct Session;

// IDA's navigation band: every loaded segment laid end to end across the
// width, coloured by what lives there, with a yellow marker at the
// current address. Clicking jumps to the function under the pointer.
class NavBand : public QWidget {
    Q_OBJECT
public:
    explicit NavBand(QWidget* parent = nullptr);

    void set_session(const Session* s);
    void set_current(addr_t va);

    [[nodiscard]] QSize sizeHint() const override;

signals:
    void address_clicked(spelunk::addr_t va);

protected:
    void paintEvent(QPaintEvent* e) override;
    void resizeEvent(QResizeEvent* e) override;
    void mousePressEvent(QMouseEvent* e) override;
    void mouseMoveEvent(QMouseEvent* e) override;

private:
    struct Span { addr_t vaddr = 0; u64 size = 0; u64 offset = 0; };

    void rebuild();
    [[nodiscard]] std::optional<addr_t> address_at_x(int x) const;
    [[nodiscard]] std::optional<int>    x_for_address(addr_t va) const;
    [[nodiscard]] QColor colour_for(addr_t va) const;

    const Session*        session_ = nullptr;
    std::vector<Span>     spans_;
    u64                   total_   = 0;
    std::vector<QColor>   columns_;
    std::optional<addr_t> current_;

    static constexpr int kMarkerHeight = 6;
};

}  // namespace spelunk::gui
