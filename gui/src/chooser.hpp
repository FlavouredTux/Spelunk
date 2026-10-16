#pragma once

#include <QDialog>
#include <optional>

#include <spelunk/common/types.hpp>

class QLineEdit;
class QSortFilterProxyModel;
class QStandardItemModel;
class QTableView;

namespace spelunk::gui {

// IDA-style modal chooser: a sortable table with a quick filter (Ctrl+F),
// Enter or double-click picks the row. Column 0 of every row carries the
// address to jump to under kAddressRole.
class Chooser : public QDialog {
    Q_OBJECT
public:
    static constexpr int kAddressRole = Qt::UserRole + 1;

    // Takes ownership of `model`.
    Chooser(const QString& title, QStandardItemModel* model, QWidget* parent = nullptr);

    // Select the first row whose address equals `va`, if any.
    void select_address(addr_t va);

    // Runs the dialog; the chosen row's address, or nothing on cancel.
    [[nodiscard]] std::optional<addr_t> choose();

protected:
    void keyPressEvent(QKeyEvent* e) override;

private:
    void accept_current();

    QStandardItemModel*    model_;
    QSortFilterProxyModel* proxy_;
    QTableView*            table_;
    QLineEdit*             filter_;
    std::optional<addr_t>  chosen_;
};

}  // namespace spelunk::gui
