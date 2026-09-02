#pragma once

#include <QAbstractTableModel>
#include <QString>
#include <vector>

#include <ember/common/types.hpp>

namespace ember::gui {

struct Session;

// Backs the Functions window: name | segment | start | length, the same
// four columns IDA shows by default. Rows are pre-formatted once per
// session so scrolling and filtering never touch the Binary.
class FunctionModel : public QAbstractTableModel {
    Q_OBJECT
public:
    enum Column { Name, Segment, Start, Length, ColumnCount };
    static constexpr int kAddressRole = Qt::UserRole + 1;

    using QAbstractTableModel::QAbstractTableModel;

    void set_session(const Session* s);

    [[nodiscard]] addr_t address_at(int row) const;
    [[nodiscard]] int    row_for(addr_t entry) const;   // -1 when absent

    [[nodiscard]] int      rowCount(const QModelIndex& parent = {}) const override;
    [[nodiscard]] int      columnCount(const QModelIndex& parent = {}) const override;
    [[nodiscard]] QVariant data(const QModelIndex& index, int role) const override;
    [[nodiscard]] QVariant headerData(int section, Qt::Orientation o, int role) const override;

private:
    struct Row {
        QString name, segment, start, length;
        addr_t  addr = 0;
    };
    std::vector<Row> rows_;
};

}  // namespace ember::gui
