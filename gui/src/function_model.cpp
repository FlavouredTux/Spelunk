#include "function_model.hpp"

#include <algorithm>

#include "session.hpp"

namespace spelunk::gui {

void FunctionModel::set_session(const Session* s) {
    beginResetModel();
    rows_.clear();
    if (s) {
        rows_.reserve(s->functions.size());
        for (const auto& f : s->functions) {
            rows_.push_back(Row{
                QString::fromStdString(display_name(f.name)),
                QString::fromStdString(s->segment_name(f.addr)),
                QString("%1").arg(f.addr, 16, 16, QChar('0')),
                QString("%1").arg(f.size, 8, 16, QChar('0')),
                f.addr,
            });
        }
    }
    endResetModel();
}

addr_t FunctionModel::address_at(int row) const {
    if (row < 0 || static_cast<std::size_t>(row) >= rows_.size()) return 0;
    return rows_[static_cast<std::size_t>(row)].addr;
}

int FunctionModel::row_for(addr_t entry) const {
    auto it = std::lower_bound(rows_.begin(), rows_.end(), entry,
        [](const Row& r, addr_t v) { return r.addr < v; });
    if (it == rows_.end() || it->addr != entry) return -1;
    return static_cast<int>(it - rows_.begin());
}

int FunctionModel::rowCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : static_cast<int>(rows_.size());
}

int FunctionModel::columnCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : ColumnCount;
}

QVariant FunctionModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid()) return {};
    const auto& r = rows_[static_cast<std::size_t>(index.row())];
    switch (role) {
        case Qt::DisplayRole:
            switch (index.column()) {
                case Name:    return r.name;
                case Segment: return r.segment;
                case Start:   return r.start;
                case Length:  return r.length;
                default:      return {};
            }
        case kAddressRole:
            return QVariant::fromValue(static_cast<qulonglong>(r.addr));
        default:
            return {};
    }
}

QVariant FunctionModel::headerData(int section, Qt::Orientation o, int role) const {
    if (o != Qt::Horizontal || role != Qt::DisplayRole) return {};
    switch (section) {
        case Name:    return QStringLiteral("Function name");
        case Segment: return QStringLiteral("Segment");
        case Start:   return QStringLiteral("Start");
        case Length:  return QStringLiteral("Length");
        default:      return {};
    }
}

}  // namespace spelunk::gui
