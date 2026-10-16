#include "chooser.hpp"

#include <QDialogButtonBox>
#include <QHeaderView>
#include <QKeyEvent>
#include <QLineEdit>
#include <QShortcut>
#include <QSortFilterProxyModel>
#include <QStandardItemModel>
#include <QTableView>
#include <QVBoxLayout>

namespace spelunk::gui {

Chooser::Chooser(const QString& title, QStandardItemModel* model, QWidget* parent)
    : QDialog(parent), model_(model) {
    setWindowTitle(title);
    resize(760, 480);
    model_->setParent(this);

    proxy_ = new QSortFilterProxyModel(this);
    proxy_->setSourceModel(model_);
    proxy_->setFilterCaseSensitivity(Qt::CaseInsensitive);
    proxy_->setFilterKeyColumn(-1);

    table_ = new QTableView(this);
    table_->setModel(proxy_);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setShowGrid(false);
    table_->setSortingEnabled(true);
    table_->setWordWrap(false);
    table_->verticalHeader()->hide();
    table_->verticalHeader()->setDefaultSectionSize(table_->fontMetrics().height() + 4);
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->horizontalHeader()->setHighlightSections(false);
    table_->sortByColumn(-1, Qt::AscendingOrder);
    table_->resizeColumnsToContents();
    connect(table_, &QAbstractItemView::activated, this, &Chooser::accept_current);

    filter_ = new QLineEdit(this);
    filter_->setPlaceholderText(QStringLiteral("Quick filter (Ctrl+F)"));
    filter_->setClearButtonEnabled(true);
    connect(filter_, &QLineEdit::textChanged, this, [this](const QString& text) {
        proxy_->setFilterFixedString(text);
        if (!table_->currentIndex().isValid() && proxy_->rowCount() > 0) table_->selectRow(0);
    });
    connect(filter_, &QLineEdit::returnPressed, this, &Chooser::accept_current);
    auto* find = new QShortcut(QKeySequence(QStringLiteral("Ctrl+F")), this);
    connect(find, &QShortcut::activated, this, [this] {
        filter_->setFocus();
        filter_->selectAll();
    });

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    connect(buttons, &QDialogButtonBox::accepted, this, &Chooser::accept_current);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);

    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(4, 4, 4, 4);
    layout->addWidget(table_, 1);
    layout->addWidget(filter_);
    layout->addWidget(buttons);

    if (proxy_->rowCount() > 0) table_->selectRow(0);
    table_->setFocus();
}

void Chooser::select_address(addr_t va) {
    for (int row = 0; row < proxy_->rowCount(); ++row) {
        const QVariant v = proxy_->index(row, 0).data(kAddressRole);
        if (v.isValid() && static_cast<addr_t>(v.toULongLong()) == va) {
            table_->selectRow(row);
            table_->scrollTo(proxy_->index(row, 0), QAbstractItemView::PositionAtCenter);
            return;
        }
    }
}

std::optional<addr_t> Chooser::choose() {
    chosen_.reset();
    exec();
    return chosen_;
}

void Chooser::keyPressEvent(QKeyEvent* e) {
    // Typing in the table starts filtering, as in IDA's choosers.
    if (table_->hasFocus() && !e->text().isEmpty() && e->text().at(0).isPrint() &&
        e->modifiers() == Qt::NoModifier) {
        filter_->setFocus();
        filter_->setText(filter_->text() + e->text());
        return;
    }
    QDialog::keyPressEvent(e);
}

void Chooser::accept_current() {
    QModelIndex idx = table_->currentIndex();
    if (!idx.isValid() && proxy_->rowCount() > 0) idx = proxy_->index(0, 0);
    if (!idx.isValid()) return;
    const QVariant v = proxy_->index(idx.row(), 0).data(kAddressRole);
    if (!v.isValid()) return;
    chosen_ = static_cast<addr_t>(v.toULongLong());
    accept();
}

}  // namespace spelunk::gui
