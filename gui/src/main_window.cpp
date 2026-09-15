#include "main_window.hpp"

#include <QApplication>
#include <QDockWidget>
#include <QElapsedTimer>
#include <QFileDialog>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QScrollBar>
#include <QSignalBlocker>
#include <QMenuBar>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QSortFilterProxyModel>
#include <QStandardItemModel>
#include <QStatusBar>
#include <QStyle>
#include <QTabWidget>
#include <QTableView>
#include <QThread>
#include <QToolBar>
#include <QVBoxLayout>

#include <algorithm>

#include <spelunk/analysis/pipeline.hpp>
#include <spelunk/binary/arch.hpp>
#include <spelunk/binary/format.hpp>
#include <spelunk/common/timing.hpp>

#include "code_view.hpp"
#include "function_model.hpp"
#include "hex_view.hpp"
#include "highlighters.hpp"
#include "nav_band.hpp"
#include "session.hpp"
#include "theme.hpp"

namespace spelunk::gui {

namespace {

constexpr int kAddressRole = Qt::UserRole + 1;

QString hex(addr_t va) {
    return QStringLiteral("0x%1").arg(va, 0, 16);
}

QString hex16(addr_t va) {
    return QStringLiteral("%1").arg(va, 16, 16, QChar('0'));
}

QStandardItem* addr_item(addr_t va, const QString& text) {
    auto* it = new QStandardItem(text);
    it->setData(QVariant::fromValue(static_cast<qulonglong>(va)), kAddressRole);
    it->setEditable(false);
    return it;
}

QStandardItem* text_item(const QString& text) {
    auto* it = new QStandardItem(text);
    it->setEditable(false);
    return it;
}

QTableView* make_table(QAbstractItemModel* model, QWidget* parent, int sort_column) {
    auto* t = new QTableView(parent);
    t->setModel(model);
    t->setSelectionBehavior(QAbstractItemView::SelectRows);
    t->setSelectionMode(QAbstractItemView::SingleSelection);
    t->setShowGrid(false);
    t->setSortingEnabled(true);
    t->setWordWrap(false);
    t->setAlternatingRowColors(false);
    t->verticalHeader()->hide();
    t->verticalHeader()->setDefaultSectionSize(t->fontMetrics().height() + 4);
    t->horizontalHeader()->setStretchLastSection(true);
    t->horizontalHeader()->setHighlightSections(false);
    t->setEditTriggers(QAbstractItemView::NoEditTriggers);
    t->sortByColumn(sort_column, Qt::AscendingOrder);
    return t;
}

}  // namespace

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    setWindowTitle(QStringLiteral("Spelunk"));
    resize(1400, 900);
    setDockOptions(QMainWindow::AnimatedDocks | QMainWindow::AllowNestedDocks |
                   QMainWindow::AllowTabbedDocks);
    setTabPosition(Qt::AllDockWidgetAreas, QTabWidget::North);
    setCorner(Qt::BottomLeftCorner, Qt::BottomDockWidgetArea);
    setCorner(Qt::BottomRightCorner, Qt::BottomDockWidgetArea);

    build_actions();
    build_menus();
    build_toolbars();
    build_central();
    build_docks();

    au_label_   = new QLabel(QStringLiteral("AU: idle"), this);
    addr_label_ = new QLabel(this);
    statusBar()->addWidget(au_label_);
    statusBar()->addPermanentWidget(addr_label_);

    update_history_actions();
    log(QStringLiteral("Spelunk %1 ready. File > Open to load a binary.")
            .arg(QApplication::applicationVersion()));
}

MainWindow::~MainWindow() {
    for (QThread* t : workers_) {
        t->wait();
        delete t;
    }
}

void MainWindow::spawn(std::function<void()> work) {
    QThread* t = QThread::create(std::move(work));
    workers_.push_back(t);
    // `finished` is emitted on the worker; this slot runs queued on the
    // GUI thread, after which the thread object is safe to drop.
    connect(t, &QThread::finished, this, [this, t] {
        t->wait();
        std::erase(workers_, t);
        t->deleteLater();
    });
    t->start();
}

void MainWindow::build_actions() {
    act_open_ = new QAction(QStringLiteral("&Open..."), this);
    act_open_->setShortcut(QKeySequence::Open);
    connect(act_open_, &QAction::triggered, this, &MainWindow::prompt_open);

    act_quit_ = new QAction(QStringLiteral("&Quit"), this);
    act_quit_->setShortcut(QKeySequence(QStringLiteral("Alt+X")));
    connect(act_quit_, &QAction::triggered, this, &QWidget::close);

    act_back_ = new QAction(QStringLiteral("Jump &back"), this);
    act_back_->setShortcut(QKeySequence(QStringLiteral("Alt+Left")));
    connect(act_back_, &QAction::triggered, this, &MainWindow::jump_back);

    act_forward_ = new QAction(QStringLiteral("Jump &forward"), this);
    act_forward_->setShortcut(QKeySequence(QStringLiteral("Ctrl+Return")));
    connect(act_forward_, &QAction::triggered, this, &MainWindow::jump_forward);

    act_jump_addr_ = new QAction(QStringLiteral("Jump to &address..."), this);
    act_jump_addr_->setShortcut(QKeySequence(QStringLiteral("G")));
    connect(act_jump_addr_, &QAction::triggered, this, &MainWindow::prompt_jump_address);

    act_jump_fn_ = new QAction(QStringLiteral("Jump to f&unction..."), this);
    act_jump_fn_->setShortcut(QKeySequence(QStringLiteral("Ctrl+P")));
    connect(act_jump_fn_, &QAction::triggered, this, &MainWindow::prompt_jump_function);

    act_jump_entry_ = new QAction(QStringLiteral("Jump to &entry point"), this);
    act_jump_entry_->setShortcut(QKeySequence(QStringLiteral("Ctrl+E")));
    connect(act_jump_entry_, &QAction::triggered, this, &MainWindow::jump_to_entry);

    act_disasm_ = new QAction(QStringLiteral("&Disassembly"), this);
    connect(act_disasm_, &QAction::triggered, this, [this] {
        if (auto* v = ensure_disassembly_tab()) tabs_->setCurrentWidget(v);
    });

    act_hex_ = new QAction(QStringLiteral("&Hex Dump"), this);
    act_hex_->setShortcut(QKeySequence(QStringLiteral("H")));
    connect(act_hex_, &QAction::triggered, this, &MainWindow::open_hex);

    act_pseudo_ = new QAction(QStringLiteral("&Pseudocode"), this);
    act_pseudo_->setShortcut(QKeySequence(QStringLiteral("F5")));
    connect(act_pseudo_, &QAction::triggered, this, &MainWindow::open_pseudocode);

    act_strings_ = new QAction(QStringLiteral("&Strings"), this);
    act_strings_->setShortcut(QKeySequence(QStringLiteral("Shift+F12")));
    connect(act_strings_, &QAction::triggered, this, &MainWindow::open_strings);

    act_imports_ = new QAction(QStringLiteral("&Imports"), this);
    connect(act_imports_, &QAction::triggered, this, &MainWindow::open_imports);

    act_exports_ = new QAction(QStringLiteral("&Exports"), this);
    connect(act_exports_, &QAction::triggered, this, &MainWindow::open_exports);

    act_segments_ = new QAction(QStringLiteral("Se&gments"), this);
    act_segments_->setShortcut(QKeySequence(QStringLiteral("Shift+F7")));
    connect(act_segments_, &QAction::triggered, this, &MainWindow::open_segments);

    act_about_ = new QAction(QStringLiteral("&About"), this);
    connect(act_about_, &QAction::triggered, this, [this] {
        QMessageBox::about(this, QStringLiteral("About Spelunk"),
            QStringLiteral("<b>Spelunk %1</b><br>Reverse engineering toolkit.<br>"
                           "Qt %2 front end linked directly against spelunk::core.")
                .arg(QApplication::applicationVersion(), QString::fromLatin1(qVersion())));
    });

    for (QAction* a : {act_back_, act_forward_, act_jump_addr_, act_jump_fn_, act_jump_entry_,
                        act_disasm_, act_hex_, act_pseudo_, act_strings_, act_imports_, act_exports_,
                        act_segments_})
        a->setEnabled(false);
}

void MainWindow::build_menus() {
    QMenu* file = menuBar()->addMenu(QStringLiteral("&File"));
    file->addAction(act_open_);
    file->addSeparator();
    file->addAction(act_quit_);

    QMenu* jump = menuBar()->addMenu(QStringLiteral("&Jump"));
    jump->addAction(act_back_);
    jump->addAction(act_forward_);
    jump->addSeparator();
    jump->addAction(act_jump_addr_);
    jump->addAction(act_jump_fn_);
    jump->addAction(act_jump_entry_);

    QMenu* view = menuBar()->addMenu(QStringLiteral("&View"));
    QMenu* sub  = view->addMenu(QStringLiteral("&Open subviews"));
    sub->addAction(act_disasm_);
    sub->addAction(act_pseudo_);
    sub->addAction(act_hex_);
    sub->addSeparator();
    sub->addAction(act_strings_);
    sub->addAction(act_imports_);
    sub->addAction(act_exports_);
    sub->addAction(act_segments_);
    view->addSeparator();
    // Dock toggles are appended in build_docks() once the docks exist.
    view->setObjectName(QStringLiteral("viewMenu"));

    QMenu* help = menuBar()->addMenu(QStringLiteral("&Help"));
    help->addAction(act_about_);
}

void MainWindow::build_toolbars() {
    QToolBar* main = addToolBar(QStringLiteral("Main"));
    main->setMovable(false);
    main->setToolButtonStyle(Qt::ToolButtonIconOnly);
    act_open_->setIcon(style()->standardIcon(QStyle::SP_DialogOpenButton));
    act_back_->setIcon(style()->standardIcon(QStyle::SP_ArrowBack));
    act_forward_->setIcon(style()->standardIcon(QStyle::SP_ArrowForward));
    act_pseudo_->setIcon(style()->standardIcon(QStyle::SP_FileDialogDetailedView));
    main->addAction(act_open_);
    main->addSeparator();
    main->addAction(act_back_);
    main->addAction(act_forward_);
    main->addSeparator();
    main->addAction(act_pseudo_);

    addToolBarBreak();
    QToolBar* nav = addToolBar(QStringLiteral("Navigator"));
    nav->setMovable(false);
    band_ = new NavBand(nav);
    nav->addWidget(band_);
    connect(band_, &NavBand::address_clicked, this, [this](addr_t va) {
        if (!session_) return;
        const DiscoveredFunction* fn = session_->function_at(va);
        if (!fn) fn = session_->function_after(va);
        if (fn) jump_to(fn->addr);
    });
}

void MainWindow::build_central() {
    tabs_ = new QTabWidget(this);
    tabs_->setTabsClosable(true);
    tabs_->setMovable(true);
    tabs_->setDocumentMode(true);
    connect(tabs_, &QTabWidget::tabCloseRequested, this, &MainWindow::on_tab_close);
    setCentralWidget(tabs_);
}

void MainWindow::build_docks() {
    // Functions window
    fn_dock_ = new QDockWidget(QStringLiteral("Functions"), this);
    fn_dock_->setObjectName(QStringLiteral("functionsDock"));
    auto* fn_widget = new QWidget(fn_dock_);
    auto* fn_layout = new QVBoxLayout(fn_widget);
    fn_layout->setContentsMargins(0, 0, 0, 0);
    fn_layout->setSpacing(0);

    fn_model_ = new FunctionModel(this);
    fn_proxy_ = new QSortFilterProxyModel(this);
    fn_proxy_->setSourceModel(fn_model_);
    fn_proxy_->setFilterCaseSensitivity(Qt::CaseInsensitive);
    fn_proxy_->setFilterKeyColumn(FunctionModel::Name);

    fn_table_ = make_table(fn_proxy_, fn_widget, FunctionModel::Start);
    connect(fn_table_, &QAbstractItemView::activated, this, [this](const QModelIndex& idx) {
        const QModelIndex src = fn_proxy_->mapToSource(idx);
        if (src.isValid()) jump_to(fn_model_->address_at(src.row()));
    });

    fn_filter_ = new QLineEdit(fn_widget);
    fn_filter_->setPlaceholderText(QStringLiteral("Quick filter"));
    fn_filter_->setClearButtonEnabled(true);
    connect(fn_filter_, &QLineEdit::textChanged, fn_proxy_,
            &QSortFilterProxyModel::setFilterFixedString);
    connect(fn_filter_, &QLineEdit::returnPressed, this, [this] {
        if (fn_proxy_->rowCount() == 0) return;
        const QModelIndex src = fn_proxy_->mapToSource(fn_proxy_->index(0, 0));
        if (src.isValid()) jump_to(fn_model_->address_at(src.row()));
    });

    fn_layout->addWidget(fn_table_, 1);
    fn_layout->addWidget(fn_filter_);
    fn_dock_->setWidget(fn_widget);
    addDockWidget(Qt::LeftDockWidgetArea, fn_dock_);

    // Output window
    out_dock_ = new QDockWidget(QStringLiteral("Output"), this);
    out_dock_->setObjectName(QStringLiteral("outputDock"));
    auto* out_widget = new QWidget(out_dock_);
    auto* out_layout = new QVBoxLayout(out_widget);
    out_layout->setContentsMargins(0, 0, 0, 0);
    out_layout->setSpacing(0);

    output_ = new QPlainTextEdit(out_widget);
    output_->setReadOnly(true);
    output_->setFont(theme::code_font());
    output_->setMaximumBlockCount(5000);

    cmdline_ = new QLineEdit(out_widget);
    cmdline_->setFont(theme::code_font());
    cmdline_->setPlaceholderText(QStringLiteral("Jump to name or address"));
    connect(cmdline_, &QLineEdit::returnPressed, this, [this] {
        const QString t = cmdline_->text().trimmed();
        if (t.isEmpty()) return;
        jump_to_token(t);
        cmdline_->clear();
    });

    out_layout->addWidget(output_, 1);
    out_layout->addWidget(cmdline_);
    out_dock_->setWidget(out_widget);
    addDockWidget(Qt::BottomDockWidgetArea, out_dock_);

    resizeDocks({fn_dock_}, {440}, Qt::Horizontal);
    resizeDocks({out_dock_}, {160}, Qt::Vertical);

    if (auto* view = findChild<QMenu*>(QStringLiteral("viewMenu"))) {
        QAction* fn_toggle = fn_dock_->toggleViewAction();
        fn_toggle->setShortcut(QKeySequence(QStringLiteral("Shift+F3")));
        QAction* out_toggle = out_dock_->toggleViewAction();
        out_toggle->setShortcut(QKeySequence(QStringLiteral("Alt+0")));
        view->addAction(fn_toggle);
        view->addAction(out_toggle);
    }
}

// ---------------------------------------------------------------------------
// Session lifecycle
// ---------------------------------------------------------------------------

void MainWindow::log(const QString& line) {
    output_->appendPlainText(line);
}

void MainWindow::prompt_open() {
    const QString path = QFileDialog::getOpenFileName(
        this, QStringLiteral("Open binary"), QString(),
        QStringLiteral("All files (*)"));
    if (!path.isEmpty()) open_path(path);
}

void MainWindow::open_path(const QString& path) {
    if (loading_) return;
    loading_ = true;
    close_session();

    log(QStringLiteral("Loading file '%1'...").arg(path));
    au_label_->setText(QStringLiteral("AU: analyzing"));
    act_open_->setEnabled(false);
    QApplication::setOverrideCursor(Qt::WaitCursor);

    const std::filesystem::path fs_path(path.toStdString());
    spawn([this, fs_path] {
        auto r = open_session(fs_path);
        std::shared_ptr<Session> s;
        QString err;
        if (r) s = std::move(*r);
        else   err = QString::fromStdString(r.error().message);
        QMetaObject::invokeMethod(this, [this, s, err] { on_session_loaded(s, err); },
                                  Qt::QueuedConnection);
    });
}

void MainWindow::on_session_loaded(std::shared_ptr<Session> s, const QString& error) {
    loading_ = false;
    QApplication::restoreOverrideCursor();
    act_open_->setEnabled(true);

    if (!s) {
        au_label_->setText(QStringLiteral("AU: idle"));
        log(QStringLiteral("Failed to load: %1").arg(error));
        QMessageBox::warning(this, QStringLiteral("Open binary"), error);
        return;
    }

    session_ = std::move(s);
    const Binary& b = *session_->binary;
    const QString name = QString::fromStdString(session_->path.filename().string());
    setWindowTitle(QStringLiteral("Spelunk - %1").arg(name));

    log(QStringLiteral("Format: %1, arch: %2, %3 sections, %4 symbols, entry point %5")
            .arg(QString::fromUtf8(format_name(b.format()).data(),
                                   static_cast<int>(format_name(b.format()).size())),
                 QString::fromUtf8(arch_name(b.arch()).data(),
                                   static_cast<int>(arch_name(b.arch()).size())))
            .arg(b.sections().size())
            .arg(b.symbols().size())
            .arg(hex(b.entry_point())));
    log(QStringLiteral("Functions: %1.").arg(session_->functions.size()));

    fn_model_->set_session(session_.get());
    fn_table_->resizeColumnsToContents();
    fn_table_->horizontalHeader()->setSectionResizeMode(FunctionModel::Name, QHeaderView::Interactive);
    fn_table_->setColumnWidth(FunctionModel::Name,
                              std::clamp(fn_table_->columnWidth(FunctionModel::Name), 200, 320));
    band_->set_session(session_.get());

    for (QAction* a : {act_jump_addr_, act_jump_fn_, act_jump_entry_, act_disasm_, act_hex_,
                        act_pseudo_, act_strings_, act_imports_, act_exports_, act_segments_})
        a->setEnabled(true);

    jump_to_entry();
    start_xref_analysis();
    emit session_ready();
}

void MainWindow::start_xref_analysis() {
    // Whole-program call graph. Runs while the user already browses;
    // the disassembly header gains its `xrefs from:` line once it lands.
    au_label_->setText(QStringLiteral("AU: analyzing"));
    std::shared_ptr<Session> session = session_;
    spawn([this, session] {
        QElapsedTimer timer;
        timer.start();
        const auto edges = compute_call_graph(*session->binary);
        auto callers = std::make_shared<std::unordered_map<addr_t, std::vector<addr_t>>>();
        for (const auto& e : edges) (*callers)[e.callee].push_back(e.caller);
        for (auto& [callee, list] : *callers) {
            std::sort(list.begin(), list.end());
            list.erase(std::unique(list.begin(), list.end()), list.end());
        }
        const std::size_t n  = edges.size();
        const qint64      ms = timer.elapsed();
        QMetaObject::invokeMethod(this, [this, session, callers, n, ms] {
            on_xrefs_ready(session, callers, n, ms);
        }, Qt::QueuedConnection);
    });
}

void MainWindow::on_xrefs_ready(const std::shared_ptr<Session>& s,
                                std::shared_ptr<std::unordered_map<addr_t, std::vector<addr_t>>> callers,
                                std::size_t edges, qint64 ms) {
    if (s != session_) return;   // a different file was opened meanwhile
    session_->callers     = std::move(*callers);
    session_->xrefs_ready = true;
    disasm_cache_.clear();

    // Re-render the visible function in place, keeping the scroll and
    // cursor where they are.
    if (disasm_ && current_fn_) {
        if (const auto* fn = session_->function_at(*current_fn_)) {
            if (auto win = session_->window_for(*fn)) {
                const auto va     = disasm_->current_line_address();
                const int  scroll = disasm_->verticalScrollBar()->value();
                auto& r = disasm_cache_.emplace(fn->addr, render_disassembly(*win)).first->second;
                disasm_->set_content(r.text, r.lines);
                if (va) disasm_->go_to_address(*va, /*center=*/false);
                disasm_->verticalScrollBar()->setValue(scroll);
            }
        }
    }
    au_label_->setText(QStringLiteral("AU: idle"));
    log(QStringLiteral("Cross-references: %1 call edges in %2 ms.").arg(edges).arg(ms));
    log(QStringLiteral("The initial autoanalysis has been finished."));
    emit analysis_finished();
}

void MainWindow::close_session() {
    while (tabs_->count() > 0) on_tab_close(0);
    fn_model_->set_session(nullptr);
    band_->set_session(nullptr);
    disasm_cache_.clear();
    pseudo_cache_.clear();
    history_.clear();
    history_pos_ = 0;
    current_fn_.reset();
    session_.reset();
    addr_label_->clear();
    setWindowTitle(QStringLiteral("Spelunk"));
    update_history_actions();
}

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------

void MainWindow::jump_to(addr_t va, bool record) {
    if (!session_) return;
    const DiscoveredFunction* fn = session_->function_at(va);
    if (!fn) {
        log(QStringLiteral("Cannot jump to %1: address is not inside a function.").arg(hex(va)));
        return;
    }
    ensure_disassembly_tab();
    if (!current_fn_ || *current_fn_ != fn->addr) show_function(*fn);

    // Keep the focused view's tab; only raise the disassembly when the
    // current tab is a table (Strings, Imports, ...) that cannot show code.
    QWidget* cur = tabs_->currentWidget();
    if (cur != disasm_ && cur != pseudo_) tabs_->setCurrentWidget(disasm_);

    // Setting the cursor fires line_address_changed, which calls sync_chrome.
    if (disasm_) disasm_->go_to_address(va);
    if (pseudo_) pseudo_->go_to_address(va);
    sync_chrome(va);

    if (record) push_history(va);
}

void MainWindow::jump_to_or_hex(addr_t va, bool record) {
    if (!session_) return;
    if (session_->function_at(va)) {
        jump_to(va, record);
        return;
    }
    // Data address (strings, tables, ...): the disassembly has nothing to
    // show, so surface the raw bytes instead of an error.
    if (session_->section_at(va)) {
        if (HexView* h = ensure_hex_tab()) {
            h->show_address(va);
            tabs_->setCurrentWidget(h);
        }
        update_chrome(va);
        if (record) push_history(va);
        return;
    }
    log(QStringLiteral("Cannot jump to %1: address is not mapped.").arg(hex(va)));
}

void MainWindow::jump_to_token(const QString& token) {
    if (!session_ || token.isEmpty()) return;
    bool ok = false;
    if (token.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)) {
        const addr_t va = token.mid(2).toULongLong(&ok, 16);
        if (ok) { jump_to_or_hex(va); return; }
    }
    if (auto w = resolve_function(*session_->binary, token.toStdString())) {
        jump_to(w->start);
        return;
    }
    const addr_t va = token.toULongLong(&ok, 16);
    if (ok) { jump_to_or_hex(va); return; }
    log(QStringLiteral("Cannot find '%1'.").arg(token));
}

void MainWindow::push_history(addr_t va) {
    if (!history_.empty() && history_[history_pos_] == va) return;
    if (!history_.empty()) history_.resize(history_pos_ + 1);
    history_.push_back(va);
    history_pos_ = history_.size() - 1;
    update_history_actions();
}

void MainWindow::jump_back() {
    if (history_pos_ == 0 || history_.empty()) return;
    --history_pos_;
    jump_to_or_hex(history_[history_pos_], /*record=*/false);
    update_history_actions();
}

void MainWindow::jump_forward() {
    if (history_.empty() || history_pos_ + 1 >= history_.size()) return;
    ++history_pos_;
    jump_to_or_hex(history_[history_pos_], /*record=*/false);
    update_history_actions();
}

void MainWindow::update_history_actions() {
    act_back_->setEnabled(!history_.empty() && history_pos_ > 0);
    act_forward_->setEnabled(!history_.empty() && history_pos_ + 1 < history_.size());
}

void MainWindow::prompt_jump_address() {
    if (!session_) return;
    bool ok = false;
    const QString text = QInputDialog::getText(
        this, QStringLiteral("Jump to address"), QStringLiteral("Jump address"),
        QLineEdit::Normal, QString(), &ok);
    if (ok && !text.trimmed().isEmpty()) jump_to_token(text.trimmed());
}

void MainWindow::prompt_jump_function() {
    if (!session_) return;
    fn_dock_->show();
    fn_dock_->raise();
    fn_filter_->setFocus();
    fn_filter_->selectAll();
}

void MainWindow::jump_to_entry() {
    if (!session_) return;
    const addr_t entry = session_->binary->entry_point();
    if (session_->function_at(entry)) { jump_to(entry); return; }
    if (!session_->functions.empty()) jump_to(session_->functions.front().addr);
}

void MainWindow::sync_chrome(addr_t va) {
    update_chrome(va);
    // Follow the code cursor in the hex window, if it is open. Block the
    // hex's own change signal so the status bar keeps the exact address
    // rather than snapping to the 16-byte row start.
    if (hex_) {
        const QSignalBlocker block(hex_);
        hex_->show_address(va, /*center=*/false);
    }
}

void MainWindow::update_chrome(addr_t va) {
    if (!session_) return;
    band_->set_current(va);
    QString label = QStringLiteral("%1:%2")
                        .arg(QString::fromStdString(session_->segment_name(va)), hex16(va));
    if (const auto* fn = session_->function_at(va)) {
        label += QStringLiteral("   %1").arg(QString::fromStdString(display_name(fn->name)));
        if (va != fn->addr) label += QStringLiteral("+%1").arg(va - fn->addr, 0, 16);
        const int row = fn_model_->row_for(fn->addr);
        if (row >= 0) {
            const QModelIndex idx = fn_proxy_->mapFromSource(fn_model_->index(row, 0));
            if (idx.isValid() && fn_table_->currentIndex().row() != idx.row()) {
                fn_table_->selectRow(idx.row());
                fn_table_->scrollTo(idx);
            }
        }
    }
    addr_label_->setText(label);
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

MainWindow::Rendered MainWindow::render_disassembly(const FuncWindow& w) {
    Rendered out;
    auto r = session_->disassembly(w);
    if (!r) {
        out.text = QStringLiteral("; %1").arg(QString::fromStdString(r.error().message));
        out.lines.push_back(0);
        return out;
    }
    // Rewrite spelunk's `0x<16 hex>` line prefix into IDA's `<segment>:<16 hex>`.
    std::string_view text(*r);
    std::string      rewritten;
    rewritten.reserve(text.size() + text.size() / 8);
    std::size_t pos = 0;
    while (pos <= text.size()) {
        const std::size_t nl   = text.find('\n', pos);
        const std::size_t end  = nl == std::string_view::npos ? text.size() : nl;
        std::string_view  line = text.substr(pos, end - pos);
        addr_t            va   = 0;
        if (line.size() >= 18 && line.starts_with("0x")) {
            bool all_hex = true;
            for (std::size_t i = 2; i < 18; ++i) {
                const char c = line[i];
                const bool h = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
                if (!h) { all_hex = false; break; }
            }
            if (all_hex) {
                va = std::stoull(std::string(line.substr(2, 16)), nullptr, 16);
                rewritten += session_->segment_name(va);
                rewritten += ':';
                rewritten += line.substr(2);
            }
        }
        if (va == 0) rewritten += line;
        out.lines.push_back(va);
        if (nl == std::string_view::npos) break;
        rewritten += '\n';
        pos = nl + 1;
    }
    out.text = QString::fromStdString(rewritten);
    return out;
}

MainWindow::Rendered MainWindow::render_pseudocode(const FuncWindow& w) {
    Rendered out;
    LineMap  map;
    auto r = session_->pseudocode(w, &map);
    if (!r) {
        out.text = QStringLiteral("// %1").arg(QString::fromStdString(r.error().message));
        out.lines.push_back(0);
        return out;
    }
    const std::string& text = *r;
    std::size_t line_count = 1;
    for (char c : text) if (c == '\n') ++line_count;
    out.lines.assign(line_count, 0);

    // Hits arrive in emit order; translate byte offsets to line numbers
    // with one forward scan. The first hit on a line wins.
    std::vector<LineMap::Hit> hits = map.hits;
    std::sort(hits.begin(), hits.end(),
              [](const LineMap::Hit& a, const LineMap::Hit& b) { return a.byte_offset < b.byte_offset; });
    std::size_t line = 0, scan = 0;
    for (const auto& h : hits) {
        const std::size_t off = std::min(h.byte_offset, text.size());
        for (; scan < off; ++scan) if (text[scan] == '\n') ++line;
        if (line < out.lines.size() && out.lines[line] == 0) out.lines[line] = h.source_addr;
    }
    out.text = QString::fromStdString(text);
    return out;
}

CodeView* MainWindow::ensure_disassembly_tab() {
    if (!session_) return nullptr;
    if (!disasm_) {
        disasm_ = new CodeView(CodeView::Kind::Disassembly, tabs_);
        new AsmHighlighter(disasm_->document());
        connect(disasm_, &CodeView::jump_requested, this, &MainWindow::jump_to_token);
        connect(disasm_, &CodeView::back_requested, this, &MainWindow::jump_back);
        connect(disasm_, &CodeView::line_address_changed, this, &MainWindow::sync_chrome);
        tabs_->insertTab(0, disasm_, QStringLiteral("Spelunk View-A"));
        if (current_fn_) {
            if (const auto* fn = session_->function_at(*current_fn_)) {
                auto it = disasm_cache_.find(fn->addr);
                if (it == disasm_cache_.end() && session_->window_for(*fn))
                    it = disasm_cache_.emplace(fn->addr, render_disassembly(*session_->window_for(*fn))).first;
                if (it != disasm_cache_.end()) disasm_->set_content(it->second.text, it->second.lines);
            }
        }
    }
    return disasm_;
}

CodeView* MainWindow::ensure_pseudocode_tab() {
    if (!session_) return nullptr;
    if (!pseudo_) {
        pseudo_ = new CodeView(CodeView::Kind::Pseudocode, tabs_);
        new PseudoHighlighter(pseudo_->document());
        connect(pseudo_, &CodeView::jump_requested, this, &MainWindow::jump_to_token);
        connect(pseudo_, &CodeView::back_requested, this, &MainWindow::jump_back);
        connect(pseudo_, &CodeView::line_address_changed, this, &MainWindow::sync_chrome);
        const int at = disasm_ ? tabs_->indexOf(disasm_) + 1 : 0;
        tabs_->insertTab(at, pseudo_, QStringLiteral("Pseudocode-A"));
    }
    return pseudo_;
}

void MainWindow::show_function(const DiscoveredFunction& fn) {
    auto win = session_->window_for(fn);
    if (!win) {
        log(QStringLiteral("Cannot resolve function at %1.").arg(hex(fn.addr)));
        return;
    }
    current_fn_ = fn.addr;

    CodeView* d = ensure_disassembly_tab();
    auto dit = disasm_cache_.find(fn.addr);
    if (dit == disasm_cache_.end()) {
        ScopedTimer t("gui.render_disasm");
        dit = disasm_cache_.emplace(fn.addr, render_disassembly(*win)).first;
    }
    {
        ScopedTimer t("gui.set_content_disasm");
        d->set_content(dit->second.text, dit->second.lines);
    }

    if (pseudo_) {
        QApplication::setOverrideCursor(Qt::WaitCursor);
        auto pit = pseudo_cache_.find(fn.addr);
        if (pit == pseudo_cache_.end()) {
            ScopedTimer t("gui.render_pseudo");
            pit = pseudo_cache_.emplace(fn.addr, render_pseudocode(*win)).first;
        }
        {
            ScopedTimer t("gui.set_content_pseudo");
            pseudo_->set_content(pit->second.text, pit->second.lines);
        }
        QApplication::restoreOverrideCursor();
    }
}

void MainWindow::open_pseudocode() {
    if (!session_ || !current_fn_) return;
    const bool fresh = pseudo_ == nullptr;
    CodeView* p = ensure_pseudocode_tab();
    if (fresh) {
        if (const auto* fn = session_->function_at(*current_fn_)) {
            if (auto win = session_->window_for(*fn)) {
                QApplication::setOverrideCursor(Qt::WaitCursor);
                auto pit = pseudo_cache_.find(fn->addr);
                if (pit == pseudo_cache_.end())
                    pit = pseudo_cache_.emplace(fn->addr, render_pseudocode(*win)).first;
                p->set_content(pit->second.text, pit->second.lines);
                QApplication::restoreOverrideCursor();
            }
        }
    }
    tabs_->setCurrentWidget(p);
    if (disasm_) {
        if (auto va = disasm_->current_line_address()) p->go_to_address(*va);
    }
    p->setFocus();
}

void MainWindow::open_table_tab(const QString& title, QStandardItemModel* model) {
    for (int i = 0; i < tabs_->count(); ++i) {
        if (tabs_->tabText(i) == title) {
            tabs_->setCurrentIndex(i);
            model->deleteLater();
            return;
        }
    }
    QTableView* table = make_table(model, tabs_, 0);
    model->setParent(table);
    connect(table, &QAbstractItemView::activated, this, [this, table](const QModelIndex& idx) {
        const QVariant v = table->model()->index(idx.row(), 0).data(kAddressRole);
        if (v.isValid()) jump_to_or_hex(static_cast<addr_t>(v.toULongLong()));
    });
    tabs_->addTab(table, title);
    tabs_->setCurrentWidget(table);
    table->resizeColumnsToContents();
}

HexView* MainWindow::ensure_hex_tab() {
    if (!session_) return nullptr;
    if (!hex_) {
        hex_ = new HexView(tabs_);
        hex_->set_session(session_.get());
        connect(hex_, &HexView::jump_requested, this, &MainWindow::jump_to_token);
        // Hex cursor movement updates the chrome only; the disassembly
        // cursor is never steered from here (see sync_chrome).
        connect(hex_, &HexView::line_address_changed, this, &MainWindow::update_chrome);
        // Insert after the pseudocode tab when it exists, else after
        // the disassembly, else at the front.
        int at = 0;
        if (pseudo_) at = tabs_->indexOf(pseudo_) + 1;
        else if (disasm_) at = tabs_->indexOf(disasm_) + 1;
        tabs_->insertTab(at, hex_, QStringLiteral("Hex Dump"));
    }
    return hex_;
}

void MainWindow::open_hex() {
    if (!session_) return;
    HexView* h = ensure_hex_tab();
    std::optional<addr_t> va;
    if (disasm_) va = disasm_->current_line_address();
    if (!va && pseudo_) va = pseudo_->current_line_address();
    if (!va) va = current_fn_;
    if (!va) {
        const addr_t entry = session_->binary->entry_point();
        va = session_->function_at(entry) ? std::optional<addr_t>(entry)
             : (!session_->functions.empty() ? std::optional<addr_t>(session_->functions.front().addr)
                                             : std::nullopt);
    }
    if (!va) {
        for (const auto& sec : session_->binary->sections()) {
            if (sec.size != 0) { va = sec.vaddr; break; }
        }
    }
    if (va) h->show_address(*va);
    tabs_->setCurrentWidget(h);
    h->setFocus();
}

void MainWindow::open_strings() {
    if (!session_) return;
    QApplication::setOverrideCursor(Qt::WaitCursor);
    const auto& strings = session_->string_table();
    QApplication::restoreOverrideCursor();

    auto* model = new QStandardItemModel(this);
    model->setHorizontalHeaderLabels({QStringLiteral("Address"), QStringLiteral("Length"),
                                      QStringLiteral("Type"), QStringLiteral("String")});
    for (const auto& s : strings) {
        // Double-click follows the first code reference when one exists;
        // otherwise it lands on the string bytes themselves in the hex view.
        const addr_t target = s.xrefs.empty() ? s.addr : s.xrefs.front();
        QString seg = QString::fromStdString(session_->segment_name(s.addr));
        model->appendRow({addr_item(target, QStringLiteral("%1:%2").arg(seg, hex16(s.addr))),
                          text_item(QStringLiteral("%1").arg(s.text.size() + 1, 8, 16, QChar('0'))),
                          text_item(QStringLiteral("C")),
                          text_item(QString::fromStdString(s.text))});
    }
    log(QStringLiteral("Strings: %1 entries.").arg(strings.size()));
    open_table_tab(QStringLiteral("Strings"), model);
}

void MainWindow::open_imports() {
    if (!session_) return;
    auto* model = new QStandardItemModel(this);
    model->setHorizontalHeaderLabels({QStringLiteral("Address"), QStringLiteral("Name"),
                                      QStringLiteral("GOT slot")});
    for (const auto& sym : session_->binary->symbols()) {
        if (!sym.is_import) continue;
        model->appendRow({addr_item(sym.addr, sym.addr ? hex16(sym.addr) : QString()),
                          text_item(QString::fromStdString(sym.name)),
                          text_item(sym.got_addr ? hex16(sym.got_addr) : QString())});
    }
    open_table_tab(QStringLiteral("Imports"), model);
}

void MainWindow::open_exports() {
    if (!session_) return;
    auto* model = new QStandardItemModel(this);
    model->setHorizontalHeaderLabels({QStringLiteral("Address"), QStringLiteral("Name")});
    for (const auto& sym : session_->binary->symbols()) {
        if (!sym.is_export || sym.is_import) continue;
        model->appendRow({addr_item(sym.addr, hex16(sym.addr)),
                          text_item(QString::fromStdString(sym.name))});
    }
    open_table_tab(QStringLiteral("Exports"), model);
}

void MainWindow::open_segments() {
    if (!session_) return;
    auto* model = new QStandardItemModel(this);
    model->setHorizontalHeaderLabels({QStringLiteral("Name"), QStringLiteral("Start"),
                                      QStringLiteral("End"), QStringLiteral("R"),
                                      QStringLiteral("W"), QStringLiteral("X"),
                                      QStringLiteral("Class")});
    for (const auto& sec : session_->binary->sections()) {
        if (sec.size == 0) continue;
        const char* cls = sec.flags.executable ? "CODE" : (sec.data.empty() ? "BSS" : "DATA");
        model->appendRow({addr_item(sec.vaddr, QString::fromStdString(sec.name)),
                          text_item(hex16(sec.vaddr)),
                          text_item(hex16(sec.vaddr + sec.size)),
                          text_item(sec.flags.readable   ? QStringLiteral("R") : QStringLiteral(".")),
                          text_item(sec.flags.writable   ? QStringLiteral("W") : QStringLiteral(".")),
                          text_item(sec.flags.executable ? QStringLiteral("X") : QStringLiteral(".")),
                          text_item(QString::fromLatin1(cls))});
    }
    open_table_tab(QStringLiteral("Segments"), model);
}

void MainWindow::on_tab_close(int index) {
    QWidget* w = tabs_->widget(index);
    tabs_->removeTab(index);
    if (w == disasm_) disasm_ = nullptr;
    if (w == pseudo_) pseudo_ = nullptr;
    if (w == hex_) hex_ = nullptr;
    w->deleteLater();
}

}  // namespace spelunk::gui
