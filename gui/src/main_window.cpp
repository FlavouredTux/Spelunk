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
#include <QRegularExpression>
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
#include <charconv>
#include <format>
#include <set>

#include <spelunk/analysis/cfg_builder.hpp>
#include <spelunk/analysis/data_xrefs.hpp>
#include <spelunk/analysis/pipeline.hpp>
#include <spelunk/binary/arch.hpp>
#include <spelunk/binary/format.hpp>
#include <spelunk/common/timing.hpp>
#include <spelunk/disasm/decoder.hpp>

#include "chooser.hpp"
#include "code_view.hpp"
#include "function_model.hpp"
#include "graph_view.hpp"
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

// One instruction line of the core's text disassembly:
//   0x0000000000401000  48 89 e5                        mov rbp, rsp  ; comment
struct RawInsn {
    addr_t           addr = 0;
    std::string_view bytes;
    std::string_view mnemonic;
    std::string_view operands;
    std::string_view comment;
};

std::vector<std::string_view> split_lines(std::string_view text) {
    std::vector<std::string_view> lines;
    std::size_t pos = 0;
    while (pos <= text.size()) {
        const std::size_t nl = text.find('\n', pos);
        if (nl == std::string_view::npos) { lines.push_back(text.substr(pos)); break; }
        lines.push_back(text.substr(pos, nl - pos));
        pos = nl + 1;
    }
    return lines;
}

bool is_hex_digit(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

std::optional<RawInsn> parse_raw_insn(std::string_view line) {
    if (line.size() < 20 || !line.starts_with("0x")) return std::nullopt;
    RawInsn insn;
    if (std::from_chars(line.data() + 2, line.data() + 18, insn.addr, 16).ec != std::errc{})
        return std::nullopt;
    std::size_t pos = 18;
    while (pos < line.size() && line[pos] == ' ') ++pos;
    const std::size_t bytes_start = pos;
    // Opcode bytes are "hh " pairs; the column ends at a run of spaces.
    while (pos + 2 < line.size() && is_hex_digit(line[pos]) && is_hex_digit(line[pos + 1]) &&
           line[pos + 2] == ' ') {
        pos += 3;
        if (pos < line.size() && line[pos] == ' ') break;
    }
    insn.bytes = line.substr(bytes_start, pos - bytes_start);
    while (!insn.bytes.empty() && insn.bytes.back() == ' ') insn.bytes.remove_suffix(1);
    while (pos < line.size() && line[pos] == ' ') ++pos;
    std::string_view rest = line.substr(pos);
    if (const auto semi = rest.find("  ; "); semi != std::string_view::npos) {
        insn.comment = rest.substr(semi + 4);
        rest = rest.substr(0, semi);
    }
    const auto space = rest.find(' ');
    insn.mnemonic = rest.substr(0, space);
    if (space != std::string_view::npos) insn.operands = rest.substr(space + 1);
    if (insn.mnemonic.empty()) return std::nullopt;
    return insn;
}

// Direct call / jump target, when the operand is a bare address.
std::optional<addr_t> branch_target(const RawInsn& insn) {
    if (insn.mnemonic.empty() || (insn.mnemonic[0] != 'j' && insn.mnemonic != "call"))
        return std::nullopt;
    std::string_view op = insn.operands;
    if (!op.starts_with("0x") || op.size() < 3) return std::nullopt;
    addr_t va = 0;
    const auto [end, ec] = std::from_chars(op.data() + 2, op.data() + op.size(), va, 16);
    if (ec != std::errc{} || end != op.data() + op.size()) return std::nullopt;
    return va;
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
    const auto make = [this](const QString& text, const QString& keys, auto slot) {
        auto* a = new QAction(text, this);
        if (!keys.isEmpty()) a->setShortcut(QKeySequence(keys));
        connect(a, &QAction::triggered, this, slot);
        return a;
    };

    act_open_ = new QAction(QStringLiteral("&Open..."), this);
    act_open_->setShortcut(QKeySequence::Open);
    connect(act_open_, &QAction::triggered, this, &MainWindow::prompt_open);
    act_save_ = make(QStringLiteral("&Save database"), QStringLiteral("Ctrl+W"), &MainWindow::save_database);
    act_quit_ = make(QStringLiteral("&Quit"), QStringLiteral("Alt+X"), &QWidget::close);

    // Jump menu: IDA's default keymap.
    act_back_ = make(QStringLiteral("Jump &back"), QStringLiteral("Esc"), &MainWindow::jump_back);
    act_back_->setShortcutContext(Qt::WidgetShortcut);   // views handle Esc themselves
    act_forward_ = make(QStringLiteral("Jump &forward"), QStringLiteral("Ctrl+Return"),
                        &MainWindow::jump_forward);
    act_jump_addr_ = make(QStringLiteral("Jump to &address..."), QStringLiteral("G"),
                          &MainWindow::prompt_jump_address);
    act_jump_fn_ = make(QStringLiteral("Jump to f&unction..."), QStringLiteral("Ctrl+P"),
                        &MainWindow::choose_function);
    act_names_ = make(QStringLiteral("Jump by &name..."), QStringLiteral("Ctrl+L"),
                      &MainWindow::choose_name);
    act_jump_entry_ = make(QStringLiteral("Jump to &entry point"), QStringLiteral("Ctrl+E"),
                           &MainWindow::jump_to_entry);
    act_mark_ = make(QStringLiteral("&Mark position..."), QStringLiteral("Alt+M"),
                     &MainWindow::mark_position);
    act_jump_mark_ = make(QStringLiteral("Jump to marke&d position..."), QStringLiteral("Ctrl+M"),
                          &MainWindow::choose_mark);
    act_xrefs_ = make(QStringLiteral("Jump to &xref to operand..."), QStringLiteral("X"),
                      [this] { show_xrefs(false); });
    act_xrefs_item_ = make(QStringLiteral("&List cross references to..."), QStringLiteral("Ctrl+X"),
                           [this] { show_xrefs(true); });

    // Search menu
    act_search_text_ = make(QStringLiteral("&Text..."), QStringLiteral("Alt+T"),
                            [this] { search_text(true); });
    act_search_text_next_ = make(QStringLiteral("Ne&xt text"), QStringLiteral("Ctrl+T"),
                                 [this] { search_text(false); });
    act_search_bytes_ = make(QStringLiteral("Sequence of &bytes..."), QStringLiteral("Alt+B"),
                             [this] { search_bytes(true); });
    act_search_bytes_next_ = make(QStringLiteral("Next seq&uence of bytes"), QStringLiteral("Ctrl+B"),
                                  [this] { search_bytes(false); });

    // Edit menu. These act on the cursor in a code view, so they are bound
    // to the tab area: typing in the filters must not trigger them.
    act_rename_ = make(QStringLiteral("&Rename..."), QStringLiteral("N"), &MainWindow::rename_at_cursor);
    act_comment_ = make(QStringLiteral("&Comment..."), QStringLiteral(":"), &MainWindow::comment_at_cursor);
    act_comment_alt_ = make(QStringLiteral("Repeatable comment..."), QStringLiteral(";"),
                            &MainWindow::comment_at_cursor);
    act_comment_pseudo_ = make(QStringLiteral("Pseudocode comment..."), QStringLiteral("/"),
                               &MainWindow::comment_at_cursor);
    act_number_ = make(QStringLiteral("&Hexadecimal / decimal"), QStringLiteral("H"),
                       &MainWindow::toggle_number);
    act_toggle_view_ = make(QStringLiteral("Toggle &pseudocode / disassembly"), QStringLiteral("Tab"),
                            &MainWindow::toggle_view);
    act_graph_ = make(QStringLiteral("&Graph view"), QStringLiteral("Space"), &MainWindow::toggle_graph);
    for (QAction* a : {act_rename_, act_comment_, act_comment_alt_, act_comment_pseudo_, act_number_,
                        act_toggle_view_, act_graph_, act_xrefs_}) {
        a->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    }
    act_filter_ = make(QStringLiteral("Quick &filter"), QStringLiteral("Ctrl+F"), &MainWindow::focus_filter);

    // View > Open subviews
    act_disasm_ = new QAction(QStringLiteral("&Disassembly"), this);
    connect(act_disasm_, &QAction::triggered, this, [this] {
        if (auto* v = ensure_disassembly_tab()) tabs_->setCurrentWidget(v);
    });
    act_pseudo_ = make(QStringLiteral("&Pseudocode"), QStringLiteral("F5"), &MainWindow::open_pseudocode);
    // IDA binds H to the number base, so the hex view has no key of its own.
    act_hex_ = make(QStringLiteral("&Hex dump"), QString(), &MainWindow::open_hex);
    act_strings_ = make(QStringLiteral("&Strings"), QStringLiteral("Shift+F12"), &MainWindow::open_strings);
    act_names_window_ = make(QStringLiteral("&Names"), QStringLiteral("Shift+F4"), &MainWindow::open_names);
    act_imports_ = make(QStringLiteral("&Imports"), QString(), &MainWindow::open_imports);
    act_exports_ = make(QStringLiteral("&Exports"), QString(), &MainWindow::open_exports);
    act_segments_ = make(QStringLiteral("Se&gments"), QStringLiteral("Shift+F7"), &MainWindow::open_segments);

    act_opcodes_ = new QAction(QStringLiteral("Show &opcode bytes"), this);
    act_opcodes_->setCheckable(true);
    act_opcodes_->setChecked(show_opcodes_);
    connect(act_opcodes_, &QAction::toggled, this, [this](bool on) {
        show_opcodes_ = on;
        refresh_views(false);
    });

    act_about_ = new QAction(QStringLiteral("&About"), this);
    connect(act_about_, &QAction::triggered, this, [this] {
        QMessageBox::about(this, QStringLiteral("About Spelunk"),
            QStringLiteral("<b>Spelunk %1</b><br>Reverse engineering toolkit.<br>"
                           "Qt %2 front end linked directly against spelunk::core.")
                .arg(QApplication::applicationVersion(), QString::fromLatin1(qVersion())));
    });

    for (QAction* a : session_actions()) a->setEnabled(false);
}

std::vector<QAction*> MainWindow::session_actions() const {
    return {act_save_, act_back_, act_forward_, act_jump_addr_, act_jump_fn_, act_names_,
            act_jump_entry_, act_mark_, act_jump_mark_, act_xrefs_, act_xrefs_item_,
            act_search_text_, act_search_text_next_, act_search_bytes_, act_search_bytes_next_,
            act_rename_, act_comment_, act_comment_alt_, act_comment_pseudo_, act_number_,
            act_toggle_view_, act_graph_, act_disasm_, act_hex_, act_pseudo_, act_strings_,
            act_names_window_, act_imports_, act_exports_, act_segments_};
}

void MainWindow::build_menus() {
    QMenu* file = menuBar()->addMenu(QStringLiteral("&File"));
    file->addAction(act_open_);
    file->addAction(act_save_);
    file->addSeparator();
    file->addAction(act_quit_);

    QMenu* edit = menuBar()->addMenu(QStringLiteral("&Edit"));
    edit->addAction(act_rename_);
    edit->addAction(act_comment_);
    edit->addAction(act_comment_alt_);
    edit->addAction(act_comment_pseudo_);
    edit->addSeparator();
    QMenu* operand = edit->addMenu(QStringLiteral("&Operand type"));
    operand->addAction(act_number_);

    QMenu* jump = menuBar()->addMenu(QStringLiteral("&Jump"));
    jump->addAction(act_back_);
    jump->addAction(act_forward_);
    jump->addSeparator();
    jump->addAction(act_jump_addr_);
    jump->addAction(act_jump_fn_);
    jump->addAction(act_names_);
    jump->addAction(act_jump_entry_);
    jump->addSeparator();
    jump->addAction(act_xrefs_);
    jump->addAction(act_xrefs_item_);
    jump->addSeparator();
    jump->addAction(act_mark_);
    jump->addAction(act_jump_mark_);

    QMenu* search = menuBar()->addMenu(QStringLiteral("&Search"));
    search->addAction(act_search_text_);
    search->addAction(act_search_text_next_);
    search->addSeparator();
    search->addAction(act_search_bytes_);
    search->addAction(act_search_bytes_next_);

    QMenu* view = menuBar()->addMenu(QStringLiteral("&View"));
    QMenu* sub  = view->addMenu(QStringLiteral("&Open subviews"));
    sub->addAction(act_disasm_);
    sub->addAction(act_pseudo_);
    sub->addAction(act_hex_);
    sub->addSeparator();
    sub->addAction(act_strings_);
    sub->addAction(act_names_window_);
    sub->addAction(act_imports_);
    sub->addAction(act_exports_);
    sub->addAction(act_segments_);
    view->addSeparator();
    view->addAction(act_toggle_view_);
    view->addAction(act_graph_);
    view->addAction(act_filter_);
    view->addSeparator();
    // Dock toggles are appended in build_docks() once the docks exist.
    view->setObjectName(QStringLiteral("viewMenu"));

    QMenu* options = menuBar()->addMenu(QStringLiteral("&Options"));
    options->addAction(act_opcodes_);

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
    // A graph tab brought forward with the mouse shows the current function.
    connect(tabs_, &QTabWidget::currentChanged, this, [this] {
        if (!session_ || !graph_ || tabs_->currentWidget() != graph_ || !current_fn_ ||
            graph_fn_ == current_fn_) return;
        if (const auto* fn = session_->function_at(*current_fn_)) render_graph(*fn);
    });
    tabs_->addActions({act_rename_, act_comment_, act_comment_alt_, act_comment_pseudo_,
                       act_number_, act_toggle_view_, act_graph_, act_xrefs_});
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

    resizeDocks({fn_dock_}, {520}, Qt::Horizontal);
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
    {
        QHeaderView* header = fn_table_->horizontalHeader();
        header->setStretchLastSection(true);
        fn_table_->resizeColumnsToContents();
        header->setSectionResizeMode(FunctionModel::Name, QHeaderView::Interactive);
        fn_table_->setColumnWidth(FunctionModel::Name,
                                  std::clamp(fn_table_->columnWidth(FunctionModel::Name), 180, 260));
    }
    band_->set_session(session_.get());

    for (QAction* a : session_actions()) a->setEnabled(true);
    update_history_actions();
    log(QStringLiteral("Annotations: %1").arg(QString::fromStdString(session_->annotations_path.string())));

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
        auto data_refs = std::make_shared<std::map<addr_t, std::vector<DataXref>>>(
            compute_data_xrefs(*session->binary));
        auto callers = std::make_shared<std::unordered_map<addr_t, std::vector<addr_t>>>();
        for (const auto& e : edges) (*callers)[e.callee].push_back(e.caller);
        for (auto& [callee, list] : *callers) {
            std::sort(list.begin(), list.end());
            list.erase(std::unique(list.begin(), list.end()), list.end());
        }
        const std::size_t n  = edges.size();
        const qint64      ms = timer.elapsed();
        QMetaObject::invokeMethod(this, [this, session, callers, data_refs, n, ms] {
            on_xrefs_ready(session, callers, data_refs, n, ms);
        }, Qt::QueuedConnection);
    });
}

void MainWindow::on_xrefs_ready(const std::shared_ptr<Session>& s,
                                std::shared_ptr<std::unordered_map<addr_t, std::vector<addr_t>>> callers,
                                std::shared_ptr<std::map<addr_t, std::vector<DataXref>>> data_refs,
                                std::size_t edges, qint64 ms) {
    if (s != session_) return;   // a different file was opened meanwhile
    session_->callers     = std::move(*callers);
    session_->data_refs   = std::move(*data_refs);
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
    std::size_t data_count = 0;
    for (const auto& [_, refs] : session_->data_refs) data_count += refs.size();
    log(QStringLiteral("Cross-references: %1 call edges, %2 data references in %3 ms.")
            .arg(edges).arg(data_count).arg(ms));
    log(QStringLiteral("The initial autoanalysis has been finished."));
    emit analysis_finished();
}

void MainWindow::close_session() {
    while (tabs_->count() > 0) on_tab_close(0);
    fn_model_->set_session(nullptr);
    band_->set_session(nullptr);
    disasm_cache_.clear();
    disasm_raw_.clear();
    pseudo_cache_.clear();
    pseudo_pending_.clear();
    number_toggles_.clear();
    marks_.clear();
    history_.clear();
    history_pos_ = 0;
    current_fn_.reset();
    graph_fn_.reset();
    session_.reset();
    addr_label_->clear();
    setWindowTitle(QStringLiteral("Spelunk"));
    for (QAction* a : session_actions()) a->setEnabled(false);
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
    if (cur != disasm_ && cur != pseudo_ && (!graph_ || cur != graph_)) tabs_->setCurrentWidget(disasm_);

    // Setting the cursor fires line_address_changed, which calls sync_chrome.
    if (disasm_) disasm_->go_to_address(va);
    if (pseudo_) pseudo_->go_to_address(va);
    if (graph_ && tabs_->currentWidget() == graph_) graph_->go_to_address(va);
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
    if (auto w = resolve_function(*session_->binary, token.toStdString(), &session_->annotations)) {
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
    act_back_->setEnabled(session_ && !history_.empty() && history_pos_ > 0);
    act_forward_->setEnabled(session_ && !history_.empty() && history_pos_ + 1 < history_.size());
}

void MainWindow::prompt_jump_address() {
    if (!session_) return;
    bool ok = false;
    const QString text = QInputDialog::getText(
        this, QStringLiteral("Jump to address"), QStringLiteral("Jump address"),
        QLineEdit::Normal, QString(), &ok);
    if (ok && !text.trimmed().isEmpty()) jump_to_token(text.trimmed());
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
    const std::string* raw = raw_disassembly(w.start);
    if (!raw) {
        auto r = session_->disassembly(w);
        out.text = QStringLiteral("; %1").arg(r ? QStringLiteral("no instructions")
                                                : QString::fromStdString(r.error().message));
        out.lines.push_back(0);
        return out;
    }
    std::vector<RawInsn> insns;
    for (std::string_view line : split_lines(*raw))
        if (auto insn = parse_raw_insn(line)) insns.push_back(*insn);
    if (insns.empty()) {
        out.text = QStringLiteral("; no instructions");
        out.lines.push_back(0);
        return out;
    }

    const auto& notes = session_->annotations.notes;
    // In-function branch targets become loc_ labels, with IDA's
    // `CODE XREF` comments naming the jumps that reach them.
    std::map<addr_t, std::vector<addr_t>> labels;
    for (const auto& insn : insns) {
        if (auto target = branch_target(insn); target && *target != w.start &&
            *target >= insns.front().addr && *target <= insns.back().addr && insn.mnemonic != "call")
            labels[*target].push_back(insn.addr);
    }
    for (const auto& [va, _] : session_->annotations.renames)
        if (va != w.start && va >= insns.front().addr && va <= insns.back().addr) labels[va];

    const auto name_of = [&](addr_t va) -> std::string {
        if (std::string n = session_->name_at(va); !n.empty()) return n;
        if (va == w.start) return display_name(w.label);
        return std::format("loc_{:x}", va);
    };
    const auto ref_text = [&](addr_t from, addr_t to, char kind) {
        const DiscoveredFunction* f = session_->function_at(from);
        std::string where = f ? name_of(f->addr) : std::format("{:x}", from);
        if (f && from != f->addr) where += std::format("+{:X}", from - f->addr);
        return std::format("{}{}{}", where, from < to ? "↑" : "↓", kind);
    };

    QString text;
    const auto prefix = [&](addr_t va) {
        return QString::fromStdString(session_->segment_name(va)) + QLatin1Char(':') +
               QStringLiteral("%1").arg(va, 16, 16, QChar('0')).toUpper();
    };
    const auto emit_line = [&](addr_t va, const QString& body, addr_t line_va) {
        text += prefix(va);
        if (!body.isEmpty()) text += QLatin1Char(' ') + body;
        text += QLatin1Char('\n');
        out.lines.push_back(line_va);
    };
    const auto with_comment = [](QString body, const QStringList& comments) {
        if (comments.isEmpty()) return body;
        if (body.size() < 56) body = body.leftJustified(56);
        else body += QLatin1Char(' ');
        return body + QStringLiteral("; ") + comments.join(QStringLiteral(" | "));
    };
    const QString name_pad = QString(16, QLatin1Char(' '));

    // Function header
    const addr_t start = w.start;
    emit_line(start, {}, 0);
    emit_line(start, QStringLiteral("; =============== S U B R O U T I N E ======================================="), 0);
    emit_line(start, {}, 0);
    if (auto note = notes.find(start); note != notes.end())
        emit_line(start, QStringLiteral("; ") + QString::fromStdString(note->second), 0);
    {
        QStringList refs;
        const auto callers = session_->callers_of(start);
        for (std::size_t i = 0; i < callers.size() && i < 3; ++i)
            refs << QString::fromStdString(ref_text(callers[i], start, 'p'));
        if (callers.size() > 3) refs << QStringLiteral("...");
        // The name column is 16 wide including the separator, so `proc`
        // lines up with the mnemonics.
        const QString head = QString::fromStdString(name_of(start)).leftJustified(15) +
                             QStringLiteral(" proc near");
        emit_line(start, refs.isEmpty() ? head
                                        : with_comment(head, {QStringLiteral("CODE XREF: ") + refs.join(QStringLiteral(", "))}),
                  start);
    }

    for (const auto& insn : insns) {
        if (auto label = labels.find(insn.addr); label != labels.end() && insn.addr != start) {
            QStringList refs;
            for (std::size_t i = 0; i < label->second.size() && i < 3; ++i)
                refs << QString::fromStdString(ref_text(label->second[i], insn.addr, 'j'));
            if (label->second.size() > 3) refs << QStringLiteral("...");
            emit_line(insn.addr, {}, 0);
            const QString head = QString::fromStdString(name_of(insn.addr)) + QLatin1Char(':');
            emit_line(insn.addr, refs.isEmpty() ? head
                                                : with_comment(head, {QStringLiteral("CODE XREF: ") + refs.join(QStringLiteral(", "))}),
                      insn.addr);
        }

        std::string mnemonic(insn.mnemonic);
        if (mnemonic == "jne") mnemonic = "jnz";
        else if (mnemonic == "je") mnemonic = "jz";
        QString operands = QString::fromUtf8(insn.operands.data(), static_cast<qsizetype>(insn.operands.size()));
        QStringList comments;
        bool named_target = false;
        if (auto target = branch_target(insn)) {
            const DiscoveredFunction* f = session_->function_at(*target);
            std::string name;
            if (labels.contains(*target) || *target == start || (f && f->addr == *target))
                name = name_of(*target);
            else if (f)
                name = std::format("{}+{:X}", name_of(f->addr), *target - f->addr);
            // PLT stubs are not discovered functions; the core still names
            // them in its comment (`call 0x401030  ; printf`).
            static const QRegularExpression plain_name(QStringLiteral(R"(^[A-Za-z_.$@?][\w.$@?]*$)"));
            if (name.empty() && !insn.comment.empty()) {
                const QString c = QString::fromUtf8(insn.comment.data(), static_cast<qsizetype>(insn.comment.size()));
                if (plain_name.match(c).hasMatch()) name = c.toStdString();
            }
            if (!name.empty()) {
                operands = QString::fromStdString(name);
                named_target = true;
            }
        }
        // Immediates that are function addresses read as `offset name`, as
        // in IDA. Memory operands keep their raw address.
        if (!named_target && !operands.contains(QLatin1Char('['))) {
            static const QRegularExpression imm(QStringLiteral(R"(\b0x([0-9a-fA-F]+)\b)"));
            QString rewritten;
            qsizetype last_end = 0;
            auto it = imm.globalMatch(operands);
            while (it.hasNext()) {
                const auto m = it.next();
                bool ok = false;
                const addr_t va = m.captured(1).toULongLong(&ok, 16);
                const DiscoveredFunction* f = ok ? session_->function_at(va) : nullptr;
                if (!f || f->addr != va) continue;
                rewritten += operands.mid(last_end, m.capturedStart(0) - last_end);
                rewritten += QStringLiteral("offset ") + QString::fromStdString(name_of(va));
                last_end = m.capturedEnd(0);
            }
            if (last_end > 0) operands = rewritten + operands.mid(last_end);
        }
        apply_number_toggles(operands, insn.addr);
        if (auto note = notes.find(insn.addr); note != notes.end())
            comments << QString::fromStdString(note->second);
        // The core annotates calls with the callee name; once the operand
        // already says it, the comment is noise.
        if (!insn.comment.empty() && !named_target)
            comments << QString::fromUtf8(insn.comment.data(), static_cast<qsizetype>(insn.comment.size()));

        QString graph_line = QStringLiteral("  ") + QString::fromStdString(mnemonic).leftJustified(8) + operands;
        if (!comments.isEmpty()) graph_line += QStringLiteral("  ; ") + comments.join(QStringLiteral(" | "));
        out.graph_lines.emplace(insn.addr, std::move(graph_line));

        QString body;
        if (show_opcodes_)
            body += QString::fromUtf8(insn.bytes.data(), static_cast<qsizetype>(insn.bytes.size()))
                        .toUpper().leftJustified(30);
        body += name_pad + QString::fromStdString(mnemonic).leftJustified(8) + operands;
        emit_line(insn.addr, with_comment(body, comments), insn.addr);
    }

    const addr_t last = insns.back().addr;
    emit_line(last, QString::fromStdString(name_of(start)).leftJustified(15) + QStringLiteral(" endp"), last);
    emit_line(last, {}, 0);
    text.chop(1);
    out.text = std::move(text);
    return out;
}

const std::string* MainWindow::raw_disassembly(addr_t fn) {
    if (auto it = disasm_raw_.find(fn); it != disasm_raw_.end()) return &it->second;
    const DiscoveredFunction* f = session_->function_at(fn);
    if (!f || f->addr != fn) return nullptr;
    auto win = session_->window_for(*f);
    if (!win) return nullptr;
    auto r = session_->disassembly(*win);
    if (!r) return nullptr;
    return &disasm_raw_.emplace(fn, std::move(*r)).first->second;
}

MainWindow::Rendered MainWindow::render_pseudocode(const Session& session,
                                                   const FuncWindow& w) {
    Rendered out;
    LineMap  map;
    auto r = session.pseudocode(w, &map);
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

void MainWindow::request_pseudocode(const FuncWindow& w) {
    if (!pseudo_ || !session_) return;
    if (auto cached = pseudo_cache_.find(w.start); cached != pseudo_cache_.end()) {
        const Rendered shown = decorate_pseudocode(cached->second);
        pseudo_->set_content(shown.text, shown.lines);
        emit pseudocode_ready();
        return;
    }
    pseudo_->set_content(QStringLiteral("// Analyzing pseudocode..."), {0});
    if (!pseudo_pending_.insert(w.start).second) return;

    const std::shared_ptr<Session> session = session_;
    spawn([this, session, w] {
        Rendered rendered = render_pseudocode(*session, w);
        QMetaObject::invokeMethod(this,
            [this, session, addr = w.start, rendered = std::move(rendered)]() mutable {
                if (session_ != session) return;
                pseudo_pending_.erase(addr);
                auto [it, _] = pseudo_cache_.insert_or_assign(addr, std::move(rendered));
                if (pseudo_ && current_fn_ && *current_fn_ == addr) {
                    const auto va = disasm_ ? disasm_->current_line_address()
                                            : std::nullopt;
                    const Rendered shown = decorate_pseudocode(it->second);
                    pseudo_->set_content(shown.text, shown.lines);
                    if (va) pseudo_->go_to_address(*va);
                    emit pseudocode_ready();
                }
            }, Qt::QueuedConnection);
    });
}

CodeView* MainWindow::ensure_disassembly_tab() {
    if (!session_) return nullptr;
    if (!disasm_) {
        disasm_ = new CodeView(CodeView::Kind::Disassembly, tabs_);
        new AsmHighlighter(disasm_->document());
        connect(disasm_, &CodeView::jump_requested, this, &MainWindow::jump_to_token);
        connect(disasm_, &CodeView::back_requested, this, &MainWindow::jump_back);
        connect(disasm_, &CodeView::toggle_view_requested, this, &MainWindow::toggle_view);
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
        connect(pseudo_, &CodeView::toggle_view_requested, this, &MainWindow::toggle_view);
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
        request_pseudocode(*win);
    }
    if (graph_ && tabs_->currentWidget() == graph_) render_graph(fn);
}

void MainWindow::open_pseudocode() {
    if (!session_ || !current_fn_) return;
    std::optional<addr_t> va;
    if (const auto at = cursor()) va = at->address;
    if (!va && disasm_) va = disasm_->current_line_address();
    const bool fresh = pseudo_ == nullptr;
    CodeView* p = ensure_pseudocode_tab();
    if (fresh) {
        if (const auto* fn = session_->function_at(*current_fn_)) {
            if (auto win = session_->window_for(*fn)) {
                request_pseudocode(*win);
            }
        }
    }
    tabs_->setCurrentWidget(p);
    if (va) p->go_to_address(*va);
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
    auto* page   = new QWidget(tabs_);
    auto* layout = new QVBoxLayout(page);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    auto* proxy = new QSortFilterProxyModel(page);
    proxy->setSourceModel(model);
    proxy->setFilterCaseSensitivity(Qt::CaseInsensitive);
    proxy->setFilterKeyColumn(-1);
    model->setParent(page);
    QTableView* table = make_table(proxy, page, 0);
    connect(table, &QAbstractItemView::activated, this, [this, table](const QModelIndex& idx) {
        const QVariant v = table->model()->index(idx.row(), 0).data(kAddressRole);
        if (v.isValid()) jump_to_or_hex(static_cast<addr_t>(v.toULongLong()));
    });
    auto* filter = new QLineEdit(page);
    filter->setObjectName(QStringLiteral("quickFilter"));
    filter->setPlaceholderText(QStringLiteral("Quick filter (Ctrl+F)"));
    filter->setClearButtonEnabled(true);
    filter->hide();
    connect(filter, &QLineEdit::textChanged, proxy, &QSortFilterProxyModel::setFilterFixedString);
    layout->addWidget(table, 1);
    layout->addWidget(filter);
    tabs_->addTab(page, title);
    tabs_->setCurrentWidget(page);
    table->resizeColumnsToContents();
    table->setFocus();
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
        tabs_->insertTab(at, hex_, QStringLiteral("Hex View-1"));
    }
    return hex_;
}

GraphView* MainWindow::ensure_graph_tab() {
    if (!session_) return nullptr;
    if (!graph_) {
        graph_ = new GraphView(tabs_);
        connect(graph_, &GraphView::jump_requested, this, &MainWindow::jump_to_token);
        connect(graph_, &GraphView::back_requested, this, &MainWindow::jump_back);
        connect(graph_, &GraphView::line_address_changed, this, &MainWindow::sync_chrome);
        const int at = disasm_ ? tabs_->indexOf(disasm_) + 1 : 0;
        tabs_->insertTab(at, graph_, QStringLiteral("Spelunk Graph-A"));
    }
    return graph_;
}

void MainWindow::render_graph(const DiscoveredFunction& fn) {
    GraphView* g = ensure_graph_tab();
    if (!g) return;
    graph_fn_ = fn.addr;
    auto decoder = make_decoder(*session_->binary);
    if (!decoder) {
        g->show_message(QString::fromStdString(decoder.error().message));
        return;
    }
    const CfgBuilder builder(*session_->binary, **decoder);
    auto cfg = builder.build(fn.addr, fn.name);
    if (!cfg) {
        g->show_message(QStringLiteral("No control-flow graph: %1")
                            .arg(QString::fromStdString(cfg.error().message)));
        return;
    }
    constexpr std::size_t kMaxGraphBlocks = 1500;
    if (cfg->blocks.size() > kMaxGraphBlocks) {
        g->show_message(QStringLiteral("%1 blocks are too many to lay out; Space returns to the text view.")
                            .arg(cfg->blocks.size()));
        return;
    }
    // Block lines come from the text listing so names, comments and the
    // H toggles read the same in both views.
    auto listing = disasm_cache_.find(fn.addr);
    if (listing == disasm_cache_.end()) {
        if (auto win = session_->window_for(fn))
            listing = disasm_cache_.emplace(fn.addr, render_disassembly(*win)).first;
    }

    // IDA labels only the blocks something jumps to, not plain fallthroughs.
    std::set<addr_t> jumped_to;
    for (const auto& bb : cfg->blocks) {
        if (bb.kind == BlockKind::Fallthrough) continue;
        for (std::size_t k = 0; k < bb.successors.size(); ++k)
            if (!(bb.kind == BlockKind::Conditional && k == 1)) jumped_to.insert(bb.successors[k]);
    }
    std::vector<GraphView::Block> blocks;
    blocks.reserve(cfg->blocks.size());
    for (const auto& bb : cfg->blocks) {
        GraphView::Block block;
        if (bb.start == fn.addr) {
            block.lines << QStringLiteral(" %1 proc near").arg(QString::fromStdString(session_->name_at(fn.addr)));
            block.line_addrs.push_back(bb.start);
        } else if (jumped_to.contains(bb.start)) {
            std::string label = session_->name_at(bb.start);
            if (label.empty()) label = std::format("loc_{:x}", bb.start);
            block.lines << QStringLiteral(" %1:").arg(QString::fromStdString(label));
            block.line_addrs.push_back(bb.start);
        }
        for (const auto& insn : bb.instructions) {
            QString line;
            if (listing != disasm_cache_.end()) {
                if (const auto found = listing->second.graph_lines.find(insn.address);
                    found != listing->second.graph_lines.end()) line = found->second;
            }
            if (line.isEmpty()) line = QStringLiteral("  ") + QString::fromStdString(format_instruction(insn));
            block.lines << line;
            block.line_addrs.push_back(insn.address);
        }
        blocks.push_back(std::move(block));
    }
    std::vector<GraphView::Edge> edges;
    for (std::size_t i = 0; i < cfg->blocks.size(); ++i) {
        const auto& bb = cfg->blocks[i];
        const bool conditional = bb.kind == BlockKind::Conditional && bb.successors.size() >= 2;
        for (std::size_t k = 0; k < bb.successors.size(); ++k) {
            const auto to = cfg->block_at.find(bb.successors[k]);
            if (to == cfg->block_at.end()) continue;   // tail call into another function
            GraphView::EdgeKind kind = GraphView::EdgeKind::Always;
            if (conditional) kind = k == 0 ? GraphView::EdgeKind::Taken : GraphView::EdgeKind::NotTaken;
            edges.push_back({i, to->second, kind});
        }
    }
    const auto entry = cfg->block_at.find(fn.addr);
    g->set_graph(blocks, edges, entry != cfg->block_at.end() ? entry->second : 0);
}

void MainWindow::toggle_graph() {
    if (!session_ || !current_fn_) return;
    if (graph_ && tabs_->currentWidget() == graph_) {
        const auto va = graph_->current_line_address();
        CodeView* d = ensure_disassembly_tab();
        tabs_->setCurrentWidget(d);
        if (va) d->go_to_address(*va);
        d->setFocus();
        return;
    }
    std::optional<addr_t> va;
    if (const auto at = cursor()) va = at->address;
    const DiscoveredFunction* fn = session_->function_at(*current_fn_);
    if (!fn) return;
    GraphView* g = ensure_graph_tab();
    if (graph_fn_ != fn->addr) render_graph(*fn);
    tabs_->setCurrentWidget(g);
    g->go_to_address(va ? *va : fn->addr);
    g->setFocus();
}

void MainWindow::open_graph_for_test(bool fit) {
    toggle_graph();
    if (fit && graph_) graph_->fit_to_window();
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
    if (w == graph_) {
        graph_ = nullptr;
        graph_fn_.reset();
    }
    w->deleteLater();
}

// ---------------------------------------------------------------------------
// IDA commands
// ---------------------------------------------------------------------------

CodeView* MainWindow::current_code_view() const {
    return qobject_cast<CodeView*>(tabs_->currentWidget());
}

std::optional<MainWindow::Cursor> MainWindow::cursor() const {
    if (const CodeView* view = current_code_view())
        return Cursor{view->kind() == CodeView::Kind::Pseudocode, view->current_token(),
                      view->current_line_address()};
    if (graph_ && tabs_->currentWidget() == graph_)
        return Cursor{false, graph_->current_token(), graph_->current_line_address()};
    return std::nullopt;
}

QString MainWindow::instruction_text(addr_t pc) {
    const DiscoveredFunction* f = session_->function_at(pc);
    const std::string* raw = f ? raw_disassembly(f->addr) : nullptr;
    if (!raw) return {};
    for (std::string_view line : split_lines(*raw)) {
        const auto insn = parse_raw_insn(line);
        if (!insn || insn->addr != pc) continue;
        return QStringLiteral("%1 %2")
            .arg(QString::fromUtf8(insn->mnemonic.data(), static_cast<qsizetype>(insn->mnemonic.size())),
                 QString::fromUtf8(insn->operands.data(), static_cast<qsizetype>(insn->operands.size())))
            .trimmed();
    }
    return {};
}

std::optional<addr_t> MainWindow::resolve_token(const QString& token) const {
    if (!session_ || token.isEmpty()) return std::nullopt;
    const std::string name = token.toStdString();
    for (const auto& [va, renamed] : session_->annotations.renames)
        if (renamed == name) return va;
    for (const auto& f : session_->functions)
        if (f.name == name || display_name(f.name) == name) return f.addr;
    // Dummy names carry their address: sub_401000, loc_401010, unk_...
    static const QRegularExpression dummy(
        QStringLiteral(R"(^(?:sub|loc|locret|unk|byte|word|dword|qword|off|str|asc|stru|j)_([0-9A-Fa-f]+)$)"));
    if (const auto m = dummy.match(token); m.hasMatch()) {
        bool ok = false;
        const addr_t va = m.captured(1).toULongLong(&ok, 16);
        if (ok) return va;
    }
    if (token.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)) {
        bool ok = false;
        const addr_t va = token.mid(2).toULongLong(&ok, 16);
        if (ok && session_->section_at(va)) return va;
    }
    for (const auto& sym : session_->binary->symbols())
        if (sym.addr != 0 && (sym.name == name || display_name(sym.name) == name)) return sym.addr;
    return std::nullopt;
}

void MainWindow::rename_at_cursor() {
    const auto at = cursor();
    if (!session_ || !at) return;
    std::optional<addr_t> target = resolve_token(at->token);
    if (!target) {
        // In pseudocode a name with no address is the function's own:
        // a local, a parameter or a temporary.
        if (at->pseudocode && !at->token.isEmpty()) {
            rename_local(at->token);
            return;
        }
        // IDA names the address of the current line.
        target = at->address;
    }
    if (!target) return;
    const std::string current = session_->name_at(*target);
    bool ok = false;
    QString name = QInputDialog::getText(
        this, QStringLiteral("Rename address"),
        QStringLiteral("Please enter a name for %1\n(empty restores the default name)").arg(hex(*target)),
        QLineEdit::Normal, QString::fromStdString(current), &ok).trimmed();
    if (!ok) return;
    static const QRegularExpression valid(QStringLiteral(R"(^[A-Za-z_$?@.][\w$?@.:]*$)"));
    if (!name.isEmpty() && !valid.match(name).hasMatch()) {
        QMessageBox::warning(this, QStringLiteral("Rename address"),
                             QStringLiteral("'%1' is not a valid name.").arg(name));
        return;
    }
    if (!name.isEmpty()) {
        if (auto other = resolve_token(name); other && *other != *target) {
            QMessageBox::warning(this, QStringLiteral("Rename address"),
                                 QStringLiteral("The name '%1' is already used at %2.").arg(name, hex(*other)));
            return;
        }
    }
    session_->rename(*target, name.toStdString());
    log(name.isEmpty() ? QStringLiteral("%1: name removed.").arg(hex(*target))
                       : QStringLiteral("%1: renamed to %2.").arg(hex(*target), name));
    save_database();
    refresh_views(true);
}

void MainWindow::rename_local(const QString& shown) {
    if (!current_fn_) return;
    const auto rendered = pseudo_cache_.find(*current_fn_);
    if (rendered == pseudo_cache_.end()) return;
    static const QRegularExpression identifier(QStringLiteral(R"(^[A-Za-z_]\w*$)"));
    static const QStringList kReserved = {
        QStringLiteral("if"), QStringLiteral("else"), QStringLiteral("while"), QStringLiteral("for"),
        QStringLiteral("do"), QStringLiteral("return"), QStringLiteral("switch"), QStringLiteral("case"),
        QStringLiteral("default"), QStringLiteral("break"), QStringLiteral("continue"),
        QStringLiteral("goto"), QStringLiteral("sizeof"), QStringLiteral("struct"),
        QStringLiteral("union"), QStringLiteral("enum"), QStringLiteral("const"),
        QStringLiteral("static"), QStringLiteral("void"), QStringLiteral("char"),
        QStringLiteral("short"), QStringLiteral("int"), QStringLiteral("long"),
        QStringLiteral("unsigned"), QStringLiteral("signed"), QStringLiteral("float"),
        QStringLiteral("double"), QStringLiteral("bool"), QStringLiteral("true"),
        QStringLiteral("false"), QStringLiteral("NULL"),
    };
    const QString& text = rendered->second.text;
    const auto usable = [&](const QString& name) {
        if (!identifier.match(name).hasMatch() || kReserved.contains(name) || name.endsWith(QStringLiteral("_t")) ||
            name.startsWith(QStringLiteral("__"))) return false;
        // Call targets without an address (helpers, intrinsics) are not variables.
        const QRegularExpression call(QStringLiteral(R"(\b%1\s*\()").arg(QRegularExpression::escape(name)));
        return !text.contains(call);
    };
    if (!usable(shown)) {
        log(QStringLiteral("'%1' is not a variable of this function.").arg(shown));
        return;
    }
    const std::string emitted = session_->emitted_local(*current_fn_, shown.toStdString());
    bool ok = false;
    const QString name = QInputDialog::getText(
        this, QStringLiteral("Rename local variable"),
        QStringLiteral("Please enter a new name for %1\n(empty restores %2)")
            .arg(shown, QString::fromStdString(emitted)),
        QLineEdit::Normal, shown, &ok).trimmed();
    if (!ok || name == shown) return;
    if (!name.isEmpty()) {
        if (!usable(name)) {
            QMessageBox::warning(this, QStringLiteral("Rename local variable"),
                                 QStringLiteral("'%1' is not a valid variable name.").arg(name));
            return;
        }
        const QRegularExpression word(QStringLiteral(R"(\b%1\b)").arg(QRegularExpression::escape(name)));
        if (name.toStdString() != emitted && text.contains(word)) {
            QMessageBox::warning(this, QStringLiteral("Rename local variable"),
                                 QStringLiteral("The name '%1' is already used in this function.").arg(name));
            return;
        }
    }
    session_->rename_local(*current_fn_, emitted, name.toStdString());
    log(name.isEmpty() ? QStringLiteral("%1: restored.").arg(QString::fromStdString(emitted))
                       : QStringLiteral("%1: renamed to %2.").arg(shown, name));
    save_database();
    refresh_views(true);
}

void MainWindow::comment_at_cursor() {
    const auto at = cursor();
    if (!session_ || !at) return;
    const auto va = at->address;
    if (!va) return;
    auto& notes = session_->annotations.notes;
    const auto it = notes.find(*va);
    bool ok = false;
    const QString text = QInputDialog::getMultiLineText(
        this, QStringLiteral("Comment"), QStringLiteral("Comment at %1").arg(hex(*va)),
        it == notes.end() ? QString() : QString::fromStdString(it->second), &ok).trimmed();
    if (!ok) return;
    if (text.isEmpty()) notes.erase(*va);
    else notes[*va] = QString(text).replace(QLatin1Char('\n'), QLatin1Char(' ')).toStdString();
    save_database();
    refresh_views(false);
}

void MainWindow::show_xrefs(bool current_item) {
    const auto at = cursor();
    if (!session_) return;
    std::optional<addr_t> target;
    if (at && !current_item) target = resolve_token(at->token);
    if (!target && current_fn_) target = current_fn_;
    if (!target) return;
    if (!session_->xrefs_ready) {
        log(QStringLiteral("Cross-references are still being computed."));
        return;
    }

    auto* model = new QStandardItemModel(this);
    model->setHorizontalHeaderLabels({QStringLiteral("Address"), QStringLiteral("Direction"),
                                      QStringLiteral("Type"), QStringLiteral("Text")});
    const auto where = [&](addr_t va) {
        const DiscoveredFunction* f = session_->function_at(va);
        if (!f) return hex(va);
        QString text = QString::fromStdString(session_->name_at(f->addr));
        if (va != f->addr) text += QStringLiteral("+%1").arg(va - f->addr, 0, 16).toUpper();
        return text;
    };
    const auto add = [&](addr_t from, const QString& type, const QString& text) {
        model->appendRow({addr_item(from, where(from)),
                          text_item(from < *target ? QStringLiteral("Up") : QStringLiteral("Down")),
                          text_item(type), text_item(text)});
    };

    // Code references: scan each caller for the instructions that reach
    // the target, since the call graph records only the calling function.
    std::set<addr_t> scanned;
    std::vector<addr_t> sources(session_->callers_of(*target).begin(), session_->callers_of(*target).end());
    if (const auto* own = session_->function_at(*target)) sources.push_back(own->addr);
    for (addr_t fn : sources) {
        if (!scanned.insert(fn).second) continue;
        const std::string* raw = raw_disassembly(fn);
        bool found = false;
        if (raw) {
            for (std::string_view line : split_lines(*raw)) {
                auto insn = parse_raw_insn(line);
                if (!insn || branch_target(*insn) != target) continue;
                found = true;
                add(insn->addr, insn->mnemonic == "call" ? QStringLiteral("p") : QStringLiteral("j"),
                    QStringLiteral("%1 %2").arg(QString::fromUtf8(insn->mnemonic.data(),
                                                                  static_cast<qsizetype>(insn->mnemonic.size())),
                                                QString::fromStdString(session_->name_at(*target))));
            }
        }
        if (!found && fn != session_->function_at(*target)->addr) add(fn, QStringLiteral("p"), {});
    }
    // Reads, writes and address-taking (IDA's r / w / o).
    if (const auto refs = session_->data_refs.find(*target); refs != session_->data_refs.end()) {
        for (const DataXref& ref : refs->second) {
            const QString type = ref.kind == DataXrefKind::Read    ? QStringLiteral("r")
                               : ref.kind == DataXrefKind::Write   ? QStringLiteral("w")
                                                                   : QStringLiteral("o");
            add(ref.from_pc, type, instruction_text(ref.from_pc));
        }
    }
    // Data references to strings, from the string scan's xref lists.
    if (session_->strings) {
        for (const auto& str : *session_->strings) {
            if (str.addr != *target) continue;
            for (addr_t from : str.xrefs)
                add(from, QStringLiteral("o"), QStringLiteral("\"%1\"").arg(QString::fromStdString(str.text)));
        }
    }
    if (model->rowCount() == 0) {
        log(QStringLiteral("There are no xrefs to %1.").arg(where(*target)));
        delete model;
        return;
    }
    Chooser chooser(QStringLiteral("xrefs to %1").arg(where(*target)), model, this);
    if (auto va = chooser.choose()) jump_to_or_hex(*va);
}

void MainWindow::choose_function() {
    if (!session_) return;
    auto* model = new QStandardItemModel(this);
    model->setHorizontalHeaderLabels({QStringLiteral("Function name"), QStringLiteral("Segment"),
                                      QStringLiteral("Start"), QStringLiteral("Length")});
    for (const auto& f : session_->functions) {
        model->appendRow({addr_item(f.addr, QString::fromStdString(display_name(f.name))),
                          text_item(QString::fromStdString(session_->segment_name(f.addr))),
                          text_item(hex16(f.addr).toUpper()),
                          text_item(QStringLiteral("%1").arg(f.size, 8, 16, QChar('0')).toUpper())});
    }
    Chooser chooser(QStringLiteral("Choose function to jump to"), model, this);
    if (current_fn_) chooser.select_address(*current_fn_);
    if (auto va = chooser.choose()) jump_to(*va);
}

QStandardItemModel* MainWindow::names_model() {
    auto* model = new QStandardItemModel(this);
    model->setHorizontalHeaderLabels({QStringLiteral("Name"), QStringLiteral("Address"),
                                      QStringLiteral("Public")});
    std::set<addr_t> seen;
    for (const auto& f : session_->functions) {
        seen.insert(f.addr);
        model->appendRow({addr_item(f.addr, QString::fromStdString(session_->name_at(f.addr))),
                          text_item(QString::fromStdString(session_->segment_name(f.addr)) +
                                    QLatin1Char(':') + hex16(f.addr).toUpper()),
                          text_item({})});
    }
    for (const auto& sym : session_->binary->symbols()) {
        if (sym.addr == 0 || sym.is_import || !seen.insert(sym.addr).second) continue;
        model->appendRow({addr_item(sym.addr, QString::fromStdString(display_name(sym.name))),
                          text_item(QString::fromStdString(session_->segment_name(sym.addr)) +
                                    QLatin1Char(':') + hex16(sym.addr).toUpper()),
                          text_item(sym.is_export ? QStringLiteral("P") : QString())});
    }
    return model;
}

void MainWindow::choose_name() {
    if (!session_) return;
    Chooser chooser(QStringLiteral("Jump by name"), names_model(), this);
    if (current_fn_) chooser.select_address(*current_fn_);
    if (auto va = chooser.choose()) jump_to_or_hex(*va);
}

void MainWindow::open_names() {
    if (!session_) return;
    open_table_tab(QStringLiteral("Names"), names_model());
}

void MainWindow::mark_position() {
    CodeView* view = current_code_view();
    if (!session_ || !view) return;
    const auto va = view->current_line_address();
    if (!va) return;
    bool ok = false;
    const QString desc = QInputDialog::getText(
        this, QStringLiteral("Mark position"), QStringLiteral("Enter mark description"),
        QLineEdit::Normal, QString::fromStdString(session_->name_at(*va)).isEmpty()
                               ? hex(*va) : QString::fromStdString(session_->name_at(*va)), &ok);
    if (!ok) return;
    std::erase_if(marks_, [&](const auto& m) { return m.first == *va; });
    marks_.emplace_back(*va, desc);
    log(QStringLiteral("Marked %1: %2").arg(hex(*va), desc));
}

void MainWindow::choose_mark() {
    if (!session_) return;
    if (marks_.empty()) {
        log(QStringLiteral("No marked positions. Alt+M marks the current line."));
        return;
    }
    auto* model = new QStandardItemModel(this);
    model->setHorizontalHeaderLabels({QStringLiteral("Address"), QStringLiteral("Description")});
    for (const auto& [va, desc] : marks_)
        model->appendRow({addr_item(va, QString::fromStdString(session_->segment_name(va)) +
                                            QLatin1Char(':') + hex16(va).toUpper()),
                          text_item(desc)});
    Chooser chooser(QStringLiteral("Select a marked position"), model, this);
    if (auto va = chooser.choose()) jump_to_or_hex(*va);
}

void MainWindow::toggle_view() {
    if (!session_) return;
    QWidget* cur = tabs_->currentWidget();
    if (cur == pseudo_ && pseudo_) {
        const auto va = pseudo_->current_line_address();
        CodeView* d = ensure_disassembly_tab();
        tabs_->setCurrentWidget(d);
        if (va) d->go_to_address(*va);
        d->setFocus();
        return;
    }
    open_pseudocode();
}

void MainWindow::toggle_number() {
    const auto at = cursor();
    if (!session_ || !at) return;
    const QString tok = at->token;
    const auto va = at->address;
    if (tok.isEmpty() || !va) return;
    auto& toggles = number_toggles_[*va];
    // Toggling a shown replacement restores the original literal.
    for (auto it = toggles.begin(); it != toggles.end(); ++it) {
        if (it->second == tok) {
            toggles.erase(it);
            refresh_views(false);
            return;
        }
    }
    bool ok = false;
    QString replacement;
    if (tok.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)) {
        const qulonglong v = tok.mid(2).toULongLong(&ok, 16);
        if (ok) replacement = QString::number(v);
    } else {
        const qulonglong v = tok.toULongLong(&ok, 10);
        if (ok) replacement = QStringLiteral("0x%1").arg(v, 0, 16);
    }
    if (replacement.isEmpty()) return;
    toggles[tok] = replacement;
    refresh_views(false);
}

void MainWindow::apply_number_toggles(QString& text, addr_t va) const {
    const auto it = number_toggles_.find(va);
    if (it == number_toggles_.end()) return;
    for (const auto& [from, to] : it->second) {
        const QRegularExpression word(QStringLiteral(R"((?<![\w$@]))") +
                                      QRegularExpression::escape(from) +
                                      QStringLiteral(R"((?![\w$@]))"));
        text.replace(word, to);
    }
}

MainWindow::Rendered MainWindow::decorate_pseudocode(const Rendered& raw) const {
    if (!session_) return raw;
    const auto& notes = session_->annotations.notes;
    if (notes.empty() && number_toggles_.empty()) return raw;
    QStringList lines = raw.text.split(QLatin1Char('\n'));
    std::set<addr_t> commented;
    for (qsizetype i = 0; i < lines.size() && static_cast<std::size_t>(i) < raw.lines.size(); ++i) {
        const addr_t va = raw.lines[static_cast<std::size_t>(i)];
        if (va == 0) continue;
        apply_number_toggles(lines[i], va);
        if (auto note = notes.find(va); note != notes.end() && commented.insert(va).second)
            lines[i] += QStringLiteral(" // ") + QString::fromStdString(note->second);
    }
    return Rendered{lines.join(QLatin1Char('\n')), raw.lines, {}};
}

void MainWindow::refresh_views(bool names_changed) {
    if (!session_) return;
    disasm_cache_.clear();
    if (names_changed) {
        pseudo_cache_.clear();
        const int row = fn_table_->currentIndex().row();
        fn_model_->set_session(session_.get());
        if (row >= 0) fn_table_->selectRow(row);
    }
    const auto keep = [](CodeView* view, const std::function<void()>& rerender) {
        const int  scroll = view->verticalScrollBar()->value();
        const int  line   = view->textCursor().blockNumber();
        const int  column = view->textCursor().positionInBlock();
        rerender();
        QTextCursor c(view->document()->findBlockByNumber(line));
        c.movePosition(QTextCursor::Right, QTextCursor::MoveAnchor,
                       std::min(column, c.block().length() - 1));
        view->setTextCursor(c);
        view->verticalScrollBar()->setValue(scroll);
    };
    const DiscoveredFunction* fn = current_fn_ ? session_->function_at(*current_fn_) : nullptr;
    auto win = fn ? session_->window_for(*fn) : std::nullopt;
    if (disasm_ && win) {
        keep(disasm_, [&] {
            auto& r = disasm_cache_.emplace(fn->addr, render_disassembly(*win)).first->second;
            disasm_->set_content(r.text, r.lines);
        });
    }
    if (pseudo_ && win) {
        if (auto cached = pseudo_cache_.find(win->start); cached != pseudo_cache_.end()) {
            keep(pseudo_, [&] {
                const Rendered shown = decorate_pseudocode(cached->second);
                pseudo_->set_content(shown.text, shown.lines);
            });
        } else {
            request_pseudocode(*win);
        }
    }
    if (graph_ && fn && graph_fn_ == fn->addr) {
        const auto va = graph_->current_line_address();
        const QTransform zoom = graph_->transform();
        const int h = graph_->horizontalScrollBar()->value();
        const int v = graph_->verticalScrollBar()->value();
        render_graph(*fn);
        graph_->setTransform(zoom);
        if (va) graph_->go_to_address(*va, /*center=*/false);
        graph_->horizontalScrollBar()->setValue(h);
        graph_->verticalScrollBar()->setValue(v);
    }
    if (current_fn_) update_chrome(disasm_ && disasm_->current_line_address()
                                       ? *disasm_->current_line_address() : *current_fn_);
}

void MainWindow::search_text(bool prompt) {
    CodeView* view = current_code_view();
    if (!session_ || !view) return;
    if (prompt || last_text_search_.isEmpty()) {
        bool ok = false;
        const QString text = QInputDialog::getText(this, QStringLiteral("Text search"),
                                                   QStringLiteral("String"), QLineEdit::Normal,
                                                   last_text_search_, &ok);
        if (!ok || text.isEmpty()) return;
        last_text_search_ = text;
    }
    if (!view->find_next(last_text_search_))
        log(QStringLiteral("Search failed: '%1' not found below the cursor in this view.").arg(last_text_search_));
}

void MainWindow::search_bytes(bool prompt) {
    if (!session_) return;
    if (prompt || last_byte_search_.empty()) {
        bool ok = false;
        const QString text = QInputDialog::getText(
            this, QStringLiteral("Binary search"),
            QStringLiteral("Hex bytes (?? = any) or a \"quoted string\""), QLineEdit::Normal, {}, &ok).trimmed();
        if (!ok || text.isEmpty()) return;
        std::vector<int> pattern;
        if (text.size() >= 2 && text.startsWith(QLatin1Char('"')) && text.endsWith(QLatin1Char('"'))) {
            for (char c : text.mid(1, text.size() - 2).toStdString()) pattern.push_back(static_cast<unsigned char>(c));
        } else {
            for (const QString& part : text.split(QLatin1Char(' '), Qt::SkipEmptyParts)) {
                if (part == QStringLiteral("??") || part == QStringLiteral("?")) { pattern.push_back(-1); continue; }
                bool byte_ok = false;
                const uint v = part.toUInt(&byte_ok, 16);
                if (!byte_ok || v > 0xff) {
                    log(QStringLiteral("Binary search: '%1' is not a byte.").arg(part));
                    return;
                }
                pattern.push_back(static_cast<int>(v));
            }
        }
        if (pattern.empty()) return;
        last_byte_search_ = std::move(pattern);
    }
    std::optional<addr_t> here;
    if (CodeView* view = current_code_view()) here = view->current_line_address();
    if (!here && current_fn_) here = current_fn_;
    const addr_t from = here ? *here + 1 : 0;

    const auto& pat = last_byte_search_;
    std::optional<addr_t> best_after, best_wrapped;
    for (const auto& sec : session_->binary->sections()) {
        const auto& bytes = sec.data;
        if (bytes.size() < pat.size()) continue;
        for (std::size_t i = 0; i + pat.size() <= bytes.size(); ++i) {
            bool hit = true;
            for (std::size_t k = 0; k < pat.size() && hit; ++k)
                hit = pat[k] < 0 || static_cast<int>(static_cast<unsigned char>(bytes[i + k])) == pat[k];
            if (!hit) continue;
            const addr_t va = sec.vaddr + i;
            if (va >= from) {
                if (!best_after || va < *best_after) best_after = va;
                break;
            }
            if (!best_wrapped) best_wrapped = va;
        }
    }
    const auto found = best_after ? best_after : best_wrapped;
    if (!found) {
        log(QStringLiteral("Binary search failed: pattern not found."));
        return;
    }
    if (!best_after) log(QStringLiteral("Binary search wrapped to the start."));
    jump_to_or_hex(*found);
}

void MainWindow::save_database() {
    if (!session_) return;
    if (auto r = session_->save_annotations(); !r) {
        log(QStringLiteral("Could not save annotations: %1").arg(QString::fromStdString(r.error().message)));
        return;
    }
    log(QStringLiteral("Saved annotations to %1.").arg(QString::fromStdString(session_->annotations_path.string())));
}

void MainWindow::focus_filter() {
    QWidget* page = tabs_->currentWidget();
    if (auto* filter = page ? page->findChild<QLineEdit*>(QStringLiteral("quickFilter")) : nullptr) {
        filter->show();
        filter->setFocus();
        filter->selectAll();
        return;
    }
    fn_dock_->show();
    fn_dock_->raise();
    fn_filter_->setFocus();
    fn_filter_->selectAll();
}

}  // namespace spelunk::gui
