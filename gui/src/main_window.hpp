#pragma once

#include <QMainWindow>
#include <QString>
#include <functional>
#include <memory>
#include <optional>
#include <unordered_map>
#include <vector>

#include <spelunk/common/types.hpp>

class QAction;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QSortFilterProxyModel;
class QStandardItemModel;
class QTabWidget;
class QTableView;
class QThread;

namespace spelunk {
struct FuncWindow;
struct DiscoveredFunction;
}  // namespace spelunk

namespace spelunk::gui {

struct Session;
class CodeView;
class FunctionModel;
class HexView;
class NavBand;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

    void open_path(const QString& path);

    // Test hook for --screenshot --pseudocode; same as pressing F5.
    void open_pseudocode_for_test() { open_pseudocode(); }
    // Test hook for --screenshot --hex; same as pressing H.
    void open_hex_for_test() { open_hex(); }

signals:
    // Fired once the file is loaded and the first view is showing.
    void session_ready();
    // Fired when the background cross-reference pass has landed.
    void analysis_finished();

private:
    struct Rendered {
        QString             text;
        std::vector<addr_t> lines;   // one entry per document line, 0 = none
    };

    // construction
    void build_actions();
    void build_menus();
    void build_toolbars();
    void build_docks();
    void build_central();

    // session lifecycle
    void prompt_open();
    void on_session_loaded(std::shared_ptr<Session> s, const QString& error);
    void start_xref_analysis();
    void on_xrefs_ready(const std::shared_ptr<Session>& s,
                        std::shared_ptr<std::unordered_map<addr_t, std::vector<addr_t>>> callers,
                        std::size_t edges, qint64 ms);
    void close_session();
    void log(const QString& line);

    // Runs `work` on a fresh QThread. Threads are tracked so the window
    // can join them before it is destroyed; results come back through
    // QMetaObject::invokeMethod on this object.
    void spawn(std::function<void()> work);

    // navigation
    void jump_to(addr_t va, bool record = true);
    void jump_to_or_hex(addr_t va, bool record = true);
    void jump_to_token(const QString& token);
    void jump_back();
    void jump_forward();
    void prompt_jump_address();
    void prompt_jump_function();
    void jump_to_entry();
    void push_history(addr_t va);
    void update_history_actions();
    void sync_chrome(addr_t va);
    void update_chrome(addr_t va);

    // views
    void     show_function(const DiscoveredFunction& fn);
    Rendered render_disassembly(const FuncWindow& w);
    Rendered render_pseudocode(const FuncWindow& w);
    CodeView* ensure_disassembly_tab();
    CodeView* ensure_pseudocode_tab();
    HexView* ensure_hex_tab();
    void      open_pseudocode();
    void      open_hex();
    void      open_strings();
    void      open_imports();
    void      open_exports();
    void      open_segments();
    void      open_table_tab(const QString& title, QStandardItemModel* model);
    void      on_tab_close(int index);

    std::shared_ptr<Session> session_;
    std::vector<QThread*>    workers_;
    bool                     loading_ = false;

    std::unordered_map<addr_t, Rendered> disasm_cache_;
    std::unordered_map<addr_t, Rendered> pseudo_cache_;
    std::optional<addr_t>                current_fn_;
    std::vector<addr_t>                  history_;
    std::size_t                          history_pos_ = 0;

    // widgets
    QTabWidget*            tabs_      = nullptr;
    CodeView*              disasm_    = nullptr;
    CodeView*              pseudo_    = nullptr;
    HexView*               hex_       = nullptr;
    FunctionModel*         fn_model_  = nullptr;
    QSortFilterProxyModel* fn_proxy_  = nullptr;
    QTableView*            fn_table_  = nullptr;
    QLineEdit*             fn_filter_ = nullptr;
    QPlainTextEdit*        output_    = nullptr;
    QLineEdit*             cmdline_   = nullptr;
    NavBand*               band_      = nullptr;
    QLabel*                au_label_  = nullptr;
    QLabel*                addr_label_ = nullptr;
    QDockWidget*           fn_dock_   = nullptr;
    QDockWidget*           out_dock_  = nullptr;

    // actions
    QAction* act_open_      = nullptr;
    QAction* act_quit_      = nullptr;
    QAction* act_back_      = nullptr;
    QAction* act_forward_   = nullptr;
    QAction* act_jump_addr_ = nullptr;
    QAction* act_jump_fn_   = nullptr;
    QAction* act_jump_entry_ = nullptr;
    QAction* act_pseudo_    = nullptr;
    QAction* act_disasm_    = nullptr;
    QAction* act_hex_       = nullptr;
    QAction* act_strings_   = nullptr;
    QAction* act_imports_   = nullptr;
    QAction* act_exports_   = nullptr;
    QAction* act_segments_  = nullptr;
    QAction* act_about_     = nullptr;
};

}  // namespace spelunk::gui
