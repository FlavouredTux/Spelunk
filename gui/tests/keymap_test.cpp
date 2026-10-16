// Drives the main window with real key presses, offscreen, and checks the
// IDA keymap does what an IDA user expects. Annotations go to a scratch
// XDG cache so the user's own database is never touched.
#include <QApplication>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QInputDialog>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QSignalSpy>
#include <QTabWidget>
#include <QTableView>
#include <QTemporaryDir>
#include <QTest>
#include <QTextBlock>
#include <QTimer>

#include <cstdio>
#include <functional>

#include "../src/chooser.hpp"
#include "../src/code_view.hpp"
#include "../src/main_window.hpp"

using spelunk::gui::Chooser;
using spelunk::gui::CodeView;
using spelunk::gui::MainWindow;

namespace {

int failures = 0;

void check(bool ok, const char* what) {
    std::fprintf(stderr, "%s %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++failures;
}

// Answers the next modal dialog once it is up.
void on_next_modal(std::function<void(QWidget*)> answer) {
    auto* timer = new QTimer;
    timer->setInterval(20);
    QObject::connect(timer, &QTimer::timeout, [timer, answer] {
        if (QWidget* modal = QApplication::activeModalWidget()) {
            timer->stop();
            timer->deleteLater();
            answer(modal);
        }
    });
    timer->start();
}

void answer_text(const QString& text) {
    on_next_modal([text](QWidget* w) {
        if (auto* dialog = qobject_cast<QInputDialog*>(w)) {
            dialog->setTextValue(text);
            dialog->accept();
        }
    });
}

QTabWidget* tabs(MainWindow& w) { return w.findChild<QTabWidget*>(); }

CodeView* tab_view(MainWindow& w, const QString& title) {
    QTabWidget* t = tabs(w);
    for (int i = 0; i < t->count(); ++i)
        if (t->tabText(i) == title) return qobject_cast<CodeView*>(t->widget(i));
    return nullptr;
}

QString current_title(MainWindow& w) { return tabs(w)->tabText(tabs(w)->currentIndex()); }

// What a click on the view does for a user: activate the window, focus it.
void press(QWidget* view, Qt::Key key, Qt::KeyboardModifiers mods = Qt::NoModifier) {
    QWidget* top = view->window();
    top->activateWindow();
    (void)QTest::qWaitForWindowActive(top, 2000);
    view->setFocus();
    QTest::keyClick(view, key, mods);
}

// Put the cursor on the first occurrence of `needle` in a line matching `line_has`.
bool place_cursor(CodeView* view, const QString& line_has, const QString& needle) {
    for (QTextBlock b = view->document()->begin(); b.isValid(); b = b.next()) {
        if (!b.text().contains(line_has)) continue;
        const auto at = b.text().indexOf(needle);
        if (at < 0) continue;
        QTextCursor c(b);
        c.setPosition(b.position() + static_cast<int>(at) + 1);
        view->setTextCursor(c);
        view->setFocus();
        return true;
    }
    return false;
}

QString line_with(CodeView* view, const QString& needle) {
    for (QTextBlock b = view->document()->begin(); b.isValid(); b = b.next())
        if (b.text().contains(needle)) return b.text();
    return {};
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    QTemporaryDir cache;
    qputenv("XDG_CACHE_HOME", cache.path().toUtf8());
    qputenv("QT_QPA_PLATFORM", "offscreen");
    QApplication app(argc, argv);

    MainWindow window;
    window.show();
    window.activateWindow();
    QSignalSpy analysed(&window, &MainWindow::analysis_finished);
    window.open_path(QString::fromLocal8Bit(argv[1]));
    check(analysed.wait(30000), "binary loads and autoanalysis finishes");
    CodeView* disasm = tab_view(window, QStringLiteral("Spelunk View-A"));
    check(disasm != nullptr, "disassembly view opens");
    if (!disasm) return 1;

    // Ctrl+P: function chooser, filter by typing, Enter jumps.
    on_next_modal([](QWidget* w) {
        auto* chooser = qobject_cast<Chooser*>(w);
        if (!chooser) return;
        auto* filter = chooser->findChild<QLineEdit*>();
        filter->setText(QStringLiteral("sum_and"));
        QTest::keyClick(filter, Qt::Key_Return);
    });
    press(disasm, Qt::Key_P, Qt::ControlModifier);
    check(line_with(disasm, QStringLiteral("proc near")).contains(QStringLiteral("sum_and_report")),
          "Ctrl+P jumps to the chosen function");

    // IDA listing shape.
    check(!line_with(disasm, QStringLiteral("endp")).isEmpty(), "listing ends with endp");
    check(!line_with(disasm, QStringLiteral("call    printf")).isEmpty(), "call targets are named");

    // Tab flips to pseudocode and back.
    QSignalSpy pseudo_ready(&window, &MainWindow::pseudocode_ready);
    disasm->setFocus();
    press(disasm, Qt::Key_Tab);
    check(current_title(window) == QStringLiteral("Pseudocode-A"), "Tab opens pseudocode");
    check(pseudo_ready.count() > 0 || pseudo_ready.wait(30000), "pseudocode renders");
    CodeView* pseudo = tab_view(window, QStringLiteral("Pseudocode-A"));
    press(pseudo, Qt::Key_Tab);
    check(current_title(window) == QStringLiteral("Spelunk View-A"), "Tab returns to disassembly");

    // N renames the name under the cursor and persists it.
    check(place_cursor(disasm, QStringLiteral("proc near"), QStringLiteral("sum_and_report")),
          "cursor on function name");
    answer_text(QStringLiteral("walk_list"));
    press(disasm, Qt::Key_N);
    check(line_with(disasm, QStringLiteral("proc near")).contains(QStringLiteral("walk_list")),
          "N renames the function in the listing");
    bool saved = false;
    {
        QDirIterator it(cache.path(), QDir::Files, QDirIterator::Subdirectories);
        while (it.hasNext()) {
            QFile file(it.next());
            if (file.open(QIODevice::ReadOnly) && file.readAll().contains("walk_list")) saved = true;
        }
    }
    check(saved, "rename is saved to the annotation database");

    // ; adds a comment on the current line.
    check(place_cursor(disasm, QStringLiteral("add     "), QStringLiteral("add")), "cursor on an instruction");
    on_next_modal([](QWidget* w) {
        if (auto* dialog = qobject_cast<QInputDialog*>(w)) {
            dialog->setTextValue(QStringLiteral("sum the keys"));
            dialog->accept();
        }
    });
    press(disasm, Qt::Key_Semicolon);
    check(line_with(disasm, QStringLiteral("add     ")).contains(QStringLiteral("; sum the keys")),
          "; comments the current line");

    // H flips a literal between hex and decimal.
    const QString hex_line = line_with(disasm, QStringLiteral("0x"));
    const auto hex_at = hex_line.indexOf(QStringLiteral("0x"));
    QString literal;
    for (auto i = hex_at; i < hex_line.size() && (hex_line[i].isLetterOrNumber()); ++i) literal += hex_line[i];
    check(!literal.isEmpty() && place_cursor(disasm, hex_line, literal), "cursor on a hex literal");
    press(disasm, Qt::Key_H);
    bool ok = false;
    const QString decimal = QString::number(literal.mid(2).toULongLong(&ok, 16));
    const QString address = hex_line.section(QLatin1Char(' '), 0, 0);
    const QString after = line_with(disasm, address + QLatin1Char(' '));
    check(ok && after.contains(decimal) && !after.contains(literal), "H shows the literal in decimal");
    place_cursor(disasm, address + QLatin1Char(' '), decimal);
    press(disasm, Qt::Key_H);
    check(line_with(disasm, address + QLatin1Char(' ')).contains(literal), "H again restores hex");

    // X lists the callers of the name under the cursor.
    int xref_rows = -1;
    on_next_modal([&xref_rows](QWidget* w) {
        if (auto* chooser = qobject_cast<Chooser*>(w)) {
            xref_rows = chooser->findChild<QTableView*>()->model()->rowCount();
            chooser->reject();
        }
    });
    place_cursor(disasm, QStringLiteral("proc near"), QStringLiteral("walk_list"));
    press(disasm, Qt::Key_X);
    check(xref_rows > 0, "X lists xrefs to the function");

    // G jumps by name; Esc comes back.
    answer_text(QStringLiteral("main"));
    press(disasm, Qt::Key_G);
    check(line_with(disasm, QStringLiteral("proc near")).contains(QStringLiteral("main")), "G jumps to main");
    press(disasm, Qt::Key_Escape);
    check(line_with(disasm, QStringLiteral("proc near")).contains(QStringLiteral("walk_list")),
          "Esc goes back");

    if (failures) {
        for (auto* edit : window.findChildren<QPlainTextEdit*>())
            if (!qobject_cast<CodeView*>(edit))
                std::fprintf(stderr, "--- output ---\n%s\n", qPrintable(edit->toPlainText()));
        std::fprintf(stderr, "--- listing ---\n%s\n", qPrintable(disasm->toPlainText()));
    }
    std::fprintf(stderr, "%d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
