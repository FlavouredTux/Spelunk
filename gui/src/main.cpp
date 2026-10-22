#include <QApplication>
#include <QPalette>
#include <QCommandLineParser>
#include <QStyle>
#include <QStyleFactory>
#include <QStyleHints>
#include <QTimer>

#include "main_window.hpp"

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("Spelunk"));
    QApplication::setApplicationVersion(QStringLiteral(SPELUNK_GUI_VERSION));

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("Spelunk desktop front end"));
    parser.addHelpOption();
    parser.addVersionOption();
    parser.addPositionalArgument(QStringLiteral("binary"), QStringLiteral("File to open"));
    // Headless smoke test: load, render the main window, write a PNG, exit.
    // Pair with QT_QPA_PLATFORM=offscreen on a machine without a display.
    QCommandLineOption screenshot(QStringLiteral("screenshot"),
                                  QStringLiteral("Render the window to <png> and exit."),
                                  QStringLiteral("png"));
    QCommandLineOption pseudocode(QStringLiteral("pseudocode"),
                                   QStringLiteral("Open the pseudocode view before the screenshot."));
    QCommandLineOption hex(QStringLiteral("hex"),
                           QStringLiteral("Open the hex dump view before the screenshot."));
    QCommandLineOption graph(QStringLiteral("graph"),
                             QStringLiteral("Open the graph view before the screenshot."));
    QCommandLineOption at(QStringLiteral("at"),
                          QStringLiteral("Jump to <name> or address before the screenshot."),
                          QStringLiteral("name"));
    parser.addOption(screenshot);
    parser.addOption(pseudocode);
    parser.addOption(hex);
    QCommandLineOption fit(QStringLiteral("fit"),
                           QStringLiteral("With --graph: fit the whole graph in the window."));
    parser.addOption(graph);
    parser.addOption(fit);
    parser.addOption(at);
    parser.process(app);

    // Fusion with its stock light palette is the closest built-in match
    // for the Qt look IDA and Binary Ninja ship with.
    // IDA's default scheme is light; follow it even on a dark desktop so
    // the chrome matches the white listing.
    QApplication::styleHints()->setColorScheme(Qt::ColorScheme::Light);
    app.setStyle(QStyleFactory::create(QStringLiteral("Fusion")));
    // Explicit light palette: Fusion's standard palette follows the
    // desktop scheme, which left dark chrome around a white listing.
    QPalette light;
    light.setColor(QPalette::Window, QColor(0xf0, 0xf0, 0xf0));
    light.setColor(QPalette::WindowText, Qt::black);
    light.setColor(QPalette::Base, Qt::white);
    light.setColor(QPalette::AlternateBase, QColor(0xf5, 0xf5, 0xf5));
    light.setColor(QPalette::Text, Qt::black);
    light.setColor(QPalette::Button, QColor(0xf0, 0xf0, 0xf0));
    light.setColor(QPalette::ButtonText, Qt::black);
    light.setColor(QPalette::ToolTipBase, QColor(0xff, 0xff, 0xe1));
    light.setColor(QPalette::ToolTipText, Qt::black);
    light.setColor(QPalette::PlaceholderText, QColor(0x80, 0x80, 0x80));
    light.setColor(QPalette::Highlight, QColor(0x33, 0x99, 0xff));
    light.setColor(QPalette::HighlightedText, Qt::white);
    light.setColor(QPalette::Disabled, QPalette::Text, QColor(0x80, 0x80, 0x80));
    light.setColor(QPalette::Disabled, QPalette::WindowText, QColor(0x80, 0x80, 0x80));
    light.setColor(QPalette::Disabled, QPalette::ButtonText, QColor(0x80, 0x80, 0x80));
    app.setPalette(light);

    spelunk::gui::MainWindow window;
    window.show();

    if (parser.isSet(screenshot)) {
        const QString out = parser.value(screenshot);
        const bool want_pseudo = parser.isSet(pseudocode);
        const bool want_hex = parser.isSet(hex);
        const bool want_graph = parser.isSet(graph);
        const bool want_fit = parser.isSet(fit);
        const QString target = parser.value(at);
        QObject::connect(&window, &spelunk::gui::MainWindow::analysis_finished, &window,
                          [&window, out, want_pseudo, want_hex, want_graph, want_fit, target] {
            const auto save = [&window, out] {
                QTimer::singleShot(250, &window, [&window, out] {
                    const bool ok = window.grab().save(out);
                    QApplication::exit(ok ? 0 : 2);
                });
            };
            if (!target.isEmpty()) window.jump_for_test(target);
            if (want_graph) window.open_graph_for_test(want_fit);
            if (want_pseudo && !want_hex) {
                QObject::connect(&window, &spelunk::gui::MainWindow::pseudocode_ready,
                                 &window, save, Qt::SingleShotConnection);
                window.open_pseudocode_for_test();
                return;
            }
            if (want_pseudo) window.open_pseudocode_for_test();
            if (want_hex) window.open_hex_for_test();
            save();
        });
    }

    const QStringList args = parser.positionalArguments();
    if (!args.isEmpty()) window.open_path(args.first());
    else if (parser.isSet(screenshot)) return 2;
    return QApplication::exec();
}
