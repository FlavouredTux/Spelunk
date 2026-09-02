#include <QApplication>
#include <QCommandLineParser>
#include <QStyle>
#include <QStyleFactory>
#include <QTimer>

#include "main_window.hpp"

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("Ember"));
    QApplication::setApplicationVersion(QStringLiteral(EMBER_GUI_VERSION));

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("Ember desktop front end"));
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
    parser.addOption(screenshot);
    parser.addOption(pseudocode);
    parser.process(app);

    // Fusion with its stock light palette is the closest built-in match
    // for the Qt look IDA and Binary Ninja ship with.
    app.setStyle(QStyleFactory::create(QStringLiteral("Fusion")));
    app.setPalette(app.style()->standardPalette());

    ember::gui::MainWindow window;
    window.show();

    if (parser.isSet(screenshot)) {
        const QString out = parser.value(screenshot);
        const bool want_pseudo = parser.isSet(pseudocode);
        QObject::connect(&window, &ember::gui::MainWindow::analysis_finished, &window,
                         [&window, out, want_pseudo] {
            if (want_pseudo) window.open_pseudocode_for_test();
            QTimer::singleShot(250, &window, [&window, out] {
                const bool ok = window.grab().save(out);
                QApplication::exit(ok ? 0 : 2);
            });
        });
    }

    const QStringList args = parser.positionalArguments();
    if (!args.isEmpty()) window.open_path(args.first());
    else if (parser.isSet(screenshot)) return 2;
    return QApplication::exec();
}
