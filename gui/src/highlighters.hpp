#pragma once

#include <QRegularExpression>
#include <QSyntaxHighlighter>
#include <QTextCharFormat>
#include <vector>

namespace ember::gui {

// Colours ember's `format_disasm` lines after the view has rewritten the
// `0x<va>` prefix into IDA's `<segment>:<va>` form:
//   .text:0000000000001169  48 85 f6      test rsi, rsi  ; comment
class AsmHighlighter : public QSyntaxHighlighter {
    Q_OBJECT
public:
    explicit AsmHighlighter(QTextDocument* doc);
protected:
    void highlightBlock(const QString& text) override;
private:
    QTextCharFormat prefix_, bytes_, mnemonic_, reg_, number_, name_, comment_;
    QRegularExpression line_re_, reg_re_, number_re_, name_re_;
};

// Colours the pseudo-C emitter's output the way Hex-Rays does: keywords
// and types navy, calls blue, numbers and strings green, comments grey.
class PseudoHighlighter : public QSyntaxHighlighter {
    Q_OBJECT
public:
    explicit PseudoHighlighter(QTextDocument* doc);
protected:
    void highlightBlock(const QString& text) override;
private:
    struct Rule { QRegularExpression re; QTextCharFormat fmt; };
    std::vector<Rule> rules_;
};

}  // namespace ember::gui
