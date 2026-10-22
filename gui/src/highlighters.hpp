#pragma once

#include <QRegularExpression>
#include <QSyntaxHighlighter>
#include <QTextCharFormat>
#include <vector>

namespace spelunk::gui {

// Colours the IDA-style listing MainWindow renders:
//   .text:0000000000001169 sub_1169        proc near   ; CODE XREF: ...
//   .text:0000000000001169 48 85 F6                        test    rsi, rsi  ; comment
//   .text:0000000000001180 loc_1180:
//   .text:0000000000001190 sub_1169        endp
// Graph blocks drop the address prefix (`prefixed = false`): labels keep
// their single leading space and instructions start after two.
class AsmHighlighter : public QSyntaxHighlighter {
    Q_OBJECT
public:
    explicit AsmHighlighter(QTextDocument* doc, bool prefixed = true);
protected:
    void highlightBlock(const QString& text) override;
private:
    bool            prefixed_;
    QTextCharFormat prefix_, bytes_, mnemonic_, reg_, number_, name_, comment_, keyword_;
    QRegularExpression prefix_re_, insn_re_, label_re_, reg_re_, number_re_, name_re_;
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

}  // namespace spelunk::gui
