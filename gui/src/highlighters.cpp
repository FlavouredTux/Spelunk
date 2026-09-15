#include "highlighters.hpp"

#include "theme.hpp"

namespace spelunk::gui {

namespace {

QTextCharFormat colour(const QColor& c) {
    QTextCharFormat f;
    f.setForeground(c);
    return f;
}

}  // namespace

// ---------------------------------------------------------------------------
// Disassembly
// ---------------------------------------------------------------------------

AsmHighlighter::AsmHighlighter(QTextDocument* doc)
    : QSyntaxHighlighter(doc),
      prefix_(colour(theme::kPrefix)),
      bytes_(colour(theme::kBytes)),
      mnemonic_(colour(theme::kMnemonic)),
      reg_(colour(theme::kRegister)),
      number_(colour(theme::kNumber)),
      name_(colour(theme::kName)),
      comment_(colour(theme::kComment)),
      // 1: segment:va   2: opcode bytes   3: mnemonic   4: operands + comment
      line_re_(QStringLiteral(
          R"(^([A-Za-z_.$][\w.$]*:[0-9a-fA-F]{8,16})(\s+(?:[0-9a-f]{2}\s)*)\s*([A-Za-z][\w.]*)?(.*)$)")),
      reg_re_(QStringLiteral(
          R"(\b(?:[re]?(?:[abcd]x|[sd]i|[sb]p|ip)|[abcd][lh]|[sd]il|[sb]pl|r(?:[89]|1[0-5])[bwd]?)"
          R"(|[xyz]mm\d{1,2}|st\(?\d\)?|[cdefgs]s|[xw](?:\d{1,2}|zr|sp)|sp|lr|pc|fp)"
          R"(|[vqdshb]\d{1,2}|r\d{1,2}|f\d{1,2}|cr\d|ctr|xer|msr)\b)")),
      number_re_(QStringLiteral(R"(\b0x[0-9a-fA-F]+\b|\b\d+\b)")),
      name_re_(QStringLiteral(R"(\b[A-Za-z_][\w@$.]*\b)")) {}

void AsmHighlighter::highlightBlock(const QString& text) {
    if (text.startsWith(QLatin1Char(';'))) {
        setFormat(0, static_cast<int>(text.size()), comment_);
        return;
    }
    const auto m = line_re_.match(text);
    if (!m.hasMatch()) return;

    auto paint = [&](int group, const QTextCharFormat& fmt) {
        if (m.capturedLength(group) > 0)
            setFormat(static_cast<int>(m.capturedStart(group)),
                      static_cast<int>(m.capturedLength(group)), fmt);
    };
    paint(1, prefix_);
    paint(2, bytes_);
    paint(3, mnemonic_);

    const int  base = static_cast<int>(m.capturedStart(4));
    QString    rest = m.captured(4);
    const auto semi = rest.indexOf(QLatin1Char(';'));
    QString    ops  = semi >= 0 ? rest.left(semi) : rest;

    auto apply = [&](const QRegularExpression& re, const QTextCharFormat& fmt,
                     bool skip_size_words) {
        auto it = re.globalMatch(ops);
        while (it.hasNext()) {
            const auto mm = it.next();
            if (skip_size_words) {
                static const QStringList kSizeWords = {
                    QStringLiteral("ptr"),  QStringLiteral("byte"),   QStringLiteral("word"),
                    QStringLiteral("dword"), QStringLiteral("qword"), QStringLiteral("tbyte"),
                    QStringLiteral("xmmword"), QStringLiteral("ymmword"), QStringLiteral("zmmword"),
                    QStringLiteral("short"), QStringLiteral("near"), QStringLiteral("far"),
                    QStringLiteral("offset"),
                };
                if (kSizeWords.contains(mm.captured(0))) continue;
            }
            setFormat(base + static_cast<int>(mm.capturedStart(0)),
                      static_cast<int>(mm.capturedLength(0)), fmt);
        }
    };
    apply(name_re_, name_, /*skip_size_words=*/true);
    apply(reg_re_, reg_, false);
    apply(number_re_, number_, false);

    if (semi >= 0)
        setFormat(base + static_cast<int>(semi),
                  static_cast<int>(rest.size() - semi), comment_);
}

// ---------------------------------------------------------------------------
// Pseudocode
// ---------------------------------------------------------------------------

PseudoHighlighter::PseudoHighlighter(QTextDocument* doc)
    : QSyntaxHighlighter(doc) {
    auto add = [&](const char* pattern, const QColor& c) {
        rules_.push_back(Rule{QRegularExpression(QString::fromLatin1(pattern)), colour(c)});
    };
    // Order matters: later rules paint over earlier ones.
    add(R"(\b[A-Za-z_]\w*(?=\s*\())", theme::kCall);
    add(R"(\b(?:u?int(?:8|16|32|64)_t|size_t|ssize_t|void|char|short|int|long|unsigned|signed)"
        R"(|float|double|bool|struct|union|enum|const|static|_BOOL\d?|__int(?:8|16|32|64))\b)",
        theme::kType);
    add(R"(\b(?:if|else|while|for|do|return|switch|case|default|break|continue|goto|sizeof)\b)",
        theme::kKeyword);
    add(R"(\b0x[0-9a-fA-F]+\b|\b\d+(?:\.\d+)?[uUlLfF]*\b)", theme::kNumber);
    add(R"("(?:[^"\\]|\\.)*")", theme::kString);
    add(R"('(?:[^'\\]|\\.)*')", theme::kString);
    add(R"(//.*$)", theme::kComment);
    add(R"(/\*.*?\*/)", theme::kComment);
}

void PseudoHighlighter::highlightBlock(const QString& text) {
    for (const auto& r : rules_) {
        auto it = r.re.globalMatch(text);
        while (it.hasNext()) {
            const auto m = it.next();
            setFormat(static_cast<int>(m.capturedStart(0)),
                      static_cast<int>(m.capturedLength(0)), r.fmt);
        }
    }
}

}  // namespace spelunk::gui
