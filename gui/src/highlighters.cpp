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

AsmHighlighter::AsmHighlighter(QTextDocument* doc, bool prefixed)
    : QSyntaxHighlighter(doc),
      prefixed_(prefixed),
      prefix_(colour(theme::kPrefix)),
      bytes_(colour(theme::kBytes)),
      mnemonic_(colour(theme::kMnemonic)),
      reg_(colour(theme::kRegister)),
      number_(colour(theme::kNumber)),
      name_(colour(theme::kName)),
      comment_(colour(theme::kComment)),
      keyword_(colour(theme::kKeyword)),
      prefix_re_(QStringLiteral(R"(^[A-Za-z_.$][\w.$]*:[0-9A-Fa-f]{8,16})")),
      // After the prefix: optional opcode bytes, the name column, mnemonic, operands.
      insn_re_(QStringLiteral(R"(^ ((?:[0-9A-F]{2} ?)*)\s+([A-Za-z][\w.]*)(.*)$)")),
      // A name in the label column: `loc_1180:`, `sub_1169 proc near`, `sub_1169 endp`.
      label_re_(QStringLiteral(R"(^ ([A-Za-z_$?@.][\w$?@.:]*?)(:|\s+proc near|\s+endp)?(\s*;.*)?$)")),
      reg_re_(QStringLiteral(
          R"(\b(?:[re]?(?:[abcd]x|[sd]i|[sb]p|ip)|[abcd][lh]|[sd]il|[sb]pl|r(?:[89]|1[0-5])[bwd]?)"
          R"(|[xyz]mm\d{1,2}|st\(?\d\)?|[cdefgs]s|[xw](?:\d{1,2}|zr|sp)|sp|lr|pc|fp)"
          R"(|[vqdshb]\d{1,2}|r\d{1,2}|f\d{1,2}|cr\d|ctr|xer|msr)\b)")),
      number_re_(QStringLiteral(R"(\b0x[0-9a-fA-F]+\b|\b\d+\b)")),
      name_re_(QStringLiteral(R"(\b[A-Za-z_][\w@$.]*\b)")) {}

void AsmHighlighter::highlightBlock(const QString& text) {
    int base = 0;
    if (prefixed_) {
        const auto p = prefix_re_.match(text);
        if (!p.hasMatch()) {
            if (text.trimmed().startsWith(QLatin1Char(';'))) setFormat(0, static_cast<int>(text.size()), comment_);
            return;
        }
        base = static_cast<int>(p.capturedLength(0));
        setFormat(0, base, prefix_);
    }
    const QString rest = text.mid(base);
    if (rest.trimmed().isEmpty()) return;
    if (rest.trimmed().startsWith(QLatin1Char(';'))) {
        setFormat(base, static_cast<int>(rest.size()), comment_);
        return;
    }

    // Label column: a name right after the single separator space. Opcode
    // bytes sit in the same place, but as space-separated uppercase pairs.
    static const QRegularExpression bytes_lead(QStringLiteral(R"(^ (?:[0-9A-F]{2} )+ )"));
    if (rest.size() > 1 && rest[1] != QLatin1Char(' ') && !bytes_lead.match(rest).hasMatch()) {
        const auto m = label_re_.match(rest);
        if (m.hasMatch()) {
            setFormat(base + static_cast<int>(m.capturedStart(1)), static_cast<int>(m.capturedLength(1)), name_);
            if (m.capturedLength(2) > 0)
                setFormat(base + static_cast<int>(m.capturedStart(2)), static_cast<int>(m.capturedLength(2)), keyword_);
            if (m.capturedLength(3) > 0)
                setFormat(base + static_cast<int>(m.capturedStart(3)), static_cast<int>(m.capturedLength(3)), comment_);
            return;
        }
    }

    const auto m = insn_re_.match(rest);
    if (!m.hasMatch()) return;
    if (m.capturedLength(1) > 0)
        setFormat(base + static_cast<int>(m.capturedStart(1)), static_cast<int>(m.capturedLength(1)), bytes_);
    setFormat(base + static_cast<int>(m.capturedStart(2)), static_cast<int>(m.capturedLength(2)), mnemonic_);

    const int  ops_base = base + static_cast<int>(m.capturedStart(3));
    QString    tail     = m.captured(3);
    const auto semi     = tail.indexOf(QStringLiteral("; "));
    const QString ops   = semi >= 0 ? tail.left(semi) : tail;

    auto apply = [&](const QRegularExpression& re, const QTextCharFormat& fmt, bool skip_size_words) {
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
            setFormat(ops_base + static_cast<int>(mm.capturedStart(0)),
                      static_cast<int>(mm.capturedLength(0)), fmt);
        }
    };
    apply(name_re_, name_, /*skip_size_words=*/true);
    apply(reg_re_, reg_, false);
    apply(number_re_, number_, false);

    if (semi >= 0)
        setFormat(ops_base + static_cast<int>(semi), static_cast<int>(tail.size() - semi), comment_);
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
