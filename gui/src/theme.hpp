#pragma once

#include <QColor>
#include <QFont>
#include <QFontDatabase>

// Approximation of IDA's default (light) palette. Every colour the code
// views, tables and navigation band paint comes from here, so a dark
// variant is a one-file change.
namespace ember::gui::theme {

// Code views
inline const QColor kViewBackground {0xff, 0xff, 0xff};
inline const QColor kViewText       {0x00, 0x00, 0x00};
inline const QColor kCurrentLine    {0xff, 0xff, 0xdc};
inline const QColor kPrefix         {0x5f, 0x5f, 0x8f};   // .text:0000000000401000
inline const QColor kBytes          {0x9a, 0x9a, 0x9a};   // opcode bytes column
inline const QColor kMnemonic       {0x00, 0x00, 0x80};
inline const QColor kRegister       {0x00, 0x00, 0x80};
inline const QColor kNumber         {0x00, 0x80, 0x00};
inline const QColor kName           {0x00, 0x00, 0xff};   // sub_401000, loc_401010
inline const QColor kImport         {0xc0, 0x00, 0xc0};   // extern / PLT
inline const QColor kComment        {0x80, 0x80, 0x80};

// Pseudocode
inline const QColor kKeyword        {0x00, 0x00, 0x80};
inline const QColor kType           {0x00, 0x00, 0x80};
inline const QColor kString         {0x00, 0x80, 0x00};
inline const QColor kCall           {0x00, 0x00, 0xff};

// Navigation band
inline const QColor kBandRegular    {0x3c, 0x72, 0xd1};   // regular function
inline const QColor kBandLibrary    {0x38, 0xb7, 0xc8};   // library function
inline const QColor kBandExtern     {0xf2, 0xa1, 0xe0};   // external symbol / PLT
inline const QColor kBandData       {0x80, 0x80, 0x80};
inline const QColor kBandUnexplored {0xc8, 0xc8, 0xc8};
inline const QColor kBandMarker     {0xff, 0xdd, 0x00};
inline const QColor kBandFrame      {0x70, 0x70, 0x70};

inline QFont code_font() {
    QFont f = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    f.setPointSize(10);
    return f;
}

}  // namespace ember::gui::theme
