#pragma once

#include <string>
#include <vector>

#include <spelunk/binary/binary.hpp>
#include <spelunk/common/types.hpp>

namespace spelunk {

struct StringEntry {
    addr_t              addr   = 0;
    std::string         text;           // raw contents (unescaped, printable ASCII only)
    std::vector<addr_t> xrefs;          // instruction addresses referencing this string
};

struct StringScanOptions {
    bool collect_xrefs = true;
    std::vector<std::string> any_substrings;
};

// Scan all non-executable, readable sections for printable NUL-terminated ASCII
// strings of length >= 4. For each string, walk all defined (non-import) function
// symbols and record instructions whose operands reference the string's address
// (either as Relative targets or as Memory/Immediate absolute addresses).
[[nodiscard]] std::vector<StringEntry> scan_strings(const Binary& b);
[[nodiscard]] std::vector<StringEntry> scan_strings(const Binary& b,
                                                    const StringScanOptions& options);

struct StringNameCandidate {
    addr_t      function = 0;
    std::string name;
    std::string source_string;
};

struct StringNameInferenceOptions {
    bool        assertion_names = true;
    std::size_t max_assertion_functions = 50000;  // 0 = no cap
};

struct LogCategoryCluster {
    std::string         category;
    std::vector<addr_t> functions;
    std::vector<std::string> examples;
};

// Conservative log/string-anchor naming: identify function-like tokens in
// strings (`Class::method`, `function_name:`) and bind them to the distinct
// enclosing function(s) that reference the string.
[[nodiscard]] std::vector<StringNameCandidate>
infer_function_names_from_strings(const Binary& b,
                                  StringNameInferenceOptions options = {});

// Mine bracketed log categories such as "[FLog::MacLuaApp]" and group the
// functions that reference strings in each category.
[[nodiscard]] std::vector<LogCategoryCluster>
mine_log_categories(const Binary& b);

}  // namespace spelunk
