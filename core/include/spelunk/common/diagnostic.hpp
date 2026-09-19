#pragma once

#include <cstdio>
#include <cstdarg>
#include <format>
#include <print>
#include <string>
#include <string_view>
#include <utility>

namespace spelunk::diagnostic {

// Set once by the CLI before starting any workers. Library/GUI users retain
// the usual text diagnostics. stdout is never used for diagnostics.
inline bool json = false;
inline thread_local bool error_reported = false;
inline thread_local std::string pending;

inline std::string escape(std::string_view text) {
    std::string out;
    for (std::size_t i = 0; i < text.size(); ++i) {
        const auto c = static_cast<unsigned char>(text[i]);
        if (c == '"' || c == '\\') { out += '\\'; out += text[i]; }
        else if (c < 0x20) out += std::format("\\u{:04x}", c);
        else if (c < 0x80) out += text[i];
        else {
            // Preserve valid UTF-8; escape arbitrary bytes from filenames or
            // malformed binary symbols so every record remains valid JSON.
            const std::size_t count = c >= 0xc2 && c <= 0xdf ? 2 :
                c >= 0xe0 && c <= 0xef ? 3 : c >= 0xf0 && c <= 0xf4 ? 4 : 0;
            bool valid = count != 0 && count <= text.size() - i;
            for (std::size_t j = 1; valid && j < count; ++j) {
                const auto next = static_cast<unsigned char>(text[i + j]);
                valid = next >= 0x80 && next <= 0xbf;
                if (j == 1) valid &= !(c == 0xe0 && next < 0xa0) &&
                    !(c == 0xed && next >= 0xa0) && !(c == 0xf0 && next < 0x90) &&
                    !(c == 0xf4 && next >= 0x90);
            }
            if (valid) { out += text.substr(i, count); i += count - 1; }
            else out += std::format("\\u{:04x}", c);
        }
    }
    return out;
}

inline void write(std::string_view message, std::string_view kind = "cli",
                  bool error = false) {
    if (!json) {
        std::println(stderr, "{}", message);
        return;
    }
    error_reported |= error;
    std::println(stderr, "{{\"type\":\"{}\",\"kind\":\"{}\",\"message\":\"{}\"}}",
                 error ? "error" : "diagnostic", escape(kind), escape(message));
}

template <typename... Args>
void print(std::format_string<Args...> format, Args&&... args) {
    write(std::format(format, std::forward<Args>(args)...));
}

// Older diagnostics assemble a line with several printf calls. Keep each
// completed line one JSON record and isolate fragments from worker threads.
#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 1, 2)))
#endif
inline void printf(const char* format, ...) {
    va_list args;
    va_start(args, format);
    if (!json) { std::vfprintf(stderr, format, args); va_end(args); return; }
    va_list copy;
    va_copy(copy, args);
    const int size = std::vsnprintf(nullptr, 0, format, copy);
    va_end(copy);
    if (size < 0) { va_end(args); return; }
    std::string text(static_cast<std::size_t>(size) + 1, '\0');
    std::vsnprintf(text.data(), text.size(), format, args);
    va_end(args);
    text.resize(static_cast<std::size_t>(size));
    pending += text;
    for (auto end = pending.find('\n'); end != std::string::npos;
         end = pending.find('\n')) {
        write(pending.substr(0, end));
        pending.erase(0, end + 1);
    }
}

}  // namespace spelunk::diagnostic
