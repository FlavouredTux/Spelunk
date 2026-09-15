#include <spelunk/common/text.hpp>

#include <cstddef>

namespace spelunk {

bool parse_float_clamped(std::string_view s, float& out) noexcept {
    if (s.empty()) return false;

    std::size_t i = 0;
    bool negative = false;
    if (s[i] == '-' || s[i] == '+') {
        negative = s[i] == '-';
        ++i;
        if (i == s.size()) return false;
    }

    double value = 0.0;
    bool has_digit = false;
    while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
        has_digit = true;
        value = value * 10.0 + static_cast<double>(s[i] - '0');
        ++i;
    }
    if (i < s.size() && s[i] == '.') {
        ++i;
        double place = 0.1;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
            has_digit = true;
            value += static_cast<double>(s[i] - '0') * place;
            place *= 0.1;
            ++i;
        }
    }
    if (!has_digit) return false;

    if (i < s.size() && (s[i] == 'e' || s[i] == 'E')) {
        ++i;
        if (i == s.size()) return false;
        bool negative_exponent = false;
        if (s[i] == '-' || s[i] == '+') {
            negative_exponent = s[i] == '-';
            ++i;
            if (i == s.size()) return false;
        }

        int exponent = 0;
        bool has_exponent_digit = false;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
            has_exponent_digit = true;
            if (exponent < 64) exponent = exponent * 10 + (s[i] - '0');
            ++i;
        }
        if (!has_exponent_digit) return false;

        const int capped_exponent = exponent > 64 ? 64 : exponent;
        for (int n = 0; n < capped_exponent; ++n) {
            value = negative_exponent ? (value / 10.0) : (value * 10.0);
        }
    }

    if (i != s.size()) return false;
    if (negative) value = -value;
    if (value < 0.0) value = 0.0;
    if (value > 1.0) value = 1.0;
    out = static_cast<float>(value);
    return true;
}

}  // namespace spelunk
