#include <stdint.h>

int32_t classify(int32_t value, int32_t mode) {
    if (value < -100) return -3;
    if (value > 100) return 3;
    switch (mode) {
        case 0: return value < 0 ? -value : value;
        case 1: return value * 3 + 7;
        case 2: return value == 0 ? 11 : 100 / value;
        case 3: return (value & 1) ? 17 : 23;
        default: return -1;
    }
}
