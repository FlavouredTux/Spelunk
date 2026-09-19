#include <stdint.h>

uint32_t accumulate(uint32_t limit, uint32_t seed) {
    uint32_t sum = seed;
    for (uint32_t i = 0; i < limit; ++i) {
        if ((i & 3) == 1) continue;
        sum += i * 7;
        if (sum > 1000) break;
        for (uint32_t j = 0; j < (i & 3); ++j) {
            sum = (sum << 1) ^ (sum >> 3) ^ j;
        }
    }
    return sum;
}
