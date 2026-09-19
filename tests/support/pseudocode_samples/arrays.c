#include <stdint.h>

uint32_t transform_bytes(uint8_t *data, uint32_t count) {
    uint32_t sum = 0;
    for (uint32_t i = 0; i < count; ++i) {
        uint8_t value = data[i];
        if (value == 255) break;
        if (!value) continue;
        value ^= (uint8_t)i;
        data[i] = value;
        sum += value;
    }
    return sum;
}
