#include <stdint.h>

uint32_t shift_bytes(uint8_t *data, uint32_t count) {
    uint32_t sum = 0;
    for (uint32_t i = count; i > 1; --i) {
        data[i - 1] = data[i - 2];
        sum += data[i - 1];
    }
    return sum;
}
