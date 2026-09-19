#include <stdint.h>
#include <limits.h>

int32_t divide_pair(int32_t numerator, int32_t denominator) {
    if (!denominator || (numerator == INT32_MIN && denominator == -1)) return 0;
    return (numerator / denominator) ^ (numerator % denominator);
}
