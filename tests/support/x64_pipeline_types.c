#include <stdint.h>
uint64_t logical_from_signed(int64_t x) { return (uint64_t)x >> 1; }
int64_t arithmetic_from_unsigned(uint64_t x) { return (int64_t)x >> 1; }
uint32_t logical32_from_signed(int32_t x) { return (uint32_t)x >> 1; }
int32_t arithmetic32_from_unsigned(uint32_t x) { return (int32_t)x >> 1; }
int cpu_bmi(void) { return (__builtin_cpu_supports("bmi") ? 1 : 0) | (__builtin_cpu_supports("bmi2") ? 2 : 0); }

uint64_t branch_diamond(uint64_t x, uint64_t y, uint64_t choose) {
    uint64_t value;
    if (choose) value = x + y;
    else value = x - y;
    return value ^ 0x55;
}
uint64_t branch_early(uint64_t x, uint64_t y) {
    if (!x) return 17;
    if (x < y) return y - x;
    return x + y;
}
uint64_t loop_sum(uint64_t n, uint64_t seed) {
    for (uint64_t i = 0; i < n; ++i) seed += i;
    return seed;
}
uint64_t loop_pair(uint64_t n, uint64_t a, uint64_t b) {
    for (uint64_t i = 0; i < n; ++i) {
        uint64_t old = a;
        a = b;
        b += old;
    }
    return a ^ b;
}
uint64_t loop_early(uint64_t n, uint64_t stop, uint64_t seed) {
    for (uint64_t i = 0; i < n; ++i) {
        if (i == stop) return seed;
        seed += i;
    }
    return seed;
}
uint64_t alias_snapshot(uint64_t* p, uint64_t* q, uint64_t value) {
    uint64_t saved = *p;
    *q = value;
    return saved + *p;
}
uint64_t alias_byte(uint64_t* p, unsigned char* q, uint64_t value) {
    uint64_t saved = *p;
    *q = (unsigned char)value;
    return saved ^ *p;
}
uint64_t branch_memory(uint64_t* p, uint64_t* q, uint64_t choose) {
    uint64_t saved = *p;
    if (choose) *q = saved + 7;
    else *q = saved - 3;
    return saved ^ *p;
}
uint64_t loop_alias(uint64_t* p, uint64_t* q, uint64_t n) {
    uint64_t sum = 0;
    for (uint64_t i = 0; i < n; ++i) {
        uint64_t saved = p[i];
        q[i] = saved + 1;
        sum += saved;
    }
    return sum;
}
uint64_t void_index(void* memory, uint64_t index, uint64_t value) {
    uint64_t* words = memory;
    uint64_t old = words[index];
    words[index] = value;
    return old;
}

extern uint64_t call_step(uint64_t, uint64_t);
extern uint64_t call_mutate(uint64_t*, uint64_t);
extern uint64_t call_clobber(uint64_t);
uint64_t loop_call_result(uint64_t n, uint64_t seed, uint64_t delta) {
    for (uint64_t i = 0; i < n; ++i) seed = call_step(seed, delta + i);
    return seed;
}
uint64_t loop_call_memory(uint64_t* p, uint64_t* q, uint64_t n) {
    uint64_t sum = 0;
    for (uint64_t i = 0; i < n; ++i) {
        uint64_t saved = *p;
        uint64_t value = call_mutate(q, i + 1);
        sum += saved + *p + value;
    }
    return sum;
}
uint64_t loop_call_preserve(uint64_t n, uint64_t seed, uint64_t extra) {
    uint64_t sum = extra;
    for (uint64_t i = 0; i < n; ++i) {
        uint64_t old = seed + i;
        sum += old + call_clobber(seed);
        seed += extra;
    }
    return sum;
}
uint64_t loop_call_exit(uint64_t n, uint64_t stop, uint64_t seed) {
    for (uint64_t i = 0; i < n; ++i) {
        seed = call_step(seed, i);
        if (i == stop) return seed;
    }
    return seed;
}
