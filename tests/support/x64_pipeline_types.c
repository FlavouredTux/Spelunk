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

/* Loop-carried locals whose web also holds a pre-loop value: the back edge
 * and the exit both need explicit copies, and the pre-loop value must not
 * be clobbered by the loop's updates. */
extern uint64_t call_note(uint64_t, ...);
uint64_t loop_string_bound(const unsigned char* s, uint64_t flag, uint64_t extra) {
    uint64_t total = call_note(1, flag);
    if (flag) total = extra + 20;
    if (s) {
        do total++; while (*s++);
    }
    return total * 3 + (flag ? 1 : 0);
}
uint64_t loop_mix_keep_start(unsigned char* p, uint64_t n, uint64_t tail) {
    unsigned char* start = p;
    unsigned char acc = (unsigned char)call_note(2, n);
    if ((int64_t)n > 0) {
        unsigned char* q = p;
        do { acc = (unsigned char)(acc * 31 + *q); *q = acc; q++; } while (q != p + n);
        p += n;
    }
    *p = (unsigned char)tail;
    return ((uint64_t)(p - start) + tail) * 256 + acc;
}
uint64_t loop_copy_string(unsigned char* dst, const unsigned char* src, uint64_t extra) {
    unsigned char* start = dst;
    uint64_t salt = call_note(4, extra);
    unsigned char c;
    do { c = *src++; *dst++ = (unsigned char)(c ^ salt); } while (c);
    *dst = (unsigned char)extra;
    return (uint64_t)(dst - start) + (uint64_t)(src - start);
}
