typedef unsigned long long u64;
#define NOINLINE __attribute__((noinline))

volatile u64 trace_count;
volatile u64 trace_ints[32];
volatile double trace_floats[32];

float literal_inf(void) { return __builtin_inff(); }
double literal_nan(void) { return __builtin_nan("0x123"); }
float literal_negative_zero(void) { return -0.0f; }
double literal_division(void) {
    static const double one = 1.0, two = 2.0;
    double result;
    __asm__ volatile("movsd %1, %0; divsd %2, %0"
                     : "=x"(result) : "m"(one), "m"(two));
    return result;
}

NOINLINE double mixed_helper(u64 first, float x, double y, u64 last) {
    u64 i = trace_count++ * 2;
    trace_ints[i] = first;
    trace_ints[i + 1] = last;
    trace_floats[i] = x;
    trace_floats[i + 1] = y;
    return y + x;
}
NOINLINE float float_helper(u64 tag, float x) {
    u64 i = trace_count++ * 2;
    trace_ints[i] = tag;
    trace_floats[i] = x;
    return x + 0.25f;
}
NOINLINE double stack_helper(u64 a, double x, u64 b, float y,
                             u64 c, u64 d, u64 e, u64 f, u64 g, double z) {
    u64 i = trace_count++ * 2;
    trace_ints[i] = a + b * 3 + c * 5 + d * 7 + e * 11 + f * 13 + g * 17;
    trace_floats[i] = x;
    trace_floats[i + 1] = y + z;
    return x + y + z;
}
NOINLINE float fp_stack_helper(u64 tag, float a, float b, float c, float d,
                               float e, float f, float g, float h, float i) {
    u64 n = trace_count++ * 2;
    trace_ints[n] = tag;
    trace_floats[n] = i;
    return a + b + c + d + e + f + g + h + i;
}

double mixed_call(u64 tag, double x) {
    return mixed_helper(tag + 1, 1.5f, x, 7) + 2.0;
}
double mixed_tail(u64 tag, double x) {
    return mixed_helper(tag, 2.5f, x, 9);
}
double (*volatile mixed_pointer)(u64, float, double, u64) = mixed_helper;
NOINLINE double alternate_helper(u64 tag, float x, double y, u64 last) {
    return mixed_helper(tag, x, y, last) + 4.0;
}
double indirect_call(u64 tag, double x) {
    return mixed_pointer(tag, 1.5f, x, 7) + 1.0;
}
float float_call(u64 tag, float x) {
    return float_helper(tag, x) + 0.5f;
}
double two_mixed_calls(u64 tag, double x) {
    double a = mixed_helper(tag, 1.5f, x, 3);
    return a + mixed_helper(tag + 1, 2.5f, x + 1.0, 5);
}
double stack_call(u64 tag, double x) {
    return stack_helper(tag, x, 2, 1.5f, 3, 4, 5, 6, 7, 2.5);
}
float fp_stack_call(u64 tag, float x) {
    return fp_stack_helper(tag, x, 1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.5f);
}
u64 memory_update(volatile u64 *p, u64 n, u64 stop) {
    u64 total = 0;
    for (u64 i = 0; i < n; ++i) {
        if (i == stop) return total;
        p[i] += i + 3;
        total ^= p[i];
    }
    return total;
}
