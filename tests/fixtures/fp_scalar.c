/* Scalar floating-point fixtures. Without the SSE lifting these would
 * all decompile to chains of `addsd()`/`mulsd()` intrinsic calls with no
 * visible math; with it they become real arithmetic expressions. */

#include <math.h>

double sum(double a, double b) {
    return a + b;
}

double poly(double x) {
    return x * x + x + 1.0;
}

double mix(double a, double b, double c) {
    return (a + b) * c - a;
}

float single_sum(float a, float b) {
    return a + b;
}

/* ucomisd → ZF/CF → ja/jbe. Decompiles to `(a > b) ? a : b` when the
 * structurer collapses the branch, otherwise to an explicit if/else. */
double max_d(double a, double b) {
    if (a > b) return a;
    return b;
}

/* ucomiss path: the same shape at f32 width. */
float clamp_f(float x, float lo, float hi) {
    if (x < lo) return lo;
    if (x > hi) return hi;
    return x;
}

/* sqrtsd intrinsic — exercises lift_fp_unop / libm-style intrinsic name. */
double hypot2(double a, double b) {
    return sqrt(a * a + b * b);
}

int main(int argc, char** argv) {
    (void)argv;
    double r = sum((double)argc, 2.5) + poly(1.5) + mix(1.0, 2.0, 3.0);
    r = max_d(r, 0.0);
    r += hypot2((double)argc, 1.0);
    float c = clamp_f((float)argc, 0.0f, 10.0f);
    return (int)r + (int)single_sum((float)argc, 0.5f) + (int)c;
}
