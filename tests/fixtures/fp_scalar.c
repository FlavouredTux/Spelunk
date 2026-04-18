/* Scalar floating-point fixtures. Without the SSE lifting these would
 * all decompile to chains of `addsd()`/`mulsd()` intrinsic calls with no
 * visible math; with it they become real arithmetic expressions. */

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

int main(int argc, char** argv) {
    (void)argv;
    double r = sum((double)argc, 2.5) + poly(1.5) + mix(1.0, 2.0, 3.0);
    return (int)r + (int)single_sum((float)argc, 0.5f);
}
