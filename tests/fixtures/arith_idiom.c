/* Exercises the idiom-recognition pass.  Compiled at -O2 so the compiler
 * emits the branchless abs patterns (sign-mask and two's-complement forms)
 * that the pass should recognise and simplify. */

int abs_i32(int x) {
    return x < 0 ? -x : x;
}

long abs_i64(long x) {
    return x < 0 ? -x : x;
}

int neg_i32(int x) {
    return 0 - x;
}

int main(int argc, char** argv) {
    (void)argv;
    return abs_i32(argc) + (int)abs_i64((long)argc) + neg_i32(argc);
}
