// Tiny fixtures exercising the IR's `Mod` op (added in adffa81) and the
// do-while structurer path. Compiled at -O0 in CMakeLists so the
// compiler doesn't optimize the % operator into a magic-multiply or
// fold the do-while into a forward-branch.

unsigned divmod_runtime(unsigned a, unsigned b);
unsigned divmod_runtime(unsigned a, unsigned b) {
    return a % b;
}

// do-while loop body with an inner `if ... continue` arm. The structurer
// has to recognise this as `do { ... if (skip) continue; ... } while (cond)`
// rather than falling back to goto-soup. The internal `continue` keeps
// the test honest: a regression that breaks multi-edge predecessor
// handling shows up as a goto label inside the loop body.
int dowhile_with_skip(const int* xs, int n);
int dowhile_with_skip(const int* xs, int n) {
    int i = 0;
    int sum = 0;
    do {
        int v = xs[i];
        i++;
        if (v == 0) continue;
        sum += v;
    } while (i < n);
    return sum;
}

int main(int argc, char** argv) {
    (void)argv;
    int sample[1] = { argc };
    return (int)divmod_runtime((unsigned)argc, (unsigned)argc + 1u)
         + dowhile_with_skip(sample, 1);
}
