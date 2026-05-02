typedef int (*op_t)(int);

__attribute__((noinline))
int plus7(int x) {
    return x + 7;
}

__attribute__((noinline))
int minus3(int x) {
    return x - 3;
}

__attribute__((noinline))
int call_fp(op_t fn, int x) {
    return fn(x) + 1;
}

int main(int argc, char** argv) {
    (void)argv;
    return call_fp(plus7, argc);
}
