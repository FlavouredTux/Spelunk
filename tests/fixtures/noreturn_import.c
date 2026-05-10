extern void __assert_fail(const char*, const char*, unsigned, const char*);

int assert_fail_path(int x) {
    if (x) return x;
    __assert_fail("x != 0", "noreturn_import.c", 5, "assert_fail_path");
    return 42;
}

int main(int argc, char** argv) {
    (void)argv;
    return assert_fail_path(argc - 1);
}
