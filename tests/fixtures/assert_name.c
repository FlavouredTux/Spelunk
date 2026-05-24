extern void __assert_fail(const char*, const char*, unsigned, const char*);

int recovered_assert_name(int x) {
    __assert_fail("x is impossible", "assert_name.c", 4, "recovered_assert_name");
    return x + 1;
}

int main(int argc, char** argv) {
    (void)argv;
    return argc == 123 ? recovered_assert_name(argc) : 0;
}
