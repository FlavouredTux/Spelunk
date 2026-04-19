#include <stdio.h>
#include <string.h>

static int g_count;

int one_arg(const char* s) {
    printf("len=%zu\n", strlen(s));
    return 0;
}

int two_args(const char* a, const char* b) {
    fprintf(stderr, "a=%s b=%s\n", a, b);
    return 0;
}

int no_args(void) {
    fputs("hello\n", stdout);
    printf("ready\n");
    return 0;
}

int width_star(int w, int x) {
    printf("%*d\n", w, x);
    return 0;
}

int main(int argc, char** argv) {
    g_count += one_arg(argv[0]);
    if (argc > 1) g_count += two_args(argv[0], argv[1]);
    g_count += no_args();
    g_count += width_star(argc, g_count);
    return g_count;
}
