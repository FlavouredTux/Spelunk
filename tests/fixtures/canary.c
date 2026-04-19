// Compiled with -fstack-protector-strong to force glibc's stack cookie
// prologue/epilogue. Exists solely to pin the canary-suppression path.
#include <string.h>

int uses_buffer(const char* s) {
    char buf[64];
    strcpy(buf, s);
    return (int)strlen(buf);
}

int main(int argc, char** argv) {
    return argc > 1 ? uses_buffer(argv[1]) : 0;
}
