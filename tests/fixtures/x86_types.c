#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char buffer[14];
    memset(buffer, 0, sizeof(buffer));
    if (argc < 1) return 0;
    sscanf(argv[0], "%13s", buffer);
    return strcmp(buffer, argv[0]);
}
