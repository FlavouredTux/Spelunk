/* A small switch with a dense integer selector — exercises the PIC
 * jump-table pattern and the partial-register read that selects the case. */

int describe(int op) {
    switch (op) {
        case 0: return 100;
        case 1: return 101;
        case 2: return 102;
        case 3: return 103;
        case 4: return 104;
        case 5: return 105;
        default: return -1;
    }
}

int main(int argc, char** argv) {
    (void)argv;
    return describe(argc);
}
