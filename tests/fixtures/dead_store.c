/* A static global overwritten multiple times in the same function — -O0
 * keeps all three stores literally; DSE should collapse to the last one.
 * Exercises the global-address (Imm-keyed) store deduplication path in
 * pass_dead_store_elim. */

static long s;

void redundant(long x) {
    s = 1;
    s = 2;
    s = x;
}

int main(int argc, char** argv) {
    (void)argv;
    redundant(argc);
    return (int)s;
}
