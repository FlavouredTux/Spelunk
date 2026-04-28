/* Exercises Phase 4a-2 vector-shape recognition: a 24-byte struct
 * with three pointer fields at offsets 0, 8, 16 — the canonical
 * std::vector<T> layout under libstdc++ / libc++ / MSVC STL.
 *
 * sum_vec reads all three fields and indexes through `begin`. The
 * emitter's looks_like_vector predicate fires on the {0, 8, 16}
 * access set and renames the field reads to begin / end / capacity;
 * the runtime-array-index path then renders b[idx] cleanly. */

struct vec_int {
    int* begin;
    int* end;
    int* capacity;
};

volatile int g_sink;

__attribute__((noinline))
int sum_vec(struct vec_int* v, int idx) {
    int* b = v->begin;
    int* e = v->end;
    int* c = v->capacity;
    g_sink = (int)(c - b);   /* force capacity load past DSE */
    if (b + idx < e) return b[idx];
    return 0;
}

int main(void) {
    static struct vec_int g = {0};
    return sum_vec(&g, 0);
}
