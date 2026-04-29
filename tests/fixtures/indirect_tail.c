/* Three shapes the compiler reliably turns into an indirect tail-jmp
 * (`jmp [reg/mem]` or `jmp reg`). Without the indirect-tail-call
 * promotion in the lifter, each of these renders as a bare
 * `__unreachable();` — losing the entire call from the pseudo-C.
 *
 *   - via_table:   global fn-pointer table indexed at runtime;
 *                  -O2 emits `jmp qword ptr [tbl + idx*8]`.
 *   - via_member:  struct-field fn-pointer dereferenced through `this`;
 *                  -O2 emits `mov rax, [rdi+ofs]; jmp rax`.
 *   - via_global:  call through a single named global fn-pointer;
 *                  -O2 emits `jmp qword ptr [rip+gfp]`.
 *
 * `noinline` keeps the helpers from being inlined into main; the tail
 * shape only manifests when each function exists as a real callee. */

typedef int (*op_t)(int);

int (*g_fp)(int);
op_t fn_table[4] = { 0, 0, 0, 0 };

struct Handler {
    int (*op)(int);
    int (*log)(int);
};

__attribute__((noinline))
int via_table(int idx, int x) {
    return fn_table[idx](x);
}

__attribute__((noinline))
int via_member(struct Handler* h, int x) {
    return h->op(x);
}

__attribute__((noinline))
int via_global(int x) {
    return g_fp(x);
}

int main(int argc, char** argv) {
    (void)argv;
    struct Handler h = { 0, 0 };
    return via_table(argc, argc) + via_member(&h, argc) + via_global(argc);
}
