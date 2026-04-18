/* Stack-slot load forwarding test. With -O0 the compiler spills every
 * local to the stack and reloads on use; without GVN + memory-forwarding
 * the pseudo-C output drags those reloads through as visible `local_X`
 * references. With both passes active, the final `return` should see the
 * forwarded computation, not a fresh load. */

int forward_local(int x) {
    volatile int sink;
    int y = x + 1;
    sink  = y;
    return y + 2;
}

int main(int argc, char** argv) {
    (void)argv;
    return forward_local(argc);
}
