// Classic goto-fail cleanup pattern. Compiled at -O0 so gcc keeps the
// explicit gotos instead of deduplicating the tail into a single block.
#include <string.h>
#include <stdlib.h>

int multi_exit(const char* s, const char* t) {
    if (s == 0) goto fail;
    if (t == 0) goto fail;
    if (strlen(s) != strlen(t)) goto fail;
    return 0;
fail:
    return -1;
}

int cleanup_on_fail(const char* name) {
    char* buf = (char*)malloc(64);
    if (buf == 0) return -1;
    if (name == 0) goto bad;
    if (strlen(name) > 32) goto bad;
    strcpy(buf, name);
    free(buf);
    return 0;
bad:
    free(buf);
    return -1;
}

// A non-trivial tail: the target does work (a call, an assignment) before
// returning. Trivial-tail inliner can't handle this; the bounded-tail
// fallback should.
static int g_log;
int shared_tail(const char* s) {
    int result = 0;
    if (s == 0) goto done;
    if (*s == 0) goto done;
    result = (int)strlen(s);
done:
    g_log = result;
    return result;
}

int main(void) {
    return multi_exit("a", "b") + cleanup_on_fail("x") + shared_tail("y");
}
