#include <stdint.h>

struct Counter {
    uint32_t value;
    uint32_t limit;
    uint32_t flags;
    uint32_t updates;
};

uint32_t update_counter(struct Counter *counter, uint32_t amount) {
    if (!counter || (counter->flags & 1)) return 0;
    uint32_t old = counter->value;
    if (old >= counter->limit) return old;
    uint32_t room = counter->limit - old;
    counter->value = old + (amount < room ? amount : room);
    counter->updates += 1;
    if (counter->value == counter->limit) counter->flags |= 2;
    return counter->value;
}
