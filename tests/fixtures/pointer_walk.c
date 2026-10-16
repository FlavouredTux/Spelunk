// Linked-list walks whose loop-carried pointer update also feeds the loop
// test. The variadic printf keeps them on the merge-local path.
#include <stdint.h>
#include <stdio.h>

struct node {
    uint32_t key;
    struct node *next;
};

__attribute__((noinline)) uint32_t sum_and_report(const struct node *head) {
    uint32_t sum = 0;
    for (const struct node *n = head; n; n = n->next) sum += n->key;
    printf("%u\n", sum);
    return sum;
}

int main(int argc, char **argv) {
    (void)argv;
    struct node tail = {2, 0};
    struct node head = {(uint32_t)argc, &tail};
    return (int)sum_and_report(&head);
}
