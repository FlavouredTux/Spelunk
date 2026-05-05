struct packet {
    unsigned magic;
    unsigned flags;
    unsigned long payload;
};

__attribute__((noinline))
int inspect_packet(struct packet* p) {
    if (p->magic == 0x1234) {
        return (int)(p->flags + p->payload);
    }
    return 0;
}

int main(void) {
    static struct packet pkt = {0x1234, 7, 5};
    return inspect_packet(&pkt);
}
