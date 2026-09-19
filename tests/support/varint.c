#include <stddef.h>
#include <stdint.h>

struct ByteStream { const unsigned char* data; size_t left; };

__attribute__((noinline))
void read_bytes(struct ByteStream* stream, unsigned char* byte, size_t count) {
    if (count && stream->left) {
        *byte = *stream->data++;
        --stream->left;
    }
}

__attribute__((noinline))
static void read_byte(struct ByteStream* stream, unsigned char* byte) {
    read_bytes(stream, byte, 1);
    __asm__ volatile("" ::: "memory");
}

__attribute__((noinline))
int decode_varint(uint64_t* output, struct ByteStream* stream) {
    uint64_t value = 0;
    unsigned shift = 0;
    size_t i = 0, available = stream->left;
    unsigned char byte;
    for (;;) {
        byte = 0;
        if (i == available) return 1;
        read_byte(stream, &byte);
        value |= (uint64_t)(byte & 0x7f) << shift;
        if (i > 8) break;
        ++i;
        shift += 7;
        if (!(byte & 0x80)) break;
    }
    if (byte & 0x80) return 2;
    *output = value;
    return 0;
}

uint64_t shift_value(uint64_t value, unsigned count) {
    __asm__("shl %%cl, %0" : "+r"(value) : "c"(count) : "cc");
    return value;
}
