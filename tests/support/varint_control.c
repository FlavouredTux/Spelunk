#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>

struct ByteStream { const unsigned char* data; size_t left; };
extern jmp_buf control_error_env;

__attribute__((noinline))
void control_read_byte(struct ByteStream* stream, unsigned char* byte) {
    *byte = *stream->data++;
    --stream->left;
}

__attribute__((noinline))
void decode_control(uint64_t* output, struct ByteStream* stream) {
    uint64_t value = 0;
    unsigned shift = 0;
    size_t i = 0, available = stream->left;
    unsigned char byte;
    for (;;) {
        byte = 0;
        if (i == available) longjmp(control_error_env, 1);
        control_read_byte(stream, &byte);
        value |= (uint64_t)(byte & 0x7f) << shift;
        if (i > 8) break;
        ++i;
        shift += 7;
        if (!(byte & 0x80)) break;
    }
    if (byte & 0x80) longjmp(control_error_env, 2);
    *output = value;
}
