#include <stdint.h>
#include <setjmp.h>

struct ByteStream;
jmp_buf control_error_env;
extern void decode_control(uint64_t*, struct ByteStream*);

int invoke_control(uint64_t* output, struct ByteStream* stream) {
    const int error = setjmp(control_error_env);
    if (error) return error;
    decode_control(output, stream);
    return 0;
}

int invoke_function(void (*decode)(uint64_t*, struct ByteStream*), uint64_t* output, struct ByteStream* stream) {
    const int error = setjmp(control_error_env);
    if (error) return error;
    decode(output, stream);
    return 0;
}
