typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned char u8;
volatile u64 event_count;
volatile u64 event_value;
u32 export_counter __asm__("export.counter");
__attribute__((noinline)) u32 counter_add(void *slot, u32 delta) {
    u32 old, next;
    __builtin_memcpy(&old, slot, sizeof(old));
    next = old + delta;
    __builtin_memcpy(slot, &next, sizeof(next));
    return old;
}
u32 next_handle(void) { return counter_add(&export_counter, 1) + 1; }
__attribute__((noinline)) unsigned long strlen(const char *text) {
    unsigned long count = 0;
    while (text[count]) ++count;
    return count;
}
u64 length_or_zero(const char *text) { return text ? strlen(text) : 0; }
extern double atof(const char *);
__attribute__((noinline)) double atof_bridge(const char *text) { return atof(text); }
double call_atof_bridge(const char *text) { return atof_bridge(text); }

__attribute__((noinline)) double parse_scale(const char *text) {
    ++event_count;
    event_value = (u8)text[0];
    return (double)(text[0] - '0') + 0.25;
}
struct ScaleState { u8 padding[156]; u32 enabled; float scale; };
__attribute__((noinline)) double parse_other(const char *text) {
    ++event_count;
    event_value = (u8)text[0] + 100;
    return (double)(text[0] - '0') - 0.5;
}
struct DoubleState { u64 selector; u64 padding; double result; };
double call_join(struct DoubleState *state, const char *text) {
    double result;
    if (state->selector) result = parse_scale(text);
    else result = parse_other(text);
    state->result = result;
    return result;
}
float branch_scale(struct ScaleState *state, const char *text) {
    float scale = 1.0f;
    if (text && text[0]) {
        state->enabled = 1;
        scale = (float)parse_scale(text);
    } else {
        state->enabled = 0;
    }
    state->scale = scale;
    return scale;
}
struct Brightness { u64 owner; u8 padding[116]; float value; };
__attribute__((noinline)) void record_message(const char *message) {
    ++event_count;
    event_value = (u8)message[0];
}
float read_brightness(struct Brightness *state, u64 owner) {
    if (!state) {
        record_message("missing");
        return 1.0f;
    }
    if (state->owner != owner) {
        record_message("owner");
        return 1.0f;
    }
    return state->value;
}
struct __attribute__((packed)) PackedState { u8 tag; u32 count; u64 payload; };
u64 update_packed(struct PackedState *state, u64 delta) {
    u64 result = state->payload ^ state->count ^ state->tag;
    state->count += (u32)delta;
    state->payload += delta;
    state->tag ^= (u8)delta;
    return result;
}
__attribute__((noinline)) void record_event(u64 value) {
    ++event_count;
    event_value = value;
}
struct Ops { u64 padding[7]; void (*start)(u64); };
struct Wrapper { u64 value; struct Ops *ops; };
u32 start_record(struct Wrapper *wrapper) {
    wrapper->ops->start(wrapper->value);
    return 1;
}
