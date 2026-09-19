namespace wire {
struct Stream { unsigned size; };
struct DecodeError { const char* message; };

__attribute__((used, noinline))
static void checkSize(unsigned long long& value, Stream& stream) {
    if (!stream.size) throw DecodeError{"read past end"};
    if (stream.size > 10) throw DecodeError{"larger than maximum size"};
    value = stream.size;
}
}
