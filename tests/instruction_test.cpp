#include <ember/disasm/instruction.hpp>

#include <cstdio>
#include <cstdlib>

int main() {
    int failures = 0;
    const auto count = static_cast<ember::u16>(ember::Mnemonic::Count);
    for (ember::u16 value = 1; value < count; ++value) {
        const auto mnemonic = static_cast<ember::Mnemonic>(value);
        if (ember::mnemonic_name(mnemonic) != "???") continue;
        std::fprintf(stderr, "FAIL: mnemonic %u has no display name\n",
                     static_cast<unsigned>(value));
        ++failures;
    }
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
