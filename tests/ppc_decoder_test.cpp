#include "ppc_decoder_test_support.hpp"

int main() {
    ppc_decoder_test::run_integer_tests();
    ppc_decoder_test::run_floating_point_tests();
    ppc_decoder_test::run_control_flow_tests();
    ppc_decoder_test::run_paired_single_tests();
    return ppc_decoder_test::fails == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
