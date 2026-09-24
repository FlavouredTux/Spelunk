// Source shape for phi_tree_erase.prebuilt. GCC's inline std::map erase
// implementation produces the repeated merge pattern exercised by the
// pseudocode timeout regression.
//
// To refresh the fixture, compile this file with GCC 16 at -O2, find the
// instantiated std::_Rb_tree<...>::_M_erase symbol with nm, and extract
// its symbol-sized bytes from the ELF .text section. Keep the raw region's
// base address in phi_tree_erase_test.py aligned with the extracted bytes.
#include <cstddef>
#include <functional>
#include <map>
#include <string>

extern "C" void clear_tree(
    std::map<std::string, std::size_t, std::less<>>& values) {
    values.clear();
}
