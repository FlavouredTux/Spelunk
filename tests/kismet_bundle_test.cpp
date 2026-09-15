#include <spelunk/binary/kismet_bundle.hpp>

#include <cassert>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <string>

int main() {
    namespace fs = std::filesystem;
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    const fs::path root = fs::temp_directory_path() /
        ("spelunk-kismet-test-" + std::to_string(nonce));
    const fs::path functions = root / "functions";
    fs::create_directories(functions);

    {
        std::ofstream raw(functions / "000001.bin", std::ios::binary);
        const char bytes[] = {0x16, 0x53};
        raw.write(bytes, 2);
    }
    {
        std::ofstream disassembly(functions / "000001.txt");
        disassembly << "Label_0x0:\n  $16: Int Zero.\nLabel_0x1:\n  $53: End of script.\n";
    }
    {
        std::ofstream manifest(root / "manifest.tsv");
        manifest << "SPELUNK_KISMET_BUNDLE\t1\tengine=5.7.4\tpointer_size=8\n";
        manifest << "FUNCTION\t000001\t2\t0\t/Game/BP_Test.BP_Test_C\t"
                    "/Game/BP_Test.BP_Test_C:Run\tfunctions/000001.bin\t"
                    "functions/000001.txt\n";
    }

    auto bundle = spelunk::KismetBundle::load(root);
    assert(bundle);
    assert(bundle->engine_version() == "5.7.4");
    assert(bundle->pointer_size() == 8);
    assert(bundle->functions().size() == 1);
    assert(bundle->functions()[0].bytecode_size == 2);

    auto raw = bundle->read_bytecode(bundle->functions()[0]);
    assert(raw && raw->size() == 2);
    assert((*raw)[0] == std::byte{0x16});

    auto disassembly = bundle->read_disassembly(bundle->functions()[0]);
    assert(disassembly && disassembly->find("Int Zero") != std::string::npos);

    fs::remove_all(root);
}
