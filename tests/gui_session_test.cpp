#include "../gui/src/session.hpp"
#include <chrono>
#include <cstdio>
#include <filesystem>

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    namespace fs = std::filesystem;
    const auto dir = fs::temp_directory_path() /
        ("spelunk-gui-session-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    fs::create_directories(dir);
    const auto binary = dir / "target";
    fs::copy_file(argv[1], binary);
    auto original = spelunk::load_binary(binary);
    if (!original) return 1;
    const auto* symbol = (*original)->find_by_name("big");
    if (!symbol) return 1;
    spelunk::Annotations annotations;
    annotations.renames[symbol->addr] = "renamed_sum";
    annotations.signatures[symbol->addr] = {"int", {{"int", "first"}, {"int", "second"}, {"int", "third"}}};
    if (!annotations.save(spelunk::sidecar_annotation_path(binary))) return 1;
    auto session = spelunk::gui::open_session(binary);
    if (!session) return 1;
    const auto* function = (*session)->function_at(symbol->addr);
    if (!function || function->name != "renamed_sum") return 1;
    auto window = (*session)->window_for(*function);
    if (!window || window->label != "renamed_sum") return 1;
    auto output = (*session)->pseudocode(*window, nullptr);
    if (!output || output->find("int renamed_sum(int first, int second, int third)") == std::string::npos) {
        if (output) std::fprintf(stderr, "%s\n", output->c_str());
        return 1;
    }
    fs::remove_all(dir);
    return 0;
}
