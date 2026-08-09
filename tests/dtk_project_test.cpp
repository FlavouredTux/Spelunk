#include <ember/binary/dol.hpp>
#include <ember/binary/dtk_project.hpp>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string_view>
#include <vector>

namespace {

int fails = 0;

void check(bool condition, const char* message) {
    if (condition) return;
    std::fprintf(stderr, "FAIL: %s\n", message);
    ++fails;
}

void put_be32(std::vector<std::byte>& bytes, std::size_t offset, ember::u32 value) {
    for (unsigned i = 0; i < 4; ++i) {
        bytes[offset + i] = static_cast<std::byte>(value >> ((3 - i) * 8));
    }
}

std::vector<std::byte> make_dol() {
    std::vector<std::byte> bytes(0x160);
    put_be32(bytes, 0x00, 0x100);       // text0 file offset
    put_be32(bytes, 0x1c, 0x140);       // data0 file offset
    put_be32(bytes, 0x48, 0x80003100);  // text0 address
    put_be32(bytes, 0x64, 0x80004000);  // data0 address
    put_be32(bytes, 0x90, 0x40);        // text0 size
    put_be32(bytes, 0xac, 0x20);        // data0 size
    put_be32(bytes, 0xd8, 0x80004020);  // BSS address
    put_be32(bytes, 0xdc, 0x20);        // BSS size
    put_be32(bytes, 0xe0, 0x80003100);  // entry point
    return bytes;
}

void write_text(const std::filesystem::path& path, std::string_view text) {
    std::ofstream out(path);
    out << text;
}

void write_bytes(const std::filesystem::path& path,
                 const std::vector<std::byte>& bytes) {
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
}

void test_resolver_and_symbols() {
    namespace fs = std::filesystem;
    const auto unique = std::chrono::steady_clock::now().time_since_epoch().count();
    const fs::path root = fs::temp_directory_path() /
        ("ember_dtk_project_test_" + std::to_string(unique));
    const fs::path config_dir = root / "config" / "EU0";
    const fs::path object_dir = root / "orig" / "EU0" / "sys";
    fs::create_directories(config_dir);
    fs::create_directories(object_dir);

    write_text(config_dir / "config.yml",
        "name: main\n"
        "object: sys/main.dol\n"
        "object_base: orig/EU0\n"
        "symbols: config/EU0/symbols.txt\n");
    write_text(config_dir / "symbols.txt",
        "marioReInit = .text:0x80003100; // type:function size:0x20 scope:global align:4\n"
        "mario_work = .data:0x80004000; // type:object size:0x8 scope:local align:4\n"
        "mario_bss = .bss:0x80004020; // type:object size:0x10 scope:global align:4\n"
        "__ArenaLo = absolute:0x81200000; // type:object scope:global\n");
    const auto dol_bytes = make_dol();
    write_bytes(object_dir / "main.dol", dol_bytes);

    auto project = ember::resolve_dtk_project(root, "EU0");
    check(project.has_value(), "DTK project root resolves with an explicit version");
    if (project) {
        check(project->version == "EU0", "resolved DTK version is preserved");
        check(project->module_name == "main", "resolved DTK module name is preserved");
        check(project->object_path == fs::weakly_canonical(object_dir / "main.dol"),
              "object_base and object resolve from the project root");
        check(project->symbols_path == fs::weakly_canonical(config_dir / "symbols.txt"),
              "symbols path resolves from the project root");
    }

    auto inferred = ember::resolve_dtk_project(root);
    check(inferred.has_value() && inferred->version == "EU0",
          "a single project version is inferred");

    auto dol = ember::DolBinary::load_from_buffer(dol_bytes);
    check(dol.has_value(), "synthetic DOL loads");
    if (dol) {
        auto added = (*dol)->attach_dtk_symbols_from_path(config_dir / "symbols.txt");
        check(added.has_value() && *added == 3,
              "exact DTK parser imports in-image text, data, and BSS symbols");
        const auto* function = (*dol)->find_by_name("marioReInit");
        check(function && function->addr == 0x80003100 &&
              function->kind == ember::SymbolKind::Function && function->size == 0x20,
              "DTK function name replaces synthetic DOL entry and keeps its size");
        const auto* global = (*dol)->find_by_name("mario_work");
        check(global && global->kind == ember::SymbolKind::Object && global->size == 8 &&
              !global->is_export, "DTK initialized local imports as an object");
        const auto* bss = (*dol)->find_by_name("mario_bss");
        check(bss && bss->kind == ember::SymbolKind::Object && bss->addr == 0x80004020,
              "DTK BSS global remains addressable");
        check((*dol)->find_by_name("__ArenaLo") == nullptr,
              "out-of-image absolute symbols are ignored");

        bool has_bss_section = false;
        for (const auto& section : (*dol)->sections()) {
            if (section.name == ".bss" && section.vaddr == 0x80004020 &&
                section.size == 0x20 && section.flags.writable) {
                has_bss_section = true;
            }
        }
        check(has_bss_section, "DOL BSS is represented as an allocated section");
    }

    std::error_code ec;
    fs::remove_all(root, ec);
}

}  // namespace

int main() {
    test_resolver_and_symbols();
    return fails == 0 ? 0 : 1;
}
