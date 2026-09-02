#pragma once

#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <ember/analysis/pipeline.hpp>
#include <ember/analysis/strings.hpp>
#include <ember/binary/binary.hpp>
#include <ember/common/error.hpp>
#include <ember/common/types.hpp>
#include <ember/decompile/emit_options.hpp>

namespace ember::gui {

// Everything the widgets need from one loaded binary. Built on a worker
// thread (load + function enumeration are the slow parts), then owned by
// MainWindow and handed to views by pointer. Widgets never touch the
// Binary directly; they go through the query helpers below so the
// rendering conventions live in one place.
struct Session {
    std::filesystem::path           path;
    std::unique_ptr<Binary>         binary;
    std::vector<DiscoveredFunction> functions;   // sorted by addr
    std::unordered_set<addr_t>      entries;     // every functions[i].addr

    // Populated the first time the Strings window opens.
    std::optional<std::vector<StringEntry>> strings;

    // Whole-program call graph as callee -> sorted unique callers. Built
    // on a worker thread after the first view is up (see
    // MainWindow::start_xref_analysis) and installed from the GUI thread,
    // so readers never race the builder. Empty until `xrefs_ready`.
    std::unordered_map<addr_t, std::vector<addr_t>> callers;
    bool xrefs_ready = false;

    [[nodiscard]] std::span<const addr_t> callers_of(addr_t fn) const noexcept;

    [[nodiscard]] const Section* section_at(addr_t va) const noexcept;
    [[nodiscard]] std::string    segment_name(addr_t va) const;

    // Function whose extent contains `va`, or the closest preceding one
    // when its size is unknown. Null when nothing covers `va`.
    [[nodiscard]] const DiscoveredFunction* function_at(addr_t va) const noexcept;
    // First function starting at or after `va` (navigation band clicks).
    [[nodiscard]] const DiscoveredFunction* function_after(addr_t va) const noexcept;

    [[nodiscard]] std::optional<FuncWindow> window_for(const DiscoveredFunction& fn) const;

    [[nodiscard]] Result<std::string> disassembly(const FuncWindow& w) const;
    [[nodiscard]] Result<std::string> pseudocode(const FuncWindow& w, LineMap* map) const;
    [[nodiscard]] const std::vector<StringEntry>& string_table();
};

[[nodiscard]] Result<std::unique_ptr<Session>>
open_session(const std::filesystem::path& path);

// Name as the Functions window and status bar show it: demangled when
// the core's Itanium demangler can handle it, raw otherwise. Linker
// suffixes such as `.llvm.123` or `.cold` are dropped before demangling
// so Rust and LTO-split symbols still come out readable.
[[nodiscard]] std::string display_name(std::string_view raw);

}  // namespace ember::gui
