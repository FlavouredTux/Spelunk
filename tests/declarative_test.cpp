// Unit tests for the .ember declarative scripting format.
//
// Self-contained: a tiny MockBinary carries one defined function plus a
// rodata string the function references via lea, so [from-strings]
// has a real string→containing-fn pipeline to walk.
#include <ember/script/declarative.hpp>
#include <ember/binary/binary.hpp>
#include <ember/common/annotations.hpp>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

namespace {

int fails = 0;

template <typename A, typename B>
void check_eq(const A& got, const B& want, const char* ctx) {
    if (!(got == want)) {
        std::fprintf(stderr, "FAIL: %s\n", ctx);
        ++fails;
    }
}

void check_eq_sz(std::size_t got, std::size_t want, const char* ctx) {
    if (got != want) {
        std::fprintf(stderr, "FAIL: %s (got %zu, want %zu)\n",
                     ctx, got, want);
        ++fails;
    }
}

void check_eq_str(std::string_view got, std::string_view want, const char* ctx) {
    if (got != want) {
        std::fprintf(stderr, "FAIL: %s (got '%.*s', want '%.*s')\n",
                     ctx,
                     static_cast<int>(got.size()), got.data(),
                     static_cast<int>(want.size()), want.data());
        ++fails;
    }
}

void check(bool cond, const char* ctx) {
    if (!cond) {
        std::fprintf(stderr, "FAIL: %s\n", ctx);
        ++fails;
    }
}

// A tiny x86-64 image: one defined function `log_handler` at 0x401000
// that does `lea rax, [rip+0xff9]; ret` — the lea targets 0x402000 in
// .rodata, where the string "[HttpClient] hello" lives.
//
// Exact byte layout:
//   .text (exec, r) at 0x401000, 0x10 bytes
//     48 8d 05 f9 0f 00 00   lea rax, [rip + 0xff9]
//     c3                     ret
//     90 90 90 ...           padding (NOPs)
//   .rodata (r-only) at 0x402000, 0x20 bytes
//     "[HttpClient] hello\0..."
constexpr ember::addr_t kFnAddr      = 0x401000;
constexpr ember::addr_t kStrAddr     = 0x402000;
constexpr std::size_t   kTextLen     = 0x10;
constexpr std::size_t   kRodataLen   = 0x20;

struct CodeBytes {
    std::array<std::byte, kTextLen> data{};
    CodeBytes() {
        for (auto& b : data) b = static_cast<std::byte>(0x90u);
        const std::array<unsigned, 8> fn = {
            0x48u, 0x8du, 0x05u, 0xf9u, 0x0fu, 0x00u, 0x00u,  // lea rax,[rip+0xff9]
            0xc3u,                                            // ret
        };
        for (std::size_t i = 0; i < fn.size(); ++i) {
            data[i] = static_cast<std::byte>(fn[i]);
        }
    }
};

struct RodataBytes {
    std::array<std::byte, kRodataLen> data{};
    RodataBytes() {
        constexpr std::string_view s = "[HttpClient] hello";
        for (std::size_t i = 0; i < s.size() && i < kRodataLen; ++i) {
            data[i] = static_cast<std::byte>(s[i]);
        }
    }
};

class MockBinary final : public ember::Binary {
public:
    MockBinary() {
        text_.name = ".text";
        text_.vaddr = kFnAddr;
        text_.size  = kTextLen;
        text_.flags.executable = true;
        text_.flags.readable   = true;
        text_.data = std::span<const std::byte>(code_.data.data(), code_.data.size());

        ro_.name = ".rodata";
        ro_.vaddr = kStrAddr;
        ro_.size  = kRodataLen;
        ro_.flags.readable = true;
        ro_.data = std::span<const std::byte>(rodata_.data.data(), rodata_.data.size());

        secs_ = {text_, ro_};

        ember::Symbol s;
        s.name = "log_handler";
        s.addr = kFnAddr;
        s.size = kTextLen;
        s.kind = ember::SymbolKind::Function;
        syms_.push_back(std::move(s));
    }

    [[nodiscard]] ember::Format format() const noexcept override { return ember::Format::Elf; }
    [[nodiscard]] ember::Arch   arch()   const noexcept override { return ember::Arch::X86_64; }
    [[nodiscard]] ember::Endian endian() const noexcept override { return ember::Endian::Little; }
    [[nodiscard]] ember::addr_t entry_point() const noexcept override { return kFnAddr; }
    [[nodiscard]] std::span<const ember::Section> sections() const noexcept override { return secs_; }
    [[nodiscard]] std::span<const ember::Symbol>  symbols()  const noexcept override { return syms_; }

protected:
    [[nodiscard]] std::vector<ember::Symbol>& mutable_symbols() noexcept override { return syms_; }
public:
    [[nodiscard]] std::span<const std::byte>      image()    const noexcept override { return text_.data; }

private:
    CodeBytes                  code_{};
    RodataBytes                rodata_{};
    ember::Section             text_{};
    ember::Section             ro_{};
    std::array<ember::Section, 2> secs_{};
    std::vector<ember::Symbol>    syms_{};
};

fs::path scratch_root() {
    auto p = fs::temp_directory_path() / "ember_declarative_test";
    std::error_code ec;
    fs::remove_all(p, ec);
    fs::create_directories(p);
    return p;
}

fs::path write_text(const fs::path& dir, std::string_view name, std::string_view body) {
    const auto p = dir / name;
    std::ofstream o(p);
    o.write(body.data(), static_cast<std::streamsize>(body.size()));
    return p;
}

}  // namespace

int main() {
    using ember::script::Directive;

    // ---- Parser: sections, comments, separators ---------------------------
    {
        constexpr std::string_view src =
            "# top of file\n"
            "\n"
            "[rename]\n"
            "0x401000 = log_handler\n"
            "log_handler = handle_log_line   # trailing\n"
            "\n"
            "[note]\n"
            "0x401000 = entry point\n"
            "\n"
            "[signature]\n"
            "0x401000 = int log_handler(char* msg, int level)\n"
            "[field]\n"
            "0x401000:msg+0x10 = length\n"
            "\n"
            "[pattern-rename]\n"
            "sub_4* -> roblox_sub_*\n"
            "\n"
            "[from-strings]\n"
            "\"[HttpClient] %s\" -> HttpClient_$1\n";

        auto rv = ember::script::parse(src);
        check(rv.has_value(), "parse: clean input parses");
        if (!rv) std::fprintf(stderr, "  err: %s\n", rv.error().message.c_str());
        if (rv) {
            check_eq_sz(rv->size(), 7, "parse: 7 directives");
            if (rv->size() >= 7) {
                const auto& ds = *rv;
                check_eq(static_cast<int>(ds[0].kind),
                         static_cast<int>(Directive::Kind::Rename), "parse: d0 rename");
                check_eq_str(ds[0].lhs, "0x401000",                 "parse: d0 lhs");
                check_eq_str(ds[0].rhs, "log_handler",              "parse: d0 rhs");
                check_eq_str(ds[1].rhs, "handle_log_line",          "parse: d1 rhs (trim trailing comment? no)");
                check_eq(static_cast<int>(ds[2].kind),
                         static_cast<int>(Directive::Kind::Note),   "parse: d2 note");
                check_eq(static_cast<int>(ds[3].kind),
                         static_cast<int>(Directive::Kind::Signature), "parse: d3 sig");
                check_eq(static_cast<int>(ds[4].kind),
                         static_cast<int>(Directive::Kind::Field), "parse: d4 field");
                check_eq_str(ds[4].lhs, "0x401000:msg+0x10", "parse: d4 field lhs");
                check_eq_str(ds[4].rhs, "length",            "parse: d4 field rhs");
                check_eq(static_cast<int>(ds[5].kind),
                         static_cast<int>(Directive::Kind::PatternRename), "parse: d5 pattern");
                check_eq_str(ds[5].lhs, "sub_4*",         "parse: d5 lhs glob");
                check_eq_str(ds[5].rhs, "roblox_sub_*",   "parse: d5 rhs template");
                check_eq(static_cast<int>(ds[6].kind),
                         static_cast<int>(Directive::Kind::FromStrings), "parse: d6 from-strings");
                check_eq_str(ds[6].lhs, "[HttpClient] %s", "parse: d6 unquoted lhs");
                check_eq_str(ds[6].rhs, "HttpClient_$1",   "parse: d6 template");
            }
        }
    }

    // ---- Parser: errors ----------------------------------------------------
    {
        check(!ember::script::parse("0x401000 = foo\n").has_value(),
              "parse: directive outside any section errors");
        check(!ember::script::parse("[rename]\nfoo bar baz\n").has_value(),
              "parse: missing separator errors");
        check(!ember::script::parse("[unknown]\nfoo = bar\n").has_value(),
              "parse: unknown section errors");
        check(!ember::script::parse("[rename\n").has_value(),
              "parse: unterminated section header errors");
        check(!ember::script::parse("[rename]\nfoo -> bar\n").has_value(),
              "parse: [rename] rejects `->`");
        check(!ember::script::parse("[pattern-rename]\nfoo = bar\n").has_value(),
              "parse: [pattern-rename] rejects `=`");
    }

    // ---- Apply: direct sections -------------------------------------------
    MockBinary mb;
    {
        ember::Annotations ann;
        const std::vector<Directive> ds = {
            {Directive::Kind::Rename,    "0x401000",    "renamed_by_va",                                                    1},
            {Directive::Kind::Rename,    "log_handler", "skipped_due_to_first_win",                                          2},
            {Directive::Kind::Note,      "0x401000",    "this is a note",                                                    3},
            {Directive::Kind::Signature, "0x401000",    "int log_handler(char* msg, int level)",                             4},
            {Directive::Kind::Field,     "0x401000:msg+0x10", "length",                                                       5},
            {Directive::Kind::Field,     "0x401000:a1+0x18",  "flags",                                                        6},
        };
        auto st = ember::script::apply(ds, mb, ann);
        check_eq_sz(st.renames_added,    1, "apply: 1 rename added (first wins)");
        check_eq_sz(st.notes_added,      1, "apply: 1 note added");
        check_eq_sz(st.signatures_added, 1, "apply: 1 signature added");
        check_eq_sz(st.fields_added,     2, "apply: 2 fields added");
        check(ann.renames.contains(0x401000),  "apply: rename map has 0x401000");
        if (auto* n = ann.name_for(0x401000)) check_eq_str(*n, "renamed_by_va", "apply: rename value");
        if (auto* n = ann.note_for(0x401000)) check_eq_str(*n, "this is a note", "apply: note value");
        if (auto* s = ann.signature_for(0x401000)) {
            check_eq_str(s->return_type, "int", "apply: sig return type");
            check_eq_sz(s->params.size(), 2,    "apply: sig 2 params");
            if (s->params.size() == 2) {
                check_eq_str(s->params[0].type, "char*", "apply: sig p0 type");
                check_eq_str(s->params[0].name, "msg",   "apply: sig p0 name");
                check_eq_str(s->params[1].type, "int",   "apply: sig p1 type");
                check_eq_str(s->params[1].name, "level", "apply: sig p1 name");
            }
        }
        if (auto* f = ann.field_name_for(0x401000, 0, 0x10)) {
            check_eq_str(*f, "length", "apply: field by param name");
        }
        if (auto* f = ann.field_name_for(0x401000, 0, 0x18)) {
            check_eq_str(*f, "flags", "apply: field by a1");
        }
        // The second rename targeted the same address by name lookup; with
        // first-win semantics, it should have produced one warning and no
        // additional rename count.
        check(!st.warnings.empty(), "apply: dup rename warned");
    }

    // ---- Apply: name resolution falls back to user renames ----------------
    {
        ember::Annotations ann;
        ann.renames[0x401000] = "user_first";
        const std::vector<Directive> ds = {
            {Directive::Kind::Note, "user_first", "found via existing rename", 1},
        };
        auto st = ember::script::apply(ds, mb, ann);
        check_eq_sz(st.notes_added, 1, "apply: name-resolves-via-existing-rename");
    }

    // ---- Apply: pattern-rename --------------------------------------------
    {
        ember::Annotations ann;
        // No prior rename → discovered name from symbol is "log_handler".
        // Pattern `log_*` -> `Logger_*` should match and produce
        // "Logger_handler".
        const std::vector<Directive> ds = {
            {Directive::Kind::PatternRename, "log_*", "Logger_*", 1},
        };
        auto st = ember::script::apply(ds, mb, ann);
        check_eq_sz(st.pattern_renames_applied, 1, "apply: pattern-rename matched 1");
        if (auto* n = ann.name_for(0x401000)) {
            check_eq_str(*n, "Logger_handler", "apply: pattern-rename value");
        }
    }

    // ---- Apply: pattern doesn't override an existing user rename ----------
    {
        ember::Annotations ann;
        ann.renames[0x401000] = "user_choice";
        const std::vector<Directive> ds = {
            {Directive::Kind::PatternRename, "log_*", "Logger_*", 1},
        };
        auto st = ember::script::apply(ds, mb, ann);
        check_eq_sz(st.pattern_renames_applied, 0, "apply: pattern can't beat user rename");
        if (auto* n = ann.name_for(0x401000)) {
            check_eq_str(*n, "user_choice", "apply: user rename preserved");
        }
    }

    // ---- Apply: from-strings (lea xref → containing-fn rename) ------------
    {
        ember::Annotations ann;
        const std::vector<Directive> ds = {
            {Directive::Kind::FromStrings, "[HttpClient] %s", "HttpClient_$1", 1},
        };
        auto st = ember::script::apply(ds, mb, ann);
        check_eq_sz(st.string_renames_applied, 1, "apply: from-strings 1 fn renamed");
        if (auto* n = ann.name_for(0x401000)) {
            check_eq_str(*n, "HttpClient_hello", "apply: from-strings rendered $1");
        }
    }

    // ---- Apply: [delete] removes existing entries -------------------------
    {
        ember::Annotations ann;
        ann.renames[0x401000]    = "old_rename";
        ann.notes[0x401000]      = "old_note";
        ann.field_names[{0x401000, 0, 0x10}] = "old_field";
        ember::FunctionSig sig;
        sig.return_type = "int";
        ann.signatures[0x401000] = sig;
        const std::vector<Directive> ds = {
            {Directive::Kind::Delete, "0x401000", "rename",    1},
            {Directive::Kind::Delete, "0x401000", "note",      2},
            {Directive::Kind::Delete, "0x401000", "signature", 3},
            {Directive::Kind::Delete, "0x401000", "field",     4},
        };
        auto st = ember::script::apply(ds, mb, ann);
        check_eq_sz(st.renames_removed,    1, "delete: rename removed");
        check_eq_sz(st.notes_removed,      1, "delete: note removed");
        check_eq_sz(st.signatures_removed, 1, "delete: signature removed");
        check_eq_sz(st.fields_removed,     1, "delete: field removed");
        check(!ann.renames.contains(0x401000),    "delete: rename gone");
        check(!ann.notes.contains(0x401000),      "delete: note gone");
        check(!ann.signatures.contains(0x401000), "delete: signature gone");
        check(ann.field_names.empty(),            "delete: fields gone");
    }

    // ---- Apply: [delete]=all clears all three at once ---------------------
    {
        ember::Annotations ann;
        ann.renames[0x401000]    = "x";
        ann.notes[0x401000]      = "y";
        ember::FunctionSig sig;
        sig.return_type = "void";
        ann.signatures[0x401000] = sig;
        ann.field_names[{0x401000, 0, 0x10}] = "xfield";
        const std::vector<Directive> ds = {
            {Directive::Kind::Delete, "log_handler", "all", 1},
        };
        auto st = ember::script::apply(ds, mb, ann);
        check_eq_sz(st.renames_removed,    1, "delete=all: rename removed");
        check_eq_sz(st.notes_removed,      1, "delete=all: note removed");
        check_eq_sz(st.signatures_removed, 1, "delete=all: sig removed");
        check_eq_sz(st.fields_removed,     1, "delete=all: field removed");
    }

    // ---- Apply: [delete] runs before [rename] (pass 0) --------------------
    // Mixing delete + rename in one file should land on the new rename
    // value, never the old one. The pre-loaded "old" gets cleared in
    // pass 0, then "new_handler" lands in pass 1.
    {
        ember::Annotations ann;
        ann.renames[0x401000] = "old";
        const std::vector<Directive> ds = {
            {Directive::Kind::Rename, "0x401000", "new_handler", 1},
            {Directive::Kind::Delete, "0x401000", "rename",      2},
        };
        auto st = ember::script::apply(ds, mb, ann);
        check_eq_sz(st.renames_removed, 1, "delete+rename: removed old");
        check_eq_sz(st.renames_added,   1, "delete+rename: added new");
        if (auto* n = ann.name_for(0x401000)) {
            check_eq_str(*n, "new_handler", "delete+rename: new value wins");
        }
    }

    // ---- Apply: [delete] unknown kind warns -------------------------------
    {
        ember::Annotations ann;
        const std::vector<Directive> ds = {
            {Directive::Kind::Delete, "0x401000", "bogus", 1},
        };
        auto st = ember::script::apply(ds, mb, ann);
        check(!st.warnings.empty(), "delete: unknown kind warns");
    }

    // ---- Annotations::to_text round-trips through load --------------------
    {
        ember::Annotations original;
        original.renames[0x401000] = "round_trip";
        original.notes[0x401000]   = "with #hash and \\n newline";
        ember::FunctionSig sig;
        sig.return_type = "int";
        sig.params.push_back({"char*", "msg"});
        sig.params.push_back({"int",   "level"});
        original.signatures[0x401000] = sig;
        original.field_names[{0x401000, 0, 0x10}] = "length";

        const auto root = scratch_root();
        const auto p = root / "round.proj";
        std::ofstream o(p);
        const std::string text = original.to_text();
        o.write(text.data(), static_cast<std::streamsize>(text.size()));
        o.close();

        auto reloaded = ember::Annotations::load(p);
        check(reloaded.has_value(), "to_text: file reloads");
        if (reloaded) {
            check_eq_sz(reloaded->renames.size(),    1, "to_text: 1 rename round-trips");
            check_eq_sz(reloaded->notes.size(),      1, "to_text: 1 note round-trips");
            check_eq_sz(reloaded->signatures.size(), 1, "to_text: 1 sig round-trips");
            check_eq_sz(reloaded->field_names.size(), 1, "to_text: 1 field round-trips");
            if (auto* n = reloaded->name_for(0x401000)) {
                check_eq_str(*n, "round_trip", "to_text: rename round-trip value");
            }
        }
    }

    // ---- apply_file end-to-end --------------------------------------------
    {
        const auto root = scratch_root();
        const auto p = write_text(root, "test.ember",
            "[rename]\n"
            "0x401000 = end_to_end\n"
            "[note]\n"
            "log_handler = via name lookup\n"
            "[signature]\n"
            "log_handler = void log_handler(char* msg)\n"
            "[field]\n"
            "log_handler:msg+0x10 = length\n");
        ember::Annotations ann;
        auto rv = ember::script::apply_file(p, mb, ann);
        check(rv.has_value(), "apply_file: ok");
        if (rv) {
            check_eq_sz(rv->renames_added,    1, "apply_file: 1 rename");
            check_eq_sz(rv->notes_added,      1, "apply_file: 1 note");
            check_eq_sz(rv->signatures_added, 1, "apply_file: 1 sig");
            check_eq_sz(rv->fields_added,     1, "apply_file: 1 field");
        }
        if (auto* n = ann.name_for(0x401000)) check_eq_str(*n, "end_to_end", "apply_file: rename");
        if (auto* n = ann.note_for(0x401000)) check_eq_str(*n, "via name lookup", "apply_file: note");
    }

    if (fails) {
        std::fprintf(stderr, "%d failure(s)\n", fails);
        return 1;
    }
    std::fprintf(stderr, "all declarative tests passed\n");
    return 0;
}
