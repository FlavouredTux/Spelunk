# Ember Scripting

Ember scripts are declarative `.ember` files consumed by `ember --apply
PATH`. The format is flat and section-keyed; every directive is a
single `key = value` (or `pattern -> template`) pair, no expressions or
control flow. Scripts populate the same `Annotations` struct that drives
emit-time rename / signature / note rendering.

The on-disk annotation file is plain TSV (loaded by `Annotations::load`,
written by `Annotations::save`); `.ember` is the friendly authoring
surface above it.

## Running

```sh
ember --apply project.ember --annotations out.proj <binary>
ember --apply project.ember --dry-run <binary>          # preview only
```

The applier resolves the destination annotation file the same way emit
does (`--annotations` → `<binary>.ember-annotations` sidecar →
`~/.cache/ember/annotations/<key>`), loads the existing contents (if
any), applies the directives, writes back. User intent beats inference:
any address that already carries a rename in the loaded annotations
survives a `[pattern-rename]` or `[from-strings]` match unchanged.

## Format

```ember
# Lines starting with `#` are comments. ` # …` after whitespace mid-line
# is a trailing comment too (but `note = see ticket #42` keeps `#42`).

[rename]
0x401234   = do_thing
sub_4051a0 = main_loop
log_handler = handle_log_line     # by symbol or existing rename

[note]
0x401234 = entry point; see ticket #42

[signature]
0x401234   = int do_thing(char* name, int x)
log_handler = void log_handler(void)

[pattern-rename]
sub_4* -> roblox_sub_*            # `*` in template = matched part
log_*  -> Logger_*

[from-strings]
"[HttpClient] %s" -> HttpClient_$1   # %s/%d/%x/%* capture into $1, $2, …
"NetworkClient::%s" -> NetworkClient_$1

[delete]
0x401234   = rename                  # drop one entry kind
0x401234   = note
0x401234   = signature
log_handler = all                    # drop rename + note + signature
```

### Sections

| Section | Separator | LHS | RHS |
|---------|-----------|-----|-----|
| `[rename]` | `=` | hex VA, `sub_<hex>`, symbol, or existing rename | new name |
| `[note]` | `=` | same as rename | free-form text |
| `[signature]` | `=` | same as rename | C-style decl: `<ret> <name>(<params>)` |
| `[pattern-rename]` | `->` | glob over discovered function names (`*`) | template using `*` |
| `[from-strings]` | `->` | `printf`-style pattern (`%s`/`%d`/`%x`/`%*`) | template using `$1..$9` |
| `[delete]` | `=` | same as rename | one of `rename`, `note`, `signature`, `all` |

Section names are case-insensitive. Sections may repeat; directives are
applied in source order *within their pass* (see below).

### Apply order

1. `[delete]` — runs first, so a `[delete]` followed by a `[rename]` in
   the same file clears the old slot before the new value lands. Source
   order between the two does not matter; semantics are pass-based.
2. `[rename]`, `[note]`, `[signature]` — direct user-intent sections.
3. `[pattern-rename]` — walks `enumerate_functions()` and matches the
   current name (existing rename if any, else the discovered name).
   Skips any address with an existing rename.
4. `[from-strings]` — walks `scan_strings()`, captures from each match,
   resolves the containing function for every xref instruction, applies
   the templated rename to each. Skips any address with an existing
   rename.

### Dry run

`--dry-run` parses + applies the file in memory but doesn't write the
result. The would-be annotation TSV is dumped to stdout (so you can
`diff` against the current file or pipe to a reviewer); the apply stats
+ proposed destination still go to stderr.

```sh
ember --apply project.ember --dry-run --annotations current.proj <binary>
ember --apply project.ember --dry-run --annotations current.proj <binary> \
    | diff -u current.proj -
```

### Quoting and escapes

Values containing spaces, `=`, `->`, `#`, or `%` should be quoted with
`"..."`. Standard escapes: `\\`, `\"`, `\n`, `\r`, `\t`. Unquoted values
are taken verbatim from the trimmed line.

### Limits

- `[pattern-rename]` glob is bare `*` — no `?`, no character classes.
- `[from-strings]` patterns can't compose; first match for a given
  address wins.
- The signature parser handles plain C declarations (`int foo(char*
  name, int x)`) but not function-pointer params or templated types.

For workflows that genuinely need expressions or control flow (walk
callees, decide based on string contents, drive renames from a CFG
shape), this format isn't the right fit. The
`Annotations` struct is exposed as a public API in
`core/include/ember/common/annotations.hpp`; build a one-off C++ tool
against `ember::core` for those cases.
