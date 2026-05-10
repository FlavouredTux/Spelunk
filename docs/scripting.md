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

[field]
do_thing:name+0x10 = length       # signature param name
do_thing:a1+0x18   = flags        # ABI arg slot, 1-based

[constant]                         # [const] is accepted too
0xDEADBEEF = kernel32_CreateFileW_hash
31337      = protocol_magic

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
0xDEADBEEF = constant
log_handler = all                    # drop rename + note + signature + fields
```

### Sections

| Section | Separator | LHS | RHS |
|---------|-----------|-----|-----|
| `[rename]` | `=` | hex VA, `sub_<hex>`, symbol, or existing rename | new name |
| `[note]` | `=` | same as rename | free-form text |
| `[signature]` | `=` | same as rename | C-style decl: `<ret> <name>(<params>)` |
| `[field]` | `=` | `<function>:<param>+<offset>` | field name for pseudo-C struct rendering |
| `[constant]` / `[const]` | `=` | decimal or hex integer value | name for pseudo-C immediates |
| `[pattern-rename]` | `->` | glob over discovered function names (`*`) | template using `*` |
| `[from-strings]` | `->` | `printf`-style pattern (`%s`/`%d`/`%x`/`%*`) | template using `$1..$9` |
| `[delete]` | `=` | same as rename, or integer for `constant` | one of `rename`, `note`, `signature`, `field`, `constant`, `all` |

Section names are case-insensitive. Sections may repeat; directives are
applied in source order *within their pass* (see below).

### Apply order

1. `[delete]` — runs first, so a `[delete]` followed by a `[rename]` in
   the same file clears the old slot before the new value lands. Source
   order between the two does not matter; semantics are pass-based.
2. `[rename]`, `[note]`, `[signature]` — direct user-intent sections.
   `[field]` and `[constant]` run here too; fields can refer to signature
   parameter names declared earlier in the same file.
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

### Provenance (`; conf=… ; src=… ; ev=…`)

`[rename]`, `[note]`, and `[signature]` directives accept an optional
metadata suffix carrying confidence + source + evidence:

```ember
[rename]
0x401234 = do_thing ; conf=0.9 ; src=agent:namer ; ev=3-arg, called by 0x401120

[note]
0x401234 = entry point ; conf=0.7 ; src=cli

[signature]
0x401234 = int do_thing(char* name, int x) ; conf=0.85 ; src=hand
```

The suffix marker is **space-semicolon-space** (` ; `) — anchored by
the leading whitespace, so a literal `;` in a note value (e.g.
`0x401234 = step 1; step 2`) does NOT trigger metadata parsing.
Within the suffix, pairs are separated by `;`; each pair is
`key=value`, split on the first `=`.

Recognised keys:

- `conf=<float>` — 0..1, clamped on load.
- `src=<tag>` — short identifier for who's claiming. By convention
  `cli` (typed by hand), `agent:<role>` (worker in the agent harness),
  `import` (derived from binary symbols).
- `ev=<text>` — free-form reason. Ends at the next `;` in the
  suffix block, so embed `;` in evidence by replacing it with
  `,` upstream (the agent harness does this in `metaSuffix`).

Unknown keys are silently ignored — older ember reading a newer
script keeps the rename/note/signature, just drops the metadata.

Provenance lands in parallel maps (`rename_meta` / `note_meta` /
`signature_meta`) on the `Annotations` struct and persists in the
on-disk format as separate `meta` records (see "On-disk format"
below). `--show-provenance` surfaces it in pseudo-C output;
`--functions --json` emits it as `confidence` / `source` /
`evidence` columns.

### On-disk format

`Annotations::save` produces a flat line-per-record file. Most
records are self-describing:

```
rename <hex-addr>  <new-name>
sig    <hex-addr>  <return-type>|<param-type>|<param-name>|...
note   <hex-addr>  <text>
const  <hex-value> <name>
field  <hex-addr>  <param-index>|<hex-offset>|<field-name>
meta   <kind> <hex-addr> conf=<float>|src=<tag>|ev=<text>
```

`meta` carries provenance for one of the records above; `<kind>` is
`rename`, `note`, or `sig`. Pipes are the field separator inside the
`meta` tail; embedded `|` is `\|`. `\n` / `\r` / `\\` also escape
themselves. Unknown record kinds and unknown meta subkinds are
silently skipped, so an older ember reading a newer file pulls the
names through cleanly and just loses the metadata.

### Importing a persisted cache file

`--apply` also accepts the persisted on-disk format (the same format
`Annotations::save` writes to the cache). Useful for copying
annotations between binary versions:

```sh
# Bulk-copy renames from binary v1 to binary v2:
ember --apply ~/.cache/ember/annotations/<v1-key>/annotations.db v2.elf
```

Detection is automatic — if the file's first non-comment line starts
with `[`, it's parsed as a declarative script; if it starts with
`rename ` / `note ` / `sig ` / `meta `, it's loaded as a persisted
Annotations file and merged into the destination. Conflicts keep the
existing destination value.

### One-shot annotate

`ember annotate ADDR ...` is the single-call equivalent of writing a
one-line `.ember` file and `--apply`-ing it:

```sh
ember annotate 0x2f8908a --set-name cap_check_v2 \
    --confidence 0.9 --source agent:namer \
    --evidence "3-arg, called by 0x3f94380 with esi=immediate" \
    <binary>

# Multiple kinds in one call (rename + signature):
ember annotate 0x401234 --set-name do_thing \
    --set-signature "int do_thing(char*, int)" \
    --confidence 0.85 --source hand <binary>

# Preview only:
ember annotate 0x401234 --set-name foo --confidence 0.6 --dry-run <binary>
```

Resolves the destination using the same precedence as `--apply`
(explicit `--annotations` > `<binary>.ember-annotations` sidecar >
cache slot); the cache slot is created on first use.

### Limits

- `[pattern-rename]` glob is bare `*` — no `?`, no character classes.
- `[from-strings]` patterns can't compose; first match for a given
  address wins.
- The signature parser handles plain C declarations (`int foo(char*
  name, int x)`) but not function-pointer params or templated types.
- `[field]` names are scoped to one function parameter. The parameter can
  be a signature name (`ctx`) or an ABI slot (`a1`, `a2`, ...). Offsets
  accept decimal or hex, with optional sign.

For workflows that genuinely need expressions or control flow (walk
callees, decide based on string contents, drive renames from a CFG
shape), this format isn't the right fit. The
`Annotations` struct is exposed as a public API in
`core/include/ember/common/annotations.hpp`; build a one-off C++ tool
against `ember::core` for those cases.
