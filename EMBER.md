# Ember — agent reference

You are using **Ember**, a from-scratch reverse-engineering toolkit. This
file is your operating manual: what Ember can tell you, how to ask it,
how to read what it says back, and what it cannot do. Read once, then
treat as reference.

---

## The mental model

Ember loads a binary (ELF / Mach-O / PE / Microsoft minidump / raw region
scrape), discovers functions, lifts x86-64 (and partial AArch64 / PPC64)
to its own SSA IR, structures the CFG into `if` / `while` / `for` /
`switch` / `goto`, and emits readable pseudo-C. It runs library-function
recognition (TEEF Max), YARA-like crypto/protocol identification, full
xref + data-xref maps, and a ptrace/Mach debugger that breakpoints
against the pseudo-C view. There is no DWARF dependency; Ember invents a
source view from the binary itself.

A `.ember` annotation file persists everything you discover (renames,
type signatures, struct field names, free-form notes). Every Ember
command reads from it; `--apply` writes to it.

You drive Ember through the CLI. Output is TSV, plain text, or pseudo-C —
all designed to be parsed by another tool.

---

## The investigation loop

For an unknown binary, work in this order. Each step narrows what's
worth attention.

1. **Inventory.** What is this thing?
   ```sh
   ember <binary>                    # header, sections, imports, defined symbols
   ember --functions <binary>        # every discovered function (TSV)
   ember --strings <binary>          # printable strings + xrefs
   ember --identify <binary>         # crypto/protocol fingerprints
   ```
2. **Anchor.** Find a function whose purpose is recoverable from string
   evidence (an error message, a log format, a class name). Strings are
   the strongest single signal in stripped binaries.
   ```sh
   ember --strings <binary> | grep -i 'pcall\|version mismatch\|malloc'
   ember --refs-to '<addr_of_string>' <binary>     # who references this string
   ember --containing-fn '<code_addr>' <binary>    # which function contains this code
   ```
3. **Read.** Pull pseudo-C for the function you anchored.
   ```sh
   ember -p -s <name_or_addr> <binary>
   ember -p --ipa --resolve-calls --eh -s <fn> <binary>   # richer but slower
   ```
4. **Spread.** From an anchored function, expand outward via callers
   (`--refs-to`) and callees (`--callees`). Most binaries reveal
   themselves bottom-up: a few anchors → call graph propagates names.
5. **Persist.** Write your conclusions back as a `.ember` file and apply
   it. Subsequent Ember invocations will use your names.

---

## Commands you'll actually use

Grouped by frequency. Read the man page (`ember --help`) for the long
tail.

### Discovery
| Command | Output | Use when |
|---|---|---|
| `ember <binary>` | header + sections + imports | first contact |
| `ember --functions <binary>` | TSV: addr / size / kind / name | enumerate everything |
| `ember --functions --full-analysis <binary>` | same, deeper discovery | first pass missed obvious fns |
| `ember --strings <binary>` | `addr\|text\|xref1,xref2,...` | find anchors |
| `ember --xrefs <binary>` | `caller -> callee` per line | full call graph dump |
| `ember --data-xrefs <binary>` | TSV: target / from-pc / kind | find every read/write/lea/code-ptr |

### Reading code
| Command | Output | Use when |
|---|---|---|
| `ember -d -s <fn> <binary>` | linear disasm with annotations | low-level |
| `ember -c -s <fn> <binary>` | CFG dump with block edges | branch structure |
| `ember -p -s <fn> <binary>` | pseudo-C | default for understanding |
| `ember --disasm-at <VA> --count N <binary>` | N instructions from VA | inspect a specific spot |

### Recognition
| Command | Output | Use when |
|---|---|---|
| `ember --identify <binary>` | TSV: addr / name / category / confidence | crypto / hashes / protocols |
| `ember --teef <library> > corpus.tsv` | corpus build | build a library fingerprint |
| `ember --recognize --corpus c.tsv <binary>` | TSV: addr / current / suggested / conf | identify library functions |
| `ember --rtti <binary>` | TSV: vtable / class info | C++ class hierarchy |
| `ember --objc-names <binary>` | Mach-O ObjC method names | ObjC binaries |

### Lookups
| Command | Output | Use when |
|---|---|---|
| `ember --refs-to <VA> <binary>` | callers of VA (incl. tail-jumps + code-ptr) | "who uses this?" |
| `ember --containing-fn <VA> <binary>` | enclosing fn entry / size / name / offset | "which function is this in?" |
| `ember --callees <fn> <binary>` | classified call edges out of fn | "what does this fn call?" |
| `ember --validate <name> <binary>` | bound addr + lookalikes | sanity-check a name |

### Annotations
| Command | Effect | Use when |
|---|---|---|
| `--annotations <path>` | use this file (overrides default) | non-default sidecar |
| `--apply <path.ember>` | write annotations back | persist conclusions |
| `--apply --dry-run` | preview as TSV on stdout | audit before commit |

### Performance
- First-run heavyweight passes (`--xrefs`, `--strings`, `--arities`,
  `--fingerprints`) cache to `~/.cache/ember/`. Subsequent runs are
  instant. `--no-cache` bypasses.
- `--ipa` runs whole-program type inference; `--resolve-calls` resolves
  indirect call sites. Both add seconds; both significantly improve
  pseudo-C readability. Use them for hero functions, skip for triage.

---

## Reading the output

### `--functions` TSV
```
0x0000000000401140    0x153b    symbol    main
0x000000000040229c    0x47      sub       sub_40229c
```
Columns: `addr`, `size` (hex), `kind` (`symbol` for named, `sub` for
discovered), `name`. `sub_<hex>` names are placeholders — your job is to
replace them with meaningful ones.

### `--strings`
```
405040|format string: %s|9770,9824,a01f
405068|connection refused|3a4c
```
Columns: `addr`, `text` (escaped), comma-separated `xrefs` (instruction
VAs that reference the string). An empty xrefs column means orphan
string (unreferenced at static analysis time).

### `--xrefs`
```
0x401140 -> 0x4022a0
0x401140 -> 0x402310
```
Caller-fn-entry → callee-fn-entry. Lines are topologically sorted (leaves
first) so reading top-down gives a `main`-ward hierarchy.

### `--data-xrefs`
```
405040    9770    lea
405040    a01f    read
405068    3a4c    code-ptr
```
Columns: `target`, `from-pc`, `kind`. Kinds: `read` / `write` / `lea`
(address-taken into a data section) / `code-ptr` (address of an executable
function taken into a register, typically en route to a dispatch table).
`code-ptr` is the static signal that recovers indirect call edges through
vtables / callback lists / Lua C-API style runtime tables.

### `-p` (pseudo-C)
- Variables `a1`, `a2`, ... are ABI argument registers.
- `r_<callee>` (e.g. `r_strlen`) is the return value of a call to that
  fn — bound to a name when the receiver is used downstream.
- `sub_<hex>` is an unnamed function. Rename via the agent loop.
- `field_<hex>` is an unnamed struct field at offset hex from a
  parameter pointer. Name via `[field]` in `.ember`.
- `(*(u64*)(0x...))(...)` is an unresolved indirect call. Means: vtable
  / function-pointer table the static analyzer couldn't bottom out.
  Either run `--resolve-calls`, supply a `--trace edges.tsv`, or accept
  it as a known limit.
- `/* observed targets: a, b, c */` after a call expression: trace
  evidence of what the fn pointer dynamically resolved to.

### `--refs-to` output

```
0x401140 -> 0x405068
0x402240 -> 0x405068
0x97d8 -> 0x405068  (code-ptr)  ; sub_9780+0x58
```

First two lines: direct call edges (caller fn entry → target). Third
line: `code-ptr` — `sub_9780` takes the address of `0x405068` at
instruction `0x97d8` (likely storing it into a dispatch table). Surface
the table that lives at the destination of this `lea` to find indirect
callers.

### `--identify`
```
405068    sha256_compress    hash    0.95    constants    6a09e667,bb67ae85,...
```
Columns: `addr`, `name` (the recognized profile), `category`,
`confidence`, `signal` (what fired: `constants` / `pattern` /
`insn_seq` / a `+`-joined combination), `via` (the specific evidence —
constants matched, pattern offset, etc.).

### `--recognize`
```
40229c    sub_40229c    SHA256_Update    1.00    behav-exact    
```
Columns: `addr`, `current_name`, `suggested_name`, `confidence`, `via`,
optional `[alts]`. `via` distinguishes match paths: `behav-exact` >
`whole-exact` > `whole-jaccard+behav` > `prefix-exact` > `chunk-vote`
in trustworthiness.

---

## Writing annotations

`.ember` files are section-keyed, one directive per line, no
expressions, no control flow. Apply with `ember --apply <path>
<binary>`.

```ember
[rename]
0x401234     = parse_packet         # by hex VA
sub_4012a0   = decode_header        # by current name
log_handler  = handle_log_line      # by symbol or existing rename

[note]
0x401234 = uses scratch buffer at rsp+0x40, size capped at 4 KiB

[signature]
0x401234 = int parse_packet(struct Packet* pkt, int flags)

[field]
parse_packet:pkt+0x00 = magic       # signature param name
parse_packet:pkt+0x04 = length
parse_packet:a2+0x18  = dst_buf     # ABI slot when no signature param

[from-strings]
"[HttpClient] %s" -> HttpClient_$1  # %s captures, $1 in template
"error: %d at %s"  -> err_$2

[pattern-rename]
sub_4* -> roblox_sub_*              # glob match, * captures, * in template
log_*  -> Logger_*

[delete]
log_handler = all                   # drop rename + note + signature
0x401234    = signature             # drop just the signature
```

**Apply order matters.** Within one file: `[delete]` runs first, then
direct sections (`[rename]`, `[note]`, `[signature]`, `[field]`), then
`[pattern-rename]`, then `[from-strings]`. So a glob can rename a
function and a later direct rename can override it in the same file.

**Address resolution.** Hex VA (`0x401234`), `sub_<hex>`, current
symbol name, or existing rename — all valid LHS forms. RHS is the
literal value.

**`--dry-run`** prints the resolved TSV that *would* be written
without touching the file. Always dry-run first when the script came
from an automated source (LLM, batch tool).

---

## Confidence semantics

Numbers you'll see attached to claims, suggestions, identifications:

- **1.00** — exact-match path (behavioural-exact, whole-exact at
  unique distinct-name bucket, identify with all required constants
  matched + corroborating signals). Trust enough to auto-apply.
- **0.85 – 0.99** — high confidence. Cascade workflows promote at
  ≥ 0.85. Spot-check before bulk-applying.
- **0.60 – 0.84** — likely, but worth a human-grade glance. Especially
  for functions < 64 bytes — short-fn fingerprints collide.
- **< 0.60** — speculative. Surface for review, do not auto-rename.

If two claims for the same address are within 0.10 confidence and
disagree on value, that's a **dispute** — the right move is to gather
more evidence (xrefs, strings, callees) before picking, not to
arbitrarily promote the higher one.

---

## When Ember can't help

Stop trying these things; they're known limits, not bugs:

- **Indirect calls without IAT, constant vtable, runtime trace, or
  receiver-type fact.** They render as `(*(u64*)(0x...))(...)`.
  Workaround: feed `--trace edges.tsv` if you can collect runtime
  evidence; otherwise note the call site and move on.
- **Function pointers installed by `.init_array` ctors at runtime**
  (Lua C-API tables, plugin registration patterns). Static analysis
  doesn't see the assignment yet — the table address is computed in
  ctor code that builds the dispatch slot dynamically. `--refs-to` on
  these returns empty even though they're called constantly.
  Workaround: identify the ctor, read its pseudo-C, manually note the
  table slot ↔ fn mapping.
- **AArch64 floating-point and Advanced SIMD** lift as
  `arm64.<op>(...)` intrinsics. Shape-only, not modelled. SVE / SME
  unmapped.
- **PPC64** stops at CFG. No lifter, no pseudo-C.
- **Switch defaults** outside the bounds-check guard can misattribute
  to a wrong case label.
- **MSVC demangle** is partial (Itanium is comprehensive). Don't trust
  every MSVC name verbatim.
- **Computed-goto VM dispatchers** (one big function with `jmp [tab+rax*8]`
  to internal labels) aren't real callers from the compiler's POV.
  `--refs-to` on the "labels" returns nothing because they're not
  separate functions. Use `--vm-detect` to find the dispatcher.
- **Anti-debug / packed binaries** that flip section permissions at
  runtime: load a runtime memory image instead — Microsoft minidump
  (`ember -p ./crash.dmp`) or a `--regions <manifest>` scrape.

---

## Quick recipes

**"Find this function's purpose without DWARF."**
```sh
ember --strings <binary> | grep -i '<probable error message in fn>'
# → grep returns: 0x405068|the message|3a4c,9770
ember --containing-fn 0x3a4c <binary>
# → 0x402240  0x4f  symbol  do_thing  0x10
```

**"Who calls this address?"**
```sh
ember --refs-to 0x402240 <binary>
# Surfaces direct calls + tail-jumps + code-ptr (address-taken into tables).
```

**"What library is this?"**
```sh
ember --identify <binary>     # YARA-like (crypto/hash/encoding)
ember --recognize --corpus libcrypto.tsv --corpus libssl.tsv <binary>
                              # TEEF Max — cross-compiler library-fn ID
```

**"What's at this hex address?"**
```sh
ember --containing-fn 0x405068 <binary>     # if it's code
ember --strings <binary> | grep '^405068|' # if it's a string
ember --data-xrefs <binary> | awk '$1=="405068"'  # who reads/writes it
```

**"Persist a batch of renames."**
```sh
cat > project.ember <<EOF
[rename]
sub_402240 = parse_packet
sub_4022a0 = decode_header
[signature]
parse_packet  = int parse_packet(struct Packet* pkt, int flags)
decode_header = u32 decode_header(const u8* buf, size_t len)
[field]
parse_packet:pkt+0x00 = magic
parse_packet:pkt+0x04 = length
EOF
ember --apply project.ember --dry-run <binary>     # preview
ember --apply project.ember <binary>               # commit
ember -p -s parse_packet <binary>                  # see your names in pseudo-C
```

**"Find every function-pointer table init."**
```sh
ember --data-xrefs <binary> | awk '$3=="code-ptr"' \
  | sort -k2 | head -50
# Each `code-ptr` line is "function whose address gets stored somewhere."
# Cluster by from_pc to find the ctor that writes the table.
```

---

## Output you can rely on

- TSV columns are stable. Field separators are tabs unless noted (`--strings`
  uses `|` because text fields contain tabs).
- Hex addresses are always `0x`-prefixed in human-facing output and
  *unprefixed* in TSV columns.
- `sub_<hex>` is the canonical placeholder name. Treat any name matching
  `^sub_[0-9a-f]+$` as "unnamed" for cascade-style decisions.
- Pseudo-C output is deterministic for a given binary + annotations +
  flag combination. Cache the output keyed on those.

---

If a command in this file disagrees with `ember --help` on a recent
binary, trust `--help` — Ember's CLI is the source of truth, this
document is a curated subset.
