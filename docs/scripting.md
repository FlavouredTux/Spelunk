# Ember Scripting API

Reference for `ember --script PATH <binary> [-- args...]`. The script runs
inside a sandboxed QuickJS context with a small set of read-only and
staging globals pointing at the loaded `<binary>`. Mutations need
`--project PATH` (or an auto-resolved annotations file — see below).

## Running scripts

```sh
ember --script scripts/names.js <binary> -- dump
ember --script scripts/query.js --project proj.ann <binary> -- <query>
```

Arguments after the `--` separator appear in `argv`. `argv[0]` is the
**first** user argument, not the script path; there is no `argv[-1]` or
`process.argv` — QuickJS is not Node.

Annotations auto-load in this precedence: `--project`/`--annotations` →
`<binary>.ember-annotations` sidecar → `~/.cache/ember/annotations/<key>`.
When any of those exists, `project.*` mutations are enabled. `--no-cache`
bypasses the cache path.

## Global surface at a glance

| Global | Purpose |
|--------|---------|
| `binary` | Everything about the loaded binary: metadata, bytes, symbols, analyses. |
| `xrefs` | Call and data cross-references. |
| `strings` | String literal scanner. |
| `project` | Staging buffer for renames / signatures / notes — write via mutators, persist via `commit()`. |
| `log` | `log.info` → stdout, `log.warn` / `log.error` → stderr. |
| `print` | `console.log` stand-in. Joins args with spaces, adds newline. |
| `io` | `io.read(path)` → string, `io.write(path, content)` → undefined. |
| `argv` | Array of strings passed after `--`. |

There is no `console`, no `fs`, no `crypto`, no `process`, no `require` —
this is a QuickJS sandbox with the surface listed here, nothing else.

## Gotchas worth calling out first

- `binary.bytesAt(addr, len)` returns **`ArrayBuffer`**, not
  `Uint8Array`. Use `new Uint8Array(buf)` to index bytes or
  `new DataView(buf).getBigUint64(0, true)` to read a LE u64.
- Addresses are `BigInt`. Format with `'0x' + addr.toString(16)`; don't
  pass `Number` into `symbolAt`/`bytesAt`/etc. unless the value fits.
- `print(x)` ≠ `console.log(x)`. Only `print`, `log.info`, `log.warn`,
  `log.error` write to the host tty.
- Pseudo-C and disassembly come back as strings. Parse them with string
  utilities; they are not JSON.

## `binary.*`

Metadata (properties, not calls):

- `arch` — `"x86_64" | "x86" | "arm64" | "arm" | "ppc32" | "ppc64" | "riscv32" | "riscv64" | "unknown"`.
- `endian` — `"little" | "big" | "unknown"`.
- `format` — `"elf" | "mach-o" | "pe" | "unknown"`.
- `entry` — `BigInt` entry-point address.

Symbols and sections:

- `symbols()` → `Array<{ name, addr, size, kind, isImport, isExport, gotAddr? }>`.
  `kind` is `"function" | "object" | "other"`. `addr`/`size`/`gotAddr` are `BigInt`.
- `sections()` → `Array<{ name, addr, size, readable, writable, executable }>`.
- `findSymbol(name)` → symbol object or `null`.
- `symbolAt(addr)` → symbol containing `addr`, or `null`.

Bytes:

- `bytesAt(addr, len = 16)` → `ArrayBuffer`. Zero-length result means
  either no bytes are mapped or the range lies in BSS (indistinguishable
  from "not in file" today).
- `findBytes(pattern, maxResults = 64)` → `Array<BigInt>`. Pattern is a
  hex string with optional spaces: `"0f 57 c0"`, `"48 8b"`.
- `stringAt(addr, maxLen = 256)` → string or `null`. NUL-terminated only.

Analyses (heavy — each result is memoised for the script run):

- `decompile(addr | symbol)` → pseudo-C source as a string. Accepts a VA
  or a name (`"main"`, `"sub_401020"`).
- `disasm(addr, len = 32)` → assembly block as a string.
- `disasmRange(start, end)` → assembly from `start` to `end`.
- `cfg(addr)` → control-flow graph text representation.
- `fingerprint(addr)` → `{ hash: "0x...", blocks, insts, calls } | null`.
  Address-independent content hash — stable across recompiles.
- `functions()` → `Array<{ name, addr, size, blocks, edges, calls }>`.
- `functionAt(addr)` → function entry object covering `addr`, or `null`.

Higher-level domain helpers (return empty arrays on formats where they
don't apply):

- `stdString(addr)` → decoded libc++ / libstdc++ `std::string`, or `null`.
- `objcMethods()` — Mach-O Obj-C method list.
- `objcProtocols()` — Mach-O Obj-C protocol list.
- `rtti()` — Itanium C++ RTTI: classes, typeinfo, vtable, methods.
- `vmDispatchers()` — heuristic interpreter-dispatcher scan.

Manual call-graph edits:

- `recordIndirectEdge(site, target)` — teach the CFG that an indirect
  call at `site` resolves to `target` for this script run only.
- `indirectEdges(addr)` → `Array<BigInt>` of currently-recorded targets.
- `clearIndirectEdges()`.

## `xrefs.*`

All four take a target VA and return plain arrays.

- `callers(addr)` → `Array<{ site, kind }>` — who calls this function.
  `kind` is `"direct" | "tail" | "indirect_const"`.
- `callees(addr)` → `Array<{ site, kind }>` — who this function calls.
- `data(addr)` → `Array<{ site, kind }>` — rip-rel / absolute data refs.
  `kind` is `"read" | "write" | "lea"`.
- `to(addr)` → union of `callers` + `data` for a single query.

## `strings.*`

- `strings.search(pattern)` → `Array<{ str, xrefs: Array<BigInt> }>`.
  Pattern accepts a literal string or a `RegExp` object.
- `strings.xrefs(pattern)` — same, but filters out strings with no
  xrefs (trims noise when you only care about live uses).

## `project.*` (staging buffer)

Available when `--project`, `--annotations`, an existing sidecar, or a
cached annotation file is resolvable. All mutators accept an optional
final `opts` object:

- `{ dryRun: true }` — return the diff entry but don't stage.
- `{ force: true }` — **`rename` only** — bypass the "name already
  bound to a different address" check. Use for intentional aliases; the
  check otherwise throws to prevent collision import disasters.

Mutators:

- `project.rename(addr, name, opts?)` — stage `addr → name`.
- `project.setSignature(addr, { returnType, params: [{ type, name }] }, opts?)`.
- `project.note(addr, text, opts?)` — free-form attached note.
- `project.nameConstant(value, name, opts?)` — symbolic constant.

Inspection / persistence:

- `project.diff()` → array of pending diff entries
  `{ kind: "rename"|"sig"|"note"|"const", addr, detail }`.
- `project.commit()` → number of entries written; also flushes to disk.
- `project.revert()` → number of entries dropped from the staging buffer.

## Recipes

### Read a u64 at an address

```js
const buf = binary.bytesAt(0x404018n, 8);
if (buf.byteLength === 8) {
    const value = new DataView(buf).getBigUint64(0, true);  // little-endian
    print("0x" + value.toString(16));
} else {
    log.warn("no bytes mapped — BSS or outside image");
}
```

### Enumerate callers of `main`

```js
const sym = binary.findSymbol("main");
if (!sym) throw new Error("main not found");
for (const c of xrefs.callers(sym.addr)) {
    print("0x" + c.site.toString(16) + "\t" + c.kind);
}
```

### Dump a vtable's IMPs

```js
function readU64(addr) {
    const buf = binary.bytesAt(addr, 8);
    if (buf.byteLength !== 8) return null;
    return new DataView(buf).getBigUint64(0, true);
}

const vptr = 0x105dbf190n;      // vtable + 8, i.e. methods[0]
for (let slot = 0; slot < 16; ++slot) {
    const imp = readU64(vptr + BigInt(slot) * 8n);
    if (imp === null) break;
    const s = binary.symbolAt(imp);
    print(`slot ${slot}: 0x${imp.toString(16)}  ${s ? s.name : "?"}`);
}
```

### Iterate RTTI classes and resolve virtual slots

```js
for (const cls of binary.rtti()) {
    print(cls.demangled);
    for (let i = 0; i < cls.methods.length; ++i) {
        const imp = cls.methods[i];
        const s   = binary.symbolAt(imp);
        print(`  vfn_${i}: 0x${imp.toString(16)}  ${s ? s.name : "sub_" + imp.toString(16)}`);
    }
}
```

---

# Ember Declarative Scripts (`*.ember`)

A flat, section-keyed config file consumed by `ember --apply PATH`. No
expressions, no control flow — every directive is a single
`key = value` (or `pattern -> template`) pair. Designed for the
high-volume but low-complexity workflows the QuickJS surface above is
overkill for: bulk renames, signature batches, log-format-driven
recovery, glob renames over the discovered function set.

## Running

```sh
ember --apply project.ember --project out.proj <binary>
```

The applier resolves the destination annotation file the same way emit
does (`--annotations` / `--project` → `<binary>.ember-annotations`
sidecar → `~/.cache/ember/annotations/<key>`), loads the existing
contents (if any), applies the directives, writes back. User intent
beats inference: any address that already carries a rename in the
loaded annotations survives a `[pattern-rename]` or `[from-strings]`
match unchanged.

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
```

### Sections

| Section | Separator | LHS | RHS |
|---------|-----------|-----|-----|
| `[rename]` | `=` | hex VA, `sub_<hex>`, symbol, or existing rename | new name |
| `[note]` | `=` | same as rename | free-form text |
| `[signature]` | `=` | same as rename | C-style decl: `<ret> <name>(<params>)` |
| `[pattern-rename]` | `->` | glob over discovered function names (`*`) | template using `*` |
| `[from-strings]` | `->` | `printf`-style pattern (`%s`/`%d`/`%x`/`%*`) | template using `$1..$9` |

Section names are case-insensitive. Sections may repeat; directives are
applied in source order.

### Apply order

1. `[rename]`, `[note]`, `[signature]` — direct sections, applied first.
2. `[pattern-rename]` — walks `enumerate_functions()` and matches the
   current name (existing rename if any, else the discovered name).
   Skips any address with an existing rename.
3. `[from-strings]` — walks `scan_strings()`, captures from each match,
   resolves the containing function for every xref instruction, applies
   the templated rename to each. Skips any address with an existing
   rename.

### Quoting and escapes

Values containing spaces, `=`, `->`, `#`, or `%` should be quoted with
`"..."`. Standard escapes: `\\`, `\"`, `\n`, `\r`, `\t`. Unquoted values
are taken verbatim from the trimmed line.

### When to choose this over `--script`

- Choose `.ember` when the task is "apply this list of declarations" —
  it parses fast, has zero runtime, can be diffed cleanly, and reads
  like a config file. Good for log-format-driven rename tables, pattern
  bulk-renames over a stripped binary, and check-in-friendly
  per-project annotations.
- Choose `--script` when the task needs decisions or composition: walk
  this fn's callees, look at their strings, decide. Anything dynamic
  belongs there.
