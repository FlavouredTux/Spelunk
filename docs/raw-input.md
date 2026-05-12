# Raw Input

Two ways to feed Ember bytes that aren't a complete PE / ELF / Mach-O
container - runtime memory captures, Scylla scrapes, hand-rolled
fixtures, anything where the file-magic dispatch in `load_binary()`
doesn't have a container to recognise.

## `--raw-bytes PATH --base-va 0xVA`

The one-region shortcut. `PATH` is loaded as a flat byte buffer and
exposed as a single `rwx` section starting at `0xVA`. No headers, no
manifest. Used for runtime captures of one contiguous range:

```sh
# Disassemble bytes pulled from a debugger at 0x180010000.
ember --raw-bytes dump.bin --base-va 0x180010000 -p -s 0x180012a40

# Dump every discovered function in a runtime region.
ember --raw-bytes runtime.bin --base-va 0x180010000 --functions
```

`--base-va` is mandatory. It accepts `0x`-prefixed hex or bare hex
(`0x180010000`, `180010000`, both valid). Decimal isn't supported -
addresses in this codebase are always hex.

The region is marked `rwx` so all of analysis (CFG walking, prologue
sweep, indirect-call resolution) runs against the bytes. There's no
symbol table, so the natural entry is `sub_<base_va>` and the user
supplies `-s <addr>` to target a specific VA.

## `--regions PATH`

The multi-region path. `PATH` points at a manifest file describing a
set of regions, one per non-blank, non-`#` line:

```
<vaddr-hex>  <size-hex>  <flags>  <file-relative-to-manifest>
```

`flags` is a 3-character permission bitmap matching the section-flag
renderer (`r--`, `r-x`, `rw-`, `rwx`, `---`). Whitespace is one or
more spaces or tabs. The file path is interpreted relative to the
directory containing the manifest.

Example `regions.txt`:

```
# .text + .rdata scraped from a running process at 0x140000000.
0x140000000  0x00400000  r-x  text.bin
0x140400000  0x00100000  rw-  rdata.bin
```

The manifest's declared size wins over the on-disk file size - pad
with zeros if the file is shorter (for uninitialised BSS-like
ranges), truncate if longer.

```sh
ember --regions /path/to/scrape/regions.txt -p -s 0x140012a40
```

When to pick which:

- **`--raw-bytes`** for a single contiguous capture. Lower friction,
  no manifest to maintain. The 95% case for runtime debugger dumps.
- **`--regions`** when you have multiple non-contiguous ranges (text
  + rdata + heap), or when you need different per-range permissions
  (e.g. a writable data section the analyses should treat as data,
  not code).

## What you don't get

Raw input bypasses all the container-specific extras:

- No symbol table - every discovered function reads as `sub_<hex>`
  unless you pair with `--annotations` or `--apply <script>`.
- No imports / exports - runtime captures of a process *do* contain
  the IAT bytes, but Ember can't recognise an IAT without the
  IMAGE_DIRECTORY_ENTRY_IMPORT directory the PE loader normally
  parses. Indirect calls through the captured IAT slots stay
  unresolved.
- No PDATA-derived function starts - function discovery falls back
  to the prologue-sweep + vtable-harvest pipeline.

For VMProtect / commercial-packer runtime analysis these
limits are usually fine: the disk PE was a decoy anyway, and the
captured bytes are what actually run.

## Loaded Android / PIE Dumps

For `--regions` memory captures, `--data-xrefs` scans readable
non-executable regions for pointer-sized slots whose values point back
into any loaded region. This covers RELRO/vtable tables after the
dynamic linker has already applied ASLR relocations.

`--vtables` dumps pointer-dense tables in readable non-executable
regions without requiring RTTI. On loaded Android dumps this is the
fast path for `.data.rel.ro` vtables whose on-disk ELF view would show
zero-filled relocation targets:

```sh
ember --regions module.regions --vtables
```

`--refs-to-loose` also accepts a module-relative offset for raw-region
captures. If the requested address is not mapped, Ember tries
`lowest_region_vaddr + offset` as the runtime address. For example, a
query for `0x2987800` against a dump whose first mapped region starts at
`0x7fe341c0d000` also searches slots containing
`0x7fe344594800`.

For raw-region inputs, `--refs-to-loose` is data-first: it reports
matching runtime slots directly instead of building the global callgraph
first. That avoids the high-CPU/noisy path where table bytes are decoded
as code-like direct references.

`--explain-vcall OBJ:OFF` resolves the common C++ dispatch question for
loaded objects: read `*(OBJ)` as the vptr, read `*(vptr + OFF)` as the
target, then print the target section, first disassembly line, and a
short pseudo-C summary when the target function can be recovered.

```sh
ember --regions module.regions --explain-vcall 0x7fe350001000:0x8
```

Pair it with runtime facts when the object pointer lives in a singleton
global rather than directly in the dump:

```text
qword 0x7fe34811f10 0x7fe350001000
object 0x7fe350001000 0x7fe344c0d000
```

`--dump-object ADDR --size N` prints pointer-sized fields and classifies
each as `vtable`, `code`, `string`, `ptr`, `null`, or `raw`. This is the
quick snapshot view for AppBridge / SingleSurface-style runtime objects:

```sh
ember --regions module.regions --dump-object 0x7fe350001000 --size 0x100
```
