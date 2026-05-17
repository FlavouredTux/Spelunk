# Ember - agent reference

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
type signatures, struct field names, named constants, free-form notes).
Every Ember command reads from it; `--apply` writes to it.

You drive Ember through the CLI or the `emberpy` Python wrapper. CLI
output is TSV, JSON, plain text, or pseudo-C - all designed to be parsed
by another tool. The Python wrapper shells out to the same executable and
adds function handles, structured helper methods, path explanation, and
batch annotation writing.

---

## Agent operating rules

Your job is to turn binary evidence into names, types, notes, constants,
and call/class facts. Be fast by being narrow:

- **Use the cheapest command that answers the current question.** Start
  with inventory and lookup commands; escalate to pseudo-C, IPA, EH, or
  indirect-call resolution only when the extra facts change the next
  decision.
- **Batch before looping.** Prefer `--functions --json`, `--strings`,
  `--xrefs`, `--data-xrefs`, `--disasm-window @FILE`, and cached TSV/JSON
  outputs over launching Ember once per address.
- **Carry evidence forward.** If a previous command already produced a
  function list, xref row, string xref, vtable slot, pseudo-C body, or
  annotation, reuse it. Do not rediscover the same fact unless it is stale
  or disputed.
- **Read locally, then expand.** For a target address, first ask
  `--containing-fn`, `--refs-to`, `--callees`, or `-p -s <fn>`. Avoid
  whole-binary heavy passes until local evidence says they are worth it.
- **Promote only evidence-backed claims.** A rename/signature/note should
  cite strings, callees, imports, constants, RTTI/vtables, control flow,
  recognized library matches, or runtime facts. Use confidence values
  honestly.
- **Stop when the next action is clear.** Ember output is a tool result,
  not a scroll to exhaust. Once you have enough evidence to rename, note,
  inspect a neighbor, or mark uncertainty, act.

Cost model for agents:

| Cheap / broad | Medium / targeted | Expensive / use deliberately |
|---|---|---|
| `--functions`, `--strings`, `--identify`, `--validate`, `--containing-fn` | `-p -s`, `--callees`, `--refs-to`, `--refs-to-loose`, `--disasm-window` | `--full-analysis`, `--ipa`, `--resolve-calls`, `--eh`, whole-binary pseudo-C sweeps |

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
3. **Read.** Pull pseudo-C for the function you anchored. Start plain;
   add expensive flags only if the simple body is blocked by missing
   types, exceptions, or indirect calls.
   ```sh
   ember -p -s <name_or_addr> <binary>
   ember -p --ipa --resolve-calls --eh -s <fn> <binary>   # richer but slower
   ```
4. **Spread.** From an anchored function, expand outward via callers
   (`--refs-to`) and callees (`--callees`). Most binaries reveal
   themselves bottom-up: a few anchors → call graph propagates names.
5. **Persist.** Write conclusions back as `.ember` annotations with
   confidence, source, and evidence. Subsequent Ember invocations will
   use your names.

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
| `ember --xrefs <binary>` | `caller -> callee` per line | full call graph dump; builds/reuses the broad xrefs cache |
| `ember --data-xrefs <binary>` | TSV: target / from-pc / kind | whole-binary read/write/lea/code-ptr inventory; reuses the xrefs/cache work |

### Reading code
| Command | Output | Use when |
|---|---|---|
| `ember -d -s <fn> <binary>` | linear disasm with annotations | low-level |
| `ember -c -s <fn> <binary>` | CFG dump with block edges | branch structure |
| `ember -p -s <fn> <binary>` | pseudo-C | default for understanding |
| `ember --disasm-at <VA> --count N <binary>` | N instructions from VA plus trampoline metadata (`steal_len`, relocation needed, first basic-block end, absolute-jump safety). `--json` emits tiny structured rows: VA, bytes, mnemonic, operands, branch target, RIP-relative target, hazards. | inspect a specific spot; check whether bytes are safe to steal |
| `ember --disasm-window VA1,VA2,... --count N <binary>` | batch disasm; one block per VA, separated by `# <hex-va>` lines (or `--json` array). `@FILE` reads VAs one-per-line | sweep thousands of hits without per-call ember startup |

### Recognition
| Command | Output | Use when |
|---|---|---|
| `ember --identify <binary>` | TSV: addr / name / category / confidence | crypto / hashes / protocols |
| `ember --teef <library> > corpus.tsv` | corpus build | build a library fingerprint |
| `ember --recognize --corpus c.tsv <binary>` | TSV: addr / current / suggested / conf | identify library functions |
| `ember --rtti <binary>` | TSV: vtable / class info | C++ class hierarchy |
| `ember --vtables <binary>` | runtime vtables + slots | full loaded-dump / RELRO vtable inventory |
| `ember --vtable-at <VA> [--limit N] <binary>` | one runtime vtable around a vptr/typeinfo-adjacent/table-slot VA | narrow std::function / vtable work without dumping every table |
| `ember --objc-names <binary>` | Mach-O ObjC method names | ObjC binaries |

### Lookups
| Command | Output | Use when |
|---|---|---|
| `ember --refs-to <VA> <binary>` | target-only refs for one VA: direct callers plus code-ptr/lea address-taking by default. Add `--access read|write|lea|code-ptr|all` to ask for data-reference rows. | "who uses this?" / "who writes this global?" |
| `ember --refs-to-loose <VA> [--json] <binary>` | superset of `--refs-to`. Direct E8/E9 + CodePtr/Lea (mov reg,imm64 + lea rip+disp pointing at VA), plus a pointer-aligned literal-qword scan over every readable section (`imm64-stored` rows) and an ELF R_*_RELATIVE addend scan (`relocated` rows — `.data.rel.ro` slots the dynamic linker patches at startup, which read zero on disk). `--json` emits structured rows: `{from, target, kind, slot?, fn?, fn_offset?}`. Accepts `--access` like `--refs-to`. | fn-pointer-only callees (Roblox-style obfuscation, runtime dispatch tables) where direct callers don't exist |
| `ember --state-map <VA> [--json] <binary>` | target-only state/global map: read/write/lea/code-ptr counts plus per-site function, offset, shape (`set`, `clear`, `branch-input`, `load`, `read-modify-write`, etc.), and one disasm line | mutation map for flags, scheduler state, anti-cheat gates |
| `ember --branch-on <VA> [--json] <binary>` | target-only branch-dependency probe: reads of one state/global that reach a nearby conditional branch, with read instruction, branch instruction, taken target, fallthrough, function, and offset | "which checks branch on this flag/global?" |
| `ember --guard-map <FN-or-VA> [--json] <binary>` | function-level guard inventory: conditional branches, nearest `cmp/test`, direct memory/global used by that condition, taken target, and fallthrough | "what conditions gate this function?" |
| `ember --state-lifetime <VA> [--json] <binary>` | target-only lifecycle story for one state/global: writers, branch gates, readers, address-taking, function offsets, shapes, and disasm | "who sets/checks/uses this state?" |
| `ember --side-effects <FN-or-VA> [--json] <binary>` | function-level effect summary: direct mapped memory writes, write shape, section, classified callees, and return presence | "what does this function mutate/call?" |
| `ember --object-roles <FN-or-VA> [--json] <binary>` | function-level object layout sketch: direct `[this+offset]` reads/writes, branch gates, address-taking, call-target slots, and use sites | "what fields does this method touch?" |
| `ember --explain-address <VA> [--json] <binary>` | fast orientation summary: mapped section, kind (`function`, `code`, `state`, `pointer`, `data`), containing function, pointer classification, state/ref counts, and patch summary for code | first command for an unknown VA from a crash, trace, object, string, or agent hypothesis |
| `ember --patch-plan <VA> [--json] <binary>` | hook/trampoline safety plan for code: recommended steal length, relocation requirement, first basic-block end, absolute-jump safety, strategy, and per-instruction hazards | before copying bytes into a trampoline or patch stub |
| `ember --explain-vcall <OBJ>:<OFF> <binary>` | object / vptr / slot / target + disasm/pseudo summary | resolve `obj->vfn_N` in loaded memory |
| `ember --dump-object <ADDR> --size <N> <binary>` | qword fields classified as vtable/code/string/ptr/null/raw | inspect runtime object snapshots |
| `ember --refs-to <VA> --json <binary>` | same shape as above, just direct + CodePtr/Lea | machine-readable refs-to for pipelines that prefer structured rows |
| `ember --containing-fn <VA> <binary>` | enclosing fn entry / size / name / offset | "which function is this in?" |
| `ember --callees <fn> <binary>` | classified call edges out of fn | "what does this fn call?" |
| `ember --validate <name> <binary>` | bound addr + lookalikes | sanity-check a name |

### Annotations
| Command | Effect | Use when |
|---|---|---|
| `--annotations <path>` | use this file (overrides default) | non-default sidecar |
| `--apply <path.ember>` | apply a declarative script (renames + notes + sigs + fields + constants in bulk) | persist many conclusions at once |
| `--apply --dry-run` | preview as TSV on stdout | audit before commit |
| `--annotate <addr> --set-name X --confidence 0.9 --evidence "…" --source agent:foo` | one-shot append for a single record | agent / single-call writes |
| `-s <rename>` | resolve a function by its annotation rename, not just its symbol | after `ember annotate`, the new name is reachable directly |
| `--show-provenance` | with `-p`, surface `// confidence: …` under each annotated function | downstream agent reading pseudo-C wants to know whether to trust the rename |
| `--functions --json` | function list with `confidence` / `source` / `evidence` columns when set; renames substitute into the `name` column | machine-readable triage; `--functions=cap_check` matches the annotated name |
| `--list-annotations` | every record in the resolved annotations file (rename / note / signature) with its meta. TSV by default, structured form under `--json` | enumerate notes - `--functions --json` only surfaces named records, so pure `--set-note` annotations are otherwise invisible |
| `--apply <cache.db>` | same as `--apply <script.ember>` - auto-detects persisted-format cache files | copy annotations between binary versions |
| `--validate NAME` | bound rows include `confidence=` / `source=` when annotated | sanity-check a name with provenance |

Provenance rides through the whole stack: `(confidence, source, evidence)`
fields persist alongside the rename / note / signature. When the agent
harness promotes a `.ember` file via `agent/src/promote.ts`, the suffix
` ; conf=0.9 ; src=agent:namer ; ev=…` is consumed by `[rename]` /
`[note]` / `[signature]` directives and written into parallel `*_meta`
maps. Avoid stating inferences as facts - pass `--confidence` so the
next agent / tool can decide whether to verify.

### Spending analysis budget
- First-run heavyweight passes (`--xrefs`, `--strings`, `--arities`,
  `--fingerprints`) cache to `~/.cache/ember/`. If you need the same
  broad fact twice, prefer the cached command over rebuilding your own
  scan. `--no-cache` is for freshness/debugging, not default agent use.
- `--xrefs` is now cheap enough to use as the first broad pass on very
  large Roblox-scale clients. On a 117 MB RobloxPlayer/libroblox image,
  fixed xrefs measured around 2.7s total after the worklist/filtering
  improvements (`call_graph.fast_scan` was sub-second; remaining cost
  was mostly function discovery/worklist). Use `EMBER_TIMING=1` when
  validating performance or deciding whether the bottleneck is xref
  formatting, function discovery, or pseudo-C lifting.
- `--data-xrefs` is also whole-binary inventory. Prefer
  `--refs-to <VA> --access read|write|lea|all` for one target.
- For stripped Roblox-style investigations, a good broad setup is:
  ```sh
  env EMBER_TIMING=1 ember --xrefs --no-cache <binary> > /tmp/ember-xrefs.out
  ember --functions --json <binary> > /tmp/ember-functions.json
  ember --data-xrefs <binary> > /tmp/ember-data-xrefs.tsv
  ```
  Then correlate locally with `rg`, TSV/JSON parsers, and targeted
  `--pseudo -s sub_<addr>` reads. This is faster and less noisy than
  running `--refs-to-loose` repeatedly while exploring a whole subsystem.
- For repeated agent/UI probes, use `ember --serve` / `ember --daemon`
  instead of spawning one CLI process per question. The daemon keeps the
  binary and hot refs/disasm caches alive across requests.
- `--ipa` runs whole-program type inference; `--resolve-calls` resolves
  indirect call sites; `--eh` parses exception metadata. They improve
  pseudo-C, but they are not the opening move. Use them for functions
  you are actively naming, typing, or explaining.
- `--full-analysis` is for missed functions and suspicious gaps in the
  function list. Do not add it to every inventory command by habit.
- `--refs-to-loose` is broader than `--refs-to`; use it when ordinary
  callers are empty but the target may live in a table, relocation slot,
  callback array, or runtime dump.
- `--refs-to-loose` is not the first move when xrefs are already cached.
  If a loose string lookup misses, use the cached `--xrefs`/`--data-xrefs`
  output and `--containing-fn` around manually observed LEA sites before
  assuming there are no references.
- For one VA and a specific access question, start with
  `--refs-to <VA> --access write` (or `read` / `lea` / `all`).
- For many nearby addresses, use `--disasm-window` or `@FILE` batching.
  For one address, use `--disasm-at` or `--containing-fn`.

---

## Reading the output

### `--functions` TSV
```
0x0000000000401140    0x153b    symbol    main
0x000000000040229c    0x47      sub       sub_40229c
```
Columns: `addr`, `size` (hex), `kind` (`symbol` for named, `sub` for
discovered), `name`. `sub_<hex>` names are placeholders - your job is to
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

On `--regions` loaded-memory inputs, Ember also scans readable
non-executable regions for pointer-sized slots that already contain
runtime-relocated pointers. This is the path that sees Android / PIE
`.data.rel.ro` vtable slots whose static ELF view would show zeros.

### Loaded dumps: vtables, vcalls, objects

```sh
ember --regions module.regions --vtables
ember --regions module.regions --vtable-at 0xVTABLE_OR_SLOT --limit 24
ember --regions module.regions --explain-vcall 0xOBJECT:0x40
ember --regions module.regions --dump-object 0xOBJECT --size 0x100
```

`--vtables` finds pointer-dense tables in readable non-executable
regions whose slots point into executable memory. Use `--vtable-at`
for the normal interactive case: it prints only the vtable containing
or immediately adjacent to the queried VA, capped by `--limit` slots
(default 16, `0` means all). `--explain-vcall` reads `*(OBJECT)` as the
vptr and `*(vptr + OFF)` as the target, then prints section/name/disasm
and a short pseudo-C summary when available. `--dump-object` walks
pointer-sized fields and classifies each value as `vtable`, `code`,
`string`, `ptr`, `null`, or `raw`.

Runtime facts can be supplied with `--trace`:

```text
indirect 0xCALLSITE 0xTARGET
qword 0xGLOBAL 0xVALUE
object 0xOBJECT 0xVTABLE
vptr 0xADDR 0xVTABLE
```

Plain two-column `from to` still records an observed indirect edge.

### `-p` (pseudo-C)
- Variables `a1`, `a2`, ... are ABI argument registers.
- `r_<callee>` (e.g. `r_strlen`) is the return value of a call to that
  fn - bound to a name when the receiver is used downstream.
- `sub_<hex>` is an unnamed function. Rename via the agent loop.
- `field_<hex>` is an unnamed struct field at offset hex from a
  parameter pointer. Name via `[field]` in `.ember`.
- `NAME /* 0x... */` in an immediate expression is a named constant
  supplied by annotations. Use `[const]` for hashes, magic values,
  protocol IDs, or resolver constants that make the pseudo-C readable.
- `(*(u64*)(0x...))(...)` is an unresolved indirect call. Means: vtable
  / function-pointer table the static analyzer couldn't bottom out.
  Either run `--resolve-calls`, inspect the receiver with
  `--explain-vcall OBJ:OFF`, supply runtime facts via `--trace`, or
  accept it as a known limit.
- `/* observed targets: a, b, c */` after a call expression: trace
  evidence of what the fn pointer dynamically resolved to.

### `--refs-to` output

```
0x401140 -> 0x405068
0x402240 -> 0x405068
0x97d8 -> 0x405068  (code-ptr)  ; sub_9780+0x58
0x401106 -> 0x404028  (write)  ; sub_4010fd+0x9
```

First two lines: direct call edges (caller fn entry → target). Third
line: `code-ptr` - `sub_9780` takes the address of `0x405068` at
instruction `0x97d8` (likely storing it into a dispatch table). Surface
the table that lives at the destination of this `lea` to find indirect
callers. Filter access-specific rows with `--access`; for example,
`ember --refs-to 0x404028 --access write <binary>` answers
"who writes this VA?" with a target-only scan.

### `--state-map` output

Use this when a VA behaves like state: scheduler flags, anti-cheat gates,
feature toggles, global counters, object fields, or "something flips this
and later a branch/call changes behavior." It is target-only and built on
the fast data-xref scanner.

```
ember --state-map 0x10627e1b0 <binary>
ember --state-map 0x10627e1b0 --json <binary>
```

Human output starts with a summary, then one row per access site:

```
state	0x404028	reads=7	writes=1	lea=0	code-ptr=0
read	0x4010f4	branch-input	__do_global_dtors_aux+0x4	...
write	0x401106	set	sub_4010fd+0x9	...
```

Columns: `kind`, `site`, `shape`, `function+offset`, and one disasm
line. Useful shapes include `set`, `clear`, `store`,
`read-modify-write`, `atomic-write`, `branch-input`, `load`,
`address-taken`, and `code-pointer`.

Daemon form for agents:

```
{"method":"state_map","addr":"0x10627e1b0","json":true}
```

### `--branch-on` output

Use this after `--state-map` when a global/state VA looks like a gate.
It is target-only: Ember finds reads of the VA and decodes a tiny local
window looking for the conditional branch fed by that read.

```
ember --branch-on 0x10627e1b0 <binary>
ember --branch-on 0x10627e1b0 --json <binary>
```

Human rows are:

```
branch-on	0x404028	branches=1
0x4010f4	__do_global_dtors_aux+0x4	cmp byte ptr [0x404028], 0x0	0x4010fb	jne 0x401108	0x401108	0x4010fd
```

Columns after the header are `read_site`, `function+offset`,
`read_instruction`, `branch_site`, `branch_instruction`, `taken`, and
`fallthrough`.

Daemon form:

```
{"method":"branch_on","addr":"0x10627e1b0","json":true}
```

### `--guard-map` output

Use this on a function when you want the local gate inventory: every
conditional branch Ember can decode, the nearest preceding `cmp/test`,
and any direct mapped memory/global used by that condition.

```
ember --guard-map 0x4010f0 <binary>
ember --guard-map SomeFunction --json <binary>
```

Human rows are:

```
guard-map	0x4010f0	__do_global_dtors_aux	guards=1
0x4010f4	cmp byte ptr [0x404028], 0x0	0x4010fb	jne 0x401110	0x401110	0x4010fd	0x404028	.bss
```

Columns after the header are `condition_site`, `condition_instruction`,
`branch_site`, `branch_instruction`, `taken`, `fallthrough`,
`memory_target`, and `memory_section`.

Daemon form:

```
{"method":"guard_map","fn":"0x4010f0","json":true}
```

### `--state-lifetime` output

Use this when a VA is probably state and you want the whole local story
without asking five separate probes. It combines the target-only data
xref scan with branch-gate detection.

```
ember --state-lifetime 0x10627e1b0 <binary>
ember --state-lifetime 0x10627e1b0 --json <binary>
```

Human output is grouped:

```
state-lifetime	0x404028	reads=7	writes=1	branches=1	lea=0	code-ptr=0
writers
0x401106	set	sub_4010fd+0x9	mov byte ptr [0x404028], 0x1
branch-gates
0x4010f4	__do_global_dtors_aux+0x4	cmp byte ptr [0x404028], 0x0	0x4010fb	jne 0x401110	0x401110	0x4010fd
readers
...
```

Daemon form:

```
{"method":"state_lifetime","addr":"0x10627e1b0","json":true}
```

### `--side-effects` output

Use this when naming an unknown function. It is a single-function scan:
direct mapped memory writes, classified callees, and whether Ember saw a
return instruction.

```
ember --side-effects 0x4010fd <binary>
ember --side-effects SomeFunction --json <binary>
```

Human output:

```
side-effects	0x4010fd	sub_4010fd	writes=1	calls=1	returns=yes
writes
0x401106	0x404028	.bss	set	mov byte ptr [0x404028], 0x1
calls
0x401050	direct
```

Daemon form:

```
{"method":"side_effects","fn":"0x4010fd","json":true}
```

### `--object-roles` output

Use this on a likely method to sketch object layout. Ember infers the
first integer argument register as `this` (`rdi` on SysV x64, `rcx` on
Win64, `x0` on AArch64) and reports direct `[this+offset]` memory uses.

```
ember --object-roles 0x100123abc <binary>
ember --object-roles SomeMethod --json <binary>
```

Human output:

```
object-roles	0x100123abc	sub_100123abc	this-reg=rdi	fields=3
fields
+0x10	read,branch-gate	uses=2
0x100123ad0	read	mov rax, qword ptr [rdi+0x10]
0x100123ad8	branch-gate	cmp qword ptr [rdi+0x10], 0x0
+0x30	call-target	uses=1
0x100123b20	call-target	call qword ptr [rdi+0x30]
```

Daemon form:

```
{"method":"object_roles","fn":"0x100123abc","json":true}
```

### `--explain-address` output

Use this as the front door for an unknown VA. It is target-only and
combines the cheap orientation facts agents usually ask for one by one.

```
ember --explain-address 0x10627e1b0 <binary>
ember --explain-address 0x10627e1b0 --json <binary>
```

For data/state addresses it reports section, pointer classification, and
state/ref counts. For code addresses it reports the containing function
and the same patch-safety summary used by `--disasm-at --json`:
recommended steal length, relocation requirement, first basic-block end,
and absolute-jump trampoline safety.

Daemon form:

```
{"method":"explain_address","addr":"0x10627e1b0","json":true}
```

### `--patch-plan` output

Use this before stealing bytes for a hook/trampoline. It is stricter and
more direct than `--disasm-at`: the output is about whether copied bytes
need relocation and whether an absolute jump trampoline is safe.

```
ember --patch-plan 0x100123abc <binary>
ember --patch-plan 0x100123abc --json <binary>
```

Human output:

```
patch-plan	0x401020
strategy	copy-with-relocation
steal_len	19
needs_relocation	yes
first_basic_block_end	0x401033
safe_absolute_jump_trampoline	no
instructions
0x401020	rip-relative	mov rax, qword ptr [0x404018]
```

Strategies: `absolute-jump-ok`, `copy-with-relocation`,
`insufficient-bytes`, or `manual-review`. Hazards include
`rip-relative`, `short-branch`, and `rel32-branch-or-call`.

Daemon form:

```
{"method":"patch_plan","addr":"0x100123abc","json":true}
```

When driving agents or UI tools, prefer the daemon form (`ember --serve`
or `ember --daemon`). The daemon loads the binary once and keeps hot
serve-side refs/disasm products in memory, including loose pointer-slot
scans by target and relocated qword maps. Repeated `refs_to`,
`refs_to_loose`, `state_map`, `branch_on`, `guard_map`, `state_lifetime`, `side_effects`, `object_roles`, and `disasm_at` requests over the serve
protocol avoid CLI startup.

Serve protocol: one request per stdin line, framed responses on stdout
as `ok <bytes>\n<body>\n` or `err <message>\n`. Ask `help` first if in
doubt. Both forms are accepted:

```
refs_to	addr=0x401000	access=write	quick=true	json=true
{"method":"refs_to","addr":"0x401000","access":"write","quick":true,"json":true}
```

JSON request aliases `tool` and `op` are accepted in place of `method`.
Common daemon methods: `refs_to`, `refs_to_loose`, `state_map`, `branch_on`, `guard_map`, `state_lifetime`, `side_effects`, `object_roles`, `disasm_at`,
`decompile`, `callees`, `containing_fn`, `describe_address`, `get_data`,
`functions`, `strings`, `strings_in_range`, `annotations`,
`callees_all`, and `recognize`.

### `--disasm-at --json` output

Use this for patch/trampoline probes. Each instruction includes raw
bytes, operands, branch target, RIP-relative target, and hazard booleans
for `rip_relative`, `short_branch`, and `rel32_branch_or_call`. The
top-level fields summarize the prologue window:
`recommended_steal_len`, `needs_relocation`, `first_basic_block_end`,
and `safe_absolute_jump_trampoline`.

### `--identify`
```
405068    sha256_compress    hash    0.95    constants    6a09e667,bb67ae85,...
```
Columns: `addr`, `name` (the recognized profile), `category`,
`confidence`, `signal` (what fired: `constants` / `pattern` /
`insn_seq` / a `+`-joined combination), `via` (the specific evidence -
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

[const]                             # [constant] works too
0xDEADBEEF = kernel32_CreateFileW_hash
31337      = protocol_magic

[from-strings]
"[HttpClient] %s" -> HttpClient_$1  # %s captures, $1 in template
"error: %d at %s"  -> err_$2

[pattern-rename]
sub_4* -> roblox_sub_*              # glob match, * captures, * in template
log_*  -> Logger_*

[delete]
log_handler = all                   # drop rename + note + signature + fields
0x401234    = signature             # drop just the signature
0xDEADBEEF  = constant              # drop a named immediate
```

**Apply order matters.** Within one file: `[delete]` runs first, then
direct sections (`[rename]`, `[note]`, `[signature]`, `[field]`,
`[const]`), then `[pattern-rename]`, then `[from-strings]`.
Use this to clear stale annotations and write replacements in one file.

**Address/value resolution.** Rename/note/signature/field LHS accepts
hex VA (`0x401234`), `sub_<hex>`, current symbol name, or existing
rename. `[const]` LHS is a numeric value (decimal or hex), not an
address lookup. RHS is the literal value.

**`--dry-run`** prints the resolved TSV that *would* be written
without touching the file. Always dry-run first when the script came
from an automated source (LLM, batch tool).

---

## Confidence semantics

Numbers you'll see attached to claims, suggestions, identifications:

- **1.00** - exact-match path (behavioural-exact, whole-exact at
  unique distinct-name bucket, identify with all required constants
  matched + corroborating signals). Trust enough to auto-apply.
- **0.85 – 0.99** - high confidence. Cascade workflows promote at
  ≥ 0.85. Spot-check before bulk-applying.
- **0.60 – 0.84** - likely, but worth a human-grade glance. Especially
  for functions < 64 bytes - short-fn fingerprints collide.
- **< 0.60** - speculative. Surface for review, do not auto-rename.

If two claims for the same address are within 0.10 confidence and
disagree on value, that's a **dispute** - the right move is to gather
more evidence (xrefs, strings, callees) before picking, not to
arbitrarily promote the higher one.

---

## When Ember can't help

Stop trying these things; they're known limits, not bugs:

- **Indirect calls without IAT, constant vtable, runtime trace, or
  receiver-type fact.** They render as typed unresolved function-pointer
  slot calls with an evidence comment.
  Workaround: feed `--trace edges.tsv` if you can collect runtime
  evidence; otherwise note the call site and move on.
- **Function pointers installed by `.init_array` ctors at runtime**
  (Lua C-API tables, plugin registration patterns). Static analysis
  doesn't see the assignment yet - the table address is computed in
  ctor code that builds the dispatch slot dynamically. `--refs-to` on
  these returns empty even though they're called constantly.
  Workaround: identify the ctor, read its pseudo-C, manually note the
  table slot ↔ fn mapping.
- **AArch64 floating-point and Advanced SIMD** lift as
  `arm64.<op>(...)` intrinsics. Shape-only, not modelled. SVE / SME
  unmapped.
- **PPC32/PPC64** lifting is intentionally small: scalar GPR/control-flow basics only.
- **Switch defaults** outside the bounds-check guard can misattribute
  to a wrong case label.
- **MSVC demangle** is partial (Itanium is comprehensive). Don't trust
  every MSVC name verbatim.
- **Computed-goto VM dispatchers** (one big function with `jmp [tab+rax*8]`
  to internal labels) aren't real callers from the compiler's POV.
  `--refs-to` on the "labels" returns nothing because they're not
  separate functions - read the dispatcher's pseudo-C directly.
- **Anti-debug / packed binaries** that flip section permissions at
  runtime: load a runtime memory image instead - Microsoft minidump
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
                              # TEEF Max - cross-compiler library-fn ID
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

**"What does this runtime vcall actually target?"**
```sh
ember --regions module.regions --vtables
ember --regions module.regions --vtable-at 0xVTABLE_OR_SLOT --limit 24
ember --regions module.regions --dump-object 0xOBJECT --size 0x100
ember --regions module.regions --explain-vcall 0xOBJECT:0x40
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
binary, trust `--help` - Ember's CLI is the source of truth, this
document is a curated subset.
