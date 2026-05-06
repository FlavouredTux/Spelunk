# forge-spec inference

Given an entry function and a target virtual address, ember computes the
minimum heap/struct field shape and the sequence of branch decisions
that one representative call chain from the entry to the target
requires. The output is a *witness* for reachability, not the meet of
every possible reaching path — useful for quickly answering "what
does my mocked input have to look like to drive control to this code?"
without running the binary, and for comparing multiple candidate
fakes head-to-head.

## CLI

```sh
ember --forge-spec ENTRY:VA <binary>
ember --forge-spec ENTRY:VA --json <binary>
```

`ENTRY` is a function name, hex VA, or `sub_<hex>`. `VA` is a hex
address (with or without the `0x` prefix), or `sub_<hex>`.

The text output groups output into:

* `// forge-spec: reach <target> from <entry>` — header.
* `// call chain: a -> b -> c` — the BFS-shortest sequence of function
  entries from `<entry>` to the function containing `<target>`.
* `required input shape:` — one line per de-duplicated field
  requirement, formatted as a normalized comparison rooted at a
  parameter (`*(arg0 + 0x138)`, `*(*(arg0 + 0x60) + 0x10)`, etc.).
  Each line is annotated with the source VA where the constraint
  was extracted.
* `branch decisions:` — every conditional branch on the chosen path,
  with the direction taken and the predicate as a (canonicalized)
  comparison.

The JSON form (under `--json`) is stable and intended for tools.

## Worked example

```c
struct packet { unsigned magic; unsigned flags; unsigned long payload; };

int inspect_packet(struct packet* p) {
    if (p->magic == 0x1234)
        return p->flags + p->payload;
    return 0;
}
```

```
$ ember --forge-spec inspect_packet:0x401130 ./struct_fields
// forge-spec: reach 0x401130 (inspect_packet) from 0x401120 (inspect_packet)
// call chain: 0x401120

required input shape:
    *(arg0 + 0) == 0x1234    // at 0x401128

branch decisions:
    0x401128  fn 0x401120  taken -> 0x401130    *(u32*)arg0 == 0x1234
```

## Cross-function chains

When `ENTRY` doesn't itself contain `VA`, ember walks the static call
graph to find the shortest chain of direct/tail/indirect-const calls
from `ENTRY` to the function containing `VA`. For each function on the
chain, the inside-the-function path is from that function's entry block
to (a) the call site that targets the next function on the chain, or
(b) the block containing `VA` for the final function.

```
$ ember --forge-spec main:0x401130 ./struct_fields
// forge-spec: reach 0x401130 (inspect_packet) from 0x401020 (main)
// call chain: 0x401020 -> 0x401120

required input shape:
    *(arg0 + 0) == 0x1234    // at 0x401128

branch decisions:
    0x401128  fn 0x401120  taken -> 0x401130    *(u32*)arg0 == 0x1234
```

The reported parameter slots (`arg0`, `arg1`, ...) are scoped to the
function each constraint was extracted in — interprocedural argument
forwarding is *not* yet projected (see "Limits" below).

## How it works

1. Each function on the call chain is lifted through the standard
   pipeline: `CfgBuilder.build` → `Lifter.lift` → `SsaBuilder.convert`
   → `run_cleanup` → `seed_call_return_types` → `infer_local_types`.
2. A shortest CFG path is BFS'd from the function's entry block to a
   block matching the per-function terminus predicate.
3. Each conditional branch on the path is turned into a
   `BranchDecision`. The CondBranch predicate's i1 SSA value is
   walked backwards through the def chain; live-in arg registers
   (SSA version 0, ABI integer-arg slots) are tagged as `Param`
   leaves, loads become `Load(addr)`, etc.
4. The resulting `ForgeExpr` for each predicate is canonicalized
   (`Cmp(BinOp(Sub, A, B), 0)` → `Cmp(A, B)`, etc.) and inspected:
   if one side is a `Load` chain rooted at a `Param`, the chain is
   peeled into a `FieldRequirement` (`{param_index, offset_chain,
   access_width, cmp_op, rhs}`).
5. Phi nodes are resolved path-relatively: when the use is at a join
   block reached via predecessor `P`, the phi operand contributed by
   `P` is taken; merging across siblings only kicks in if the path
   somehow didn't traverse a unique predecessor.

## Limits

The inferencer is a witness for reachability, not a soundness check.
Known gaps:

* **One path, not the meet.** A single shortest BFS path is chosen.
  Functions whose target is reachable through several semantically
  distinct paths will only have the constraints from one of them
  reported; the user is expected to consult the others by re-running
  with a different entry.
* **Loops are not widened.** A path through a loop body unrolls at
  most once; inductive constraints are not synthesized.
* **No interprocedural argument forwarding.** Parameter slots
  (`arg0`, `arg1`) are reported per function, not lifted back through
  the call chain to express the entry's parameters. A constraint on
  `arg0` of a callee is *not* automatically translated into the
  corresponding setup at the caller.
* **No abstract heap.** The only memory shape recovered is a load
  chain rooted at a parameter. Globals, allocations, and aliasing
  through saved registers are not modeled.
* **No RTTI / vtable seeding.** Polymorphic dispatch on a class
  hierarchy is not narrowed by the typer; an `arg0->vptr->method`
  call site shows up as a generic indirect call.

These are deliberate v1 compromises — every one of them is
implementable as an extension on top of the same `ForgeExpr` /
`FieldRequirement` data model in `ember/analysis/forge_spec.hpp`.
