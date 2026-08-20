# Unreal Kismet bundles

Ember can inspect Blueprint bytecode captured from a live Unreal Engine runtime:

```text
ember --kismet PATH --functions[=FILTER]
ember --kismet PATH -d -s FUNCTION
ember --kismet PATH -c -s FUNCTION
ember --kismet PATH -p -s FUNCTION
ember --kismet PATH --kismet-events -s ExecuteUbergraph_NAME
ember --kismet PATH -p -s ExecuteUbergraph_NAME --kismet-event EVENT
```

`PATH` may name the bundle directory or `manifest.tsv`. `--json` works for both
function listings and a selected disassembly.

`-c` builds a basic-block graph from labels and unconditional/conditional jump
targets. `--kismet-events` finds wrapper functions that invoke an Ubergraph with
a literal entry offset, recovering the event-to-entry dispatch table.
`--kismet-event` follows one of those entries through shared blocks. The `-p`
view renders typed assignments and calls, simplifies common Kismet library
operations, and structures acyclic branches around their nearest common join.
The CFG evaluator tracks `PushExecutionFlow`, `PopExecutionFlow`, and conditional
flow-stack pops as stateful continuations, which covers Blueprint Sequence and
ForEach-style control flow. Functions containing computed jumps or cycles retain
complete explicit labels and gotos instead of pretending that unsafe structuring
succeeded.

## Bundle format

Version 1 is a tab-separated manifest with sidecar files:

```text
EMBER_KISMET_BUNDLE  1  engine=5.7.4  pointer_size=8  bytecode=live_pointer_expanded
FUNCTION  000001  BYTE_COUNT  FUNCTION_FLAGS  CLASS_PATH  FUNCTION_PATH  RAW_PATH  DISASM_PATH
```

Fields shown separated by spaces above are literal tabs on disk. Sidecar paths
must be relative and cannot contain a `..` component. Ember validates duplicate
IDs/function paths and checks each selected raw file against its declared size.

The raw stream is the live `UFunction::Script` representation. Object, field,
and function operands are process pointers after Unreal deserializes a cooked
package, so raw bundles are not directly replayable in another process. Capture
tools should resolve those operands while the source runtime is alive and store
the canonical textual disassembly beside the bytes.

## Recovery boundary

The disassembly preserves executable operations, named properties and
functions, constants, jumps, calls, and bytecode offsets. Cooking usually strips
visual node coordinates, comments, and some editor-only graph organization.
Ember therefore reports recovered behavior and does not claim to recreate the
original Blueprint editor graph exactly.
