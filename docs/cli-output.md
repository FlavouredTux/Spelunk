# CLI results and timeouts

## Function views

Use `--json` with `-d`, `-c`, `--cfg-pseudo`, `-i`, `--ssa`, `-O`,
`--struct`, `-p`, or `--emit-c` to get newline-delimited JSON on stdout.
There is one record per function, including failures. This works with either
`-s NAME` or `--symbols FILE`.

```sh
spelunk --json -p --symbols functions.txt --timeout 30s ./target
```

The manifest contains one symbol or address per line. Blank lines and `#`
comments are ignored; duplicates and entries containing whitespace are errors.
Records follow manifest order. A failed function does not stop the remaining
functions, in either JSON or plain-text mode.

Each record has these fields:

- `schema_version`: currently `1`.
- `build`: Spelunk semantic `version` and Git `revision` used to produce it.
- `type`: `function`.
- `symbol`: the requested selector (empty when using the default target).
- `address`: resolved address as a hexadecimal string, or `null` if unresolved.
- `name`: resolved function label, or `null` if unresolved.
- `view`: `disasm`, `cfg`, `cfg-pseudo`, `ir`, `ssa`, `opt`, `struct`, `pseudo`, or `emit-c`.
- `status`: `ok` or `error`.
- `output`: the selected view's text on success, otherwise `null`.
- `error`: `null` on success, otherwise an object with `kind` and `message`.

Resolution failures use kind `resolve-failed`. Analysis/export failures retain
their original error kind. Diagnostics remain on stderr, never mixed into the
function records. Setup failures (such as an unreadable binary or malformed
manifest) are reported on stderr before any function records are emitted.

Exit status is `0` if all requested functions succeeded and `1` if any failed.
Completed JSON records are flushed immediately. Existing inventory commands
such as `--functions --json` retain their own output formats.

Plain function views begin with a `spelunk-build` comment. Callee reports and
disassembly probes carry the same stamp; their JSON objects use the `build`
field. A revision ending in `-dirty` was built from local uncommitted changes.

## Timeouts

`--timeout` applies to the entire command after argument parsing, including
binary loading, shared analysis and all functions in a batch. It is not a
per-function budget. Without this option there is no deadline.

Durations accept `ms`, `s`, `m`, or `h`; bare numbers mean seconds. Decimal
values are allowed. The range is `1ms` through `24h`, rounded up to whole
milliseconds. Invalid, zero, negative and non-finite durations are rejected.

On expiry, Spelunk terminates with exit status **124** and attempts to write a
`timeout` error to stderr (JSON when `--json` is set). Reporting has at most a
10ms grace period so a blocked stderr pipe cannot prevent termination.

This is a hard stop, not graceful cancellation. Already completed records
remain usable, but later functions may have no record. If stdout was interrupted
mid-write, discard its incomplete final line. Do not interpret a missing result
as success. File-writing operations may leave incomplete outputs or temporary
files; use deadlines primarily for analysis commands.
