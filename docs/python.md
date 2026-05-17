# Python Wrapper

`emberpy` is a small Python client for the Ember CLI. It keeps Ember's
C++ pipeline as the source of truth, but gives scripts a nicer API for
function-centric analysis, JSON probes, path explanation, and annotation
batching.

Install it from a checkout:

```sh
python -m pip install -e .
```

The wrapper finds the executable in this order:

1. `EMBER_BIN`
2. common local build paths such as `./build/cli/ember`
3. `ember` on `PATH`

You can also pass `ember_bin=` explicitly:

```python
from emberpy import Ember

e = Ember("target.elf", ember_bin="./build/cli/ember")
```

## Function Handles

Use `Ember.function()` when you already have an address and want to stay
focused on that function. `pseudo()` can also resolve symbols and
annotation names, but address-backed handles unlock the VA-oriented
helpers such as `disasm(count=...)`, `callees()`, and `investigate()`:

```python
from emberpy import Ember

e = Ember("macos_ref/RobloxPlayer.app/Contents/MacOS/RobloxPlayer")
fn = e.function(0x1041EA0D0)

print(fn.pseudo())
print(fn.disasm(count=120))
print(fn.callees(json=True))
print(fn.guard_map(json=True))
```

The same handle exposes the common targeted probes:

```python
fn.explain()
fn.containing_function()
fn.refs_to(loose=True, json=True)
fn.state_lifetime()
fn.branch_on()
fn.side_effects()
fn.object_roles()
```

Plain text remains the default for commands whose CLI output is meant to
be read directly. Pass `json=True` for commands that support structured
output.

## Investigation Bundle

`investigate()` gathers the facts usually needed when landing on an
unknown code address:

```python
report = fn.investigate(disasm_count=120)

print(report["explain"])
print(report["containing_function"])
print(report["callees"])
print(report["guard_map"])
print(report["side_effects"])
print(report["object_roles"])
print(report["pseudo"])
```

Set `include_pseudo=False` when you want the cheap orientation facts
without lifting and structuring the function:

```python
report = fn.investigate(include_pseudo=False)
```

## Path Explanation

`explain_path()` is for trace-like workflows: you give it the VAs you
care about, and it returns one structured row per address with index and
previous-hop context.

```python
path = e.explain_path([
    0x1041AD47A,
    0x1041EA070,
    0x1041EA0D0,
    0x1041E81A2,
])

for step in path:
    print(step["index"], step["address"], step["kind"])
```

Add guard maps for code/function rows:

```python
path = e.explain_path(addresses, include_guard_map=True)
```

## High-Signal Probes

The top-level client mirrors the CLI flags and parses JSON by default
where that is usually the useful form:

```python
e.containing_function(0x1041EA0D0)
e.refs_to(0x1041EA0D0, loose=True, json=True)
e.state_map(0x1041EA070, json=True)
e.state_lifetime(0x1041EA070)
e.branch_on(0x1041EA070)
e.side_effects(0x1041EA0D0)
e.object_roles(0x1041EA0D0)
e.explain_vcall(0x120001000, 0x40)
e.dump_object(0x120001000, 0x120)
```

For broad inventory:

```python
print(e.functions())
functions = e.functions_json()
print(e.strings())
print(e.xrefs())
```

For library recognition:

```python
print(e.recognize(["corpus/libcrypto.tsv", "corpus/libssl.tsv"]))
```

## Annotation Batches

`annotate_batch()` turns Python findings into a `.ember` script and
applies it with `ember --apply`.

```python
findings = [
    {
        "address": 0x401234,
        "name": "http_join",
        "note": "joins URL fragments before request dispatch",
        "signature": "int http_join(void* ctx, const char* base)",
        "confidence": 0.9,
        "source": "script:http-join",
        "evidence": "string refs and call shape",
    },
    {
        "address": 0x401280,
        "note": "caller validates scheme before joining",
        "confidence": 0.75,
        "source": "script:http-join",
    },
]

e.annotate_batch("tools/re/http_join_findings.ember", findings)
```

The generated script uses `[rename]`, `[note]`, `[signature]`, and
`[constant]` sections, including provenance suffixes when confidence,
source, or evidence is present. Parent directories are created
automatically.

Preview without writing annotations:

```python
result = e.annotate_batch(
    "tools/re/http_join_findings.ember",
    findings,
    dry_run=True,
)
print(result.stdout)
```

Only write the script, without applying it:

```python
e.annotate_batch("tools/re/http_join_findings.ember", findings, apply=False)
```

Raw `.ember` lines can be mixed into the batch:

```python
e.annotate_batch(
    "tools/re/manual.ember",
    [
        {"address": 0x401234, "name": "http_join"},
        "[constant]\n0xDEADBEEF = protocol_magic",
    ],
)
```

See [scripting.md](scripting.md) for the full `.ember` format.

## Errors And Results

Low-level calls return `EmberResult`:

```python
result = e.run("--strings", check=False)
if not result.ok:
    print(result.returncode)
    print(result.stderr)
```

By default, unsuccessful commands raise `EmberError` and keep the failed
result attached:

```python
from emberpy import EmberError

try:
    e.function(0x401234).pseudo()
except EmberError as exc:
    print(exc.result.args)
    print(exc.result.stderr)
```

Use `run()` for CLI flags that do not have a named wrapper yet:

```python
raw = e.run("--patch-plan", "0x401234", "--json").json()
```
