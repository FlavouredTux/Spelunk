# Ember Pi Extension

Project-local Pi extension for driving Ember from the agent.

## Tools

- `ember_inventory` — first-contact binary inventory: headers/sections/imports, functions, strings, identify.
- `ember_lookup` — targeted probes: refs, loose refs, callees, containing function, state/guard maps, object roles, vtables, address explanation, disasm-at.
- `ember_code` — one-function pseudo-C/disasm/CFG/IR/SSA/structured views.
- `ember_annotate` — one-shot evidence-backed rename/note/signature. Symbol names are resolved through `ember --validate` before `--annotate`.
- `ember_apply` — apply or dry-run `.ember` scripts / annotation dbs.
- `ember_recognize` — identify, TEEF corpus build, recognize, fingerprints, and diff workflows.
- `ember_python` — run short Python snippets with the in-repo `emberpy` wrapper preloaded (`Ember`, `EmberError`, optional `e`, and `dump()`).
- `ember_cli` — argv-based escape hatch for long-tail Ember flags not covered above.
- `ember_artifact_read` — inspect focused slices of large saved Ember outputs.
- `goal_complete` — mark the active `/goal` complete with evidence.

Large RE outputs use artifact-first handling: outputs above 16 KiB are saved under `.pi/ember-artifacts/`, and only a bounded preview is sent to context. Use `ember_artifact_read` with offsets/limits/filters to inspect the saved file. Smaller outputs are returned directly; all outputs still obey Pi's 2000 line / 50 KiB hard truncation.

## Commands

- `/ember` — show status and insert the recommended Ember workflow.
- `/goal <text>` — set a must-finish checkbox.
- `/goal` — show current goal.
- `/goal done` — mark it complete manually.
- `/goal clear` — remove it.

While a goal is open, the extension injects instructions telling the agent not to stop. If the agent ends without completing the goal, it queues a follow-up prompt to continue. The agent should call `goal_complete` only once the goal is genuinely satisfied.

## Ember binary resolution

1. `EMBER_BIN`
2. `./build/cli/ember`
3. `ember` on `PATH`

## Reload

After edits:

```text
/reload
```
