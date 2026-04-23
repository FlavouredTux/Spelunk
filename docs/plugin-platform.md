# Ember Plugin Platform

This document specifies a first-class plugin ecosystem for Ember. The goal
is not "users can run scripts", but "Ember can host reusable domain packs,
analysis modules, UI extensions, and workflows for real reverse-engineering
targets such as game engines and live-service clients."

## What's actually live (as of Phase 1)

The full spec below is aspirational. Everything in that spec is optional
until a plugin asks for it. Shipped today:

- **Manifest**: `id`, `name`, `version`, `description`, `entry`,
  `apiVersion`, `permissions[]`, `matchers[]`. Other fields (categories,
  targets, publisher, license, contributes) are not read yet.
- **Matchers** (`kind`): `format`, `arch`, `symbol-present`,
  `string-present`, `section-present`. Literal-value only — no regex,
  no fingerprint matcher yet. Aggregation is strict AND (all must hit
  for score 100 / `matched: true`). Plugins without matchers implicitly
  match every binary.
- **Permissions** (strict enum, unknown names reject the manifest):
  `read.binary-summary`, `read.strings`, `read.annotations`,
  `read.functions`, `read.xrefs`, `read.arities`, `read.decompile`,
  `project.rename`, `project.note`.
- **Host context** (everything permission-gated):
  `loadSummary`, `loadStrings`, `loadFunctions`, `loadXrefs`,
  `loadArities`, `decompile(sym, { view })`, `loadAnnotations`,
  `currentBinaryPath`, `proposalBuilders.{rename, note}`.
- **Proposal kinds**: `rename`, `note`. Staged into the project
  annotations file via the same flow as manual edits.
- **UI**: plugin cards in Settings show a match badge + tooltip; a
  plugin's commands run normally when matched, and require a
  run-anyway confirm when the current binary mismatched.
- **Discovery roots**: `<repo>/plugins/` in dev, `<resources>/plugins/`
  when packaged, plus `<userData>/plugins/` for user-installed.

Not yet implemented (see the full spec below for aspirational shapes):
workflows, UI contributions (plugin-supplied panels/views), findings
store, events, plugin-local storage, task system, capability tiers,
signing/marketplace, fingerprint/RTTI matchers.


The design keeps Ember core generic:

- binary loading, decoding, CFG, IR, SSA, structuring, pseudo-C
- project annotations and review/apply flow
- extension host, plugin registry, permissions, task runtime, UI shell

Domain-specific knowledge lives in plugins:

- engine and game identification
- naming/signature recovery
- packet/protocol discovery
- RTTI/vtable/class-model recovery
- asset/archive readers
- build-to-build carryover
- workflow automation and dashboards

## Goals

- Support an ecosystem, not a one-off extension hook.
- Make game- and engine-specific reversing first-class.
- Allow plugins to interoperate through shared entities and findings.
- Keep core trustworthy by routing plugin mutations through staged project
  annotations instead of direct core mutation.
- Support local-only operation by default; networked ecosystems come later.

## Non-Goals

- Putting game-specific logic in Ember core.
- Letting plugins patch internal analysis structures in-place.
- Treating emitted pseudo-C text as the primary plugin interface.
- Shipping an unbounded arbitrary-code marketplace without permissions.

## Plugin Types

Plugins may contribute one or more of these roles.

### Analyzer Plugins

Read analysis state and publish structured findings or proposals.

Examples:

- Unreal reflection recovery
- Unity IL2CPP metadata correlation
- Source interface-registry discovery
- packet dispatcher detection
- anti-cheat startup-path identification

Outputs:

- findings
- rename proposals
- signature proposals
- subsystem tags
- class/vtable candidates
- packet candidates
- evidence with confidence

### Knowledge Pack Plugins

Ship domain datasets and matching rules, versioned independently from code.

Examples:

- `ember.engine.unreal`
- `ember.game.roblox`
- `ember.net.source2`

Contents:

- known signatures
- string tables
- constant maps
- packet IDs
- class names
- engine fingerprints
- build-family metadata

### Workflow Plugins

Expose user-invoked tasks that orchestrate analysis and proposal staging.

Examples:

- `seed-names-from-logs`
- `map-networking-subsystem`
- `recover-reflected-classes`
- `carry-forward-annotations`

### Format Plugins

Add support for non-executable artifacts common in game reversing.

Examples:

- archive/container readers
- asset bundle decoders
- script metadata loaders
- resource-table importers

### UI Plugins

Contribute panels, dashboards, inspectors, overlays, and review flows.

Examples:

- packet explorer
- subsystem graph
- class tree
- build diff dashboard
- proposal review pane

### Service Plugins

Run background indexing or maintain derived caches.

Examples:

- string classification indexer
- build lineage tracker
- signature cache
- cross-version function matcher

## Core Principles

### 1. Shared Entity Model

Plugins must communicate through typed entities, not ad hoc text blobs.

Core entity kinds:

- `binary`
- `module`
- `section`
- `function`
- `basic_block`
- `callsite`
- `string`
- `import`
- `export`
- `vtable`
- `class_candidate`
- `method_candidate`
- `packet_candidate`
- `subsystem`
- `asset`
- `rename_proposal`
- `signature_proposal`
- `note_proposal`
- `finding`
- `match_evidence`

Each entity should carry:

- stable id within the project
- source plugin or `core`
- timestamp
- confidence when inferred
- evidence references
- applied/proposed status where relevant

### 2. Findings Before Mutations

Plugin output moves through three states:

- `finding`: observed fact or heuristic result
- `proposal`: candidate mutation to the project
- `applied`: committed annotation in the project database

This lets Ember show reviewable diffs before plugin output changes the
user-visible project state.

### 3. Structured Access Over Text Scraping

Plugins should consume structured APIs for symbols, CFG, IR, strings, and
cross-references. Scraping pseudo-C text should be a last resort.

### 4. Capability Boundaries

The host grants permissions explicitly. Plugin packages declare what they
need; the user or local policy decides what is allowed.

## Package Layout

Suggested on-disk layout:

```text
plugins/
  unreal/
    plugin.json
    main.js
    README.md
    schema/
    knowledge/
    ui/
    tests/
  roblox/
    plugin.json
    main.js
    knowledge/
      strings.json
      signatures.json
      packets.json
```

`plugin.json` is required. Other directories are optional.

## Manifest Schema

Every plugin package ships a manifest.

```json
{
  "id": "ember.engine.unreal",
  "name": "Unreal Engine Support",
  "version": "0.1.0",
  "emberApiVersion": "1",
  "description": "Engine-level analysis, matching, and workflow support for Unreal-family binaries.",
  "publisher": "ember-labs",
  "license": "MIT",
  "entry": "main.js",
  "categories": ["analyzer", "knowledge-pack", "workflow", "ui"],
  "targets": ["game", "engine", "windows", "linux"],
  "permissions": [
    "read.binary",
    "read.analysis",
    "read.ir",
    "read.strings",
    "read.xrefs",
    "project.propose",
    "project.apply",
    "ui.panels",
    "storage.plugin"
  ],
  "contributes": {
    "matchers": ["match.binary"],
    "commands": [
      "unreal.detect-engine",
      "unreal.recover-reflection",
      "unreal.seed-names"
    ],
    "panels": ["unreal.dashboard", "unreal.classes"],
    "entitySchemas": ["schema/class-candidate.json"],
    "workflows": ["recover-engine-surface"]
  },
  "dependencies": {
    "ember.net.common": "^0.2.0"
  },
  "engines": {
    "ember": "^0.2.0"
  }
}
```

Manifest fields:

- `id`: globally unique plugin id
- `name`: display name
- `version`: plugin package version
- `emberApiVersion`: plugin API major
- `description`: short summary
- `publisher`: publisher or organization id
- `license`: package license
- `entry`: runtime entry module
- `categories`: one or more plugin roles
- `targets`: coarse target tags
- `permissions`: requested host capabilities
- `contributes`: declarative contributions
- `dependencies`: plugin package dependencies
- `engines`: Ember version compatibility

## Host Lifecycle

The host manages plugin discovery, activation, and teardown.

Lifecycle:

1. Discover installed plugins.
2. Validate manifest and API compatibility.
3. Resolve dependencies.
4. Evaluate permissions against policy.
5. Activate plugin runtime.
6. Register contributions.
7. Deliver lifecycle events.
8. Deactivate cleanly on disable/uninstall/shutdown.

Runtime hooks:

- `activate(ctx)`
- `deactivate()`
- `onBinaryOpen?(session)`
- `onAnalysisComplete?(session)`
- `onProjectLoad?(project)`
- `onProjectDiff?(diff)`

The runtime must not assume a single binary forever; the host may reuse the
same plugin across sessions.

## Matching Model

Plugins may suggest themselves for a target through scored matchers.

Example matcher contract:

```ts
type MatchResult = {
  score: number;           // 0..100
  summary: string;
  evidence: MatchEvidence[];
  tags?: string[];
};
```

Matchers may use:

- file format and architecture
- imports and exports
- strings
- section names
- RTTI/class names
- fingerprints and hashes
- known constants

The UI should present suggestions as confidence-ranked recommendations, not
as hard assertions.

## Capabilities and Permissions

Permission names should be stable and explicit.

Suggested v1 capability set:

- `read.binary`
- `read.analysis`
- `read.cfg`
- `read.ir`
- `read.pseudoc`
- `read.strings`
- `read.xrefs`
- `read.project`
- `project.propose`
- `project.apply`
- `storage.plugin`
- `ui.panels`
- `ui.contextMenus`
- `ui.commandPalette`
- `task.background`
- `network.http`
- `filesystem.external`

Default posture:

- allow read-only analysis access
- allow plugin-local storage
- deny network by default
- deny external filesystem by default
- require explicit approval for project-apply and advanced capabilities

The platform should eventually distinguish between:

- sandboxed plugins
- trusted plugins
- native plugins

Native plugins are not required for v1 and should be treated as a future,
high-risk tier.

## Runtime Context

Plugins receive a structured host context.

```ts
interface PluginContext {
  manifest: PluginManifest;
  log: Logger;
  capabilities: CapabilitySet;
  commands: CommandRegistry;
  tasks: TaskService;
  storage: PluginStorage;
  findings: FindingsStore;
  proposals: ProposalStore;
  ui: UiRegistry;
  events: EventBus;
  sessions: SessionRegistry;
}
```

Per-binary session context:

```ts
interface BinarySession {
  id: string;
  binary: BinaryApi;
  analysis: AnalysisApi;
  strings: StringsApi;
  xrefs: XrefsApi;
  project: ProjectApi;
  graph: GraphApi;
}
```

The `ProjectApi` must preserve Ember's staged mutation model. Example write
operations:

- `project.proposeRename(...)`
- `project.proposeSignature(...)`
- `project.proposeNote(...)`
- `project.preview(proposalSet)`
- `project.apply(proposalSet)`

Do not expose raw mutable internals of analysis structures to plugin code.

## Command and Workflow Model

Plugins may contribute commands and workflows.

Command properties:

- id
- title
- description
- required capabilities
- input schema
- output schema
- whether it is preview-only or mutating

Workflows are named multi-step tasks that compose analysis and proposals.

Examples:

- detect engine
- classify subsystems
- seed names from logs
- recover packet handlers
- carry forward names from prior build

Workflows should run through the host task system so the UI can show:

- progress
- cancellation
- logs
- produced findings
- staged proposals

## Findings, Proposals, and Review

Every plugin-generated conclusion should be attributable and reviewable.

Finding shape:

```ts
type Finding = {
  id: string;
  pluginId: string;
  kind: string;
  subject: EntityRef;
  confidence: number;
  summary: string;
  evidence: EvidenceRef[];
  payload: unknown;
};
```

Proposal shape:

```ts
type Proposal = {
  id: string;
  pluginId: string;
  kind: "rename" | "signature" | "note" | "tag";
  subject: EntityRef;
  confidence: number;
  summary: string;
  evidence: EvidenceRef[];
  payload: unknown;
};
```

Ember should let users:

- filter proposals by plugin and confidence
- inspect evidence before apply
- accept/reject individually or in batches
- persist provenance after apply

## Shared Graph

Game-focused reversing benefits from a project graph rather than isolated
flat annotations.

Useful relation kinds:

- `calls`
- `references_string`
- `belongs_to_subsystem`
- `handles_packet`
- `owns_vtable`
- `implements_method_candidate`
- `loads_asset`
- `matches_engine_profile`
- `derived_from_build`

Plugins may publish graph facts with provenance and confidence. Other
plugins can consume those graph facts instead of duplicating detection work.

Example:

1. networking plugin marks a set of packet-dispatch functions
2. knowledge pack maps packet ids to names
3. UI plugin renders packet explorer
4. workflow plugin stages rename and signature proposals

## UI Contributions

Plugins should contribute UI declaratively where possible.

Supported contribution points:

- command palette entries
- right-click context actions
- sidebar panels
- inspectors
- graph overlays
- dashboards
- review views
- status widgets

Example panel contributions:

- `packet-explorer`
- `engine-dashboard`
- `class-tree`
- `build-diff`

The host owns navigation, docking, persistence, and theming. Plugins provide
data and renderers, not their own window-management model.

## Package Dependencies

The ecosystem should support layered reuse.

Example stack:

- `ember.engine.unreal`
- `ember.net.unreal`
- `ember.game.valorant`
- `ember.game.valorant.build-2026-04-22`

This keeps generic engine knowledge separate from game- or build-specific
overlays.

Dependency rules:

- hard dependencies must resolve before activation
- optional peers may enrich UI or workflows if present
- plugin ids are immutable once published
- API-major mismatches block activation

## Storage Model

Plugin storage should be isolated from project annotations.

Two storage classes:

- plugin-private storage: caches, indexes, settings
- project-bound derived state: findings, proposals, graph facts

Project-bound derived state should be exportable with the project or
rebuildable from plugin execution, depending on type. The host should let
plugins mark data as:

- cacheable
- reproducible
- user-visible
- exportable

## Distribution Model

The ecosystem rollout can happen in phases.

Phase 1:

- local plugin folders
- manifest validation
- runtime loading
- permissions
- commands
- findings and proposals
- UI panels

Phase 2:

- dependency resolution
- signed packages
- plugin install/update/remove commands
- git or registry-backed distribution

Phase 3:

- marketplace
- verified publishers
- ratings/download stats
- automated compatibility checks

## Testing

Plugins need first-class testing support.

Recommended package tests:

- manifest validation
- capability enforcement
- fixture-based analyzer tests
- proposal golden tests
- schema validation
- compatibility tests against Ember API versions

The host should offer a plugin test runner over small fixture binaries and
expected findings/proposals.

## Versioning

Two different versions must be tracked:

- Ember application version
- Ember plugin API version

Rules:

- plugin API major changes may break runtime compatibility
- plugin package version tracks plugin behavior and datasets
- data schema versions must be explicit for exportable findings/proposals

## Game-Focused First-Class Extensions

If Ember wants a differentiated ecosystem for games, the host should treat
these domains as first-class extension areas:

- engine identification
- reflection / object-model recovery
- packet/protocol mapping
- asset/archive parsing
- build-to-build diffing
- anti-cheat / startup guard discovery
- scripting VM discovery
- subsystem classification

These are more useful in practice than generic "custom toolbar button"
extensions, so the platform should optimize around them.

## Example Plugin Families

Strong early ecosystem targets:

- `ember.engine.unreal`
- `ember.engine.unity-native`
- `ember.engine.source`
- `ember.game.roblox`
- `ember.net.common`
- `ember.diff.build-lineage`
- `ember.assets.pak`

## Recommended Implementation Order

1. Define the manifest, lifecycle, and permissions.
2. Add findings/proposals as first-class host concepts.
3. Add typed session APIs and shared entities.
4. Add command and workflow registration.
5. Add UI contribution points.
6. Add dependency resolution and packaging.
7. Add marketplace and signed distribution.

This order keeps the platform useful early without locking Ember into a weak
"just run a script" design.
