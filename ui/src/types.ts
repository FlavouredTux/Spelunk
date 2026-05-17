export type FunctionInfo = {
  addr: string;       // "0x4747"
  addrNum: number;    // 0x4747
  size: number;
  kind: string;       // "function", "object", ...
  name: string;
  isImport?: boolean;
};

export type BinaryInfo = {
  path: string;
  format: string;
  arch: string;
  endian: string;
  entry: string;
  base: string;       // preferred_load_base, e.g. "0x400000"
  sections: { name: string; vaddr: string; size: string; flags: string }[];
  functions: FunctionInfo[];
  imports: FunctionInfo[];
};

// `cfg` and `cfgPseudo` differ only in body content - both render in
// the graph view. The CfgGraph component owns a toggle that switches
// between them.
export type ViewKind = "pseudo" | "asm" | "cfg" | "cfgPseudo" | "ir" | "ssa" | "identify";

export type ParamSig = {
  type: string;    // e.g. "const char *"
  name: string;    // e.g. "path"
};

export type FunctionSig = {
  returnType: string;
  params: ParamSig[];
};

export type IdentifyResult = {
  addr: string;        // "0x4747"
  addrNum: number;     // 0x4747
  name: string;        // "sha256", "chacha20", etc.
  category: string;    // "hash", "encryption", "network", "encoding"
  confidence: number;  // 0..1
  signal: string;      // "constants" or "imports"
  via: string;         // detail string
};

export type Annotations = {
  renames:    Record<string, string>;        // addr hex ("0x6661") -> user-given name
  notes:      Record<string, string>;        // addr hex -> note text
  signatures: Record<string, FunctionSig>;   // addr hex -> declared signature
  // Struct field names keyed as `<function-addr>:<param-index>:<offset>`,
  // where param-index is 0-based and offset is the textual value passed
  // through to the CLI annotation file (decimal or 0x-prefixed hex).
  fields?: Record<string, string>;
  // Per-function local / arg / SSA-result renames. Outer key is the
  // owning function's address hex; inner map is `from-name → to-name`.
  // Applied renderer-side as word-boundary substitutions on pseudo-C
  // output - they don't flow through the C++ analysis pipeline (so
  // they don't show in asm / ir / ssa views, only in pseudo).
  localRenames?: Record<string, Record<string, string>>;
  // Byte patches keyed by virtual-address hex. Each entry replaces
  // `orig` bytes (kept for revert + display) with `bytes` at that
  // address. Both stored as space-free uppercase hex strings (e.g.
  // "9090C3"). Applied through the C++ CLI's --apply-patches: the
  // main process materializes a patched temp binary and routes all
  // analysis through it, so the disasm and pseudo-C views reflect
  // patches live.
  patches?: Record<string, { bytes: string; orig?: string; comment?: string }>;
};

export type Xrefs = {
  callers: Record<number, number[]>;  // callee addrNum -> caller addrNums
  callees: Record<number, number[]>;  // caller addrNum -> callee addrNums
};

export type StringEntry = {
  addr:    string;       // "0x90b53"
  addrNum: number;
  text:    string;       // already-unescaped
  xrefs:   number[];     // instruction addrs referencing the string
};

// addrNum (function start) -> inferred SysV arity (0..6)
export type Arities = Record<number, number>;

export type AiMessage  = { role: "system" | "user" | "assistant"; content: string };
export type AiProvider = "openrouter" | "9router" | "assistant-cli" | "codex-cli";
export type AiConfig   = {
  provider:  AiProvider;
  model:     string;
  hasKey:    boolean;     // only meaningful for openrouter
  encrypted: boolean;
};
export type AiCliStatus = {
  installed: boolean;
  loggedIn:  boolean;
  version:   string;
};
export type AiChatRequest = {
  messages:    AiMessage[];
  model?:      string;
  temperature?: number;
};
// Agentic tool-call events. `args` is the parsed arguments object the
// model passed; `chars` on Done is the result length (rough proxy for
// how much context just got pulled in).
export type AiToolInvocation = { name: string; args: Record<string, unknown> };
export type AiToolResult     = { name: string; ok: boolean; chars: number };

export type PluginCommand = {
  id: string;
  ref: string;
  title: string;
  description: string;
};

export type PluginMatcher =
  | { kind: "format";          value: string }
  | { kind: "arch";            value: string }
  | { kind: "symbol-present";  name:  string }
  | { kind: "string-present";  text:  string }
  | { kind: "section-present"; name:  string };

export type PluginMatchResult = {
  score: number;                                 // 0..100
  matched: boolean;                              // score === 100
  evidence: Array<{ kind: string; detail: string }>;
  failed:   Array<PluginMatcher & { detail: string }>;
};

export type PluginPanelContribution = {
  id: string;
  title: string;
  description: string;
  command: string;     // id of the command that produces this panel's data
};

export type PluginContributes = {
  panels: PluginPanelContribution[];
};

export type PluginPanelRow = {
  label: string;
  addr?: string;       // hex-formatted; when present the row is jump-navigable
  detail?: string;
  tags?: string[];
};

export type PluginPanelData =
  | { kind: "list"; rows: PluginPanelRow[] };

export type PluginInfo = {
  id: string;
  name: string;
  version: string;
  description: string;
  permissions: string[];
  matchers: PluginMatcher[];
  contributes: PluginContributes;
  commands: PluginCommand[];
  invalid?: boolean;
};

export type PluginRenameProposal = {
  kind: "rename";
  addr: string;
  name: string;
  confidence: number;
  reason: string;
};

export type PluginNoteProposal = {
  kind: "note";
  addr: string;
  text: string;
  confidence: number;
  reason: string;
};

export type PluginLogEntry = {
  level: "info" | "warn" | "error";
  text:  string;
  ts:    number;     // ms since epoch
};

export type PluginRunResult = {
  pluginId: string;
  commandId: string;
  summary: string;
  notes: string;
  proposals: Array<PluginRenameProposal | PluginNoteProposal>;
  panel: PluginPanelData | null;
  logs?: PluginLogEntry[];
  applied: boolean;
  appliedCount: number;
  annotations?: Annotations;
};

// Shape pushed to Discord Rich Presence by the renderer. The main
// process does the field-length / button-URL sanitisation and owns
// the actual RPC connection - see electron/main.cjs.
export type DiscordActivityPayload = {
  details?: string;        // line 1 (e.g. binary file name)
  state?: string;          // line 2 (e.g. function + view)
  startTimestamp?: number; // ms since epoch; renders as "elapsed"
  largeImageKey?: string;  // asset name uploaded in Discord Dev Portal
  largeImageText?: string;
  smallImageKey?: string;
  smallImageText?: string;
  buttons?: Array<{ label: string; url: string }>;
  // Which field drives the inline mini-status under the user's name.
  // 0 = NAME ("ember"), 1 = STATE (the function · view line),
  // 2 = DETAILS (the binary line). Only renders for type=Playing.
  statusDisplayType?: 0 | 1 | 2;
};

export type ReleaseUpdateStatus = {
  ok: boolean;
  currentVersion?: string;
  latestVersion?: string;
  tag?: string;
  releaseName?: string;
  url?: string;
  assetName?: string;
  assetUrl?: string;
  notes?: string;
  available?: boolean;
  error?: string;
};

declare global {
  interface Window {
    ember: {
      pick:             () => Promise<string | null>;
      // CLI-launch / second-instance binary open. Returns an unsubscribe fn.
      onOpenBinary?:    (handler: (path: string) => void) => () => void;
      pickFile:         (opts?: {
        title?: string;
        filters?: { name: string; extensions: string[] }[];
      } | null) => Promise<string | null>;
      setBinary:        (p: string) => Promise<string | null>;
      binary:           () => Promise<string | null>;
      run:              (args: string[]) => Promise<string>;
      debug?: {
        diagnostics: () => Promise<Record<string, unknown>>;
      };
      appVersion:       () => Promise<string>;
      openExternal:     (url: string) => Promise<boolean>;

      loadAnnotations:   (bp: string) => Promise<Annotations>;
      saveAnnotations:   (bp: string, data: Annotations) => Promise<boolean>;
      applyEmberScript:  (scriptPath: string, dryRun: boolean) => Promise<{
        dryRun: boolean;
        preview: string | null;
        annotations: Annotations | null;
      }>;
      exportAnnotations: (bp: string, data: Annotations) => Promise<string | null>;
      importAnnotations: () => Promise<(Annotations & { path: string }) | null>;
      importCorpusRenames: (opts?: {
        threshold?: number;
        minFnSize?: number;
        maxFnSize?: number;
        l0Prefilter?: boolean;
      } | null) => Promise<{
        annotations: Annotations;
        imported: number;
        scanned: number;
        corpusPaths: string[];
      } | null>;
      identify: (opts?: { threshold?: number } | null) => Promise<IdentifyResult[]>;
      savePatchedAs:     () => Promise<string | null>;

      recents:          () => Promise<string[]>;
      openRecent:       (bp: string) => Promise<string>;
      readBytes:        (offset: number, length: number) => Promise<{
        base64: string;
        eof: boolean;
        totalSize: number;
      }>;
      vaddrToOffset:    (vaddr: number) => Promise<number | null>;
      updates: {
        check: () => Promise<ReleaseUpdateStatus>;
        downloadAndInstall: () => Promise<{
          ok: boolean;
          path?: string;
          message?: string;
          error?: string;
        }>;
      };
      discord: {
        setActivity: (payload: DiscordActivityPayload | null) => Promise<boolean>;
      };
      plugins: {
        list:  () => Promise<PluginInfo[]>;
        run:   (pluginId: string, commandId: string, opts?: {
          apply?: boolean;
          args?: Record<string, unknown>;
        }) => Promise<PluginRunResult>;
        match: (pluginId: string) => Promise<PluginMatchResult>;
      };

      ai: {
        getConfig:    () => Promise<AiConfig>;
        setConfig:    (c: {
          apiKey?:   string;
          model?:    string;
          provider?: AiProvider;
        }) => Promise<AiConfig>;
        listModels:   (provider?: AiProvider) => Promise<string[]>;
        detectCli:    (kind: "assistant-cli" | "codex-cli") => Promise<AiCliStatus>;
        chat:         (req: AiChatRequest) => Promise<string>;
        cancel:       (id: string) => Promise<boolean>;
        onChunk:      (cb: (id: string, delta: string) => void) => () => void;
        onDone:       (cb: (id: string, info: { chars: number }) => void) => () => void;
        onError:      (cb: (id: string, msg: string) => void) => () => void;
        onTool:       (cb: (id: string, info: AiToolInvocation) => void) => () => void;
        onToolDone:   (cb: (id: string, info: AiToolResult) => void) => () => void;
      };
    };
  }
}
