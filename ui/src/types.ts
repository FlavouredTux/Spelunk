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
  sections: { name: string; vaddr: string; size: string; flags: string }[];
  functions: FunctionInfo[];
  imports: FunctionInfo[];
};

// `cfg` and `cfgPseudo` differ only in body content — both render in
// the graph view. The CfgGraph component owns a toggle that switches
// between them.
export type ViewKind = "pseudo" | "asm" | "cfg" | "cfgPseudo" | "ir" | "ssa";

export type ParamSig = {
  type: string;    // e.g. "const char *"
  name: string;    // e.g. "path"
};

export type FunctionSig = {
  returnType: string;
  params: ParamSig[];
};

export type Annotations = {
  renames:    Record<string, string>;        // addr hex ("0x6661") -> user-given name
  notes:      Record<string, string>;        // addr hex -> note text
  signatures: Record<string, FunctionSig>;   // addr hex -> declared signature
  // Per-function local / arg / SSA-result renames. Outer key is the
  // owning function's address hex; inner map is `from-name → to-name`.
  // Applied renderer-side as word-boundary substitutions on pseudo-C
  // output — they don't flow through the C++ analysis pipeline (so
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

export type PluginInfo = {
  id: string;
  name: string;
  version: string;
  description: string;
  permissions: string[];
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

export type PluginRunResult = {
  pluginId: string;
  commandId: string;
  summary: string;
  notes: string;
  proposals: PluginRenameProposal[];
  applied: boolean;
  appliedCount: number;
  annotations?: Annotations;
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
      setBinary:        (p: string) => Promise<string | null>;
      binary:           () => Promise<string | null>;
      run:              (args: string[]) => Promise<string>;

      loadAnnotations:   (bp: string) => Promise<Annotations>;
      saveAnnotations:   (bp: string, data: Annotations) => Promise<boolean>;
      exportAnnotations: (bp: string, data: Annotations) => Promise<string | null>;
      importAnnotations: () => Promise<(Annotations & { path: string }) | null>;
      savePatchedAs:     () => Promise<string | null>;

      recents:          () => Promise<string[]>;
      openRecent:       (bp: string) => Promise<string>;
      updates: {
        check: () => Promise<ReleaseUpdateStatus>;
        downloadAndInstall: () => Promise<{
          ok: boolean;
          path?: string;
          message?: string;
          error?: string;
        }>;
      };
      plugins: {
        list: () => Promise<PluginInfo[]>;
        run: (pluginId: string, commandId: string, opts?: {
          apply?: boolean;
          args?: Record<string, unknown>;
        }) => Promise<PluginRunResult>;
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
