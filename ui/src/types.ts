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

declare global {
  interface Window {
    ember: {
      pick:             () => Promise<string | null>;
      setBinary:        (p: string) => Promise<string | null>;
      binary:           () => Promise<string | null>;
      run:              (args: string[]) => Promise<string>;

      loadAnnotations:  (bp: string) => Promise<Annotations>;
      saveAnnotations:  (bp: string, data: Annotations) => Promise<boolean>;

      recents:          () => Promise<string[]>;
      openRecent:       (bp: string) => Promise<string>;

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
      };
    };
  }
}
