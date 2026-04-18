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

export type ViewKind = "pseudo" | "asm" | "cfg" | "ir" | "ssa";

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
    };
  }
}
