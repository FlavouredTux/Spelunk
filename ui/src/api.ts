import type {
  BinaryInfo, FunctionInfo, ViewKind, Xrefs, Annotations, StringEntry, Arities,
  PluginInfo, PluginMatchResult, PluginRunResult, ReleaseUpdateStatus,
} from "./types";

// ---------- Renderer-side result cache ------------------------------------
//
// Every UI gesture used to spawn a fresh `ember` process via IPC, which
// re-loaded the entire binary off disk. On a 150 MB PE that's a one- to
// three-second wall on EVERY tab switch. The fix is two-tier: a
// promise-cache here in the renderer (zero IPC for repeats), and a
// matching stdout cache in the Electron main process keyed by binary
// mtime so even cold renderer cache misses stay snappy as long as the
// binary hasn't been rebuilt.
//
// Entries are Promises rather than resolved values so concurrent
// duplicate requests dedupe to a single underlying CLI call (matters
// during route changes that fire multiple effects).

class Lru<K, V> {
  private m = new Map<K, V>();
  constructor(private cap: number) {}
  get(k: K): V | undefined {
    const v = this.m.get(k);
    if (v === undefined) return undefined;
    // Bubble to most-recent position. Map iteration order = insertion
    // order, so re-insert on hit.
    this.m.delete(k);
    this.m.set(k, v);
    return v;
  }
  set(k: K, v: V): void {
    if (this.m.has(k)) this.m.delete(k);
    this.m.set(k, v);
    while (this.m.size > this.cap) {
      const first = this.m.keys().next().value as K | undefined;
      if (first === undefined) break;
      this.m.delete(first);
    }
  }
  delete(k: K): boolean { return this.m.delete(k); }
  clear(): void { this.m.clear(); }
  get size(): number { return this.m.size; }
}

// Sized to comfortably hold a session's worth of (function × view)
// browsing on a multi-thousand-function binary (5 views × ~100 functions
// before LRU eviction kicks in).
const FUNC_CACHE = new Lru<string, Promise<string>>(512);
let SUMMARY_PROMISE:  Promise<BinaryInfo>    | null = null;
let XREFS_PROMISE:    Promise<Xrefs>         | null = null;
let STRINGS_PROMISE:  Promise<StringEntry[]> | null = null;
let ARITIES_PROMISE:  Promise<Arities>       | null = null;

// Drop everything cached. Call when:
//   - a new binary is opened (results are per-binary)
//   - annotations change (renames flow into pseudo-C output, so cached
//     pre-rename text is stale)
//   - a manual "refresh" gesture
export function clearRendererCaches(): void {
  FUNC_CACHE.clear();
  SUMMARY_PROMISE = null;
  XREFS_PROMISE   = null;
  STRINGS_PROMISE = null;
  ARITIES_PROMISE = null;
  IDENTIFY_PROMISE = null;
}

// Promise-cache wrapper that evicts on rejection so a transient error
// (binary momentarily absent during rebuild, etc.) doesn't pin a stale
// failure forever.
function memoOnce<T>(get: () => Promise<T>, set: (p: Promise<T> | null) => void,
                    cur: Promise<T> | null): Promise<T> {
  if (cur) return cur;
  const p = get().catch((e) => { set(null); throw e; });
  set(p);
  return p;
}

export async function pickBinary(): Promise<string | null> {
  return await window.ember.pick();
}

export async function openRecent(path: string): Promise<string> {
  return await window.ember.openRecent(path);
}

// Read raw bytes from the currently-loaded binary at a file offset.
// Returns a Uint8Array (base64-decoded from the IPC payload).
export async function readBytes(offset: number, length: number): Promise<{
  bytes: Uint8Array;
  eof: boolean;
  totalSize: number;
}> {
  const r = await window.ember.readBytes(offset, length);
  const bin = atob(r.base64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return { bytes, eof: r.eof, totalSize: r.totalSize };
}

// Translate a virtual address into a file offset using the binary's
// PT_LOAD / LC_SEGMENT / PE-section map. Returns null when the vaddr
// falls outside any loaded segment.
export async function vaddrToOffset(vaddr: number): Promise<number | null> {
  return await window.ember.vaddrToOffset(vaddr);
}

export async function getRecents(): Promise<string[]> {
  return await window.ember.recents();
}

export async function checkForReleaseUpdate(): Promise<ReleaseUpdateStatus> {
  return await window.ember.updates.check();
}

export async function downloadAndInstallReleaseUpdate(): Promise<{
  ok: boolean;
  path?: string;
  message?: string;
  error?: string;
}> {
  return await window.ember.updates.downloadAndInstall();
}

export async function listPlugins(): Promise<PluginInfo[]> {
  return await window.ember.plugins.list();
}

export async function runPluginCommand(
  pluginId: string,
  commandId: string,
  opts?: { apply?: boolean; args?: Record<string, unknown> },
): Promise<PluginRunResult> {
  return await window.ember.plugins.run(pluginId, commandId, opts);
}

export async function matchPlugin(pluginId: string): Promise<PluginMatchResult> {
  return await window.ember.plugins.match(pluginId);
}

// Header-only summary: format, arch, entry, sections, imports. No
// function list — that's the slow query, fetched separately so the UI
// shell can render before it returns. `loadHeader` and `loadFunctions`
// each spawn the CLI once and are independent; they used to be a single
// Promise.all inside the old `loadSummary` and the slow leg blocked the
// fast one.
export async function loadHeader(): Promise<BinaryInfo> {
  return memoOnce<BinaryInfo>(
    async () => {
      const path = (await window.ember.binary()) ?? "";
      const rawSummary = await window.ember.run([]);
      const info = parseSummary(rawSummary, path);
      info.functions = [];
      return info;
    },
    (p) => { SUMMARY_PROMISE = p; },
    SUMMARY_PROMISE,
  );
}

// `--full-analysis` bypasses the packed-binary gate in
// enumerate_functions; only set it when the user explicitly clicked
// "Run full analysis" on the heads-up banner.
export async function loadFunctions(
  opts: { fullAnalysis?: boolean } = {},
): Promise<FunctionInfo[]> {
  const args = opts.fullAnalysis
    ? ["--functions", "--full-analysis"]
    : ["--functions"];
  const raw = await window.ember.run(args);
  return parseFunctionsTsv(raw);
}

function parseFunctionsTsv(raw: string): FunctionInfo[] {
  const out: FunctionInfo[] = [];
  // Pass 1: parse every row, collapsing kinds onto "function".
  type Row = FunctionInfo & { rawKind: string };
  const rows: Row[] = [];
  for (const line of raw.split("\n")) {
    if (!line) continue;
    // Columns: addr\tsize\tkind\tname — all four required.
    const parts = line.split("\t");
    if (parts.length < 4) continue;
    const addr = parts[0];
    const addrNum = parseInt(addr, 16);
    if (!Number.isFinite(addrNum)) continue;
    const size    = parseInt(parts[1], 16) || 0;
    const rawKind = parts[2];
    const name    = parts.slice(3).join("\t").trim();
    rows.push({ addr, addrNum, size, kind: "function", name, rawKind });
  }
  // Pass 2: drop sub entries that duplicate a real symbol at the same
  // address (the symbol carries the name; the sub row would just be a
  // gray placeholder). Earlier this filter also dropped every size=0
  // sub on the assumption they were spurious mid-function rows from
  // PE linear-sweep, but on stripped Linux/ELF binaries every
  // CFG-discovered sub legitimately reports size=0 (extents need a
  // CFG build the enumerator skips), so dropping them here hid every
  // unnamed function from the sidebar — a fully stripped 179-fn
  // sha256sum would render as 2 entries. The C++ enumerator already
  // performs stride-1 dedup against known-extent windows, so what
  // reaches us is real function entries; trust them.
  const symbolAddrs = new Set<number>();
  for (const r of rows) if (r.rawKind === "symbol") symbolAddrs.add(r.addrNum);
  for (const r of rows) {
    if (r.rawKind === "sub" && symbolAddrs.has(r.addrNum)) continue;
    out.push({ addr: r.addr, addrNum: r.addrNum, size: r.size, kind: r.kind, name: r.name });
  }
  return out;
}

export type LoadFunctionOptions = {
  // Pass --labels to the CLI so pseudo-C / cfg-pseudo output carries
  // `// bb_xxxxxx` markers before each block. Cache key includes this
  // so toggling it doesn't return stale unlabelled text.
  showBbLabels?: boolean;
};

export async function loadFunction(
  sym: string,
  view: ViewKind,
  opts: LoadFunctionOptions = {},
): Promise<string> {
  const wantsLabels = !!opts.showBbLabels &&
    (view === "pseudo" || view === "cfgPseudo");
  const key = `${view}|${sym}|labels=${wantsLabels ? 1 : 0}`;
  const cacheInRenderer = !wantsLabels;
  if (cacheInRenderer) {
    const hit = FUNC_CACHE.get(key);
    if (hit) return hit;
  }
  const args: Record<ViewKind, string[]> = {
    pseudo:    ["-p", "-s", sym],
    asm:       ["-d", "-s", sym],
    cfg:       ["-c", "-s", sym],
    cfgPseudo: ["--cfg-pseudo", "-s", sym],
    ir:        ["-i", "-s", sym],
    ssa:       ["-i", "--ssa", "-s", sym],
    identify:  ["--identify"],
  };
  const finalArgs = [...args[view]];
  if (wantsLabels) finalArgs.push("--labels");
  const p = window.ember.run(finalArgs).catch((e) => {
    FUNC_CACHE.delete(key);
    throw e;
  });
  if (cacheInRenderer) FUNC_CACHE.set(key, p);
  return p;
}

export async function loadXrefs(): Promise<Xrefs> {
  return memoOnce<Xrefs>(
    () => loadXrefsImpl(),
    (p) => { XREFS_PROMISE = p; },
    XREFS_PROMISE,
  );
}

async function loadXrefsImpl(): Promise<Xrefs> {
  const raw = await window.ember.run(["--xrefs"]);
  const callers: Record<number, number[]> = {};
  const callees: Record<number, number[]> = {};
  for (const line of raw.split("\n")) {
    const m = /^(0x[0-9a-f]+)\s*->\s*(0x[0-9a-f]+)/.exec(line);
    if (!m) continue;
    const caller = parseInt(m[1], 16);
    const callee = parseInt(m[2], 16);
    (callees[caller] ??= []).push(callee);
    (callers[callee] ??= []).push(caller);
  }
  // Dedupe
  for (const k in callers) callers[k] = Array.from(new Set(callers[k]));
  for (const k in callees) callees[k] = Array.from(new Set(callees[k]));
  return { callers, callees };
}

export async function loadStrings(): Promise<StringEntry[]> {
  return memoOnce<StringEntry[]>(
    () => loadStringsImpl(),
    (p) => { STRINGS_PROMISE = p; },
    STRINGS_PROMISE,
  );
}

async function loadStringsImpl(): Promise<StringEntry[]> {
  const raw = await window.ember.run(["--strings"]);
  const out: StringEntry[] = [];
  for (const line of raw.split("\n")) {
    if (!line) continue;
    // Split on unescaped '|' only (the emitter escapes any embedded '|' as '\|').
    const parts = splitPipes(line);
    if (parts.length < 3) continue;
    const [addrHex, escText, xrefStr] = parts;
    const addrNum = parseInt(addrHex, 16);
    if (!Number.isFinite(addrNum)) continue;
    const text = unescape(escText);
    const xrefs = xrefStr
      ? xrefStr.split(",").map((s) => parseInt(s, 16)).filter(Number.isFinite)
      : [];
    out.push({ addr: "0x" + addrNum.toString(16), addrNum, text, xrefs });
  }
  return out;
}

export async function loadArities(): Promise<Arities> {
  return memoOnce<Arities>(
    () => loadAritiesImpl(),
    (p) => { ARITIES_PROMISE = p; },
    ARITIES_PROMISE,
  );
}

async function loadAritiesImpl(): Promise<Arities> {
  const raw = await window.ember.run(["--arities"]);
  const out: Arities = {};
  for (const line of raw.split("\n")) {
    const m = /^(0x[0-9a-f]+)\s+(\d+)$/.exec(line.trim());
    if (!m) continue;
    out[parseInt(m[1], 16)] = parseInt(m[2], 10);
  }
  return out;
}

function splitPipes(line: string): string[] {
  const out: string[] = [];
  let cur = "";
  for (let i = 0; i < line.length; ++i) {
    const c = line[i];
    if (c === "\\" && i + 1 < line.length) {
      cur += c + line[i + 1];
      ++i;
      continue;
    }
    if (c === "|") { out.push(cur); cur = ""; continue; }
    cur += c;
  }
  out.push(cur);
  return out;
}

function unescape(s: string): string {
  let out = "";
  for (let i = 0; i < s.length; ++i) {
    const c = s[i];
    if (c !== "\\" || i + 1 >= s.length) { out += c; continue; }
    const n = s[++i];
    switch (n) {
      case "n": out += "\n"; break;
      case "r": out += "\r"; break;
      case "t": out += "\t"; break;
      case "\\": out += "\\"; break;
      case "|": out += "|"; break;
      case "x": {
        const hex = s.slice(i + 1, i + 3);
        if (/^[0-9a-fA-F]{2}$/.test(hex)) {
          out += String.fromCharCode(parseInt(hex, 16));
          i += 2;
        } else {
          out += n;
        }
        break;
      }
      default: out += n;
    }
  }
  return out;
}

export async function loadAnnotations(binaryPath: string): Promise<Annotations> {
  return await window.ember.loadAnnotations(binaryPath);
}

export async function saveAnnotations(binaryPath: string, data: Annotations): Promise<void> {
  await window.ember.saveAnnotations(binaryPath, data);
}

export async function exportAnnotations(binaryPath: string, data: Annotations): Promise<string | null> {
  return await window.ember.exportAnnotations(binaryPath, data);
}

export type ImportedAnnotations = Annotations & { path: string };
export async function importAnnotations(): Promise<ImportedAnnotations | null> {
  return await window.ember.importAnnotations();
}

export type CorpusImportResult = {
  annotations: Annotations;
  imported: number;
  scanned: number;
  corpusPaths: string[];
};

export async function importCorpusRenames(opts?: {
  threshold?: number;
  minFnSize?: number;
  maxFnSize?: number;
  l0Prefilter?: boolean;
}): Promise<CorpusImportResult | null> {
  return await window.ember.importCorpusRenames(opts ?? null);
}

import type { IdentifyResult } from "./types";
export type { IdentifyResult };

let IDENTIFY_PROMISE: Promise<IdentifyResult[]> | null = null;

export async function loadIdentifications(opts?: {
  threshold?: number;
}): Promise<IdentifyResult[]> {
  return memoOnce<IdentifyResult[]>(
    () => window.ember.identify(opts ?? null),
    (p) => { IDENTIFY_PROMISE = p; },
    IDENTIFY_PROMISE,
  );
}

function parseSummary(raw: string, path: string): BinaryInfo {
  const lines = raw.split("\n");
  const info: BinaryInfo = {
    path,
    format: "",
    arch: "",
    endian: "",
    entry: "",
    base: "0x0",
    sections: [],
    functions: [],
    imports: [],
  };

  for (const l of lines) {
    const m = /^(file|format|arch|endian|entry|base)\s+(.+)$/.exec(l.trim());
    if (m) {
      if (m[1] === "format") info.format = m[2];
      else if (m[1] === "arch") info.arch = m[2];
      else if (m[1] === "endian") info.endian = m[2];
      else if (m[1] === "entry") info.entry = m[2];
      else if (m[1] === "base") info.base = m[2];
    }
  }

  let mode: "none" | "sections" | "defined" | "imports" = "none";
  for (const raw_line of lines) {
    const line = raw_line.replace(/\r$/, "");
    if (/^sections\s+\(\d+\)/.test(line)) { mode = "sections"; continue; }
    if (/^defined symbols\s+\(\d+\)/.test(line)) { mode = "defined"; continue; }
    if (/^imports\s+\(\d+\)/.test(line)) { mode = "imports"; continue; }
    if (/^(file|format|arch|endian|entry|base)/.test(line.trim())) { mode = "none"; continue; }
    if (!line.trim()) continue;

    if (mode === "sections") {
      const m = /^\s*(\d+)\s+(\S+)?\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(\S+)/.exec(line);
      if (m && m[2]) {
        info.sections.push({ name: m[2], vaddr: m[3], size: m[4], flags: m[5] });
      }
      continue;
    }
    if (mode === "defined") {
      const m = /^\s*(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(\S+)\s+(.+)$/.exec(line);
      if (m) {
        info.functions.push({
          addr: m[1],
          addrNum: parseInt(m[1], 16),
          size: parseInt(m[2], 16),
          kind: m[3],
          name: m[4].trim(),
        });
      }
      continue;
    }
    if (mode === "imports") {
      const m = /^\s*(\S+)\s+(.+)$/.exec(line);
      if (m) {
        info.imports.push({
          addr: "0x0",
          addrNum: 0,
          size: 0,
          kind: m[1],
          name: m[2].trim(),
          isImport: true,
        });
      }
      continue;
    }
  }

  // Keep real named functions, drop placeholders (<section-N>, etc.).
  // `size > 0` used to gate here too, but dynsym on stripped binaries
  // has no size info — `_start` and library exports would vanish.
  info.functions = info.functions.filter(
    (f) => f.kind === "function" && f.name && !f.name.startsWith("<"),
  );

  return info;
}

export function formatAddr(n: number): string {
  return "0x" + n.toString(16).padStart(8, "0");
}

export function formatSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export function demangle(name: string): string {
  if (!name.startsWith("_Z")) return name;
  const syms = Array.from(name.matchAll(/(\d+)([A-Za-z_][\w]*)/g));
  if (syms.length >= 1) {
    const parts = syms.map((m) => m[2]);
    return parts.slice(-2).join("::");
  }
  return name;
}

// Resolve the "best" display name: user rename → demangled → mangled
import type { Annotations as Ann } from "./types";
export function displayName(fn: FunctionInfo, annotations?: Ann): string {
  if (annotations?.renames[fn.addr]) return annotations.renames[fn.addr];
  return demangle(fn.name);
}

// Format a raw address as "0x1234" like the backend does
export function formatAddrHex(n: number): string {
  return "0x" + n.toString(16);
}

// Rebase a display address: subtract the binary's preferred_load_base
// and add the user's chosen display base.  With defaults (base=0x0,
// rebaseAddr=0x0) this shows RVAs.  Set rebaseAddr to the actual
// image base to keep original VAs.
export function rebaseDisplayAddr(addr: number, binaryBase: string, userBase: string): number {
  const base = parseInt(binaryBase, 16) || 0;
  const target = parseInt(userBase, 16) || 0;
  return addr - base + target;
}

// Format a rebased address as "0x1234"
export function formatAddrRebased(addr: number, binaryBase: string, userBase: string): string {
  return "0x" + rebaseDisplayAddr(addr, binaryBase, userBase).toString(16);
}
