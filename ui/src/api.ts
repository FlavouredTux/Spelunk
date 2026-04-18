import type {
  BinaryInfo, FunctionInfo, ViewKind, Xrefs, Annotations, StringEntry, Arities,
} from "./types";

export async function pickBinary(): Promise<string | null> {
  return await window.ember.pick();
}

export async function openRecent(path: string): Promise<string> {
  return await window.ember.openRecent(path);
}

export async function getRecents(): Promise<string[]> {
  return await window.ember.recents();
}

export async function loadSummary(): Promise<BinaryInfo> {
  const path = (await window.ember.binary()) ?? "";
  const raw = await window.ember.run([]);
  return parseSummary(raw, path);
}

export async function loadFunction(sym: string, view: ViewKind): Promise<string> {
  const args: Record<ViewKind, string[]> = {
    pseudo: ["-p", "-s", sym],
    asm:    ["-d", "-s", sym],
    cfg:    ["-c", "-s", sym],
    ir:     ["-i", "-s", sym],
    ssa:    ["-i", "--ssa", "-s", sym],
  };
  return await window.ember.run(args[view]);
}

export async function loadXrefs(): Promise<Xrefs> {
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

function parseSummary(raw: string, path: string): BinaryInfo {
  const lines = raw.split("\n");
  const info: BinaryInfo = {
    path,
    format: "",
    arch: "",
    entry: "",
    sections: [],
    functions: [],
    imports: [],
  };

  for (const l of lines) {
    const m = /^(file|format|arch|entry)\s+(.+)$/.exec(l.trim());
    if (m) {
      if (m[1] === "format") info.format = m[2];
      else if (m[1] === "arch") info.arch = m[2];
      else if (m[1] === "entry") info.entry = m[2];
    }
  }

  let mode: "none" | "sections" | "defined" | "imports" = "none";
  for (const raw_line of lines) {
    const line = raw_line.replace(/\r$/, "");
    if (/^sections\s+\(\d+\)/.test(line)) { mode = "sections"; continue; }
    if (/^defined symbols\s+\(\d+\)/.test(line)) { mode = "defined"; continue; }
    if (/^imports\s+\(\d+\)/.test(line)) { mode = "imports"; continue; }
    if (/^(file|format|arch|entry)/.test(line.trim())) { mode = "none"; continue; }
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

  info.functions = info.functions.filter(
    (f) => f.kind === "function" && f.size > 0 && f.name && !f.name.startsWith("<"),
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
