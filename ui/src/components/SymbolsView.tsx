import { useDeferredValue, useEffect, useMemo, useRef, useState } from "react";
import { C, sans, serif, mono } from "../theme";
import { displayName, demangle, formatSize } from "../api";
import type { BinaryInfo, FunctionInfo, Annotations } from "../types";

type Tab = "imports" | "exports" | "sections" | "memmap" | "all";
type SectionScope = "all" | "exec" | "text";
type FunctionScope = "all" | "code" | "renamed" | "notes";

function isTextSection(s: BinaryInfo["sections"][number]): boolean {
  const name = s.name.toLowerCase();
  return name === ".text" || name === "text" || name.endsWith(",__text") || name.includes("__text");
}

function isExecutableSection(s: BinaryInfo["sections"][number]): boolean {
  const flags = s.flags.toLowerCase();
  return isTextSection(s) || flags.includes("x") || flags.includes("exec") || flags.includes("code");
}

function matchesSectionScope(s: BinaryInfo["sections"][number], scope: SectionScope): boolean {
  if (scope === "text") return isTextSection(s);
  if (scope === "exec") return isExecutableSection(s);
  return true;
}

function sectionRanges(sections: BinaryInfo["sections"]): Array<{ start: number; end: number }> {
  return sections
    .filter(isExecutableSection)
    .map((s) => {
      const start = parseInt(s.vaddr, 16);
      const size = parseInt(s.size, 16);
      return { start, end: start + size };
    })
    .filter((r) => Number.isFinite(r.start) && Number.isFinite(r.end) && r.end > r.start);
}

function isInRanges(addr: number, ranges: Array<{ start: number; end: number }>): boolean {
  return ranges.some((r) => addr >= r.start && addr < r.end);
}

export function SymbolsView(props: {
  info: BinaryInfo;
  annotations: Annotations;
  onSelect: (fn: FunctionInfo) => void;
  onClose: () => void;
}) {
  const { info, annotations, onSelect, onClose } = props;
  const [tab, setTab] = useState<Tab>("imports");
  const [q, setQ] = useState("");
  const [sectionScope, setSectionScope] = useState<SectionScope>("all");
  const [functionScope, setFunctionScope] = useState<FunctionScope>("all");
  const deferredQ = useDeferredValue(q);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.preventDefault(); onClose(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  // "Exports" = defined symbols with `kind === "function"` plus any
  // top-level symbol the user has explicitly renamed. ELF/Mach-O don't
  // use a separate "export" table the way PE does; the closest meaningful
  // surface is the dynsym/exported-trie set, which Ember conflates with
  // defined functions in the summary.
  const exports = useMemo(() => info.functions, [info]);
  const imports = useMemo(() => info.imports.filter((f) => f.name), [info.imports]);
  const codeRanges = useMemo(() => sectionRanges(info.sections), [info.sections]);

  const filterFunctions = (pool: FunctionInfo[], applyScope: boolean): FunctionInfo[] => {
    const needle = deferredQ.trim().toLowerCase();
    const scoped = !applyScope || functionScope === "all" ? pool : pool.filter((f) => {
      if (functionScope === "code") return isInRanges(f.addrNum, codeRanges);
      if (functionScope === "renamed") return !!annotations.renames[f.addr];
      if (functionScope === "notes") return !!annotations.notes[f.addr];
      return true;
    });
    if (!needle) return scoped;
    return scoped.filter((f) => {
      const dn = displayName(f, annotations).toLowerCase();
      return f.name.toLowerCase().includes(needle) ||
             dn.includes(needle) ||
             f.addr.includes(needle);
    });
  };
  const filteredImports = useMemo(
    () => filterFunctions(imports, false),
    [imports, deferredQ, annotations],
  );
  const filteredExports = useMemo(
    () => filterFunctions(exports, true),
    [exports, deferredQ, annotations, functionScope, codeRanges],
  );
  const functionScopeCounts = useMemo<Record<FunctionScope, number>>(() => ({
    all: exports.length,
    code: exports.filter((f) => isInRanges(f.addrNum, codeRanges)).length,
    renamed: exports.filter((f) => !!annotations.renames[f.addr]).length,
    notes: exports.filter((f) => !!annotations.notes[f.addr]).length,
  }), [exports, codeRanges, annotations]);

  const scopedSections = useMemo(() => {
    return info.sections.filter((s) => matchesSectionScope(s, sectionScope));
  }, [info.sections, sectionScope]);
  const sectionScopeCounts = useMemo<Record<SectionScope, number>>(() => ({
    all: info.sections.length,
    exec: info.sections.filter(isExecutableSection).length,
    text: info.sections.filter(isTextSection).length,
  }), [info.sections]);
  const filteredSections = useMemo(() => {
    const needle = deferredQ.trim().toLowerCase();
    if (!needle) return scopedSections;
    return scopedSections.filter((s) =>
      s.name.toLowerCase().includes(needle) ||
      s.flags.toLowerCase().includes(needle) ||
      s.vaddr.includes(needle));
  }, [scopedSections, deferredQ]);

  return (
    <div
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}
      style={{
        position: "fixed", inset: 0,
        background: "rgba(10,10,9,0.55)",
        backdropFilter: "blur(3px)",
        zIndex: 1850,
        display: "flex", justifyContent: "center",
        padding: "6vh 5vw",
        animation: "fadeIn .15s ease-out",
      }}
    >
      <div
        style={{
          flex: 1, maxWidth: 1100,
          display: "flex", flexDirection: "column",
          background: C.bg,
          border: `1px solid ${C.borderStrong}`,
          borderRadius: 8,
          boxShadow: "0 30px 80px rgba(0,0,0,0.6)",
          overflow: "hidden",
        }}
      >
        <div style={{
          padding: "12px 18px", borderBottom: `1px solid ${C.border}`,
          background: C.bgAlt,
          display: "flex", alignItems: "center", gap: 14,
        }}>
          <div style={{ display: "flex", flexDirection: "column", lineHeight: 1.2 }}>
            <span style={{ fontFamily: sans, fontSize: 13, fontWeight: 600, color: C.text }}>
              Symbols & sections
            </span>
            <span style={{ fontFamily: serif, fontStyle: "italic", fontSize: 11, color: C.textMuted, marginTop: 2 }}>
              {info.format.toUpperCase()} · {info.arch}
            </span>
          </div>
          <div style={{ flex: 1 }} />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="filter…"
            aria-label="Filter symbols and sections"
            style={{
              padding: "5px 10px", width: 220,
              fontFamily: mono, fontSize: 12, color: C.text,
              background: C.bgMuted,
              border: `1px solid ${C.border}`,
              borderRadius: 4,
            }}
          />
          <button
            onClick={onClose}
            style={{
              padding: "4px 10px",
              fontFamily: mono, fontSize: 10, color: C.textMuted,
              background: C.bgMuted,
              border: `1px solid ${C.border}`, borderRadius: 4,
            }}
          >close</button>
        </div>
        <div style={{
          display: "flex", padding: "0 18px", gap: 4,
          borderBottom: `1px solid ${C.border}`, background: C.bgAlt,
        }}>
          {([
            { id: "imports",  label: "imports",  count: imports.length  },
            { id: "exports",  label: "exports",  count: exports.length  },
            { id: "sections", label: "sections", count: info.sections.length },
            { id: "memmap",   label: "memory map", count: info.sections.length },
            { id: "all",      label: "all",      count: imports.length + exports.length },
          ] as const).map((t) => {
            const active = tab === t.id;
            return (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                style={{
                  padding: "10px 14px 8px",
                  fontFamily: sans, fontSize: 12,
                  color: active ? C.text : C.textMuted,
                  fontWeight: active ? 600 : 400,
                  borderBottom: `2px solid ${active ? C.accent : "transparent"}`,
                  marginBottom: -1,
                }}
              >
                {t.label}
                <span style={{
                  marginLeft: 8, fontFamily: mono, fontSize: 10, color: C.textFaint,
                }}>{t.count}</span>
              </button>
            );
          })}
        </div>
        <div style={{ flex: 1, overflow: "hidden" }}>
          {(tab === "sections") && (
            <div style={{ height: "100%", display: "flex", flexDirection: "column" }}>
              <SectionScopeBar
                value={sectionScope}
                counts={sectionScopeCounts}
                onChange={setSectionScope}
              />
              <div style={{ flex: 1, minHeight: 0, overflowY: "auto" }}>
                <SectionsList sections={filteredSections} />
              </div>
            </div>
          )}
          {(tab === "memmap") && (
            <div style={{ height: "100%", display: "flex", flexDirection: "column" }}>
              <SectionScopeBar
                value={sectionScope}
                counts={sectionScopeCounts}
                onChange={setSectionScope}
              />
              <div style={{ flex: 1, minHeight: 0, overflowY: "auto" }}>
                <MemoryMap sections={filteredSections} />
              </div>
            </div>
          )}
          {(tab === "imports" || tab === "exports" || tab === "all") && (
            <div style={{ height: "100%", display: "flex", flexDirection: "column" }}>
              {tab !== "imports" && (
                <FunctionScopeBar
                  value={functionScope}
                  counts={functionScopeCounts}
                  onChange={setFunctionScope}
                />
              )}
              <div style={{ flex: 1, minHeight: 0 }}>
                <FunctionList
                  imports={tab === "exports" || (tab === "all" && functionScope !== "all") ? [] : filteredImports}
                  exports={tab === "imports" ? [] : filteredExports}
                  annotations={annotations}
                  onSelect={(f) => { onSelect(f); onClose(); }}
                  showHeaders={tab === "all"}
                />
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function FunctionScopeBar(props: {
  value: FunctionScope;
  counts: Record<FunctionScope, number>;
  onChange: (v: FunctionScope) => void;
}) {
  const options: Array<{ id: FunctionScope; label: string; title: string }> = [
    { id: "all",     label: "all",   title: "Show every defined function" },
    { id: "code",    label: "code",  title: "Show functions inside executable sections" },
    { id: "renamed", label: "named", title: "Show functions with user renames" },
    { id: "notes",   label: "notes", title: "Show functions with notes" },
  ];
  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      gap: 6,
      padding: "8px 18px",
      background: C.bgAlt,
      borderBottom: `1px solid ${C.border}`,
      flexShrink: 0,
    }}>
      <span style={{
        fontFamily: mono,
        fontSize: 9,
        letterSpacing: 1,
        textTransform: "uppercase",
        color: C.textFaint,
        marginRight: 3,
      }}>
        functions
      </span>
      {options.map((opt) => {
        const active = props.value === opt.id;
        return (
          <button
            key={opt.id}
            title={opt.title}
            onClick={() => props.onChange(opt.id)}
            aria-pressed={active}
            style={{
              padding: "4px 8px",
              fontFamily: mono,
              fontSize: 10,
              color: active ? "#fff" : C.textMuted,
              background: active ? C.accent : C.bgMuted,
              border: `1px solid ${active ? C.accent : C.border}`,
              borderRadius: 4,
              cursor: "pointer",
            }}
          >
            {opt.label}
            <span style={{
              marginLeft: 6,
              color: active ? "rgba(255,255,255,0.72)" : C.textFaint,
            }}>
              {props.counts[opt.id]}
            </span>
          </button>
        );
      })}
    </div>
  );
}

function SectionScopeBar(props: {
  value: SectionScope;
  counts: Record<SectionScope, number>;
  onChange: (v: SectionScope) => void;
}) {
  const options: Array<{ id: SectionScope; label: string; title: string }> = [
    { id: "all",  label: "all",  title: "Show every section" },
    { id: "exec", label: "code", title: "Show executable sections" },
    { id: "text", label: ".text", title: "Show text/code section names only" },
  ];
  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      gap: 6,
      padding: "8px 18px",
      background: C.bgAlt,
      borderBottom: `1px solid ${C.border}`,
      flexShrink: 0,
    }}>
      <span style={{
        fontFamily: mono,
        fontSize: 9,
        letterSpacing: 1,
        textTransform: "uppercase",
        color: C.textFaint,
        marginRight: 3,
      }}>
        sections
      </span>
      {options.map((opt) => {
        const active = props.value === opt.id;
        return (
          <button
            key={opt.id}
            title={opt.title}
            onClick={() => props.onChange(opt.id)}
            aria-pressed={active}
            style={{
              padding: "4px 8px",
              fontFamily: mono,
              fontSize: 10,
              color: active ? "#fff" : C.textMuted,
              background: active ? C.accent : C.bgMuted,
              border: `1px solid ${active ? C.accent : C.border}`,
              borderRadius: 4,
              cursor: "pointer",
            }}
          >
            {opt.label}
            <span style={{
              marginLeft: 6,
              color: active ? "rgba(255,255,255,0.72)" : C.textFaint,
            }}>
              {props.counts[opt.id]}
            </span>
          </button>
        );
      })}
    </div>
  );
}

// Visualization of the binary's vaddr layout: each section drawn as
// a horizontal band with width proportional to its size, color-coded by
// permission flags, and gaps between adjacent sections shown as
// striped "unmapped" placeholders. Useful when sanity-checking that
// e.g. an entry point you found at 0x401000 lives in an executable
// section, or when measuring how much of a binary is .text vs .rdata.
function MemoryMap(props: { sections: BinaryInfo["sections"] }) {
  const items = useMemo(() => {
    const parsed = props.sections
      .map((s) => ({
        name:  s.name || "(unnamed)",
        flags: s.flags,
        vaddr: parseInt(s.vaddr, 16),
        size:  parseInt(s.size,  16),
      }))
      .filter((s) => Number.isFinite(s.vaddr) && Number.isFinite(s.size) && s.size > 0)
      .sort((a, b) => a.vaddr - b.vaddr);
    // Compute gaps between consecutive sections so the user sees the
    // unmapped space in the address range too. We treat a gap > 4 KB
    // as worth surfacing — anything smaller is likely alignment slop
    // and would only add noise.
    const out: Array<
      | { kind: "section"; name: string; flags: string; vaddr: number; size: number }
      | { kind: "gap";     vaddr: number; size: number }
    > = [];
    for (let i = 0; i < parsed.length; i++) {
      const cur = parsed[i];
      if (i > 0) {
        const prev = parsed[i - 1];
        const gap = cur.vaddr - (prev.vaddr + prev.size);
        if (gap >= 0x1000) out.push({ kind: "gap", vaddr: prev.vaddr + prev.size, size: gap });
      }
      out.push({ kind: "section", ...cur });
    }
    return out;
  }, [props.sections]);

  if (items.length === 0) {
    return (
      <div style={{
        padding: 28, textAlign: "center",
        fontFamily: serif, fontStyle: "italic",
        fontSize: 12, color: C.textFaint,
      }}>no sections to map</div>
    );
  }

  // Total address span we draw. Use the union of sizes (excluding gaps)
  // for percentage widths so the bars use space efficiently — drawing
  // gaps proportionally would dwarf the actual sections on binaries
  // with sparse layouts (e.g. shared libraries with .got far from .text).
  const totalSizeExcludingGaps = items.reduce(
    (a, it) => a + (it.kind === "section" ? it.size : 0), 0,
  );
  const totalSize = totalSizeExcludingGaps || 1;

  const colorFor = (flags: string): { bg: string; bd: string; fg: string; label: string } => {
    const f = flags.toLowerCase();
    const exec = f.includes("x");
    const wr   = f.includes("w");
    const rd   = f.includes("r");
    if (exec)        return { bg: "rgba(217,119,87,0.20)",  bd: C.accent,                 fg: C.accent,        label: "exec" };
    if (wr)          return { bg: "rgba(199,93,58,0.12)",   bd: "rgba(199,93,58,0.45)",  fg: "#c75d3a",       label: "data" };
    if (rd)          return { bg: "rgba(176,164,134,0.16)", bd: "rgba(176,164,134,0.55)", fg: "#b0a486",       label: "rodata" };
    return                  { bg: C.bgMuted,                bd: C.border,                 fg: C.textMuted,    label: "—"     };
  };

  return (
    <div style={{ padding: "10px 18px 24px" }}>
      <div style={{
        padding: "6px 0 12px",
        fontFamily: serif, fontStyle: "italic",
        fontSize: 11, color: C.textMuted,
      }}>
        layout of the binary's loaded address space, sorted by vaddr.
        bands are sized in proportion to each section's vsize.
      </div>
      <div style={{
        display: "flex", flexDirection: "column", gap: 4,
      }}>
        {items.map((it, i) => {
          if (it.kind === "gap") {
            return (
              <div key={`gap-${i}`} style={{
                display: "flex", alignItems: "center", gap: 12,
                padding: "4px 0",
              }}>
                <span style={{
                  width: 110, fontFamily: mono, fontSize: 10, color: C.textFaint,
                  textAlign: "right",
                }}>0x{it.vaddr.toString(16)}</span>
                <span style={{
                  flex: 1, height: 16,
                  background: `repeating-linear-gradient(45deg, ${C.bgMuted} 0 6px, transparent 6px 12px)`,
                  border: `1px dashed ${C.border}`,
                  borderRadius: 3,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  fontFamily: serif, fontStyle: "italic",
                  fontSize: 10, color: C.textFaint,
                }}>unmapped · {formatSize(it.size)}</span>
                <span style={{ width: 70 }} />
              </div>
            );
          }
          const c = colorFor(it.flags);
          const widthPct = Math.max(2, (it.size / totalSize) * 100);
          return (
            <div key={`s-${it.vaddr}-${i}`} style={{
              display: "flex", alignItems: "center", gap: 12,
              padding: "4px 0",
            }}>
              <span style={{
                width: 110, fontFamily: mono, fontSize: 10, color: C.accent,
                textAlign: "right",
              }} title={`vaddr 0x${it.vaddr.toString(16)}`}>
                0x{it.vaddr.toString(16)}
              </span>
              <div style={{ flex: 1 }}>
                <div style={{
                  width: `${widthPct}%`,
                  minWidth: 60,
                  height: 22,
                  background: c.bg,
                  border: `1px solid ${c.bd}`,
                  borderRadius: 3,
                  padding: "0 8px",
                  display: "flex", alignItems: "center", gap: 8,
                }}>
                  <span style={{
                    fontFamily: mono, fontSize: 11, color: c.fg, fontWeight: 600,
                    overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                  }}>{it.name}</span>
                  <span style={{
                    fontFamily: mono, fontSize: 9, color: C.textFaint, letterSpacing: 0.5,
                  }}>{it.flags || c.label}</span>
                </div>
              </div>
              <span style={{
                width: 70, textAlign: "right",
                fontFamily: mono, fontSize: 10, color: C.textMuted,
              }}>{formatSize(it.size)}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function SectionsList(props: { sections: BinaryInfo["sections"] }) {
  if (props.sections.length === 0) {
    return (
      <div style={{
        padding: 28, textAlign: "center",
        fontFamily: serif, fontStyle: "italic",
        fontSize: 12, color: C.textFaint,
      }}>no sections match</div>
    );
  }
  return (
    <table style={{
      width: "100%", borderCollapse: "collapse",
      fontFamily: mono, fontSize: 11,
    }}>
      <thead>
        <tr style={{ background: C.bgAlt }}>
          <th style={th}>name</th>
          <th style={th}>vaddr</th>
          <th style={th}>size</th>
          <th style={th}>flags</th>
        </tr>
      </thead>
      <tbody>
        {props.sections.map((s, i) => (
          <tr key={`${s.name}-${i}`} style={{ borderBottom: `1px solid ${C.border}` }}>
            <td style={{ ...td, color: C.text, fontWeight: 500 }}>{s.name}</td>
            <td style={{ ...td, color: C.accent }}>{s.vaddr}</td>
            <td style={{ ...td, color: C.textMuted }}>
              {(() => {
                const n = parseInt(s.size, 16);
                return Number.isFinite(n) ? formatSize(n) : s.size;
              })()}
            </td>
            <td style={{ ...td, color: C.textWarm }}>
              <span style={{
                padding: "1px 6px",
                background: C.bgMuted,
                border: `1px solid ${C.border}`,
                borderRadius: 3,
                letterSpacing: 1,
              }}>{s.flags}</span>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

const FN_ROW_H = 32;
const FN_OVERSCAN = 10;

type FunctionListEntry =
  | { kind: "header"; id: string; label: string; count: number }
  | { kind: "fn"; id: string; fn: FunctionInfo; isImport: boolean };

function FunctionList(props: {
  imports: FunctionInfo[];
  exports: FunctionInfo[];
  annotations: Annotations;
  onSelect: (f: FunctionInfo) => void;
  showHeaders: boolean;
}) {
  const scRef = useRef<HTMLDivElement | null>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewH, setViewH] = useState(0);

  useEffect(() => {
    const el = scRef.current;
    if (!el) return;
    const onScroll = () => setScrollTop(el.scrollTop);
    el.addEventListener("scroll", onScroll, { passive: true });
    const ro = new ResizeObserver(() => setViewH(el.clientHeight));
    ro.observe(el);
    setViewH(el.clientHeight);
    return () => { el.removeEventListener("scroll", onScroll); ro.disconnect(); };
  }, []);

  useEffect(() => {
    if (scRef.current) scRef.current.scrollTop = 0;
    setScrollTop(0);
  }, [props.imports, props.exports]);

  const entries = useMemo<FunctionListEntry[]>(() => {
    const out: FunctionListEntry[] = [];
    if (props.imports.length > 0) {
      if (props.showHeaders) {
        out.push({ kind: "header", id: "imports", label: "imports", count: props.imports.length });
      }
      for (const fn of props.imports) {
        out.push({ kind: "fn", id: `i-${fn.addr}-${fn.name}`, fn, isImport: true });
      }
    }
    if (props.exports.length > 0) {
      if (props.showHeaders) {
        out.push({ kind: "header", id: "exports", label: "exports", count: props.exports.length });
      }
      for (const fn of props.exports) {
        out.push({ kind: "fn", id: `e-${fn.addr}-${fn.name}`, fn, isImport: false });
      }
    }
    return out;
  }, [props.imports, props.exports, props.showHeaders]);

  if (entries.length === 0) {
    return (
      <div style={{
        padding: 28, textAlign: "center",
        fontFamily: serif, fontStyle: "italic",
        fontSize: 12, color: C.textFaint,
      }}>nothing matches</div>
    );
  }

  const total = entries.length;
  const first = Math.max(0, Math.floor(scrollTop / FN_ROW_H) - FN_OVERSCAN);
  const last = Math.min(total, Math.ceil((scrollTop + viewH) / FN_ROW_H) + FN_OVERSCAN);
  const padTop = first * FN_ROW_H;
  const padBot = Math.max(0, (total - last) * FN_ROW_H);
  const visible = entries.slice(first, last);

  return (
    <div ref={scRef} style={{ height: "100%", overflowY: "auto" }}>
      <div style={{ height: padTop }} />
      {visible.map((entry) => {
        if (entry.kind === "header") {
          return (
            <div
              key={entry.id}
              style={{
                height: FN_ROW_H,
                padding: "9px 18px 0",
                fontFamily: sans, fontSize: 11, fontWeight: 600,
                textTransform: "uppercase",
                letterSpacing: 0.8,
                color: C.textMuted,
                borderBottom: `1px solid ${C.border}`,
              }}
            >
              {entry.label}
              <span style={{
                marginLeft: 8, fontFamily: mono, fontSize: 10,
                color: C.textFaint, letterSpacing: 0,
              }}>{entry.count}</span>
            </div>
          );
        }
        return (
          <FunctionRow
            key={entry.id}
            fn={entry.fn}
            annotations={props.annotations}
            onSelect={props.onSelect}
            isImport={entry.isImport}
          />
        );
      })}
      <div style={{ height: padBot }} />
    </div>
  );
}

function FunctionRow(props: {
  fn: FunctionInfo;
  annotations: Annotations;
  onSelect: (f: FunctionInfo) => void;
  isImport: boolean;
}) {
  const { fn, annotations, onSelect, isImport } = props;
  const dn = displayName(fn, annotations);
  const dm = demangle(fn.name);
  const navigable = !isImport || fn.addrNum !== 0;
  return (
    <button
      onClick={() => navigable && onSelect(fn)}
      disabled={!navigable}
      style={{
        width: "100%", height: FN_ROW_H,
        padding: "7px 18px",
        display: "flex", alignItems: "baseline", gap: 14,
        borderBottom: `1px solid ${C.border}`,
        cursor: navigable ? "pointer" : "default",
        background: "transparent",
        textAlign: "left",
      }}
      onMouseEnter={(e) => {
        if (navigable) (e.currentTarget as HTMLElement).style.background = C.bgMuted;
      }}
      onMouseLeave={(e) => {
        (e.currentTarget as HTMLElement).style.background = "transparent";
      }}
    >
      <span style={{
        fontFamily: mono, fontSize: 11, color: C.accent,
        width: 96, flexShrink: 0,
      }}>{fn.addr}</span>
      <span style={{
        flex: 1,
        fontFamily: sans, fontSize: 12, color: C.text,
        overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
      }} title={fn.name}>{dn}</span>
      {dm !== dn && (
        <span style={{
          fontFamily: serif, fontStyle: "italic",
          fontSize: 11, color: C.textFaint,
          overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
          maxWidth: "40%",
        }}>{dm}</span>
      )}
      {fn.size > 0 && (
        <span style={{ fontFamily: mono, fontSize: 10, color: C.textFaint }}>
          {formatSize(fn.size)}
        </span>
      )}
    </button>
  );
}

const th: React.CSSProperties = {
  padding: "8px 18px",
  textAlign: "left",
  fontFamily: sans, fontSize: 10, fontWeight: 600,
  textTransform: "uppercase",
  letterSpacing: 1,
  color: C.textMuted,
  borderBottom: `1px solid ${C.border}`,
};

const td: React.CSSProperties = {
  padding: "6px 18px",
};
