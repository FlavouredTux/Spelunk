import { useEffect, useMemo, useState } from "react";
import { C, sans, serif, mono } from "../theme";
import { displayName, demangle, formatSize } from "../api";
import type { BinaryInfo, FunctionInfo, Annotations } from "../types";

type Tab = "imports" | "exports" | "sections" | "memmap" | "all";

export function SymbolsView(props: {
  info: BinaryInfo;
  annotations: Annotations;
  onSelect: (fn: FunctionInfo) => void;
  onClose: () => void;
}) {
  const { info, annotations, onSelect, onClose } = props;
  const [tab, setTab] = useState<Tab>("imports");
  const [q, setQ] = useState("");

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

  const filteredFunctions = (pool: FunctionInfo[]): FunctionInfo[] => {
    const needle = q.trim().toLowerCase();
    if (!needle) return pool;
    return pool.filter((f) => {
      const dn = displayName(f, annotations).toLowerCase();
      return f.name.toLowerCase().includes(needle) ||
             dn.includes(needle) ||
             f.addr.includes(needle);
    });
  };

  const filteredSections = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return info.sections;
    return info.sections.filter((s) =>
      s.name.toLowerCase().includes(needle) ||
      s.flags.toLowerCase().includes(needle) ||
      s.vaddr.includes(needle));
  }, [info.sections, q]);

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
        <div style={{ flex: 1, overflowY: "auto" }}>
          {(tab === "sections") && (
            <SectionsList sections={filteredSections} />
          )}
          {(tab === "memmap") && (
            <MemoryMap sections={filteredSections} />
          )}
          {(tab === "imports" || tab === "all") && (
            <FunctionList
              title={tab === "all" ? "imports" : null}
              list={filteredFunctions(imports)}
              annotations={annotations}
              onSelect={(f) => { onSelect(f); onClose(); }}
              isImport
            />
          )}
          {(tab === "exports" || tab === "all") && (
            <FunctionList
              title={tab === "all" ? "exports" : null}
              list={filteredFunctions(exports)}
              annotations={annotations}
              onSelect={(f) => { onSelect(f); onClose(); }}
            />
          )}
        </div>
      </div>
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

function FunctionList(props: {
  title: string | null;
  list: FunctionInfo[];
  annotations: Annotations;
  onSelect: (f: FunctionInfo) => void;
  isImport?: boolean;
}) {
  if (props.list.length === 0) {
    return (
      <div style={{
        padding: 28, textAlign: "center",
        fontFamily: serif, fontStyle: "italic",
        fontSize: 12, color: C.textFaint,
      }}>nothing matches</div>
    );
  }
  return (
    <div>
      {props.title && (
        <div style={{
          padding: "10px 18px 4px",
          fontFamily: sans, fontSize: 11, fontWeight: 600,
          textTransform: "uppercase",
          letterSpacing: 0.8,
          color: C.textMuted,
        }}>{props.title}</div>
      )}
      {props.list.map((f, i) => {
        const dn = displayName(f, props.annotations);
        const dm = demangle(f.name);
        const navigable = !props.isImport || f.addrNum !== 0;
        return (
          <button
            key={`${f.addr}-${i}`}
            onClick={() => navigable && props.onSelect(f)}
            disabled={!navigable}
            style={{
              width: "100%", padding: "8px 18px",
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
            }}>{f.addr}</span>
            <span style={{
              flex: 1,
              fontFamily: sans, fontSize: 12, color: C.text,
              overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
            }} title={f.name}>{dn}</span>
            {dm !== dn && (
              <span style={{
                fontFamily: serif, fontStyle: "italic",
                fontSize: 11, color: C.textFaint,
                overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                maxWidth: "40%",
              }}>{dm}</span>
            )}
            {f.size > 0 && (
              <span style={{ fontFamily: mono, fontSize: 10, color: C.textFaint }}>
                {formatSize(f.size)}
              </span>
            )}
          </button>
        );
      })}
    </div>
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
