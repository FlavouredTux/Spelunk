import { useEffect, useMemo, useState } from "react";
import { C, sans, serif, mono } from "../theme";
import { displayName, formatAddrHex } from "../api";
import { useFmtAddr } from "../RebaseContext";
import type { IdentifyResult, FunctionInfo, BinaryInfo, Annotations } from "../types";

const MAX_VISIBLE = 500;

const CATEGORY_COLORS: Record<string, string> = {
  hash: C.violet,
  encryption: C.red,
  network: C.blue,
  encoding: C.green,
};

const CATEGORY_LABELS: Record<string, string> = {
  hash: "Hash",
  encryption: "Encrypt",
  network: "Network",
  encoding: "Encode",
};

function confidenceColor(c: number): string {
  if (c >= 0.8) return C.green;
  if (c >= 0.5) return C.yellow;
  return C.textMuted;
}

export function IdentifyPanel(props: {
  info: BinaryInfo;
  hits: IdentifyResult[];
  loading?: boolean;
  annotations: Annotations;
  onSelect: (fn: FunctionInfo) => void;
  onClose: () => void;
}) {
  const { info, hits, loading, annotations, onSelect, onClose } = props;
  const fmtAddr = useFmtAddr();
  const [q, setQ] = useState("");
  const [catFilter, setCatFilter] = useState<string>("all");

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.preventDefault(); onClose(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const categories = useMemo(() => {
    const s = new Set<string>();
    for (const h of hits) s.add(h.category);
    return Array.from(s).sort();
  }, [hits]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return hits.filter((h) => {
      if (catFilter !== "all" && h.category !== catFilter) return false;
      if (!needle) return true;
      return h.name.toLowerCase().includes(needle)
        || h.addr.toLowerCase().includes(needle)
        || h.via.toLowerCase().includes(needle)
        || h.category.toLowerCase().includes(needle);
    });
  }, [hits, q, catFilter]);

  const visible = filtered.slice(0, MAX_VISIBLE);
  const truncated = filtered.length > MAX_VISIBLE;

  // Group by function address for display
  const grouped = useMemo(() => {
    const m = new Map<number, IdentifyResult[]>();
    for (const h of visible) {
      const arr = m.get(h.addrNum) ?? [];
      arr.push(h);
      m.set(h.addrNum, arr);
    }
    return Array.from(m.entries()).sort((a, b) => a[0] - b[0]);
  }, [visible]);

  const resolveFn = (addrNum: number): FunctionInfo | null => {
    for (const f of info.functions) {
      if (f.addrNum === addrNum) return f;
    }
    return null;
  };

  return (
    <div
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(10,10,9,0.55)",
        backdropFilter: "blur(3px)",
        zIndex: 1800,
        display: "flex",
        justifyContent: "center",
        padding: "6vh 5vw",
        animation: "fadeIn .15s ease-out",
      }}
    >
      <div style={{
        flex: 1,
        display: "flex",
        flexDirection: "column",
        background: C.bg,
        border: `1px solid ${C.borderStrong}`,
        borderRadius: 8,
        boxShadow: "0 30px 80px rgba(0,0,0,0.6)",
        overflow: "hidden",
      }}>
        {/* Header */}
        <div style={{
          padding: "14px 20px",
          borderBottom: `1px solid ${C.border}`,
          display: "flex", alignItems: "center", gap: 18,
          background: C.bgAlt,
        }}>
          <div style={{ display: "flex", flexDirection: "column", lineHeight: 1.2 }}>
            <span style={{ fontFamily: sans, fontSize: 14, fontWeight: 600, color: C.text }}>
              Identification
            </span>
            <span style={{ fontFamily: serif, fontStyle: "italic", fontSize: 11, color: C.textMuted, marginTop: 2 }}>
              {hits.length} match{hits.length !== 1 ? "es" : ""} · {filtered.length} shown
              {truncated ? ` (first ${MAX_VISIBLE})` : ""}
            </span>
          </div>

          {/* Category filter pills */}
          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <button
              onClick={() => setCatFilter("all")}
              style={{
                padding: "3px 10px",
                borderRadius: 4,
                fontSize: 11,
                fontFamily: sans,
                fontWeight: catFilter === "all" ? 600 : 400,
                color: catFilter === "all" ? C.text : C.textMuted,
                background: catFilter === "all" ? C.bgDark : C.bgMuted,
                border: `1px solid ${catFilter === "all" ? C.borderStrong : C.border}`,
                cursor: "pointer",
              }}
            >All</button>
            {categories.map((cat) => (
              <button
                key={cat}
                onClick={() => setCatFilter(catFilter === cat ? "all" : cat)}
                style={{
                  padding: "3px 10px",
                  borderRadius: 4,
                  fontSize: 11,
                  fontFamily: sans,
                  fontWeight: catFilter === cat ? 600 : 400,
                  color: catFilter === cat ? CATEGORY_COLORS[cat] ?? C.text : C.textMuted,
                  background: catFilter === cat ? (CATEGORY_COLORS[cat] ?? C.accent) + "18" : C.bgMuted,
                  border: `1px solid ${catFilter === cat ? (CATEGORY_COLORS[cat] ?? C.accent) + "40" : C.border}`,
                  cursor: "pointer",
                }}
              >{CATEGORY_LABELS[cat] ?? cat}</button>
            ))}
          </div>

          {/* Search */}
          <div style={{
            display: "flex", alignItems: "center", gap: 8,
            padding: "6px 10px",
            background: C.bgMuted,
            border: `1px solid ${C.border}`,
            borderRadius: 4,
            minWidth: 220,
          }}>
            <span style={{ color: C.textFaint, fontFamily: mono, fontSize: 11 }}>/</span>
            <input
              autoFocus
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="filter identifications…"
              style={{ flex: 1, fontFamily: sans, fontSize: 12, color: C.text }}
            />
            {q && (
              <button onClick={() => setQ("")} style={{ color: C.textFaint, fontSize: 11 }}>×</button>
            )}
          </div>

          <div style={{ flex: 1 }} />

          <button
            onClick={onClose}
            style={{ color: C.textMuted, fontSize: 13, padding: "4px 8px" }}
            title="Close (Esc)"
          >✕</button>
        </div>

        {/* Content */}
        <div style={{ flex: 1, overflow: "auto", padding: 0 }}>
          {loading ? (
            <div style={{
              padding: 40,
              textAlign: "center",
              fontFamily: serif,
              fontStyle: "italic",
              color: C.textMuted,
              fontSize: 13,
            }}>
              Scanning functions…
            </div>
          ) : grouped.length === 0 ? (
            <div style={{
              padding: 40,
              textAlign: "center",
              fontFamily: serif,
              fontStyle: "italic",
              color: C.textMuted,
              fontSize: 13,
            }}>
              No identified profiles found. Try lowering the confidence threshold.
            </div>
          ) : (
            <table style={{
              width: "100%",
              borderCollapse: "collapse",
              fontFamily: mono,
              fontSize: 12,
            }}>
              <thead>
                <tr style={{
                  position: "sticky",
                  top: 0,
                  background: C.bgAlt,
                  borderBottom: `1px solid ${C.border}`,
                  zIndex: 1,
                }}>
                  <th style={{ textAlign: "left", padding: "8px 14px", color: C.textMuted, fontWeight: 500, fontSize: 11 }}>Address</th>
                  <th style={{ textAlign: "left", padding: "8px 10px", color: C.textMuted, fontWeight: 500, fontSize: 11 }}>Function</th>
                  <th style={{ textAlign: "left", padding: "8px 10px", color: C.textMuted, fontWeight: 500, fontSize: 11 }}>Profile</th>
                  <th style={{ textAlign: "left", padding: "8px 10px", color: C.textMuted, fontWeight: 500, fontSize: 11 }}>Category</th>
                  <th style={{ textAlign: "right", padding: "8px 10px", color: C.textMuted, fontWeight: 500, fontSize: 11 }}>Conf</th>
                  <th style={{ textAlign: "left", padding: "8px 10px", color: C.textMuted, fontWeight: 500, fontSize: 11 }}>Signal</th>
                  <th style={{ textAlign: "left", padding: "8px 14px", color: C.textMuted, fontWeight: 500, fontSize: 11 }}>Detail</th>
                </tr>
              </thead>
              <tbody>
                {grouped.map(([addrNum, rowHits]) => {
                  const fn = resolveFn(addrNum);
                  return rowHits.map((h, i) => (
                    <tr
                      key={`${h.addr}-${h.name}`}
                      onClick={() => {
                        if (fn) onSelect(fn);
                      }}
                      style={{
                        cursor: fn ? "pointer" : "default",
                        borderBottom: `1px solid ${C.border}`,
                        background: i === 0 ? "transparent" : C.bgMuted + "40",
                      }}
                      onMouseEnter={(e) => { e.currentTarget.style.background = C.accentDim; }}
                      onMouseLeave={(e) => { e.currentTarget.style.background = i === 0 ? "transparent" : C.bgMuted + "40"; }}
                    >
                      <td style={{ padding: "6px 14px", color: C.blue, whiteSpace: "nowrap" }}>
                        {i === 0 ? fmtAddr(h.addrNum) : ""}
                      </td>
                      <td style={{ padding: "6px 10px", color: C.textWarm, whiteSpace: "nowrap", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis" }}>
                        {i === 0 && fn ? displayName(fn, annotations) : ""}
                      </td>
                      <td style={{ padding: "6px 10px", color: CATEGORY_COLORS[h.category] ?? C.accent, fontWeight: 600 }}>
                        {h.name}
                      </td>
                      <td style={{ padding: "6px 10px" }}>
                        <span style={{
                          padding: "2px 7px",
                          borderRadius: 3,
                          fontSize: 10,
                          fontFamily: sans,
                          color: CATEGORY_COLORS[h.category] ?? C.textMuted,
                          background: (CATEGORY_COLORS[h.category] ?? C.accent) + "18",
                        }}>
                          {CATEGORY_LABELS[h.category] ?? h.category}
                        </span>
                      </td>
                      <td style={{ padding: "6px 10px", textAlign: "right", color: confidenceColor(h.confidence) }}>
                        {(h.confidence * 100).toFixed(0)}%
                      </td>
                      <td style={{ padding: "6px 10px", color: C.textMuted, fontSize: 11 }}>
                        {h.signal}
                      </td>
                      <td style={{ padding: "6px 14px", color: C.textFaint, fontSize: 11, maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {h.via}
                      </td>
                    </tr>
                  ));
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* Footer */}
        <div style={{
          padding: "8px 20px",
          borderTop: `1px solid ${C.border}`,
          display: "flex",
          alignItems: "center",
          gap: 16,
          background: C.bgAlt,
          fontFamily: serif,
          fontStyle: "italic",
          fontSize: 11,
          color: C.textFaint,
        }}>
          <span>Click a row to navigate</span>
          <span>Esc to close</span>
        </div>
      </div>
    </div>
  );
}
