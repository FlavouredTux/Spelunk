import { useEffect, useMemo, useState } from "react";
import { C, sans, serif, mono } from "../theme";
import { displayName } from "../api";
import type { BinaryInfo, FunctionInfo, StringEntry, Annotations } from "../types";

const MAX_VISIBLE = 500;  // cap rendered rows; filter narrows

function hexAddr(n: number): string {
  return "0x" + n.toString(16);
}

function escapeVisible(s: string): string {
  let out = "";
  for (const c of s) {
    const code = c.charCodeAt(0);
    if (c === "\n") { out += "\\n"; continue; }
    if (c === "\r") { out += "\\r"; continue; }
    if (c === "\t") { out += "\\t"; continue; }
    if (code < 0x20 || code === 0x7f) {
      out += "\\x" + code.toString(16).padStart(2, "0");
    } else {
      out += c;
    }
  }
  return out;
}

// Fuzzy-ish: lowercase substring on both text and addr.
function scoreMatch(needle: string, entry: StringEntry): number {
  const t = entry.text.toLowerCase();
  const a = entry.addr.toLowerCase();
  if (t.includes(needle) || a.includes(needle)) return 1;
  return 0;
}

// Find the function whose [addr, addr+size) contains `ip`.
function resolveFunction(info: BinaryInfo, ip: number): FunctionInfo | null {
  // Functions can be sparse; linear scan is fine for typical binary sizes.
  for (const f of info.functions) {
    if (ip >= f.addrNum && ip < f.addrNum + f.size) return f;
  }
  return null;
}

export function StringsView(props: {
  info: BinaryInfo;
  strings: StringEntry[];
  loading?: boolean;
  annotations: Annotations;
  onSelect: (fn: FunctionInfo) => void;
  onClose: () => void;
}) {
  const { info, strings, loading, annotations, onSelect, onClose } = props;
  const [q, setQ] = useState("");
  const [onlyReferenced, setOnlyReferenced] = useState(true);
  const [selected, setSelected] = useState<number | null>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.preventDefault(); onClose(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const rows = strings.filter((s) => {
      if (onlyReferenced && s.xrefs.length === 0) return false;
      if (!needle) return true;
      return scoreMatch(needle, s) > 0;
    });
    return rows;
  }, [strings, q, onlyReferenced]);

  const visible = filtered.slice(0, MAX_VISIBLE);
  const truncated = filtered.length > MAX_VISIBLE;

  const selectedEntry =
    selected != null ? strings.find((s) => s.addrNum === selected) ?? null : null;
  const selectedXrefFuncs = useMemo(() => {
    if (!selectedEntry) return [];
    const seen = new Set<number>();
    const out: { ip: number; fn: FunctionInfo | null }[] = [];
    for (const ip of selectedEntry.xrefs) {
      const fn = resolveFunction(info, ip);
      const key = fn?.addrNum ?? ip;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ ip, fn });
    }
    return out;
  }, [selectedEntry, info]);

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
      <div
        style={{
          flex: 1,
          display: "flex",
          flexDirection: "column",
          background: C.bg,
          border: `1px solid ${C.borderStrong}`,
          borderRadius: 8,
          boxShadow: "0 30px 80px rgba(0,0,0,0.6)",
          overflow: "hidden",
        }}
      >
        {/* Header */}
        <div style={{
          padding: "14px 20px",
          borderBottom: `1px solid ${C.border}`,
          display: "flex", alignItems: "center", gap: 18,
          background: C.bgAlt,
        }}>
          <div style={{ display: "flex", flexDirection: "column", lineHeight: 1.2 }}>
            <span style={{ fontFamily: sans, fontSize: 14, fontWeight: 600, color: C.text }}>
              Strings
            </span>
            <span style={{ fontFamily: serif, fontStyle: "italic", fontSize: 11, color: C.textMuted, marginTop: 2 }}>
              {strings.length} total · {filtered.length} shown
              {truncated ? ` (first ${MAX_VISIBLE})` : ""}
            </span>
          </div>

          <div style={{
            display: "flex", alignItems: "center", gap: 8,
            padding: "6px 10px",
            background: C.bgMuted,
            border: `1px solid ${C.border}`,
            borderRadius: 4,
            minWidth: 280,
          }}>
            <span style={{ color: C.textFaint, fontFamily: mono, fontSize: 11 }}>/</span>
            <input
              autoFocus
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="filter strings…"
              style={{ flex: 1, fontFamily: sans, fontSize: 12, color: C.text }}
            />
            {q && (
              <button
                onClick={() => setQ("")}
                style={{ color: C.textFaint, fontSize: 11 }}
              >×</button>
            )}
          </div>

          <button
            onClick={() => setOnlyReferenced((v) => !v)}
            title="Show only strings with code xrefs"
            style={{
              padding: "5px 10px",
              fontFamily: mono, fontSize: 10,
              color: onlyReferenced ? C.accent : C.textMuted,
              background: onlyReferenced ? C.accentDim : C.bgMuted,
              border: `1px solid ${onlyReferenced ? "rgba(217,119,87,0.35)" : C.border}`,
              borderRadius: 4,
            }}
          >
            {onlyReferenced ? "referenced only" : "all"}
          </button>

          <div style={{ flex: 1 }} />
          <span style={{ fontFamily: mono, fontSize: 10, color: C.textFaint }}>
            click to inspect · esc closes
          </span>
          <button
            onClick={onClose}
            style={{
              width: 24, height: 24, borderRadius: 4,
              color: C.textMuted,
              background: "transparent",
              border: `1px solid ${C.border}`,
              fontSize: 14,
            }}
          >×</button>
        </div>

        {/* Body: list + detail panel */}
        <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
          <div style={{
            flex: 1,
            overflowY: "auto",
            padding: "6px 0",
          }} className="sel">
            {visible.length === 0 ? (
              <div style={{
                padding: 40,
                textAlign: "center",
                fontFamily: serif, fontStyle: "italic",
                color: C.textFaint, fontSize: 13,
              }}>
                {loading
                  ? "extracting strings…"
                  : strings.length === 0
                    ? "no strings extracted"
                    : "no matches"}
              </div>
            ) : (
              visible.map((s) => {
                const isSel = s.addrNum === selected;
                return (
                  <button
                    key={s.addrNum}
                    onClick={() => setSelected(s.addrNum)}
                    style={{
                      width: "100%",
                      display: "grid",
                      gridTemplateColumns: "110px 1fr 50px",
                      alignItems: "center",
                      gap: 14,
                      padding: "5px 20px",
                      textAlign: "left",
                      background: isSel ? C.accentDim : "transparent",
                      borderLeft: isSel
                        ? `2px solid ${C.accent}`
                        : `2px solid transparent`,
                      transition: "background .08s",
                    }}
                    onMouseEnter={(e) => {
                      if (!isSel) (e.currentTarget as HTMLElement).style.background = C.bgMuted;
                    }}
                    onMouseLeave={(e) => {
                      if (!isSel) (e.currentTarget as HTMLElement).style.background = "transparent";
                    }}
                  >
                    <span style={{
                      fontFamily: mono, fontSize: 10,
                      color: isSel ? C.accent : C.textFaint,
                    }}>
                      {s.addr}
                    </span>
                    <span style={{
                      fontFamily: mono, fontSize: 11,
                      color: C.text,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}>
                      <span style={{ color: C.textFaint }}>"</span>
                      <span style={{ color: C.text }}>{escapeVisible(s.text)}</span>
                      <span style={{ color: C.textFaint }}>"</span>
                    </span>
                    <span style={{
                      fontFamily: mono, fontSize: 10,
                      color: s.xrefs.length > 0 ? C.textWarm : C.textFaint,
                      textAlign: "right",
                    }}>
                      {s.xrefs.length > 0 ? `${s.xrefs.length}×` : "—"}
                    </span>
                  </button>
                );
              })
            )}
          </div>

          {/* Detail */}
          <div style={{
            width: 360,
            borderLeft: `1px solid ${C.border}`,
            background: C.bgAlt,
            overflowY: "auto",
            padding: 18,
          }} className="sel">
            {!selectedEntry ? (
              <div style={{
                fontFamily: serif, fontStyle: "italic",
                color: C.textFaint, fontSize: 12,
                paddingTop: 40, textAlign: "center",
              }}>
                select a string to see its references
              </div>
            ) : (
              <>
                <div style={{
                  fontFamily: mono, fontSize: 10,
                  color: C.accent, marginBottom: 6,
                }}>
                  {selectedEntry.addr}
                </div>
                <div style={{
                  fontFamily: mono, fontSize: 12,
                  color: C.text,
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                  padding: 10,
                  background: C.bg,
                  border: `1px solid ${C.border}`,
                  borderRadius: 4,
                  marginBottom: 14,
                }}>
                  <span style={{ color: C.textFaint }}>"</span>
                  <span>{escapeVisible(selectedEntry.text)}</span>
                  <span style={{ color: C.textFaint }}>"</span>
                </div>

                <div style={{
                  fontFamily: sans, fontSize: 11, fontWeight: 600,
                  color: C.textMuted, marginBottom: 8,
                  textTransform: "uppercase", letterSpacing: 0.5,
                }}>
                  Referenced by ({selectedEntry.xrefs.length})
                </div>
                {selectedEntry.xrefs.length === 0 ? (
                  <div style={{
                    fontFamily: serif, fontStyle: "italic",
                    color: C.textFaint, fontSize: 11,
                  }}>
                    no code references found
                  </div>
                ) : (
                  <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                    {selectedXrefFuncs.map(({ ip, fn }) => (
                      <button
                        key={ip}
                        onClick={() => { if (fn) { onSelect(fn); onClose(); } }}
                        disabled={!fn}
                        style={{
                          display: "grid",
                          gridTemplateColumns: "auto 1fr",
                          alignItems: "center",
                          gap: 10,
                          padding: "4px 8px",
                          textAlign: "left",
                          borderRadius: 4,
                          cursor: fn ? "pointer" : "default",
                          opacity: fn ? 1 : 0.6,
                        }}
                        onMouseEnter={(e) => {
                          if (fn) (e.currentTarget as HTMLElement).style.background = C.bgMuted;
                        }}
                        onMouseLeave={(e) => {
                          (e.currentTarget as HTMLElement).style.background = "transparent";
                        }}
                      >
                        <span style={{ fontFamily: mono, fontSize: 10, color: C.textFaint }}>
                          {hexAddr(ip)}
                        </span>
                        <span style={{
                          fontFamily: sans, fontSize: 12,
                          color: fn ? C.textWarm : C.textFaint,
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                        }}>
                          {fn ? displayName(fn, annotations) : "<no function>"}
                        </span>
                      </button>
                    ))}
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
