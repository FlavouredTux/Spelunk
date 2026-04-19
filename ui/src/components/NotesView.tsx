import { useEffect, useMemo, useState } from "react";
import { C, sans, serif, mono } from "../theme";
import { displayName } from "../api";
import type { BinaryInfo, FunctionInfo, Annotations } from "../types";

// Find the function whose [addr, addr+size) contains `ip`.
function resolveFunction(info: BinaryInfo, ip: number): FunctionInfo | null {
  for (const f of info.functions) {
    if (ip >= f.addrNum && ip < f.addrNum + f.size) return f;
  }
  return null;
}

export function NotesView(props: {
  info: BinaryInfo;
  annotations: Annotations;
  onSelect: (fn: FunctionInfo) => void;
  onClose: () => void;
}) {
  const { info, annotations, onSelect, onClose } = props;
  const [q, setQ] = useState("");

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.preventDefault(); onClose(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const rows = useMemo(() => {
    const entries = Object.entries(annotations.notes ?? {});
    const out = entries.map(([addr, text]) => {
      const ip = parseInt(addr, 16);
      const fn = resolveFunction(info, ip);
      return { addr, ip, fn, text };
    });
    out.sort((a, b) => a.ip - b.ip);
    const needle = q.trim().toLowerCase();
    if (!needle) return out;
    return out.filter((r) =>
      r.addr.toLowerCase().includes(needle) ||
      r.text.toLowerCase().includes(needle) ||
      (r.fn && displayName(r.fn, annotations).toLowerCase().includes(needle))
    );
  }, [annotations, info, q]);

  return (
    <div
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.6)",
        display: "flex",
        alignItems: "flex-start",
        justifyContent: "center",
        paddingTop: "10vh",
        zIndex: 100,
      }}
    >
      <div
        style={{
          width: "min(720px, 90vw)",
          maxHeight: "78vh",
          background: C.bg,
          border: `1px solid ${C.borderStrong}`,
          borderRadius: 6,
          display: "flex",
          flexDirection: "column",
          overflow: "hidden",
        }}
      >
        <div style={{
          padding: "14px 16px 10px",
          borderBottom: `1px solid ${C.border}`,
          display: "flex", alignItems: "center", gap: 12,
        }}>
          <span style={{ fontFamily: serif, fontSize: 16, color: C.text }}>notes</span>
          <span style={{ fontFamily: mono, fontSize: 10, color: C.textFaint }}>
            {rows.length} {rows.length === 1 ? "entry" : "entries"}
          </span>
          <input
            autoFocus
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="filter…"
            className="sel"
            style={{
              marginLeft: "auto",
              width: 200,
              fontFamily: mono, fontSize: 12, color: C.text,
              padding: "4px 8px",
              background: C.bgInput,
              border: `1px solid ${C.border}`,
              borderRadius: 4,
            }}
          />
        </div>
        <div className="sel" style={{ flex: 1, overflowY: "auto" }}>
          {rows.length === 0 ? (
            <div style={{
              padding: 40, textAlign: "center",
              fontFamily: serif, fontStyle: "italic",
              color: C.textFaint, fontSize: 13,
            }}>
              {Object.keys(annotations.notes ?? {}).length === 0
                ? "no notes yet — add one via right-click on a function"
                : "no matches"}
            </div>
          ) : rows.map((r) => (
            <button
              key={r.addr}
              onClick={() => { if (r.fn) { onSelect(r.fn); onClose(); } }}
              disabled={!r.fn}
              style={{
                display: "block",
                width: "100%",
                textAlign: "left",
                padding: "10px 16px",
                borderBottom: `1px solid ${C.border}`,
                cursor: r.fn ? "pointer" : "default",
              }}
              onMouseEnter={(e) => {
                if (r.fn) (e.currentTarget as HTMLElement).style.background = C.bgMuted;
              }}
              onMouseLeave={(e) => {
                (e.currentTarget as HTMLElement).style.background = "transparent";
              }}
            >
              <div style={{ display: "flex", alignItems: "baseline", gap: 12 }}>
                <span style={{ fontFamily: mono, fontSize: 11, color: C.accent, width: 90, flexShrink: 0 }}>
                  {r.addr}
                </span>
                <span style={{ fontFamily: sans, fontSize: 13, color: C.text, fontWeight: 500 }}>
                  {r.fn ? displayName(r.fn, annotations) : <em style={{ color: C.textFaint }}>— no containing function —</em>}
                </span>
              </div>
              <div style={{
                fontFamily: serif, fontSize: 12.5, color: C.textWarm,
                marginLeft: 102, marginTop: 3, whiteSpace: "pre-wrap",
              }}>
                {r.text}
              </div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
