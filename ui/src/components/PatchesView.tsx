import { useEffect, useMemo, useState } from "react";
import { C, sans, serif, mono } from "../theme";
import { displayName } from "../api";
import type { BinaryInfo, FunctionInfo, Annotations } from "../types";

function resolveFunction(info: BinaryInfo, ip: number): FunctionInfo | null {
  for (const f of info.functions) {
    if (ip >= f.addrNum && ip < f.addrNum + f.size) return f;
  }
  return null;
}

// Pretty-print a contiguous hex string ("9090C3") as "90 90 C3" so
// the eye can chunk it. Identity for empty input.
function prettyBytes(s: string): string {
  return (s.match(/.{1,2}/g) || []).join(" ");
}

export function PatchesView(props: {
  info: BinaryInfo;
  annotations: Annotations;
  onSelect: (fn: FunctionInfo) => void;
  onRevert: (vaddrHex: string) => void;
  onSaveAs: () => void;
  onClose: () => void;
}) {
  const { info, annotations, onSelect, onRevert, onSaveAs, onClose } = props;
  const [q, setQ] = useState("");

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.preventDefault(); onClose(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const rows = useMemo(() => {
    const entries = Object.entries(annotations.patches ?? {});
    const out = entries.map(([addr, p]) => {
      const ip = parseInt(addr, 16);
      const fn = resolveFunction(info, ip);
      return { addr, ip, fn, bytes: p.bytes, orig: p.orig || "", comment: p.comment || "" };
    });
    out.sort((a, b) => a.ip - b.ip);
    const needle = q.trim().toLowerCase();
    if (!needle) return out;
    return out.filter((r) =>
      r.addr.toLowerCase().includes(needle) ||
      r.bytes.toLowerCase().includes(needle) ||
      r.comment.toLowerCase().includes(needle) ||
      (r.fn && displayName(r.fn, annotations).toLowerCase().includes(needle))
    );
  }, [annotations, info, q]);

  return (
    <div
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}
      style={{
        position: "fixed", inset: 0,
        background: "rgba(0,0,0,0.6)",
        display: "flex", alignItems: "flex-start", justifyContent: "center",
        paddingTop: "10vh", zIndex: 100,
      }}
    >
      <div
        style={{
          width: "min(820px, 92vw)",
          maxHeight: "78vh",
          background: C.bg,
          border: `1px solid ${C.borderStrong}`,
          borderRadius: 6,
          display: "flex", flexDirection: "column", overflow: "hidden",
        }}
      >
        <div style={{
          padding: "14px 16px 10px",
          borderBottom: `1px solid ${C.border}`,
          display: "flex", alignItems: "center", gap: 12,
        }}>
          <span style={{ fontFamily: serif, fontSize: 16, color: C.text }}>patches</span>
          <span style={{ fontFamily: mono, fontSize: 10, color: C.textFaint }}>
            {rows.length} {rows.length === 1 ? "patch" : "patches"}
          </span>
          <span style={{ flex: 1 }} />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="filter…"
            spellCheck={false}
            style={{
              padding: "5px 10px",
              background: C.bgMuted, color: C.text,
              border: `1px solid ${C.border}`, borderRadius: 4,
              fontFamily: mono, fontSize: 11, width: 180,
            }}
          />
          <button
            type="button"
            onClick={onSaveAs}
            disabled={rows.length === 0}
            style={{
              padding: "5px 12px",
              background: rows.length > 0 ? C.accent : C.bgMuted,
              color:      rows.length > 0 ? "#fff"   : C.textMuted,
              border: "none", borderRadius: 4,
              fontFamily: mono, fontSize: 10, fontWeight: 600,
              cursor: rows.length > 0 ? "pointer" : "not-allowed",
            }}
          >save patched binary as…</button>
        </div>

        <div style={{ overflowY: "auto", flex: 1 }}>
          {rows.length === 0 ? (
            <div style={{
              padding: "32px 24px",
              fontFamily: serif, fontStyle: "italic", fontSize: 13,
              color: C.textMuted, textAlign: "center",
            }}>
              No patches yet. Right-click any instruction in the asm view to patch it.
            </div>
          ) : rows.map((r) => (
            <div
              key={r.addr}
              style={{
                padding: "10px 16px",
                borderBottom: `1px solid ${C.border}`,
                display: "flex", flexDirection: "column", gap: 4,
              }}
            >
              <div style={{ display: "flex", alignItems: "baseline", gap: 10 }}>
                <button
                  type="button"
                  onClick={() => { if (r.fn) { onSelect(r.fn); onClose(); } }}
                  disabled={!r.fn}
                  style={{
                    all: "unset",
                    fontFamily: mono, fontSize: 12, color: C.accent,
                    cursor: r.fn ? "pointer" : "default",
                    textDecoration: r.fn ? "underline" : "none",
                    textUnderlineOffset: 3,
                  }}
                >{r.addr}</button>
                {r.fn && (
                  <span style={{
                    fontFamily: serif, fontStyle: "italic", fontSize: 12,
                    color: C.textMuted,
                  }}>in {displayName(r.fn, annotations)}</span>
                )}
                <span style={{ flex: 1 }} />
                <button
                  type="button"
                  onClick={() => onRevert(r.addr)}
                  style={{
                    padding: "3px 8px",
                    background: "transparent", color: C.red,
                    border: `1px solid ${C.red}`, borderRadius: 4,
                    fontFamily: mono, fontSize: 9, cursor: "pointer",
                  }}
                  title="revert this patch"
                >revert</button>
              </div>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap", fontFamily: mono, fontSize: 11 }}>
                {r.orig && (
                  <>
                    <span style={{
                      color: C.textFaint, textDecoration: "line-through",
                    }}>{prettyBytes(r.orig)}</span>
                    <span style={{ color: C.textFaint }}>→</span>
                  </>
                )}
                <span style={{ color: C.text }}>{prettyBytes(r.bytes)}</span>
                <span style={{ color: C.textFaint, marginLeft: "auto" }}>
                  {r.bytes.length / 2} byte{r.bytes.length / 2 === 1 ? "" : "s"}
                </span>
              </div>
              {r.comment && (
                <div style={{
                  fontFamily: serif, fontStyle: "italic", fontSize: 12,
                  color: C.textMuted,
                }}>{r.comment}</div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
