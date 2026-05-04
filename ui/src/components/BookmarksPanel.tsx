import { useEffect, useState } from "react";
import { C, sans, serif, mono } from "../theme";
import { displayName } from "../api";
import { useFmtAddr } from "../RebaseContext";
import type { BinaryInfo, FunctionInfo, Annotations } from "../types";

export type Bookmark = { addr: string; label?: string };

export function BookmarksPanel(props: {
  info: BinaryInfo;
  bookmarks: Bookmark[];
  annotations: Annotations;
  onSelect: (fn: FunctionInfo) => void;
  onRemove: (addr: string) => void;
  onRename: (addr: string, label: string) => void;
  onClose: () => void;
}) {
  const { info, bookmarks, annotations, onSelect, onRemove, onRename, onClose } = props;
  const fmtAddr = useFmtAddr();
  const [editing, setEditing] = useState<string | null>(null);
  const [draftLabel, setDraftLabel] = useState("");

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.preventDefault(); onClose(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const fnByAddr = new Map<string, FunctionInfo>();
  for (const f of info.functions) fnByAddr.set(f.addr, f);

  return (
    <div
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}
      style={{
        position: "fixed", inset: 0,
        background: "rgba(10,10,9,0.55)",
        backdropFilter: "blur(3px)",
        zIndex: 1850,
        display: "flex", justifyContent: "center",
        padding: "8vh 25vw",
        animation: "fadeIn .15s ease-out",
      }}
    >
      <div style={{
        flex: 1, maxWidth: 720,
        display: "flex", flexDirection: "column",
        background: C.bg,
        border: `1px solid ${C.borderStrong}`,
        borderRadius: 8,
        boxShadow: "0 30px 80px rgba(0,0,0,0.6)",
        overflow: "hidden",
      }}>
        <div style={{
          padding: "12px 18px", borderBottom: `1px solid ${C.border}`,
          background: C.bgAlt,
          display: "flex", alignItems: "center", gap: 14,
        }}>
          <div style={{ display: "flex", flexDirection: "column", lineHeight: 1.2 }}>
            <span style={{ fontFamily: sans, fontSize: 13, fontWeight: 600, color: C.text }}>
              Bookmarks
            </span>
            <span style={{ fontFamily: serif, fontStyle: "italic", fontSize: 11, color: C.textMuted, marginTop: 2 }}>
              {bookmarks.length} saved · per binary
            </span>
          </div>
          <div style={{ flex: 1 }} />
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

        {bookmarks.length === 0 && (
          <div style={{
            padding: 36, textAlign: "center",
            fontFamily: serif, fontStyle: "italic",
            fontSize: 12, color: C.textFaint,
          }}>
            no bookmarks yet — press <span style={{ fontFamily: mono, color: C.textMuted }}>b</span> on any function to save one
          </div>
        )}

        <div style={{ flex: 1, overflowY: "auto" }}>
          {bookmarks.map((b) => {
            const fn = fnByAddr.get(b.addr);
            const dn = fn ? displayName(fn, annotations) : (b.label || b.addr);
            return (
              <div
                key={b.addr}
                style={{
                  padding: "8px 18px",
                  display: "flex", alignItems: "center", gap: 12,
                  borderBottom: `1px solid ${C.border}`,
                }}
              >
                <span style={{
                  fontFamily: mono, fontSize: 11, color: C.accent,
                  width: 96, flexShrink: 0,
                }}>{fmtAddr(parseInt(b.addr, 16))}</span>
                <button
                  onClick={() => fn && onSelect(fn)}
                  disabled={!fn}
                  style={{
                    flex: 1, textAlign: "left",
                    fontFamily: sans, fontSize: 12,
                    color: fn ? C.text : C.textFaint,
                    cursor: fn ? "pointer" : "default",
                  }}
                >{dn}</button>
                {editing === b.addr ? (
                  <input
                    value={draftLabel}
                    autoFocus
                    onChange={(e) => setDraftLabel(e.target.value)}
                    onBlur={() => { onRename(b.addr, draftLabel); setEditing(null); }}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") { onRename(b.addr, draftLabel); setEditing(null); }
                      if (e.key === "Escape") { setEditing(null); }
                    }}
                    placeholder="label…"
                    style={{
                      fontFamily: mono, fontSize: 11, color: C.text,
                      background: C.bgMuted,
                      border: `1px solid ${C.border}`,
                      borderRadius: 3, padding: "2px 6px",
                      width: 160,
                    }}
                  />
                ) : (
                  <>
                    {b.label && (
                      <span style={{
                        fontFamily: serif, fontStyle: "italic",
                        fontSize: 11, color: C.textMuted,
                      }}>{b.label}</span>
                    )}
                    <button
                      onClick={() => { setEditing(b.addr); setDraftLabel(b.label || ""); }}
                      title="Edit label"
                      aria-label="Edit bookmark label"
                      style={{
                        fontFamily: mono, fontSize: 10, color: C.textFaint,
                        padding: "2px 8px",
                        border: `1px solid ${C.border}`, borderRadius: 3,
                      }}
                    >edit</button>
                  </>
                )}
                <button
                  onClick={() => onRemove(b.addr)}
                  title="Remove bookmark"
                  aria-label="Remove bookmark"
                  style={{
                    fontFamily: mono, fontSize: 12, color: C.textFaint,
                    padding: "2px 8px",
                    border: `1px solid ${C.border}`, borderRadius: 3,
                  }}
                >×</button>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
