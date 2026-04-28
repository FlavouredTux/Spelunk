import { useEffect, useMemo, useRef, useState } from "react";
import { C, sans, serif, mono } from "../theme";
import { demangle, displayName, formatSize } from "../api";
import type { FunctionInfo, Annotations } from "../types";

export function CommandPalette(props: {
  functions: FunctionInfo[];
  annotations?: Annotations;
  onSelect: (fn: FunctionInfo) => void;
  // Optional handler for "fall through" hex addresses that don't match
  // any function start. App wires this to open the hex view at the
  // typed address — letting the palette double as a goto-vaddr dialog.
  onJumpAddress?: (vaddr: number) => void;
  onClose: () => void;
}) {
  const [q, setQ] = useState("");
  const [idx, setIdx] = useState(0);
  const listRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => inputRef.current?.focus(), []);

  // Parse the input as a hex address if it looks like one. Used to add
  // a synthetic "open hex view at 0x…" row when the typed value
  // doesn't exactly match a function start.
  const parsedVaddr: number | null = useMemo(() => {
    const t = q.trim();
    if (!t) return null;
    const m = /^(?:0x)?([0-9a-fA-F]+)$/.exec(t);
    if (!m) return null;
    const n = parseInt(m[1], 16);
    return Number.isFinite(n) && n > 0 ? n : null;
  }, [q]);

  const results = useMemo(() => {
    const needle = q.toLowerCase().trim();
    if (!needle) return props.functions.slice(0, 200);

    // Simple fuzzy score: prefer name prefix, then substring, then demangled, then addr.
    const scored = props.functions
      .map((f) => {
        const name = f.name.toLowerCase();
        const dem  = demangle(f.name).toLowerCase();
        const rn   = (props.annotations?.renames[f.addr] ?? "").toLowerCase();
        const addr = f.addr.toLowerCase();
        let score = 0;
        if (rn && rn.startsWith(needle))     score = 1200 - rn.length;
        else if (rn && rn.includes(needle))  score = 900  - rn.indexOf(needle);
        else if (name.startsWith(needle))    score = 1000 - name.length;
        else if (dem.startsWith(needle))     score = 800  - dem.length;
        else if (name.includes(needle))      score = 600 - name.indexOf(needle);
        else if (dem.includes(needle))       score = 500 - dem.indexOf(needle);
        else if (addr.includes(needle))      score = 300;
        return { f, score };
      })
      .filter((x) => x.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, 200)
      .map((x) => x.f);
    return scored;
  }, [q, props.functions]);

  // Show the synthetic "jump to address" row when the input parses as
  // a hex value AND the user has supplied the goto handler. We always
  // surface it (even if a function happens to start at that addr) so
  // typing `0x4047b3` with no matching function still gives the user
  // a way out — opening the hex view at exactly that byte.
  const showAddressRow =
    parsedVaddr != null && !!props.onJumpAddress;
  // Combined index space for keyboard navigation: row 0 is the
  // synthetic jump-to-addr row when present, then the function list.
  const totalRows = (showAddressRow ? 1 : 0) + results.length;

  useEffect(() => setIdx(0), [q]);

  // Scroll selection into view
  useEffect(() => {
    const el = listRef.current?.children[idx] as HTMLElement | undefined;
    if (!el) return;
    el.scrollIntoView({ block: "nearest" });
  }, [idx]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setIdx((i) => Math.min(i + 1, totalRows - 1));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setIdx((i) => Math.max(i - 1, 0));
      } else if (e.key === "Enter") {
        e.preventDefault();
        if (showAddressRow && idx === 0) {
          props.onJumpAddress!(parsedVaddr!);
          props.onClose();
          return;
        }
        const r = results[idx - (showAddressRow ? 1 : 0)];
        if (r) {
          props.onSelect(r);
          props.onClose();
        }
      } else if (e.key === "Escape") {
        e.preventDefault();
        props.onClose();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [results, idx, props, showAddressRow, parsedVaddr, totalRows]);

  return (
    <div
      onMouseDown={(e) => { if (e.target === e.currentTarget) props.onClose(); }}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(10,10,9,0.55)",
        backdropFilter: "blur(3px)",
        zIndex: 2000,
        display: "flex",
        justifyContent: "center",
        paddingTop: "12vh",
        animation: "fadeIn .12s ease-out",
      }}
    >
      <div
        style={{
          width: 560,
          maxWidth: "90%",
          maxHeight: "70vh",
          display: "flex",
          flexDirection: "column",
          background: C.bgAlt,
          border: `1px solid ${C.borderStrong}`,
          borderRadius: 8,
          overflow: "hidden",
          boxShadow: "0 24px 60px rgba(0,0,0,0.55)",
        }}
      >
        <div
          style={{
            display: "flex", alignItems: "center", gap: 12,
            padding: "14px 18px",
            borderBottom: `1px solid ${C.border}`,
          }}
        >
          <span style={{ fontFamily: serif, fontStyle: "italic", color: C.textFaint, fontSize: 13 }}>
            jump to
          </span>
          <input
            ref={inputRef}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="function name, address, or mangled symbol…"
            style={{
              flex: 1,
              fontFamily: sans, fontSize: 15,
              color: C.text,
            }}
          />
          <span style={{ fontFamily: mono, fontSize: 10, color: C.textFaint }}>
            {results.length} result{results.length === 1 ? "" : "s"}
          </span>
        </div>
        <div ref={listRef} style={{ overflowY: "auto", flex: 1, padding: 4 }}>
          {totalRows === 0 && (
            <div style={{
              padding: "32px 18px", textAlign: "center",
              fontFamily: serif, fontStyle: "italic", color: C.textFaint, fontSize: 13,
            }}>
              {q ? "no matches" : "type to search"}
            </div>
          )}
          {showAddressRow && (() => {
            const active = idx === 0;
            const v = parsedVaddr!;
            return (
              <button
                key="__jump_addr__"
                onClick={() => { props.onJumpAddress!(v); props.onClose(); }}
                onMouseEnter={() => setIdx(0)}
                style={{
                  width: "100%",
                  display: "flex",
                  alignItems: "center",
                  gap: 12,
                  padding: "8px 14px",
                  borderRadius: 4,
                  background: active ? C.bgDark : "transparent",
                  border: `1px solid ${active ? C.borderStrong : "transparent"}`,
                  textAlign: "left",
                  marginBottom: 1,
                }}
              >
                <span style={{
                  fontFamily: mono, fontSize: 10,
                  color: active ? C.accent : C.textFaint,
                  width: 76, flexShrink: 0,
                }}>0x{v.toString(16)}</span>
                <span style={{
                  flex: 1,
                  fontFamily: serif, fontStyle: "italic",
                  fontSize: 13, color: active ? C.text : C.textWarm,
                }}>
                  open hex view at this address
                </span>
                <span style={{
                  fontFamily: mono, fontSize: 9, color: C.textFaint,
                }}>hex</span>
              </button>
            );
          })()}
          {results.map((f, i) => {
            const rowIdx = i + (showAddressRow ? 1 : 0);
            const active = rowIdx === idx;
            const dem = demangle(f.name);
            const dn = displayName(f, props.annotations);
            const isRenamed = dn !== dem && dn !== f.name;
            return (
              <button
                key={f.addr + "-" + i}
                onClick={() => { props.onSelect(f); props.onClose(); }}
                onMouseEnter={() => setIdx(rowIdx)}
                style={{
                  width: "100%",
                  display: "flex",
                  alignItems: "center",
                  gap: 12,
                  padding: "8px 14px",
                  borderRadius: 4,
                  background: active ? C.bgDark : "transparent",
                  border: `1px solid ${active ? C.borderStrong : "transparent"}`,
                  textAlign: "left",
                  marginBottom: 1,
                }}
              >
                <span style={{
                  fontFamily: mono, fontSize: 10,
                  color: active ? C.text : C.textFaint,
                  width: 76, flexShrink: 0,
                  overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                }} title={f.addr}>{f.addr.replace(/^0x0+(?=.)/, "0x")}</span>
                <span style={{
                  flex: 1, minWidth: 0,
                  overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                  fontFamily: sans, fontSize: 13,
                  fontWeight: active ? 600 : (isRenamed ? 500 : 400),
                  color: active ? C.text : C.textWarm,
                }}>{dn}</span>
                {isRenamed && (
                  <span style={{ color: C.accent, fontSize: 9, fontFamily: mono }}>•</span>
                )}
                {dem !== f.name && !isRenamed && (
                  <span style={{
                    fontFamily: serif, fontStyle: "italic",
                    fontSize: 10, color: C.textFaint,
                    overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                    maxWidth: 180,
                  }}
                  title={f.name}
                  >{f.name}</span>
                )}
                <span style={{
                  fontFamily: mono, fontSize: 9, color: C.textFaint,
                }}>{formatSize(f.size)}</span>
              </button>
            );
          })}
        </div>
        <div style={{
          display: "flex", justifyContent: "space-between", alignItems: "center",
          padding: "8px 18px",
          borderTop: `1px solid ${C.border}`,
          fontFamily: mono, fontSize: 10, color: C.textFaint,
        }}>
          <span>↑↓ navigate · ⏎ open · esc close</span>
          <span style={{ fontFamily: serif, fontStyle: "italic" }}>
            {props.functions.length} symbols indexed
          </span>
        </div>
      </div>
    </div>
  );
}
