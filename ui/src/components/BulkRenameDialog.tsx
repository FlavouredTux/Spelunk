import { useEffect, useMemo, useRef, useState } from "react";
import { C, sans, mono, serif } from "../theme";
import { displayName } from "../api";
import type { BinaryInfo, FunctionInfo, Annotations } from "../types";

// UI-side mirror of the CLI's [pattern-rename] semantics. The user
// supplies a glob pattern with a single `*` and a template that uses
// `*` to interpolate the captured part. Matches are computed against
// each function's currently-displayed name (existing rename if any,
// else the discovered name) — so iterating "rename log_* -> Logger_*"
// then "Logger_* -> NetLogger_*" works the way you'd expect.
//
// Rule that mirrors the CLI: any address that already carries a
// rename is skipped on apply, so user intent always beats inference.
// The preview lists those skipped rows separately so the user can
// see exactly what will and won't change before committing.
export function BulkRenameDialog(props: {
  info: BinaryInfo;
  annotations: Annotations;
  onApply: (next: Annotations, count: number) => void;
  onClose: () => void;
}) {
  const { info, annotations, onApply, onClose } = props;

  const [pattern,  setPattern ] = useState("sub_*");
  const [template, setTemplate] = useState("fn_*");
  const inputRef = useRef<HTMLInputElement>(null);
  useEffect(() => inputRef.current?.focus(), []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.preventDefault(); onClose(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  // Compile `sub_*` into a matcher that returns the captured piece,
  // mirroring the CLI's bare-`*` glob.
  const compiled = useMemo(() => {
    const star = pattern.indexOf("*");
    if (star < 0) {
      // Exact match — empty capture. Useful for "rename main -> entry".
      return { match: (name: string) => name === pattern ? "" : null };
    }
    const prefix = pattern.slice(0, star);
    const suffix = pattern.slice(star + 1);
    const tail   = pattern.indexOf("*", star + 1);
    if (tail >= 0) {
      // Multi-star pattern — fall back to "no match" since the CLI
      // also rejects this form, and explaining the error is clearer
      // than silently doing something half-right.
      return { match: () => null };
    }
    return {
      match: (name: string) => {
        if (!name.startsWith(prefix)) return null;
        if (suffix && !name.endsWith(suffix)) return null;
        if (name.length < prefix.length + suffix.length) return null;
        return name.slice(prefix.length, name.length - suffix.length);
      },
    };
  }, [pattern]);

  const interpolate = (capture: string) => template.split("*").join(capture);

  // Walk all defined functions + named imports and bucket them into:
  //   - rename: pattern matched, no existing user rename
  //   - skip:   pattern matched but user rename already present
  //   - miss:   pattern didn't match (not surfaced; just for counts)
  const buckets = useMemo(() => {
    type Row = { fn: FunctionInfo; current: string; next: string; skipped: boolean };
    const rename: Row[] = [];
    const skip:   Row[] = [];
    const targets: FunctionInfo[] = [
      ...info.functions,
      ...info.imports.filter((f) => f.addrNum !== 0 && f.name),
    ];
    for (const f of targets) {
      const current = displayName(f, annotations);
      const cap = compiled.match(current);
      if (cap == null) continue;
      const next = interpolate(cap);
      if (!next || next === current) continue;
      const hasUserRename = !!annotations.renames[f.addr];
      const row: Row = { fn: f, current, next, skipped: hasUserRename };
      if (hasUserRename) skip.push(row);
      else rename.push(row);
    }
    return { rename, skip };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [info, annotations, pattern, template]);

  const apply = () => {
    if (buckets.rename.length === 0) return;
    const next: Annotations = {
      ...annotations,
      renames: { ...annotations.renames },
    };
    for (const row of buckets.rename) {
      next.renames[row.fn.addr] = row.next;
    }
    onApply(next, buckets.rename.length);
  };

  const PREVIEW_CAP = 200;

  return (
    <div
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}
      style={{
        position: "fixed", inset: 0,
        background: "rgba(10,10,9,0.55)",
        backdropFilter: "blur(3px)",
        zIndex: 1900,
        display: "flex", justifyContent: "center",
        padding: "5vh 5vw",
        animation: "fadeIn .15s ease-out",
      }}
    >
      <div
        style={{
          flex: 1, maxWidth: 920,
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
              Bulk rename
            </span>
            <span style={{ fontFamily: serif, fontStyle: "italic", fontSize: 11, color: C.textMuted, marginTop: 2 }}>
              glob with single `*` capture · existing user renames are preserved
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

        <div style={{
          padding: "16px 22px",
          display: "flex", flexDirection: "column", gap: 10,
          borderBottom: `1px solid ${C.border}`,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{
              fontFamily: mono, fontSize: 10, color: C.textFaint,
              width: 70, textAlign: "right",
            }}>pattern</span>
            <input
              ref={inputRef}
              value={pattern}
              onChange={(e) => setPattern(e.target.value)}
              placeholder="sub_*"
              style={{
                flex: 1,
                fontFamily: mono, fontSize: 13, color: C.text,
                padding: "6px 10px",
                background: C.bgMuted,
                border: `1px solid ${C.border}`, borderRadius: 4,
              }}
            />
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{
              fontFamily: mono, fontSize: 10, color: C.textFaint,
              width: 70, textAlign: "right",
            }}>template</span>
            <input
              value={template}
              onChange={(e) => setTemplate(e.target.value)}
              placeholder="fn_*"
              style={{
                flex: 1,
                fontFamily: mono, fontSize: 13, color: C.text,
                padding: "6px 10px",
                background: C.bgMuted,
                border: `1px solid ${C.border}`, borderRadius: 4,
              }}
            />
          </div>
        </div>

        <div style={{ flex: 1, overflowY: "auto", padding: "8px 0 14px" }}>
          {buckets.rename.length === 0 && buckets.skip.length === 0 && (
            <div style={{
              padding: 28, textAlign: "center",
              fontFamily: serif, fontStyle: "italic",
              fontSize: 12, color: C.textFaint,
            }}>
              {pattern.includes("*")
                ? "no matches — try a different prefix"
                : "type a pattern with `*` (e.g. sub_*)"}
            </div>
          )}
          {buckets.rename.length > 0 && (
            <PreviewSection
              label="will rename"
              count={buckets.rename.length}
              rows={buckets.rename.slice(0, PREVIEW_CAP)}
              accent={C.accent}
              truncated={buckets.rename.length > PREVIEW_CAP}
            />
          )}
          {buckets.skip.length > 0 && (
            <PreviewSection
              label="skipped (already renamed)"
              count={buckets.skip.length}
              rows={buckets.skip.slice(0, PREVIEW_CAP / 2)}
              accent={C.textFaint}
              truncated={buckets.skip.length > PREVIEW_CAP / 2}
            />
          )}
        </div>

        <div style={{
          padding: "12px 18px",
          borderTop: `1px solid ${C.border}`,
          background: C.bgAlt,
          display: "flex", alignItems: "center", gap: 10,
        }}>
          <span style={{
            fontFamily: serif, fontStyle: "italic",
            fontSize: 11, color: C.textMuted,
          }}>
            {buckets.rename.length > 0
              ? `${buckets.rename.length} rename${buckets.rename.length === 1 ? "" : "s"} ready · undo with Ctrl+Z`
              : "preview only — apply enabled when matches arrive"}
          </span>
          <div style={{ flex: 1 }} />
          <button
            onClick={apply}
            disabled={buckets.rename.length === 0}
            style={{
              padding: "6px 14px",
              fontFamily: mono, fontSize: 11,
              color: buckets.rename.length === 0 ? C.textFaint : C.accent,
              background: C.bgMuted,
              border: `1px solid ${C.border}`, borderRadius: 4,
              cursor: buckets.rename.length === 0 ? "default" : "pointer",
              opacity: buckets.rename.length === 0 ? 0.5 : 1,
            }}
          >apply {buckets.rename.length > 0 ? buckets.rename.length : ""}</button>
        </div>
      </div>
    </div>
  );
}

function PreviewSection(props: {
  label: string;
  count: number;
  rows: Array<{ fn: FunctionInfo; current: string; next: string; skipped: boolean }>;
  accent: string;
  truncated: boolean;
}) {
  return (
    <div>
      <div style={{
        padding: "10px 22px 4px",
        fontFamily: sans, fontSize: 10, fontWeight: 600,
        color: C.textMuted,
        textTransform: "uppercase", letterSpacing: 0.8,
        display: "flex", alignItems: "baseline", justifyContent: "space-between",
      }}>
        <span>{props.label}</span>
        <span style={{
          fontFamily: mono, fontSize: 10,
          color: props.accent,
        }}>{props.count}</span>
      </div>
      {props.rows.map((row, i) => (
        <div
          key={`${row.fn.addr}-${i}`}
          style={{
            display: "flex", alignItems: "baseline", gap: 14,
            padding: "5px 22px",
            fontFamily: mono, fontSize: 11,
          }}
        >
          <span style={{
            color: C.textFaint, width: 90, flexShrink: 0,
          }}>{row.fn.addr.replace(/^0x0+(?=.)/, "0x")}</span>
          <span style={{
            color: row.skipped ? C.textFaint : C.textMuted,
            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
            maxWidth: "30%", flexShrink: 0,
          }} title={row.current}>{row.current}</span>
          <span style={{ color: C.textFaint }}>→</span>
          <span style={{
            color: row.skipped ? C.textFaint : props.accent,
            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
            flex: 1,
            textDecoration: row.skipped ? "line-through" : "none",
          }} title={row.next}>{row.next}</span>
        </div>
      ))}
      {props.truncated && (
        <div style={{
          padding: "6px 22px",
          fontFamily: serif, fontStyle: "italic",
          fontSize: 10, color: C.textFaint,
        }}>
          (more rows hidden — apply will process all of them)
        </div>
      )}
    </div>
  );
}
