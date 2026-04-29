import { useEffect, useState } from "react";
import { C, sans, serif, mono } from "../theme";
import type { BinaryInfo, Annotations } from "../types";

// Lightweight summary parsed off the dry-run TSV: each section header
// (`[rename]`, `[note]`, `[signature]`, `[pattern-rename]`,
// `[from-strings]`, `[delete]`) is counted by its non-blank, non-comment
// directive lines. The user gets an at-a-glance "+12 renames, +3 notes"
// readout without us round-tripping ember just for stats.
function summarize(text: string): { sections: { name: string; count: number }[] } {
  const sections = new Map<string, number>();
  let current: string | null = null;
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const m = /^\[([a-z-]+)\]$/.exec(line);
    if (m) { current = m[1]; sections.set(current, sections.get(current) ?? 0); continue; }
    if (!current) continue;
    sections.set(current, (sections.get(current) ?? 0) + 1);
  }
  return {
    sections: Array.from(sections.entries())
      .filter(([, n]) => n > 0)
      .map(([name, count]) => ({ name, count })),
  };
}

export function EmberScriptView(props: {
  info: BinaryInfo;
  annotations: Annotations;
  onApplied: (next: Annotations) => void;
  onClose: () => void;
}) {
  const { onApplied, onClose } = props;
  const [scriptPath, setScriptPath] = useState<string | null>(null);
  const [preview,    setPreview]    = useState<string | null>(null);
  const [running,    setRunning]    = useState<"dry" | "apply" | null>(null);
  const [error,      setError]      = useState<string | null>(null);
  const [appliedMsg, setAppliedMsg] = useState<string | null>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.preventDefault(); onClose(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  async function pickAndPreview() {
    setError(null);
    setAppliedMsg(null);
    const picked = await window.ember.pickFile({
      title: "Select .ember script",
      filters: [
        { name: "Ember scripts", extensions: ["ember"] },
        { name: "All files",     extensions: ["*"] },
      ],
    });
    if (!picked) return;
    setScriptPath(picked);
    setRunning("dry");
    try {
      const out = await window.ember.applyEmberScript(picked, true);
      setPreview(out.preview ?? "");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setPreview(null);
    } finally {
      setRunning(null);
    }
  }

  async function applyForReal() {
    if (!scriptPath) return;
    setError(null);
    setAppliedMsg(null);
    setRunning("apply");
    try {
      const out = await window.ember.applyEmberScript(scriptPath, false);
      if (out.annotations) onApplied(out.annotations);
      setAppliedMsg(`Applied ${scriptPath.split("/").pop()} — annotations updated.`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setRunning(null);
    }
  }

  const summary = preview ? summarize(preview) : null;

  return (
    <div
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}
      style={{
        position: "fixed", inset: 0,
        background: "rgba(0,0,0,0.6)",
        display: "flex", alignItems: "flex-start", justifyContent: "center",
        paddingTop: "8vh", zIndex: 100,
      }}
    >
      <div
        style={{
          width: "min(880px, 94vw)",
          maxHeight: "84vh",
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
          <span style={{ fontFamily: serif, fontSize: 16, color: C.text }}>
            apply .ember script
          </span>
          <span style={{ fontFamily: mono, fontSize: 10, color: C.textFaint }}>
            {scriptPath ? scriptPath.split("/").pop() : "no script picked"}
          </span>
          <span style={{ flex: 1 }} />
          <button
            type="button"
            onClick={pickAndPreview}
            disabled={running !== null}
            style={{
              padding: "5px 12px",
              background: running ? C.bgMuted : C.bgAlt,
              color:      running ? C.textMuted : C.text,
              border: `1px solid ${C.border}`, borderRadius: 4,
              fontFamily: mono, fontSize: 10, fontWeight: 500,
              cursor: running ? "wait" : "pointer",
            }}
          >{scriptPath ? "pick another…" : "pick script…"}</button>
          <button
            type="button"
            onClick={applyForReal}
            disabled={!scriptPath || running !== null || !!error}
            style={{
              padding: "5px 12px",
              background: scriptPath && !running && !error ? C.accent : C.bgMuted,
              color:      scriptPath && !running && !error ? "#fff"   : C.textMuted,
              border: "none", borderRadius: 4,
              fontFamily: mono, fontSize: 10, fontWeight: 600,
              cursor: scriptPath && !running && !error ? "pointer" : "not-allowed",
            }}
            title="Write the resulting annotations to disk"
          >{running === "apply" ? "applying…" : "apply"}</button>
        </div>

        {summary && (
          <div style={{
            padding: "8px 16px",
            borderBottom: `1px solid ${C.border}`,
            display: "flex", flexWrap: "wrap", alignItems: "center", gap: 10,
            fontFamily: mono, fontSize: 10, color: C.textMuted,
          }}>
            <span style={{ color: C.textFaint }}>would write:</span>
            {summary.sections.length === 0 ? (
              <span style={{ color: C.textFaint, fontStyle: "italic" }}>
                no annotations (script matched nothing or all sections empty)
              </span>
            ) : (
              summary.sections.map((s) => (
                <span key={s.name} style={{
                  padding: "2px 8px",
                  background: `${C.accent}14`, color: C.accent,
                  border: `1px solid ${C.border}`, borderRadius: 4,
                }}>
                  {s.count} {s.name}
                </span>
              ))
            )}
          </div>
        )}

        {appliedMsg && (
          <div style={{
            padding: "10px 16px",
            background: `${C.green}14`,
            color: C.green,
            fontFamily: mono, fontSize: 11,
            borderBottom: `1px solid ${C.border}`,
          }}>{appliedMsg}</div>
        )}
        {error && (
          <div style={{
            padding: "10px 16px",
            background: `${C.red}14`,
            color: C.red,
            fontFamily: mono, fontSize: 11,
            borderBottom: `1px solid ${C.border}`,
            whiteSpace: "pre-wrap",
          }}>{error}</div>
        )}

        <div style={{ overflow: "auto", flex: 1 }} className="sel">
          {!scriptPath && !running && !error && (
            <div style={{
              padding: "32px 24px",
              fontFamily: serif, fontStyle: "italic", fontSize: 13,
              color: C.textMuted, textAlign: "center",
            }}>
              Pick a declarative .ember script — sections like
              <code style={{ fontFamily: mono, fontSize: 11, color: C.textWarm,
                              padding: "0 4px" }}>[rename]</code>,
              <code style={{ fontFamily: mono, fontSize: 11, color: C.textWarm,
                              padding: "0 4px" }}>[signature]</code>,
              <code style={{ fontFamily: mono, fontSize: 11, color: C.textWarm,
                              padding: "0 4px" }}>[from-strings]</code>
              are previewed here as a TSV before you apply.
            </div>
          )}
          {running === "dry" && !preview && (
            <div style={{
              padding: "40px 24px",
              fontFamily: mono, fontSize: 11,
              color: C.textMuted, textAlign: "center",
            }}>running script (dry-run)…</div>
          )}
          {preview && (
            <pre style={{
              margin: 0,
              padding: "12px 18px",
              fontFamily: mono, fontSize: 11,
              color: C.textWarm,
              whiteSpace: "pre",
              minWidth: "min-content",
            }}>{preview}</pre>
          )}
        </div>
      </div>
    </div>
  );
}
