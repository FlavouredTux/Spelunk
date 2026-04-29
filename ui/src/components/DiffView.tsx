import { useEffect, useMemo, useState } from "react";
import { C, sans, serif, mono } from "../theme";
import type { BinaryInfo, FunctionInfo } from "../types";

type DiffTag = "kept" | "moved" | "edited" | "fuzzy" | "added" | "removed";

type DiffEntry = {
  tag: DiffTag;
  fp: string;
  old_addr: string | null;
  new_addr: string | null;
  old_name: string;
  new_name: string;
};

type DiffSummary = Record<DiffTag, number>;

type DiffResult = {
  old: { path: string; functions: number };
  new: { path: string; functions: number };
  summary: DiffSummary;
  entries: DiffEntry[];
};

const TAG_ORDER: DiffTag[] = ["added", "removed", "edited", "fuzzy", "moved", "kept"];

// Tag → palette pick. `kept` and `moved` are "no observable change",
// edited/fuzzy are the interesting cases, added/removed are deltas.
function tagColor(t: DiffTag): string {
  switch (t) {
    case "added":   return C.green;
    case "removed": return C.red;
    case "edited":  return C.accent;
    case "fuzzy":   return C.yellow;
    case "moved":   return C.blue;
    case "kept":    return C.textMuted;
  }
}

export function DiffView(props: {
  info: BinaryInfo;
  fnByAddr: Map<number, FunctionInfo>;
  onSelect: (fn: FunctionInfo) => void;
  onClose: () => void;
}) {
  const { info, fnByAddr, onSelect, onClose } = props;
  const [oldPath, setOldPath] = useState<string | null>(null);
  const [result,  setResult]  = useState<DiffResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState<string | null>(null);
  // Default to hiding "kept" — the unchanged majority that drowns
  // out the interesting deltas. User can flip any chip to include it.
  const [enabled, setEnabled] = useState<Record<DiffTag, boolean>>({
    added: true, removed: true, edited: true, fuzzy: true, moved: true, kept: false,
  });
  const [q, setQ] = useState("");

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.preventDefault(); onClose(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  async function pickAndRun() {
    setError(null);
    const picked = await window.ember.pickFile({
      title: "Select older binary to diff against",
      filters: [{ name: "All files", extensions: ["*"] }],
    });
    if (!picked) return;
    setOldPath(picked);
    setLoading(true);
    try {
      const raw = await window.ember.run([
        "--diff", picked, "--diff-format", "json",
      ]);
      setResult(JSON.parse(raw) as DiffResult);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setResult(null);
    } finally {
      setLoading(false);
    }
  }

  const filtered = useMemo(() => {
    if (!result) return [] as DiffEntry[];
    const needle = q.trim().toLowerCase();
    return result.entries.filter((e) => {
      if (!enabled[e.tag]) return false;
      if (!needle) return true;
      return (
        e.old_name.toLowerCase().includes(needle) ||
        e.new_name.toLowerCase().includes(needle) ||
        (e.old_addr ?? "").toLowerCase().includes(needle) ||
        (e.new_addr ?? "").toLowerCase().includes(needle) ||
        e.fp.toLowerCase().includes(needle)
      );
    });
  }, [result, enabled, q]);

  const onEntryClick = (e: DiffEntry) => {
    if (!e.new_addr) return;
    const addr = parseInt(e.new_addr, 16);
    if (!Number.isFinite(addr)) return;
    const fn = fnByAddr.get(addr);
    if (fn) { onSelect(fn); onClose(); }
  };

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
          width: "min(960px, 94vw)",
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
          <span style={{ fontFamily: serif, fontSize: 16, color: C.text }}>diff</span>
          <span style={{ fontFamily: mono, fontSize: 10, color: C.textFaint }}>
            {info.path.split("/").pop()}
            {oldPath ? ` ← ${oldPath.split("/").pop()}` : ""}
          </span>
          <span style={{ flex: 1 }} />
          {result && (
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
          )}
          <button
            type="button"
            onClick={pickAndRun}
            disabled={loading}
            style={{
              padding: "5px 12px",
              background: loading ? C.bgMuted : C.accent,
              color: loading ? C.textMuted : "#fff",
              border: "none", borderRadius: 4,
              fontFamily: mono, fontSize: 10, fontWeight: 600,
              cursor: loading ? "wait" : "pointer",
            }}
          >{result ? "diff again…" : loading ? "diffing…" : "pick old binary…"}</button>
        </div>

        {result && (
          <div style={{
            padding: "8px 16px",
            borderBottom: `1px solid ${C.border}`,
            display: "flex", flexWrap: "wrap", alignItems: "center", gap: 8,
            fontFamily: mono, fontSize: 10,
          }}>
            <span style={{ color: C.textFaint }}>
              old {result.old.functions} fn · new {result.new.functions} fn
            </span>
            <span style={{ flex: 1 }} />
            {TAG_ORDER.map((t) => {
              const n = result.summary[t] ?? 0;
              const on = enabled[t];
              return (
                <button
                  key={t}
                  type="button"
                  onClick={() => setEnabled((s) => ({ ...s, [t]: !s[t] }))}
                  style={{
                    padding: "3px 8px",
                    background: on ? `${tagColor(t)}1f` : "transparent",
                    color: on ? tagColor(t) : C.textFaint,
                    border: `1px solid ${on ? tagColor(t) : C.border}`,
                    borderRadius: 4,
                    fontFamily: mono, fontSize: 10,
                    cursor: "pointer",
                    opacity: n === 0 ? 0.4 : 1,
                  }}
                  title={`${t}: ${n}`}
                >{t} <span style={{ opacity: 0.6 }}>{n}</span></button>
              );
            })}
          </div>
        )}

        <div style={{ overflowY: "auto", flex: 1 }}>
          {!result && !loading && !error && (
            <div style={{
              padding: "32px 24px",
              fontFamily: serif, fontStyle: "italic", fontSize: 13,
              color: C.textMuted, textAlign: "center",
            }}>
              Pick a previous build of this binary to compare against — ember
              fingerprints both sides and reports kept / moved / edited /
              added / removed functions.
            </div>
          )}
          {loading && (
            <div style={{
              padding: "40px 24px",
              fontFamily: mono, fontSize: 11,
              color: C.textMuted, textAlign: "center",
            }}>
              fingerprinting both binaries — first run can take a moment.
            </div>
          )}
          {error && (
            <div style={{
              padding: "20px 24px",
              fontFamily: mono, fontSize: 11,
              color: C.red, whiteSpace: "pre-wrap",
            }}>{error}</div>
          )}
          {result && filtered.length === 0 && (
            <div style={{
              padding: "32px 24px",
              fontFamily: serif, fontStyle: "italic", fontSize: 13,
              color: C.textMuted, textAlign: "center",
            }}>No entries match the current filter.</div>
          )}
          {result && filtered.map((e, i) => {
            const newAddr = e.new_addr ? parseInt(e.new_addr, 16) : null;
            const navigable =
              newAddr !== null && Number.isFinite(newAddr) && fnByAddr.has(newAddr);
            return (
              <div
                key={`${e.tag}-${i}`}
                onClick={() => navigable && onEntryClick(e)}
                style={{
                  padding: "8px 16px",
                  borderBottom: `1px solid ${C.border}`,
                  display: "grid",
                  gridTemplateColumns: "70px 1fr auto",
                  gap: 12, alignItems: "baseline",
                  cursor: navigable ? "pointer" : "default",
                  fontFamily: mono, fontSize: 11,
                }}
              >
                <span style={{
                  color: tagColor(e.tag),
                  fontWeight: 600,
                  textTransform: "uppercase",
                  fontSize: 9,
                  letterSpacing: 0.5,
                }}>{e.tag}</span>
                <div style={{ minWidth: 0 }}>
                  {e.old_name && e.new_name ? (
                    e.old_name === e.new_name ? (
                      <span style={{ color: C.text }}>{e.new_name}</span>
                    ) : (
                      <>
                        <span style={{ color: C.textMuted }}>{e.old_name}</span>
                        <span style={{ color: C.textFaint, margin: "0 6px" }}>→</span>
                        <span style={{ color: C.text }}>{e.new_name}</span>
                      </>
                    )
                  ) : (
                    <span style={{ color: C.text }}>{e.new_name || e.old_name}</span>
                  )}
                </div>
                <span style={{ color: C.textFaint, fontSize: 10 }}>
                  {e.old_addr ?? "—"}
                  <span style={{ margin: "0 4px" }}>→</span>
                  <span style={{ color: navigable ? C.accent : C.textFaint }}>
                    {e.new_addr ?? "—"}
                  </span>
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
