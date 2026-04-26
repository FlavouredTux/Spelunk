import { useEffect } from "react";
import { C, sans, serif, mono } from "../theme";

// Keep grouped + ordered by frequency-of-use. The wrap-up step of
// the first-run tutorial promises this exists; if you add a new
// global keybinding in App.tsx, mirror it here.
type Row = { keys: string; label: string };
type Group = { title: string; rows: Row[] };

const GROUPS: Group[] = [
  {
    title: "Navigation",
    rows: [
      { keys: "⌃P",          label: "jump to function (palette)" },
      { keys: "Alt+← / ⌃[",  label: "back" },
      { keys: "Alt+→ / ⌃]",  label: "forward" },
      { keys: "⌃F",          label: "search in current view" },
    ],
  },
  {
    title: "Views",
    rows: [
      { keys: "p", label: "pseudo-C" },
      { keys: "d", label: "asm (linear disasm)" },
      { keys: "c", label: "control-flow graph" },
      { keys: "i", label: "lifted IR" },
      { keys: "s", label: "SSA" },
    ],
  },
  {
    title: "Panels",
    rows: [
      { keys: "⌃G",   label: "call graph" },
      { keys: "⌃T",   label: "strings" },
      { keys: "⌃J",   label: "notes" },
      { keys: "⌃U",   label: "plugins" },
      { keys: "⌃K",   label: "AI assistant" },
      { keys: "⌃⇧P",  label: "patches" },
    ],
  },
  {
    title: "Editing",
    rows: [
      { keys: "N",  label: "rename current function" },
      { keys: "⇧S", label: "edit signature" },
    ],
  },
  {
    title: "This panel",
    rows: [
      { keys: "?",   label: "open / close shortcuts" },
      { keys: "Esc", label: "close any open panel" },
    ],
  },
];

export function Shortcuts(props: { onClose: () => void }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" || e.key === "?") {
        e.preventDefault();
        props.onClose();
      }
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [props]);

  return (
    <div
      onMouseDown={(e) => { if (e.target === e.currentTarget) props.onClose(); }}
      style={{
        position: "fixed", inset: 0,
        background: "rgba(10,10,9,0.55)",
        backdropFilter: "blur(3px)",
        zIndex: 2500,
        display: "flex",
        justifyContent: "center",
        paddingTop: "10vh",
        animation: "fadeIn .12s ease-out",
      }}
    >
      <div
        style={{
          width: 580,
          maxWidth: "90%",
          maxHeight: "80vh",
          background: C.bgAlt,
          border: `1px solid ${C.borderStrong}`,
          borderRadius: 8,
          overflow: "hidden",
          display: "flex",
          flexDirection: "column",
          boxShadow: "0 24px 60px rgba(0,0,0,0.55)",
        }}
      >
        <div
          style={{
            padding: "14px 20px 12px",
            borderBottom: `1px solid ${C.border}`,
            display: "flex", alignItems: "baseline", gap: 12,
          }}
        >
          <span style={{ fontFamily: sans, fontSize: 14, fontWeight: 600, color: C.text }}>
            Keyboard shortcuts
          </span>
          <span style={{ fontFamily: serif, fontStyle: "italic", fontSize: 12, color: C.textFaint }}>
            press ? again or Esc to close
          </span>
        </div>
        <div
          style={{
            padding: "12px 20px 18px",
            overflowY: "auto",
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: "16px 28px",
          }}
        >
          {GROUPS.map((g) => (
            <div key={g.title}>
              <div
                style={{
                  fontFamily: mono, fontSize: 9,
                  color: C.accent, letterSpacing: 1,
                  marginBottom: 6, paddingTop: 4,
                }}
              >
                {g.title.toUpperCase()}
              </div>
              {g.rows.map((r) => (
                <div
                  key={r.keys + r.label}
                  style={{
                    display: "flex", alignItems: "baseline",
                    padding: "3px 0",
                    fontFamily: sans, fontSize: 12, color: C.textWarm,
                  }}
                >
                  <span
                    style={{
                      fontFamily: mono, fontSize: 11,
                      color: C.text,
                      minWidth: 96,
                      flexShrink: 0,
                    }}
                  >
                    {r.keys}
                  </span>
                  <span>{r.label}</span>
                </div>
              ))}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
