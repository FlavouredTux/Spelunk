import { C, sans, mono, serif } from "../theme";
import type { ViewKind } from "../types";

const VIEWS: { id: ViewKind; label: string; hint: string }[] = [
  { id: "pseudo", label: "pseudo-C",  hint: "decompiled"   },
  { id: "asm",    label: "asm",       hint: "linear disasm"},
  { id: "cfg",    label: "cfg",       hint: "graph"        },
  { id: "ir",     label: "ir",        hint: "lifted"       },
  { id: "ssa",    label: "ssa",       hint: "ssa form"     },
];

export function Tabs(props: { view: ViewKind; setView: (v: ViewKind) => void }) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "stretch",
        padding: "0 16px",
        borderBottom: `1px solid ${C.border}`,
        background: C.bgAlt,
        gap: 2,
      }}
    >
      {VIEWS.map((v) => {
        const active = props.view === v.id;
        return (
          <button
            key={v.id}
            onClick={() => props.setView(v.id)}
            style={{
              padding: "12px 14px 10px",
              fontFamily: sans,
              fontSize: 12,
              fontWeight: active ? 600 : 400,
              color: active ? C.text : C.textMuted,
              display: "flex",
              flexDirection: "column",
              alignItems: "flex-start",
              gap: 2,
              borderBottom: `2px solid ${active ? C.accent : "transparent"}`,
              marginBottom: -1,
              transition: "color .12s",
            }}
            onMouseEnter={(e) => {
              if (!active) (e.currentTarget as HTMLElement).style.color = C.text;
            }}
            onMouseLeave={(e) => {
              if (!active) (e.currentTarget as HTMLElement).style.color = C.textMuted;
            }}
          >
            <span style={{ fontFamily: mono, fontSize: 11 }}>{v.label}</span>
            <span style={{ fontFamily: serif, fontStyle: "italic", fontSize: 9.5, color: C.textFaint }}>
              {v.hint}
            </span>
          </button>
        );
      })}
    </div>
  );
}
