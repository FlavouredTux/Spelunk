import { C, sans } from "../theme";
import type { ViewKind } from "../types";

const VIEWS: { id: ViewKind; label: string; hint: string }[] = [
  { id: "pseudo",    label: "pseudo-C",  hint: "decompiled"   },
  { id: "asm",       label: "asm",       hint: "linear disasm"},
  { id: "cfg",       label: "cfg",       hint: "graph"        },
  { id: "ir",        label: "ir",        hint: "lifted"       },
  { id: "ssa",       label: "ssa",       hint: "ssa form"     },
  { id: "identify",  label: "identify",  hint: "YARA-like"    },
];

export function Tabs(props: { view: ViewKind; setView: (v: ViewKind) => void; onIdentify?: () => void }) {
  return (
    <div
      data-tutorial="tabs"
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
        const isIdentify = v.id === "identify";
        return (
          <button
            key={v.id}
            onClick={() => isIdentify ? (props.onIdentify?.()) : props.setView(v.id)}
            style={{
              padding: "12px 18px 10px",
              minWidth: 92,
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
            <span style={{ fontFamily: sans, fontSize: 12.5, whiteSpace: "nowrap" }}>{v.label}</span>
            <span style={{ fontFamily: sans, fontSize: 10.5, color: C.textFaint }}>
              {v.hint}
            </span>
          </button>
        );
      })}
    </div>
  );
}
