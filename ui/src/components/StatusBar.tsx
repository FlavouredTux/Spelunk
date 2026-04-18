import { C, sans, mono, serif } from "../theme";
import { demangle, formatSize } from "../api";
import type { FunctionInfo, ViewKind } from "../types";

export function StatusBar(props: {
  current: FunctionInfo | null;
  view: ViewKind;
  lines: number;
  loading: boolean;
}) {
  const { current, view, lines, loading } = props;
  return (
    <div
      style={{
        height: 28,
        background: C.bgAlt,
        borderTop: `1px solid ${C.border}`,
        display: "flex",
        alignItems: "center",
        padding: "0 16px",
        fontSize: 11,
        color: C.textMuted,
        fontFamily: mono,
        gap: 18,
        flexShrink: 0,
      }}
    >
      <span
        style={{
          width: 6, height: 6, borderRadius: 3,
          background: loading ? C.accent : current ? C.green : C.textFaint,
          animation: loading ? "pulse 1s ease-in-out infinite" : "none",
        }}
      />
      {current ? (
        <>
          <span style={{ color: C.accent }}>{current.addr}</span>
          <span style={{ color: C.text, fontFamily: sans, fontWeight: 500 }}>
            {demangle(current.name)}
          </span>
          <span>{formatSize(current.size)}</span>
          <span>{lines} lines</span>
          <span
            style={{
              marginLeft: "auto",
              fontFamily: serif,
              fontStyle: "italic",
            }}
          >
            viewing <span style={{ color: C.text }}>{view}</span>
          </span>
        </>
      ) : (
        <span style={{ fontFamily: serif, fontStyle: "italic" }}>
          no function selected
        </span>
      )}
    </div>
  );
}
