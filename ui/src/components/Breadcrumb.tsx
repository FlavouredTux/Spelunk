import { C, sans, mono } from "../theme";
import { displayName } from "../api";
import type { FunctionInfo, Annotations } from "../types";

// Renders the back-history chain as `caller › caller › current`. Items
// are clickable: jump to that point in the navigation stack.
export function Breadcrumb(props: {
  history: number[];          // addrNum, oldest first
  histIdx: number;            // current position in history
  fnByAddr: Map<number, FunctionInfo>;
  annotations: Annotations;
  onJumpTo: (idx: number) => void;
}) {
  const { history, histIdx, fnByAddr, annotations, onJumpTo } = props;
  if (history.length <= 1) return null;
  const items = history.slice(0, histIdx + 1).slice(-5);
  const baseIdx = histIdx + 1 - items.length;
  return (
    <div style={{
      padding: "6px 22px",
      display: "flex", alignItems: "center", gap: 6,
      flexWrap: "wrap",
      borderBottom: `1px solid ${C.border}`,
      background: C.bgAlt,
      flexShrink: 0,
      fontFamily: sans, fontSize: 11,
      color: C.textMuted,
    }}>
      <span style={{
        fontFamily: mono, fontSize: 9, color: C.textFaint,
        textTransform: "uppercase", letterSpacing: 1,
      }}>path</span>
      {items.map((addr, i) => {
        const idx = baseIdx + i;
        const fn = fnByAddr.get(addr);
        const isCurrent = idx === histIdx;
        const label = fn ? displayName(fn, annotations) : "0x" + addr.toString(16);
        return (
          <span key={`${addr}-${idx}`} style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <button
              onClick={() => onJumpTo(idx)}
              disabled={isCurrent}
              style={{
                fontFamily: sans, fontSize: 11,
                color: isCurrent ? C.text : C.textMuted,
                fontWeight: isCurrent ? 600 : 400,
                cursor: isCurrent ? "default" : "pointer",
                padding: "1px 4px",
                borderRadius: 3,
              }}
              onMouseEnter={(e) => { if (!isCurrent) (e.currentTarget as HTMLElement).style.color = C.text; }}
              onMouseLeave={(e) => { if (!isCurrent) (e.currentTarget as HTMLElement).style.color = C.textMuted; }}
              title={fn?.addr || ""}
            >{label}</button>
            {i < items.length - 1 && (
              <span style={{ color: C.textFaint, fontSize: 10 }}>›</span>
            )}
          </span>
        );
      })}
    </div>
  );
}
