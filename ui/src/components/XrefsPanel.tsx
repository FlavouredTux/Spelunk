import { useMemo } from "react";
import { C, sans, mono, serif } from "../theme";
import { displayName, formatAddrHex } from "../api";
import type { BinaryInfo, FunctionInfo, Xrefs, Annotations } from "../types";

export function XrefsPanel(props: {
  info: BinaryInfo;
  current: FunctionInfo | null;
  xrefs: Xrefs;
  annotations: Annotations;
  width?: number;
  onSelect: (fn: FunctionInfo) => void;
  onToggle: () => void;
  open: boolean;
}) {
  const { info, current, xrefs, annotations, width, onSelect, onToggle, open } = props;

  const byAddr = useMemo(() => {
    const m = new Map<number, FunctionInfo>();
    for (const f of info.functions) m.set(f.addrNum, f);
    return m;
  }, [info]);

  if (!open) {
    return (
      <button
        data-tutorial="xrefs"
        onClick={onToggle}
        title="Show references"
        aria-label="Show references panel"
        style={{
          width: 28,
          background: C.bgAlt,
          borderLeft: `1px solid ${C.border}`,
          color: C.textMuted,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          gap: 6,
          flexShrink: 0,
          fontFamily: mono,
          fontSize: 10,
          writingMode: "vertical-rl",
          transform: "rotate(180deg)",
          cursor: "pointer",
        }}
      >
        <span style={{ fontFamily: serif, fontStyle: "italic" }}>references</span>
      </button>
    );
  }

  const callers = current ? (xrefs.callers[current.addrNum] || []) : [];
  const callees = current ? (xrefs.callees[current.addrNum] || []) : [];

  const renderList = (addrs: number[], emptyHint: string, kind: "caller" | "callee") => {
    if (!current) return <EmptyHint text="no function selected" />;
    if (addrs.length === 0) return <EmptyHint text={emptyHint} />;
    return (
      <div style={{ padding: "4px 8px 12px" }}>
        {addrs
          .map((a) => byAddr.get(a))
          .filter((f): f is FunctionInfo => !!f)
          .sort((a, b) => a.addrNum - b.addrNum)
          .map((f) => {
            const name = displayName(f, annotations);
            return (
              <button
                key={f.addrNum}
                onClick={() => onSelect(f)}
                style={{
                  width: "100%",
                  display: "flex",
                  alignItems: "center",
                  gap: 10,
                  padding: "6px 10px",
                  borderRadius: 4,
                  background: "transparent",
                  textAlign: "left",
                  marginBottom: 1,
                  cursor: "pointer",
                }}
                onMouseEnter={(e) => {
                  (e.currentTarget as HTMLElement).style.background = C.bgMuted;
                }}
                onMouseLeave={(e) => {
                  (e.currentTarget as HTMLElement).style.background = "transparent";
                }}
              >
                <span style={{
                  fontFamily: mono, fontSize: 10, color: C.textFaint,
                  width: 70, flexShrink: 0,
                  overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                }} title={f.addr}>{f.addr.replace(/^0x0+(?=.)/, "0x")}</span>
                <span style={{
                  fontFamily: sans, fontSize: 11, color: C.textWarm,
                  flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                }}
                title={f.name}
                >{name}</span>
                <span style={{ color: C.textFaint, fontFamily: mono, fontSize: 10 }}>
                  {kind === "caller" ? "›" : "›"}
                </span>
              </button>
            );
          })}
      </div>
    );
  };

  // Extract string literals referenced from the current pseudo-C view (best effort).
  // For this MVP the xrefs panel shows just callers and callees.

  return (
    <div
      data-tutorial="xrefs"
      style={{
        width: width ?? 260,
        background: C.bgAlt,
        borderLeft: `1px solid ${C.border}`,
        display: "flex",
        flexDirection: "column",
        flexShrink: 0,
        overflow: "hidden",
      }}
    >
      <div style={{
        padding: "14px 16px",
        borderBottom: `1px solid ${C.border}`,
        display: "flex",
        alignItems: "baseline",
        justifyContent: "space-between",
      }}>
        <div>
          <div style={{
            fontFamily: sans, fontSize: 13, fontWeight: 600, color: C.text,
          }}>References</div>
          {current && (
            <div style={{
              fontFamily: serif, fontStyle: "italic", fontSize: 11, color: C.textMuted,
              marginTop: 2,
              maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
            }} title={current.name}>
              {displayName(current, annotations)}
            </div>
          )}
        </div>
        <button
          onClick={onToggle}
          title="Hide"
          aria-label="Hide references panel"
          style={{ color: C.textFaint, fontSize: 14 }}
        >×</button>
      </div>

      <div style={{ flex: 1, overflowY: "auto" }}>
        <SectionHeader
          label="Called by"
          count={callers.length}
          hint={current ? "functions that call this one" : ""}
        />
        {renderList(callers, "no incoming callers", "caller")}

        <SectionHeader
          label="Calls"
          count={callees.length}
          hint={current ? "direct call targets from this function" : ""}
        />
        {renderList(callees, "no outgoing calls", "callee")}

        {current && annotations.notes[current.addr] && (
          <>
            <SectionHeader label="Note" count={0} hint="" />
            <div style={{
              padding: "4px 14px 16px",
              fontFamily: serif, fontStyle: "italic",
              fontSize: 12, color: C.textWarm,
              whiteSpace: "pre-wrap",
              lineHeight: 1.5,
            }}>
              {annotations.notes[current.addr]}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function SectionHeader(props: { label: string; count: number; hint: string }) {
  return (
    <div style={{
      padding: "12px 16px 6px",
      display: "flex",
      alignItems: "baseline",
      justifyContent: "space-between",
    }}>
      <span style={{
        fontFamily: sans, fontSize: 11, fontWeight: 600,
        color: C.textMuted,
        textTransform: "uppercase",
        letterSpacing: 0.8,
      }}>{props.label}</span>
      {props.count > 0 && (
        <span style={{
          fontFamily: mono, fontSize: 9, color: C.textFaint,
        }}>{props.count}</span>
      )}
    </div>
  );
}

function EmptyHint(props: { text: string }) {
  return (
    <div style={{
      padding: "8px 16px 14px",
      fontFamily: serif, fontStyle: "italic",
      fontSize: 11, color: C.textFaint,
    }}>{props.text}</div>
  );
}
