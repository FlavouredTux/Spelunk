import { useMemo } from "react";
import { C } from "../theme";

// Generic shimmer block. Width and height are in CSS units (string or
// number) so the same primitive can stand in for an address pill, a
// long name, or a multi-line paragraph.
export function Skel(props: {
  w?: number | string;
  h?: number | string;
  style?: React.CSSProperties;
}) {
  return (
    <span
      className="ember-skel"
      style={{
        display: "inline-block",
        width:  props.w ?? "100%",
        height: props.h ?? 10,
        verticalAlign: "middle",
        ...props.style,
      }}
    />
  );
}

// Sidebar row stand-in. Mirrors the layout of the real virtualized
// row in Sidebar.tsx (addr column 72px, name column flexes, size
// column ~28px) so the eye doesn't reflow when real data arrives.
export function SkelSidebarRow(props: { seed: number }) {
  // Pseudo-random widths driven by the index so each row looks unique
  // without re-shuffling on every render. Math.sin gives a deterministic
  // "natural" spread without us having to ship a seeded PRNG.
  const nameW = 60 + Math.abs(Math.sin(props.seed * 7.3) * 60);
  return (
    <div style={{
      width: "100%", height: 35,
      padding: "8px 10px",
      display: "flex", alignItems: "center", gap: 10,
    }}>
      <Skel w={64} h={9} />
      <Skel w={`${nameW}%`} h={11} style={{ flex: 1 }} />
      <Skel w={28} h={9} />
    </div>
  );
}

// Code-pane stand-in. Renders `lines` rows of variable-width shimmer
// blocks so the body looks like it has indented code rather than a
// single rectangle. Line numbers stay realistic (1, 2, 3, …) so the
// gutter doesn't pop in when real content lands.
export function SkelCode(props: { lines?: number; lineHeight?: number }) {
  const lines = props.lines ?? 28;
  const lineH = props.lineHeight ?? 20;
  const widths = useMemo(() => {
    const out: number[] = [];
    // Hand-tuned "shape" — depth-of-indent tracks block structure so
    // the placeholder reads as code, not as blocks of static text.
    for (let i = 0; i < lines; i++) {
      const t = (Math.sin(i * 1.7) + 1) * 0.5;     // 0..1
      out.push(20 + t * 65);                        // 20..85% width
    }
    return out;
  }, [lines]);
  const indents = useMemo(() => {
    const out: number[] = [];
    let depth = 0;
    for (let i = 0; i < lines; i++) {
      // Pseudo-cycle through indent levels so the silhouette has nests.
      const phase = (Math.sin(i * 0.61) + 1) * 0.5;
      depth = Math.round(phase * 3);
      out.push(depth * 18);
    }
    return out;
  }, [lines]);
  return (
    <div style={{
      flex: 1, overflow: "hidden",
      padding: "16px 0",
    }}>
      {Array.from({ length: lines }, (_, i) => (
        <div key={i} style={{
          display: "flex", alignItems: "center",
          height: lineH, padding: "0 24px", gap: 18,
        }}>
          <Skel w={20} h={8} style={{ flexShrink: 0, opacity: 0.55 }} />
          <Skel w={`${widths[i]}%`} h={9} style={{ marginLeft: indents[i] }} />
        </div>
      ))}
    </div>
  );
}

// Function-header stand-in. Mirrors the address pill + name + sig
// chips so the toolbar height doesn't change when the real data
// arrives. Lives in App.tsx between the breadcrumb and the tabs.
export function SkelFunctionHeader() {
  return (
    <div style={{
      padding: "14px 22px",
      background: C.bg,
      borderBottom: `1px solid ${C.border}`,
      display: "flex", alignItems: "baseline", gap: 16,
      flexShrink: 0,
    }}>
      <Skel w={92} h={11} />
      <Skel w={170} h={15} />
      <Skel w={220} h={11} />
    </div>
  );
}

// Xrefs panel stand-in. Two stacked sections (Called by / Calls)
// matching the real panel structure.
export function SkelXrefs() {
  return (
    <div style={{ padding: "12px 16px" }}>
      <Skel w={70} h={9} style={{ marginBottom: 8 }} />
      {[0, 1, 2].map((i) => (
        <div key={i} style={{ display: "flex", gap: 10, padding: "5px 4px" }}>
          <Skel w={64} h={9} />
          <Skel w="60%" h={10} style={{ flex: 1 }} />
        </div>
      ))}
      <Skel w={50} h={9} style={{ marginTop: 14, marginBottom: 8 }} />
      {[0, 1].map((i) => (
        <div key={i} style={{ display: "flex", gap: 10, padding: "5px 4px" }}>
          <Skel w={64} h={9} />
          <Skel w="55%" h={10} style={{ flex: 1 }} />
        </div>
      ))}
    </div>
  );
}
