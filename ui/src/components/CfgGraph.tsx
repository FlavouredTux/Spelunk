import { memo, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { C, sans, mono, serif } from "../theme";
import { highlightLine } from "../syntax";

// Kind hint matches the BlockKind enum in core/include/ember/analysis/function.hpp
// — derived per-block from the successor labels printed by pipeline.cpp.
// `fallthrough` is the catch-all for plain straight-line blocks. `entry`
// overrides any of the others (see `kindOf` below).
type CfgKind =
  | "entry"
  | "return"
  | "conditional"
  | "switch"
  | "indirect"
  | "tailcall"
  | "unconditional"
  | "fallthrough";

type CfgInst = { addr: string; text: string };

type CfgBlock = {
  id: string;
  addr: number;
  entry: boolean;
  kind: CfgKind;
  preds: string[];
  insts: CfgInst[];
  succs: { target: string; label: string }[];
};

// Derive the structural kind from the successor labels we just parsed.
// The CLI's pipeline.cpp emits the same label vocabulary that the
// emitter uses; mapping it here keeps the renderer one-to-one with the
// backend's BlockKind enum without us having to re-encode it.
function kindOf(b: { entry: boolean; succs: { target: string; label: string }[] }): CfgKind {
  if (b.entry) return "entry";
  for (const s of b.succs) {
    if (s.target === "<return>") return "return";
    if (s.target === "<indirect>") return "indirect";
    if (s.label === "tail-call") return "tailcall";
  }
  if (b.succs.some((s) => s.label.startsWith("case ") || s.label === "default")) {
    return "switch";
  }
  if (b.succs.some((s) => s.label === "taken" || s.label === "fallthrough")) {
    return "conditional";
  }
  if (b.succs.length === 1) return "unconditional";
  return "fallthrough";
}

function parseCfg(text: string): { blocks: CfgBlock[]; entry: string | null } {
  const rawLines = text.split("\n");
  const blocks: CfgBlock[] = [];
  let cur: CfgBlock | null = null;
  let entry: string | null = null;

  const header = /^(bb_[0-9a-f]+)\s*(\(entry\))?\s*(?:<-\s*([^:]+?))?\s*:\s*$/;
  const succ   = /^\s+->\s+(bb_[0-9a-f]+|<[^>]+>)(?:\s+\((.+?)\))?\s*$/;
  // Asm-body line:
  //   "  0x0000000000401120  83 ff 05                        cmp edi, 0x5"
  //   → addr=401120, bytes="83 ff 05", disasm="cmp edi, 0x5"
  const inst   = /^\s+0x([0-9a-f]+)\s+((?:[0-9a-f]{2}\s+)+)(.*\S)\s*$/;
  // Pseudo-body line: any other indented non-arrow text. The cfg-pseudo
  // emitter doesn't carry per-line VAs (block scope is enough), so we
  // just keep the source line verbatim and let the syntax highlighter
  // colour it.
  const pseudoInst = /^\s{2,}(\S.*\S?)\s*$/;

  for (const raw of rawLines) {
    const l = raw.replace(/\r$/, "");
    const m = header.exec(l);
    if (m) {
      if (cur) {
        cur.kind = kindOf(cur);
        blocks.push(cur);
      }
      const id = m[1];
      const isEntry = !!m[2];
      const preds = (m[3] ?? "").trim().split(/\s+/).filter(Boolean);
      cur = {
        id,
        addr: parseInt(id.slice(3), 16),
        entry: isEntry,
        kind: "fallthrough",  // overwritten when we close the block
        preds,
        insts: [],
        succs: [],
      };
      if (isEntry) entry = id;
      continue;
    }
    const s = succ.exec(l);
    if (s && cur) {
      cur.succs.push({ target: s[1], label: s[2] ?? "" });
      continue;
    }
    const m2 = inst.exec(l);
    if (m2 && cur) {
      const shortAddr = m2[1].replace(/^0+/, "") || "0";
      cur.insts.push({ addr: shortAddr, text: m2[3] });
      continue;
    }
    // Pseudo-body fallback. The `cur` check naturally excludes the
    // file-preamble comments (which appear before any block opens);
    // in-block comments (landing-pad / EH notes from emit_block) are
    // kept verbatim as body lines.
    const pm = pseudoInst.exec(l);
    if (pm && cur) {
      cur.insts.push({ addr: "", text: pm[1] });
    }
  }
  if (cur) {
    cur.kind = kindOf(cur);
    blocks.push(cur);
  }
  return { blocks, entry };
}

// Collapse single-succ / single-pred fallthrough chains into one node.
function mergeFallthroughs(blocks: CfgBlock[]): CfgBlock[] {
  const byId = new Map<string, CfgBlock>();
  for (const b of blocks) {
    byId.set(b.id, { ...b, preds: [...b.preds], succs: [...b.succs], insts: [...b.insts] });
  }
  const isFallthrough = (label: string) => label === "" || label === "fallthrough";

  let changed = true;
  while (changed) {
    changed = false;
    for (const p of Array.from(byId.values())) {
      if (p.succs.length !== 1) continue;
      const edge = p.succs[0];
      if (edge.target.startsWith("<")) continue;
      if (!isFallthrough(edge.label)) continue;
      const b = byId.get(edge.target);
      if (!b || b === p) continue;
      if (b.preds.length !== 1 || b.preds[0] !== p.id) continue;

      p.insts = p.insts.concat(b.insts);
      p.succs = b.succs;
      // Inherit the merged-in block's structural role — it now owns the
      // outgoing edges, so the renderer should show ITS kind (return,
      // conditional, etc.) not the original fallthrough's.
      p.kind  = b.entry ? p.kind : b.kind;
      for (const s of b.succs) {
        const t = byId.get(s.target);
        if (!t) continue;
        t.preds = t.preds.map((x) => (x === b.id ? p.id : x));
      }
      byId.delete(b.id);
      changed = true;
    }
  }
  return Array.from(byId.values());
}

// Block-kind palette. Picked to harmonize with the existing edge colors
// (taken=green, indirect=violet) and the global accent (orange-ish).
// Each entry: border colour, header tint, badge label.
const KIND_STYLE: Record<CfgKind, { border: string; tint: string; badge: string }> = {
  entry:         { border: C.accent,  tint: "rgba(217,119, 87,0.16)", badge: "entry" },
  return:        { border: C.red,     tint: "rgba(220, 95, 95,0.14)", badge: "ret"   },
  conditional:   { border: C.green,   tint: "rgba(120,180,120,0.10)", badge: "cond"  },
  switch:        { border: C.violet,  tint: "rgba(160,120,200,0.12)", badge: "switch"},
  indirect:      { border: C.violet,  tint: "rgba(160,120,200,0.10)", badge: "?call" },
  tailcall:      { border: C.accent,  tint: "rgba(217,119, 87,0.10)", badge: "tail"  },
  unconditional: { border: C.border,  tint: "transparent",            badge: ""      },
  fallthrough:   { border: C.border,  tint: "transparent",            badge: ""      },
};

const NODE_W    = 340;
const HEADER_H  = 26;
const FOOTER_H  = 22;
const LINE_H    = 15;
const PAD       = 11;
const X_GAP     = 64;
const Y_GAP     = 44;
const MAX_LINES = 14;

type Position = { x: number; y: number; height: number };

type Layout = {
  positions: Map<string, Position>;
  ranks: Map<string, number>;
  bounds: { x: number; y: number; w: number; h: number };
};

function layoutCfg(blocks: CfgBlock[], entryId: string): Layout {
  const byId = new Map(blocks.map((b) => [b.id, b]));
  const positions = new Map<string, Position>();
  const ranks = new Map<string, number>();
  const emptyBounds = { x: 0, y: 0, w: 0, h: 0 };
  if (!byId.has(entryId)) return { positions, ranks, bounds: emptyBounds };

  const q: string[] = [entryId];
  ranks.set(entryId, 0);
  while (q.length) {
    const cur = q.shift()!;
    const b = byId.get(cur);
    if (!b) continue;
    for (const s of b.succs) {
      if (!byId.has(s.target)) continue;
      if (!ranks.has(s.target)) {
        ranks.set(s.target, (ranks.get(cur) ?? 0) + 1);
        q.push(s.target);
      }
    }
  }

  const byRank = new Map<number, string[]>();
  let maxRank = 0;
  ranks.forEach((r, id) => {
    if (r > maxRank) maxRank = r;
    if (!byRank.has(r)) byRank.set(r, []);
    byRank.get(r)!.push(id);
  });
  blocks.forEach((b) => {
    if (!ranks.has(b.id)) {
      const r = maxRank + 1;
      ranks.set(b.id, r);
      if (!byRank.has(r)) byRank.set(r, []);
      byRank.get(r)!.push(b.id);
      if (r > maxRank) maxRank = r;
    }
  });

  // Barycenter ordering
  const indexIn = new Map<string, number>();
  (byRank.get(0) ?? []).forEach((id, i) => indexIn.set(id, i));
  for (let r = 1; r <= maxRank; r++) {
    const ids = byRank.get(r) ?? [];
    ids.sort((a, b) => {
      const pa = byId.get(a)?.preds ?? [];
      const pb = byId.get(b)?.preds ?? [];
      const barA = pa.length
        ? pa.reduce((s, p) => s + (indexIn.get(p) ?? 0), 0) / pa.length : 0;
      const barB = pb.length
        ? pb.reduce((s, p) => s + (indexIn.get(p) ?? 0), 0) / pb.length : 0;
      return barA - barB;
    });
    ids.forEach((id, i) => indexIn.set(id, i));
  }

  // Footer is only drawn for blocks whose outgoing edges carry meaningful
  // labels we want to surface (taken/fall, switch cases, tail target).
  // Plain unconditional / fallthrough blocks have no labels worth space.
  const hasFooter = (b: CfgBlock): boolean =>
    b.kind === "conditional" || b.kind === "switch" ||
    b.kind === "tailcall"    || b.kind === "return"  ||
    b.kind === "indirect";

  const heightOf = (b: CfgBlock) =>
    HEADER_H + Math.min(b.insts.length, MAX_LINES) * LINE_H + PAD * 2 +
    (hasFooter(b) ? FOOTER_H : 0);

  let y = 0;
  let minX = Infinity, maxX = -Infinity, maxY = 0;
  for (let r = 0; r <= maxRank; r++) {
    const ids = byRank.get(r) ?? [];
    let rowH = 0;
    const totalW = (ids.length - 1) * (NODE_W + X_GAP);
    ids.forEach((id, i) => {
      const b = byId.get(id)!;
      const h = heightOf(b);
      const x = i * (NODE_W + X_GAP) - totalW / 2;
      positions.set(id, { x, y, height: h });
      if (h > rowH) rowH = h;
      if (x < minX) minX = x;
      if (x + NODE_W > maxX) maxX = x + NODE_W;
    });
    y += rowH + Y_GAP;
    if (y > maxY) maxY = y;
  }
  if (positions.size === 0) return { positions, ranks, bounds: emptyBounds };
  return {
    positions, ranks,
    bounds: { x: minX, y: 0, w: maxX - minX, h: maxY },
  };
}

// Level-of-detail tier. Driven by current zoom scale: below 0.35 text is
// unreadable anyway so we skip it (the expensive bit to rasterize).
type Lod = "full" | "compact" | "tiny";

function lodFor(scale: number): Lod {
  if (scale < 0.25) return "tiny";
  if (scale < 0.55) return "compact";
  return "full";
}

// Render the labels for outgoing edges as a compact summary inside the
// block footer. Reading this is what tells the user "this block branches
// taken to bb_X, falls through to bb_Y" without having to chase the
// arrow visually across the whole graph.
function footerSummary(b: CfgBlock): { color: string; text: string }[] {
  if (b.kind === "return") return [{ color: C.red, text: "→ return" }];
  if (b.kind === "indirect") return [{ color: C.violet, text: "→ indirect" }];
  if (b.kind === "tailcall") {
    const t = b.succs[0]?.target ?? "?";
    return [{ color: C.accent, text: `→ tail-call ${t}` }];
  }
  if (b.kind === "conditional") {
    const taken = b.succs.find((s) => s.label === "taken");
    const fall  = b.succs.find((s) => s.label === "fallthrough");
    const out: { color: string; text: string }[] = [];
    if (taken) out.push({ color: C.green,     text: `T → ${taken.target}` });
    if (fall)  out.push({ color: C.textFaint, text: `F → ${fall.target}` });
    return out;
  }
  if (b.kind === "switch") {
    const cases = b.succs.filter((s) => s.label.startsWith("case "));
    const def = b.succs.find((s) => s.label === "default");
    const summary = cases.length > 0
      ? `${cases.length} case${cases.length === 1 ? "" : "s"}`
      : "switch";
    const parts: { color: string; text: string }[] =
      [{ color: C.violet, text: summary }];
    if (def) parts.push({ color: C.textFaint, text: `default → ${def.target}` });
    return parts;
  }
  return [];
}

// Consolidated node renderer — a single <g> per block. At full LOD the
// body is HTML inside a <foreignObject> so we can reuse the existing
// syntax highlighter and clickable-symbol affordances from the source
// view. At lower LODs we degrade to plain SVG <text> for performance.
// Memoized: only re-renders if the backing block, position, or LOD
// changes (function-name map handed in via stable Map ref).
const Node = memo(function Node(props: {
  block: CfgBlock;
  pos: Position;
  lod: Lod;
  // emphasized = direct neighbour of the focused/hovered block (pred or succ)
  // focused    = the block the user clicked or is currently hovering
  // dimmed     = grayed out because the user has focused something else
  emphasis: "normal" | "emphasized" | "focused" | "dimmed";
  searchHit?: boolean;
  fnAddrByName?: Map<string, number>;
  onXref?: (addr: number) => void;
  onHover?: (id: string | null) => void;
  onClick?: (id: string) => void;
}) {
  const { block: b, pos: p, lod, emphasis, searchHit, fnAddrByName, onXref,
          onHover, onClick } = props;
  const shown = lod !== "tiny" ? b.insts.slice(0, MAX_LINES) : [];
  const extra = lod !== "tiny" ? b.insts.length - shown.length : 0;
  const showHeader = lod !== "tiny";
  const showBody   = lod === "full" || lod === "compact";
  const bodyHtml   = lod === "full";
  const style      = KIND_STYLE[b.kind];
  const showFooter = lod !== "tiny" && (
    b.kind === "conditional" || b.kind === "switch" ||
    b.kind === "tailcall"    || b.kind === "return"  ||
    b.kind === "indirect"
  );
  const bodyTop    = HEADER_H + PAD;
  const bodyH      = Math.min(shown.length, MAX_LINES) * LINE_H +
                     (extra > 0 ? LINE_H : 0);
  const footerTop  = p.height - FOOTER_H;
  const footer     = showFooter ? footerSummary(b) : [];

  const noop = () => {};
  // Emphasis-driven visuals. Dimmed blocks fade to ~30% opacity so the
  // focused subgraph stands out; focused/emphasized blocks get a
  // thicker border + accent halo.
  const opacity = emphasis === "dimmed" ? 0.28 : 1;
  const strokeW = b.entry ? 1.6 : 1;
  const finalStroke =
    emphasis === "focused"     ? C.accent  :
    emphasis === "emphasized"  ? style.border :
    style.border;
  const finalStrokeW =
    emphasis === "focused"     ? strokeW + 1.5 :
    emphasis === "emphasized"  ? strokeW + 0.6 :
    strokeW;
  const cardFill = searchHit ? "rgba(217,119,87,0.10)" : C.bgAlt;
  return (
    <g
      transform={`translate(${p.x}, ${p.y})`}
      opacity={opacity}
      style={{ cursor: onClick ? "pointer" : "default", transition: "opacity 0.12s" }}
      onMouseEnter={() => onHover?.(b.id)}
      onMouseLeave={() => onHover?.(null)}
      onClick={(e) => { e.stopPropagation(); onClick?.(b.id); }}
    >
      {/* Halo behind focused / emphasized blocks so they stand out
          even at low LOD when the body text is hidden. */}
      {emphasis !== "normal" && emphasis !== "dimmed" && (
        <rect
          x={-4}
          y={-4}
          width={NODE_W + 8}
          height={p.height + 8}
          rx={7}
          fill="none"
          stroke={emphasis === "focused" ? C.accent : style.border}
          strokeWidth={emphasis === "focused" ? 2 : 1}
          opacity={emphasis === "focused" ? 0.4 : 0.25}
        />
      )}
      {/* Outer card */}
      <rect
        width={NODE_W}
        height={p.height}
        rx={5}
        fill={cardFill}
        stroke={finalStroke}
        strokeWidth={finalStrokeW}
      />

      {/* Left accent strip — same colour as the border, makes the kind
          easy to spot in the corner of the eye while panning. */}
      <rect width={3} height={p.height} fill={style.border} rx={1.5} opacity={0.65} />

      {showHeader && (
        <>
          <rect width={NODE_W} height={HEADER_H} fill={style.tint} />
          <line x1={0} y1={HEADER_H} x2={NODE_W} y2={HEADER_H} stroke={C.border} opacity={0.6} />
          <text
            x={PAD}
            y={HEADER_H / 2 + 4}
            fontFamily={mono}
            fontSize={11}
            fontWeight={600}
            fill={b.entry ? C.accent : C.text}
          >
            {b.id}
          </text>
          {style.badge && (
            <text
              x={NODE_W - PAD}
              y={HEADER_H / 2 + 4}
              fontFamily={sans}
              fontSize={9}
              fontStyle="italic"
              fill={style.border}
              textAnchor="end"
            >
              {style.badge}
            </text>
          )}
        </>
      )}

      {showBody && shown.length > 0 && (
        bodyHtml
          ? (
            // foreignObject lets us embed the existing HTML-based syntax
            // highlighter and its click handlers — clicking `sub_xxx`
            // navigates the same way as in the pseudo-C view.
            <foreignObject
              x={PAD}
              y={bodyTop}
              width={NODE_W - PAD * 2}
              height={bodyH + PAD}
              className="cfg-body"
            >
              <div
                // xmlns required for some SVG renderers to parse the
                // foreignObject children as XHTML; React's HTML element
                // typing doesn't expose it, so spread to bypass.
                {...{ xmlns: "http://www.w3.org/1999/xhtml" } as Record<string, string>}
                style={{
                  fontFamily: mono,
                  fontSize: 10.5,
                  lineHeight: `${LINE_H}px`,
                  color: C.textWarm,
                  whiteSpace: "pre",
                  overflow: "hidden",
                }}
              >
                {shown.map((ins, i) => (
                  <div key={i} style={{ display: "flex", gap: 8 }}>
                    {/* Pseudo lines have no per-instruction VA, so the
                        gutter would just be empty space — hide it. */}
                    {ins.addr && (
                      <span style={{ color: C.textFaint, flexShrink: 0, opacity: 0.7 }}>
                        {ins.addr.padStart(5, " ")}
                      </span>
                    )}
                    <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis" }}>
                      {highlightLine(ins.text, onXref ?? noop, fnAddrByName)}
                    </span>
                  </div>
                ))}
                {extra > 0 && (
                  <div style={{
                    fontFamily: serif, fontSize: 9, fontStyle: "italic",
                    color: C.textFaint, textAlign: "right", marginTop: 1,
                  }}>+ {extra} more</div>
                )}
              </div>
            </foreignObject>
          )
          : (
            // Compact LOD: cheap SVG text, no syntax highlighting.
            <text
              x={PAD}
              y={bodyTop + 9}
              fontFamily={mono}
              fontSize={10}
              fill={C.textMuted}
              className="cfg-body"
            >
              {shown.map((ins, i) => (
                <tspan key={i} x={PAD} dy={i === 0 ? 0 : LINE_H}>
                  {truncate(ins.addr ? `${ins.addr}  ${ins.text}` : ins.text, 42)}
                </tspan>
              ))}
              {extra > 0 && (
                <tspan x={PAD} dy={LINE_H} fontStyle="italic" fill={C.textFaint}>
                  + {extra} more
                </tspan>
              )}
            </text>
          )
      )}

      {showFooter && footer.length > 0 && (
        <>
          <line
            x1={0} y1={footerTop} x2={NODE_W} y2={footerTop}
            stroke={C.border} opacity={0.5}
          />
          <text
            x={PAD}
            y={footerTop + FOOTER_H / 2 + 4}
            fontFamily={mono}
            fontSize={10}
          >
            {footer.map((f, i) => (
              <tspan
                key={i}
                fill={f.color}
                dx={i === 0 ? 0 : 12}
              >
                {f.text}
              </tspan>
            ))}
          </text>
        </>
      )}
    </g>
  );
});

type Rect = { x: number; y: number; w: number; h: number };
function rectsIntersect(a: Rect, b: Rect) {
  return a.x < b.x + b.w && a.x + a.w > b.x &&
         a.y < b.y + b.h && a.y + a.h > b.y;
}
function segmentInRect(x1: number, y1: number, x2: number, y2: number, r: Rect) {
  const minX = Math.min(x1, x2), maxX = Math.max(x1, x2);
  const minY = Math.min(y1, y2), maxY = Math.max(y1, y2);
  return rectsIntersect({ x: minX, y: minY, w: maxX - minX, h: maxY - minY }, r);
}

// Edges rendered as a single memoized group — only rebuilt if layout/data
// or the visible rect changes. Each edge gets a tiny midpoint label
// (T/F, case N, etc.) when the LOD is high enough to read it; without
// labels users have to chase colours through the legend.
const Edges = memo(function Edges(props: {
  blocks: CfgBlock[];
  layout: Layout;
  viewRect: Rect;
  showLabels: boolean;
  // When set, any edge incident on this block is rendered in full
  // colour at 1.6× width; every other edge fades. Drives the hover /
  // focus highlighting that lets the user trace control flow into and
  // out of one block at a glance.
  emphasizeBlock?: string | null;
}) {
  const { blocks, layout, viewRect, showLabels, emphasizeBlock } = props;
  const paths: React.ReactElement[] = [];
  const labels: React.ReactElement[] = [];
  for (const b of blocks) {
    const sp = layout.positions.get(b.id);
    if (!sp) continue;
    // Group successors by destination so back-to-back edges to the same
    // block (e.g. switch with multiple cases hitting one handler) don't
    // overlap-stack their midpoint labels.
    const seen = new Set<string>();
    for (let i = 0; i < b.succs.length; i++) {
      const s = b.succs[i];
      if (s.target.startsWith("<")) continue;
      const ep = layout.positions.get(s.target);
      if (!ep) continue;
      const x1 = sp.x + NODE_W / 2;
      const y1 = sp.y + sp.height;
      const x2 = ep.x + NODE_W / 2;
      const y2 = ep.y;
      if (!segmentInRect(x1, y1, x2, y2, viewRect)) continue;
      const isBack = (layout.ranks.get(s.target) ?? 0) <= (layout.ranks.get(b.id) ?? 0);
      const isFall = s.label === "" || s.label === "fallthrough";
      const color =
        isFall                  ? C.textFaint :
        s.label === "taken"     ? C.green     :
        s.target === "<indirect>" || s.label === "indirect" ? C.violet :
        s.label.startsWith("case ") || s.label === "default" ? C.violet :
        s.label === "tail-call" ? C.accent :
        C.textMuted;
      const marker =
        isFall                  ? "url(#arrow-fall)"     :
        s.label === "taken"     ? "url(#arrow-taken)"    :
        color === C.violet      ? "url(#arrow-indirect)" :
        color === C.accent      ? "url(#arrow-taken)"    :
        "url(#arrow-uncond)";
      const d = isBack
        ? backEdgePath(x1, y1, x2, y2)
        : forwardEdgePath(x1, y1, x2, y2);
      const incident = !!emphasizeBlock &&
        (emphasizeBlock === b.id || emphasizeBlock === s.target);
      const dimmed = !!emphasizeBlock && !incident;
      const baseOpacity = isFall ? 0.55 : 0.9;
      paths.push(
        <path
          key={b.id + "-" + i}
          d={d}
          stroke={color}
          strokeWidth={(isFall ? 1.1 : 1.4) * (incident ? 1.7 : 1)}
          strokeDasharray={isFall ? "4 3" : undefined}
          fill="none"
          markerEnd={marker}
          opacity={dimmed ? 0.18 : (incident ? 1 : baseOpacity)}
        />
      );

      // Inline midpoint label. Skip if we've already labelled an edge
      // to this destination from this block (avoids label pile-up in
      // switches), and skip the implicit blank label on unconditional
      // jumps where the edge colour alone is unambiguous.
      if (showLabels && s.label && !seen.has(s.target)) {
        seen.add(s.target);
        const short =
          s.label === "fallthrough" ? "F" :
          s.label === "taken"       ? "T" :
          s.label === "tail-call"   ? "tail" :
          s.label.startsWith("case ") ? s.label.slice(5) :
          s.label;
        // Midpoint along a forward edge sits at ~60% down the curve
        // visually; for back-edges we rest the label on the right rail.
        const lx = isBack ? Math.max(x1, x2) + NODE_W / 2 + 60
                          : (x1 + x2) / 2;
        const ly = isBack ? (y1 + y2) / 2
                          : y1 + (y2 - y1) * 0.55;
        labels.push(
          <g key={b.id + "-" + i + "-l"} transform={`translate(${lx}, ${ly})`}>
            <rect
              x={-(short.length * 3 + 4)}
              y={-7}
              width={short.length * 6 + 8}
              height={13}
              rx={2}
              fill={C.bg}
              stroke={color}
              strokeWidth={0.8}
              opacity={0.95}
            />
            <text
              x={0}
              y={3}
              fontFamily={mono}
              fontSize={9}
              fontWeight={600}
              fill={color}
              textAnchor="middle"
            >
              {short}
            </text>
          </g>
        );
      }
    }
  }
  return <g>{paths}{labels}</g>;
});

export function CfgGraph(props: {
  text: string;
  onXref?: (addr: number) => void;
  fnAddrByName?: Map<string, number>;
  // Sub-mode toggle: "pseudo" → bodies are Ember pseudo-C statements,
  // "asm" → raw disasm. Owned by the parent so the cached fetch result
  // sticks to the right backend route. Optional for back-compat with
  // older mounts that don't surface the toggle.
  mode?: "pseudo" | "asm";
  onModeChange?: (m: "pseudo" | "asm") => void;
}) {
  const parsed = useMemo(() => {
    const raw = parseCfg(props.text);
    return { blocks: mergeFallthroughs(raw.blocks), entry: raw.entry };
  }, [props.text]);
  const layout = useMemo(() => {
    if (!parsed.entry) return {
      positions: new Map(), ranks: new Map(),
      bounds: { x: 0, y: 0, w: 0, h: 0 },
    };
    return layoutCfg(parsed.blocks, parsed.entry);
  }, [parsed]);

  const svgRef = useRef<SVGSVGElement>(null);
  const gRef   = useRef<SVGGElement>(null);
  const viewportRef = useRef({ x: 0, y: 0, scale: 1 });
  const dragRef = useRef<{ mx: number; my: number; vx: number; vy: number } | null>(null);
  const svgSizeRef = useRef({ w: 0, h: 0 });

  // Display-only state so the zoom indicator updates; none of the node DOM depends on it.
  const [displayScale, setDisplayScale] = useState(1);
  const [isDragging, setIsDragging] = useState(false);
  // Visible world-rect in graph coords. Updated at the tail of each pan/zoom
  // gesture via rAF — used to cull offscreen nodes/edges.
  const [viewRect, setViewRect] = useState({ x: -1e9, y: -1e9, w: 3e9, h: 3e9 });

  // Hover / focus / search — drives node and edge emphasis. `focusedId`
  // is sticky (set on click); `hoverId` is transient (mouseenter). When
  // both are set, focus wins so the user's selection isn't drowned out
  // by mouse motion.
  const [hoverId, setHoverId]     = useState<string | null>(null);
  const [focusedId, setFocusedId] = useState<string | null>(null);
  const [searchQ, setSearchQ]     = useState("");
  const [showMinimap, setShowMinimap] = useState(true);

  const emphasizeId = focusedId ?? hoverId;

  // Pre-compute the predecessor/successor sets of the emphasis block so
  // the per-node emphasis decision is O(1) rather than O(edges).
  const neighbours = useMemo(() => {
    if (!emphasizeId) return null;
    const succs = new Set<string>();
    const preds = new Set<string>();
    for (const b of parsed.blocks) {
      if (b.id === emphasizeId) {
        for (const s of b.succs) {
          if (!s.target.startsWith("<")) succs.add(s.target);
        }
      }
      for (const s of b.succs) {
        if (s.target === emphasizeId) preds.add(b.id);
      }
    }
    return { preds, succs };
  }, [emphasizeId, parsed.blocks]);

  // Search → set of block ids whose body or id contains the query
  // string (case-insensitive). Empty query disables filtering.
  const searchHits = useMemo<Set<string> | null>(() => {
    const q = searchQ.trim().toLowerCase();
    if (!q) return null;
    const hits = new Set<string>();
    for (const b of parsed.blocks) {
      if (b.id.includes(q)) { hits.add(b.id); continue; }
      for (const ins of b.insts) {
        if (ins.text.toLowerCase().includes(q) ||
            (ins.addr && ins.addr.includes(q))) {
          hits.add(b.id);
          break;
        }
      }
    }
    return hits;
  }, [searchQ, parsed.blocks]);

  const lod = useMemo(() => lodFor(displayScale), [displayScale]);

  // Compute current viewport rect in graph coordinates from viewportRef + svg size.
  const computeViewRect = () => {
    const { w, h } = svgSizeRef.current;
    if (!w || !h) return null;
    const v = viewportRef.current;
    const pad = 200; // soft pad so partially-offscreen nodes aren't popped mid-pan
    return {
      x: (-v.x - pad) / v.scale,
      y: (-v.y - pad) / v.scale,
      w: (w + pad * 2) / v.scale,
      h: (h + pad * 2) / v.scale,
    };
  };

  const scheduledUpdate = useRef(false);
  const scheduleViewUpdate = () => {
    if (scheduledUpdate.current) return;
    scheduledUpdate.current = true;
    requestAnimationFrame(() => {
      scheduledUpdate.current = false;
      const r = computeViewRect();
      if (r) setViewRect(r);
    });
  };

  const applyTransform = () => {
    const g = gRef.current;
    if (!g) return;
    const v = viewportRef.current;
    g.setAttribute("transform",
      `translate(${v.x.toFixed(2)}, ${v.y.toFixed(2)}) scale(${v.scale.toFixed(4)})`);
  };

  // Fit the world rect into the SVG viewport. Used both on first mount
  // and as a "fit to screen" toolbar action.
  const fitToScreen = useCallback(() => {
    const svg = svgRef.current;
    if (!svg || !layout.bounds.w) return;
    const rect = svg.getBoundingClientRect();
    svgSizeRef.current = { w: rect.width, h: rect.height };
    const padX = 80, padY = 80;
    const sx = (rect.width  - padX) / Math.max(1, layout.bounds.w);
    const sy = (rect.height - padY) / Math.max(1, layout.bounds.h);
    const scale = Math.max(0.1, Math.min(1, Math.min(sx, sy)));
    const x = rect.width / 2 - (layout.bounds.x + layout.bounds.w / 2) * scale;
    const y = padY / 2 - layout.bounds.y * scale;
    viewportRef.current = { x, y, scale };
    applyTransform();
    setDisplayScale(scale);
    const r = computeViewRect();
    if (r) setViewRect(r);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [layout]);

  // Centre the camera on a specific block. Keeps the user's current
  // zoom level so jumping to a block during a deep-zoom inspection
  // doesn't yank them all the way out. Clamps to layout bounds so the
  // user can't end up looking at empty space if a tiny block sits at
  // the edge of a tall function.
  const zoomToBlock = useCallback((id: string, opts?: { scale?: number }) => {
    const svg = svgRef.current;
    const pos = layout.positions.get(id);
    if (!svg || !pos) return;
    const rect = svg.getBoundingClientRect();
    svgSizeRef.current = { w: rect.width, h: rect.height };
    const targetScale = opts?.scale ?? Math.max(0.45, viewportRef.current.scale);
    const cx = pos.x + NODE_W / 2;
    const cy = pos.y + pos.height / 2;
    viewportRef.current = {
      x: rect.width  / 2 - cx * targetScale,
      y: rect.height / 2 - cy * targetScale,
      scale: targetScale,
    };
    applyTransform();
    setDisplayScale(targetScale);
    const r = computeViewRect();
    if (r) setViewRect(r);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [layout]);

  // Fit to viewport on content change
  useLayoutEffect(() => {
    fitToScreen();
  }, [fitToScreen]);

  // Track SVG size for culling.
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    const obs = new ResizeObserver((entries) => {
      const b = entries[0]?.contentRect;
      if (!b) return;
      svgSizeRef.current = { w: b.width, h: b.height };
      scheduleViewUpdate();
    });
    obs.observe(svg);
    return () => obs.disconnect();
  }, []);

  // Display-scale throttle during zoom to avoid setState on every wheel tick.
  const displayScaleTimer = useRef<number | null>(null);
  const scheduleDisplayScale = (scale: number) => {
    if (displayScaleTimer.current != null) return;
    displayScaleTimer.current = window.setTimeout(() => {
      setDisplayScale(scale);
      displayScaleTimer.current = null;
    }, 60);
  };

  const onWheel: React.WheelEventHandler<SVGSVGElement> = (e) => {
    const rect = svgRef.current!.getBoundingClientRect();
    svgSizeRef.current = { w: rect.width, h: rect.height };
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    const delta = -e.deltaY * 0.0015;
    const v = viewportRef.current;
    const newScale = Math.max(0.1, Math.min(3, v.scale * (1 + delta)));
    const ratio = newScale / v.scale;
    v.x = mx - (mx - v.x) * ratio;
    v.y = my - (my - v.y) * ratio;
    v.scale = newScale;
    applyTransform();
    scheduleDisplayScale(newScale);
    scheduleViewUpdate();
  };

  const onMouseDown: React.MouseEventHandler<SVGSVGElement> = (e) => {
    // Reserve a small "drag intent" delta — if the user mousedowns and
    // releases without moving, treat as a click on the background and
    // clear the current focus. Distinguishes "click to deselect" from
    // an actual pan gesture so we don't drop the user's selection on
    // the first frame of every pan.
    dragRef.current = {
      mx: e.clientX, my: e.clientY,
      vx: viewportRef.current.x, vy: viewportRef.current.y,
    };
    setIsDragging(true);
  };

  // Apply a delta zoom centred on the SVG viewport — used by the
  // toolbar +/- buttons. Wheel zoom keeps its mouse-anchor logic.
  const zoomBy = useCallback((delta: number) => {
    const svg = svgRef.current;
    if (!svg) return;
    const rect = svg.getBoundingClientRect();
    const cx = rect.width / 2;
    const cy = rect.height / 2;
    const v = viewportRef.current;
    const newScale = Math.max(0.1, Math.min(3, v.scale * (1 + delta)));
    const ratio = newScale / v.scale;
    v.x = cx - (cx - v.x) * ratio;
    v.y = cy - (cy - v.y) * ratio;
    v.scale = newScale;
    applyTransform();
    setDisplayScale(newScale);
    scheduleViewUpdate();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const onMouseMove: React.MouseEventHandler<SVGSVGElement> = (e) => {
    const d = dragRef.current;
    if (!d) return;
    viewportRef.current.x = d.vx + (e.clientX - d.mx);
    viewportRef.current.y = d.vy + (e.clientY - d.my);
    applyTransform();
  };
  // Click-on-background to clear focus. We piggyback on `endDrag` —
  // if the mouse hasn't moved since mousedown, treat the gesture as
  // a click rather than a (zero-length) pan and drop the focus.
  const endDrag = (e?: React.MouseEvent) => {
    const d = dragRef.current;
    if (d && e && Math.abs(e.clientX - d.mx) < 3 && Math.abs(e.clientY - d.my) < 3) {
      // Treat as a background click only when the original target was
      // the SVG itself (not a node — nodes stop propagation).
      setFocusedId(null);
    }
    if (d) {
      dragRef.current = null;
      setIsDragging(false);
      scheduleViewUpdate();
    }
  };

  // Prevent native wheel bubble while over the graph (non-passive listener via ref)
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    const handler = (e: WheelEvent) => e.preventDefault();
    svg.addEventListener("wheel", handler, { passive: false });
    return () => svg.removeEventListener("wheel", handler);
  }, []);

  // Keyboard shortcuts when the graph has focus — Esc clears selection,
  // F fits, +/- zoom, E re-centres on the entry block. Gated on `info`
  // (parser produced something) so empty graphs ignore the bindings.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement | null)?.tagName ?? "";
      const inInput = tag === "INPUT" || tag === "TEXTAREA";
      if (inInput) {
        // Allow Esc inside the search box to clear it.
        if (e.key === "Escape" && (e.target as HTMLInputElement).dataset?.cfg === "search") {
          e.preventDefault();
          setSearchQ("");
          (e.target as HTMLInputElement).blur();
        }
        return;
      }
      if (e.key === "Escape") {
        if (focusedId) { e.preventDefault(); setFocusedId(null); }
        return;
      }
      if (!e.metaKey && !e.ctrlKey && !e.altKey && !e.shiftKey) {
        if (e.key === "f" || e.key === "F") { e.preventDefault(); fitToScreen(); return; }
        if (e.key === "e" || e.key === "E") {
          if (parsed.entry) { e.preventDefault(); zoomToBlock(parsed.entry); }
          return;
        }
        if (e.key === "+" || e.key === "=") { e.preventDefault(); zoomBy(0.18); return; }
        if (e.key === "-" || e.key === "_") { e.preventDefault(); zoomBy(-0.18); return; }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [focusedId, fitToScreen, zoomToBlock, zoomBy, parsed.entry]);

  if (!parsed.entry || parsed.blocks.length === 0) {
    return (
      <div style={{
        flex: 1, display: "flex", alignItems: "center", justifyContent: "center",
        background: C.bg, color: C.textFaint,
        fontFamily: serif, fontStyle: "italic", fontSize: 14,
      }}>no CFG data</div>
    );
  }

  return (
    <div
      style={{
        flex: 1, background: C.bg, overflow: "hidden",
        position: "relative",
      }}
    >
      <style>{`
        .cfg-dragging .cfg-body { display: none; }
      `}</style>
      <svg
        ref={svgRef}
        width="100%"
        height="100%"
        style={{ display: "block", cursor: isDragging ? "grabbing" : "grab" }}
        shapeRendering="optimizeSpeed"
        textRendering="optimizeSpeed"
        onWheel={onWheel}
        onMouseDown={onMouseDown}
        onMouseMove={onMouseMove}
        onMouseUp={(e) => endDrag(e)}
        onMouseLeave={() => endDrag()}
      >
        <defs>
          <marker id="arrow-taken" viewBox="0 0 10 10" refX="8" refY="5"
                  markerWidth="6" markerHeight="6" orient="auto">
            <path d="M0,0 L10,5 L0,10 z" fill={C.green}/>
          </marker>
          <marker id="arrow-fall" viewBox="0 0 10 10" refX="8" refY="5"
                  markerWidth="6" markerHeight="6" orient="auto">
            <path d="M0,0 L10,5 L0,10 z" fill={C.textFaint}/>
          </marker>
          <marker id="arrow-uncond" viewBox="0 0 10 10" refX="8" refY="5"
                  markerWidth="6" markerHeight="6" orient="auto">
            <path d="M0,0 L10,5 L0,10 z" fill={C.textMuted}/>
          </marker>
          <marker id="arrow-indirect" viewBox="0 0 10 10" refX="8" refY="5"
                  markerWidth="6" markerHeight="6" orient="auto">
            <path d="M0,0 L10,5 L0,10 z" fill={C.violet}/>
          </marker>
        </defs>

        <g
          ref={gRef}
          className={isDragging && (displayScale < 0.8 || parsed.blocks.length > 120)
            ? "cfg-dragging" : undefined}
        >
          <Edges
            blocks={parsed.blocks}
            layout={layout}
            viewRect={viewRect}
            showLabels={lod === "full"}
            emphasizeBlock={emphasizeId}
          />
          {parsed.blocks.map((b) => {
            const p = layout.positions.get(b.id);
            if (!p) return null;
            if (!rectsIntersect(
              { x: p.x, y: p.y, w: NODE_W, h: p.height }, viewRect)) return null;
            const isEmph = emphasizeId === b.id;
            const isNeighbour = !!neighbours &&
              (neighbours.preds.has(b.id) || neighbours.succs.has(b.id));
            const emphasis: "normal" | "emphasized" | "focused" | "dimmed" =
              isEmph        ? "focused"
              : isNeighbour ? "emphasized"
              : emphasizeId ? "dimmed"
              : "normal";
            const isHit = !!searchHits && searchHits.has(b.id);
            return (
              <Node
                key={b.id}
                block={b}
                pos={p}
                lod={lod}
                emphasis={emphasis}
                searchHit={isHit}
                fnAddrByName={props.fnAddrByName}
                onXref={props.onXref}
                onHover={setHoverId}
                onClick={(id) => {
                  setFocusedId((cur) => (cur === id ? null : id));
                  zoomToBlock(id);
                }}
              />
            );
          })}
        </g>
      </svg>

      {/* Top-left toolbar: pan/zoom controls, search, minimap toggle.
          The toolbar lives over the SVG (no layout shift) — pointerEvents
          on the inner buttons keeps drag-to-pan available everywhere
          else. */}
      <div style={{
        position: "absolute", top: 10, left: 12,
        display: "flex", gap: 6, alignItems: "center",
        fontFamily: mono, fontSize: 10,
      }}>
        <ToolbarGroup>
          <ToolbarButton title="Fit to screen (F)" aria-label="Fit graph to viewport"
                         onClick={fitToScreen}>fit</ToolbarButton>
          <ToolbarButton title="Zoom to entry (E)" aria-label="Recenter on entry block"
                         onClick={() => parsed.entry && zoomToBlock(parsed.entry)}>entry</ToolbarButton>
          {focusedId && (
            <ToolbarButton title="Recenter on focused block"
                           aria-label="Recenter on focused block"
                           onClick={() => zoomToBlock(focusedId)}>focus</ToolbarButton>
          )}
        </ToolbarGroup>
        <ToolbarGroup>
          <ToolbarButton title="Zoom out (-)" aria-label="Zoom out"
                         onClick={() => zoomBy(-0.18)}>−</ToolbarButton>
          <ToolbarButton title="Zoom in (+)" aria-label="Zoom in"
                         onClick={() => zoomBy(0.18)}>+</ToolbarButton>
        </ToolbarGroup>
        <div style={{
          display: "flex", alignItems: "center", gap: 6,
          padding: "3px 8px",
          background: C.bgAlt, border: `1px solid ${C.border}`, borderRadius: 4,
        }}>
          <span style={{ color: C.textFaint, fontSize: 10 }}>find</span>
          <input
            data-cfg="search"
            value={searchQ}
            onChange={(e) => setSearchQ(e.target.value)}
            placeholder="block / asm…"
            aria-label="Search blocks"
            style={{
              width: 140, fontFamily: mono, fontSize: 11, color: C.text,
            }}
          />
          {searchHits && (
            <span style={{ color: C.accent, fontSize: 10 }}>{searchHits.size}</span>
          )}
          {searchQ && (
            <button
              onClick={() => setSearchQ("")}
              aria-label="Clear search"
              style={{ color: C.textFaint, fontSize: 11 }}
            >×</button>
          )}
        </div>
        <ToolbarButton
          title={showMinimap ? "Hide minimap" : "Show minimap"}
          aria-label={showMinimap ? "Hide minimap" : "Show minimap"}
          onClick={() => setShowMinimap((v) => !v)}
        >{showMinimap ? "minimap•" : "minimap"}</ToolbarButton>
      </div>

      {focusedId && (
        <div style={{
          position: "absolute", top: 50, left: 12,
          padding: "5px 9px",
          background: C.bgAlt, border: `1px solid ${C.accent}`, borderRadius: 4,
          fontFamily: mono, fontSize: 10, color: C.accent,
          display: "flex", alignItems: "center", gap: 8,
        }}>
          <span>focused</span>
          <span style={{ color: C.text, fontWeight: 600 }}>{focusedId}</span>
          <button
            onClick={() => setFocusedId(null)}
            aria-label="Clear focus"
            title="Clear (Esc)"
            style={{ color: C.textFaint, fontSize: 11 }}
          >×</button>
        </div>
      )}

      {showMinimap && layout.bounds.w > 0 && (
        <Minimap
          blocks={parsed.blocks}
          layout={layout}
          viewRect={viewRect}
          emphasizeId={emphasizeId}
          searchHits={searchHits}
          onClickPoint={(wx, wy) => {
            // wx/wy are in graph-coordinate space — recenter the
            // viewport on them at the current zoom.
            const svg = svgRef.current;
            if (!svg) return;
            const rect = svg.getBoundingClientRect();
            const v = viewportRef.current;
            v.x = rect.width  / 2 - wx * v.scale;
            v.y = rect.height / 2 - wy * v.scale;
            applyTransform();
            scheduleViewUpdate();
          }}
        />
      )}

      <div style={{
        position: "absolute", bottom: 10, left: 12,
        display: "flex", gap: 12, padding: "6px 10px",
        background: C.bgAlt, border: `1px solid ${C.border}`, borderRadius: 4,
        fontFamily: mono, fontSize: 9, color: C.textMuted,
        pointerEvents: "none",
      }}>
        <LegendSwatch color={C.green}     label="taken" />
        <LegendSwatch color={C.textMuted} label="uncond" />
        <LegendSwatch color={C.violet}    label="indirect" />
        <LegendSwatch color={C.textFaint} label="fallthrough" dashed />
      </div>
      {/* Mode toggle + zoom indicator. Two pills sharing the bottom-right
          corner; toggling re-fetches via the parent's effect, which
          hits the renderer cache on second visit. */}
      <div style={{
        position: "absolute", bottom: 10, right: 12,
        display: "flex", gap: 6, alignItems: "center",
        fontFamily: mono, fontSize: 9,
      }}>
        {props.onModeChange && (
          <div
            style={{
              display: "flex",
              background: C.bgAlt,
              border: `1px solid ${C.border}`,
              borderRadius: 4,
              overflow: "hidden",
            }}
          >
            {(["pseudo", "asm"] as const).map((m) => {
              const active = (props.mode ?? "pseudo") === m;
              return (
                <button
                  key={m}
                  onClick={() => props.onModeChange?.(m)}
                  title={m === "pseudo"
                    ? "Render each block as Ember pseudo-C statements"
                    : "Render each block as raw x86 disassembly"}
                  style={{
                    padding: "5px 9px",
                    background: active ? C.bgMuted : "transparent",
                    color:      active ? C.text    : C.textMuted,
                    border:     "none",
                    borderRight: m === "pseudo" ? `1px solid ${C.border}` : "none",
                    fontFamily: mono,
                    fontSize:   9,
                    fontWeight: active ? 600 : 400,
                    cursor:     "pointer",
                  }}
                >{m}</button>
              );
            })}
          </div>
        )}
        <div style={{
          padding: "6px 10px",
          background: C.bgAlt, border: `1px solid ${C.border}`, borderRadius: 4,
          color: C.textFaint, pointerEvents: "none",
        }}>
          {parsed.blocks.length} blocks · cc {cyclomaticComplexity(parsed.blocks)} · {Math.round(displayScale * 100)}%
        </div>
      </div>
    </div>
  );
}

// Reusable toolbar pieces. Kept as inline components so the styling
// stays at the call site — the buttons are visually identical so a
// helper makes the JSX above stay readable.
function ToolbarGroup(props: { children: React.ReactNode }) {
  return (
    <div style={{
      display: "flex",
      background: C.bgAlt, border: `1px solid ${C.border}`, borderRadius: 4,
      overflow: "hidden",
    }}>
      {props.children}
    </div>
  );
}

function ToolbarButton(props: {
  onClick: () => void;
  children: React.ReactNode;
  title?: string;
  ["aria-label"]?: string;
}) {
  const [hover, setHover] = useState(false);
  return (
    <button
      onClick={props.onClick}
      title={props.title}
      aria-label={props["aria-label"]}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        padding: "5px 9px",
        background: hover ? C.bgMuted : "transparent",
        color: hover ? C.text : C.textMuted,
        border: "none",
        borderRight: `1px solid ${C.border}`,
        fontFamily: mono, fontSize: 10,
      }}
    >{props.children}</button>
  );
}

// Cyclomatic complexity for the merged-fallthrough graph.
//   M = E - N + 2P
// where E = edges (non-pseudo), N = nodes, P = connected components.
// We assume P=1 here — a function's CFG by construction is one
// connected component (the entry reaches everything; unreachable
// subgraphs have already been pruned by the analysis pipeline).
function cyclomaticComplexity(blocks: CfgBlock[]): number {
  const ids = new Set(blocks.map((b) => b.id));
  let edges = 0;
  for (const b of blocks) {
    for (const s of b.succs) {
      if (s.target.startsWith("<")) continue;
      if (!ids.has(s.target)) continue;
      edges++;
    }
  }
  const m = edges - blocks.length + 2;
  return Math.max(1, m);
}

// Compact overview panel that mirrors the full graph at micro-scale.
// Drag-anywhere centre the main viewport on the clicked spot. The
// `viewRect` rectangle inside the minimap shows what's currently on
// screen so the user knows where they are in a large function.
function Minimap(props: {
  blocks: CfgBlock[];
  layout: Layout;
  viewRect: Rect;
  emphasizeId?: string | null;
  searchHits?: Set<string> | null;
  onClickPoint: (wx: number, wy: number) => void;
}) {
  const { blocks, layout, viewRect, emphasizeId, searchHits, onClickPoint } = props;
  const PAD_PX  = 6;
  const MAX_W   = 200;
  const MAX_H   = 160;
  const bb      = layout.bounds;
  const scale   = Math.min(
    (MAX_W - PAD_PX * 2) / Math.max(1, bb.w),
    (MAX_H - PAD_PX * 2) / Math.max(1, bb.h),
  );
  const widthPx  = Math.min(MAX_W, bb.w * scale + PAD_PX * 2);
  const heightPx = Math.min(MAX_H, bb.h * scale + PAD_PX * 2);

  const toLocal = (e: React.MouseEvent<SVGSVGElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const lx = e.clientX - rect.left - PAD_PX;
    const ly = e.clientY - rect.top  - PAD_PX;
    return { wx: lx / scale + bb.x, wy: ly / scale + bb.y };
  };

  return (
    <div style={{
      position: "absolute", top: 10, right: 12,
      width: widthPx, height: heightPx,
      background: C.bgAlt, border: `1px solid ${C.border}`, borderRadius: 4,
      boxShadow: "0 4px 14px rgba(0,0,0,0.25)",
      cursor: "crosshair",
      overflow: "hidden",
    }}>
      <svg
        width="100%" height="100%"
        onMouseDown={(e) => {
          const { wx, wy } = toLocal(e);
          onClickPoint(wx, wy);
        }}
        onMouseMove={(e) => {
          if (e.buttons & 1) {
            const { wx, wy } = toLocal(e);
            onClickPoint(wx, wy);
          }
        }}
      >
        {/* Block dots — colour-coded by kind, scaled to layout height
            so a long block reads as a tall sliver. */}
        {blocks.map((b) => {
          const p = layout.positions.get(b.id);
          if (!p) return null;
          const x = (p.x - bb.x) * scale + PAD_PX;
          const y = (p.y - bb.y) * scale + PAD_PX;
          const w = NODE_W * scale;
          const h = p.height * scale;
          const isHit = searchHits?.has(b.id);
          const isEmph = emphasizeId === b.id;
          const fill = isHit ? C.accent
                       : isEmph ? C.accent
                       : KIND_STYLE[b.kind].border;
          return (
            <rect
              key={b.id}
              x={x} y={y}
              width={Math.max(2, w)} height={Math.max(2, h)}
              fill={fill}
              opacity={isEmph ? 1 : (isHit ? 0.85 : 0.55)}
              rx={1}
            />
          );
        })}
        {/* Current viewport rect, clipped to the minimap bounds. */}
        <rect
          x={Math.max(PAD_PX, (viewRect.x - bb.x) * scale + PAD_PX)}
          y={Math.max(PAD_PX, (viewRect.y - bb.y) * scale + PAD_PX)}
          width={Math.min(widthPx - PAD_PX * 2, viewRect.w * scale)}
          height={Math.min(heightPx - PAD_PX * 2, viewRect.h * scale)}
          fill="none"
          stroke={C.text}
          strokeWidth={1.2}
          opacity={0.85}
          pointerEvents="none"
        />
      </svg>
    </div>
  );
}

function LegendSwatch(props: { color: string; label: string; dashed?: boolean }) {
  return (
    <span style={{ display: "flex", alignItems: "center", gap: 4 }}>
      <span
        style={{
          width: 10, height: 2,
          background: props.dashed
            ? `repeating-linear-gradient(90deg, ${props.color} 0 3px, transparent 3px 5px)`
            : props.color,
        }}
      />
      <span>{props.label}</span>
    </span>
  );
}

function truncate(s: string, max: number): string {
  return s.length <= max ? s : s.slice(0, max - 1) + "…";
}

function forwardEdgePath(x1: number, y1: number, x2: number, y2: number): string {
  const dy = y2 - y1;
  const cp = Math.max(20, dy * 0.4);
  return `M${x1},${y1} C${x1},${y1 + cp} ${x2},${y2 - cp} ${x2},${y2}`;
}

function backEdgePath(x1: number, y1: number, x2: number, y2: number): string {
  const sideX = Math.max(x1, x2) + NODE_W / 2 + 60;
  return `M${x1},${y1} L${x1},${y1 + 30} L${sideX},${y1 + 30} L${sideX},${y2 - 30} L${x2},${y2 - 30} L${x2},${y2}`;
}
