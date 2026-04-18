import { memo, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { C, sans, mono, serif } from "../theme";

type CfgBlock = {
  id: string;
  addr: number;
  entry: boolean;
  preds: string[];
  lines: string[];
  succs: { target: string; label: string }[];
};

function parseCfg(text: string): { blocks: CfgBlock[]; entry: string | null } {
  const rawLines = text.split("\n");
  const blocks: CfgBlock[] = [];
  let cur: CfgBlock | null = null;
  let entry: string | null = null;

  const header = /^(bb_[0-9a-f]+)\s*(\(entry\))?\s*(?:<-\s*([^:]+?))?\s*:\s*$/;
  const succ   = /^\s+->\s+(bb_[0-9a-f]+|<[^>]+>)(?:\s+\((.+?)\))?\s*$/;
  // "  0x0000000000401120  83 ff 05                        cmp edi, 0x5"
  //   ↓
  // addr=401120, bytes="83 ff 05", disasm="cmp edi, 0x5"
  const inst   = /^\s+0x([0-9a-f]+)\s+((?:[0-9a-f]{2}\s+)+)(.*\S)\s*$/;

  for (const raw of rawLines) {
    const l = raw.replace(/\r$/, "");
    const m = header.exec(l);
    if (m) {
      if (cur) blocks.push(cur);
      const id = m[1];
      const isEntry = !!m[2];
      const preds = (m[3] ?? "").trim().split(/\s+/).filter(Boolean);
      cur = {
        id,
        addr: parseInt(id.slice(3), 16),
        entry: isEntry,
        preds,
        lines: [],
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
      cur.lines.push(`${shortAddr}  ${m2[3]}`);
    }
  }
  if (cur) blocks.push(cur);
  return { blocks, entry };
}

const NODE_W   = 288;
const HEADER_H = 24;
const LINE_H   = 14;
const PAD      = 10;
const X_GAP    = 60;
const Y_GAP    = 40;
const MAX_LINES = 7;

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

  const heightOf = (b: CfgBlock) =>
    HEADER_H + Math.min(b.lines.length, MAX_LINES) * LINE_H + PAD * 2;

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

// Consolidated node renderer — a single <g> per block with minimal children.
// Memoized: only re-renders if the backing block, position, or LOD changes.
const Node = memo(function Node(props: {
  block: CfgBlock;
  pos: Position;
  lod: Lod;
}) {
  const { block: b, pos: p, lod } = props;
  const shownLines = lod === "full" ? b.lines.slice(0, MAX_LINES) : [];
  const extra = lod === "full" ? b.lines.length - shownLines.length : 0;
  const showHeader = lod !== "tiny";
  return (
    <g transform={`translate(${p.x}, ${p.y})`}>
      <rect
        width={NODE_W}
        height={p.height}
        rx={4}
        fill={C.bgAlt}
        stroke={b.entry ? C.accent : C.border}
        strokeWidth={b.entry ? 1.5 : 1}
      />
      {showHeader && (
        <>
          <rect
            width={NODE_W}
            height={HEADER_H}
            fill={b.entry ? "rgba(217,119,87,0.12)" : C.bgMuted}
          />
          <line x1={0} y1={HEADER_H} x2={NODE_W} y2={HEADER_H} stroke={C.border} />
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
          {b.entry && (
            <text
              x={NODE_W - PAD}
              y={HEADER_H / 2 + 4}
              fontFamily={sans}
              fontSize={9}
              fontStyle="italic"
              fill={C.accent}
              textAnchor="end"
            >entry</text>
          )}
        </>
      )}

      {shownLines.length > 0 && (
        <text
          x={PAD}
          y={HEADER_H + PAD + 9}
          fontFamily={mono}
          fontSize={10}
          fill={C.textWarm}
          className="cfg-body"
        >
          {shownLines.map((ln, i) => (
            <tspan key={i} x={PAD} dy={i === 0 ? 0 : LINE_H}>
              {truncate(ln, 36)}
            </tspan>
          ))}
        </text>
      )}
      {extra > 0 && (
        <text
          x={NODE_W - PAD}
          y={HEADER_H + PAD + shownLines.length * LINE_H + 9}
          fontFamily={serif}
          fontStyle="italic"
          fontSize={9}
          fill={C.textFaint}
          textAnchor="end"
          className="cfg-body"
        >+ {extra} more</text>
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
// or the visible rect changes.
const Edges = memo(function Edges(props: {
  blocks: CfgBlock[];
  layout: Layout;
  viewRect: Rect;
}) {
  const { blocks, layout, viewRect } = props;
  const paths: React.ReactElement[] = [];
  for (const b of blocks) {
    const sp = layout.positions.get(b.id);
    if (!sp) continue;
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
      const color =
        s.label === "taken"       ? C.green    :
        s.label === "fallthrough" ? C.accent   :
        s.label === "indirect"    ? C.violet   :
        C.textMuted;
      const marker =
        s.label === "taken"       ? "url(#arrow-taken)" :
        s.label === "fallthrough" ? "url(#arrow-fall)"  :
        s.label === "indirect"    ? "url(#arrow-indirect)" :
        "url(#arrow-uncond)";
      const d = isBack
        ? backEdgePath(x1, y1, x2, y2)
        : forwardEdgePath(x1, y1, x2, y2);
      paths.push(
        <path
          key={b.id + "-" + i}
          d={d}
          stroke={color}
          strokeWidth={1.4}
          fill="none"
          markerEnd={marker}
          opacity={0.85}
        />
      );
    }
  }
  return <g>{paths}</g>;
});

export function CfgGraph(props: { text: string; onXref?: (addr: number) => void }) {
  const parsed = useMemo(() => parseCfg(props.text), [props.text]);
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

  // Fit to viewport on content change
  useLayoutEffect(() => {
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
  }, [layout]);

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
    dragRef.current = {
      mx: e.clientX, my: e.clientY,
      vx: viewportRef.current.x, vy: viewportRef.current.y,
    };
    setIsDragging(true);
  };
  const onMouseMove: React.MouseEventHandler<SVGSVGElement> = (e) => {
    const d = dragRef.current;
    if (!d) return;
    viewportRef.current.x = d.vx + (e.clientX - d.mx);
    viewportRef.current.y = d.vy + (e.clientY - d.my);
    applyTransform();
  };
  const endDrag = () => {
    if (dragRef.current) {
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
        onMouseUp={endDrag}
        onMouseLeave={endDrag}
      >
        <defs>
          <marker id="arrow-taken" viewBox="0 0 10 10" refX="8" refY="5"
                  markerWidth="6" markerHeight="6" orient="auto">
            <path d="M0,0 L10,5 L0,10 z" fill={C.green}/>
          </marker>
          <marker id="arrow-fall" viewBox="0 0 10 10" refX="8" refY="5"
                  markerWidth="6" markerHeight="6" orient="auto">
            <path d="M0,0 L10,5 L0,10 z" fill={C.accent}/>
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
          <Edges blocks={parsed.blocks} layout={layout} viewRect={viewRect} />
          {parsed.blocks.map((b) => {
            const p = layout.positions.get(b.id);
            if (!p) return null;
            if (!rectsIntersect(
              { x: p.x, y: p.y, w: NODE_W, h: p.height }, viewRect)) return null;
            return <Node key={b.id} block={b} pos={p} lod={lod} />;
          })}
        </g>
      </svg>

      <div style={{
        position: "absolute", bottom: 10, left: 12,
        display: "flex", gap: 12, padding: "6px 10px",
        background: C.bgAlt, border: `1px solid ${C.border}`, borderRadius: 4,
        fontFamily: mono, fontSize: 9, color: C.textMuted,
        pointerEvents: "none",
      }}>
        <LegendSwatch color={C.green}     label="taken" />
        <LegendSwatch color={C.accent}    label="fallthrough" />
        <LegendSwatch color={C.textMuted} label="uncond" />
        <LegendSwatch color={C.violet}    label="indirect" />
      </div>
      <div style={{
        position: "absolute", bottom: 10, right: 12,
        padding: "6px 10px",
        background: C.bgAlt, border: `1px solid ${C.border}`, borderRadius: 4,
        fontFamily: mono, fontSize: 9, color: C.textFaint,
        pointerEvents: "none",
      }}>
        {parsed.blocks.length} blocks · {Math.round(displayScale * 100)}%
      </div>
    </div>
  );
}

function LegendSwatch(props: { color: string; label: string }) {
  return (
    <span style={{ display: "flex", alignItems: "center", gap: 4 }}>
      <span style={{ width: 10, height: 2, background: props.color }} />
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
