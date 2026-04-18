import { memo, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { C, sans, mono, serif } from "../theme";
import { displayName } from "../api";
import type { BinaryInfo, FunctionInfo, Xrefs, Annotations } from "../types";

type Node = {
  addr: number;
  label: string;       // display name (user rename → demangled → mangled)
  fullName: string;
  size: number;
  inDeg: number;
  outDeg: number;
};

type Edge = { from: number; to: number };

type Graph = {
  nodes: Node[];
  edges: Edge[];
  byAddr: Map<number, Node>;
};

type Layout = {
  positions: Map<number, { x: number; y: number }>;
  ranks: Map<number, number>;
  bounds: { x: number; y: number; w: number; h: number };
};

const NODE_W = 184;
const NODE_H = 32;
const X_GAP  = 14;
const Y_GAP  = 24;

function buildGraph(
  info: BinaryInfo,
  xrefs: Xrefs,
  annotations: Annotations,
): Graph {
  const byAddr = new Map<number, Node>();
  for (const f of info.functions) {
    byAddr.set(f.addrNum, {
      addr: f.addrNum,
      label: displayName(f, annotations),
      fullName: f.name,
      size: f.size,
      inDeg: 0,
      outDeg: 0,
    });
  }
  const edges: Edge[] = [];
  for (const caller_k in xrefs.callees) {
    const caller = Number(caller_k);
    if (!byAddr.has(caller)) continue;
    for (const callee of xrefs.callees[caller]) {
      if (!byAddr.has(callee)) continue;
      edges.push({ from: caller, to: callee });
      byAddr.get(caller)!.outDeg++;
      byAddr.get(callee)!.inDeg++;
    }
  }
  // Keep only functions with at least one in/out edge — the rest would be noise.
  const nodes: Node[] = [];
  byAddr.forEach((n) => {
    if (n.inDeg > 0 || n.outDeg > 0) nodes.push(n);
  });
  const kept = new Set(nodes.map((n) => n.addr));
  const filteredEdges = edges.filter((e) => kept.has(e.from) && kept.has(e.to));
  const filteredByAddr = new Map<number, Node>();
  for (const n of nodes) filteredByAddr.set(n.addr, n);
  return { nodes, edges: filteredEdges, byAddr: filteredByAddr };
}

// k-hop neighborhood around `center`: walks both callers and callees
// outwards up to `hops` steps. Returns a subgraph with only those nodes
// and the edges between them.
function neighborhood(g: Graph, center: number, hops: number): Graph {
  if (!g.byAddr.has(center)) return g;
  const succ = new Map<number, number[]>();
  const pred = new Map<number, number[]>();
  for (const e of g.edges) {
    if (!succ.has(e.from)) succ.set(e.from, []);
    succ.get(e.from)!.push(e.to);
    if (!pred.has(e.to)) pred.set(e.to, []);
    pred.get(e.to)!.push(e.from);
  }
  const keep = new Set<number>([center]);
  let frontier = new Set<number>([center]);
  for (let h = 0; h < hops; h++) {
    const next = new Set<number>();
    frontier.forEach((a) => {
      for (const n of succ.get(a) ?? []) if (!keep.has(n)) next.add(n);
      for (const n of pred.get(a) ?? []) if (!keep.has(n)) next.add(n);
    });
    next.forEach((a) => keep.add(a));
    frontier = next;
    if (!frontier.size) break;
  }
  const nodes: Node[] = [];
  const byAddr = new Map<number, Node>();
  g.nodes.forEach((n) => {
    if (keep.has(n.addr)) { nodes.push(n); byAddr.set(n.addr, n); }
  });
  const edges = g.edges.filter((e) => keep.has(e.from) && keep.has(e.to));
  return { nodes, edges, byAddr };
}

function layoutGraph(g: Graph, entryAddr: number | null): Layout {
  const ranks = new Map<number, number>();
  const positions = new Map<number, { x: number; y: number }>();

  // Pick a BFS root: entry if available, else highest-in-degree
  let root = entryAddr != null && g.byAddr.has(entryAddr) ? entryAddr : 0;
  if (!g.byAddr.has(root)) {
    let maxIn = -1;
    for (const n of g.nodes) {
      if (n.inDeg > maxIn) { maxIn = n.inDeg; root = n.addr; }
    }
  }

  // BFS for ranks via callees
  const callees = new Map<number, number[]>();
  for (const e of g.edges) {
    if (!callees.has(e.from)) callees.set(e.from, []);
    callees.get(e.from)!.push(e.to);
  }
  const q: number[] = [];
  if (g.byAddr.has(root)) {
    q.push(root);
    ranks.set(root, 0);
  }
  while (q.length) {
    const cur = q.shift()!;
    const cs = callees.get(cur) || [];
    for (const c of cs) {
      if (!ranks.has(c)) {
        ranks.set(c, (ranks.get(cur) || 0) + 1);
        q.push(c);
      }
    }
  }

  // Unreachable nodes: BFS from any remaining root with out edges
  for (const n of g.nodes) {
    if (ranks.has(n.addr)) continue;
    // Start a new BFS tree for this node
    if (n.outDeg === 0 && n.inDeg > 0) continue;  // leaf-like, skip, will be placed later
    ranks.set(n.addr, 0);
    const q2: number[] = [n.addr];
    while (q2.length) {
      const cur = q2.shift()!;
      const cs = callees.get(cur) || [];
      for (const c of cs) {
        if (!ranks.has(c)) {
          ranks.set(c, (ranks.get(cur) || 0) + 1);
          q2.push(c);
        }
      }
    }
  }

  // Any remaining leaves (callees not reached via BFS because all roots fed them from "above"):
  for (const n of g.nodes) {
    if (!ranks.has(n.addr)) ranks.set(n.addr, 0);
  }

  // Group by rank
  let maxRank = 0;
  const byRank = new Map<number, number[]>();
  ranks.forEach((r, addr) => {
    if (r > maxRank) maxRank = r;
    if (!byRank.has(r)) byRank.set(r, []);
    byRank.get(r)!.push(addr);
  });

  // Barycenter ordering within each rank, relative to previous rank
  const indexIn = new Map<number, number>();
  const preds = new Map<number, number[]>();
  for (const e of g.edges) {
    if (!preds.has(e.to)) preds.set(e.to, []);
    preds.get(e.to)!.push(e.from);
  }
  (byRank.get(0) ?? []).forEach((a, i) => indexIn.set(a, i));
  for (let r = 1; r <= maxRank; r++) {
    const addrs = byRank.get(r) ?? [];
    addrs.sort((a, b) => {
      const pa = preds.get(a) ?? [];
      const pb = preds.get(b) ?? [];
      const barA = pa.length ? pa.reduce((s, p) => s + (indexIn.get(p) ?? 0), 0) / pa.length : 0;
      const barB = pb.length ? pb.reduce((s, p) => s + (indexIn.get(p) ?? 0), 0) / pb.length : 0;
      return barA - barB;
    });
    addrs.forEach((a, i) => indexIn.set(a, i));
  }

  // Place
  let minX = Infinity, maxX = -Infinity, minY = 0, maxY = 0;
  for (let r = 0; r <= maxRank; r++) {
    const addrs = byRank.get(r) ?? [];
    const totalW = (addrs.length - 1) * (NODE_W + X_GAP);
    const y = r * (NODE_H + Y_GAP);
    addrs.forEach((a, i) => {
      const x = i * (NODE_W + X_GAP) - totalW / 2;
      positions.set(a, { x, y });
      if (x < minX) minX = x;
      if (x + NODE_W > maxX) maxX = x + NODE_W;
    });
    if (y + NODE_H > maxY) maxY = y + NODE_H;
  }

  if (positions.size === 0) {
    return { positions, ranks, bounds: { x: 0, y: 0, w: 0, h: 0 } };
  }
  return {
    positions,
    ranks,
    bounds: { x: minX, y: minY, w: maxX - minX, h: maxY - minY },
  };
}

type Lod = "full" | "compact" | "tiny";
function lodFor(scale: number): Lod {
  if (scale < 0.3) return "tiny";
  if (scale < 0.6) return "compact";
  return "full";
}

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

const GraphNode = memo(function GraphNode(props: {
  node: Node;
  pos: { x: number; y: number };
  current: boolean;
  lod: Lod;
  onClick: () => void;
}) {
  const { node: n, pos: p, current, lod, onClick } = props;
  const [hover, setHover] = useState(false);
  return (
    <g
      transform={`translate(${p.x}, ${p.y})`}
      onClick={onClick}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{ cursor: "pointer" }}
    >
      <rect
        width={NODE_W}
        height={NODE_H}
        rx={4}
        fill={current ? "rgba(217,119,87,0.14)" : (hover ? C.bgDark : C.bgAlt)}
        stroke={current ? C.accent : (hover ? C.borderStrong : C.border)}
        strokeWidth={current ? 1.5 : 1}
      />
      {lod !== "tiny" && (
        <>
          <text
            x={10}
            y={NODE_H / 2 + 4}
            fontFamily={mono}
            fontSize={10}
            fill={current ? C.accent : C.textFaint}
            className="cg-text"
          >{hexAddr(n.addr)}</text>
          {lod === "full" && (
            <text
              x={80}
              y={NODE_H / 2 + 4}
              fontFamily={sans}
              fontSize={11}
              fontWeight={current ? 700 : 500}
              fill={current ? C.text : C.textWarm}
              className="cg-text"
            >{truncate(n.label, 18)}</text>
          )}
        </>
      )}
    </g>
  );
});

const Edges = memo(function Edges(props: {
  edges: Edge[];
  layout: Layout;
  viewRect: Rect;
}) {
  const paths: React.ReactElement[] = [];
  for (let i = 0; i < props.edges.length; i++) {
    const e = props.edges[i];
    const sp = props.layout.positions.get(e.from);
    const ep = props.layout.positions.get(e.to);
    if (!sp || !ep) continue;
    const x1 = sp.x + NODE_W / 2;
    const y1 = sp.y + NODE_H;
    const x2 = ep.x + NODE_W / 2;
    const y2 = ep.y;
    if (!segmentInRect(x1, y1, x2, y2, props.viewRect)) continue;
    const sameRank = (props.layout.ranks.get(e.from) ?? 0) === (props.layout.ranks.get(e.to) ?? 0);
    const upward   = (props.layout.ranks.get(e.to)   ?? 0) < (props.layout.ranks.get(e.from) ?? 0);
    const d = sameRank
      ? sideEdgePath(x1, y1, x2, y2)
      : upward
        ? backEdgePath(x1, y1, x2, y2)
        : forwardEdgePath(x1, y1, x2, y2);
    paths.push(
      <path
        key={e.from + "-" + e.to + "-" + i}
        d={d}
        stroke={C.border}
        strokeWidth={0.8}
        fill="none"
        markerEnd="url(#cg-arrow)"
        opacity={0.6}
      />
    );
  }
  return <g>{paths}</g>;
});

export function CallGraphView(props: {
  info: BinaryInfo;
  xrefs: Xrefs;
  annotations: Annotations;
  current: FunctionInfo | null;
  onSelect: (fn: FunctionInfo) => void;
  onClose: () => void;
}) {
  const { info, xrefs, annotations, current, onSelect, onClose } = props;

  const fullGraph = useMemo(
    () => buildGraph(info, xrefs, annotations),
    [info, xrefs, annotations],
  );

  const entryAddr = useMemo(() => {
    const main = info.functions.find((f) => f.name === "main");
    if (main) return main.addrNum;
    const entry = parseInt(info.entry, 16);
    if (!Number.isNaN(entry)) return entry;
    return info.functions[0]?.addrNum ?? null;
  }, [info]);

  // Default to neighborhood when we have a selected function and the full
  // graph would otherwise be unwieldy.
  const [mode, setMode] = useState<"neighborhood" | "all">(() =>
    current && fullGraph.nodes.length > 40 ? "neighborhood" : "all",
  );
  const [hops, setHops] = useState(1);

  const graph = useMemo(() => {
    if (mode === "all" || !current) return fullGraph;
    return neighborhood(fullGraph, current.addrNum, hops);
  }, [mode, fullGraph, current, hops]);

  const layout = useMemo(() => layoutGraph(graph, entryAddr), [graph, entryAddr]);

  const svgRef = useRef<SVGSVGElement>(null);
  const gRef   = useRef<SVGGElement>(null);
  const viewportRef = useRef({ x: 0, y: 0, scale: 1 });
  const dragRef = useRef<{ mx: number; my: number; vx: number; vy: number } | null>(null);
  const svgSizeRef = useRef({ w: 0, h: 0 });

  const [displayScale, setDisplayScale] = useState(1);
  const [isDragging, setIsDragging] = useState(false);
  const [q, setQ] = useState("");
  const [viewRect, setViewRect] = useState<Rect>({ x: -1e9, y: -1e9, w: 3e9, h: 3e9 });

  const lod = useMemo(() => lodFor(displayScale), [displayScale]);

  const computeViewRect = (): Rect | null => {
    const { w, h } = svgSizeRef.current;
    if (!w || !h) return null;
    const v = viewportRef.current;
    const pad = 200;
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

  // Fit to viewport on mount
  useLayoutEffect(() => {
    const svg = svgRef.current;
    if (!svg || !layout.bounds.w) return;
    const rect = svg.getBoundingClientRect();
    svgSizeRef.current = { w: rect.width, h: rect.height };
    const padX = 60, padY = 60;
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
    const newScale = Math.max(0.1, Math.min(4, v.scale * (1 + delta)));
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

  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    const handler = (e: WheelEvent) => e.preventDefault();
    svg.addEventListener("wheel", handler, { passive: false });
    return () => svg.removeEventListener("wheel", handler);
  }, []);

  // Esc to close
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.preventDefault(); onClose(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const centerOn = (addr: number) => {
    const svg = svgRef.current;
    const pos = layout.positions.get(addr);
    if (!svg || !pos) return;
    const rect = svg.getBoundingClientRect();
    const scale = Math.max(viewportRef.current.scale, 0.9);
    viewportRef.current = {
      scale,
      x: rect.width  / 2 - (pos.x + NODE_W / 2) * scale,
      y: rect.height / 2 - (pos.y + NODE_H / 2) * scale,
    };
    applyTransform();
    setDisplayScale(scale);
  };

  const searchResults = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return [];
    return graph.nodes.filter((n) =>
      n.label.toLowerCase().includes(needle) ||
      n.fullName.toLowerCase().includes(needle) ||
      hexAddr(n.addr).includes(needle),
    ).slice(0, 20);
  }, [q, graph]);

  return (
    <div
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(10,10,9,0.55)",
        backdropFilter: "blur(3px)",
        zIndex: 1800,
        display: "flex",
        justifyContent: "center",
        padding: "6vh 5vw",
        animation: "fadeIn .15s ease-out",
      }}
    >
      <div
        style={{
          flex: 1,
          display: "flex",
          flexDirection: "column",
          background: C.bg,
          border: `1px solid ${C.borderStrong}`,
          borderRadius: 8,
          boxShadow: "0 30px 80px rgba(0,0,0,0.6)",
          overflow: "hidden",
        }}
      >
        {/* Header */}
        <div style={{
          padding: "14px 20px",
          borderBottom: `1px solid ${C.border}`,
          display: "flex", alignItems: "center", gap: 18,
          background: C.bgAlt,
        }}>
          <div style={{ display: "flex", flexDirection: "column", lineHeight: 1.2 }}>
            <span style={{ fontFamily: sans, fontSize: 14, fontWeight: 600, color: C.text }}>
              Call Graph
            </span>
            <span style={{ fontFamily: serif, fontStyle: "italic", fontSize: 11, color: C.textMuted, marginTop: 2 }}>
              {graph.nodes.length} functions · {graph.edges.length} calls
              {mode === "neighborhood" && fullGraph.nodes.length > graph.nodes.length &&
                ` · ${fullGraph.nodes.length} total`}
            </span>
          </div>

          <div style={{
            display: "flex", alignItems: "center", gap: 4,
            padding: 2,
            background: C.bgMuted,
            border: `1px solid ${C.border}`,
            borderRadius: 4,
          }}>
            <ModeButton
              active={mode === "neighborhood"}
              disabled={!current}
              onClick={() => setMode("neighborhood")}
              title={current ? `±${hops} hops from ${displayName(current, annotations)}`
                             : "select a function first"}
            >neighborhood</ModeButton>
            <ModeButton
              active={mode === "all"}
              onClick={() => setMode("all")}
              title="show entire call graph"
            >all</ModeButton>
            {mode === "neighborhood" && current && (
              <div style={{ display: "flex", alignItems: "center", gap: 2, marginLeft: 4 }}>
                <HopButton onClick={() => setHops((h) => Math.max(1, h - 1))} label="−" />
                <span style={{
                  fontFamily: mono, fontSize: 10, color: C.textFaint,
                  minWidth: 22, textAlign: "center",
                }}>{hops} hop{hops === 1 ? "" : "s"}</span>
                <HopButton onClick={() => setHops((h) => Math.min(6, h + 1))} label="+" />
              </div>
            )}
          </div>

          <div style={{
            display: "flex", alignItems: "center", gap: 8,
            padding: "6px 10px",
            background: C.bgMuted,
            border: `1px solid ${C.border}`,
            borderRadius: 4,
            minWidth: 260,
            position: "relative",
          }}>
            <span style={{ color: C.textFaint, fontFamily: mono, fontSize: 11 }}>/</span>
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="search nodes…"
              style={{ flex: 1, fontFamily: sans, fontSize: 12, color: C.text }}
            />
            {q && (
              <button
                onClick={() => setQ("")}
                style={{ color: C.textFaint, fontSize: 11 }}
              >×</button>
            )}
            {searchResults.length > 0 && (
              <div style={{
                position: "absolute",
                top: "100%", left: 0, right: 0,
                marginTop: 4,
                maxHeight: 260, overflowY: "auto",
                background: C.bgAlt,
                border: `1px solid ${C.borderStrong}`,
                borderRadius: 4,
                boxShadow: "0 12px 30px rgba(0,0,0,0.4)",
                zIndex: 5,
              }}>
                {searchResults.map((n) => (
                  <button
                    key={n.addr}
                    onClick={() => { centerOn(n.addr); setQ(""); }}
                    style={{
                      width: "100%",
                      display: "flex",
                      alignItems: "center",
                      gap: 10,
                      padding: "6px 10px",
                      textAlign: "left",
                    }}
                    onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = C.bgMuted; }}
                    onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = "transparent"; }}
                  >
                    <span style={{ fontFamily: mono, fontSize: 10, color: C.textFaint }}>{hexAddr(n.addr)}</span>
                    <span style={{ fontFamily: sans, fontSize: 12, color: C.textWarm }}>{truncate(n.label, 32)}</span>
                  </button>
                ))}
              </div>
            )}
          </div>

          <div style={{ flex: 1 }} />
          <span style={{ fontFamily: mono, fontSize: 10, color: C.textFaint }}>
            drag to pan · wheel to zoom · esc closes
          </span>
          <button
            onClick={onClose}
            style={{
              width: 24, height: 24, borderRadius: 4,
              color: C.textMuted,
              background: "transparent",
              border: `1px solid ${C.border}`,
              fontSize: 14,
            }}
          >×</button>
        </div>

        {/* Canvas */}
        <div style={{ flex: 1, position: "relative", background: C.bg }}>
          <style>{`
            .cg-dragging .cg-text { display: none; }
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
              <marker id="cg-arrow" viewBox="0 0 10 10" refX="8" refY="5"
                      markerWidth="5" markerHeight="5" orient="auto">
                <path d="M0,0 L10,5 L0,10 z" fill={C.textMuted}/>
              </marker>
            </defs>
            <g
              ref={gRef}
              className={isDragging && (displayScale < 0.8 || graph.nodes.length > 120)
                ? "cg-dragging" : undefined}
            >
              <Edges edges={graph.edges} layout={layout} viewRect={viewRect} />
              {graph.nodes.map((n) => {
                const pos = layout.positions.get(n.addr);
                if (!pos) return null;
                if (!rectsIntersect(
                  { x: pos.x, y: pos.y, w: NODE_W, h: NODE_H }, viewRect)) return null;
                return (
                  <GraphNode
                    key={n.addr}
                    node={n}
                    pos={pos}
                    current={current?.addrNum === n.addr}
                    lod={lod}
                    onClick={() => {
                      const fn = info.functions.find((f) => f.addrNum === n.addr);
                      if (fn) { onSelect(fn); onClose(); }
                    }}
                  />
                );
              })}
            </g>
          </svg>

          {/* Zoom indicator */}
          <div style={{
            position: "absolute", bottom: 12, right: 16,
            padding: "6px 10px",
            background: C.bgAlt, border: `1px solid ${C.border}`, borderRadius: 4,
            fontFamily: mono, fontSize: 9, color: C.textFaint,
            pointerEvents: "none",
          }}>
            {Math.round(displayScale * 100)}%
          </div>
        </div>
      </div>
    </div>
  );
}

function ModeButton(props: {
  active: boolean;
  disabled?: boolean;
  onClick: () => void;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={props.disabled ? undefined : props.onClick}
      title={props.title}
      disabled={props.disabled}
      style={{
        padding: "3px 10px",
        fontFamily: sans,
        fontSize: 11,
        fontWeight: props.active ? 600 : 500,
        color: props.disabled ? C.textFaint
             : props.active   ? C.accent
                              : C.textWarm,
        background: props.active ? C.bgAlt : "transparent",
        border: "none",
        borderRadius: 3,
        cursor: props.disabled ? "not-allowed" : "pointer",
        opacity: props.disabled ? 0.5 : 1,
      }}
    >{props.children}</button>
  );
}

function HopButton(props: { onClick: () => void; label: string }) {
  return (
    <button
      onClick={props.onClick}
      style={{
        width: 18, height: 18,
        fontFamily: mono, fontSize: 11,
        color: C.textWarm,
        background: "transparent",
        border: `1px solid ${C.border}`,
        borderRadius: 3,
        cursor: "pointer",
      }}
    >{props.label}</button>
  );
}

function hexAddr(n: number): string {
  return "0x" + n.toString(16);
}
function truncate(s: string, max: number): string {
  return s.length <= max ? s : s.slice(0, max - 1) + "…";
}
function forwardEdgePath(x1: number, y1: number, x2: number, y2: number): string {
  const dy = y2 - y1;
  const cp = Math.max(12, dy * 0.4);
  return `M${x1},${y1} C${x1},${y1 + cp} ${x2},${y2 - cp} ${x2},${y2}`;
}
function backEdgePath(x1: number, y1: number, x2: number, y2: number): string {
  const sideX = Math.max(x1, x2) + NODE_W / 2 + 40;
  return `M${x1},${y1} L${x1},${y1 + 20} L${sideX},${y1 + 20} L${sideX},${y2 - 20} L${x2},${y2 - 20} L${x2},${y2}`;
}
function sideEdgePath(x1: number, y1: number, x2: number, y2: number): string {
  // Same-rank edge: route with a side bump
  const midY = (y1 + y2) / 2 + 28;
  return `M${x1},${y1} C${x1},${midY} ${x2},${midY} ${x2},${y2}`;
}
