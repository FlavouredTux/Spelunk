import { useMemo, useEffect, useRef, useState } from "react";
import { C, sans, mono } from "../theme";
import { highlightLine } from "../syntax";
import { ContextMenu, type MenuItem } from "./ContextMenu";
import { demangle, displayName, formatSize } from "../api";
import type { FunctionInfo, Annotations } from "../types";

export function CodeView(props: {
  text: string;
  onXref: (addr: number) => void;
  search: string;
  searchActive: boolean;
  onSearchChange: (q: string) => void;
  onSearchClose: () => void;
  fnByAddr?: Map<number, FunctionInfo>;
  fnAddrByName?: Map<string, number>;
  annotations?: Annotations;
  onRename?: (fn: FunctionInfo) => void;
  onAddNote?: (fn: FunctionInfo) => void;
  onEditSignature?: (fn: FunctionInfo) => void;
}) {
  const lines = useMemo(() => props.text.split("\n"), [props.text]);

  const [fnCtx, setFnCtx] = useState<{ x: number; y: number; fn: FunctionInfo } | null>(null);

  const handleFnContext = useMemo(() => {
    if (!props.fnByAddr || !(props.onRename || props.onAddNote || props.onEditSignature)) {
      return undefined;
    }
    return (addr: number, ev: React.MouseEvent) => {
      const fn = props.fnByAddr!.get(addr);
      if (!fn) return;
      ev.preventDefault();
      setFnCtx({ x: ev.clientX, y: ev.clientY, fn });
    };
  }, [props.fnByAddr, props.onRename, props.onAddNote, props.onEditSignature]);

  const buildFnMenu = (fn: FunctionInfo): MenuItem[] => {
    const ann = props.annotations;
    const hasRename = !!ann?.renames[fn.addr];
    const hasNote   = !!ann?.notes[fn.addr];
    const hasSig    = !!ann?.signatures[fn.addr];
    const items: MenuItem[] = [
      { kind: "header",
        label: ann ? displayName(fn, ann) : demangle(fn.name),
        meta:  `${fn.addr}  ·  ${formatSize(fn.size)}` },
    ];
    if (props.onRename) items.push({
      kind: "item", label: hasRename ? "Rename…" : "Rename…",
      onClick: () => props.onRename!(fn),
    });
    if (props.onEditSignature) items.push({
      kind: "item", label: hasSig ? "Edit signature…" : "Define signature…",
      onClick: () => props.onEditSignature!(fn),
    });
    if (props.onAddNote) items.push({
      kind: "item", label: hasNote ? "Edit note…" : "Add note…",
      onClick: () => props.onAddNote!(fn),
    });
    return items;
  };

  // Compute match locations
  const matches = useMemo(() => {
    const q = props.search.trim();
    if (!props.searchActive || !q) return [] as { line: number; start: number; end: number }[];
    const lower = q.toLowerCase();
    const out: { line: number; start: number; end: number }[] = [];
    lines.forEach((line, li) => {
      const ll = line.toLowerCase();
      let idx = 0;
      while (true) {
        const f = ll.indexOf(lower, idx);
        if (f === -1) break;
        out.push({ line: li, start: f, end: f + q.length });
        idx = f + Math.max(1, q.length);
      }
    });
    return out;
  }, [lines, props.search, props.searchActive]);

  const [activeMatch, setActiveMatch] = useState(0);
  useEffect(() => setActiveMatch(0), [props.search]);

  const scrollerRef = useRef<HTMLDivElement>(null);

  // Scroll to active match
  useEffect(() => {
    if (!props.searchActive || matches.length === 0) return;
    const m = matches[activeMatch];
    if (!m) return;
    const el = scrollerRef.current?.querySelector(`[data-line="${m.line}"]`) as HTMLElement | null;
    if (el) el.scrollIntoView({ block: "center", behavior: "smooth" });
  }, [activeMatch, matches, props.searchActive]);

  // Search keyboard navigation
  useEffect(() => {
    if (!props.searchActive) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Enter") {
        e.preventDefault();
        if (matches.length === 0) return;
        if (e.shiftKey) {
          setActiveMatch((i) => (i - 1 + matches.length) % matches.length);
        } else {
          setActiveMatch((i) => (i + 1) % matches.length);
        }
      } else if (e.key === "F3") {
        e.preventDefault();
        if (matches.length) setActiveMatch((i) => (i + 1) % matches.length);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [matches, props.searchActive]);

  return (
    <div style={{
      flex: 1,
      display: "flex",
      flexDirection: "column",
      background: C.bg,
      position: "relative",
      minHeight: 0,   // allow this flex item to shrink below its min-content
    }}>
      {props.searchActive && (
        <SearchBar
          query={props.search}
          onChange={props.onSearchChange}
          onClose={props.onSearchClose}
          totalMatches={matches.length}
          activeIndex={matches.length ? activeMatch + 1 : 0}
          onPrev={() => matches.length && setActiveMatch((i) => (i - 1 + matches.length) % matches.length)}
          onNext={() => matches.length && setActiveMatch((i) => (i + 1) % matches.length)}
        />
      )}
      <div
        ref={scrollerRef}
        className="sel"
        style={{
          flex: 1,
          minHeight: 0,   // same — lets overflow: auto actually scroll instead of pushing past the clip
          overflow: "auto",
          fontFamily: mono,
          fontSize: 12.5,
          lineHeight: 1.65,
          padding: "16px 0",
        }}
      >
        <div style={{ display: "flex", flexDirection: "column", minWidth: "min-content" }}>
          {lines.map((line, i) => {
            const lineMatches = props.searchActive
              ? matches.filter((m) => m.line === i)
              : [];
            const isActiveLine = props.searchActive &&
              matches[activeMatch] && matches[activeMatch].line === i;
            return (
              <div
                key={i}
                data-line={i}
                style={{
                  display: "flex",
                  padding: "0 24px",
                  whiteSpace: "pre",
                  alignItems: "baseline",
                  background: isActiveLine ? "rgba(217,119,87,0.06)" : "transparent",
                }}
              >
                <span
                  style={{
                    width: 42,
                    color: isActiveLine ? C.accent : C.textFaint,
                    flexShrink: 0,
                    textAlign: "right",
                    paddingRight: 18,
                    userSelect: "none",
                    fontSize: 10.5,
                    opacity: .7,
                  }}
                >{i + 1}</span>
                <LineContent
                  line={line}
                  onXref={props.onXref}
                  fnAddrByName={props.fnAddrByName}
                  onFnContext={handleFnContext}
                  matches={lineMatches}
                  isActiveMatch={(start) =>
                    isActiveLine &&
                    matches[activeMatch] &&
                    matches[activeMatch].line === i &&
                    matches[activeMatch].start === start
                  }
                />
              </div>
            );
          })}
          <div style={{ height: 40 }} />
        </div>
      </div>
      {fnCtx && (
        <ContextMenu
          x={fnCtx.x}
          y={fnCtx.y}
          items={buildFnMenu(fnCtx.fn)}
          onClose={() => setFnCtx(null)}
        />
      )}
    </div>
  );
}

function LineContent(props: {
  line: string;
  onXref: (addr: number) => void;
  fnAddrByName?: Map<string, number>;
  onFnContext?: (addr: number, ev: React.MouseEvent) => void;
  matches: { line: number; start: number; end: number }[];
  isActiveMatch: (start: number) => boolean;
}) {
  const { line, onXref, matches, fnAddrByName, onFnContext } = props;
  if (line === "") return <span>&nbsp;</span>;

  // If no matches, fall through to regular syntax highlighting.
  if (matches.length === 0) {
    return <span style={{ color: C.text }}>{highlightLine(line, onXref, fnAddrByName, onFnContext)}</span>;
  }

  // Render the line as slices: before-match | match | between | match | after
  // We use the already-computed highlights for non-match regions so we don't
  // lose syntax coloring outside the highlight band.
  const slices: { text: string; match: boolean; start: number }[] = [];
  let cursor = 0;
  for (const m of matches) {
    if (m.start > cursor) slices.push({ text: line.slice(cursor, m.start), match: false, start: cursor });
    slices.push({ text: line.slice(m.start, m.end), match: true, start: m.start });
    cursor = m.end;
  }
  if (cursor < line.length) slices.push({ text: line.slice(cursor), match: false, start: cursor });

  return (
    <span style={{ color: C.text }}>
      {slices.map((s, k) => {
        if (s.match) {
          const isActive = props.isActiveMatch(s.start);
          return (
            <span
              key={k}
              style={{
                background: isActive ? C.accent : "rgba(217,119,87,0.3)",
                color: isActive ? "#fff" : C.text,
                borderRadius: 2,
                padding: "0 1px",
                fontWeight: isActive ? 600 : 400,
              }}
            >{s.text}</span>
          );
        }
        return <span key={k}>{highlightLine(s.text, onXref, fnAddrByName, onFnContext)}</span>;
      })}
    </span>
  );
}

function SearchBar(props: {
  query: string;
  onChange: (q: string) => void;
  onClose: () => void;
  totalMatches: number;
  activeIndex: number;
  onPrev: () => void;
  onNext: () => void;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  useEffect(() => inputRef.current?.focus(), []);
  return (
    <div
      style={{
        position: "absolute",
        top: 10, right: 22,
        zIndex: 50,
        display: "flex",
        alignItems: "center",
        gap: 8,
        padding: "6px 10px",
        background: C.bgAlt,
        border: `1px solid ${C.borderStrong}`,
        borderRadius: 6,
        boxShadow: "0 8px 24px rgba(0,0,0,0.4)",
      }}
    >
      <span style={{ fontFamily: mono, fontSize: 10, color: C.textFaint }}>find</span>
      <input
        ref={inputRef}
        value={props.query}
        onChange={(e) => props.onChange(e.target.value)}
        placeholder="search in code…"
        style={{
          width: 220, fontFamily: mono, fontSize: 12, color: C.text,
        }}
      />
      <span style={{ fontFamily: mono, fontSize: 10, color: C.textMuted, minWidth: 50, textAlign: "right" }}>
        {props.totalMatches > 0 ? `${props.activeIndex}/${props.totalMatches}` : "0/0"}
      </span>
      <button
        onClick={props.onPrev}
        title="Previous (Shift+Enter)"
        style={{
          width: 20, height: 20, color: C.textMuted,
          display: "flex", alignItems: "center", justifyContent: "center",
          borderRadius: 3,
        }}
      >↑</button>
      <button
        onClick={props.onNext}
        title="Next (Enter)"
        style={{
          width: 20, height: 20, color: C.textMuted,
          display: "flex", alignItems: "center", justifyContent: "center",
          borderRadius: 3,
        }}
      >↓</button>
      <button
        onClick={props.onClose}
        title="Close (Esc)"
        style={{
          width: 20, height: 20, color: C.textMuted,
          display: "flex", alignItems: "center", justifyContent: "center",
          borderRadius: 3,
        }}
      >×</button>
    </div>
  );
}
