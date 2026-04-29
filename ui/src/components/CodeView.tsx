import { useMemo, useEffect, useRef, useState } from "react";
import { C, sans, mono, SH } from "../theme";
import { highlightLine } from "../syntax";
import { ContextMenu, type MenuItem } from "./ContextMenu";
import { demangle, displayName, formatSize } from "../api";
import type { FunctionInfo, Annotations } from "../types";

// Match an asm-view instruction line emitted by ember -d. Captures
// addr, the bytes column (space-separated hex pairs), and the
// disasm tail. Format example:
//   "0x0000000000401120  83 ff 05                        cmp edi, 0x5"
const ASM_INSN_RE = /^\s*(0x[0-9a-fA-F]+)\s+((?:[0-9a-fA-F]{2}\s+)+?)\s{2,}(.+)$/;

// Pseudo-C body lines indent in 2-space steps; the leading whitespace
// is what we measure to draw nesting guides.
const INDENT_UNIT = 2;

// `// foo` at column 0 is the function-name header ember emits at the
// top of a function block. Body comments use `;`, so this prefix is a
// clean signal that the next line is a function signature.
const FN_HEADER_RE = /^\/\/\s+\S/;
// Indent-0 line that ends with `)` or `) {` — heuristic for the
// function signature line that immediately follows the header. Used
// only for adding a subtle bottom-border, never for parsing semantics.
const FN_SIG_RE = /^[A-Za-z_][^\n]*\)\s*\{?\s*$/;

function leadingIndentDepth(line: string): number {
  let i = 0;
  while (i < line.length && line[i] === " ") i++;
  return Math.floor(i / INDENT_UNIT);
}

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
  // Right-click on a pseudo-C identifier → rename the local. `oldName`
  // is the token as shown to the user (may already be a user-chosen
  // rename); `newName` empty means reset. App handles chain-collapse
  // against the canonical original name on the storage side.
  onRenameLocal?: (oldName: string, newName: string) => void;
  // Right-click on an asm instruction → opens patch dialog. Caller
  // passes the parsed virtual address and the current bytes (already
  // reflecting any in-flight patches via the CLI temp-file routing).
  onPatchInsn?: (vaddr: number, origBytes: string, disasm: string) => void;
  // Pixel font size for the main code body. Driven from app settings
  // so the user can dial it up on a 4K display without DevTools.
  fontSize?: number;
}) {
  const lines = useMemo(() => props.text.split("\n"), [props.text]);

  const [fnCtx, setFnCtx] = useState<{ x: number; y: number; fn: FunctionInfo } | null>(null);
  const [localCtx, setLocalCtx] = useState<{ x: number; y: number; name: string } | null>(null);

  const handleLocalContext = useMemo(() => {
    if (!props.onRenameLocal) return undefined;
    return (name: string, ev: React.MouseEvent) => {
      ev.preventDefault();
      ev.stopPropagation();
      setLocalCtx({ x: ev.clientX, y: ev.clientY, name });
    };
  }, [props.onRenameLocal]);

  const handleFnContext = useMemo(() => {
    // Always available now that the menu's first item ("Go to function")
    // is unconditional. Without this, right-click on a call target
    // showed the browser's default menu when no rename/note callbacks
    // happened to be wired up.
    if (!props.fnByAddr) return undefined;
    return (addr: number, ev: React.MouseEvent) => {
      const fn = props.fnByAddr!.get(addr);
      if (!fn) return;
      ev.preventDefault();
      setFnCtx({ x: ev.clientX, y: ev.clientY, fn });
    };
  }, [props.fnByAddr]);

  const buildFnMenu = (fn: FunctionInfo): MenuItem[] => {
    const ann = props.annotations;
    const hasRename = !!ann?.renames[fn.addr];
    const hasNote   = !!ann?.notes[fn.addr];
    const hasSig    = !!ann?.signatures[fn.addr];
    const items: MenuItem[] = [
      { kind: "header",
        label: ann ? displayName(fn, ann) : demangle(fn.name),
        meta:  `${fn.addr}  ·  ${formatSize(fn.size)}` },
      { kind: "item", label: "Go to function", hint: "↵",
        onClick: () => props.onXref(fn.addrNum) },
    ];
    items.push({ kind: "sep" });
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
          fontSize: props.fontSize ?? 12.5,
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
            // Asm-line right-click → patch. We parse here so the
            // expensive regex only runs on the lines the user actually
            // interacts with (the onContextMenu handler captures `line`
            // by closure).
            const onLineContext = props.onPatchInsn
              ? (ev: React.MouseEvent) => {
                  const m = ASM_INSN_RE.exec(line);
                  if (!m) return;       // not an asm line — let default menu show
                  ev.preventDefault();
                  const vaddr = parseInt(m[1], 16);
                  if (!Number.isFinite(vaddr)) return;
                  props.onPatchInsn!(vaddr, m[2].trim(), m[3].trim());
                }
              : undefined;
            // Function-block decoration: top rule above each `// fn-name`
            // marker, slight emphasis on the matching signature line.
            // Detection is heuristic but stable for ember's emitter
            // output — body comments use `;`, so `// ` at col 0 is
            // unambiguous.
            const isFnHeader = FN_HEADER_RE.test(line);
            const prevLine = i > 0 ? lines[i - 1] : "";
            const isFnSig =
              !isFnHeader &&
              FN_HEADER_RE.test(prevLine) &&
              FN_SIG_RE.test(line);
            const lineBg = isActiveLine
              ? "rgba(217,119,87,0.06)"
              : "transparent";
            const lineBorderTop = isFnHeader && i > 0
              ? `1px solid ${C.border}`
              : undefined;
            return (
              <div
                key={i}
                data-line={i}
                onContextMenu={onLineContext}
                style={{
                  display: "flex",
                  padding: isFnHeader && i > 0 ? "10px 24px 0" : "0 24px",
                  marginTop: isFnHeader && i > 0 ? 8 : 0,
                  borderTop: lineBorderTop,
                  whiteSpace: "pre",
                  alignItems: "baseline",
                  background: lineBg,
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
                  fnByAddr={props.fnByAddr}
                  onFnContext={handleFnContext}
                  onLocalContext={handleLocalContext}
                  matches={lineMatches}
                  emphasized={isFnHeader || isFnSig}
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
      {localCtx && (
        <ContextMenu
          x={localCtx.x}
          y={localCtx.y}
          items={[
            { kind: "header", label: localCtx.name, meta: "local / arg" },
            { kind: "item", label: "Rename…", onClick: () => {
                const name = localCtx.name;
                setLocalCtx(null);
                // Deferred so the menu closes cleanly before the prompt
                // blocks the UI thread. Without this the menu stays drawn
                // under the prompt on Linux.
                setTimeout(() => {
                  const next = window.prompt(`Rename "${name}" to:`, name);
                  if (next && next !== name) props.onRenameLocal?.(name, next);
                }, 0);
              } },
            { kind: "item", label: "Reset to original", onClick: () => {
                const name = localCtx.name;
                setLocalCtx(null);
                props.onRenameLocal?.(name, "");
              } },
          ]}
          onClose={() => setLocalCtx(null)}
        />
      )}
    </div>
  );
}

// One indent-guide column: a 2-char-wide span carrying a 1px inset
// shadow on its left edge. `box-shadow: inset` sidesteps the
// box-sizing arithmetic that `border-left` would force on us, so the
// guide stays exactly INDENT_UNIT chars wide and aligns with the
// monospaced text that follows.
function IndentGuides({ depth }: { depth: number }) {
  if (depth <= 0) return null;
  const cells: JSX.Element[] = [];
  for (let k = 0; k < depth; k++) {
    cells.push(
      <span
        key={k}
        aria-hidden
        style={{
          display: "inline-block",
          width: `${INDENT_UNIT}ch`,
          boxShadow: `inset 1px 0 0 ${SH.indent}`,
        }}
      >{" ".repeat(INDENT_UNIT)}</span>
    );
  }
  return <>{cells}</>;
}

function LineContent(props: {
  line: string;
  onXref: (addr: number) => void;
  fnAddrByName?: Map<string, number>;
  fnByAddr?: Map<number, FunctionInfo>;
  onFnContext?: (addr: number, ev: React.MouseEvent) => void;
  onLocalContext?: (name: string, ev: React.MouseEvent) => void;
  matches: { line: number; start: number; end: number }[];
  isActiveMatch: (start: number) => boolean;
  // True for `// fn-name` and the matching signature line; bumps the
  // weight a notch so the eye lands on function boundaries.
  emphasized?: boolean;
}) {
  const { line, onXref, matches, fnAddrByName, fnByAddr,
          onFnContext, onLocalContext, emphasized } = props;
  if (line === "") return <span>&nbsp;</span>;

  // Indent guides span only the leading whitespace; the rest of the
  // line keeps its raw characters (no trailing whitespace gets eaten).
  const depth   = leadingIndentDepth(line);
  const prefix  = depth * INDENT_UNIT;
  const content = line.slice(prefix);
  const baseStyle: React.CSSProperties = {
    color: C.text,
    fontWeight: emphasized ? 500 : 400,
  };

  // If no matches, fall through to regular syntax highlighting.
  if (matches.length === 0) {
    return (
      <span style={baseStyle}>
        <IndentGuides depth={depth} />
        {highlightLine(content, onXref, fnAddrByName, onFnContext,
                       onLocalContext, fnByAddr)}
      </span>
    );
  }

  // Match offsets are computed against the full original line, so
  // shift them into `content`-relative coordinates. Matches that fall
  // entirely inside the indent prefix get dropped (rare; would be a
  // user searching for spaces) — the guide span has no text to land
  // a highlight on.
  const slices: { text: string; match: boolean; start: number }[] = [];
  let cursor = prefix;
  for (const m of matches) {
    if (m.end <= prefix) continue;
    const mStart = Math.max(m.start, prefix);
    if (mStart > cursor) {
      slices.push({ text: line.slice(cursor, mStart), match: false, start: cursor });
    }
    slices.push({ text: line.slice(mStart, m.end), match: true, start: m.start });
    cursor = m.end;
  }
  if (cursor < line.length) {
    slices.push({ text: line.slice(cursor), match: false, start: cursor });
  }

  return (
    <span style={baseStyle}>
      <IndentGuides depth={depth} />
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
        return <span key={k}>{highlightLine(s.text, onXref, fnAddrByName,
                                            onFnContext, onLocalContext, fnByAddr)}</span>;
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
