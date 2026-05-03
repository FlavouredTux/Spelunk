import { useDeferredValue, useEffect, useMemo, useRef, useState } from "react";
import { C, sans, serif, mono } from "../theme";
import { demangle, displayName, formatSize, loadFunction } from "../api";
import type { BinaryInfo, FunctionInfo, ViewKind, Annotations } from "../types";
import { ContextMenu, ToastPill, type MenuItem } from "./ContextMenu";
import { SkelSidebarRow } from "./Skeleton";

export function Sidebar(props: {
  info: BinaryInfo;
  currentAddr: number | null;
  annotations: Annotations;
  // True while the background --functions query is still running. The
  // sidebar can already render imports + the "defined" tab shell while
  // we wait, so a spinner in the count badge is enough.
  functionsLoading?: boolean;
  width?: number;
  onSelect: (fn: FunctionInfo) => void;
  onOpen: (fn: FunctionInfo, view: ViewKind) => void;
  onReopen: () => void;
  onRename: (fn: FunctionInfo) => void;
  onAddNote: (fn: FunctionInfo) => void;
  onEditSignature: (fn: FunctionInfo) => void;
  onExport?: () => void;
  onImport?: () => void;
  onImportCorpus?: () => void;
}) {
  const { info, currentAddr, annotations, functionsLoading, width, onSelect, onOpen, onReopen,
          onRename, onAddNote, onEditSignature, onExport, onImport, onImportCorpus } = props;
  const [q, setQ] = useState("");
  const deferredQ = useDeferredValue(q);
  const [showImports, setShowImports] = useState(false);
  const [sortBy, setSortBy] = useState<"addr" | "size">("addr");
  const [ctx, setCtx] = useState<{ x: number; y: number; fn: FunctionInfo } | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  const copy = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setToast(label);
    } catch {
      setToast("copy failed");
    }
  };

  const list = useMemo(() => {
    const pool = showImports ? info.imports : info.functions;
    const needle = deferredQ.trim().toLowerCase();
    const filtered = !needle ? pool : pool.filter((f) => {
      const rn = annotations.renames[f.addr];
      return (
        f.name.toLowerCase().includes(needle) ||
        demangle(f.name).toLowerCase().includes(needle) ||
        f.addr.includes(needle) ||
        (rn && rn.toLowerCase().includes(needle))
      );
    });
    // Imports don't have real addresses or sizes, so the sort is a no-op
    // there — keep pool order (matches dynsym insertion order).
    if (showImports || sortBy === "addr") return filtered;
    // Clone before sort — pool is a memoised prop, mutating it would
    // invalidate the parent's reference and break referential equality
    // checks in VirtualList. Sort biggest first: the large functions are
    // almost always the ones worth opening.
    return [...filtered].sort((a, b) => b.size - a.size);
  }, [deferredQ, info, showImports, sortBy, annotations]);

  const buildMenu = (fn: FunctionInfo): MenuItem[] => {
    const hasRename = !!annotations.renames[fn.addr];
    const hasNote   = !!annotations.notes[fn.addr];
    return [
      { kind: "header", label: displayName(fn, annotations), meta: `${fn.addr}  ·  ${formatSize(fn.size)}` },
      { kind: "item", label: "Open as pseudo-C",  hint: "p", onClick: () => { onOpen(fn, "pseudo"); } },
      { kind: "item", label: "Open as assembly",  hint: "d", onClick: () => { onOpen(fn, "asm"); } },
      { kind: "item", label: "Open as CFG",       hint: "c", onClick: () => { onOpen(fn, "cfg"); } },
      { kind: "item", label: "Open as IR",        hint: "i", onClick: () => { onOpen(fn, "ir"); } },
      { kind: "item", label: "Open as SSA",       hint: "s", onClick: () => { onOpen(fn, "ssa"); } },
      { kind: "sep" },
      { kind: "item", label: hasRename ? "Rename…" : "Rename…",
        onClick: () => onRename(fn) },
      { kind: "item",
        label: annotations.signatures[fn.addr] ? "Edit signature…" : "Define signature…",
        onClick: () => onEditSignature(fn) },
      { kind: "item", label: hasNote ? "Edit note…" : "Add note…",
        onClick: () => onAddNote(fn) },
      { kind: "sep" },
      { kind: "item", label: "Copy address",      onClick: () => copy(fn.addr, "address copied") },
      { kind: "item", label: "Copy name",         onClick: () => copy(fn.name, "name copied") },
      { kind: "item", label: "Copy demangled",    onClick: () => copy(demangle(fn.name), "demangled copied") },
      { kind: "sep" },
      {
        kind: "item",
        label: "Copy pseudo-C",
        onClick: async () => {
          try {
            const code = await loadFunction(fn.name, "pseudo");
            await navigator.clipboard.writeText(code);
            setToast(`${code.split("\n").length} lines copied`);
          } catch { setToast("copy failed"); }
        },
      },
      {
        kind: "item",
        label: "Copy assembly",
        onClick: async () => {
          try {
            const code = await loadFunction(fn.name, "asm");
            await navigator.clipboard.writeText(code);
            setToast("assembly copied");
          } catch { setToast("copy failed"); }
        },
      },
    ];
  };

  return (
    <div
      style={{
        width: width ?? 288,
        height: "100%",
        background: C.bgAlt,
        borderRight: `1px solid ${C.border}`,
        display: "flex",
        flexDirection: "column",
        flexShrink: 0,
      }}
    >
      {/* Header */}
      <div style={{ padding: "18px 18px 14px", borderBottom: `1px solid ${C.border}` }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
          <div
            style={{
              width: 26, height: 26, borderRadius: 4,
              background: C.text, color: C.bg,
              display: "flex", alignItems: "center", justifyContent: "center",
              fontFamily: sans, fontWeight: 700, fontSize: 12,
            }}
          >A</div>
          <div style={{ display: "flex", flexDirection: "column", lineHeight: 1 }}>
            <span style={{ fontFamily: sans, fontWeight: 600, fontSize: 14 }}>Ember</span>
            <span style={{ fontFamily: serif, fontStyle: "italic", fontSize: 10, color: C.textMuted, marginTop: 2 }}>
              reverse engineering
            </span>
          </div>
        </div>
        <button
          onClick={onReopen}
          className="sel"
          style={{
            width: "100%",
            textAlign: "left",
            padding: "8px 10px",
            background: C.bgMuted,
            border: `1px solid ${C.border}`,
            borderRadius: 4,
            fontFamily: mono,
            fontSize: 11,
            color: C.textWarm,
            display: "flex",
            alignItems: "center",
            gap: 8,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
          title={info.path}
        >
          <span style={{ color: C.textFaint }}>&rsaquo;</span>
          <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>
            {info.path.split("/").pop() || info.path}
          </span>
        </button>
        <div style={{ display: "flex", gap: 12, marginTop: 10, fontSize: 10, fontFamily: mono, color: C.textFaint }}>
          <span><span style={{ color: C.textMuted }}>fmt</span> {info.format}</span>
          <span><span style={{ color: C.textMuted }}>arch</span> {info.arch}</span>
          <span><span style={{ color: C.textMuted }}>endian</span> {info.endian || "?"}</span>
          <span><span style={{ color: C.textMuted }}>entry</span> {info.entry.replace(/^0x0+/, "0x")}</span>
        </div>
        {(onExport || onImport || onImportCorpus) && (
          <div style={{
            display: "flex", gap: 6, marginTop: 10,
            fontFamily: sans, fontSize: 10,
            flexWrap: "wrap",
          }}>
            {onImport && (
              <button
                onClick={onImport}
                title="Merge renames / notes / signatures / patches from a JSON file"
                style={{
                  flex: 1, padding: "4px 8px",
                  background: "transparent", border: `1px solid ${C.border}`,
                  borderRadius: 3, color: C.textMuted,
                }}
              >import renames</button>
            )}
            {onImportCorpus && (
              <button
                onClick={onImportCorpus}
                title="Run TEEF recognition against a corpus and merge high-confidence matches as renames"
                style={{
                  flex: 1, padding: "4px 8px",
                  background: "transparent", border: `1px solid ${C.border}`,
                  borderRadius: 3, color: C.textMuted,
                }}
              >import corpus</button>
            )}
            {onExport && (
              <button
                onClick={onExport}
                title="Save all current annotations to a JSON file"
                style={{
                  flex: 1, padding: "4px 8px",
                  background: "transparent", border: `1px solid ${C.border}`,
                  borderRadius: 3, color: C.textMuted,
                }}
              >export</button>
            )}
          </div>
        )}
      </div>

      {/* Search */}
      <div style={{ padding: "12px 14px 6px" }}>
        <div
          data-tutorial="sidebar-search"
          style={{
            display: "flex", alignItems: "center", gap: 8,
            padding: "8px 12px",
            background: C.bgMuted,
            border: `1px solid ${C.border}`,
            borderRadius: 4,
          }}
        >
          <span style={{ color: C.textFaint, fontSize: 12 }}>/</span>
          <input
            placeholder="search functions…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            style={{ flex: 1, fontFamily: sans, fontSize: 12, color: C.text }}
          />
          {q && (
            <button
              onClick={() => setQ("")}
              style={{ color: C.textFaint, fontSize: 11 }}
            >×</button>
          )}
        </div>
      </div>

      {/* Toggle: defined / imports */}
      <div style={{ padding: "6px 14px 4px", display: "flex", gap: 4 }}>
        {([
          { k: false, label: "defined", count: info.functions.length },
          { k: true,  label: "imports", count: info.imports.length },
        ] as const).map((t) => {
          const active = showImports === t.k;
          return (
            <button
              key={t.label}
              onClick={() => setShowImports(t.k)}
              style={{
                flex: 1,
                padding: "6px 10px",
                background: active ? C.bgMuted : "transparent",
                border: `1px solid ${active ? C.border : "transparent"}`,
                borderRadius: 4,
                fontFamily: sans,
                fontSize: 11,
                fontWeight: active ? 600 : 400,
                color: active ? C.text : C.textMuted,
                display: "flex", justifyContent: "space-between", alignItems: "center",
              }}
            >
              <span>{t.label}</span>
              <span style={{ fontFamily: mono, fontSize: 10, color: C.textFaint }}>
                {functionsLoading && t.k === false ? "…" : t.count}
              </span>
            </button>
          );
        })}
      </div>

      {/* Sort toggle — disabled when viewing imports (they have no real size). */}
      {!showImports && (
        <div style={{
          padding: "2px 14px 6px",
          display: "flex", justifyContent: "flex-end", gap: 6,
          fontFamily: sans, fontSize: 10,
        }}>
          <span style={{ color: C.textFaint, alignSelf: "center" }}>sort</span>
          {([
            { k: "addr", label: "addr" },
            { k: "size", label: "size" },
          ] as const).map((s) => {
            const active = sortBy === s.k;
            return (
              <button
                key={s.k}
                onClick={() => setSortBy(s.k)}
                style={{
                  padding: "2px 8px",
                  background: active ? C.bgMuted : "transparent",
                  border: `1px solid ${active ? C.border : "transparent"}`,
                  borderRadius: 3,
                  color: active ? C.text : C.textMuted,
                  fontWeight: active ? 600 : 400,
                }}
              >{s.label}</button>
            );
          })}
        </div>
      )}

      {functionsLoading && !showImports && info.functions.length === 0 ? (
        <div style={{ padding: "4px 8px 12px", flex: 1 }}>
          {Array.from({ length: 14 }, (_, i) => <SkelSidebarRow key={i} seed={i} />)}
        </div>
      ) : (
      /* Virtualized; 50k-symbol binaries would otherwise OOM the renderer. */
      <VirtualList
        list={list}
        showImports={showImports}
        currentAddr={currentAddr}
        annotations={annotations}
        activeCtxAddr={ctx?.fn.addrNum ?? null}
        onSelect={onSelect}
        onContext={(fn, e) => {
          if (showImports) return;
          e.preventDefault();
          setCtx({ x: e.clientX, y: e.clientY, fn });
        }}
      />
      )}

      {ctx && (
        <ContextMenu
          x={ctx.x}
          y={ctx.y}
          items={buildMenu(ctx.fn)}
          onClose={() => setCtx(null)}
        />
      )}
      {toast && <ToastPill message={toast} onDone={() => setToast(null)} />}
    </div>
  );
}

const ROW_H = 36;
const OVERSCAN = 8;

function VirtualList(props: {
  list: FunctionInfo[];
  showImports: boolean;
  currentAddr: number | null;
  annotations: Annotations;
  activeCtxAddr: number | null;
  onSelect: (fn: FunctionInfo) => void;
  onContext: (fn: FunctionInfo, e: React.MouseEvent) => void;
}) {
  const { list, showImports, currentAddr, annotations, activeCtxAddr,
          onSelect, onContext } = props;

  const scRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewH, setViewH] = useState(600);

  useEffect(() => {
    const el = scRef.current;
    if (!el) return;
    const onScroll = () => setScrollTop(el.scrollTop);
    el.addEventListener("scroll", onScroll, { passive: true });
    const ro = new ResizeObserver(() => setViewH(el.clientHeight));
    ro.observe(el);
    setViewH(el.clientHeight);
    return () => { el.removeEventListener("scroll", onScroll); ro.disconnect(); };
  }, []);

  const total = list.length;
  const first = Math.max(0, Math.floor(scrollTop / ROW_H) - OVERSCAN);
  const last  = Math.min(total, Math.ceil((scrollTop + viewH) / ROW_H) + OVERSCAN);
  const padTop = first * ROW_H;
  const padBot = Math.max(0, (total - last) * ROW_H);

  return (
    <div
      ref={scRef}
      style={{ flex: 1, overflowY: "auto", padding: "4px 8px 12px" }}
    >
      {total === 0 && (
        <div style={{
          padding: 24, textAlign: "center",
          fontFamily: serif, fontStyle: "italic",
          fontSize: 12, color: C.textFaint,
        }}>no matches</div>
      )}
      {total > 0 && (
        <>
          <div style={{ height: padTop }} />
          {list.slice(first, last).map((f, idx) => {
            const i = first + idx;
            const active  = !showImports && currentAddr === f.addrNum;
            const renamed = !showImports && !!annotations.renames[f.addr];
            const noted   = !showImports && !!annotations.notes[f.addr];
            const displayLabel = showImports ? demangle(f.name) : displayName(f, annotations);
            return (
              <button
                key={f.addr + "-" + i}
                onClick={() => !showImports && onSelect(f)}
                onContextMenu={(e) => onContext(f, e)}
                disabled={showImports}
                style={{
                  width: "100%",
                  height: ROW_H - 1,
                  textAlign: "left",
                  padding: "8px 10px",
                  borderRadius: 4,
                  background: active ? C.bgDark
                            : (activeCtxAddr === f.addrNum ? C.bgMuted : "transparent"),
                  border: `1px solid ${active ? C.borderStrong : "transparent"}`,
                  color: active ? C.text : C.textWarm,
                  marginBottom: 1,
                  display: "flex",
                  alignItems: "center",
                  gap: 10,
                  cursor: showImports ? "default" : "pointer",
                }}
                onMouseEnter={(e) => {
                  if (!active && !showImports) (e.currentTarget as HTMLElement).style.background = C.bgMuted;
                }}
                onMouseLeave={(e) => {
                  if (!active && activeCtxAddr !== f.addrNum)
                    (e.currentTarget as HTMLElement).style.background = "transparent";
                }}
              >
                <span style={{
                  fontFamily: mono, fontSize: 10,
                  color: active ? C.text : C.textFaint,
                  width: 72, flexShrink: 0,
                  overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                  fontWeight: active ? 600 : 400,
                }} title={f.addr}>{f.addr.replace(/^0x0+(?=.)/, "0x")}</span>
                <span
                  style={{
                    flex: 1, overflow: "hidden", textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    fontFamily: sans, fontSize: 12, fontWeight: active ? 600 : (renamed ? 500 : 400),
                    color: renamed ? C.text : undefined,
                  }}
                  title={f.name}
                >{displayLabel}</span>
                <div style={{ display: "flex", gap: 4, alignItems: "center", flexShrink: 0 }}>
                  {renamed && <span title="renamed" style={{ color: C.accent, fontSize: 9, fontFamily: mono }}>•</span>}
                  {noted && <span title="has note" style={{ color: C.blue, fontSize: 9, fontFamily: mono }}>✎</span>}
                  {!showImports && f.size > 0 && (
                    <span style={{ fontFamily: mono, fontSize: 9, color: C.textFaint }}>
                      {formatSize(f.size)}
                    </span>
                  )}
                </div>
              </button>
            );
          })}
          <div style={{ height: padBot }} />
        </>
      )}
    </div>
  );
}
