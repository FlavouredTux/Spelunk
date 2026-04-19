import { useEffect, useState, useCallback, useMemo, useRef } from "react";
import { C, sans, serif, mono, globalCSS } from "./theme";
import { Sidebar } from "./components/Sidebar";
import { CodeView } from "./components/CodeView";
import { Welcome } from "./components/Welcome";
import { Tabs } from "./components/Tabs";
import { StatusBar } from "./components/StatusBar";
import { CommandPalette } from "./components/CommandPalette";
import { CfgGraph } from "./components/CfgGraph";
import { CallGraphView } from "./components/CallGraphView";
import { StringsView } from "./components/StringsView";
import { XrefsPanel } from "./components/XrefsPanel";
import { EditDialog } from "./components/EditDialog";
import {
  loadSummary, loadFunction, pickBinary, openRecent,
  loadXrefs, loadStrings, loadArities, loadAnnotations, saveAnnotations, getRecents,
  displayName, demangle,
} from "./api";
import type {
  BinaryInfo, FunctionInfo, ViewKind, Xrefs, Annotations, StringEntry, Arities,
  FunctionSig,
} from "./types";

const EMPTY_XREFS: Xrefs = { callers: {}, callees: {} };
const EMPTY_ANN:   Annotations = { renames: {}, notes: {}, signatures: {} };
const EMPTY_STRINGS: StringEntry[] = [];
const EMPTY_ARITIES: Arities = {};

export default function App() {
  const [info, setInfo] = useState<BinaryInfo | null>(null);
  const [current, setCurrent] = useState<FunctionInfo | null>(null);
  const [view, setView] = useState<ViewKind>("pseudo");
  const [code, setCode] = useState<string>("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Navigation history
  const [history, setHistory] = useState<number[]>([]);
  const [histIdx, setHistIdx] = useState(-1);
  const navigatingRef = useRef(false);

  // Overlays
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [xrefsOpen, setXrefsOpen] = useState(true);
  const [callGraphOpen, setCallGraphOpen] = useState(false);
  const [stringsOpen, setStringsOpen] = useState(false);

  // Data: cross-refs + user annotations + strings + arities
  const [xrefs, setXrefs] = useState<Xrefs>(EMPTY_XREFS);
  const [annotations, setAnnotations] = useState<Annotations>(EMPTY_ANN);
  const [strings, setStrings] = useState<StringEntry[]>(EMPTY_STRINGS);
  const [arities, setArities] = useState<Arities>(EMPTY_ARITIES);
  const [recents, setRecents] = useState<string[]>([]);

  // Strings are only consumed by StringsView and the payload can be hundreds
  // In-flight async analyses — shown in the status bar so huge binaries
  // don't look frozen while xrefs/arities/etc. churn in the background.
  const [pending, setPending] = useState<Set<string>>(new Set());
  const track = useCallback(<T,>(tag: string, p: Promise<T>): Promise<T> => {
    setPending((s) => { const n = new Set(s); n.add(tag); return n; });
    const done = () => setPending((s) => { const n = new Set(s); n.delete(tag); return n; });
    p.then(done, done);
    return p;
  }, []);

  // Strings are consumed only by StringsView and can be hundreds of MB.
  // Fetch on first open of the view, cache in state.
  const [stringsLoading, setStringsLoading] = useState(false);
  useEffect(() => {
    if (!stringsOpen) return;
    if (strings.length > 0 || stringsLoading) return;
    if (!info) return;
    setStringsLoading(true);
    track("strings", loadStrings()
      .then(setStrings)
      .catch(() => {})
      .finally(() => setStringsLoading(false)));
  }, [stringsOpen, strings.length, stringsLoading, info, track]);

  // Edit dialog
  const [editing, setEditing] =
    useState<{ fn: FunctionInfo; mode: "rename" | "note" | "signature" } | null>(null);

  const fnByAddr = useMemo(() => {
    const m = new Map<number, FunctionInfo>();
    if (!info) return m;
    for (const f of info.functions) m.set(f.addrNum, f);
    // Imports with addr=0 are linker-only records; skip to avoid collisions.
    for (const f of info.imports)
      if (f.addrNum !== 0) m.set(f.addrNum, f);
    return m;
  }, [info]);

  const fnAddrByName = useMemo(() => {
    const m = new Map<string, number>();
    if (!info) return m;
    // First name wins.
    const add = (name: string, addr: number) => {
      if (!name) return;
      if (!m.has(name)) m.set(name, addr);
    };
    for (const f of info.functions) {
      add(f.name, f.addrNum);
      const dm = demangle(f.name);
      if (dm !== f.name) add(dm, f.addrNum);
      const rn = annotations.renames[f.addr];
      if (rn) add(rn, f.addrNum);
    }
    for (const f of info.imports) {
      if (f.addrNum === 0) continue;
      add(f.name, f.addrNum);
      const dm = demangle(f.name);
      if (dm !== f.name) add(dm, f.addrNum);
    }
    return m;
  }, [info, annotations]);

  // Inject globals once
  useEffect(() => {
    const id = "ember-globals";
    if (!document.getElementById(id)) {
      const s = document.createElement("style");
      s.id = id;
      s.textContent = globalCSS;
      document.head.appendChild(s);
    }
    // Initial recents load (for welcome screen)
    getRecents().then(setRecents).catch(() => {});
  }, []);

  const openBinaryAt = useCallback(async (binaryPath: string | null) => {
    setLoading(true);
    setError(null);
    try {
      if (binaryPath === null) {
        const p = await pickBinary();
        if (!p) { setLoading(false); return; }
        binaryPath = p;
      }
      const summary = await loadSummary();
      setInfo(summary);
      // Strings are lazy; see stringsLoading below.
      setStrings(EMPTY_STRINGS);
      track("annotations", loadAnnotations(summary.path).then(setAnnotations).catch(() => {}));
      track("xrefs",       loadXrefs().then(setXrefs).catch(() => {}));
      track("arities",     loadArities().then(setArities).catch(() => {}));
      getRecents().then(setRecents).catch(() => {});
      const main = summary.functions.find((f) => f.name === "main");
      const start = main ?? summary.functions[0] ?? null;
      if (start) {
        setCurrent(start);
        setHistory([start.addrNum]);
        setHistIdx(0);
      }
    } catch (e: any) {
      setError(e?.message ?? String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  const handleOpen      = useCallback(() => openBinaryAt(null), [openBinaryAt]);
  const handleOpenRecent = useCallback(async (bp: string) => {
    try { await openRecent(bp); await openBinaryAt(bp); }
    catch (e: any) { setError(e?.message ?? String(e)); }
  }, [openBinaryAt]);

  // Navigate to a function — pushes history (unless we're in back/forward)
  const navigateTo = useCallback((fn: FunctionInfo) => {
    setCurrent(fn);
    if (navigatingRef.current) {
      navigatingRef.current = false;
      return;
    }
    setHistory((h) => {
      if (histIdx >= 0 && h[histIdx] === fn.addrNum) return h;
      const truncated = h.slice(0, histIdx + 1);
      return [...truncated, fn.addrNum];
    });
    setHistIdx((i) => (history[i] === fn.addrNum ? i : i + 1));
  }, [history, histIdx]);

  const navBack = useCallback(() => {
    if (histIdx <= 0 || !info) return;
    const addr = history[histIdx - 1];
    const fn = info.functions.find((f) => f.addrNum === addr);
    if (!fn) return;
    navigatingRef.current = true;
    setHistIdx((i) => i - 1);
    setCurrent(fn);
  }, [histIdx, history, info]);

  const navForward = useCallback(() => {
    if (histIdx >= history.length - 1 || !info) return;
    const addr = history[histIdx + 1];
    const fn = info.functions.find((f) => f.addrNum === addr);
    if (!fn) return;
    navigatingRef.current = true;
    setHistIdx((i) => i + 1);
    setCurrent(fn);
  }, [histIdx, history, info]);

  // Global keyboard shortcuts
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const tag = target?.tagName ?? "";
      const inInput = tag === "INPUT" || tag === "TEXTAREA";
      const mod = e.metaKey || e.ctrlKey;

      if (e.key === "Escape") {
        if (editing)        { setEditing(null);        return; }
        if (stringsOpen)    { setStringsOpen(false);   return; }
        if (callGraphOpen)  { setCallGraphOpen(false); return; }
        if (paletteOpen)    { setPaletteOpen(false);   return; }
        if (searchOpen)     { setSearchOpen(false);    return; }
      }

      if (e.altKey && e.key === "ArrowLeft")  { e.preventDefault(); navBack();    return; }
      if (e.altKey && e.key === "ArrowRight") { e.preventDefault(); navForward(); return; }

      if (mod && (e.key === "p" || e.key === "P")) {
        e.preventDefault();
        setPaletteOpen(true);
        return;
      }
      if (mod && (e.key === "f" || e.key === "F")) {
        if (info) { e.preventDefault(); setSearchOpen(true); }
        return;
      }
      if (mod && (e.key === "g" || e.key === "G")) {
        if (info) { e.preventDefault(); setCallGraphOpen((o) => !o); }
        return;
      }
      if (mod && (e.key === "t" || e.key === "T")) {
        if (info) { e.preventDefault(); setStringsOpen((o) => !o); }
        return;
      }
      if (mod && (e.key === "[" || e.key === "{")) { e.preventDefault(); navBack(); return; }
      if (mod && (e.key === "]" || e.key === "}")) { e.preventDefault(); navForward(); return; }

      // Rename shortcut
      if (!inInput && !mod && !e.altKey && !e.shiftKey && (e.key === "n" || e.key === "N") && current) {
        e.preventDefault();
        setEditing({ fn: current, mode: "rename" });
        return;
      }
      // Signature editor shortcut (Shift+S: "signature" → S)
      if (!inInput && !mod && !e.altKey && e.shiftKey && (e.key === "S") && current) {
        e.preventDefault();
        setEditing({ fn: current, mode: "signature" });
        return;
      }

      // View switches
      if (!inInput && !mod && !e.altKey && !e.shiftKey) {
        if (e.key === "p") { setView("pseudo"); return; }
        if (e.key === "d") { setView("asm");    return; }
        if (e.key === "c") { setView("cfg");    return; }
        if (e.key === "i") { setView("ir");     return; }
        if (e.key === "s") { setView("ssa");    return; }
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [info, paletteOpen, searchOpen, editing, callGraphOpen, stringsOpen, navBack, navForward, current]);

  // Load code whenever selection or view changes
  useEffect(() => {
    if (!current || !info) return;
    let cancel = false;
    setLoading(true);
    setError(null);
    setCode("");
    loadFunction(current.name, view)
      .then((text) => { if (!cancel) setCode(text); })
      .catch((e) => { if (!cancel) setError(e?.message ?? String(e)); })
      .finally(() => { if (!cancel) setLoading(false); });
    return () => { cancel = true; };
  }, [current, view, info]);

  const onXref = useCallback((addr: number) => {
    if (!info) return;
    const match = info.functions.find((f) => f.addrNum === addr);
    if (match) navigateTo(match);
  }, [info, navigateTo]);

  // Annotation mutations
  const writeAnnotations = useCallback(async (a: Annotations) => {
    setAnnotations(a);
    if (info) await saveAnnotations(info.path, a).catch(() => {});
  }, [info]);

  const cloneAnn = useCallback((): Annotations => ({
    renames:    { ...annotations.renames    },
    notes:      { ...annotations.notes      },
    signatures: { ...annotations.signatures },
  }), [annotations]);

  const saveRename = useCallback((fn: FunctionInfo, value: string) => {
    const next = cloneAnn();
    if (value) next.renames[fn.addr] = value;
    else delete next.renames[fn.addr];
    writeAnnotations(next);
  }, [cloneAnn, writeAnnotations]);

  const saveNote = useCallback((fn: FunctionInfo, value: string) => {
    const next = cloneAnn();
    if (value) next.notes[fn.addr] = value;
    else delete next.notes[fn.addr];
    writeAnnotations(next);
  }, [cloneAnn, writeAnnotations]);

  const saveSignature = useCallback((fn: FunctionInfo, sig: FunctionSig | null) => {
    const next = cloneAnn();
    if (sig) next.signatures[fn.addr] = sig;
    else delete next.signatures[fn.addr];
    writeAnnotations(next);
  }, [cloneAnn, writeAnnotations]);

  const lines = useMemo(() => code.split("\n").length, [code]);
  const canBack    = histIdx > 0;
  const canForward = histIdx < history.length - 1;

  if (!info) {
    return (
      <Welcome
        onOpen={handleOpen}
        loading={loading}
        error={error}
        recents={recents}
        onOpenRecent={handleOpenRecent}
      />
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100vh" }}>
      {/* Title bar */}
      <div
        style={{
          height: 36,
          background: C.bgAlt,
          borderBottom: `1px solid ${C.border}`,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "0 14px",
          flexShrink: 0,
          ...({ WebkitAppRegion: "drag" } as React.CSSProperties),
        }}
      >
        <div
          style={{
            display: "flex", alignItems: "center", gap: 14,
            fontFamily: sans, fontSize: 12, color: C.textMuted,
            ...({ WebkitAppRegion: "no-drag" } as React.CSSProperties),
          }}
        >
          <NavArrow dir="back"    enabled={canBack}    onClick={navBack}    />
          <NavArrow dir="forward" enabled={canForward} onClick={navForward} />
          <span style={{ color: C.text, fontWeight: 600 }}>Ember</span>
          <span style={{ fontFamily: serif, fontStyle: "italic", color: C.textFaint }}>
            / {info.path.split("/").pop()}
          </span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <button
            onClick={() => setStringsOpen(true)}
            style={{
              padding: "4px 10px",
              fontFamily: mono, fontSize: 10,
              color: C.textMuted,
              background: C.bgMuted,
              border: `1px solid ${C.border}`,
              borderRadius: 4,
              display: "flex", alignItems: "center", gap: 6,
              ...({ WebkitAppRegion: "no-drag" } as React.CSSProperties),
            }}
            title="Strings (Ctrl+T)"
          >
            <span>strings</span>
            <span style={{ color: C.textFaint }}>⌃T</span>
          </button>
          <button
            onClick={() => setCallGraphOpen(true)}
            style={{
              padding: "4px 10px",
              fontFamily: mono, fontSize: 10,
              color: C.textMuted,
              background: C.bgMuted,
              border: `1px solid ${C.border}`,
              borderRadius: 4,
              display: "flex", alignItems: "center", gap: 6,
              ...({ WebkitAppRegion: "no-drag" } as React.CSSProperties),
            }}
            title="Call graph (Ctrl+G)"
          >
            <span>graph</span>
            <span style={{ color: C.textFaint }}>⌃G</span>
          </button>
          <button
            onClick={() => setPaletteOpen(true)}
            style={{
              padding: "4px 10px",
              fontFamily: mono, fontSize: 10,
              color: C.textMuted,
              background: C.bgMuted,
              border: `1px solid ${C.border}`,
              borderRadius: 4,
              display: "flex", alignItems: "center", gap: 6,
              ...({ WebkitAppRegion: "no-drag" } as React.CSSProperties),
            }}
            title="Jump to function (Ctrl+P)"
          >
            <span>jump</span>
            <span style={{ color: C.textFaint }}>⌃P</span>
          </button>
          <span style={{ fontFamily: mono, fontSize: 10, color: C.textFaint, letterSpacing: 1, marginLeft: 4 }}>
            {info.arch.toUpperCase()} · {info.format.toUpperCase()}
          </span>
        </div>
      </div>

      {/* Body */}
      <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
        <Sidebar
          info={info}
          annotations={annotations}
          currentAddr={current?.addrNum ?? null}
          onSelect={(f) => navigateTo(f)}
          onOpen={(f, v) => { navigateTo(f); setView(v); }}
          onReopen={handleOpen}
          onRename={(fn) => setEditing({ fn, mode: "rename" })}
          onAddNote={(fn) => setEditing({ fn, mode: "note" })}
          onEditSignature={(fn) => setEditing({ fn, mode: "signature" })}
        />
        <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
          <FunctionHeader current={current} annotations={annotations} arities={arities} />
          <Tabs view={view} setView={setView} />
          {error ? (
            <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", padding: 32 }}>
              <div
                style={{
                  maxWidth: 520, padding: 20,
                  background: "rgba(199,93,58,0.06)",
                  border: "1px solid rgba(199,93,58,0.25)",
                  borderRadius: 4,
                  fontFamily: mono, fontSize: 12, color: C.red,
                  whiteSpace: "pre-wrap",
                }}
              >{error}</div>
            </div>
          ) : view === "cfg" ? (
            <CfgGraph text={code} onXref={onXref} />
          ) : (
            <CodeView
              text={code}
              onXref={onXref}
              search={searchOpen ? searchQuery : ""}
              searchActive={searchOpen}
              onSearchChange={setSearchQuery}
              onSearchClose={() => setSearchOpen(false)}
              fnByAddr={fnByAddr}
              fnAddrByName={fnAddrByName}
              annotations={annotations}
              onRename={(fn) => setEditing({ fn, mode: "rename" })}
              onAddNote={(fn) => setEditing({ fn, mode: "note" })}
              onEditSignature={(fn) => setEditing({ fn, mode: "signature" })}
            />
          )}
        </div>
        <XrefsPanel
          info={info}
          current={current}
          xrefs={xrefs}
          annotations={annotations}
          onSelect={(f) => navigateTo(f)}
          onToggle={() => setXrefsOpen((x) => !x)}
          open={xrefsOpen}
        />
      </div>

      <StatusBar current={current} view={view} lines={lines} loading={loading} pending={pending} />

      {paletteOpen && (
        <CommandPalette
          functions={info.functions}
          annotations={annotations}
          onSelect={(f) => navigateTo(f)}
          onClose={() => setPaletteOpen(false)}
        />
      )}
      {stringsOpen && (
        <StringsView
          info={info}
          strings={strings}
          loading={stringsLoading}
          annotations={annotations}
          onSelect={(f) => navigateTo(f)}
          onClose={() => setStringsOpen(false)}
        />
      )}
      {callGraphOpen && (
        <CallGraphView
          info={info}
          xrefs={xrefs}
          annotations={annotations}
          current={current}
          onSelect={(f) => navigateTo(f)}
          onClose={() => setCallGraphOpen(false)}
        />
      )}
      {editing && (
        <EditDialog
          fn={editing.fn}
          mode={editing.mode}
          initial={
            editing.mode === "rename"    ? (annotations.renames[editing.fn.addr] ?? "") :
            editing.mode === "note"      ? (annotations.notes[editing.fn.addr]   ?? "") :
            {
              name:      annotations.renames[editing.fn.addr]    ?? "",
              signature: annotations.signatures[editing.fn.addr] ?? null,
            }
          }
          onSave={(v) => {
            if (editing.mode === "rename")    saveRename(editing.fn, v as string);
            else if (editing.mode === "note") saveNote(editing.fn,   v as string);
            else {
              const sv = v as { name: string; returnType: string; params: { type: string; name: string }[] };
              // A signature edit covers both the name and the typed params.
              saveRename(editing.fn, sv.name);
              const sig: FunctionSig | null = (sv.params.length === 0 && (sv.returnType === "void" || !sv.returnType))
                ? null
                : { returnType: sv.returnType || "void", params: sv.params };
              saveSignature(editing.fn, sig);
            }
            setEditing(null);
          }}
          onClear={() => {
            if (editing.mode === "rename")    saveRename(editing.fn, "");
            else if (editing.mode === "note") saveNote(editing.fn, "");
            else {
              saveRename(editing.fn, "");
              saveSignature(editing.fn, null);
            }
          }}
          onClose={() => setEditing(null)}
        />
      )}
    </div>
  );
}

function NavArrow(props: { dir: "back" | "forward"; enabled: boolean; onClick: () => void }) {
  const [hover, setHover] = useState(false);
  return (
    <button
      onClick={props.onClick}
      disabled={!props.enabled}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      title={props.dir === "back" ? "Back (Alt+←)" : "Forward (Alt+→)"}
      style={{
        width: 22, height: 22,
        display: "flex", alignItems: "center", justifyContent: "center",
        borderRadius: 4,
        color: props.enabled ? (hover ? C.text : C.textMuted) : C.textFaint,
        background: props.enabled && hover ? C.bgMuted : "transparent",
        cursor: props.enabled ? "pointer" : "default",
        opacity: props.enabled ? 1 : 0.35,
        transition: "all .12s",
        fontSize: 14,
        ...({ WebkitAppRegion: "no-drag" } as React.CSSProperties),
      }}
    >
      {props.dir === "back" ? "‹" : "›"}
    </button>
  );
}

function FunctionHeader(props: {
  current: FunctionInfo | null;
  annotations: Annotations;
  arities: Arities;
}) {
  const c = props.current;
  if (!c) return null;
  const dn = displayName(c, props.annotations);
  const isRenamed = !!props.annotations.renames[c.addr];
  const declared = props.annotations.signatures[c.addr];
  const arity = props.arities[c.addrNum];
  // A declared signature wins over the inferred arity. Otherwise we fall
  // back to `u64 a1, u64 a2, …` derived from arity inference.
  type Param = { ty: string; name: string };
  const paramList: Param[] | null = declared
    ? declared.params.map(p => ({ ty: p.type, name: p.name }))
    : arity == null
      ? null
      : arity === 0
        ? []
        : Array.from({ length: arity }, (_, i) => ({ ty: "u64", name: `a${i + 1}` }));
  const returnType = declared?.returnType ?? "void";
  const hasSig = !!declared;
  return (
    <div
      style={{
        padding: "14px 22px",
        background: C.bg,
        borderBottom: `1px solid ${C.border}`,
        display: "flex",
        alignItems: "baseline",
        gap: 16,
        flexShrink: 0,
      }}
    >
      <span style={{ fontFamily: mono, fontSize: 11, color: C.accent, letterSpacing: .5 }}>
        {c.addr}
      </span>
      <span
        style={{
          fontFamily: sans, fontSize: 17, fontWeight: 600, color: C.text,
          overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: "40%",
        }}
        title={c.name}
      >
        {dn}
      </span>
      {paramList != null && (
        <span
          style={{
            fontFamily: mono, fontSize: 11,
            color: C.textWarm,
            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
            maxWidth: "36%",
          }}
          title={hasSig ? `declared signature` : `inferred arity: ${arity}`}
        >
          {hasSig && returnType !== "void" && (
            <>
              <span style={{ color: "#b0a486" }}>{returnType}</span>{" "}
            </>
          )}
          <span style={{ color: C.textFaint }}>(</span>
          {paramList.length === 0
            ? <span style={{ color: C.textFaint }}>void</span>
            : paramList.map((p, i, arr) => (
                <span key={i}>
                  <span style={{ color: "#b0a486" }}>{p.ty}</span>
                  {" "}
                  <span style={{ color: C.textWarm }}>{p.name}</span>
                  {i < arr.length - 1 && <span style={{ color: C.textFaint }}>, </span>}
                </span>
              ))}
          <span style={{ color: C.textFaint }}>)</span>
        </span>
      )}
      {hasSig && (
        <span style={{
          padding: "1px 6px",
          fontFamily: mono, fontSize: 9,
          color: C.accent,
          background: C.accentDim,
          borderRadius: 3,
          letterSpacing: 0.5,
          textTransform: "uppercase",
        }}>signed</span>
      )}
      {isRenamed && (
        <span style={{
          padding: "1px 6px",
          fontFamily: mono, fontSize: 9,
          color: C.accent,
          background: C.accentDim,
          borderRadius: 3,
          letterSpacing: 0.5,
          textTransform: "uppercase",
        }}>renamed</span>
      )}
      <span
        style={{
          fontFamily: serif, fontStyle: "italic", fontSize: 12, color: C.textMuted,
          overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
        }}
      >
        {demangle(c.name)}
      </span>
    </div>
  );
}
