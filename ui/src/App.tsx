import { useEffect, useState, useCallback, useMemo, useRef } from "react";
import { C, sans, serif, mono, globalCSS } from "./theme";
import { Sidebar } from "./components/Sidebar";
import { CodeView } from "./components/CodeView";
import { Welcome } from "./components/Welcome";
import { Tabs } from "./components/Tabs";
import { StatusBar } from "./components/StatusBar";
import { CommandPalette } from "./components/CommandPalette";
import { CfgGraph } from "./components/CfgGraph";
import { AIPanel, SparkIcon } from "./components/AIPanel";
import { GearIcon, SettingsPanel } from "./components/Settings";
import { loadSettings, saveSettings } from "./settings";
import type { AppSettings } from "./settings";
import { CallGraphView } from "./components/CallGraphView";
import { StringsView } from "./components/StringsView";
import { NotesView } from "./components/NotesView";
import { PatchesView } from "./components/PatchesView";
import { XrefsPanel } from "./components/XrefsPanel";
import { EditDialog } from "./components/EditDialog";
import { PatchDialog } from "./components/PatchDialog";
import {
  loadSummary, loadFunction, pickBinary, openRecent,
  loadXrefs, loadStrings, loadArities, loadAnnotations, saveAnnotations, getRecents,
  exportAnnotations, importAnnotations,
  clearRendererCaches,
  displayName, demangle,
} from "./api";
import type {
  BinaryInfo, FunctionInfo, ViewKind, Xrefs, Annotations, StringEntry, Arities,
  FunctionSig,
} from "./types";

const EMPTY_XREFS: Xrefs = { callers: {}, callees: {} };
const EMPTY_ANN:   Annotations = { renames: {}, notes: {}, signatures: {}, localRenames: {}, patches: {} };
const EMPTY_STRINGS: StringEntry[] = [];
const EMPTY_ARITIES: Arities = {};

// Word-boundary substitute every key in `pairs` with its mapped value
// in one pass. One-pass matters because rename A → B and rename B → C
// applied sequentially would chain (A → C); applied atomically they
// don't. Identifier-shape `from` keys make `\b` anchors safe.
function applyLocalRenames(text: string, pairs: Record<string, string>): string {
  const keys = Object.keys(pairs).filter(Boolean);
  if (keys.length === 0) return text;
  const escaped = keys
    .map((k) => k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .sort((a, b) => b.length - a.length);   // longest-first to avoid prefix shadowing
  const re = new RegExp(`\\b(?:${escaped.join("|")})\\b`, "g");
  return text.replace(re, (m) => pairs[m] ?? m);
}

export default function App() {
  const [info, setInfo] = useState<BinaryInfo | null>(null);
  const [current, setCurrent] = useState<FunctionInfo | null>(null);
  const [view, setView] = useState<ViewKind>("pseudo");
  // App-wide settings. Loaded synchronously from localStorage on mount
  // so the initial render uses the user's saved values rather than
  // flashing defaults first.
  const [settings, setSettings] = useState<AppSettings>(() => loadSettings());
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [aiOpen, setAiOpen] = useState(false);
  const updateSettings = useCallback((s: AppSettings) => {
    setSettings(s);
    saveSettings(s);
    // Pseudo-C output depends on `--labels` — toggling it would serve
    // stale text from the renderer cache otherwise.
    clearRendererCaches();
  }, []);
  // CFG view sub-mode. Initialized from the user's setting; the toggle
  // in the graph's bottom-right corner overrides for the current
  // session without touching the saved default.
  const [cfgMode, setCfgMode] = useState<"pseudo" | "asm">(
    () => settings.cfgDefaultMode
  );
  // Effective view used for fetching: when on the CFG tab, choose the
  // backend route based on the sub-mode toggle.
  const fetchView: ViewKind =
    view === "cfg" ? (cfgMode === "pseudo" ? "cfgPseudo" : "cfg") : view;
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
  const [notesOpen, setNotesOpen] = useState(false);
  const [patchesOpen, setPatchesOpen] = useState(false);

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

  // Byte-patch dialog. Opened from a right-click on an asm-view
  // instruction line. `origBytes` is the bytes string we display
  // (post-existing-patch — i.e. what the disasm currently shows).
  const [patching, setPatching] =
    useState<{ vaddr: number; origBytes: string; disasm: string } | null>(null);

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
      // New binary → previous binary's cached results are stale.
      clearRendererCaches();
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
        if (patching)       { setPatching(null);       return; }
        if (patchesOpen)    { setPatchesOpen(false);   return; }
        if (editing)        { setEditing(null);        return; }
        if (stringsOpen)    { setStringsOpen(false);   return; }
        if (notesOpen)      { setNotesOpen(false);     return; }
        if (callGraphOpen)  { setCallGraphOpen(false); return; }
        if (paletteOpen)    { setPaletteOpen(false);   return; }
        if (searchOpen)     { setSearchOpen(false);    return; }
      }

      if (e.altKey && e.key === "ArrowLeft")  { e.preventDefault(); navBack();    return; }
      if (e.altKey && e.key === "ArrowRight") { e.preventDefault(); navForward(); return; }

      if (mod && !e.shiftKey && (e.key === "p" || e.key === "P")) {
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
      if (mod && (e.key === "j" || e.key === "J")) {
        if (info) { e.preventDefault(); setNotesOpen((o) => !o); }
        return;
      }
      if (mod && (e.key === "k" || e.key === "K")) {
        if (info) { e.preventDefault(); setAiOpen((o) => !o); }
        return;
      }
      if (mod && e.shiftKey && (e.key === "p" || e.key === "P")) {
        if (info) { e.preventDefault(); setPatchesOpen((o) => !o); }
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
  }, [info, paletteOpen, searchOpen, editing, callGraphOpen, stringsOpen, notesOpen, patchesOpen, patching, navBack, navForward, current]);

  // Load code whenever selection or view (or CFG sub-mode) changes.
  // Pseudo-C views also get local-rename substitution applied on top
  // of whatever the C++ emitter produced, since localRenames live in
  // the UI sidecar only and never round-trip through the analysis
  // pipeline.
  useEffect(() => {
    if (!current || !info) return;
    let cancel = false;
    setLoading(true);
    setError(null);
    setCode("");
    loadFunction(current.name, fetchView, { showBbLabels: settings.showBbLabels })
      .then((text) => {
        if (cancel) return;
        const locals = annotations.localRenames?.[current.addr];
        const isPseudo = fetchView === "pseudo" || fetchView === "cfgPseudo";
        setCode(isPseudo && locals ? applyLocalRenames(text, locals) : text);
      })
      .catch((e) => { if (!cancel) setError(e?.message ?? String(e)); })
      .finally(() => { if (!cancel) setLoading(false); });
    return () => { cancel = true; };
  }, [current, fetchView, info, settings.showBbLabels, annotations.localRenames]);

  const onXref = useCallback((addr: number) => {
    if (!info) return;
    const match = info.functions.find((f) => f.addrNum === addr);
    if (match) navigateTo(match);
  }, [info, navigateTo]);

  // Annotation mutations
  const writeAnnotations = useCallback(async (a: Annotations) => {
    setAnnotations(a);
    // Renames and signature changes flow into pseudo-C output via the
    // CLI's --annotations file, so cached function bodies are stale
    // after any mutation. Drop them so the next view reload picks up
    // the fresh names.
    clearRendererCaches();
    if (info) await saveAnnotations(info.path, a).catch(() => {});
  }, [info]);

  const cloneAnn = useCallback((): Annotations => ({
    renames:      { ...annotations.renames    },
    notes:        { ...annotations.notes      },
    signatures:   { ...annotations.signatures },
    localRenames: { ...(annotations.localRenames || {}) },
    patches:      { ...(annotations.patches      || {}) },
  }), [annotations]);

  // Export all current annotations to a user-chosen JSON file. The main
  // process handles the save dialog; we pass the in-memory annotations
  // (not the on-disk sidecar) so unsaved edits are captured too.
  const handleExport = useCallback(async () => {
    if (!info) return;
    try {
      const out = await exportAnnotations(info.path, annotations);
      if (out) setError(`Exported to ${out}`);
    } catch (e: unknown) {
      setError(`Export failed: ${(e as Error).message}`);
    }
  }, [info, annotations]);

  // Import annotations from a user-chosen JSON file, merging into the
  // current set. Strategy: per-map union, with imported values winning
  // on collisions — the user is explicitly pulling in someone else's
  // work, so their renames override. A replace-instead-of-merge flow
  // can be added later if the use case shows up.
  const handleImport = useCallback(async () => {
    if (!info) return;
    try {
      const imp = await importAnnotations();
      if (!imp) return;
      const merged: Annotations = {
        renames:      { ...annotations.renames,    ...imp.renames    },
        notes:        { ...annotations.notes,      ...imp.notes      },
        signatures:   { ...annotations.signatures, ...imp.signatures },
        localRenames: { ...(annotations.localRenames || {}) },
        patches:      { ...(annotations.patches || {}),   ...(imp.patches || {}) },
      };
      for (const [fnAddr, lr] of Object.entries(imp.localRenames || {})) {
        merged.localRenames![fnAddr] = { ...(merged.localRenames![fnAddr] || {}), ...lr };
      }
      clearRendererCaches();
      setAnnotations(merged);
      await saveAnnotations(info.path, merged);
    } catch (e: unknown) {
      setError(`Import failed: ${(e as Error).message}`);
    }
  }, [info, annotations]);

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

  // Add / update / remove a single byte patch by virtual address.
  // Empty `bytes` removes the entry. Hex strings get normalised to
  // uppercase and whitespace-stripped so equality comparison and
  // sidecar diffs stay clean.
  const savePatch = useCallback(
    (vaddrHex: string, bytes: string, opts?: { orig?: string; comment?: string }) => {
      const next = cloneAnn();
      next.patches = next.patches || {};
      const cleanBytes = bytes.replace(/\s+/g, "").toUpperCase();
      if (cleanBytes) {
        next.patches[vaddrHex] = {
          bytes: cleanBytes,
          ...(opts?.orig    ? { orig:    opts.orig.replace(/\s+/g, "").toUpperCase() } : {}),
          ...(opts?.comment ? { comment: opts.comment } : {}),
        };
      } else {
        delete next.patches[vaddrHex];
      }
      writeAnnotations(next);
    },
    [cloneAnn, writeAnnotations],
  );

  // Bulk-apply per-function local renames. `pairs` is { from: to }.
  // Empty `to` removes the entry (the user can revert a single rename
  // by passing { from: "" }). Merges into any existing per-fn map so
  // applying a partial AI suggestion doesn't blow away earlier ones.
  //
  // Chain-collapse: when `from` matches some existing entry's `to`
  // (user renamed an already-renamed token), rewrite that entry in
  // place rather than stacking a second rename. This keeps the map
  // keyed on canonical emitter names (`local_10`, `a1`, `r_strlen`)
  // so `applyLocalRenames` does the substitution in one pass.
  const saveLocalRenames = useCallback((fn: FunctionInfo, pairs: Record<string, string>) => {
    const next = cloneAnn();
    next.localRenames = next.localRenames || {};
    const cur = { ...(next.localRenames[fn.addr] || {}) };
    for (const [from, to] of Object.entries(pairs)) {
      let key = from;
      for (const [k, v] of Object.entries(cur)) {
        if (v === from) { key = k; break; }
      }
      if (to) cur[key] = to;
      else delete cur[key];
    }
    if (Object.keys(cur).length > 0) next.localRenames[fn.addr] = cur;
    else delete next.localRenames[fn.addr];
    writeAnnotations(next);
  }, [cloneAnn, writeAnnotations]);

  // Adapter for CodeView: single-token rename from the pseudo-C context
  // menu. Empty `newName` removes the rename (resets to the emitter's
  // canonical form).
  const renameLocalFromCode = useCallback((oldName: string, newName: string) => {
    if (!current) return;
    saveLocalRenames(current, { [oldName]: newName });
  }, [current, saveLocalRenames]);

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
          <button
            onClick={() => setAiOpen(true)}
            style={{
              padding: 5,
              fontFamily: mono, fontSize: 10,
              color: C.textMuted,
              background: "transparent",
              border: `1px solid transparent`,
              borderRadius: 4,
              cursor: "pointer",
              display: "flex", alignItems: "center", justifyContent: "center",
              ...({ WebkitAppRegion: "no-drag" } as React.CSSProperties),
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.color = C.accent;
              e.currentTarget.style.background = C.bgMuted;
              e.currentTarget.style.borderColor = C.border;
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.color = C.textMuted;
              e.currentTarget.style.background = "transparent";
              e.currentTarget.style.borderColor = "transparent";
            }}
            title="Ember AI (⌘K / Ctrl+K)"
            aria-label="AI assistant"
          >
            <SparkIcon size={14} />
          </button>
          <button
            onClick={() => setSettingsOpen(true)}
            style={{
              padding: 5,
              marginLeft: 4,
              fontFamily: mono, fontSize: 10,
              color: C.textMuted,
              background: "transparent",
              border: `1px solid transparent`,
              borderRadius: 4,
              cursor: "pointer",
              display: "flex", alignItems: "center", justifyContent: "center",
              ...({ WebkitAppRegion: "no-drag" } as React.CSSProperties),
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.color = C.text;
              e.currentTarget.style.background = C.bgMuted;
              e.currentTarget.style.borderColor = C.border;
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.color = C.textMuted;
              e.currentTarget.style.background = "transparent";
              e.currentTarget.style.borderColor = "transparent";
            }}
            title="Settings"
            aria-label="Settings"
          >
            <GearIcon size={14} />
          </button>
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
          onExport={handleExport}
          onImport={handleImport}
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
            <CfgGraph
              text={code}
              onXref={onXref}
              fnAddrByName={fnAddrByName}
              mode={cfgMode}
              onModeChange={setCfgMode}
            />
          ) : (
            <CodeView
              text={code}
              fontSize={settings.codeFontSize}
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
              onRenameLocal={view === "pseudo" ? renameLocalFromCode : undefined}
              onPatchInsn={view === "asm" ? (vaddr, origBytes, disasm) =>
                setPatching({ vaddr, origBytes, disasm }) : undefined}
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
      {settingsOpen && (
        <SettingsPanel
          settings={settings}
          onChange={updateSettings}
          onClose={() => setSettingsOpen(false)}
        />
      )}
      {aiOpen && (
        <AIPanel
          context={current ? {
            fnName: current.name,
            fnAddr: current.addr,
            view:   fetchView,
            code,
          } : undefined}
          current={current}
          annotations={annotations}
          onApplyRename={(fn, name) => saveRename(fn, name)}
          onApplyLocalRenames={saveLocalRenames}
          onClose={() => setAiOpen(false)}
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
      {notesOpen && (
        <NotesView
          info={info}
          annotations={annotations}
          onSelect={(f) => navigateTo(f)}
          onClose={() => setNotesOpen(false)}
        />
      )}
      {patchesOpen && (
        <PatchesView
          info={info}
          annotations={annotations}
          onSelect={(f) => navigateTo(f)}
          onRevert={(addr) => savePatch(addr, "")}
          onSaveAs={async () => {
            try {
              const out = await window.ember.savePatchedAs();
              if (out) console.info(`patched binary saved -> ${out}`);
            } catch (e) {
              console.error("save patched failed:", e);
            }
          }}
          onClose={() => setPatchesOpen(false)}
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
      {patching && (
        <PatchDialog
          vaddr={patching.vaddr}
          origBytes={patching.origBytes}
          disasm={patching.disasm}
          onSave={(addrHex, bytesHex) => {
            // Stash the original bytes only on the first patch at this
            // address so revert returns to truth, not to a previous
            // patched value.
            const existing = annotations.patches?.[addrHex];
            const orig = existing?.orig
              ?? patching.origBytes.replace(/\s+/g, "").toUpperCase();
            savePatch(addrHex, bytesHex, { orig });
            setPatching(null);
          }}
          onRevert={annotations.patches?.[`0x${patching.vaddr.toString(16)}`]
            ? () => savePatch(`0x${patching.vaddr.toString(16)}`, "")
            : undefined}
          onClose={() => setPatching(null)}
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
