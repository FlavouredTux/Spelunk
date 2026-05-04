import { useEffect, useState, useCallback, useMemo, useRef } from "react";
import { C, sans, serif, mono, globalCSS, applyTheme, setMonoFamily } from "./theme";
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
import { PluginsPanelView } from "./components/PluginsPanelView";
import { AgentPanel } from "./components/AgentPanel";
import { StringsView } from "./components/StringsView";
import { NotesView } from "./components/NotesView";
import { PatchesView } from "./components/PatchesView";
import { DiffView } from "./components/DiffView";
import { EmberScriptView } from "./components/EmberScriptView";
import { XrefsPanel } from "./components/XrefsPanel";
import { EditDialog } from "./components/EditDialog";
import { PatchDialog } from "./components/PatchDialog";
import { Tutorial } from "./components/Tutorial";
import { ErrorView } from "./components/ErrorView";
import { Shortcuts } from "./components/Shortcuts";
import { HexView } from "./components/HexView";
import { SymbolsView } from "./components/SymbolsView";
import { BookmarksPanel } from "./components/BookmarksPanel";
import { IdentifyPanel } from "./components/IdentifyPanel";
import { BulkRenameDialog } from "./components/BulkRenameDialog";
import type { Bookmark } from "./components/BookmarksPanel";
import { ResizeHandle } from "./components/ResizeHandle";
import { Breadcrumb } from "./components/Breadcrumb";
import { SkelCode, SkelFunctionHeader, SkelXrefs } from "./components/Skeleton";
import {
  loadHeader, loadFunctions, loadFunction, pickBinary, openRecent,
  loadXrefs, loadStrings, loadArities, loadAnnotations, saveAnnotations, getRecents,
  exportAnnotations, importAnnotations, importCorpusRenames, loadIdentifications,
  checkForReleaseUpdate, downloadAndInstallReleaseUpdate,
  clearRendererCaches,
  displayName, demangle,
} from "./api";
import type {
  BinaryInfo, FunctionInfo, ViewKind, Xrefs, Annotations, StringEntry, Arities,
  FunctionSig, ReleaseUpdateStatus, IdentifyResult,
} from "./types";

const EMPTY_XREFS: Xrefs = { callers: {}, callees: {} };
const EMPTY_ANN:   Annotations = { renames: {}, notes: {}, signatures: {}, fields: {}, localRenames: {}, patches: {} };
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

// Heuristic: spot binaries that have been packed / obfuscated /
// protected (Themida, VMProtect, …). Static analysis is
// effectively useless on these — the real code only exists in
// memory at runtime — so we surface a one-line banner before the
// user spends ten clicks discovering nothing decodes.
//
// Returns a human-readable reason or null when the binary looks
// honest. Cheap; runs once at load time off the section table.
function detectPackedBinary(info: BinaryInfo): string | null {
  const entryNum = parseInt(info.entry, 16);
  if (!Number.isFinite(entryNum)) return null;

  const sectionAt = (addr: number) => info.sections.find((s) => {
    const v  = parseInt(s.vaddr, 16);
    const sz = parseInt(s.size,  16);
    return Number.isFinite(v) && Number.isFinite(sz) && addr >= v && addr < v + sz;
  });

  const entrySec = sectionAt(entryNum);
  if (entrySec && !entrySec.flags.includes("x")) {
    const where = entrySec.name || "(unnamed section)";
    return `entry point lives in '${where}' which isn't marked executable — likely packed or protected (VMProtect, Themida, …); decompilation will mostly fail`;
  }

  // Secondary: a "code-shaped" section (named .text / __text / CODE)
  // that's large enough to hold real code but lacks the exec flag.
  // Catches binaries where the entry point WAS rerouted to a tiny
  // stub section with x — some packers do exactly this.
  const CODE_NAMES = new Set([".text", "__text", "CODE"]);
  for (const s of info.sections) {
    const sz = parseInt(s.size, 16);
    if (!Number.isFinite(sz) || sz < 0x40000) continue;
    if (!CODE_NAMES.has(s.name)) continue;
    if (!s.flags.includes("x")) {
      return `'${s.name}' is ${(sz >>> 20).toString()} MB but not marked executable — this binary may be packed or protected`;
    }
    // Tertiary: section has exec but lacks read — Byfron/Themida strip
    // all memory-protection flags from .text except CNT_CODE. A real
    // compiler always emits MEM_READ alongside MEM_EXECUTE.
    if (s.flags.includes("x") && !s.flags.includes("r")) {
      return `'${s.name}' is marked executable but not readable — packer stripped section flags (Byfron, Themida); decompilation will mostly fail`;
    }
  }

  // Quaternary: entry point is outside the main code section. Packers
  // redirect entry to a tiny unpacker stub (tempest, .byfron, etc.)
  // while the real .text is encrypted.
  if (entrySec) {
    const mainCode = info.sections.find((s) =>
      CODE_NAMES.has(s.name) && parseInt(s.size, 16) > 0x40000);
    if (mainCode && entrySec.name !== mainCode.name) {
      return `entry point is in '${entrySec.name || "(unnamed)"}', not '${mainCode.name}' — likely packed; decompilation will mostly fail`;
    }
  }

  return null;
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
  // First-run coach-marks. Mounts once after a binary loads; the
  // Tutorial component itself flips `seenTutorial` on close.
  const [tutorialOpen, setTutorialOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  // Per-session "packed binary" banner. We re-show it for each new
  // binary the user opens; once dismissed for a given path, it stays
  // hidden until that path is opened again in a fresh session.
  const [packedDismissedFor, setPackedDismissedFor] = useState<string | null>(null);
  // Set of binary paths the user has explicitly opted into full
  // analysis for. The CLI defaults to a fast loader-only mode on packed
  // binaries; when this set contains the current path, we re-spawn the
  // function-list query with --full-analysis so the polluted call-graph
  // pass runs anyway.
  const [forceFullAnalysisFor, setForceFullAnalysisFor] = useState<Set<string>>(() => new Set());
  const packedWarning = useMemo(
    () => (info ? detectPackedBinary(info) : null),
    [info],
  );
  const updateSettings = useCallback((s: AppSettings) => {
    setSettings(s);
    saveSettings(s);
    // Pseudo-C output depends on `--labels` — toggling it would serve
    // stale text from the renderer cache otherwise.
    clearRendererCaches();
  }, []);
  const patchSettings = useCallback((patch: Partial<AppSettings>) => {
    setSettings((cur) => {
      const next = { ...cur, ...patch };
      saveSettings(next);
      return next;
    });
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
  const [pluginsPanelOpen, setPluginsPanelOpen] = useState(false);
  const [agentPanelOpen, setAgentPanelOpen] = useState(false);
  const [patchesOpen, setPatchesOpen] = useState(false);
  const [diffOpen, setDiffOpen] = useState(false);
  const [emberApplyOpen, setEmberApplyOpen] = useState(false);
  const [hexOpen, setHexOpen] = useState(false);
  // Optional starting vaddr for the next HexView open. Set when the
  // palette falls through with an address that doesn't map to a
  // function — HexView's auto-jump logic picks it up on mount.
  const [hexInitialVaddr, setHexInitialVaddr] = useState<number | null>(null);
  const [symbolsOpen, setSymbolsOpen] = useState(false);
  const [bookmarksOpen, setBookmarksOpen] = useState(false);
  const [identifyOpen, setIdentifyOpen] = useState(false);
  const [identifyHits, setIdentifyHits] = useState<IdentifyResult[]>([]);
  const [identifyLoading, setIdentifyLoading] = useState(false);
  const [bulkRenameOpen, setBulkRenameOpen] = useState(false);
  // Dirty indicator: pulses when annotations are mid-flight to disk so
  // the user can see saves are happening. "saved" sticks for ~1.5s
  // after each successful write so single edits also flash.
  const [saveState, setSaveState] = useState<"idle" | "saving" | "saved" | "error">("idle");
  // Toast for transient actions (bookmarked, exported, …).
  const [toast, setToast] = useState<string | null>(null);
  // Undo stack — snapshots of the annotations object before each write.
  // Capped to keep memory bounded on long editing sessions.
  const undoStackRef = useRef<Annotations[]>([]);
  // Lazy xrefs latch — stays false until the first consumer panel is
  // opened, then true forever (per-binary). Kept as a ref so flipping
  // it doesn't trigger a re-render — the effect that watches xrefsOpen
  // / callGraphOpen / aiOpen reads it directly.
  const xrefsRequestedRef = useRef(false);
  // Keyboard handler needs a stable hook-into for undo, but the actual
  // implementation depends on `annotations` and other state defined later
  // in this component. Bridge with a ref so the keyboard useEffect can
  // call `undoRef.current()` without a forward-declaration TypeError.
  const undoRef = useRef<() => void>(() => {});

  // Data: cross-refs + user annotations + strings + arities
  const [xrefs, setXrefs] = useState<Xrefs>(EMPTY_XREFS);
  const [annotations, setAnnotations] = useState<Annotations>(EMPTY_ANN);
  const [strings, setStrings] = useState<StringEntry[]>(EMPTY_STRINGS);
  const [arities, setArities] = useState<Arities>(EMPTY_ARITIES);
  const [recents, setRecents] = useState<string[]>([]);
  const [releaseUpdate, setReleaseUpdate] = useState<ReleaseUpdateStatus | null>(null);

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
  // True while the background --functions query is running. Sidebar
  // shows a "discovering functions…" spinner; CommandPalette filters
  // gracefully on an empty list.
  const [functionsLoading, setFunctionsLoading] = useState(false);
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

  // Identification panel data loading
  useEffect(() => {
    if (!identifyOpen) return;
    if (identifyHits.length > 0 || identifyLoading) return;
    if (!info) return;
    setIdentifyLoading(true);
    track("identify", loadIdentifications()
      .then(setIdentifyHits)
      .catch(() => {})
      .finally(() => setIdentifyLoading(false)));
  }, [identifyOpen, identifyHits.length, identifyLoading, info, track]);

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

  // Palette searches the union of defined + imports so the user can
  // jump straight to printf / malloc / etc. by name. Imports with
  // addr=0 are linker-only stubs and aren't navigable.
  const paletteFunctions = useMemo(() => {
    if (!info) return [];
    const imports = info.imports.filter((f) => f.addrNum !== 0);
    return [...info.functions, ...imports];
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

  // Apply theme + font from settings whenever they change. The exported
  // C / mono bindings are mutable so existing component imports keep
  // working without prop-drilling — we just bump a render counter on
  // App so children re-paint with the new values.
  const [themeRev, setThemeRev] = useState(0);
  useEffect(() => {
    applyTheme(settings.theme);
    setMonoFamily(settings.codeFontFamily);
    setThemeRev((n) => n + 1);
  }, [settings.theme, settings.codeFontFamily]);
  void themeRev;   // referenced so the linter doesn't strip the bump

  // Lazy xrefs: spawn the --xrefs CLI run only when a consumer panel
  // becomes visible. Saves a slow ember invocation on initial load
  // for users who never open xrefs / callgraph / AI in a session.
  useEffect(() => {
    if (!info) return;
    if (xrefsRequestedRef.current) return;
    if (!(xrefsOpen || callGraphOpen || aiOpen)) return;
    xrefsRequestedRef.current = true;
    track("xrefs", loadXrefs().then(setXrefs).catch(() => {}));
  }, [info, xrefsOpen, callGraphOpen, aiOpen, track]);

  // Auto-resume the most recently opened binary on launch. Settings
  // persists `lastBinary`; the main process's setBinary IPC just pins
  // the path without doing analysis, mirroring openRecent. If the file
  // has moved we silently fall back to the welcome screen.
  const resumedRef = useRef(false);
  useEffect(() => {
    if (resumedRef.current) return;
    if (!settings.resumeOnLaunch) return;
    const path = settings.lastBinary;
    if (!path) return;
    resumedRef.current = true;
    openRecent(path)
      .then(() => openBinaryAt(path))
      .catch(() => { /* binary moved or missing — leave welcome screen up */ });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // External-trigger open: the main process emits `ember:open-binary`
  // when the app was launched with a path argument or when a second
  // invocation forwards one via the single-instance handler. Routes
  // through the same chain as the recents/drag-drop paths so panel
  // reset, info fetch, and last-binary persistence are all consistent.
  useEffect(() => {
    if (!window.ember.onOpenBinary) return;
    const off = window.ember.onOpenBinary((bp: string) => {
      void openRecent(bp).then(() => openBinaryAt(bp)).catch(() => {});
    });
    return off;
    // openBinaryAt is stable via useCallback; subscribing once on mount.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Discord Rich Presence: push the current activity whenever it
  // changes; clear when toggled off or on unmount. Elapsed-time
  // anchor (`startTimestamp`) is per-binary so flipping between
  // functions doesn't reset it; opening a new binary does.
  const discordSessionStart = useRef<{ path: string; ts: number } | null>(null);
  useEffect(() => {
    if (!settings.discordRichPresence) {
      window.ember.discord.setActivity(null).catch(() => {});
      discordSessionStart.current = null;
      return;
    }
    if (!info) {
      window.ember.discord.setActivity(null).catch(() => {});
      return;
    }
    if (!discordSessionStart.current ||
        discordSessionStart.current.path !== info.path) {
      discordSessionStart.current = { path: info.path, ts: Date.now() };
    }
    const fileName = info.path.split(/[\\/]/).pop() || info.path;
    const fnName   = current ? displayName(current, annotations) : null;
    // Per-view unicode glyph + label. Each glyph is loosely meaningful:
    //   ❯  pseudo-C  — chevron, like a code prompt
    //   ▸  asm       — small play triangle, evokes execution
    //   ◆  cfg       — diamond, the canonical CFG-node shape
    //   λ  ir        — lambda, the IR / functional-form convention
    //   φ  ssa       — phi-node, the defining feature of SSA
    const viewBadge: Record<typeof view, { glyph: string; label: string; key: string }> = {
      pseudo:    { glyph: "❯", label: "pseudo-C",     key: "view_pseudo" },
      asm:       { glyph: "▸", label: "asm",          key: "view_asm"    },
      cfg:       { glyph: "◆", label: "control-flow", key: "view_cfg"    },
      cfgPseudo: { glyph: "◆", label: "control-flow", key: "view_cfg"    },
      ir:        { glyph: "λ", label: "lifted IR",    key: "view_ir"     },
      ssa:       { glyph: "φ", label: "SSA",          key: "view_ssa"    },
      identify:  { glyph: "🔍", label: "identification", key: "view_identify" },
    };
    const badge = viewBadge[view];
    // Two privacy modes:
    //  - default: details = binary, state = function <glyph> view
    //  - hide-binary: details = "reverse engineering", state = function <glyph> view
    // Privacy mode: hide binary path and function name entirely so
    // the broadcast only reveals "user is running Ember in <view>".
    const details = settings.discordHideBinaryName
      ? "reverse engineering"
      : fileName;
    const state = settings.discordHideBinaryName
      ? `${badge.glyph}  ${badge.label}`
      : (fnName
          ? `${fnName}  ${badge.glyph}  ${badge.label}`
          : `${badge.glyph}  ${badge.label}`);
    window.ember.discord.setActivity({
      details,
      state,
      startTimestamp: discordSessionStart.current.ts,
      largeImageKey:  "ember_logo",
      largeImageText: "Ember · from-scratch x86-64 decompiler",
      // Small overlay corner-icon on the large image — Discord just
      // hides this slot when the asset isn't uploaded, so always
      // sending it means the moment you upload view_pseudo / view_asm
      // / view_cfg / view_ir / view_ssa, the badge appears with no
      // code change.
      smallImageKey:  badge.key,
      smallImageText: badge.label,
      // 1 = STATE → the inline mini-status under your username shows
      // the function + view glyph (e.g. "sub_1021bb368  ❯  pseudo-C")
      // instead of just the app name "ember". Best signal-to-pixel
      // ratio of the three options.
      statusDisplayType: 1,
      buttons: [
        { label: "Get Ember",     url: "https://github.com/FlavouredTux/Ember" },
        { label: "GitHub Profile", url: "https://github.com/FlavouredTux"        },
      ],
    }).catch(() => {});
  }, [info, current, view, annotations,
      settings.discordRichPresence, settings.discordHideBinaryName]);

  // Fire the first-run tour the first time a binary finishes loading.
  // Gated behind seenTutorial so reload-after-close is silent.
  useEffect(() => {
    if (info && !settings.seenTutorial) setTutorialOpen(true);
  }, [info, settings.seenTutorial]);

  useEffect(() => {
    if (!settings.releaseUpdatePopup) {
      setReleaseUpdate(null);
      return;
    }

    let cancel = false;
    const seen = settings.seenReleaseTag || "";

    const poll = async () => {
      try {
        const status = await checkForReleaseUpdate();
        if (cancel || !status.ok || !status.tag) return;
        if (!status.available) {
          setReleaseUpdate(null);
          return;
        }
        if (seen === status.tag) {
          if (releaseUpdate?.tag === status.tag) setReleaseUpdate(null);
          return;
        }
        setReleaseUpdate(status);
      } catch {
        // Release polling is best-effort.
      }
    };

    poll();
    const t = window.setInterval(poll, 120000);
    return () => { cancel = true; window.clearInterval(t); };
  }, [settings.releaseUpdatePopup, settings.seenReleaseTag, releaseUpdate?.tag]);

  const dismissReleaseUpdate = useCallback((status?: ReleaseUpdateStatus | null) => {
    const s = status ?? releaseUpdate;
    if (!s?.tag) {
      setReleaseUpdate(null);
      return;
    }
    patchSettings({
      seenReleaseTag: s.tag,
    });
    setReleaseUpdate(null);
  }, [releaseUpdate, patchSettings]);

  const openBinaryAt = useCallback(async (binaryPath: string | null) => {
    setLoading(true);
    setError(null);
    try {
      if (binaryPath === null) {
        const p = await pickBinary();
        if (!p) { setLoading(false); return; }
        binaryPath = p;
      }
      // New binary → previous binary's cached results are stale, and
      // any selection from the prior binary is meaningless against
      // this one's address space.
      clearRendererCaches();
      setCurrent(null);
      setHistory([]);
      setHistIdx(-1);
      // Staged load — each ember CLI invocation re-parses the binary
      // from scratch, so firing four of them in parallel on a 200 MB
      // PE quadruples the parse cost and thrashes the OS file cache.
      // Order:
      //   1. header (synchronous)            — UI shell
      //   2. annotations + functions parallel — sidecar is tiny;
      //                                         functions gates the sidebar
      //   3. arities (after functions)       — fills the FunctionHeader
      //   4. xrefs (lazy)                    — only spawned when the user
      //                                         opens xrefs / callgraph /
      //                                         AI, where it's actually used
      const header = await loadHeader();
      setInfo(header);
      setStrings(EMPTY_STRINGS);
      setIdentifyHits([]);
      undoStackRef.current = [];
      xrefsRequestedRef.current = false;
      patchSettings({ lastBinary: header.path });
      setFunctionsLoading(true);
      track("annotations", loadAnnotations(header.path).then(setAnnotations).catch(() => {}));
      getRecents().then(setRecents).catch(() => {});
      track("functions", loadFunctions({
        fullAnalysis: forceFullAnalysisFor.has(binaryPath),
      }).then((fns) => {
        // Merge into whatever info shape we currently have. If the
        // user already opened a different binary by the time we
        // resolve, drop the result on the floor.
        setInfo((prev) => (prev && prev.path === header.path
          ? { ...prev, functions: fns } : prev));
        // Default selection: prefer the per-binary saved last function,
        // then `main`, then the first function. Guard against the user
        // navigating somewhere already.
        setCurrent((cur) => {
          if (cur) return cur;
          const lastAddr = settings.binaryState[header.path]?.lastFunctionAddr;
          const last = lastAddr ? fns.find((f) => f.addr === lastAddr) : null;
          const main = fns.find((f) => f.name === "main");
          const start = last ?? main ?? fns[0] ?? null;
          if (start) {
            setHistory([start.addrNum]);
            setHistIdx(0);
          }
          return start;
        });
        // Now that functions is in, fire arities. Sequencing avoids a
        // third concurrent ember process competing with the function
        // loader for binary parse + file-cache pages.
        track("arities", loadArities().then(setArities).catch(() => {}));
      }).catch(() => {}).finally(() => setFunctionsLoading(false)));
    } catch (e: any) {
      setError(e?.message ?? String(e));
    } finally {
      setLoading(false);
    }
  }, [forceFullAnalysisFor]);

  const handleOpen      = useCallback(() => openBinaryAt(null), [openBinaryAt]);
  const handleOpenRecent = useCallback(async (bp: string) => {
    try { await openRecent(bp); await openBinaryAt(bp); }
    catch (e: any) { setError(e?.message ?? String(e)); }
  }, [openBinaryAt]);

  // Navigate to a function — pushes history (unless we're in back/forward)
  const navigateTo = useCallback((fn: FunctionInfo) => {
    setCurrent(fn);
    if (info) {
      // Stash the last-visited function for this binary so the next
      // session resumes here. Per-binary, keyed on absolute path.
      patchSettings({
        binaryState: {
          ...settings.binaryState,
          [info.path]: {
            ...(settings.binaryState[info.path] || {}),
            lastFunctionAddr: fn.addr,
          },
        },
      });
    }
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
  }, [history, histIdx, info, settings.binaryState, patchSettings]);

  // Bookmark the current function — toggles on if not already saved.
  // Bookmarks live per-binary in settings so they survive across
  // sessions and don't leak between unrelated targets.
  const currentBookmarks: Bookmark[] = useMemo(() => {
    if (!info) return [];
    return settings.binaryState[info.path]?.bookmarks ?? [];
  }, [info, settings.binaryState]);

  const updateBookmarks = useCallback((next: Bookmark[]) => {
    if (!info) return;
    patchSettings({
      binaryState: {
        ...settings.binaryState,
        [info.path]: {
          ...(settings.binaryState[info.path] || {}),
          bookmarks: next,
        },
      },
    });
  }, [info, settings.binaryState, patchSettings]);

  const toggleBookmark = useCallback((fn: FunctionInfo) => {
    const list = currentBookmarks;
    const idx = list.findIndex((b) => b.addr === fn.addr);
    if (idx >= 0) {
      updateBookmarks(list.filter((_, i) => i !== idx));
      setToast("bookmark removed");
    } else {
      updateBookmarks([...list, { addr: fn.addr }]);
      setToast("bookmarked");
    }
  }, [currentBookmarks, updateBookmarks]);

  const navBack = useCallback(() => {
    if (histIdx <= 0 || !info) return;
    const addr = history[histIdx - 1];
    const fn = fnByAddr.get(addr);
    if (!fn) return;
    navigatingRef.current = true;
    setHistIdx((i) => i - 1);
    setCurrent(fn);
  }, [histIdx, history, info, fnByAddr]);

  const navForward = useCallback(() => {
    if (histIdx >= history.length - 1 || !info) return;
    const addr = history[histIdx + 1];
    const fn = fnByAddr.get(addr);
    if (!fn) return;
    navigatingRef.current = true;
    setHistIdx((i) => i + 1);
    setCurrent(fn);
  }, [histIdx, history, info, fnByAddr]);

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
        if (diffOpen)       { setDiffOpen(false);      return; }
        if (emberApplyOpen) { setEmberApplyOpen(false); return; }
        if (pluginsPanelOpen) { setPluginsPanelOpen(false); return; }
        if (paletteOpen)    { setPaletteOpen(false);   return; }
        if (shortcutsOpen)  { setShortcutsOpen(false); return; }
        if (searchOpen)     { setSearchOpen(false);    return; }
        if (hexOpen)        { setHexOpen(false);       return; }
        if (symbolsOpen)    { setSymbolsOpen(false);   return; }
        if (bookmarksOpen)  { setBookmarksOpen(false); return; }
        if (identifyOpen)   { setIdentifyOpen(false);  return; }
        if (bulkRenameOpen) { setBulkRenameOpen(false); return; }
      }

      // Ctrl+Z: undo last annotation mutation. Goes through the ref so
      // the inner `undoLast` (declared further down) can be the actual
      // implementation without a forward-declaration error here.
      if (mod && !e.shiftKey && (e.key === "z" || e.key === "Z")) {
        if (info) { e.preventDefault(); undoRef.current(); }
        return;
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
      if (mod && (e.key === "u" || e.key === "U")) {
        if (info) { e.preventDefault(); setPluginsPanelOpen((o) => !o); }
        return;
      }
      // Ctrl+H — hex view; Ctrl+Shift+S — symbols & sections;
      // Ctrl+B — bookmarks panel; Ctrl+I — identification panel;
      // bare "b" — toggle bookmark on current.
      if (mod && !e.shiftKey && (e.key === "h" || e.key === "H")) {
        if (info) { e.preventDefault(); setHexOpen((o) => !o); }
        return;
      }
      if (mod && e.shiftKey && (e.key === "S")) {
        if (info) { e.preventDefault(); setSymbolsOpen((o) => !o); }
        return;
      }
      if (mod && (e.key === "b" || e.key === "B")) {
        if (info) { e.preventDefault(); setBookmarksOpen((o) => !o); }
        return;
      }
      if (mod && (e.key === "i" || e.key === "I")) {
        if (info) { e.preventDefault(); setIdentifyOpen((o) => !o); }
        return;
      }
      if (!inInput && !mod && !e.altKey && !e.shiftKey && (e.key === "b" || e.key === "B")) {
        if (current) { e.preventDefault(); toggleBookmark(current); }
        return;
      }
      if (mod && (e.key === "[" || e.key === "{")) { e.preventDefault(); navBack(); return; }
      if (mod && (e.key === "]" || e.key === "}")) { e.preventDefault(); navForward(); return; }

      // Cheat-sheet. `?` is Shift+/ on US layouts; gate on !inInput so
      // it doesn't fire mid-typing. The Shortcuts modal handles its own
      // close on `?` / Esc.
      if (!inInput && !mod && e.key === "?") {
        e.preventDefault();
        setShortcutsOpen((o) => !o);
        return;
      }

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

      // Ctrl+Shift+R: open bulk-rename modal. Mirrors the .ember
      // pattern-rename surface so users don't have to hand-edit a
      // script file for "rename every sub_*" style sweeps.
      if (mod && e.shiftKey && (e.key === "r" || e.key === "R")) {
        if (info) { e.preventDefault(); setBulkRenameOpen(true); }
        return;
      }

      // Ctrl+Shift+C: copy current code body to clipboard. Cheaper than
      // mouse-selecting a 2000-line pseudo-C dump and avoids the
      // line-number column polluting the result.
      if (mod && e.shiftKey && (e.key === "c" || e.key === "C")) {
        if (info && code) {
          e.preventDefault();
          navigator.clipboard.writeText(code).then(
            () => setToast(`copied ${view} as text`),
            () => setToast("clipboard unavailable"),
          );
        }
        return;
      }

      // Code-pane font zoom. Ctrl+= and Ctrl+- act on settings.codeFontSize
      // so the change persists; Ctrl+0 resets to the default. Both `=`
      // and `+` map to zoom-in because the unmodified key on US layouts
      // is `=`; Shift+= is `+` and many users still hit it that way.
      if (mod && !e.altKey && (e.key === "=" || e.key === "+")) {
        e.preventDefault();
        patchSettings({ codeFontSize: Math.min(24, settings.codeFontSize + 1) });
        return;
      }
      if (mod && !e.altKey && e.key === "-") {
        e.preventDefault();
        patchSettings({ codeFontSize: Math.max(9, settings.codeFontSize - 1) });
        return;
      }
      if (mod && !e.altKey && e.key === "0") {
        e.preventDefault();
        patchSettings({ codeFontSize: 12 });
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
  }, [info, paletteOpen, searchOpen, editing, callGraphOpen, stringsOpen, notesOpen, patchesOpen, pluginsPanelOpen, diffOpen, emberApplyOpen, patching, shortcutsOpen, hexOpen, symbolsOpen, bookmarksOpen, identifyOpen, bulkRenameOpen, navBack, navForward, current, toggleBookmark, settings.codeFontSize, patchSettings, code, view]);

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
    // Pass the VA, not the symbol name. Mangled C++ names can be
    // bound to several addresses (e.g. `.constprop.0.cold` clones
    // share the parent's symbol), and the CLI's --symbol then refuses
    // to guess. Address is always unique.
    loadFunction(current.addr, fetchView, { showBbLabels: settings.showBbLabels })
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
    // fnByAddr unions defined + imports — `info.functions` alone misses
    // calls to library symbols like `printf` that the user still wants
    // to jump to (the import row in the sidebar shows its PLT/GOT info).
    const match = fnByAddr.get(addr);
    if (match) navigateTo(match);
  }, [info, fnByAddr, navigateTo]);

  // Annotation mutations
  const writeAnnotations = useCallback(async (a: Annotations, opts?: { skipUndo?: boolean }) => {
    // Push current state to the undo stack BEFORE replacing it so
    // Ctrl+Z restores exactly what was visible. Cap the stack so
    // long-running sessions don't grow unbounded.
    if (!opts?.skipUndo) {
      undoStackRef.current.push(annotations);
      if (undoStackRef.current.length > 80) undoStackRef.current.shift();
    }
    setAnnotations(a);
    // Renames and signature changes flow into pseudo-C output via the
    // CLI's --annotations file, so cached function bodies are stale
    // after any mutation. Drop them so the next view reload picks up
    // the fresh names.
    clearRendererCaches();
    if (info) {
      setSaveState("saving");
      try {
        await saveAnnotations(info.path, a);
        setSaveState("saved");
        window.setTimeout(() => setSaveState((s) => s === "saved" ? "idle" : s), 1500);
      } catch {
        setSaveState("error");
      }
    }
  }, [info, annotations]);

  // Restore the previous annotations snapshot. The current state is
  // pushed onto a redo stack — but we keep this minimal (undo only)
  // since rename / note mutations are quick to redo by hand.
  const undoLast = useCallback(() => {
    const prev = undoStackRef.current.pop();
    if (!prev) {
      setToast("nothing to undo");
      return;
    }
    setAnnotations(prev);
    clearRendererCaches();
    if (info) {
      setSaveState("saving");
      saveAnnotations(info.path, prev)
        .then(() => {
          setSaveState("saved");
          window.setTimeout(() => setSaveState((s) => s === "saved" ? "idle" : s), 1500);
        })
        .catch(() => setSaveState("error"));
    }
    setToast("undone");
  }, [info]);

  // Keep the keyboard-handler ref pointed at the latest `undoLast`.
  useEffect(() => { undoRef.current = undoLast; }, [undoLast]);

  const cloneAnn = useCallback((): Annotations => ({
    renames:      { ...annotations.renames    },
    notes:        { ...annotations.notes      },
    signatures:   { ...annotations.signatures },
    fields:       { ...(annotations.fields     || {}) },
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
        fields:       { ...(annotations.fields || {}), ...(imp.fields || {}) },
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

  const handleImportCorpus = useCallback(async () => {
    if (!info) return;
    try {
      setToast("running corpus recognition...");
      const res = await importCorpusRenames({
        threshold: 0.85,
        minFnSize: 32,
        maxFnSize: 200000,
        l0Prefilter: true,
      });
      if (!res) return;
      clearRendererCaches();
      setAnnotations(res.annotations);
      setToast(`imported ${res.imported} corpus rename${res.imported === 1 ? "" : "s"}`);
    } catch (e: unknown) {
      setError(`Corpus import failed: ${(e as Error).message}`);
    }
  }, [info]);

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

  // Drag-and-drop: accept a binary path drop anywhere on the window.
  // Electron exposes the absolute path via dataTransfer.files[0].path,
  // which we route through the same `setBinary + openBinaryAt` chain
  // as the picker.
  const dragHandlers = useMemo(() => ({
    onDragOver: (e: React.DragEvent) => {
      if (e.dataTransfer.types.includes("Files")) {
        e.preventDefault();
        e.dataTransfer.dropEffect = "copy";
      }
    },
    onDrop: async (e: React.DragEvent) => {
      e.preventDefault();
      const file = e.dataTransfer.files[0];
      const dropped = (file as File & { path?: string })?.path;
      if (!dropped) return;
      try { await window.ember.setBinary(dropped); await openBinaryAt(dropped); }
      catch (err: unknown) { setError((err as Error).message); }
    },
  }), [openBinaryAt]);

  if (!info) {
    return (
      <div {...dragHandlers} style={{ height: "100%" }}>
        <Welcome
          onOpen={handleOpen}
          loading={loading}
          error={error}
          recents={recents}
          onOpenRecent={handleOpenRecent}
        />
        {releaseUpdate && (
          <ReleaseUpdatePopup
            status={releaseUpdate}
            onDismiss={() => dismissReleaseUpdate(releaseUpdate)}
          />
        )}
      </div>
    );
  }

  return (
    <div {...dragHandlers} style={{ display: "flex", flexDirection: "column", height: "100vh" }}>
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
          {history.length > 1 && (
            <NavHistoryDropdown
              history={history}
              histIdx={histIdx}
              fnByAddr={fnByAddr}
              annotations={annotations}
              onPick={(addr) => {
                const fn = fnByAddr.get(addr);
                if (!fn) return;
                navigatingRef.current = true;
                setHistIdx(history.indexOf(addr));
                setCurrent(fn);
              }}
            />
          )}
          <span style={{ color: C.text, fontWeight: 600 }}>Ember</span>
          <span style={{ fontFamily: serif, fontStyle: "italic", color: C.textFaint }}>
            / {info.path.split("/").pop()}
          </span>
          <SavePip state={saveState} />
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <button
            onClick={() => setHexOpen(true)}
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
            title="Hex view (Ctrl+H)"
            aria-label="Open hex view"
          >
            <span>hex</span>
            <span style={{ color: C.textFaint }}>⌃H</span>
          </button>
          <button
            onClick={() => setSymbolsOpen(true)}
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
            title="Symbols & sections (Ctrl+Shift+S)"
            aria-label="Open symbols and sections"
          >
            <span>symbols</span>
            <span style={{ color: C.textFaint }}>⇧⌃S</span>
          </button>
          <button
            onClick={() => setBookmarksOpen(true)}
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
            title="Bookmarks (Ctrl+B)"
            aria-label="Open bookmarks panel"
          >
            <span>bookmarks</span>
            {currentBookmarks.length > 0 && (
              <span style={{ color: C.accent }}>{currentBookmarks.length}</span>
            )}
            <span style={{ color: C.textFaint }}>⌃B</span>
          </button>
          <button
            onClick={() => setBulkRenameOpen(true)}
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
            title="Bulk rename (Ctrl+Shift+R)"
            aria-label="Open bulk rename dialog"
          >
            <span>rename</span>
            <span style={{ color: C.textFaint }}>⇧⌃R</span>
          </button>
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
            aria-label="Open strings"
          >
            <span>strings</span>
            <span style={{ color: C.textFaint }}>⌃T</span>
          </button>
          <button
            onClick={() => setIdentifyOpen(true)}
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
            title="Identification (Ctrl+I)"
            aria-label="Open identification panel"
          >
            <span>identify</span>
            <span style={{ color: C.textFaint }}>⌃I</span>
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
            onClick={() => setPluginsPanelOpen(true)}
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
            title="Plugin panels (Ctrl+U)"
          >
            <span>plugins</span>
            <span style={{ color: C.textFaint }}>⌃U</span>
          </button>
          <button
            onClick={() => setAgentPanelOpen(true)}
            style={{
              padding: "4px 10px",
              fontFamily: mono, fontSize: 10,
              color: C.text,
              background: "transparent",
              border: `1px solid ${C.accent}`,
              borderRadius: 4,
              display: "flex", alignItems: "center", gap: 6,
              ...({ WebkitAppRegion: "no-drag" } as React.CSSProperties),
            }}
            title="Agent harness — swarm intel, disputes, promote"
          >
            <span style={{ color: C.accent }}>◈</span>
            <span>agentic</span>
          </button>
          <button
            onClick={() => setDiffOpen(true)}
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
            title="Diff against an older binary"
          >
            <span>diff</span>
          </button>
          <button
            onClick={() => setEmberApplyOpen(true)}
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
            title="Apply a .ember script"
          >
            <span>apply…</span>
          </button>
          <button
            data-tutorial="jump"
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
            {info.arch.toUpperCase()} · {info.endian.toUpperCase()} · {info.format.toUpperCase()}
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
          functionsLoading={functionsLoading}
          currentAddr={current?.addrNum ?? null}
          width={settings.sidebarWidth}
          onSelect={(f) => navigateTo(f)}
          onOpen={(f, v) => { navigateTo(f); setView(v); }}
          onReopen={handleOpen}
          onRename={(fn) => setEditing({ fn, mode: "rename" })}
          onAddNote={(fn) => setEditing({ fn, mode: "note" })}
          onEditSignature={(fn) => setEditing({ fn, mode: "signature" })}
          onExport={handleExport}
          onImport={handleImport}
          onImportCorpus={handleImportCorpus}
        />
        <ResizeHandle
          edge="right"
          width={settings.sidebarWidth}
          min={220}
          max={600}
          ariaLabel="Resize sidebar"
          onChange={(px) => setSettings((s) => ({ ...s, sidebarWidth: px }))}
          onCommit={() => saveSettings(settings)}
        />
        <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
          {packedWarning && packedDismissedFor !== info.path && (
            <div
              style={{
                padding: "8px 16px",
                background: "rgba(184,154,58,0.08)",
                borderBottom: `1px solid rgba(184,154,58,0.25)`,
                display: "flex", alignItems: "center", gap: 12,
                fontFamily: sans, fontSize: 11.5,
                color: C.textWarm,
                flexShrink: 0,
              }}
            >
              <span style={{ color: C.yellow, fontFamily: mono, fontSize: 10, letterSpacing: 1 }}>
                HEADS UP
              </span>
              <span style={{ flex: 1, lineHeight: 1.4 }}>
                {packedWarning}
              </span>
              {!forceFullAnalysisFor.has(info.path) && (
                <button
                  onClick={() => {
                    const path = info.path;
                    setForceFullAnalysisFor((prev) => {
                      const next = new Set(prev);
                      next.add(path);
                      return next;
                    });
                    // Re-spawn the load with --full-analysis. Banner stays
                    // up so the user can still dismiss after the (slow)
                    // run finishes.
                    openBinaryAt(path);
                  }}
                  title="Re-run with full call-graph walk (slow on packed binaries)"
                  style={{
                    fontFamily: mono, fontSize: 10, color: C.yellow,
                    padding: "2px 8px", borderRadius: 3,
                    border: `1px solid rgba(184,154,58,0.4)`,
                  }}
                >run full analysis</button>
              )}
              <button
                onClick={() => setPackedDismissedFor(info.path)}
                title="Dismiss for this session"
                style={{
                  fontFamily: mono, fontSize: 10, color: C.textFaint,
                  padding: "2px 8px", borderRadius: 3,
                }}
              >dismiss</button>
            </div>
          )}
          <Breadcrumb
            history={history}
            histIdx={histIdx}
            fnByAddr={fnByAddr}
            annotations={annotations}
            onJumpTo={(idx) => {
              const addr = history[idx];
              const fn = fnByAddr.get(addr);
              if (!fn) return;
              navigatingRef.current = true;
              setHistIdx(idx);
              setCurrent(fn);
            }}
          />
          {current
            ? <FunctionHeader
                current={current}
                annotations={annotations}
                arities={arities}
                code={code}
                view={view}
                onToast={setToast}
              />
            : <SkelFunctionHeader />
          }
          <Tabs view={view} setView={setView} onIdentify={() => setIdentifyOpen(true)} />
          {error ? (
            <ErrorView message={error} currentView={view} onSwitchView={setView} />
          ) : !current ? (
            <SkelCode lines={28} />
          ) : loading && !code ? (
            <SkelCode lines={28} />
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
        {xrefsOpen && (
          <ResizeHandle
            edge="left"
            width={settings.xrefsWidth}
            min={200}
            max={520}
            ariaLabel="Resize references panel"
            onChange={(px) => setSettings((s) => ({ ...s, xrefsWidth: px }))}
            onCommit={() => saveSettings(settings)}
          />
        )}
        <XrefsPanel
          info={info}
          current={current}
          xrefs={xrefs}
          annotations={annotations}
          width={settings.xrefsWidth}
          loading={pending.has("xrefs")}
          onSelect={(f) => navigateTo(f)}
          onToggle={() => setXrefsOpen((x) => !x)}
          open={xrefsOpen}
        />
      </div>

      <StatusBar current={current} view={view} lines={lines} loading={loading} pending={pending} />

      {paletteOpen && (
        <CommandPalette
          functions={paletteFunctions}
          annotations={annotations}
          onSelect={(f) => navigateTo(f)}
          onJumpAddress={(v) => {
            // Palette accepts hex addresses that don't match a function
            // start — open the hex view at the typed vaddr instead of
            // silently doing nothing.
            setHexInitialVaddr(v);
            setHexOpen(true);
          }}
          onClose={() => setPaletteOpen(false)}
        />
      )}
      {settingsOpen && (
        <SettingsPanel
          settings={settings}
          onChange={updateSettings}
          binaryPath={info?.path ?? null}
          onAnnotationsApplied={(a) => {
            clearRendererCaches();
            setAnnotations(a);
          }}
          onReplayTutorial={() => {
            setSettingsOpen(false);
            setTutorialOpen(true);
          }}
          onClose={() => setSettingsOpen(false)}
        />
      )}
      {tutorialOpen && (
        <Tutorial
          onClose={() => {
            setTutorialOpen(false);
            patchSettings({ seenTutorial: true });
          }}
        />
      )}
      {shortcutsOpen && (
        <Shortcuts onClose={() => setShortcutsOpen(false)} />
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
      {pluginsPanelOpen && (
        <PluginsPanelView
          info={info}
          onSelect={(f) => navigateTo(f)}
          onClose={() => setPluginsPanelOpen(false)}
        />
      )}
      {agentPanelOpen && (
        <AgentPanel
          binaryPath={info?.path ?? null}
          onClose={() => setAgentPanelOpen(false)}
          onNavigate={(addr) => {
            if (!info) return;
            const num = parseInt(addr, 16);
            if (Number.isNaN(num)) return;
            const fn = fnByAddr.get(num) ?? fnByAddr.get(fnAddrByName.get(addr) ?? -1);
            if (fn) {
              navigateTo(fn);
              setAgentPanelOpen(false);
            }
          }}
        />
      )}
      {diffOpen && info && (
        <DiffView
          info={info}
          fnByAddr={fnByAddr}
          onSelect={(f) => navigateTo(f)}
          onClose={() => setDiffOpen(false)}
        />
      )}
      {emberApplyOpen && info && (
        <EmberScriptView
          info={info}
          annotations={annotations}
          onApplied={(next) => {
            // The IPC handler already merged + saved to the sidecar;
            // adopt the returned object directly and bust render caches
            // so the freshly-applied renames/sigs/notes show up
            // immediately in the open view.
            clearRendererCaches();
            setAnnotations(next);
          }}
          onClose={() => setEmberApplyOpen(false)}
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
          asmEnabled={info.arch === "x86_64"}
          asmDisabledReason={info.arch === "x86_64"
            ? undefined
            : `Assembly patching is x86-64 only right now; ${info.arch} is limited to raw hex edits.`}
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
      {hexOpen && (
        <HexView
          info={info}
          current={current}
          initialVaddr={hexInitialVaddr}
          onClose={() => { setHexOpen(false); setHexInitialVaddr(null); }}
        />
      )}
      {symbolsOpen && (
        <SymbolsView
          info={info}
          annotations={annotations}
          onSelect={(f) => navigateTo(f)}
          onClose={() => setSymbolsOpen(false)}
        />
      )}
      {bookmarksOpen && (
        <BookmarksPanel
          info={info}
          bookmarks={currentBookmarks}
          annotations={annotations}
          onSelect={(f) => { navigateTo(f); setBookmarksOpen(false); }}
          onRemove={(addr) => updateBookmarks(currentBookmarks.filter((b) => b.addr !== addr))}
          onRename={(addr, label) => updateBookmarks(currentBookmarks.map(
            (b) => b.addr === addr ? { ...b, label: label || undefined } : b))}
          onClose={() => setBookmarksOpen(false)}
        />
      )}
      {identifyOpen && (
        <IdentifyPanel
          info={info}
          hits={identifyHits}
          loading={identifyLoading}
          annotations={annotations}
          onSelect={(f) => { navigateTo(f); setIdentifyOpen(false); }}
          onClose={() => setIdentifyOpen(false)}
        />
      )}
      {bulkRenameOpen && (
        <BulkRenameDialog
          info={info}
          annotations={annotations}
          onApply={(next, count) => {
            writeAnnotations(next);
            setBulkRenameOpen(false);
            setToast(`renamed ${count} function${count === 1 ? "" : "s"}`);
          }}
          onClose={() => setBulkRenameOpen(false)}
        />
      )}
      {toast && <Toast message={toast} onDone={() => setToast(null)} />}
      {releaseUpdate && (
        <ReleaseUpdatePopup
          status={releaseUpdate}
          onDismiss={() => dismissReleaseUpdate(releaseUpdate)}
        />
      )}
    </div>
  );
}

function SavePip(props: { state: "idle" | "saving" | "saved" | "error" }) {
  if (props.state === "idle") return null;
  const colour = props.state === "error" ? C.red
                 : props.state === "saving" ? C.yellow
                 : C.green;
  const label  = props.state === "error" ? "save failed"
                 : props.state === "saving" ? "saving…"
                 : "saved";
  return (
    <span
      title={label}
      role="status"
      aria-live="polite"
      style={{
        display: "inline-flex", alignItems: "center", gap: 6,
        fontFamily: mono, fontSize: 9, color: colour,
        animation: props.state === "saving" ? "pulse 1.4s ease-in-out infinite" : undefined,
      }}
    >
      <span style={{
        width: 6, height: 6, borderRadius: 3, background: colour,
      }} />
      <span>{label}</span>
    </span>
  );
}

function Toast(props: { message: string; onDone: () => void }) {
  useEffect(() => {
    const t = window.setTimeout(props.onDone, 1700);
    return () => window.clearTimeout(t);
  }, [props]);
  return (
    <div
      role="status"
      aria-live="polite"
      style={{
        position: "fixed",
        bottom: 36, left: "50%",
        transform: "translateX(-50%)",
        padding: "6px 14px",
        background: C.bgAlt,
        border: `1px solid ${C.borderStrong}`,
        borderRadius: 999,
        fontFamily: mono, fontSize: 11, color: C.textWarm,
        boxShadow: "0 8px 24px rgba(0,0,0,0.35)",
        zIndex: 2300,
        animation: "fadeIn .15s ease-out",
      }}
    >{props.message}</div>
  );
}

function ReleaseUpdatePopup(props: {
  status: ReleaseUpdateStatus;
  onDismiss: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const notes = (props.status.notes || "")
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean)
    .slice(0, 3);

  const onUpdate = async () => {
    setBusy(true);
    setMsg("");
    try {
      const res = await downloadAndInstallReleaseUpdate();
      if (res.ok) {
        setMsg(res.message || "Update downloaded.");
        props.onDismiss();
      } else {
        setMsg(res.error || "Update failed.");
      }
    } catch (e: any) {
      setMsg(e?.message ?? String(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div
      style={{
        position: "fixed",
        top: 48,
        right: 16,
        width: 320,
        padding: "12px 14px",
        background: C.bgAlt,
        border: `1px solid ${C.borderStrong}`,
        borderRadius: 8,
        boxShadow: "0 16px 40px rgba(0,0,0,0.45)",
        zIndex: 2200,
        animation: "fadeIn .14s ease-out",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <span style={{
          width: 8, height: 8, borderRadius: 4, background: C.green, flexShrink: 0,
        }} />
        <span style={{ fontFamily: sans, fontSize: 12, color: C.text, fontWeight: 600 }}>
          Update available
        </span>
        <button
          onClick={props.onDismiss}
          style={{
            marginLeft: "auto",
            color: C.textFaint,
            fontFamily: mono,
            fontSize: 11,
            cursor: "pointer",
          }}
          aria-label="Dismiss update popup"
          title="Dismiss"
        >×</button>
      </div>
      <div style={{
        marginTop: 6,
        fontFamily: serif,
        fontStyle: "italic",
        fontSize: 11,
        color: C.textFaint,
      }}>
        Ember {props.status.latestVersion} is available. You’re on {props.status.currentVersion}.
      </div>
      <div style={{
        marginTop: 8,
        display: "flex",
        alignItems: "center",
        gap: 8,
        fontFamily: mono,
        fontSize: 10,
        color: C.textMuted,
        flexWrap: "wrap",
      }}>
        {props.status.releaseName && <span>{props.status.releaseName}</span>}
        {props.status.assetName && <span style={{ color: C.accent }}>{props.status.assetName}</span>}
      </div>
      {notes.length > 0 && (
        <div style={{
          marginTop: 8,
          display: "flex",
          flexDirection: "column",
          gap: 3,
          fontFamily: serif,
          fontStyle: "italic",
          fontSize: 11,
          color: C.textFaint,
        }}>
          {notes.map((line, i) => <span key={i}>{line}</span>)}
        </div>
      )}
      {msg && (
        <div style={{
          marginTop: 8,
          fontFamily: mono,
          fontSize: 10,
          color: C.textMuted,
        }}>
          {msg}
        </div>
      )}
      <div style={{ marginTop: 10, display: "flex", gap: 8 }}>
        <button
          onClick={onUpdate}
          disabled={busy}
          style={{
            padding: "5px 10px",
            background: busy ? C.bgMuted : C.accent,
            border: `1px solid ${busy ? C.border : C.accent}`,
            borderRadius: 4,
            color: busy ? C.textMuted : "#fff",
            fontFamily: mono,
            fontSize: 10,
            cursor: busy ? "not-allowed" : "pointer",
          }}
        >{busy ? "downloading…" : "update"}</button>
        <button
          onClick={props.onDismiss}
          style={{
            padding: "5px 10px",
            background: "transparent",
            border: `1px solid ${C.border}`,
            borderRadius: 4,
            color: C.textMuted,
            fontFamily: mono,
            fontSize: 10,
            cursor: "pointer",
          }}
        >dismiss</button>
      </div>
    </div>
  );
}

// Popover that lists the navigation history with the current entry
// marked. Lets the user jump arbitrarily far in either direction
// without spamming Alt+arrow. Closes on outside click / Esc.
function NavHistoryDropdown(props: {
  history: number[];
  histIdx: number;
  fnByAddr: Map<number, FunctionInfo>;
  annotations: Annotations;
  onPick: (addr: number) => void;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onMouseDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    window.addEventListener("mousedown", onMouseDown, true);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("mousedown", onMouseDown, true);
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);
  return (
    <div ref={ref} style={{ position: "relative" }}>
      <button
        onClick={() => setOpen((o) => !o)}
        title="Navigation history"
        aria-label="Open navigation history"
        style={{
          width: 18, height: 22,
          display: "flex", alignItems: "center", justifyContent: "center",
          color: open ? C.text : C.textMuted,
          background: open ? C.bgMuted : "transparent",
          borderRadius: 3,
          fontSize: 9,
          cursor: "pointer",
          ...({ WebkitAppRegion: "no-drag" } as React.CSSProperties),
        }}
      >▾</button>
      {open && (
        <div style={{
          position: "absolute",
          top: 26, left: 0,
          minWidth: 280, maxWidth: 460,
          maxHeight: 320, overflowY: "auto",
          background: C.bgAlt,
          border: `1px solid ${C.borderStrong}`,
          borderRadius: 6,
          boxShadow: "0 12px 40px rgba(0,0,0,0.5)",
          zIndex: 1500,
          padding: 4,
        }}>
          <div style={{
            padding: "6px 10px",
            fontFamily: sans, fontSize: 10, fontWeight: 600,
            color: C.textMuted,
            textTransform: "uppercase", letterSpacing: 0.8,
            borderBottom: `1px solid ${C.border}`,
            marginBottom: 4,
          }}>navigation history</div>
          {props.history.slice().reverse().map((addr, ri) => {
            const i = props.history.length - 1 - ri;
            const isCurrent = i === props.histIdx;
            const fn = props.fnByAddr.get(addr);
            const name = fn ? displayName(fn, props.annotations) : `0x${addr.toString(16)}`;
            return (
              <button
                key={`${addr}-${i}`}
                onClick={() => { props.onPick(addr); setOpen(false); }}
                disabled={!fn}
                style={{
                  width: "100%",
                  display: "flex", alignItems: "center", gap: 10,
                  padding: "6px 10px",
                  borderRadius: 4,
                  background: isCurrent ? C.bgDark : "transparent",
                  border: `1px solid ${isCurrent ? C.borderStrong : "transparent"}`,
                  textAlign: "left",
                  cursor: fn ? "pointer" : "default",
                  opacity: fn ? 1 : 0.5,
                }}
                onMouseEnter={(e) => {
                  if (!isCurrent && fn) (e.currentTarget as HTMLElement).style.background = C.bgMuted;
                }}
                onMouseLeave={(e) => {
                  if (!isCurrent) (e.currentTarget as HTMLElement).style.background = "transparent";
                }}
              >
                <span style={{
                  width: 10, color: isCurrent ? C.accent : C.textFaint,
                  fontFamily: mono, fontSize: 10,
                }}>{isCurrent ? "›" : ""}</span>
                <span style={{
                  fontFamily: mono, fontSize: 10,
                  color: isCurrent ? C.accent : C.textFaint,
                  width: 84, flexShrink: 0,
                  overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                }}>0x{addr.toString(16)}</span>
                <span style={{
                  flex: 1, minWidth: 0,
                  fontFamily: sans, fontSize: 12,
                  color: isCurrent ? C.text : C.textWarm,
                  overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                }}>{name}</span>
              </button>
            );
          })}
        </div>
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
  code: string;
  onToast: (msg: string) => void;
  view: ViewKind;
}) {
  const c = props.current;
  const [copied, setCopied] = useState(false);
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
      <span
        title={c.addr}
        style={{ fontFamily: mono, fontSize: 11, color: C.accent, letterSpacing: .5 }}
      >
        {c.addr.replace(/^0x0+(?=.)/, "0x")}
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
      <div style={{ flex: 1 }} />
      <button
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(props.code);
            setCopied(true);
            props.onToast(`copied ${props.view} as text`);
            setTimeout(() => setCopied(false), 1200);
          } catch {
            props.onToast("clipboard unavailable");
          }
        }}
        disabled={!props.code}
        title="Copy current view as text (Ctrl+Shift+C)"
        aria-label="Copy current view as text"
        style={{
          padding: "3px 9px",
          fontFamily: mono, fontSize: 10,
          color: copied ? C.accent : C.textMuted,
          background: C.bgMuted,
          border: `1px solid ${C.border}`,
          borderRadius: 4,
          cursor: props.code ? "pointer" : "default",
          opacity: props.code ? 1 : 0.4,
        }}
      >{copied ? "copied" : "copy"}</button>
    </div>
  );
}
