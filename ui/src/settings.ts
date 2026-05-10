// Per-renderer-session settings, persisted in localStorage so they
// survive reloads. UI-side knobs only — the backend has its own
// flag-driven config and gets the relevant bits passed through with
// each CLI invocation.
//
// Keep this file dependency-free (no React, no api imports) so it can
// be loaded synchronously during App startup before anything else
// initializes — the initial state of components like CfgGraph reads
// from here.

const STORAGE_KEY = "ember.settings.v1";
const DEFAULT_CODE_FONT_FAMILY = "'DejaVu Sans Mono','Noto Sans Mono','Cascadia Mono','Cascadia Code','JetBrains Mono','SF Mono',ui-monospace,Menlo,Consolas,monospace";
const LEGACY_CODE_FONT_FAMILIES = new Set([
  "'JetBrains Mono','SF Mono','Fira Code',monospace",
  "'SF Mono','Cascadia Code','JetBrains Mono','Fira Code',ui-monospace,Menlo,Consolas,monospace",
]);

function clampNumber(value: unknown, fallback: number, min: number, max: number): number {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

// Per-binary view state: which function was last open, scroll position,
// view mode, plus user bookmarks. Keyed by absolute binary path so
// switching back to a previous binary restores where you were.
export type PerBinaryState = {
  lastFunctionAddr?: string;
  lastView?: "pseudo" | "asm" | "cfg" | "ir" | "ssa";
  bookmarks?: { addr: string; label?: string }[];
};

export type ThemeMode = "warm" | "dark" | "light";

export type AppSettings = {
  // CFG view's default body mode. The graph itself has a per-tab
  // toggle that overrides this for the current selection.
  cfgDefaultMode: "pseudo" | "asm";
  // Pass --labels to the CLI so pseudo-C output carries `// bb_xxxx`
  // marker comments. Cluttery for day-to-day reading; useful when
  // cross-referencing a function with its CFG view.
  showBbLabels: boolean;
  // Pixel font size for code panes (pseudo, IR, asm, etc.). Doesn't
  // affect CFG graph node bodies — those are sized by the layout
  // algorithm and trying to scale them breaks layout reasoning.
  codeFontSize: number;
  // Monospace font family for code panes. Free-form so users can pin a
  // locally-installed font; we fall back to the system stack if the
  // chosen family isn't available.
  codeFontFamily: string;
  // Color theme. "warm" = the original (charcoal + earth tones).
  // "dark" = cooler near-black. "light" = parchment.
  theme: ThemeMode;
  // Sidebar width in pixels (drag handle on the right edge persists).
  sidebarWidth: number;
  // References panel width in pixels (drag handle on its left edge).
  xrefsWidth: number;
  // Poll GitHub Releases and surface a small notice when a newer tagged
  // app release exists.
  releaseUpdatePopup: boolean;
  // Latest dismissed / handled release tag.
  seenReleaseTag: string;
  // First-run tour. Set when the user finishes (or dismisses) the
  // coach-marks tour that fires the first time a binary is opened.
  // Replay button in Settings → Help clears this back to false.
  seenTutorial: boolean;
  // Discord Rich Presence. On by default in privacy mode (binary +
  // function names suppressed) — broadcasts only that the user is
  // running Ember. Toggle off entirely in settings, or flip
  // discordHideBinaryName off to opt in to sharing what's open.
  discordRichPresence: boolean;
  // Suppress the binary file name and function name when broadcasting;
  // on by default to make Rich Presence safe-by-default. When off, the
  // binary file name and current function are visible to friends.
  discordHideBinaryName: boolean;
  // Last binary opened — restored automatically on next launch unless
  // the file has been moved or deleted.
  lastBinary: string;
  // Per-binary view state (last function, bookmarks, ...).
  binaryState: Record<string, PerBinaryState>;
  // Rebase display addresses: subtract the binary's preferred_load_base
  // and add this value. Default 0x0 means addresses display as if the
  // binary were loaded at 0x0 (RVA mode). Set to the actual load base
  // (e.g. "0x400000") to keep original VAs. Takes effect immediately.
  rebaseAddr: string;  // hex string like "0x0" or "0x400000"
  // Resume the last binary on launch. Off by default for first-run users
  // since they may want to choose. Becomes default-on after first open.
  resumeOnLaunch: boolean;
};

export const DEFAULT_SETTINGS: AppSettings = {
  cfgDefaultMode: "pseudo",
  showBbLabels:   false,
  codeFontSize:   12,
  codeFontFamily: DEFAULT_CODE_FONT_FAMILY,
  theme:          "warm",
  sidebarWidth:   288,
  xrefsWidth:     260,
  releaseUpdatePopup: true,
  seenReleaseTag: "",
  seenTutorial:   false,
  discordRichPresence:   true,
  discordHideBinaryName: true,
  lastBinary:     "",
  binaryState:    {},
  rebaseAddr:     "0x0",
  resumeOnLaunch: true,
};

function normalizeSettings(s: AppSettings): AppSettings {
  return {
    ...s,
    codeFontSize: clampNumber(s.codeFontSize, DEFAULT_SETTINGS.codeFontSize, 9, 24),
    sidebarWidth: clampNumber(s.sidebarWidth, DEFAULT_SETTINGS.sidebarWidth, 240, 520),
    xrefsWidth: clampNumber(s.xrefsWidth, DEFAULT_SETTINGS.xrefsWidth, 220, 520),
  };
}

export function loadSettings(): AppSettings {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return normalizeSettings({ ...DEFAULT_SETTINGS });
    const parsed = JSON.parse(raw) as Partial<AppSettings>;
    // Merge with defaults so missing keys (newer settings vs older
    // saved file) get sensible values instead of `undefined`.
    const merged = { ...DEFAULT_SETTINGS, ...parsed };
    if (LEGACY_CODE_FONT_FAMILIES.has(merged.codeFontFamily)) {
      merged.codeFontFamily = DEFAULT_CODE_FONT_FAMILY;
    }
    return normalizeSettings(merged);
  } catch {
    return normalizeSettings({ ...DEFAULT_SETTINGS });
  }
}

export function saveSettings(s: AppSettings): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(s));
  } catch {
    // localStorage full or disabled — settings are best-effort, the
    // user's session continues with the in-memory state regardless.
  }
}
