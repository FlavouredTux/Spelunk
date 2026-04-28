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
  // Resume the last binary on launch. Off by default for first-run users
  // since they may want to choose. Becomes default-on after first open.
  resumeOnLaunch: boolean;
};

export const DEFAULT_SETTINGS: AppSettings = {
  cfgDefaultMode: "pseudo",
  showBbLabels:   false,
  codeFontSize:   12,
  codeFontFamily: "'JetBrains Mono','SF Mono','Fira Code',monospace",
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
  resumeOnLaunch: true,
};

export function loadSettings(): AppSettings {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { ...DEFAULT_SETTINGS };
    const parsed = JSON.parse(raw) as Partial<AppSettings>;
    // Merge with defaults so missing keys (newer settings vs older
    // saved file) get sensible values instead of `undefined`.
    return { ...DEFAULT_SETTINGS, ...parsed };
  } catch {
    return { ...DEFAULT_SETTINGS };
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
