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
  // Poll GitHub Releases and surface a small notice when a newer tagged
  // app release exists.
  releaseUpdatePopup: boolean;
  // Latest dismissed / handled release tag.
  seenReleaseTag: string;
};

export const DEFAULT_SETTINGS: AppSettings = {
  cfgDefaultMode: "pseudo",
  showBbLabels:   false,
  codeFontSize:   12,
  releaseUpdatePopup: true,
  seenReleaseTag: "",
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
