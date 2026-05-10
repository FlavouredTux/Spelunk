import type { ThemeMode } from "./settings";

// Three palettes. "warm" is the original assistant-ish charcoal +
// earth tones. "dark" is a cooler near-black for users who want a
// less brown-tinged look. "light" is parchment for daytime.
type Palette = {
  bg: string; bgAlt: string; bgMuted: string; bgInput: string; bgDark: string;
  text: string; textWarm: string; textMuted: string; textFaint: string;
  accent: string; accentHover: string; accentDim: string;
  blue: string; blueDim: string; green: string; red: string; yellow: string; violet: string;
  border: string; borderStrong: string;
};

const WARM: Palette = {
  bg:           "#141413",
  bgAlt:        "#1f1e1d",
  bgMuted:      "#262524",
  bgInput:      "#1f1e1d",
  bgDark:       "#302f2d",

  text:         "#ede9df",
  textWarm:     "#d4cfc2",
  textMuted:    "#aaa59a",
  textFaint:    "#777168",

  accent:       "#d97757",
  accentHover:  "#e8896b",
  accentDim:    "rgba(217,119,87,0.12)",

  blue:         "#6a9bcc",
  blueDim:      "rgba(106,155,204,0.12)",
  green:        "#788c5d",
  red:          "#c75d3a",
  yellow:       "#b89a3a",
  violet:       "#8b7bb5",

  border:       "rgba(255,255,245,0.12)",
  borderStrong: "rgba(255,255,245,0.22)",
};

const DARK: Palette = {
  bg:           "#0e0f12",
  bgAlt:        "#16181c",
  bgMuted:      "#1d2026",
  bgInput:      "#16181c",
  bgDark:       "#252830",

  text:         "#e8eaed",
  textWarm:     "#c8ccd1",
  textMuted:    "#80858d",
  textFaint:    "#52565d",

  accent:       "#5fa9c7",
  accentHover:  "#7cbcd8",
  accentDim:    "rgba(95,169,199,0.14)",

  blue:         "#7aa6d8",
  blueDim:      "rgba(122,166,216,0.12)",
  green:        "#7fb286",
  red:          "#d36a6a",
  yellow:       "#cfb04d",
  violet:       "#9c8bca",

  border:       "rgba(255,255,255,0.08)",
  borderStrong: "rgba(255,255,255,0.15)",
};

const LIGHT: Palette = {
  bg:           "#faf7f1",
  bgAlt:        "#f1ebde",
  bgMuted:      "#e8e0cf",
  bgInput:      "#f6f0e2",
  bgDark:       "#d8cdb6",

  text:         "#2a261f",
  textWarm:     "#403a2d",
  textMuted:    "#76705f",
  textFaint:    "#9c9784",

  accent:       "#b85c3a",
  accentHover:  "#a14e2f",
  accentDim:    "rgba(184,92,58,0.12)",

  blue:         "#3b6a99",
  blueDim:      "rgba(59,106,153,0.12)",
  green:        "#5e7842",
  red:          "#a44a2c",
  yellow:       "#977a25",
  violet:       "#6b5a93",

  border:       "rgba(0,0,0,0.10)",
  borderStrong: "rgba(0,0,0,0.18)",
};

const PALETTES: Record<ThemeMode, Palette> = {
  warm:  WARM,
  dark:  DARK,
  light: LIGHT,
};

// Mutable export — App swaps the underlying object's fields when the
// theme changes so existing imports of `C` continue to read the live
// values without every component needing to re-subscribe.
export const C: Palette = { ...WARM };

export function applyTheme(mode: ThemeMode): void {
  const next = PALETTES[mode] || WARM;
  for (const k of Object.keys(C) as (keyof Palette)[]) {
    C[k] = next[k];
  }
  // Re-inject the global stylesheet so scrollbar / selection colors
  // pick up the new palette.
  const tag = document.getElementById("ember-globals");
  if (tag) tag.textContent = makeGlobalCSS();
}

export const sans  = "system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',Ubuntu,Cantarell,'Noto Sans',sans-serif";
export const serif = "Georgia,'Times New Roman',serif";
// Default mono stack. App overrides at runtime when the user picks a
// different font family in Settings; we expose a setter so the rest of
// the codebase can keep importing `mono` as a const expression.
export let mono = "'DejaVu Sans Mono','Noto Sans Mono','Cascadia Mono','Cascadia Code','JetBrains Mono','SF Mono',ui-monospace,Menlo,Consolas,monospace";
export function setMonoFamily(family: string): void {
  if (typeof family === "string" && family.trim()) mono = family;
  // Re-inject globalCSS so any rule that hard-references the mono var
  // picks up the new family on next mount. Components that read `mono`
  // at render time (most of them) automatically reflect the change on
  // the next React update.
  const tag = document.getElementById("ember-globals");
  if (tag) tag.textContent = makeGlobalCSS();
}

// Syntax-highlight palette
export const SH = {
  keyword:    "#c28b70",
  type:       "#b0a486",
  number:     "#9bb5c1",
  string:     "#a5b37f",
  comment:    "#777168",
  func:       "#d97757",
  xref:       "#d97757",
  addr:       "#87867f",
  // Operators (`+ - * / % < > = ! & | ^ ~ ? :`) get a warmer, slightly
  // more present shade — they carry meaning and were previously
  // indistinguishable from punctuation. `punct` (`, ; .`) and `bracket`
  // (`{ } [ ] ( )`) stay gray, with brackets a touch lighter so deep
  // nesting reads as structure rather than fog.
  op:         "#a39786",
  punct:      "#6f6e69",
  bracket:    "#9c958a",
  reg:        "#c9c2af",
  flag:       "#b0a486",
  label:      "#8b7bb5",
  arg:        "#b5a0d8",   // function params: a1, a2, ...
  bound:      "#c8a87a",   // call-return locals: r_fopen, r_strlen, ...
  // Faint vertical guides that mark each level of nesting in pseudo-C
  // bodies — same family as borders so they fade into the background
  // unless you're actively reading structure.
  indent:     "rgba(255,255,245,0.06)",
};

function makeGlobalCSS(): string {
  return `
  * { margin:0; padding:0; box-sizing:border-box; }
  html, body, #root { height:100%; background:${C.bg}; overflow:hidden; }
  body { font-family:${sans}; color:${C.text};
         -webkit-font-smoothing:subpixel-antialiased; -moz-osx-font-smoothing:auto;
         text-rendering:optimizeLegibility; font-synthesis:none;
         -webkit-user-select:none; user-select:none; }
  .sel { -webkit-user-select:text; user-select:text; }
  ::selection { background:${C.accent}; color:#fff; }
  ::-webkit-scrollbar { width:8px; height:8px; }
  ::-webkit-scrollbar-track { background:transparent; }
  ::-webkit-scrollbar-thumb { background:${C.border}; border-radius:4px; }
  ::-webkit-scrollbar-thumb:hover { background:${C.borderStrong}; }
  button { font-family:${sans}; background:none; border:none; color:inherit; cursor:pointer; line-height:1.2; }
  input { font-family:${sans}; background:none; border:none; color:inherit; outline:none; line-height:1.25; }
  *:focus-visible { outline: 2px solid ${C.accent}; outline-offset: 2px; }
  @keyframes fadeIn  { from {opacity:0; transform:translateY(4px)} to {opacity:1; transform:none} }
  @keyframes slideIn { from {opacity:0; transform:translateX(-6px)} to {opacity:1; transform:none} }
  @keyframes pulse   { 0%,100% {opacity:1} 50% {opacity:.5} }
  @keyframes shimmer { 0% { background-position: -150% 0 } 100% { background-position: 150% 0 } }
  @keyframes agent-pulse {
    0%   { box-shadow: 0 0 0 0   currentColor; opacity: 1; }
    70%  { box-shadow: 0 0 0 10px transparent; opacity: 0.4; }
    100% { box-shadow: 0 0 0 0   transparent; opacity: 1; }
  }
  @keyframes neural-halo {
    0%   { r: 9;  stroke-opacity: 0.7 }
    100% { r: 18; stroke-opacity: 0   }
  }
  .neural-halo { animation: neural-halo 1.6s ease-out infinite; }
  @keyframes neural-jitter {
    0%, 100% { transform: translate(0, 0); }
    25%      { transform: translate(1.2px, -0.8px); }
    50%      { transform: translate(-0.8px, 1.2px); }
    75%      { transform: translate(-1.0px, -1.0px); }
  }
  .neural-jitter { animation: neural-jitter 0.6s linear infinite; transform-origin: center; transform-box: fill-box; }
  .ember-skel {
    background: linear-gradient(90deg, ${C.bgMuted} 0%, ${C.bgDark} 50%, ${C.bgMuted} 100%);
    background-size: 220% 100%;
    animation: shimmer 1.6s ease-in-out infinite;
    border-radius: 3px;
  }
`;
}

export const globalCSS = makeGlobalCSS();
