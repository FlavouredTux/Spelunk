// Warm palette, assistant-ish. Earth tones, single orange accent.
export const C = {
  bg:           "#141413",
  bgAlt:        "#1f1e1d",
  bgMuted:      "#262524",
  bgInput:      "#1f1e1d",
  bgDark:       "#302f2d",

  text:         "#ede9df",
  textWarm:     "#d4cfc2",
  textMuted:    "#87867f",
  textFaint:    "#5c5b56",

  accent:       "#d97757",
  accentHover:  "#e8896b",
  accentDim:    "rgba(217,119,87,0.12)",

  blue:         "#6a9bcc",
  blueDim:      "rgba(106,155,204,0.12)",
  green:        "#788c5d",
  red:          "#c75d3a",
  yellow:       "#b89a3a",
  violet:       "#8b7bb5",

  border:       "rgba(255,255,245,0.08)",
  borderStrong: "rgba(255,255,245,0.15)",
};

export const sans  = "'DM Sans',system-ui,-apple-system,sans-serif";
export const serif = "'Lora','Source Serif Pro',Georgia,serif";
export const mono  = "'JetBrains Mono','SF Mono','Fira Code',monospace";

// Syntax-highlight palette
export const SH = {
  keyword:    "#c28b70",
  type:       "#b0a486",
  number:     "#9bb5c1",
  string:     "#a5b37f",
  comment:    "#5c5b56",
  func:       "#d97757",
  xref:       "#d97757",
  addr:       "#87867f",
  op:         "#87867f",
  reg:        "#c9c2af",
  flag:       "#b0a486",
  label:      "#8b7bb5",
  arg:        "#b5a0d8",   // function params: a1, a2, ...
  bound:      "#c8a87a",   // call-return locals: r_fopen, r_strlen, ...
};

const fontHref =
  "https://fonts.googleapis.com/css2?family=DM+Sans:ital,wght@0,300;0,400;0,500;0,600;0,700;1,400&family=Lora:ital,wght@0,400;0,500;1,400;1,500&family=JetBrains+Mono:wght@400;500;600&display=swap";
if (!document.querySelector(`link[href="${fontHref}"]`)) {
  const link = document.createElement("link");
  link.rel = "stylesheet";
  link.href = fontHref;
  document.head.appendChild(link);
}

export const globalCSS = `
  * { margin:0; padding:0; box-sizing:border-box; }
  html, body, #root { height:100%; background:${C.bg}; overflow:hidden; }
  body { font-family:${sans}; color:${C.text}; -webkit-font-smoothing:antialiased;
         -webkit-user-select:none; user-select:none; }
  .sel { -webkit-user-select:text; user-select:text; }
  ::selection { background:${C.accent}; color:#fff; }
  ::-webkit-scrollbar { width:8px; height:8px; }
  ::-webkit-scrollbar-track { background:transparent; }
  ::-webkit-scrollbar-thumb { background:${C.border}; border-radius:4px; }
  ::-webkit-scrollbar-thumb:hover { background:${C.borderStrong}; }
  button { font-family:${sans}; background:none; border:none; color:inherit; cursor:pointer; }
  input { font-family:${sans}; background:none; border:none; color:inherit; outline:none; }
  @keyframes fadeIn  { from {opacity:0; transform:translateY(4px)} to {opacity:1; transform:none} }
  @keyframes slideIn { from {opacity:0; transform:translateX(-6px)} to {opacity:1; transform:none} }
  @keyframes pulse   { 0%,100% {opacity:1} 50% {opacity:.5} }
`;
