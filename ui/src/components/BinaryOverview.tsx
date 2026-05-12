import { useEffect, useMemo, useState } from "react";
import type React from "react";
import { C, mono, sans, serif } from "../theme";
import { displayName, formatSize } from "../api";
import type { Annotations, BinaryInfo, FunctionInfo } from "../types";

function parseHex(s: string): number {
  const n = parseInt(s, 16);
  return Number.isFinite(n) ? n : 0;
}

type Tone = { fg: string; bg: string; border: string; label: string };

function sectionTone(s: BinaryInfo["sections"][number]): Tone {
  const flags = s.flags.toLowerCase();
  const name = s.name.toLowerCase();
  if (flags.includes("x") || name.includes("text") || name.includes("plt")) {
    return { fg: C.accent, bg: C.accentDim, border: "rgba(217,119,87,0.30)", label: "code" };
  }
  if (name.includes("rodata") || name.includes("rdata") || name.includes("__const") || name.endsWith(".eh_frame") || name.includes("eh_frame")) {
    return { fg: C.yellow, bg: "rgba(184,154,58,0.10)", border: "rgba(184,154,58,0.28)", label: "ro" };
  }
  if (flags.includes("w") || name.includes("data") || name.includes("bss") || name.includes("got")) {
    return { fg: C.red, bg: "rgba(199,93,58,0.10)", border: "rgba(199,93,58,0.28)", label: "data" };
  }
  if (name.includes("idata") || name.includes("import") || name.includes("__la_") || name.includes("__nl_")) {
    return { fg: C.blue, bg: C.blueDim, border: "rgba(106,155,204,0.28)", label: "link" };
  }
  return { fg: C.textMuted, bg: C.bgMuted, border: C.border, label: "misc" };
}

function findFunctionAtOrContaining(info: BinaryInfo, addr: number): FunctionInfo | null {
  let best: FunctionInfo | null = null;
  for (const fn of info.functions) {
    if (fn.addrNum === addr) return fn;
    if (fn.size <= 0 || addr < fn.addrNum || addr >= fn.addrNum + fn.size) continue;
    if (!best || fn.addrNum > best.addrNum) best = fn;
  }
  return best;
}

export function BinaryOverview(props: {
  info: BinaryInfo;
  annotations: Annotations;
  displayBase: string;
  onSetDisplayBase: (base: string) => void;
  onJumpAddress: (vaddr: number) => void;
  onSelectFunction: (fn: FunctionInfo) => void;
  onOpenSymbols: () => void;
  onOpenStrings: () => void;
  onOpenIdentify: () => void;
  onOpenGraph: () => void;
  onOpenAI: () => void;
  onClose: () => void;
}) {
  const { info, annotations, onClose } = props;
  const [customBase, setCustomBase] = useState(props.displayBase || "0x0");
  const [sortBy, setSortBy] = useState<"vaddr" | "size" | "name">("vaddr");

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.preventDefault(); onClose(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const entryAddr = parseHex(info.entry);
  const entryFn = useMemo(() => findFunctionAtOrContaining(info, entryAddr), [info, entryAddr]);
  const mainFn = useMemo(
    () => info.functions.find((f) => displayName(f, annotations) === "main" || f.name === "main") ?? null,
    [info.functions, annotations],
  );

  const enriched = useMemo(() => info.sections.map((s) => ({
    s, vaddr: parseHex(s.vaddr), size: parseHex(s.size), tone: sectionTone(s),
  })), [info.sections]);

  const sortedSections = useMemo(() => {
    const arr = [...enriched];
    if (sortBy === "vaddr") arr.sort((a, b) => a.vaddr - b.vaddr);
    else if (sortBy === "size") arr.sort((a, b) => b.size - a.size);
    else arr.sort((a, b) => a.s.name.localeCompare(b.s.name));
    return arr;
  }, [enriched, sortBy]);

  const totalSectionBytes = useMemo(
    () => enriched.reduce((sum, e) => sum + e.size, 0),
    [enriched],
  );

  const ribbonBands = useMemo(() => {
    const live = enriched.filter((e) => e.size > 0).sort((a, b) => a.vaddr - b.vaddr);
    const total = live.reduce((sum, e) => sum + e.size, 0);
    if (total === 0) return [] as Array<typeof enriched[number] & { pct: number }>;
    return live.map((e) => ({ ...e, pct: (e.size / total) * 100 }));
  }, [enriched]);

  const applyCustomBase = () => {
    const trimmed = customBase.trim();
    if (/^0x[0-9a-f]+$/i.test(trimmed) || /^[0-9a-f]+$/i.test(trimmed)) {
      props.onSetDisplayBase(trimmed.startsWith("0x") ? trimmed : `0x${trimmed}`);
    }
  };

  const fileName = info.path.split(/[\\/]/).pop() || info.path;
  const baseLower = props.displayBase.toLowerCase();

  return (
    <div
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 1840,
        background: "rgba(10,10,9,0.55)",
        backdropFilter: "blur(3px)",
        display: "flex",
        justifyContent: "center",
        padding: "5vh 5vw",
        animation: "fadeIn .15s ease-out",
      }}
    >
      <div style={{
        flex: 1,
        maxWidth: 1180,
        display: "flex",
        flexDirection: "column",
        background: C.bg,
        border: `1px solid ${C.borderStrong}`,
        borderRadius: 8,
        boxShadow: "0 30px 80px rgba(0,0,0,0.6)",
        overflow: "hidden",
      }}>
        {/* Header */}
        <div style={{
          padding: "14px 20px",
          borderBottom: `1px solid ${C.border}`,
          background: C.bgAlt,
          display: "flex",
          alignItems: "center",
          gap: 18,
          flexShrink: 0,
        }}>
          <div style={{ minWidth: 0, flex: 1 }}>
            <div style={{ display: "flex", alignItems: "baseline", gap: 10, lineHeight: 1.15 }}>
              <span style={{ fontFamily: sans, fontSize: 14, fontWeight: 600, color: C.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {fileName}
              </span>
              <span style={{ fontFamily: mono, fontSize: 10, color: C.textFaint, textTransform: "uppercase", letterSpacing: 1.1 }}>
                {info.format} · {info.arch} · {info.endian}
              </span>
            </div>
            <div style={{ marginTop: 3, fontFamily: serif, fontStyle: "italic", fontSize: 11, color: C.textMuted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {info.path}
            </div>
          </div>

          <HeaderStat label="entry" value={info.entry} accent onClick={() => entryFn ? props.onSelectFunction(entryFn) : props.onJumpAddress(entryAddr)} />
          <HeaderStat label="base" value={info.base} />
          <HeaderStat label="funcs" value={info.functions.length.toLocaleString()} onClick={props.onOpenSymbols} />
          <HeaderStat label="imports" value={info.imports.length.toLocaleString()} onClick={props.onOpenSymbols} />

          <button
            onClick={onClose}
            title="Close (Esc)"
            style={{ color: C.textMuted, fontSize: 14, padding: "4px 8px", marginLeft: 4 }}
          >✕</button>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflow: "auto" }}>
          {/* Address-space ribbon */}
          <section style={{ padding: "18px 20px 10px" }}>
            <div style={{ display: "flex", alignItems: "baseline", gap: 10, marginBottom: 8 }}>
              <span style={{ fontFamily: sans, fontSize: 12, fontWeight: 600, color: C.text }}>Address space</span>
              <span style={{ fontFamily: serif, fontStyle: "italic", fontSize: 11, color: C.textMuted }}>
                {info.sections.length} sections · {formatSize(totalSectionBytes)} mapped
              </span>
              <div style={{ flex: 1 }} />
              <Legend />
            </div>
            <Ribbon bands={ribbonBands} onJump={props.onJumpAddress} />
          </section>

          {/* Quick anchors */}
          <section style={{ padding: "4px 20px 14px", display: "flex", gap: 10, flexWrap: "wrap" }}>
            <Anchor
              label="entrypoint"
              value={entryFn ? displayName(entryFn, annotations) : info.entry}
              hint={entryFn ? entryFn.addr : "raw address"}
              onClick={() => entryFn ? props.onSelectFunction(entryFn) : props.onJumpAddress(entryAddr)}
            />
            <Anchor
              label="main"
              value={mainFn ? displayName(mainFn, annotations) : "—"}
              hint={mainFn ? mainFn.addr : "not located"}
              dim={!mainFn}
              onClick={() => mainFn ? props.onSelectFunction(mainFn) : props.onOpenSymbols()}
            />
            <div style={{ flex: 1 }} />
            <ToolButton onClick={props.onOpenSymbols}>symbols</ToolButton>
            <ToolButton onClick={props.onOpenStrings}>strings</ToolButton>
            <ToolButton onClick={props.onOpenIdentify}>identify</ToolButton>
            <ToolButton onClick={props.onOpenGraph}>graph</ToolButton>
            <ToolButton onClick={props.onOpenAI} accent>ember ai</ToolButton>
          </section>

          {/* Sections table */}
          <section style={{ padding: "0 20px 16px" }}>
            <div style={{
              display: "flex", alignItems: "baseline", gap: 10, marginBottom: 8,
            }}>
              <span style={{ fontFamily: sans, fontSize: 12, fontWeight: 600, color: C.text }}>Sections</span>
              <span style={{ fontFamily: serif, fontStyle: "italic", fontSize: 11, color: C.textMuted }}>
                click any row to seek
              </span>
              <div style={{ flex: 1 }} />
              <SortPill active={sortBy === "vaddr"} onClick={() => setSortBy("vaddr")}>address</SortPill>
              <SortPill active={sortBy === "size"} onClick={() => setSortBy("size")}>size</SortPill>
              <SortPill active={sortBy === "name"} onClick={() => setSortBy("name")}>name</SortPill>
            </div>

            <div style={{
              border: `1px solid ${C.border}`,
              borderRadius: 6,
              overflow: "hidden",
              background: C.bgAlt,
            }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontFamily: mono, fontSize: 12 }}>
                <thead>
                  <tr style={{ background: C.bgAlt, borderBottom: `1px solid ${C.border}` }}>
                    <Th>name</Th>
                    <Th>kind</Th>
                    <Th align="right">vaddr</Th>
                    <Th align="right">end</Th>
                    <Th align="right">size</Th>
                    <Th>flags</Th>
                  </tr>
                </thead>
                <tbody>
                  {sortedSections.map(({ s, vaddr, size, tone }, i) => (
                    <tr
                      key={`${s.name}-${s.vaddr}-${i}`}
                      onClick={() => props.onJumpAddress(vaddr)}
                      style={{
                        cursor: "pointer",
                        borderBottom: i === sortedSections.length - 1 ? "none" : `1px solid ${C.border}`,
                        background: i % 2 === 0 ? "transparent" : C.bgMuted + "40",
                      }}
                      onMouseEnter={(e) => { e.currentTarget.style.background = C.accentDim; }}
                      onMouseLeave={(e) => { e.currentTarget.style.background = i % 2 === 0 ? "transparent" : C.bgMuted + "40"; }}
                    >
                      <td style={{ padding: "6px 14px", whiteSpace: "nowrap" }}>
                        <span style={{
                          display: "inline-block",
                          width: 3,
                          height: 12,
                          background: tone.fg,
                          verticalAlign: "middle",
                          marginRight: 8,
                          borderRadius: 1,
                        }} />
                        <span style={{ color: tone.fg, fontWeight: 600 }}>{s.name || "(unnamed)"}</span>
                      </td>
                      <td style={{ padding: "6px 10px" }}>
                        <span style={{
                          padding: "2px 8px",
                          borderRadius: 3,
                          fontSize: 10,
                          fontFamily: sans,
                          fontWeight: 500,
                          color: tone.fg,
                          background: tone.bg,
                          border: `1px solid ${tone.border}`,
                        }}>
                          {tone.label}
                        </span>
                      </td>
                      <td style={{ padding: "6px 10px", color: C.blue, textAlign: "right" }}>{s.vaddr}</td>
                      <td style={{ padding: "6px 10px", color: C.textFaint, textAlign: "right" }}>
                        {size > 0 ? `0x${(vaddr + size).toString(16)}` : "—"}
                      </td>
                      <td style={{ padding: "6px 10px", color: C.textWarm, textAlign: "right" }}>
                        {size > 0 ? formatSize(size) : "0"}
                      </td>
                      <td style={{ padding: "6px 14px", color: C.textMuted, fontSize: 11 }}>{s.flags || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </div>

        {/* Footer: display base */}
        <div style={{
          padding: "10px 20px",
          borderTop: `1px solid ${C.border}`,
          background: C.bgAlt,
          display: "flex",
          alignItems: "center",
          gap: 12,
          flexShrink: 0,
        }}>
          <span style={{ fontFamily: mono, fontSize: 10, color: C.textFaint, textTransform: "uppercase", letterSpacing: 1.1 }}>
            display base
          </span>
          <BasePill active={baseLower === "0x0"} onClick={() => props.onSetDisplayBase("0x0")}>
            <span style={{ color: C.textMuted }}>rva</span>
            <span style={{ marginLeft: 6, color: C.textFaint }}>0x0</span>
          </BasePill>
          <BasePill active={baseLower === info.base.toLowerCase()} onClick={() => props.onSetDisplayBase(info.base)}>
            <span style={{ color: C.textMuted }}>image</span>
            <span style={{ marginLeft: 6, color: C.textFaint }}>{info.base}</span>
          </BasePill>
          <div style={{
            display: "flex", alignItems: "center", gap: 4,
            padding: "3px 4px 3px 10px",
            background: C.bgMuted,
            border: `1px solid ${C.border}`,
            borderRadius: 4,
          }}>
            <span style={{ color: C.textFaint, fontFamily: sans, fontSize: 11 }}>custom</span>
            <input
              value={customBase}
              onChange={(e) => setCustomBase(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") applyCustomBase(); }}
              aria-label="Custom display base"
              spellCheck={false}
              style={{
                width: 110,
                padding: "2px 6px",
                fontFamily: mono,
                fontSize: 11,
                color: C.text,
                background: "transparent",
                border: "none",
                outline: "none",
              }}
            />
            <button
              onClick={applyCustomBase}
              style={{
                padding: "3px 8px",
                fontFamily: sans, fontSize: 10,
                color: C.text,
                background: C.bg,
                border: `1px solid ${C.border}`,
                borderRadius: 3,
              }}
            >
              set
            </button>
          </div>
          <div style={{ flex: 1 }} />
          <span style={{ fontFamily: serif, fontStyle: "italic", fontSize: 11, color: C.textFaint }}>
            esc to close
          </span>
        </div>
      </div>
    </div>
  );
}

function HeaderStat(props: { label: string; value: string; accent?: boolean; onClick?: () => void }) {
  const clickable = !!props.onClick;
  return (
    <button
      onClick={props.onClick}
      disabled={!clickable}
      style={{
        textAlign: "left",
        padding: "4px 10px",
        background: "transparent",
        border: "none",
        borderLeft: `1px solid ${C.border}`,
        cursor: clickable ? "pointer" : "default",
        minWidth: 0,
      }}
    >
      <div style={{ fontFamily: mono, fontSize: 9, color: C.textFaint, textTransform: "uppercase", letterSpacing: 1.1 }}>
        {props.label}
      </div>
      <div style={{
        marginTop: 2,
        fontFamily: mono,
        fontSize: 12,
        color: props.accent ? C.accent : C.text,
        fontWeight: 600,
        overflow: "hidden",
        textOverflow: "ellipsis",
        whiteSpace: "nowrap",
        maxWidth: 140,
      }}>
        {props.value || "—"}
      </div>
    </button>
  );
}

function Anchor(props: { label: string; value: string; hint: string; dim?: boolean; onClick: () => void }) {
  return (
    <button
      onClick={props.onClick}
      style={{
        flex: "0 1 240px",
        padding: "8px 12px",
        background: C.bgAlt,
        border: `1px solid ${C.border}`,
        borderRadius: 6,
        textAlign: "left",
        cursor: "pointer",
      }}
      onMouseEnter={(e) => { e.currentTarget.style.borderColor = C.borderStrong; }}
      onMouseLeave={(e) => { e.currentTarget.style.borderColor = C.border; }}
    >
      <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
        <span style={{ fontFamily: mono, fontSize: 9, color: C.textFaint, textTransform: "uppercase", letterSpacing: 1.1 }}>
          {props.label}
        </span>
        <span style={{ fontFamily: mono, fontSize: 10, color: C.textFaint, marginLeft: "auto" }}>
          {props.hint}
        </span>
      </div>
      <div style={{
        marginTop: 4,
        fontFamily: sans,
        fontSize: 13,
        fontWeight: 600,
        color: props.dim ? C.textMuted : C.text,
        overflow: "hidden",
        textOverflow: "ellipsis",
        whiteSpace: "nowrap",
      }}>
        {props.value}
      </div>
    </button>
  );
}

function ToolButton(props: { onClick: () => void; accent?: boolean; children: React.ReactNode }) {
  return (
    <button
      onClick={props.onClick}
      style={{
        padding: "6px 12px",
        fontFamily: sans, fontSize: 12,
        color: props.accent ? C.accent : C.textWarm,
        background: props.accent ? C.accentDim : C.bgMuted,
        border: `1px solid ${props.accent ? "rgba(217,119,87,0.30)" : C.border}`,
        borderRadius: 4,
        cursor: "pointer",
      }}
    >
      {props.children}
    </button>
  );
}

function SortPill(props: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={props.onClick}
      style={{
        padding: "3px 9px",
        fontFamily: sans, fontSize: 11,
        fontWeight: props.active ? 600 : 400,
        color: props.active ? C.text : C.textMuted,
        background: props.active ? C.bgDark : C.bgMuted,
        border: `1px solid ${props.active ? C.borderStrong : C.border}`,
        borderRadius: 4,
        cursor: "pointer",
      }}
    >
      {props.children}
    </button>
  );
}

function BasePill(props: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={props.onClick}
      aria-pressed={props.active}
      style={{
        padding: "5px 10px",
        background: props.active ? C.accentDim : C.bgMuted,
        border: `1px solid ${props.active ? "rgba(217,119,87,0.30)" : C.border}`,
        borderRadius: 4,
        fontFamily: mono, fontSize: 11,
        cursor: "pointer",
        display: "flex", alignItems: "baseline",
      }}
    >
      {props.children}
    </button>
  );
}

function Th(props: { align?: "left" | "right"; children: React.ReactNode }) {
  return (
    <th style={{
      textAlign: props.align ?? "left",
      padding: "8px 14px",
      color: C.textMuted,
      fontFamily: sans,
      fontSize: 11,
      fontWeight: 500,
      textTransform: "uppercase",
      letterSpacing: 1,
    }}>
      {props.children}
    </th>
  );
}

function Legend() {
  return (
    <div style={{ display: "flex", gap: 12, fontFamily: sans, fontSize: 10, color: C.textFaint }}>
      <LegendDot color={C.accent} label="code" />
      <LegendDot color={C.yellow} label="ro" />
      <LegendDot color={C.red} label="data" />
      <LegendDot color={C.blue} label="link" />
    </div>
  );
}

function LegendDot(props: { color: string; label: string }) {
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
      <span style={{ width: 8, height: 8, background: props.color, borderRadius: 1 }} />
      {props.label}
    </span>
  );
}

function Ribbon(props: {
  bands: Array<{ s: BinaryInfo["sections"][number]; vaddr: number; size: number; tone: Tone; pct: number }>;
  onJump: (vaddr: number) => void;
}) {
  const [hover, setHover] = useState<number | null>(null);
  if (props.bands.length === 0) {
    return (
      <div style={{
        height: 36,
        border: `1px dashed ${C.border}`,
        borderRadius: 4,
        display: "flex", alignItems: "center", justifyContent: "center",
        fontFamily: serif, fontStyle: "italic", fontSize: 11, color: C.textFaint,
      }}>
        no mapped sections
      </div>
    );
  }
  const first = props.bands[0];
  const last = props.bands[props.bands.length - 1];

  return (
    <div>
      <div style={{
        display: "flex",
        height: 36,
        borderRadius: 4,
        overflow: "hidden",
        border: `1px solid ${C.border}`,
        background: C.bg,
      }}>
        {props.bands.map((b, i) => {
          const isHover = hover === i;
          return (
            <button
              key={`${b.s.name}-${b.s.vaddr}-${i}`}
              onClick={() => props.onJump(b.vaddr)}
              onMouseEnter={() => setHover(i)}
              onMouseLeave={() => setHover((h) => h === i ? null : h)}
              title={`${b.s.name || "(unnamed)"}\n${b.s.vaddr}  ${formatSize(b.size)}\n${b.s.flags || "-"}`}
              style={{
                flex: `${b.pct} 1 0`,
                minWidth: 2,
                background: isHover ? b.tone.fg : b.tone.bg,
                borderRight: i < props.bands.length - 1 ? `1px solid ${C.bg}` : "none",
                cursor: "pointer",
                position: "relative",
                transition: "background .12s ease-out",
                padding: 0,
              }}
            >
              <span style={{
                position: "absolute",
                inset: 0,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontFamily: mono,
                fontSize: 10,
                fontWeight: 600,
                color: isHover ? C.bg : b.tone.fg,
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
                padding: "0 4px",
                pointerEvents: "none",
              }}>
                {b.pct >= 4 ? (b.s.name || "·") : ""}
              </span>
            </button>
          );
        })}
      </div>
      <div style={{
        display: "flex",
        justifyContent: "space-between",
        marginTop: 4,
        fontFamily: mono,
        fontSize: 10,
        color: C.textFaint,
      }}>
        <span>{first.s.vaddr}</span>
        <span style={{ fontFamily: serif, fontStyle: "italic" }}>
          {hover !== null
            ? `${props.bands[hover].s.name || "(unnamed)"}  ·  ${formatSize(props.bands[hover].size)}  ·  ${props.bands[hover].s.flags || "-"}`
            : `${props.bands.length} mapped`}
        </span>
        <span>0x{(last.vaddr + last.size).toString(16)}</span>
      </div>
    </div>
  );
}
