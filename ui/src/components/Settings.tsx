import { useEffect, useMemo, useRef, useState } from "react";
import { C, sans, serif, mono } from "../theme";
import type { AppSettings } from "../settings";
import { DEFAULT_SETTINGS } from "../settings";
import { clearRendererCaches, listPlugins, matchPlugin, runPluginCommand } from "../api";
import type {
  AiConfig, AiCliStatus, AiProvider, Annotations, PluginInfo,
  PluginMatchResult, PluginRunResult,
} from "../types";

// Monospace font presets surfaced in the Settings panel. Each value
// is a CSS font-family stack — the first listed family is the
// preferred face; trailing entries are fallbacks if the user doesn't
// have the headline font installed locally.
const FONT_FAMILIES = {
  jetbrains: "'JetBrains Mono','SF Mono','Fira Code',monospace",
  sf:        "'SF Mono','JetBrains Mono','Menlo',monospace",
  fira:      "'Fira Code','JetBrains Mono','SF Mono',monospace",
  system:    "ui-monospace,SFMono-Regular,Menlo,Consolas,monospace",
} as const;
type FontKey = keyof typeof FONT_FAMILIES;

function selectFontKey(stack: string): FontKey {
  for (const k of Object.keys(FONT_FAMILIES) as FontKey[]) {
    if (FONT_FAMILIES[k] === stack) return k;
  }
  return "jetbrains";
}

// Settings gear. Stroked-outline style (matches the rest of the
// title-bar glyphs), 24×24 viewBox so the curved tooth flanks
// stay smooth at any reasonable display size. `currentColor` for
// both stroke fields so the icon inherits the button's text colour
// and reacts to hover/focus.
export function GearIcon(props: { size?: number; style?: React.CSSProperties }) {
  const size = props.size ?? 14;
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
      style={props.style}
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z" />
    </svg>
  );
}

// Settings overlay. Reads/writes through the parent (which owns the
// settings state and persists on change). Esc / backdrop-click closes;
// changes are applied live, no Save/Cancel — the toggle IS the apply.
export function SettingsPanel(props: {
  settings: AppSettings;
  onChange: (s: AppSettings) => void;
  binaryPath?: string | null;
  onAnnotationsApplied?: (a: Annotations) => void;
  onReplayTutorial?: () => void;
  onClose: () => void;
}) {
  const [cleared, setCleared] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") props.onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [props]);

  const set = <K extends keyof AppSettings>(k: K, v: AppSettings[K]) => {
    props.onChange({ ...props.settings, [k]: v });
  };

  return (
    <div
      onMouseDown={(e) => { if (e.target === e.currentTarget) props.onClose(); }}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(10,10,9,0.55)",
        backdropFilter: "blur(3px)",
        zIndex: 2000,
        display: "flex",
        justifyContent: "center",
        paddingTop: "10vh",
        animation: "fadeIn .12s ease-out",
      }}
    >
      <div
        style={{
          width: 480,
          maxWidth: "92%",
          maxHeight: "78vh",
          display: "flex",
          flexDirection: "column",
          background: C.bgAlt,
          border: `1px solid ${C.borderStrong}`,
          borderRadius: 8,
          overflow: "hidden",
          boxShadow: "0 24px 60px rgba(0,0,0,0.55)",
        }}
      >
        {/* Header */}
        <div
          style={{
            display: "flex", alignItems: "center", gap: 10,
            padding: "14px 18px",
            borderBottom: `1px solid ${C.border}`,
          }}
        >
          <GearIcon size={16} style={{ color: C.accent }} />
          <span style={{ fontFamily: sans, fontSize: 14, fontWeight: 600, color: C.text }}>
            Settings
          </span>
          <span style={{ flex: 1 }} />
          <span style={{ fontFamily: mono, fontSize: 10, color: C.textFaint }}>esc</span>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflowY: "auto", padding: "14px 18px" }}>
          <Section title="Display">
            <Row
              label="Theme"
              hint="Color palette. Warm = original; dark = cooler near-black; light = parchment."
            >
              <Segmented
                value={props.settings.theme}
                options={["warm", "dark", "light"] as const}
                onChange={(v) => set("theme", v)}
              />
            </Row>
            <Row
              label="Code font size"
              hint="Affects pseudo-C, IR, and disasm panes."
            >
              <NumberInput
                value={props.settings.codeFontSize}
                min={9} max={20}
                onChange={(v) => set("codeFontSize", v)}
              />
            </Row>
            <Row
              label="Code font family"
              hint="Monospace stack. Falls back automatically if the chosen family isn't installed."
            >
              <Segmented
                value={selectFontKey(props.settings.codeFontFamily)}
                options={["jetbrains", "sf", "fira", "system"] as const}
                onChange={(key) => set("codeFontFamily", FONT_FAMILIES[key])}
              />
            </Row>
            <Row
              label="Resume on launch"
              hint="Re-open the most recently used binary at the function you left it on."
            >
              <Toggle
                value={props.settings.resumeOnLaunch}
                onChange={(v) => set("resumeOnLaunch", v)}
              />
            </Row>
          </Section>

          <Section title="CFG view">
            <Row
              label="Default body mode"
              hint="Each block's contents when the graph first opens. Per-graph toggle still works."
            >
              <Segmented
                value={props.settings.cfgDefaultMode}
                options={["pseudo", "asm"] as const}
                onChange={(v) => set("cfgDefaultMode", v)}
              />
            </Row>
          </Section>

          <Section title="Pseudo-C">
            <Row
              label="Show basic-block labels"
              hint="Adds // bb_xxxxxx comments before each block. Useful for cross-referencing the CFG view."
            >
              <Toggle
                value={props.settings.showBbLabels}
                onChange={(v) => set("showBbLabels", v)}
              />
            </Row>
          </Section>

          <Section title="Git">
            <Row
              label="Release update popup"
              hint="Checks GitHub Releases and shows a small notice when a newer packaged app is available."
            >
              <Toggle
                value={props.settings.releaseUpdatePopup}
                onChange={(v) => set("releaseUpdatePopup", v)}
              />
            </Row>
          </Section>

          <Section title="Discord">
            <Row
              label="Rich Presence"
              hint="Broadcast Ember activity on your Discord profile. On by default in privacy mode — only the current view is shown, never the binary or function names."
            >
              <Toggle
                value={props.settings.discordRichPresence}
                onChange={(v) => set("discordRichPresence", v)}
              />
            </Row>
            {props.settings.discordRichPresence && (
              <Row
                label="Privacy mode"
                hint="On (default): only the view is broadcast. Off: binary file name and current function are visible to your Discord friends."
              >
                <Toggle
                  value={props.settings.discordHideBinaryName}
                  onChange={(v) => set("discordHideBinaryName", v)}
                />
              </Row>
            )}
          </Section>

          <Section title="Cache">
            <Row
              label="Cleared cached results"
              hint="Force a fresh ember run on the next view request. Use after rebuilding the binary outside Ember."
            >
              <button
                onClick={() => { clearRendererCaches(); setCleared(true);
                                 setTimeout(() => setCleared(false), 1500); }}
                style={{
                  padding: "6px 12px",
                  background: cleared ? C.green : C.bgMuted,
                  color: cleared ? "#fff" : C.text,
                  border: `1px solid ${cleared ? C.green : C.border}`,
                  borderRadius: 4,
                  fontFamily: mono, fontSize: 11,
                  cursor: "pointer",
                  transition: "background .15s, color .15s, border-color .15s",
                }}
              >{cleared ? "cleared ✓" : "clear caches"}</button>
            </Row>
          </Section>

          <Section title="AI">
            <AiConfigSection />
          </Section>

          <Section title="Plugins">
            <PluginSection
              binaryPath={props.binaryPath ?? null}
              onAnnotationsApplied={props.onAnnotationsApplied}
            />
          </Section>

          <Section title="Defaults">
            {props.onReplayTutorial && (
              <Row label="Replay tutorial" hint="Walk through the first-run coach-marks again.">
                <button
                  onClick={props.onReplayTutorial}
                  style={{
                    padding: "6px 12px",
                    background: "transparent",
                    color: C.textMuted,
                    border: `1px solid ${C.border}`,
                    borderRadius: 4,
                    fontFamily: mono, fontSize: 11,
                    cursor: "pointer",
                  }}
                >show tutorial</button>
              </Row>
            )}
            <Row label="Reset all settings" hint="Restores every option above to its factory value.">
              <button
                onClick={() => props.onChange({ ...DEFAULT_SETTINGS })}
                style={{
                  padding: "6px 12px",
                  background: "transparent",
                  color: C.textMuted,
                  border: `1px solid ${C.border}`,
                  borderRadius: 4,
                  fontFamily: mono, fontSize: 11,
                  cursor: "pointer",
                }}
              >reset</button>
            </Row>
          </Section>

          <div
            style={{
              marginTop: 20, paddingTop: 14,
              borderTop: `1px solid ${C.border}`,
              display: "flex", flexDirection: "column", gap: 4,
              fontFamily: serif, fontSize: 11, color: C.textFaint, fontStyle: "italic",
            }}
          >
            <span>Ember — from-scratch binary decompiler</span>
            <span style={{ fontFamily: mono, fontStyle: "normal" }}>
              github.com/FlavouredTux/Ember
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

// Human-readable summary of a match result, used in the badge tooltip
// and the run-anyway confirm. Lists evidence for hits and the failure
// reason for misses so the user can see *why* a plugin did or didn't
// match without opening the manifest.
function describeMatch(m: PluginMatchResult): string {
  const parts: string[] = [`score ${m.score}/100`];
  if (m.evidence.length) {
    parts.push(`hit: ${m.evidence.map((e) => e.detail).join("; ")}`);
  }
  if (m.failed.length) {
    parts.push(`miss: ${m.failed.map((f) => f.detail).join("; ")}`);
  }
  return parts.join(" · ");
}

function PluginSection(props: {
  binaryPath: string | null;
  onAnnotationsApplied?: (a: Annotations) => void;
}) {
  const [plugins, setPlugins] = useState<PluginInfo[] | null>(null);
  const [busyRef, setBusyRef] = useState<string | null>(null);
  const [preview, setPreview] = useState<PluginRunResult | null>(null);
  const [status, setStatus] = useState<string>("");
  const [matches, setMatches] = useState<Record<string, PluginMatchResult>>({});

  useEffect(() => {
    let cancel = false;
    listPlugins().then((p) => { if (!cancel) setPlugins(p); }).catch(() => {
      if (!cancel) setPlugins([]);
    });
    return () => { cancel = true; };
  }, []);

  // Evaluate matchers once per (binary × plugin-set). Plugins without
  // matchers short-circuit to matched=true in the host, so this is
  // still cheap for example-shape plugins; the CLI work only kicks
  // in when a plugin actually declares matchers.
  useEffect(() => {
    if (!plugins || !props.binaryPath) { setMatches({}); return; }
    let cancel = false;
    (async () => {
      const results: Record<string, PluginMatchResult> = {};
      await Promise.all(plugins.map(async (p) => {
        if (p.invalid) return;
        try { results[p.id] = await matchPlugin(p.id); }
        catch { /* leave unset; UI treats as unknown */ }
      }));
      if (!cancel) setMatches(results);
    })();
    return () => { cancel = true; };
  }, [plugins, props.binaryPath]);

  if (!props.binaryPath) {
    return <div style={{ color: C.textFaint, fontFamily: serif, fontStyle: "italic" }}>
      open a binary to preview or apply plugin proposals
    </div>;
  }
  if (!plugins) {
    return <div style={{ color: C.textFaint, fontFamily: serif, fontStyle: "italic" }}>
      loading plugins…
    </div>;
  }
  if (plugins.length === 0) {
    return <div style={{ color: C.textFaint, fontFamily: serif, fontStyle: "italic" }}>
      no local plugins found
    </div>;
  }

  async function previewCommand(pluginId: string, commandId: string) {
    const ref = `${pluginId}:${commandId}`;
    setBusyRef(ref);
    try {
      const res = await runPluginCommand(pluginId, commandId, { apply: false });
      setPreview(res);
      setStatus(res.summary);
    } catch (e: any) {
      setStatus(`Plugin preview failed: ${e?.message ?? String(e)}`);
    } finally {
      setBusyRef(null);
    }
  }

  async function applyPreview() {
    if (!preview) return;
    setBusyRef(`${preview.pluginId}:${preview.commandId}:apply`);
    try {
      const res = await runPluginCommand(preview.pluginId, preview.commandId, { apply: true });
      setPreview(res);
      setStatus(`${res.summary} Applied ${res.appliedCount} rename${res.appliedCount === 1 ? "" : "s"}.`);
      if (res.annotations && props.onAnnotationsApplied) props.onAnnotationsApplied(res.annotations);
    } catch (e: any) {
      setStatus(`Plugin apply failed: ${e?.message ?? String(e)}`);
    } finally {
      setBusyRef(null);
    }
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      {plugins.map((plugin) => {
        const match = matches[plugin.id];
        const hasMatchers = plugin.matchers && plugin.matchers.length > 0;
        // No matchers = plugin opts into every binary (example-plugin shape).
        // With matchers = show a badge reflecting the score.
        const badge = !hasMatchers
          ? null
          : match
            ? match.matched
              ? { color: C.accent, label: "matches", tooltip: describeMatch(match) }
              : match.score > 0
                ? { color: "#d4a017", label: `partial ${match.score}%`, tooltip: describeMatch(match) }
                : { color: C.textFaint, label: "no match", tooltip: describeMatch(match) }
            : { color: C.textFaint, label: "…", tooltip: "evaluating" };
        const mismatched = hasMatchers && !!match && !match.matched;
        return (
        <div
          key={plugin.id}
          style={{
            border: `1px solid ${plugin.invalid ? C.red : C.border}`,
            borderRadius: 6,
            padding: "10px 12px",
            background: C.bg,
            opacity: mismatched ? 0.75 : 1,
          }}
        >
          <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
            <span style={{ fontFamily: sans, fontSize: 12, color: C.text, fontWeight: 600 }}>
              {plugin.name}
            </span>
            <span style={{ fontFamily: mono, fontSize: 10, color: C.textFaint }}>
              {plugin.version}
            </span>
            {badge && (
              <span
                title={badge.tooltip}
                style={{
                  fontFamily: mono, fontSize: 9, color: badge.color,
                  padding: "2px 6px", borderRadius: 999,
                  border: `1px solid ${badge.color}`,
                  letterSpacing: 0.2,
                }}
              >{badge.label}</span>
            )}
          </div>
          <div style={{
            marginTop: 3,
            fontFamily: serif, fontStyle: "italic", fontSize: 11, color: C.textFaint,
          }}>
            {plugin.description}
          </div>
          {plugin.permissions.length > 0 && (
            <div style={{
              marginTop: 6, display: "flex", flexWrap: "wrap", gap: 4,
            }}>
              {plugin.permissions.map((perm) => (
                <span
                  key={perm}
                  style={{
                    fontFamily: mono, fontSize: 9, color: C.textFaint,
                    padding: "2px 6px", borderRadius: 999,
                    border: `1px solid ${C.border}`, background: C.bgAlt,
                  }}
                >{perm}</span>
              ))}
            </div>
          )}
          {plugin.invalid ? null : (
            <div style={{ marginTop: 8, display: "flex", flexWrap: "wrap", gap: 6 }}>
              {plugin.commands.map((cmd) => {
                const ref = `${plugin.id}:${cmd.id}`;
                const active = busyRef === ref;
                const onClick = () => {
                  if (mismatched) {
                    const proceed = window.confirm(
                      `${plugin.name} did not match this binary (${describeMatch(match!)}). ` +
                      `Run "${cmd.title}" anyway?`,
                    );
                    if (!proceed) return;
                  }
                  previewCommand(plugin.id, cmd.id);
                };
                return (
                  <button
                    key={cmd.ref}
                    title={mismatched
                      ? `${cmd.description}\n\nthis plugin did not match this binary; click to run anyway`
                      : cmd.description}
                    disabled={!!busyRef}
                    onClick={onClick}
                    style={{
                      padding: "5px 10px",
                      background: mismatched ? "transparent" : C.bgMuted,
                      color: mismatched ? C.textMuted : C.text,
                      border: `1px solid ${mismatched ? C.border : C.border}`,
                      borderRadius: 4,
                      fontFamily: mono,
                      fontSize: 10,
                      fontStyle: mismatched ? "italic" : "normal",
                      cursor: busyRef ? "not-allowed" : "pointer",
                    }}
                  >{active ? "previewing…" : cmd.title}</button>
                );
              })}
            </div>
          )}
        </div>
        );
      })}

      {status && (
        <div style={{ fontFamily: serif, fontStyle: "italic", fontSize: 11, color: C.textFaint }}>
          {status}
        </div>
      )}

      {preview && (
        <div style={{
          border: `1px solid ${C.borderStrong}`,
          borderRadius: 6,
          background: C.bg,
          padding: "10px 12px",
        }}>
          <div style={{ display: "flex", justifyContent: "space-between", gap: 10, alignItems: "center" }}>
            <div>
              <div style={{ fontFamily: sans, fontSize: 12, color: C.text, fontWeight: 600 }}>
                Proposal Preview
              </div>
              <div style={{ fontFamily: serif, fontStyle: "italic", fontSize: 11, color: C.textFaint }}>
                {preview.summary}
              </div>
            </div>
            <button
              onClick={applyPreview}
              disabled={!!busyRef || preview.proposals.length === 0}
              style={{
                padding: "5px 10px",
                background: preview.proposals.length > 0 ? C.accent : C.bgMuted,
                color: preview.proposals.length > 0 ? "#fff" : C.textMuted,
                border: `1px solid ${preview.proposals.length > 0 ? C.accent : C.border}`,
                borderRadius: 4,
                fontFamily: mono,
                fontSize: 10,
                cursor: busyRef || preview.proposals.length === 0 ? "not-allowed" : "pointer",
              }}
            >{busyRef?.endsWith(":apply") ? "applying…" : "apply proposals"}</button>
          </div>
          {preview.notes && (
            <div style={{
              marginTop: 8, fontFamily: serif, fontStyle: "italic", fontSize: 11, color: C.textFaint,
            }}>
              {preview.notes}
            </div>
          )}
          <div style={{ marginTop: 10, maxHeight: 180, overflowY: "auto", display: "flex", flexDirection: "column", gap: 6 }}>
            {preview.proposals.length === 0 && (
              <div style={{ fontFamily: serif, fontStyle: "italic", fontSize: 11, color: C.textFaint }}>
                no proposals
              </div>
            )}
            {preview.proposals.map((p) => (
              <div key={`${p.kind}:${p.addr}:${p.kind === "rename" ? p.name : p.text}`} style={{
                padding: "7px 8px",
                borderRadius: 4,
                border: `1px solid ${C.border}`,
                background: C.bgAlt,
              }}>
                {p.kind === "rename" ? (
                  <div style={{ display: "flex", gap: 8, alignItems: "baseline", flexWrap: "wrap" }}>
                    <span style={{ fontFamily: mono, fontSize: 10, color: C.textFaint }}>{p.addr}</span>
                    <span style={{ fontFamily: mono, fontSize: 11, color: C.text }}>{p.name}</span>
                    <span style={{ fontFamily: mono, fontSize: 9, color: C.accent }}>
                      {Math.round(p.confidence * 100)}%
                    </span>
                  </div>
                ) : (
                  <div style={{ display: "flex", gap: 8, alignItems: "baseline", flexWrap: "wrap" }}>
                    <span style={{ fontFamily: mono, fontSize: 10, color: C.textFaint }}>{p.addr}</span>
                    <span style={{ fontFamily: mono, fontSize: 10, color: C.accent }}>note</span>
                    <span style={{ fontFamily: mono, fontSize: 9, color: C.accent }}>
                      {Math.round(p.confidence * 100)}%
                    </span>
                  </div>
                )}
                <div style={{
                  marginTop: 3, fontFamily: serif, fontStyle: "italic", fontSize: 11, color: C.textFaint,
                }}>
                  {p.kind === "rename" ? p.reason : p.text}
                </div>
                {p.kind === "note" && (
                  <div style={{
                    marginTop: 4, fontFamily: serif, fontStyle: "italic", fontSize: 11, color: C.textMuted,
                  }}>
                    {p.reason}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function Section(props: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 18 }}>
      <div style={{
        fontFamily: mono, fontSize: 9, letterSpacing: 1.5,
        color: C.textFaint, textTransform: "uppercase",
        marginBottom: 8,
      }}>
        {props.title}
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        {props.children}
      </div>
    </div>
  );
}

function Row(props: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div style={{ display: "flex", alignItems: "flex-start", gap: 12 }}>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontFamily: sans, fontSize: 12, color: C.text }}>
          {props.label}
        </div>
        {props.hint && (
          <div style={{
            fontFamily: serif, fontStyle: "italic", fontSize: 11,
            color: C.textFaint, marginTop: 2,
          }}>
            {props.hint}
          </div>
        )}
      </div>
      <div style={{ flexShrink: 0 }}>{props.children}</div>
    </div>
  );
}

function Toggle(props: { value: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      onClick={() => props.onChange(!props.value)}
      style={{
        position: "relative",
        width: 36, height: 20,
        borderRadius: 10,
        background: props.value ? C.accent : C.bgMuted,
        border: `1px solid ${props.value ? C.accent : C.border}`,
        cursor: "pointer",
        transition: "background .15s, border-color .15s",
      }}
      aria-pressed={props.value}
    >
      <span
        style={{
          position: "absolute",
          top: 2, left: props.value ? 18 : 2,
          width: 14, height: 14,
          borderRadius: 7,
          background: C.bg,
          transition: "left .15s",
        }}
      />
    </button>
  );
}

function NumberInput(props: {
  value: number; min: number; max: number;
  onChange: (v: number) => void;
}) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
      <button
        onClick={() => props.onChange(Math.max(props.min, props.value - 1))}
        style={stepBtnStyle}
      >–</button>
      <span style={{
        fontFamily: mono, fontSize: 12, color: C.text,
        minWidth: 22, textAlign: "center",
      }}>{props.value}</span>
      <button
        onClick={() => props.onChange(Math.min(props.max, props.value + 1))}
        style={stepBtnStyle}
      >+</button>
    </div>
  );
}

const stepBtnStyle: React.CSSProperties = {
  width: 22, height: 22,
  background: C.bgMuted,
  color: C.text,
  border: `1px solid ${C.border}`,
  borderRadius: 4,
  fontFamily: mono, fontSize: 13,
  cursor: "pointer",
  display: "flex", alignItems: "center", justifyContent: "center",
};

// AI provider + key + model picker. Talks to the main process
// directly so credentials never live in renderer state — we hold an
// opaque "have a key" boolean and only ever ship a fresh string back
// when the user pastes a new one. The CLI providers don't need keys
// at all; their auth lives inside the installed CLI.
function AiConfigSection() {
  const [cfg,    setCfg]   = useState<AiConfig | null>(null);
  const [models, setMs]    = useState<string[]>([]);
  const [assistant, setassistant] = useState<AiCliStatus | null>(null);
  const [codex,  setCodex]  = useState<AiCliStatus | null>(null);
  const reloadProbes = () => {
    window.ember.ai.detectCli("assistant-cli").then(setassistant).catch(() => {});
    window.ember.ai.detectCli("codex-cli").then(setCodex).catch(() => {});
  };

  useEffect(() => {
    let cancel = false;
    window.ember.ai.getConfig()
      .then((c) => {
        if (cancel) return;
        setCfg(c);
        return window.ember.ai.listModels(c.provider);
      })
      .then((m) => { if (!cancel && m) setMs(m); })
      .catch(() => {});
    reloadProbes();
    return () => { cancel = true; };
  }, []);

  if (!cfg) {
    return <div style={{ color: C.textFaint, fontFamily: serif, fontStyle: "italic" }}>
      loading…
    </div>;
  }

  async function changeProvider(p: AiProvider) {
    const next = await window.ember.ai.setConfig({ provider: p });
    setCfg(next);
    const m = await window.ember.ai.listModels(p);
    setMs(m);
    if (p === "assistant-cli" || p === "codex-cli") reloadProbes();
  }
  async function saveKey(k: string) {
    const next = await window.ember.ai.setConfig({ apiKey: k });
    setCfg(next);
  }
  async function changeModel(m: string) {
    const next = await window.ember.ai.setConfig({ model: m });
    setCfg(next);
  }

  return (
    <>
      <Row
        label="Provider"
        hint="Which backend handles AI requests. CLI paths use the logged-in subscription of the matching tool — no API key lives in Ember."
      >
        <Segmented
          value={cfg.provider}
          options={["openrouter", "9router", "assistant-cli", "codex-cli"] as const}
          onChange={changeProvider}
        />
      </Row>

      {cfg.provider === "openrouter" && (
        <OpenRouterKeySection cfg={cfg} onSave={saveKey} />
      )}

      {cfg.provider === "9router" && (
        <NineRouterSection cfg={cfg} onSave={saveKey} />
      )}

      {cfg.provider === "assistant-cli" && (
        <CliStatusSection
          kind="assistant-cli"
          status={assistant}
          onRefresh={reloadProbes}
          loginCmd="assistant auth login"
          note="Uses the official @assistant-ai/assistant-agent-sdk to invoke your installed assistant Code session. Works for both Pro / Max subscription auth (the SDK handles the OAuth that `assistant -p` alone refuses) and assistant Console API billing — whichever `assistant auth login` was run with."
        />
      )}

      {cfg.provider === "codex-cli" && (
        <CliStatusSection
          kind="codex-cli"
          status={codex}
          onRefresh={reloadProbes}
          loginCmd="codex login"
          note="Uses the ChatGPT Plus / Pro / Business / Edu / Enterprise subscription linked via `codex login`. OpenAI explicitly supports subscription OAuth in third-party tools for Codex."
        />
      )}

      <Row label="Default model" hint="Type any model id, or pick from the list.">
        <ModelCombobox
          value={cfg.model}
          options={models}
          onChange={changeModel}
          width={240}
        />
      </Row>
    </>
  );
}

function OpenRouterKeySection(props: {
  cfg: AiConfig;
  onSave: (k: string) => Promise<void>;
}) {
  const [draft, setDraft]   = useState("");
  const [revealed, setRev]  = useState(false);
  const [saving, setSaving] = useState(false);
  return (
    <>
      <Row
        label="OpenRouter API key"
        hint={props.cfg.hasKey
          ? (props.cfg.encrypted
              ? "Stored encrypted via the OS keychain (safeStorage). Paste a new key to replace."
              : "Stored as plaintext — your platform doesn't expose a keychain. Treat the userData dir as sensitive.")
          : "Paste a key from openrouter.ai/keys — never leaves the main process."}
      >
        <div style={{ display: "flex", gap: 4 }}>
          <input
            type={revealed ? "text" : "password"}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder={props.cfg.hasKey ? "•••••• (key set)" : "sk-or-v1-…"}
            style={{
              width: 200,
              fontFamily: mono, fontSize: 11,
              color: C.text, background: C.bg,
              border: `1px solid ${C.border}`, borderRadius: 4,
              padding: "5px 8px",
            }}
          />
          <button onClick={() => setRev((r) => !r)} style={iconBtnStyle}>
            {revealed ? "hide" : "show"}
          </button>
          <button
            onClick={async () => { if (!draft) return;
              setSaving(true);
              try { await props.onSave(draft); setDraft(""); }
              finally { setSaving(false); } }}
            disabled={!draft || saving}
            style={{
              ...iconBtnStyle,
              background: draft ? C.accent : C.bgMuted,
              color:      draft ? "#fff"   : C.textMuted,
              cursor:     draft ? "pointer" : "not-allowed",
            }}
          >save</button>
        </div>
      </Row>
      {props.cfg.hasKey && (
        <Row label="Forget stored key" hint="Removes the key from disk. Settings panel can re-add it later.">
          <button
            onClick={() => props.onSave("")}
            style={{ ...iconBtnStyle, borderColor: C.red, color: C.red }}
          >forget key</button>
        </Row>
      )}
    </>
  );
}

function NineRouterSection(props: {
  cfg: AiConfig;
  onSave: (k: string) => Promise<void>;
}) {
  const [draft, setDraft]   = useState("");
  const [revealed, setRev]  = useState(false);
  const [saving, setSaving] = useState(false);
  return (
    <>
      <Row
        label="9Router endpoint"
        hint="Local proxy that fans out to 40+ providers with subscription / cheap / free tier fallback. Defaults to http://localhost:20128 — override with EMBER_9ROUTER_URL."
      >
        <code style={{
          fontFamily: mono, fontSize: 11,
          color: C.text, background: C.bg,
          border: `1px solid ${C.border}`, borderRadius: 4,
          padding: "5px 10px",
        }}>http://localhost:20128</code>
      </Row>
      <Row
        label="API key (optional)"
        hint={props.cfg.hasKey
          ? "Stored. Only needed if you set REQUIRE_API_KEY=true on the proxy (e.g. you exposed it to the internet)."
          : "Leave blank for local use. Set only if your 9router proxy requires a Bearer key."}
      >
        <div style={{ display: "flex", gap: 4 }}>
          <input
            type={revealed ? "text" : "password"}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder={props.cfg.hasKey ? "•••••• (key set)" : "(blank for local)"}
            style={{
              width: 200,
              fontFamily: mono, fontSize: 11,
              color: C.text, background: C.bg,
              border: `1px solid ${C.border}`, borderRadius: 4,
              padding: "5px 8px",
            }}
          />
          <button onClick={() => setRev((r) => !r)} style={iconBtnStyle}>
            {revealed ? "hide" : "show"}
          </button>
          <button
            onClick={async () => { if (!draft) return;
              setSaving(true);
              try { await props.onSave(draft); setDraft(""); }
              finally { setSaving(false); } }}
            disabled={!draft || saving}
            style={{
              ...iconBtnStyle,
              background: draft ? C.accent : C.bgMuted,
              color:      draft ? "#fff"   : C.textMuted,
              cursor:     draft ? "pointer" : "not-allowed",
            }}
          >save</button>
        </div>
      </Row>
      {props.cfg.hasKey && (
        <Row label="Forget stored key" hint="Removes the key from disk.">
          <button
            onClick={() => props.onSave("")}
            style={{ ...iconBtnStyle, borderColor: C.red, color: C.red }}
          >forget key</button>
        </Row>
      )}
    </>
  );
}

function CliStatusSection(props: {
  kind:     "assistant-cli" | "codex-cli";
  status:   AiCliStatus | null;
  onRefresh: () => void;
  loginCmd: string;
  note:     string;
}) {
  const s = props.status;
  const statusLabel =
    !s               ? "probing…"
    : !s.installed   ? "not installed"
    : !s.loggedIn    ? "installed · not signed in"
    :                  `signed in · ${s.version}`;
  const statusColor =
    !s               ? C.textFaint
    : !s.installed   ? C.red
    : !s.loggedIn    ? C.red
    :                  C.green;

  return (
    <>
      <Row label="Auth status" hint={props.note}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{
            width: 7, height: 7, borderRadius: 4,
            background: statusColor, flexShrink: 0,
          }} />
          <span style={{ fontFamily: mono, fontSize: 11, color: C.text }}>
            {statusLabel}
          </span>
          <button onClick={props.onRefresh} style={iconBtnStyle}>recheck</button>
        </div>
      </Row>
      {s && !s.loggedIn && (
        <Row label="To sign in" hint="Run in a terminal, then click recheck above.">
          <code style={{
            fontFamily: mono, fontSize: 11,
            color: C.accent,
            background: C.bg,
            border: `1px solid ${C.border}`,
            borderRadius: 4,
            padding: "5px 10px",
            whiteSpace: "nowrap",
          }}>{props.loginCmd}</code>
        </Row>
      )}
    </>
  );
}

const iconBtnStyle: React.CSSProperties = {
  padding: "5px 10px",
  background: C.bgMuted, color: C.text,
  border: `1px solid ${C.border}`, borderRadius: 4,
  fontFamily: mono, fontSize: 10, cursor: "pointer",
};

// Free-text input with a custom dropdown of suggestions. Beats
// `<input list>` + `<datalist>` because the native datalist popup is
// styled by the host OS (white box on Linux, ugly grey on Windows)
// and can't be themed to match the rest of the UI. We render the
// popup ourselves so it picks up Ember's dark tokens. Still
// free-text-editable so the user can type any model id the proxy
// supports — the suggestion list is just a hinted shortlist.
export function ModelCombobox(props: {
  value:    string;
  options:  string[];
  onChange: (v: string) => void;
  width?:   number;
}) {
  const [draft, setDraft]   = useState(props.value);
  const [open,  setOpen]    = useState(false);
  const [active, setActive] = useState(-1);
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => { setDraft(props.value); }, [props.value]);

  // Close on outside-click. Inside-clicks (input, popup) bubble to
  // the wrapper and don't trigger this.
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [open]);

  const filtered = useMemo(() => {
    const q = draft.trim().toLowerCase();
    if (!q) return props.options;
    return props.options.filter((m) => m.toLowerCase().includes(q));
  }, [draft, props.options]);

  const commit = (v: string) => {
    const t = v.trim();
    if (t && t !== props.value) props.onChange(t);
    else if (!t) setDraft(props.value);
    setOpen(false);
    setActive(-1);
  };

  const width = props.width ?? 220;
  return (
    <div ref={wrapRef} style={{ position: "relative", width }}>
      <input
        ref={inputRef}
        value={draft}
        onChange={(e) => { setDraft(e.target.value); setOpen(true); setActive(-1); }}
        onFocus={() => setOpen(true)}
        onBlur={() => {
          // Defer so a click on a popup row registers before close.
          setTimeout(() => commit(draft), 100);
        }}
        onKeyDown={(e) => {
          if (e.key === "Enter") {
            e.preventDefault();
            commit(active >= 0 && filtered[active] ? filtered[active] : draft);
            inputRef.current?.blur();
          } else if (e.key === "Escape") {
            setDraft(props.value); setOpen(false); setActive(-1);
            inputRef.current?.blur();
          } else if (e.key === "ArrowDown") {
            e.preventDefault();
            setOpen(true);
            setActive((a) => Math.min(filtered.length - 1, a + 1));
          } else if (e.key === "ArrowUp") {
            e.preventDefault();
            setActive((a) => Math.max(-1, a - 1));
          }
        }}
        spellCheck={false}
        autoCapitalize="off"
        autoCorrect="off"
        placeholder="vendor/model-id"
        style={{
          background: C.bgMuted, color: C.text,
          border: `1px solid ${open ? C.borderStrong : C.border}`,
          borderRadius: 4,
          padding: "5px 8px",
          fontFamily: mono, fontSize: 11,
          width: "100%",
          boxSizing: "border-box",
          outline: "none",
        }}
      />
      {open && filtered.length > 0 && (
        <div
          style={{
            position: "absolute", top: "calc(100% + 4px)", left: 0,
            width: "100%",
            maxHeight: 240, overflowY: "auto",
            background: C.bgAlt,
            border: `1px solid ${C.borderStrong}`,
            borderRadius: 4,
            boxShadow: "0 8px 20px rgba(0,0,0,0.45)",
            zIndex: 4000,
            padding: 2,
          }}
          // Keep input focused when clicking the popup chrome.
          onMouseDown={(e) => e.preventDefault()}
        >
          {filtered.map((m, i) => {
            const isActive = i === active;
            return (
              <div
                key={m}
                onMouseEnter={() => setActive(i)}
                onClick={() => commit(m)}
                style={{
                  padding: "5px 8px",
                  fontFamily: mono, fontSize: 11,
                  color: isActive ? "#fff" : C.text,
                  background: isActive ? C.accent : "transparent",
                  borderRadius: 3,
                  cursor: "pointer",
                  whiteSpace: "nowrap",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                }}
              >{m}</div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function Segmented<T extends string>(props: {
  value: T;
  options: readonly T[];
  onChange: (v: T) => void;
}) {
  return (
    <div style={{
      display: "flex",
      background: C.bgMuted,
      border: `1px solid ${C.border}`,
      borderRadius: 4,
      overflow: "hidden",
    }}>
      {props.options.map((o, i) => {
        const active = props.value === o;
        return (
          <button
            key={o}
            type="button"
            onClick={() => props.onChange(o)}
            style={{
              padding: "5px 12px",
              background: active ? C.accent : "transparent",
              color: active ? "#fff" : C.textMuted,
              border: "none",
              borderLeft: i > 0 ? `1px solid ${C.border}` : "none",
              fontFamily: mono, fontSize: 11,
              fontWeight: active ? 600 : 400,
              cursor: "pointer",
              transition: "background .12s, color .12s",
            }}
          >{o}</button>
        );
      })}
    </div>
  );
}
