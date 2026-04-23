import { useEffect, useMemo, useState } from "react";
import { C, sans, serif, mono } from "../theme";
import { listPlugins, matchPlugin, runPluginCommand } from "../api";
import type {
  BinaryInfo, FunctionInfo, PluginInfo, PluginMatchResult, PluginRunResult,
  PluginPanelContribution,
} from "../types";

type LoadState =
  | { kind: "idle" }
  | { kind: "loading"; pluginId: string; panelId: string }
  | { kind: "ready"; pluginId: string; panelId: string; result: PluginRunResult }
  | { kind: "error"; pluginId: string; panelId: string; message: string };

// Find the function whose extent covers `ip` so a row that only carries
// a raw VA still jumps somewhere useful. Linear — functions list is
// small enough that this isn't a hot path.
function resolveFunctionAt(info: BinaryInfo, ip: number): FunctionInfo | null {
  for (const f of info.functions) {
    if (f.size > 0 && ip >= f.addrNum && ip < f.addrNum + f.size) return f;
  }
  for (const f of info.functions) {
    if (f.addrNum === ip) return f;
  }
  return null;
}

export function PluginsPanelView(props: {
  info: BinaryInfo;
  onSelect: (fn: FunctionInfo) => void;
  onClose: () => void;
}) {
  const { info, onSelect, onClose } = props;
  const [plugins, setPlugins] = useState<PluginInfo[] | null>(null);
  const [matches, setMatches] = useState<Record<string, PluginMatchResult>>({});
  const [state, setState] = useState<LoadState>({ kind: "idle" });

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.preventDefault(); onClose(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  useEffect(() => {
    let cancel = false;
    listPlugins().then((p) => { if (!cancel) setPlugins(p); }).catch(() => {
      if (!cancel) setPlugins([]);
    });
    return () => { cancel = true; };
  }, []);

  useEffect(() => {
    if (!plugins) return;
    let cancel = false;
    (async () => {
      const results: Record<string, PluginMatchResult> = {};
      await Promise.all(plugins.map(async (p) => {
        if (p.invalid) return;
        try { results[p.id] = await matchPlugin(p.id); } catch { /* leave unset */ }
      }));
      if (!cancel) setMatches(results);
    })();
    return () => { cancel = true; };
  }, [plugins]);

  // Plugins that contribute at least one panel. Unmatched plugins stay
  // visible but their rows render muted (same run-anyway rule as the
  // Settings card).
  const pluginRows = useMemo(() => {
    if (!plugins) return [];
    const rows: Array<{ plugin: PluginInfo; match: PluginMatchResult | null }> = [];
    for (const p of plugins) {
      if (p.invalid) continue;
      if (!p.contributes?.panels?.length) continue;
      rows.push({ plugin: p, match: matches[p.id] ?? null });
    }
    return rows;
  }, [plugins, matches]);

  async function openPanel(plugin: PluginInfo, panel: PluginPanelContribution) {
    const match = matches[plugin.id];
    const hasMatchers = plugin.matchers && plugin.matchers.length > 0;
    if (hasMatchers && match && !match.matched) {
      const proceed = window.confirm(
        `${plugin.name} did not match this binary. Open "${panel.title}" anyway?`,
      );
      if (!proceed) return;
    }
    setState({ kind: "loading", pluginId: plugin.id, panelId: panel.id });
    try {
      const result = await runPluginCommand(plugin.id, panel.command, { apply: false });
      setState({ kind: "ready", pluginId: plugin.id, panelId: panel.id, result });
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : String(e);
      setState({ kind: "error", pluginId: plugin.id, panelId: panel.id, message });
    }
  }

  function handleRowClick(addrHex: string | undefined) {
    if (!addrHex) return;
    const ip = parseInt(addrHex, 16);
    if (!Number.isFinite(ip)) return;
    const fn = resolveFunctionAt(info, ip);
    if (fn) {
      onSelect(fn);
      onClose();
    }
  }

  const activePanel =
    state.kind === "ready" || state.kind === "loading" || state.kind === "error"
      ? { pluginId: state.pluginId, panelId: state.panelId }
      : null;

  return (
    <div
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(10,10,9,0.55)",
        backdropFilter: "blur(3px)",
        zIndex: 1800,
        display: "flex",
        justifyContent: "center",
        padding: "6vh 5vw",
        animation: "fadeIn .15s ease-out",
      }}
    >
      <div
        style={{
          flex: 1,
          display: "flex",
          flexDirection: "column",
          background: C.bg,
          border: `1px solid ${C.borderStrong}`,
          borderRadius: 8,
          boxShadow: "0 30px 80px rgba(0,0,0,0.6)",
          overflow: "hidden",
        }}
      >
        <div style={{
          padding: "14px 20px",
          borderBottom: `1px solid ${C.border}`,
          display: "flex", alignItems: "center", gap: 18,
          background: C.bgAlt,
        }}>
          <div style={{ display: "flex", flexDirection: "column", lineHeight: 1.2 }}>
            <span style={{ fontFamily: sans, fontSize: 14, fontWeight: 600, color: C.text }}>
              Plugin panels
            </span>
            <span style={{ fontFamily: serif, fontStyle: "italic", fontSize: 11, color: C.textMuted, marginTop: 2 }}>
              {pluginRows.length} plugin{pluginRows.length === 1 ? "" : "s"} contributing panels
            </span>
          </div>
          <div style={{ flex: 1 }} />
          <button
            onClick={onClose}
            style={{
              padding: "4px 10px",
              fontFamily: mono, fontSize: 10,
              color: C.textMuted,
              background: C.bgMuted,
              border: `1px solid ${C.border}`,
              borderRadius: 4,
            }}
          >close</button>
        </div>

        <div style={{ flex: 1, display: "flex", minHeight: 0 }}>
          {/* Left: plugin + panel list */}
          <div style={{
            width: 280,
            borderRight: `1px solid ${C.border}`,
            overflowY: "auto",
            padding: "10px 8px",
            display: "flex", flexDirection: "column", gap: 12,
          }}>
            {pluginRows.length === 0 && (
              <div style={{
                padding: 18, textAlign: "center",
                fontFamily: serif, fontStyle: "italic", fontSize: 12, color: C.textFaint,
              }}>
                no plugin panels available
              </div>
            )}
            {pluginRows.map(({ plugin, match }) => {
              const hasMatchers = plugin.matchers && plugin.matchers.length > 0;
              const mismatched = hasMatchers && !!match && !match.matched;
              return (
                <div key={plugin.id} style={{ opacity: mismatched ? 0.65 : 1 }}>
                  <div style={{
                    padding: "4px 8px",
                    display: "flex", alignItems: "baseline", gap: 6,
                  }}>
                    <span style={{ fontFamily: sans, fontSize: 12, fontWeight: 600, color: C.text }}>
                      {plugin.name}
                    </span>
                    {hasMatchers && match && (
                      <span style={{
                        fontFamily: mono, fontSize: 9,
                        color: match.matched ? C.accent : (match.score > 0 ? "#d4a017" : C.textFaint),
                      }}>{match.matched ? "matches" : `${match.score}%`}</span>
                    )}
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: 2, padding: "0 4px" }}>
                    {plugin.contributes.panels.map((panel) => {
                      const active = activePanel &&
                        activePanel.pluginId === plugin.id &&
                        activePanel.panelId === panel.id;
                      return (
                        <button
                          key={panel.id}
                          onClick={() => openPanel(plugin, panel)}
                          title={panel.description}
                          style={{
                            padding: "5px 8px",
                            textAlign: "left",
                            background: active ? C.bgDark : "transparent",
                            border: `1px solid ${active ? C.borderStrong : "transparent"}`,
                            borderRadius: 4,
                            fontFamily: sans, fontSize: 11,
                            color: active ? C.text : C.textWarm,
                            fontStyle: mismatched ? "italic" : "normal",
                            cursor: "pointer",
                          }}
                        >{panel.title}</button>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Right: panel contents */}
          <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
            {state.kind === "idle" && (
              <div style={{
                flex: 1, display: "flex", alignItems: "center", justifyContent: "center",
                fontFamily: serif, fontStyle: "italic", fontSize: 13, color: C.textFaint,
              }}>
                pick a panel on the left
              </div>
            )}
            {state.kind === "loading" && (
              <div style={{
                flex: 1, display: "flex", alignItems: "center", justifyContent: "center",
                fontFamily: serif, fontStyle: "italic", fontSize: 13, color: C.textFaint,
              }}>
                running…
              </div>
            )}
            {state.kind === "error" && (
              <div style={{
                flex: 1, padding: 20,
                fontFamily: mono, fontSize: 11, color: C.red,
              }}>
                {state.message}
              </div>
            )}
            {state.kind === "ready" && (
              <PanelBody
                result={state.result}
                onJump={handleRowClick}
              />
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function PanelBody(props: {
  result: PluginRunResult;
  onJump: (addrHex: string | undefined) => void;
}) {
  const { result, onJump } = props;

  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", minHeight: 0 }}>
      <div style={{
        padding: "12px 18px",
        borderBottom: `1px solid ${C.border}`,
        background: C.bgAlt,
      }}>
        {result.summary && (
          <div style={{ fontFamily: sans, fontSize: 12, color: C.text }}>
            {result.summary}
          </div>
        )}
        {result.notes && (
          <div style={{
            marginTop: 4,
            fontFamily: serif, fontStyle: "italic", fontSize: 11, color: C.textMuted,
          }}>
            {result.notes}
          </div>
        )}
        {!result.panel && !result.summary && (
          <div style={{
            fontFamily: serif, fontStyle: "italic", fontSize: 11, color: C.textFaint,
          }}>
            command returned no panel data
          </div>
        )}
      </div>

      {result.panel?.kind === "list" && (
        <div style={{ flex: 1, overflowY: "auto", padding: "6px 0" }}>
          {result.panel.rows.length === 0 && (
            <div style={{
              padding: 20, fontFamily: serif, fontStyle: "italic",
              fontSize: 12, color: C.textFaint, textAlign: "center",
            }}>
              (empty)
            </div>
          )}
          {result.panel.rows.map((row, i) => {
            const hasAddr = !!row.addr;
            return (
              <button
                key={`${row.addr ?? ""}:${i}`}
                onClick={() => onJump(row.addr)}
                disabled={!hasAddr}
                style={{
                  width: "100%",
                  padding: "6px 18px",
                  textAlign: "left",
                  background: "transparent",
                  border: "none",
                  borderBottom: `1px solid ${C.border}`,
                  cursor: hasAddr ? "pointer" : "default",
                  display: "flex", alignItems: "baseline", gap: 12,
                }}
                onMouseEnter={(e) => {
                  if (hasAddr) (e.currentTarget as HTMLElement).style.background = C.bgMuted;
                }}
                onMouseLeave={(e) => {
                  (e.currentTarget as HTMLElement).style.background = "transparent";
                }}
              >
                {row.addr && (
                  <span style={{ fontFamily: mono, fontSize: 10, color: C.textFaint, minWidth: 100 }}>
                    {row.addr}
                  </span>
                )}
                <span style={{ flex: 1, fontFamily: sans, fontSize: 12, color: C.text, minWidth: 0 }}>
                  {row.label}
                </span>
                {row.detail && (
                  <span style={{
                    fontFamily: serif, fontStyle: "italic", fontSize: 11, color: C.textMuted,
                    whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", maxWidth: "40%",
                  }}>
                    {row.detail}
                  </span>
                )}
                {row.tags && row.tags.length > 0 && (
                  <span style={{ display: "flex", gap: 4 }}>
                    {row.tags.map((t) => (
                      <span
                        key={t}
                        style={{
                          fontFamily: mono, fontSize: 9,
                          padding: "1px 6px", borderRadius: 999,
                          border: `1px solid ${C.border}`, color: C.textFaint,
                        }}
                      >{t}</span>
                    ))}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
