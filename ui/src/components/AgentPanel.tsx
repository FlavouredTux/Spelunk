import { useEffect, useMemo, useRef, useState } from "react";
import { C, sans, mono, serif } from "../theme";

// Agent harness dashboard. Read-only views over agent/src/intel/log.ts
// JSONL state plus the per-run events.jsonl files. Polls every 2s
// while open — the underlying writes are append-only so partial reads
// are always consistent. No streaming subscription mechanism needed.

declare global {
    interface Window {
        ember: any;  // wider surface than typed; we only touch ember.agent here
    }
}

type Claim = {
    kind: "claim";
    id: string; agent: string; ts: string;
    subject: string; predicate: string; value: string;
    evidence: string; confidence: number;
    supersedes?: string;
};
type Retract = {
    kind: "retract";
    id: string; agent: string; ts: string;
    target_id: string; reason: string;
};
type Decision = {
    key: string;
    winner: Claim;
    runners_up: Claim[];
    disputed: boolean;
};
type IntelView = { path?: string; entries: Array<Claim | Retract>; view: Decision[] };

type RunSummary = {
    id: string; last: string; turns: number;
    role: string; model: string; scope: string;
    usd: number; mtime: number;
    claimsFiled?: number;       // 0 = wasted run (context-only)
    forced?: boolean;            // worker had to be nudged with a force_claim message
};

const ROLE_COLOR: Record<string, string> = {
    namer:      C.accent,
    mapper:     C.blue,
    typer:      C.green,
    tiebreaker: C.violet,
    cli:        C.textMuted,
    human:      C.yellow,
};

const PRED_COLOR: Record<string, string> = {
    name:      C.accent,
    note:      C.blue,
    type:      C.green,
    tag:       C.violet,
    xref:      C.textMuted,
    signature: C.yellow,
};

function fmtAgo(ms: number): string {
    const d = Date.now() - ms;
    if (d < 60_000)        return `${Math.round(d / 1000)}s`;
    if (d < 3_600_000)     return `${Math.round(d / 60_000)}m`;
    if (d < 86_400_000)    return `${Math.round(d / 3_600_000)}h`;
    return `${Math.round(d / 86_400_000)}d`;
}

function fmtUsd(usd: number): string {
    if (usd < 0.001) return "$<0.001";
    if (usd < 1)     return `$${usd.toFixed(3)}`;
    return `$${usd.toFixed(2)}`;
}

export function AgentPanel(props: {
    binaryPath: string | null;
    onClose: () => void;
}) {
    const [intel, setIntel]   = useState<IntelView>({ entries: [], view: [] });
    const [runs, setRuns]     = useState<RunSummary[]>([]);
    const [tailEvents, setTailEvents] = useState<Array<Record<string, any>>>([]);
    const [activeRun, setActiveRun]   = useState<string | null>(null);
    const [busy, setBusy] = useState<string | null>(null);
    const [toast, setToast] = useState<string | null>(null);

    // Refresh poller. 2s feels live without thrashing the FS.
    useEffect(() => {
        let alive = true;
        const refresh = async () => {
            if (!alive) return;
            try {
                const [iv, rs] = await Promise.all([
                    props.binaryPath
                        ? window.ember.agent.intelView(props.binaryPath)
                        : Promise.resolve({ entries: [], view: [] }),
                    window.ember.agent.listRuns(),
                ]);
                if (!alive) return;
                setIntel(iv);
                setRuns(rs);
                if (activeRun) {
                    const ev = await window.ember.agent.tailRun(activeRun);
                    if (alive) setTailEvents(ev);
                }
            } catch { /* ignore transient */ }
        };
        refresh();
        const h = setInterval(refresh, 2000);
        return () => { alive = false; clearInterval(h); };
    }, [props.binaryPath, activeRun]);

    const stats = useMemo(() => {
        const claims = intel.entries.filter((e): e is Claim => e.kind === "claim");
        const retracts = intel.entries.filter((e) => e.kind === "retract");
        const disputed = intel.view.filter((d) => d.disputed);
        const agents = new Set(claims.map((c) => c.agent)).size;
        const subjects = new Set(claims.map((c) => c.subject)).size;
        const totalUsd = runs.reduce((s, r) => s + (r.usd || 0), 0);
        const liveRuns = runs.filter((r) =>
            r.last !== "done" && r.last !== "max_turns" &&
            r.last !== "abort" && r.last !== "error" &&
            r.last !== "budget_exhausted" &&
            Date.now() - r.mtime < 5 * 60_000).length;
        // Workers that completed (any terminal state) without filing a
        // claim — the libloader.so failure mode. Surfacing this lets the
        // user spot bad-faith targets early.
        const finishedRuns = runs.filter((r) =>
            r.last === "done" || r.last === "max_turns" ||
            r.last === "abort" || r.last === "budget_exhausted");
        const wastedRuns = finishedRuns.filter((r) => (r.claimsFiled ?? 0) === 0).length;
        return {
            claims:     claims.length,
            retracts:   retracts.length,
            disputed:   disputed.length,
            promotable: intel.view.filter((d) => !d.disputed && d.winner.confidence >= 0.85).length,
            agents,
            subjects,
            totalUsd,
            liveRuns,
            wastedRuns,
            finishedRuns: finishedRuns.length,
        };
    }, [intel, runs]);

    const disputed = useMemo(() => intel.view.filter((d) => d.disputed), [intel]);
    const recent   = useMemo(() => {
        const claims = intel.entries.filter((e): e is Claim => e.kind === "claim");
        return [...claims].sort((a, b) => b.ts.localeCompare(a.ts)).slice(0, 30);
    }, [intel]);

    const onPromote = async (apply: boolean) => {
        if (!props.binaryPath) return;
        setBusy(apply ? "applying…" : "previewing…");
        try {
            const r = await window.ember.agent.promote({
                binary: props.binaryPath, threshold: 0.85,
                apply, dryRun: !apply,
            });
            setToast(`promoted ${r.promoted}; skipped ${r.skipped?.disputed ?? 0} disputed, ${r.skipped?.low_conf ?? 0} low-conf`);
            setTimeout(() => setToast(null), 4000);
        } catch (e: any) {
            setToast(`error: ${e?.message ?? e}`);
            setTimeout(() => setToast(null), 4000);
        } finally { setBusy(null); }
    };

    const onCascade = async () => {
        if (!props.binaryPath) return;
        setBusy("cascading…");
        try {
            const r = await window.ember.agent.cascade({
                binary: props.binaryPath,
                role: "namer",
                perRound: 30, maxRounds: 5,
                budget: 0.05, threshold: 0.85,
                eligibilityRatio: 0.5,
            });
            const namedAcrossRounds = (r.rounds ?? []).reduce((s: number, x: any) => s + (x.new_names ?? 0), 0);
            setToast(`cascade: ${r.rounds?.length ?? 0} rounds · +${namedAcrossRounds} names · $${(r.total_cost ?? 0).toFixed(3)}`);
            setTimeout(() => setToast(null), 6000);
        } catch (e: any) {
            setToast(`cascade error: ${e?.message ?? e}`);
            setTimeout(() => setToast(null), 6000);
        } finally { setBusy(null); }
    };

    return (
        <div
            style={{
                position: "fixed", inset: 0,
                background: C.bg,
                color: C.text,
                fontFamily: sans,
                zIndex: 200,
                display: "flex", flexDirection: "column",
            }}
        >
            <Header
                disputed={stats.disputed}
                onClose={props.onClose}
                onPromoteApply={() => onPromote(true)}
                onPromoteDry={() => onPromote(false)}
                onCascade={onCascade}
                disabled={!props.binaryPath || busy != null}
                busyLabel={busy}
            />

            {/* Stat cards */}
            <div style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
                gap: 10,
                padding: "16px 20px",
                borderBottom: `1px solid ${C.border}`,
                background: C.bgAlt,
            }}>
                <Stat label="claims"      value={stats.claims}      tint={C.text} />
                <Stat label="agents"      value={stats.agents}      tint={C.blue} />
                <Stat label="subjects"    value={stats.subjects}    tint={C.text} />
                <Stat label="promotable"  value={stats.promotable}  tint={C.green} hint="conf ≥ 0.85, not disputed" />
                <Stat label="disputed"    value={stats.disputed}    tint={stats.disputed > 0 ? C.red : C.textMuted} hint="needs tiebreaker" />
                <Stat label="retracts"    value={stats.retracts}    tint={C.textMuted} />
                <Stat label="live runs"   value={stats.liveRuns}    tint={stats.liveRuns > 0 ? C.accent : C.textMuted} pulse={stats.liveRuns > 0} />
                <Stat label="wasted runs" value={stats.wastedRuns}   tint={stats.wastedRuns > 0 ? C.red : C.textMuted} hint={`${stats.wastedRuns}/${stats.finishedRuns} ended without a claim`} />
                <Stat label="swarm spend" value={fmtUsd(stats.totalUsd)} tint={C.yellow} />
            </div>

            {/* Main content */}
            <div style={{
                flex: 1,
                display: "grid",
                gridTemplateColumns: "1.1fr 1fr 1.4fr",
                gap: 0,
                minHeight: 0,
            }}>
                <DisputesColumn disputes={disputed} />
                <RecentClaimsColumn recent={recent} />
                <RunsColumn
                    runs={runs}
                    activeRun={activeRun}
                    setActiveRun={setActiveRun}
                    tailEvents={tailEvents}
                />
            </div>

            {/* Bottom: agent activity ribbon */}
            <ActivityRibbon claims={intel.entries.filter((e): e is Claim => e.kind === "claim")} />

            {toast && (
                <div style={{
                    position: "absolute", bottom: 16, left: "50%",
                    transform: "translateX(-50%)",
                    background: C.bgDark, color: C.text,
                    padding: "8px 16px",
                    borderRadius: 6,
                    border: `1px solid ${C.borderStrong}`,
                    fontFamily: mono, fontSize: 12,
                    boxShadow: "0 4px 16px rgba(0,0,0,0.4)",
                }}>
                    {toast}
                </div>
            )}
        </div>
    );
}

function Header(props: {
    disputed: number;
    onClose: () => void;
    onPromoteApply: () => void;
    onPromoteDry: () => void;
    onCascade: () => void;
    disabled: boolean;
    busyLabel: string | null;
}) {
    return (
        <div style={{
            display: "flex", alignItems: "center", justifyContent: "space-between",
            padding: "14px 20px",
            borderBottom: `1px solid ${C.border}`,
            background: C.bgMuted,
        }}>
            <div style={{ display: "flex", alignItems: "baseline", gap: 12 }}>
                <span style={{ fontFamily: serif, fontStyle: "italic", fontSize: 18, color: C.text }}>
                    Agentic
                </span>
                <span style={{ fontFamily: mono, fontSize: 11, color: C.textMuted }}>
                    swarm command center · live intel
                </span>
                {props.disputed > 0 && (
                    <span style={{
                        fontFamily: mono, fontSize: 10,
                        color: C.red,
                        background: "rgba(199,93,58,0.10)",
                        border: `1px solid ${C.red}`,
                        padding: "2px 8px", borderRadius: 999,
                    }}>
                        {props.disputed} disputed
                    </span>
                )}
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                {props.busyLabel && (
                    <span style={{ fontFamily: mono, fontSize: 11, color: C.textMuted }}>
                        {props.busyLabel}
                    </span>
                )}
                <Btn onClick={props.onCascade} disabled={props.disabled}>
                    ◈ cascade
                </Btn>
                <Btn onClick={props.onPromoteDry} disabled={props.disabled} ghost>
                    promote --dry-run
                </Btn>
                <Btn onClick={props.onPromoteApply} disabled={props.disabled} ghost>
                    promote --apply
                </Btn>
                <Btn onClick={props.onClose} ghost>close</Btn>
            </div>
        </div>
    );
}

function Btn(props: { onClick: () => void; children: React.ReactNode; ghost?: boolean; disabled?: boolean }) {
    return (
        <button
            onClick={props.onClick}
            disabled={props.disabled}
            style={{
                fontFamily: mono, fontSize: 11,
                padding: "6px 12px",
                borderRadius: 4,
                border: `1px solid ${props.ghost ? C.borderStrong : C.accent}`,
                background: props.ghost ? "transparent" : C.accent,
                color: props.ghost ? C.text : "#1a1410",
                cursor: props.disabled ? "default" : "pointer",
                opacity: props.disabled ? 0.5 : 1,
                transition: "background .12s, opacity .12s",
            }}
            onMouseEnter={(e) => {
                if (!props.disabled && !props.ghost) (e.currentTarget as HTMLElement).style.background = C.accentHover;
                if (!props.disabled && props.ghost)  (e.currentTarget as HTMLElement).style.background = C.bgDark;
            }}
            onMouseLeave={(e) => {
                if (!props.ghost) (e.currentTarget as HTMLElement).style.background = C.accent;
                else              (e.currentTarget as HTMLElement).style.background = "transparent";
            }}
        >
            {props.children}
        </button>
    );
}

function Stat(props: {
    label: string;
    value: number | string;
    tint: string;
    hint?: string;
    pulse?: boolean;
}) {
    return (
        <div style={{
            background: C.bgMuted,
            border: `1px solid ${C.border}`,
            borderRadius: 6,
            padding: "12px 14px",
            position: "relative",
        }}>
            <div style={{
                fontFamily: mono,
                fontSize: 10,
                color: C.textFaint,
                textTransform: "uppercase",
                letterSpacing: 1,
                marginBottom: 4,
                display: "flex", alignItems: "center", gap: 6,
            }}>
                {props.label}
                {props.pulse && <PulseDot tint={props.tint} />}
            </div>
            <div style={{
                fontFamily: serif, fontSize: 26,
                color: props.tint,
                lineHeight: 1.1,
                fontVariantNumeric: "tabular-nums",
            }}>
                {props.value}
            </div>
            {props.hint && (
                <div style={{
                    fontFamily: serif, fontStyle: "italic",
                    fontSize: 10, color: C.textFaint,
                    marginTop: 2,
                }}>
                    {props.hint}
                </div>
            )}
        </div>
    );
}

function PulseDot(props: { tint: string }) {
    return (
        <span style={{
            display: "inline-block",
            width: 6, height: 6,
            borderRadius: "50%",
            background: props.tint,
            boxShadow: `0 0 0 0 ${props.tint}`,
            animation: "agent-pulse 1.6s infinite",
        }} />
    );
}

function DisputesColumn(props: { disputes: Decision[] }) {
    return (
        <Column title="Disputes" subtitle="orchestrator decides">
            {props.disputes.length === 0 && (
                <Empty msg="No disputes. Swarm in agreement." />
            )}
            {props.disputes.map((d) => (
                <div key={d.key} style={{
                    border: `1px solid ${C.red}`,
                    background: "rgba(199,93,58,0.06)",
                    borderRadius: 6, padding: 10, marginBottom: 8,
                }}>
                    <div style={{ fontFamily: mono, fontSize: 11, color: C.textMuted }}>
                        {d.winner.subject}<span style={{ color: C.textFaint }}> · {d.winner.predicate}</span>
                    </div>
                    <div style={{ marginTop: 6 }}>
                        <ClaimRow claim={d.winner} mark="A" />
                        {d.runners_up[0] && <ClaimRow claim={d.runners_up[0]} mark="B" />}
                    </div>
                </div>
            ))}
        </Column>
    );
}

function ClaimRow(props: { claim: Claim; mark: string }) {
    const c = props.claim;
    const color = ROLE_COLOR[c.agent.split("-")[0]] ?? C.text;
    return (
        <div style={{
            display: "grid",
            gridTemplateColumns: "auto 1fr auto",
            gap: 8,
            alignItems: "baseline",
            padding: "4px 0",
        }}>
            <span style={{
                fontFamily: mono, fontSize: 10,
                color: C.textFaint,
                width: 14, textAlign: "center",
            }}>{props.mark}</span>
            <div style={{ minWidth: 0 }}>
                <div style={{
                    fontFamily: mono, fontSize: 12, color,
                    overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                }}>{c.value}</div>
                <div style={{
                    fontFamily: serif, fontStyle: "italic", fontSize: 10.5,
                    color: C.textMuted,
                    overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                }}>{c.evidence}</div>
            </div>
            <div style={{ fontFamily: mono, fontSize: 10, color: C.textMuted, textAlign: "right" }}>
                <div>{c.confidence.toFixed(2)}</div>
                <div style={{ color: C.textFaint }}>{c.agent.split("-")[0]}</div>
            </div>
        </div>
    );
}

function RecentClaimsColumn(props: { recent: Claim[] }) {
    return (
        <Column title="Recent claims" subtitle="last 30 entries">
            {props.recent.length === 0 && <Empty msg="No claims yet — spawn workers via fanout." />}
            {props.recent.map((c) => {
                const roleColor = ROLE_COLOR[c.agent.split("-")[0]] ?? C.textMuted;
                const predColor = PRED_COLOR[c.predicate] ?? C.textMuted;
                return (
                    <div key={c.id} style={{
                        padding: "6px 0",
                        borderBottom: `1px solid ${C.border}`,
                    }}>
                        <div style={{ display: "flex", gap: 8, alignItems: "baseline", fontFamily: mono, fontSize: 11 }}>
                            <span style={{ color: C.textFaint, width: 56 }}>{c.subject}</span>
                            <span style={{ color: predColor, width: 56 }}>{c.predicate}</span>
                            <span style={{ color: C.text, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                {c.value}
                            </span>
                            <span style={{ color: roleColor, fontSize: 10 }}>{c.agent.split("-")[0]}</span>
                            <span style={{ color: C.textMuted, fontSize: 10, width: 32, textAlign: "right" }}>
                                {c.confidence.toFixed(2)}
                            </span>
                        </div>
                        {c.evidence && (
                            <div style={{
                                fontFamily: serif, fontStyle: "italic", fontSize: 10.5,
                                color: C.textMuted, marginTop: 2, paddingLeft: 64,
                                overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                            }}>{c.evidence}</div>
                        )}
                    </div>
                );
            })}
        </Column>
    );
}

function RunsColumn(props: {
    runs: RunSummary[];
    activeRun: string | null;
    setActiveRun: (id: string | null) => void;
    tailEvents: Array<Record<string, any>>;
}) {
    return (
        <Column title="Runs" subtitle="click to tail" noPad>
            <div style={{
                display: "grid", gridTemplateColumns: "1fr 1fr",
                height: "100%", minHeight: 0,
            }}>
                {/* List */}
                <div style={{
                    overflowY: "auto", borderRight: `1px solid ${C.border}`,
                    padding: "0 12px",
                }}>
                    {props.runs.length === 0 && <Empty msg="No runs yet." />}
                    {props.runs.slice(0, 40).map((r) => {
                        const live = r.last !== "done" && r.last !== "max_turns" && r.last !== "abort" && r.last !== "error" && r.last !== "budget_exhausted" && (Date.now() - r.mtime < 5 * 60_000);
                        const active = props.activeRun === r.id;
                        const tint = ROLE_COLOR[r.role] ?? C.textMuted;
                        return (
                            <button key={r.id}
                                onClick={() => props.setActiveRun(active ? null : r.id)}
                                style={{
                                    display: "block",
                                    width: "100%",
                                    background: active ? C.bgDark : "transparent",
                                    border: `1px solid ${active ? C.borderStrong : "transparent"}`,
                                    color: C.text,
                                    textAlign: "left",
                                    padding: "8px 8px",
                                    borderRadius: 4,
                                    cursor: "pointer",
                                    marginTop: 4,
                                    fontFamily: mono, fontSize: 11,
                                }}
                                onMouseEnter={(e) => { if (!active) (e.currentTarget as HTMLElement).style.background = C.bgMuted; }}
                                onMouseLeave={(e) => { if (!active) (e.currentTarget as HTMLElement).style.background = "transparent"; }}
                            >
                                <div style={{ display: "flex", alignItems: "baseline", gap: 6 }}>
                                    {live && <PulseDot tint={tint} />}
                                    <span style={{ color: tint }}>{r.role}</span>
                                    <span style={{ color: C.textFaint }}>{r.id}</span>
                                </div>
                                <div style={{ color: C.textMuted, fontSize: 10, marginTop: 2 }}>
                                    {r.scope} · {r.turns} turns · {fmtUsd(r.usd)} · {fmtAgo(r.mtime)} ago
                                </div>
                                {!live && (r.claimsFiled === 0 || r.forced) && (
                                    <div style={{
                                        marginTop: 4,
                                        fontFamily: mono, fontSize: 9.5,
                                        color: r.claimsFiled === 0 ? C.red : C.yellow,
                                    }}>
                                        {r.claimsFiled === 0 ? "✗ no claim filed" : "⚠ forced to claim"}
                                    </div>
                                )}
                            </button>
                        );
                    })}
                </div>
                {/* Tail */}
                <div style={{ overflowY: "auto", padding: "0 12px" }}>
                    {!props.activeRun && <Empty msg="select a run" />}
                    {props.activeRun && props.tailEvents.length === 0 && <Empty msg="no events yet" />}
                    {props.activeRun && props.tailEvents.slice(-80).reverse().map((e, i) => (
                        <div key={i} style={{
                            fontFamily: mono, fontSize: 10.5, color: C.textMuted,
                            padding: "3px 0",
                            borderBottom: `1px solid ${C.border}`,
                            wordBreak: "break-all",
                        }}>
                            <span style={{ color: kindColor(e.kind) }}>{e.kind}</span>
                            {e.kind === "tool_ok" && <> {e.name}({JSON.stringify(e.input).slice(0, 40)}) → {e.bytes}B</>}
                            {e.kind === "tool_err" && <> {e.name}: <span style={{ color: C.red }}>{(e.err ?? "").slice(0, 60)}</span></>}
                            {e.kind === "turn" && <> {e.turn} stop={e.stop} usd={e.tally?.usd?.toFixed(4)}</>}
                            {e.kind === "start" && <> {e.role} {e.model} {e.scope}</>}
                            {e.kind === "done" && <> turns={e.turns} usd={e.tally?.usd?.toFixed(4)}</>}
                        </div>
                    ))}
                </div>
            </div>
        </Column>
    );
}

function kindColor(k: string): string {
    switch (k) {
        case "tool_err":         return C.red;
        case "tool_ok":          return C.blue;
        case "done":             return C.green;
        case "start":            return C.accent;
        case "abort":
        case "max_turns":        return C.yellow;
        case "budget_exhausted": return C.yellow;
        default:                 return C.textMuted;
    }
}

// Bottom ribbon: per-agent confidence histogram, gives an at-a-glance
// read on swarm health (are agents claiming high or hedging?).
function ActivityRibbon(props: { claims: Claim[] }) {
    const buckets = useMemo(() => {
        const b = [0, 0, 0, 0, 0];   // [<.5, .5-.7, .7-.85, .85-.95, ≥.95]
        for (const c of props.claims) {
            const v = c.confidence;
            if      (v < 0.5)  ++b[0];
            else if (v < 0.7)  ++b[1];
            else if (v < 0.85) ++b[2];
            else if (v < 0.95) ++b[3];
            else               ++b[4];
        }
        return b;
    }, [props.claims]);
    const total = buckets.reduce((a, b) => a + b, 0) || 1;
    const labels = ["<.5", ".5–.7", ".7–.85", ".85–.95", "≥.95"];
    const colors = [C.red, C.yellow, C.textWarm, C.blue, C.green];
    return (
        <div style={{
            borderTop: `1px solid ${C.border}`,
            background: C.bgMuted,
            padding: "10px 20px",
            display: "flex", alignItems: "center", gap: 12,
        }}>
            <div style={{ fontFamily: mono, fontSize: 10, color: C.textFaint, width: 110, letterSpacing: 1, textTransform: "uppercase" }}>
                confidence
            </div>
            <div style={{ flex: 1, display: "flex", alignItems: "stretch", gap: 4, height: 22 }}>
                {buckets.map((n, i) => (
                    <div key={i} style={{
                        flexBasis: `${(n / total) * 100}%`,
                        background: colors[i],
                        borderRadius: 2,
                        position: "relative",
                        minWidth: n > 0 ? 12 : 0,
                        transition: "flex-basis .3s",
                    }} title={`${labels[i]}: ${n}`}>
                        {n > 0 && (
                            <span style={{
                                position: "absolute",
                                top: "50%", left: "50%",
                                transform: "translate(-50%,-50%)",
                                fontFamily: mono, fontSize: 10, color: "#1a1410",
                                fontWeight: 600,
                            }}>{n}</span>
                        )}
                    </div>
                ))}
            </div>
            <div style={{ fontFamily: mono, fontSize: 10, color: C.textMuted, width: 80, textAlign: "right" }}>
                {props.claims.length} claims
            </div>
        </div>
    );
}

function Column(props: { title: string; subtitle?: string; children: React.ReactNode; noPad?: boolean }) {
    return (
        <div style={{
            display: "flex", flexDirection: "column",
            borderRight: `1px solid ${C.border}`,
            minHeight: 0,
        }}>
            <div style={{
                padding: "10px 16px",
                borderBottom: `1px solid ${C.border}`,
                background: C.bgAlt,
            }}>
                <div style={{ fontFamily: serif, fontStyle: "italic", fontSize: 13, color: C.text }}>
                    {props.title}
                </div>
                {props.subtitle && (
                    <div style={{ fontFamily: mono, fontSize: 10, color: C.textFaint, marginTop: 2 }}>
                        {props.subtitle}
                    </div>
                )}
            </div>
            <div style={{
                flex: 1, overflowY: "auto",
                padding: props.noPad ? 0 : "10px 16px",
                minHeight: 0,
            }}>
                {props.children}
            </div>
        </div>
    );
}

function Empty(props: { msg: string }) {
    return (
        <div style={{
            fontFamily: serif, fontStyle: "italic",
            color: C.textFaint, fontSize: 12,
            padding: "20px 8px",
            textAlign: "center",
        }}>{props.msg}</div>
    );
}
