import { useEffect, useMemo, useRef, useState } from "react";
import { C, mono, serif } from "../theme";

// Neural-network-shaped visualization of the agent swarm.
//
// Center: the intel hub — shared per-binary JSONL claim db. Pulses
// outward when a new claim arrives.
//
// Inner ring: live + recent workers, color by role. Idle workers fade.
// Each worker has a "halo" sized by its tool-call count this run.
//
// Outer ring: the subjects (functions) those workers are targeting.
// A disputed subject vibrates and glows red. A subject with a high-
// confidence claim glows the role color of the agent that named it.
//
// Edges: worker → subject (scope), and subject → hub (claim flow).
// Particles travel along the subject→hub edges when claims fire,
// giving the swarm a feedforward-network visual signature consistent
// with Anchor Cascade's actual topology.
//
// All physics is just polar arithmetic — no force-directed solver or
// d3 dependency. Looks alive without bringing in a graphics library.

const ROLE_COLOR: Record<string, string> = {
    namer:      C.accent,
    mapper:     C.blue,
    typer:      C.green,
    tiebreaker: C.violet,
    cli:        C.textMuted,
    human:      C.yellow,
    cascade:    C.accent,
};

interface WorkerPoint {
    id: string;
    role: string;
    angle: number;          // radians around the hub
    live: boolean;
    turns: number;
    claimsFiled: number;
    scope: string;
}

interface SubjectPoint {
    subject: string;
    angle: number;
    role: string;           // color from the winning claim's agent
    confidence: number;
    disputed: boolean;
}

interface Pulse {
    id: string;
    fromAngle: number;
    color: string;
    startedAt: number;
}

export function NeuralView(props: {
    runs: Array<{ id: string; role: string; scope: string; turns: number; claimsFiled?: number; mtime: number; last: string }>;
    view: Array<{ key: string; winner: { agent: string; subject: string; predicate: string; confidence: number; ts: string }; disputed: boolean }>;
    claimCount: number;
    disputedCount: number;     // full count from caller (doesn't depend on viz slice)
}) {
    const [pulses, setPulses] = useState<Pulse[]>([]);
    const lastClaimCount = useRef(props.claimCount);

    // Spawn a pulse every time the claim count increases. The particle
    // animates along its origin angle inward over 1.4s, then expires.
    useEffect(() => {
        if (props.claimCount > lastClaimCount.current) {
            const recent = [...props.view]
                .sort((a, b) => b.winner.ts.localeCompare(a.winner.ts))
                .slice(0, props.claimCount - lastClaimCount.current);
            const newPulses: Pulse[] = recent.map((d, i) => ({
                id: `p-${Date.now()}-${i}`,
                fromAngle: subjectAngle(d.winner.subject),
                color: ROLE_COLOR[d.winner.agent.split("-")[0]] ?? C.text,
                startedAt: Date.now(),
            }));
            setPulses((p) => [...p, ...newPulses].slice(-30));
        }
        lastClaimCount.current = props.claimCount;
    }, [props.claimCount, props.view]);

    // Garbage-collect expired pulses. 1500ms TTL.
    useEffect(() => {
        const h = setInterval(() => {
            setPulses((p) => p.filter((x) => Date.now() - x.startedAt < 1500));
        }, 500);
        return () => clearInterval(h);
    }, []);

    // Workers: place around hub. Most recent at the top; clockwise.
    const workers: WorkerPoint[] = useMemo(() => {
        const sorted = [...props.runs].sort((a, b) => b.mtime - a.mtime).slice(0, 24);
        return sorted.map((r, i) => ({
            id: r.id,
            role: r.role,
            angle: (-Math.PI / 2) + (i * 2 * Math.PI) / Math.max(sorted.length, 12),
            live: r.last !== "done" && r.last !== "max_turns" && r.last !== "abort" && r.last !== "error" && r.last !== "budget_exhausted" && (Date.now() - r.mtime < 5 * 60_000),
            turns: r.turns,
            claimsFiled: r.claimsFiled ?? 0,
            scope: r.scope,
        }));
    }, [props.runs]);

    // Subjects: each unique recent subject gets a slot on the outer
    // ring. Position derived from a stable hash of the address so the
    // same subject always lands at the same angle across renders.
    const subjects: SubjectPoint[] = useMemo(() => {
        const recent = [...props.view]
            .sort((a, b) => b.winner.ts.localeCompare(a.winner.ts))
            .slice(0, 60);
        return recent.map((d) => ({
            subject: d.winner.subject,
            angle: subjectAngle(d.winner.subject),
            role: d.winner.agent.split("-")[0],
            confidence: d.winner.confidence,
            disputed: d.disputed,
        }));
    }, [props.view]);

    // SVG viewport. Hub at (0,0); coordinates in -1..1 then scaled by W/2.
    const W = 720, H = 520;
    const cx = W / 2, cy = H / 2;
    const R_HUB = 36;
    const R_WORKER = 130;
    const R_SUBJECT = 220;

    return (
        <div style={{
            position: "relative",
            background: C.bgDark,
            borderTop: `1px solid ${C.border}`,
            height: H,
            overflow: "hidden",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
        }}>
            <svg width="100%" height={H} viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMidYMid meet" style={{ maxWidth: 900 }}>
                {/* Refined radial backdrop */}
                <defs>
                    <radialGradient id="bgrad" cx="50%" cy="50%" r="55%">
                        <stop offset="0%"  stopColor={C.bgAlt}  stopOpacity="0.6" />
                        <stop offset="60%" stopColor={C.bgDark} stopOpacity="0.2" />
                        <stop offset="100%" stopColor={C.bgDark} stopOpacity="0" />
                    </radialGradient>
                    <filter id="glow">
                        <feGaussianBlur stdDeviation="2.5" result="blur" />
                        <feMerge>
                            <feMergeNode in="blur" />
                            <feMergeNode in="SourceGraphic" />
                        </feMerge>
                    </filter>
                    <filter id="glow-soft">
                        <feGaussianBlur stdDeviation="1.5" result="blur" />
                        <feMerge>
                            <feMergeNode in="blur" />
                            <feMergeNode in="SourceGraphic" />
                        </feMerge>
                    </filter>
                </defs>
                <circle cx={cx} cy={cy} r={R_SUBJECT + 35} fill="url(#bgrad)" />

                {/* Worker → hub edges. Width by claims_filed. Live ones pulse. */}
                {workers.map((w) => {
                    const wx = cx + Math.cos(w.angle) * R_WORKER;
                    const wy = cy + Math.sin(w.angle) * R_WORKER;
                    const stroke = ROLE_COLOR[w.role] ?? C.textMuted;
                    const edgeWidth = Math.max(0.5, Math.min(2.5, 0.5 + w.claimsFiled * 0.6));
                    return (
                        <line key={`we-${w.id}`}
                            x1={cx} y1={cy} x2={wx} y2={wy}
                            stroke={stroke}
                            strokeWidth={edgeWidth}
                            strokeOpacity={w.live ? 0.55 : 0.18}
                            strokeLinecap="round"
                        />
                    );
                })}

                {/* Worker → subject edges (faint constellation). */}
                {workers.map((w) => {
                    if (!w.scope.startsWith("fn:")) return null;
                    const subj = w.scope.slice(3);
                    const a = subjectAngle(subj);
                    const wx = cx + Math.cos(w.angle) * R_WORKER;
                    const wy = cy + Math.sin(w.angle) * R_WORKER;
                    const sx = cx + Math.cos(a) * R_SUBJECT;
                    const sy = cy + Math.sin(a) * R_SUBJECT;
                    return (
                        <line key={`ws-${w.id}`}
                            x1={wx} y1={wy} x2={sx} y2={sy}
                            stroke={ROLE_COLOR[w.role] ?? C.textMuted}
                            strokeWidth={0.5}
                            strokeOpacity={w.live ? 0.35 : 0.12}
                            strokeDasharray="2 4"
                            strokeLinecap="round"
                        />
                    );
                })}

                {/* Subject nodes */}
                {subjects.map((s) => {
                    const sx = cx + Math.cos(s.angle) * R_SUBJECT;
                    const sy = cy + Math.sin(s.angle) * R_SUBJECT;
                    const stroke = s.disputed ? C.red : (ROLE_COLOR[s.role] ?? C.text);
                    const r = 2.5 + s.confidence * 4.5;
                    return (
                        <g key={`s-${s.subject}`} className={s.disputed ? "neural-jitter" : undefined}>
                            <circle cx={sx} cy={sy} r={r}
                                fill={s.disputed ? C.red : stroke}
                                fillOpacity={s.disputed ? 0.9 : (0.25 + s.confidence * 0.65)}
                                stroke={stroke}
                                strokeWidth={s.disputed ? 1.2 : 0.6}
                                strokeOpacity={s.disputed ? 0.7 : 0.4}
                                filter={s.disputed ? "url(#glow)" : undefined}
                            />
                        </g>
                    );
                })}

                {/* Worker nodes */}
                {workers.map((w) => {
                    const wx = cx + Math.cos(w.angle) * R_WORKER;
                    const wy = cy + Math.sin(w.angle) * R_WORKER;
                    const fill = ROLE_COLOR[w.role] ?? C.textMuted;
                    const nodeR = 4 + Math.min(5, w.turns * 0.35);
                    return (
                        <g key={`w-${w.id}`}>
                            {w.live && (
                                <circle cx={wx} cy={wy} r={nodeR + 5}
                                    fill="none"
                                    stroke={fill}
                                    strokeWidth={0.8}
                                    strokeOpacity={0.45}
                                    className="neural-halo"
                                />
                            )}
                            <circle cx={wx} cy={wy} r={nodeR}
                                fill={fill}
                                fillOpacity={w.live ? 0.95 : 0.3}
                                stroke={fill}
                                strokeWidth={w.live ? 1.2 : 0.5}
                                strokeOpacity={w.live ? 0.8 : 0.25}
                                filter={w.live ? "url(#glow-soft)" : undefined}
                            />
                        </g>
                    );
                })}

                {/* Inbound claim particles. Animate from subject angle
                    inward to the hub over 1.4s using SMIL — works
                    everywhere Electron renders SVG. */}
                {pulses.map((p) => {
                    const sx = cx + Math.cos(p.fromAngle) * R_SUBJECT;
                    const sy = cy + Math.sin(p.fromAngle) * R_SUBJECT;
                    return (
                        <circle key={p.id} r={3.5} fill={p.color} filter="url(#glow)">
                            <animate attributeName="cx"
                                from={sx} to={cx}
                                dur="1.4s" begin="0s" fill="freeze" />
                            <animate attributeName="cy"
                                from={sy} to={cy}
                                dur="1.4s" begin="0s" fill="freeze" />
                            <animate attributeName="opacity"
                                from="1" to="0"
                                dur="1.4s" begin="0s" fill="freeze" />
                        </circle>
                    );
                })}

                {/* Hub */}
                <circle cx={cx} cy={cy} r={R_HUB + 12}
                    fill="none" stroke={C.border} strokeWidth={1}
                    strokeDasharray="4 5"
                    opacity={0.5} />
                <circle cx={cx} cy={cy} r={R_HUB + 4}
                    fill="none" stroke={C.borderStrong} strokeWidth={0.5}
                    opacity={0.3} />
                <circle cx={cx} cy={cy} r={R_HUB}
                    fill={C.bgDark}
                    stroke={C.accent}
                    strokeWidth={2}
                    filter="url(#glow)" />
                <text x={cx} y={cy - 6}
                    textAnchor="middle"
                    fontFamily={mono}
                    fontSize={9}
                    fill={C.textFaint}
                    style={{ letterSpacing: 1.2, textTransform: "uppercase", fontWeight: 500 }}
                >
                    intel
                </text>
                <text x={cx} y={cy + 12}
                    textAnchor="middle"
                    fontFamily={serif}
                    fontStyle="italic"
                    fontSize={20}
                    fill={C.text}
                >
                    {props.claimCount}
                </text>
            </svg>

            <div style={{
                position: "absolute",
                bottom: 10,
                left: 14,
                fontFamily: mono,
                fontSize: 10,
                color: C.textFaint,
                background: C.bgDark,
                padding: "3px 8px",
                borderRadius: 4,
                border: `1px solid ${C.border}`,
                letterSpacing: 0.3,
            }}>
                {workers.filter((w) => w.live).length} live · {workers.length} total · {props.disputedCount} disputed
            </div>
            <Legend />
        </div>
    );
}

function Legend() {
    const items = [
        { color: C.accent, label: "namer / cascade" },
        { color: C.blue,   label: "mapper" },
        { color: C.green,  label: "typer" },
        { color: C.violet, label: "tiebreaker" },
        { color: C.red,    label: "disputed" },
    ];
    return (
        <div style={{
            position: "absolute",
            top: 14,
            right: 16,
            display: "flex",
            flexDirection: "column",
            gap: 6,
            fontFamily: mono,
            fontSize: 10,
            color: C.textFaint,
            background: C.bgDark,
            padding: "10px 12px",
            borderRadius: 8,
            border: `1px solid ${C.border}`,
            boxShadow: `0 2px 8px rgba(0,0,0,0.3)`,
        }}>
            {items.map((it) => (
                <span key={it.label} style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
                    <span style={{
                        width: 7, height: 7, borderRadius: "50%",
                        background: it.color,
                        boxShadow: `0 0 5px ${it.color}80`,
                        flexShrink: 0,
                    }} />
                    <span style={{ letterSpacing: 0.2 }}>{it.label}</span>
                </span>
            ))}
        </div>
    );
}

// Stable angle from a subject string. djb2 hash → [0, 2π).
function subjectAngle(subject: string): number {
    let h = 5381;
    for (let i = 0; i < subject.length; ++i) {
        h = (h * 33 + subject.charCodeAt(i)) >>> 0;
    }
    return (h % 360) * (Math.PI / 180);
}
