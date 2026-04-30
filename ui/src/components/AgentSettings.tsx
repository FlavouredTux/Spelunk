import { useEffect, useState } from "react";
import { C, sans, mono, serif } from "../theme";

// Settings drawer for the agent harness. Slides in from the right when
// the gear is clicked. Provider keys live in ~/.config/ember/agent.toml
// (mode 0600); the renderer never sees the raw key after the initial
// paste — agent:getConfig returns a masked tail like "••••sk-…xyz9".

const ROLES = ["namer", "mapper", "typer", "tiebreaker"] as const;
const ROLE_HINTS: Record<string, string> = {
    namer:      "bulk worker — owl-alpha or deepseek-v4-flash (free / cheap)",
    mapper:     "bulk worker — same tier as namer",
    typer:      "type-shape inference — flash class is fine",
    tiebreaker: "dispute resolver — use a stronger model (v4-pro / opus)",
};
const MODEL_PRESETS = [
    "openrouter/owl-alpha",        // free, 1M ctx — current default
    "deepseek/deepseek-v4-flash",
    "deepseek/deepseek-v4-pro",
    "deepseek/deepseek-r1",
    "assistant-sonnet-4-6",
    "assistant-opus-4-7",
    "assistant/assistant-sonnet-4.6",
    "assistant/assistant-opus-4.7",
    "openai/gpt-5",
    "google/gemini-2.5-pro",
];

type RoleDefaults = { model?: string; budget?: number; maxTurns?: number };
type Defaults = {
    namer?: RoleDefaults;
    mapper?: RoleDefaults;
    typer?: RoleDefaults;
    tiebreaker?: RoleDefaults;
    cascade?: {
        perRound?: number;
        maxRounds?: number;
        threshold?: number;
        eligibilityRatio?: number;
        // Per-round model rotation. Empty/absent = use the role's
        // single model. Round N uses models[N % len].
        models?: string[];
    };
};

declare global { interface Window { ember: any; } }

export function AgentSettings(props: { open: boolean; onClose: () => void }) {
    const [masked, setMasked] = useState<{ assistant: string[]; openai: string[]; openrouter: string[] }>({ assistant: [], openai: [], openrouter: [] });
    const [counts, setCounts] = useState<{ assistant: number; openai: number; openrouter: number }>({ assistant: 0, openai: 0, openrouter: 0 });
    // New keys to ADD (comma-separated input). Empty = no change.
    const [newKeys, setNewKeys] = useState<{ assistant: string; openai: string; openrouter: string }>({ assistant: "", openai: "", openrouter: "" });
    const [clearMask, setClearMask] = useState<{ assistant: boolean; openai: boolean; openrouter: boolean }>({ assistant: false, openai: false, openrouter: false });
    const [defaults, setDefaults] = useState<Defaults>({});
    const [cfgPath, setCfgPath] = useState<string>("");
    const [savedAt, setSavedAt] = useState<number | null>(null);

    useEffect(() => {
        if (!props.open) return;
        window.ember.agent.getConfig().then((r: any) => {
            setMasked(r.masked ?? { assistant: [], openai: [], openrouter: [] });
            setCounts(r.counts ?? { assistant: 0, openai: 0, openrouter: 0 });
            setDefaults(r.defaults ?? {});
            setCfgPath(r.path);
        });
    }, [props.open]);

    const save = async () => {
        // For each provider, build the FULL replacement list:
        //   - if user clicked "clear", send [] so the toml is wiped
        //   - else, append parsed new keys (comma-separated) to the existing list
        const merge = (prov: "assistant" | "openai" | "openrouter"): string[] | null | undefined => {
            if (clearMask[prov]) return null;
            const fresh = newKeys[prov]
                .split(/[,\n]/)
                .map((s) => s.trim())
                .filter((s) => s.length > 0);
            if (fresh.length === 0) return undefined;       // leave existing untouched
            // We don't have raw existing keys here (only masked). For
            // append, ask main to merge: send fresh list explicitly,
            // main appends to its parsed-from-disk current list.
            return fresh;
        };
        await window.ember.agent.setConfig({
            keys: {
                assistant:  merge("assistant"),
                openai:     merge("openai"),
                openrouter: merge("openrouter"),
            },
            keysMode: "append",   // hint to main to append rather than replace
            defaults,
        });
        setSavedAt(Date.now());
        const r = await window.ember.agent.getConfig();
        setMasked(r.masked ?? masked);
        setCounts(r.counts ?? counts);
        setNewKeys({ assistant: "", openai: "", openrouter: "" });
        setClearMask({ assistant: false, openai: false, openrouter: false });
        setTimeout(() => setSavedAt(null), 2000);
    };

    if (!props.open) return null;

    return (
        <div onClick={props.onClose} style={{
            position: "fixed", inset: 0,
            background: "rgba(0,0,0,0.4)",
            zIndex: 300,
        }}>
            <div onClick={(e) => e.stopPropagation()} style={{
                position: "absolute", top: 0, right: 0, bottom: 0,
                width: 480, maxWidth: "100vw",
                background: C.bgAlt,
                borderLeft: `1px solid ${C.borderStrong}`,
                color: C.text,
                fontFamily: sans,
                overflowY: "auto",
                padding: "20px 24px",
                boxShadow: "-8px 0 24px rgba(0,0,0,0.4)",
            }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 6 }}>
                    <div style={{ fontFamily: serif, fontStyle: "italic", fontSize: 20 }}>
                        Agent settings
                    </div>
                    <button onClick={props.onClose} style={{
                        fontFamily: mono, fontSize: 12,
                        background: "transparent", color: C.textMuted,
                        border: "none", cursor: "pointer",
                    }}>×</button>
                </div>
                <div style={{ fontFamily: mono, fontSize: 10, color: C.textFaint, marginBottom: 18 }}>
                    keys live in {cfgPath || "~/.config/ember/agent.toml"} — chmod 0600
                </div>

                <Section title="Provider keys">
                    <KeyRow
                        label="OpenRouter"
                        masked={masked.openrouter}
                        count={counts.openrouter}
                        newValue={newKeys.openrouter}
                        onNewChange={(v) => setNewKeys({ ...newKeys, openrouter: v })}
                        cleared={clearMask.openrouter}
                        onClearToggle={() => setClearMask({ ...clearMask, openrouter: !clearMask.openrouter })}
                        hint="sk-or-…  multi-key supported (comma-separated): round-robin across accounts to escape free-tier rate limits"
                    />
                    <KeyRow
                        label="assistant"
                        masked={masked.assistant}
                        count={counts.assistant}
                        newValue={newKeys.assistant}
                        onNewChange={(v) => setNewKeys({ ...newKeys, assistant: v })}
                        cleared={clearMask.assistant}
                        onClearToggle={() => setClearMask({ ...clearMask, assistant: !clearMask.assistant })}
                        hint="sk-ant-…  for cache_control prompt caching at 10× discount"
                    />
                    <KeyRow
                        label="OpenAI"
                        masked={masked.openai}
                        count={counts.openai}
                        newValue={newKeys.openai}
                        onNewChange={(v) => setNewKeys({ ...newKeys, openai: v })}
                        cleared={clearMask.openai}
                        onClearToggle={() => setClearMask({ ...clearMask, openai: !clearMask.openai })}
                        hint="sk-…  optional; OpenRouter routes the same models"
                    />
                </Section>

                <Section title="Per-role defaults">
                    <div style={{
                        fontFamily: serif, fontStyle: "italic",
                        fontSize: 11, color: C.textMuted, marginBottom: 10,
                        lineHeight: 1.4,
                    }}>
                        Cascade spawns <b>namer</b> workers (volume — pick a cheap or
                        free model). <b>Tiebreaker</b> is the high-stakes role that
                        resolves disputes — pick a stronger model since each call has
                        much higher leverage.
                    </div>
                    {ROLES.map((r) => (
                        <RoleRow key={r}
                            name={r}
                            value={defaults[r] ?? {}}
                            onChange={(rd) => setDefaults({ ...defaults, [r]: rd })}
                            hint={ROLE_HINTS[r]}
                        />
                    ))}
                </Section>

                <Section title="Cascade defaults">
                    <NumRow label="per-round"          value={defaults.cascade?.perRound          ?? 30}   onChange={(v) => setDefaults({ ...defaults, cascade: { ...defaults.cascade, perRound: v } })} hint="workers spawned each round" />
                    <NumRow label="max-rounds"         value={defaults.cascade?.maxRounds         ?? 5}    onChange={(v) => setDefaults({ ...defaults, cascade: { ...defaults.cascade, maxRounds: v } })} hint="loop terminates earlier on zero-progress" />
                    <NumRow label="threshold"          value={defaults.cascade?.threshold         ?? 0.85} onChange={(v) => setDefaults({ ...defaults, cascade: { ...defaults.cascade, threshold: v } })} step={0.01} hint="conf ≥ this gets promoted into annotations" />
                    <NumRow label="eligibility ratio"  value={defaults.cascade?.eligibilityRatio  ?? 0.3}  onChange={(v) => setDefaults({ ...defaults, cascade: { ...defaults.cascade, eligibilityRatio: v } })} step={0.05} hint="min named-callee fraction; lower lets round 1 actually run on stripped binaries" />
                    <ModelsRow
                        value={defaults.cascade?.models ?? []}
                        onChange={(arr) => setDefaults({ ...defaults, cascade: { ...defaults.cascade, models: arr } })}
                    />
                </Section>

                <div style={{ display: "flex", gap: 8, marginTop: 24, alignItems: "center" }}>
                    <button onClick={save} style={{
                        fontFamily: mono, fontSize: 12,
                        background: C.accent, color: "#1a1410",
                        border: "none", borderRadius: 4,
                        padding: "8px 16px",
                        cursor: "pointer", fontWeight: 600,
                    }}>save</button>
                    {savedAt && <span style={{ fontFamily: mono, fontSize: 11, color: C.green }}>saved ✓</span>}
                </div>
            </div>
        </div>
    );
}

function Section(props: { title: string; children: React.ReactNode }) {
    return (
        <div style={{ marginBottom: 18 }}>
            <div style={{
                fontFamily: mono, fontSize: 10,
                color: C.textFaint, letterSpacing: 1,
                textTransform: "uppercase",
                marginBottom: 10,
                paddingBottom: 4,
                borderBottom: `1px solid ${C.border}`,
            }}>{props.title}</div>
            {props.children}
        </div>
    );
}

function KeyRow(props: {
    label: string;
    masked: string[];
    count: number;
    newValue: string;
    onNewChange: (v: string) => void;
    cleared: boolean;
    onClearToggle: () => void;
    hint: string;
}) {
    return (
        <div style={{ marginBottom: 14 }}>
            <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", marginBottom: 4 }}>
                <span style={{ fontFamily: mono, fontSize: 11, color: C.text }}>
                    {props.label}
                    {props.count > 0 && (
                        <span style={{ color: C.textFaint, marginLeft: 6 }}>
                            ({props.count} key{props.count !== 1 ? "s" : ""})
                        </span>
                    )}
                </span>
                {props.count > 0 && (
                    <button onClick={props.onClearToggle} style={{
                        fontFamily: mono, fontSize: 10,
                        color: props.cleared ? C.red : C.textMuted,
                        background: "transparent",
                        border: `1px solid ${props.cleared ? C.red : C.border}`,
                        borderRadius: 3,
                        padding: "1px 6px",
                        cursor: "pointer",
                    }}>
                        {props.cleared ? "× WILL CLEAR ON SAVE" : "clear all"}
                    </button>
                )}
            </div>
            {props.count > 0 && !props.cleared && (
                <div style={{ marginBottom: 4 }}>
                    {props.masked.map((m, i) => (
                        <div key={i} style={{ fontFamily: mono, fontSize: 10, color: C.green, lineHeight: "16px" }}>
                            ✓ {m}
                        </div>
                    ))}
                </div>
            )}
            <input
                type="text"
                value={props.newValue}
                onChange={(e) => props.onNewChange(e.target.value)}
                placeholder={
                    props.count > 0 ? "add another (comma-separated for multiple)…" : "paste key (comma-separated for multiple)…"
                }
                style={{
                    width: "100%",
                    fontFamily: mono, fontSize: 11,
                    padding: "6px 8px",
                    background: C.bgInput,
                    border: `1px solid ${C.border}`,
                    borderRadius: 3,
                    color: C.text,
                }}
            />
            <div style={{ fontFamily: serif, fontStyle: "italic", fontSize: 10, color: C.textMuted, marginTop: 2 }}>
                {props.hint}
            </div>
        </div>
    );
}

function RoleRow(props: { name: string; value: RoleDefaults; onChange: (v: RoleDefaults) => void; hint?: string }) {
    return (
      <div style={{ marginBottom: 8 }}>
        <div style={{
            display: "grid",
            gridTemplateColumns: "70px 1fr 70px 70px",
            gap: 6,
            alignItems: "center",
        }}>
            <span style={{ fontFamily: mono, fontSize: 11, color: C.textMuted }}>{props.name}</span>
            <select
                value={props.value.model ?? ""}
                onChange={(e) => props.onChange({ ...props.value, model: e.target.value || undefined })}
                style={{
                    fontFamily: mono, fontSize: 10,
                    padding: "4px 6px",
                    background: C.bgInput,
                    border: `1px solid ${C.border}`,
                    borderRadius: 3,
                    color: C.text,
                }}
            >
                <option value="">(default)</option>
                {MODEL_PRESETS.map((m) => <option key={m} value={m}>{m}</option>)}
            </select>
            <input
                type="number" step={0.01} min={0}
                value={props.value.budget ?? ""}
                onChange={(e) => props.onChange({ ...props.value, budget: e.target.value === "" ? undefined : parseFloat(e.target.value) })}
                placeholder="$"
                style={{
                    fontFamily: mono, fontSize: 10,
                    padding: "4px 6px",
                    background: C.bgInput,
                    border: `1px solid ${C.border}`,
                    borderRadius: 3,
                    color: C.text,
                }}
            />
            <input
                type="number" min={1}
                value={props.value.maxTurns ?? ""}
                onChange={(e) => props.onChange({ ...props.value, maxTurns: e.target.value === "" ? undefined : parseInt(e.target.value, 10) })}
                placeholder="turns"
                style={{
                    fontFamily: mono, fontSize: 10,
                    padding: "4px 6px",
                    background: C.bgInput,
                    border: `1px solid ${C.border}`,
                    borderRadius: 3,
                    color: C.text,
                }}
            />
        </div>
        {props.hint && (
            <div style={{
                fontFamily: serif, fontStyle: "italic", fontSize: 9.5,
                color: C.textFaint, paddingLeft: 76, marginTop: 1,
            }}>{props.hint}</div>
        )}
      </div>
    );
}

function ModelsRow(props: { value: string[]; onChange: (v: string[]) => void }) {
    const [text, setText] = useState(props.value.join(", "));
    // keep text in sync when defaults reload (initial open)
    useEffect(() => { setText(props.value.join(", ")); }, [props.value.join(",")]);
    return (
        <div style={{
            display: "grid",
            gridTemplateColumns: "140px 1fr",
            gap: 8, alignItems: "start", marginBottom: 6,
        }}>
            <span style={{ fontFamily: mono, fontSize: 11, color: C.textMuted, paddingTop: 6 }}>per-round models</span>
            <div>
                <input
                    type="text"
                    value={text}
                    onChange={(e) => {
                        setText(e.target.value);
                        const arr = e.target.value.split(",").map((s) => s.trim()).filter(Boolean);
                        props.onChange(arr);
                    }}
                    placeholder="e.g.  openrouter/owl-alpha, openrouter/owl-alpha, deepseek/deepseek-v4-pro"
                    style={{
                        width: "100%",
                        fontFamily: mono, fontSize: 11,
                        padding: "4px 6px",
                        background: C.bgInput,
                        border: `1px solid ${C.border}`,
                        borderRadius: 3,
                        color: C.text,
                    }}
                />
                <div style={{ fontFamily: serif, fontStyle: "italic", fontSize: 10, color: C.textFaint, marginTop: 2 }}>
                    Round N uses models[N % count]. Comma-separated. Empty = use the role's single model.
                    Common patterns: <b>cheap → smart</b> (cheap, cheap, smart) or <b>cross-validation</b> (cheap, smart).
                </div>
            </div>
        </div>
    );
}

function NumRow(props: { label: string; value: number; onChange: (v: number) => void; hint?: string; step?: number }) {
    return (
        <div style={{
            display: "grid",
            gridTemplateColumns: "140px 80px 1fr",
            gap: 8, alignItems: "center", marginBottom: 6,
        }}>
            <span style={{ fontFamily: mono, fontSize: 11, color: C.textMuted }}>{props.label}</span>
            <input
                type="number" step={props.step ?? 1}
                value={props.value}
                onChange={(e) => props.onChange(parseFloat(e.target.value))}
                style={{
                    fontFamily: mono, fontSize: 11,
                    padding: "4px 6px",
                    background: C.bgInput,
                    border: `1px solid ${C.border}`,
                    borderRadius: 3,
                    color: C.text,
                }}
            />
            {props.hint && <span style={{ fontFamily: serif, fontStyle: "italic", fontSize: 10, color: C.textFaint }}>{props.hint}</span>}
        </div>
    );
}
