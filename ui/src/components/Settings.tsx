import { useEffect, useState } from "react";
import { C, sans, serif, mono } from "../theme";
import type { AppSettings } from "../settings";
import { DEFAULT_SETTINGS } from "../settings";
import { clearRendererCaches } from "../api";
import type { AiConfig, AiCliStatus, AiProvider } from "../types";

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
              label="Code font size"
              hint="Affects pseudo-C, IR, and disasm panes."
            >
              <NumberInput
                value={props.settings.codeFontSize}
                min={9} max={20}
                onChange={(v) => set("codeFontSize", v)}
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

          <Section title="AI (OpenRouter)">
            <AiConfigSection />
          </Section>

          <Section title="Defaults">
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
            <span>Ember — from-scratch x86-64 decompiler</span>
            <span style={{ fontFamily: mono, fontStyle: "normal" }}>
              github.com/FlavouredTux/Ember
            </span>
          </div>
        </div>
      </div>
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
    if (p !== "openrouter") reloadProbes();
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
          options={["openrouter", "assistant-cli", "codex-cli"] as const}
          onChange={changeProvider}
        />
      </Row>

      {cfg.provider === "openrouter" && (
        <OpenRouterKeySection cfg={cfg} onSave={saveKey} />
      )}

      {cfg.provider === "assistant-cli" && (
        <CliStatusSection
          kind="assistant-cli"
          status={assistant}
          onRefresh={reloadProbes}
          loginCmd="assistant auth login"
          note="Uses assistant Code's logged-in subscription (Pro / Max / Team) or assistant Console API billing — whichever `assistant auth login` was run with. Ember spawns the installed `assistant` binary per request; no OAuth tokens cross into Ember."
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

// Free-text input with native autocomplete from a list of suggestions.
// Beats <select> because the OpenRouter model namespace evolves
// faster than we can hard-code it — users want to type
// `qwen/qwen3-coder` or whatever shipped this morning. The datalist
// gives them the canned options as autocomplete without locking them
// in. Commits on blur or Enter so per-keystroke spam doesn't churn
// the IPC config write.
export function ModelCombobox(props: {
  value:    string;
  options:  string[];
  onChange: (v: string) => void;
  width?:   number;
}) {
  const [draft, setDraft] = useState(props.value);
  // Keep the input in sync if the parent's value changes via some
  // other path (e.g. main process write from another window).
  useEffect(() => { setDraft(props.value); }, [props.value]);

  const commit = () => {
    const v = draft.trim();
    if (v && v !== props.value) props.onChange(v);
    else if (!v) setDraft(props.value);   // empty input → revert
  };

  const listId = "ai-model-suggestions";
  return (
    <>
      <input
        list={listId}
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onBlur={commit}
        onKeyDown={(e) => {
          if (e.key === "Enter") { e.preventDefault(); commit(); (e.currentTarget as HTMLInputElement).blur(); }
          else if (e.key === "Escape") { setDraft(props.value); (e.currentTarget as HTMLInputElement).blur(); }
        }}
        spellCheck={false}
        autoCapitalize="off"
        autoCorrect="off"
        placeholder="vendor/model-id"
        style={{
          background: C.bgMuted, color: C.text,
          border: `1px solid ${C.border}`, borderRadius: 4,
          padding: "5px 8px",
          fontFamily: mono, fontSize: 11,
          width: props.width ?? 220,
        }}
      />
      <datalist id={listId}>
        {props.options.map((m) => <option key={m} value={m} />)}
      </datalist>
    </>
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
            onClick={() => props.onChange(o)}
            style={{
              padding: "5px 12px",
              background: active ? C.bgAlt : "transparent",
              color: active ? C.text : C.textMuted,
              border: "none",
              borderLeft: i > 0 ? `1px solid ${C.border}` : "none",
              fontFamily: mono, fontSize: 11,
              fontWeight: active ? 600 : 400,
              cursor: "pointer",
            }}
          >{o}</button>
        );
      })}
    </div>
  );
}
