import { useEffect, useMemo, useRef, useState } from "react";
import { C, sans, serif, mono } from "../theme";
import type { AiMessage, AiConfig, FunctionInfo, Annotations } from "../types";
import {
  SYSTEM_PROMPT,
  QUICK_ACTIONS,
  buildUserMessage,
  parseRenames,
  streamChat,
  type ChatStream,
  type RenameSuggestion,
} from "../ai";
import { ModelCombobox } from "./Settings";

// Sparkle / wand glyph for the title-bar AI button. Smaller four-point
// star (the AI / assistant / Gemini convention) plus a tiny accent star
// in the upper right. `currentColor` for stroke + fill so it picks up
// hover state from the wrapping button.
export function SparkIcon(props: { size?: number; style?: React.CSSProperties }) {
  const size = props.size ?? 14;
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      fill="currentColor"
      style={props.style}
      aria-hidden="true"
    >
      <path d="M11 3 L13 9 L19 11 L13 13 L11 19 L9 13 L3 11 L9 9 Z" />
      <path d="M18 3 L19 5.5 L21.5 6.5 L19 7.5 L18 10 L17 7.5 L14.5 6.5 L17 5.5 Z"
            opacity="0.7" />
    </svg>
  );
}

type ChatTurn = {
  role:    "user" | "assistant";
  content: string;
  // For assistant turns: still being streamed?
  pending?: boolean;
};

export function AIPanel(props: {
  // Current code context the user is viewing — if open via the Explain
  // shortcut, the panel auto-attaches this so the first quick-action
  // doesn't need any setup. Optional: an empty panel just chats freely.
  context?: { fnName?: string; fnAddr?: string; view: string; code: string };
  current?: FunctionInfo | null;
  annotations?: Annotations;
  onApplyRename?: (fn: FunctionInfo, newName: string) => void;
  onClose: () => void;
}) {
  const [config, setConfig] = useState<AiConfig | null>(null);
  const [model, setModel] = useState<string>("");
  const [models, setModels] = useState<string[]>([]);
  const [turns, setTurns] = useState<ChatTurn[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const streamRef = useRef<ChatStream | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef  = useRef<HTMLTextAreaElement>(null);

  // Bootstrap config + model list. Done in parallel so the panel
  // doesn't block on either.
  useEffect(() => {
    let cancel = false;
    Promise.all([window.ember.ai.getConfig(), window.ember.ai.listModels()])
      .then(([cfg, mdls]) => {
        if (cancel) return;
        setConfig(cfg);
        setModel(cfg.model);
        setModels(mdls);
      })
      .catch(() => { /* renderer survives without AI */ });
    return () => { cancel = true; };
  }, []);

  // Esc closes; Cmd/Ctrl+Enter submits even without focusing the
  // input directly (matches the rest of the app's modal idioms).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        if (busy) cancel();
        else props.onClose();
      }
      if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
        e.preventDefault();
        if (input.trim()) submit(input);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [busy, input, props]);

  // Auto-scroll on new content. We use a tail anchor rather than
  // polling scrollHeight so resize observers don't fight us.
  useEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [turns]);

  useEffect(() => { inputRef.current?.focus(); }, []);

  // Per-provider "ready to chat" check. OpenRouter needs an API key
  // in our config; CLI providers defer to the installed tool — the
  // user's auth status lives inside `assistant` / `codex` themselves and
  // we'll surface any failure as a chat error rather than gating here.
  const ready = !!config && (
    config.provider === "openrouter" ? config.hasKey : true
  );

  function cancel() {
    streamRef.current?.cancel();
    streamRef.current = null;
    setBusy(false);
    setTurns((t) => {
      const last = t[t.length - 1];
      if (last?.role === "assistant" && last.pending) {
        return [...t.slice(0, -1),
                { ...last, pending: false,
                  content: last.content + (last.content ? "\n" : "") + "[cancelled]" }];
      }
      return t;
    });
  }

  function submit(rawInput: string, opts?: { quickAction?: boolean }) {
    if (!ready) return;
    const text = rawInput.trim();
    if (!text) return;

    // First user turn pulls in the active code context if the panel
    // was opened with one. Subsequent turns are pure follow-ups —
    // re-attaching the body would just waste tokens since the model
    // already saw it.
    const userText = (turns.length === 0 && props.context && opts?.quickAction)
      ? buildUserMessage(text, props.context)
      : text;

    const newUser: ChatTurn = { role: "user", content: userText };
    const newAsst: ChatTurn = { role: "assistant", content: "", pending: true };
    const next = [...turns, newUser, newAsst];
    setTurns(next);
    setInput("");
    setBusy(true);

    const messages: AiMessage[] = [
      { role: "system", content: SYSTEM_PROMPT },
      ...next.filter((t) => t.role !== "assistant" || t.content)
            .map((t) => ({ role: t.role, content: t.content })),
    ];
    // Strip the empty pending placeholder we just added.
    if (messages[messages.length - 1].role === "assistant" &&
        messages[messages.length - 1].content === "") {
      messages.pop();
    }

    const stream = streamChat({ messages, model }, (delta) => {
      setTurns((cur) => {
        const last = cur[cur.length - 1];
        if (last?.role !== "assistant" || !last.pending) return cur;
        return [...cur.slice(0, -1),
                { ...last, content: last.content + delta }];
      });
    });
    streamRef.current = stream;
    stream.promise
      .then(() => {
        setTurns((cur) => {
          const last = cur[cur.length - 1];
          if (last?.role !== "assistant") return cur;
          return [...cur.slice(0, -1), { ...last, pending: false }];
        });
      })
      .catch((err) => {
        setTurns((cur) => {
          const last = cur[cur.length - 1];
          if (last?.role !== "assistant") return cur;
          return [...cur.slice(0, -1), {
            ...last,
            pending: false,
            content: last.content +
              (last.content ? "\n\n" : "") +
              `[error] ${err?.message ?? String(err)}`,
          }];
        });
      })
      .finally(() => {
        if (streamRef.current === stream) streamRef.current = null;
        setBusy(false);
      });
  }

  const lastAssistant = useMemo(() => {
    for (let i = turns.length - 1; i >= 0; i--) {
      if (turns[i].role === "assistant" && !turns[i].pending) return turns[i];
    }
    return null;
  }, [turns]);
  const renames = useMemo<RenameSuggestion[]>(
    () => lastAssistant ? parseRenames(lastAssistant.content) : [],
    [lastAssistant],
  );
  // Match the suggested rename against the currently-selected function
  // by either name (`main`) or address-form (`sub_1260` ↔ addr 0x1260).
  // Models routinely take the entry-block address as the function's
  // identifier even when the function has a real name printed at the
  // top of the snippet, so we accept both spellings rather than miss
  // the suggestion. Also strips a leading `bb_` in case the model
  // confused entry-block syntax for function syntax.
  const fnRename = useMemo(() => {
    if (!props.current) return undefined;
    const cur = props.current;
    return renames.find((r) => {
      if (cur.name === r.from) return true;
      const m = /^(?:sub_|bb_)([0-9a-fA-F]+)$/.exec(r.from);
      if (m) {
        const addr = parseInt(m[1], 16);
        if (Number.isFinite(addr) && addr === cur.addrNum) return true;
      }
      return false;
    });
  }, [renames, props.current]);

  return (
    <div
      onMouseDown={(e) => { if (e.target === e.currentTarget) props.onClose(); }}
      style={{
        position: "fixed", inset: 0,
        background: "rgba(10,10,9,0.55)",
        backdropFilter: "blur(3px)",
        zIndex: 2000,
        display: "flex",
        justifyContent: "center",
        paddingTop: "8vh",
        animation: "fadeIn .12s ease-out",
      }}
    >
      <div
        style={{
          width: 760, maxWidth: "94%", height: "82vh",
          display: "flex", flexDirection: "column",
          background: C.bgAlt,
          border: `1px solid ${C.borderStrong}`,
          borderRadius: 8,
          overflow: "hidden",
          boxShadow: "0 24px 60px rgba(0,0,0,0.55)",
        }}
      >
        {/* Header */}
        <div style={{
          display: "flex", alignItems: "center", gap: 10,
          padding: "12px 16px",
          borderBottom: `1px solid ${C.border}`,
        }}>
          <SparkIcon size={16} style={{ color: C.accent }} />
          <span style={{ fontFamily: sans, fontSize: 14, fontWeight: 600, color: C.text }}>
            Ember AI
          </span>
          <span style={{ flex: 1 }} />
          {(models.length > 0 || model) && (
            <ModelCombobox
              value={model}
              options={models}
              onChange={(v) => {
                setModel(v);
                window.ember.ai.setConfig({ model: v })
                  .then((c) => setConfig(c)).catch(() => {});
              }}
              width={240}
            />
          )}
          <span style={{ fontFamily: mono, fontSize: 9, color: C.textFaint }}>esc</span>
        </div>

        {/* Body — chat scroll */}
        <div ref={scrollRef} style={{
          flex: 1, overflowY: "auto", padding: "14px 18px",
          fontFamily: sans, fontSize: 13, lineHeight: 1.55, color: C.text,
        }}>
          {config && !ready && <NoKeyHint provider={config.provider} />}
          {ready && turns.length === 0 && (
            <EmptyState
              context={props.context}
              onPrompt={(p) => submit(p, { quickAction: true })}
            />
          )}
          {turns.map((t, i) => (
            <Turn key={i} turn={t} />
          ))}
        </div>

        {/* Apply-rename action — surfaces when the AI suggested a rename
            for the currently selected function. One-click commits to
            project annotations. */}
        {fnRename && props.onApplyRename && props.current && (
          <div style={{
            padding: "8px 16px",
            borderTop: `1px solid ${C.border}`,
            background: "rgba(217,119,87,0.08)",
            display: "flex", alignItems: "center", gap: 10,
            fontFamily: mono, fontSize: 11,
          }}>
            <span style={{ color: C.textMuted }}>suggested:</span>
            <span style={{ color: C.textFaint, textDecoration: "line-through" }}>
              {fnRename.from}
            </span>
            <span style={{ color: C.textFaint }}>→</span>
            <span style={{ color: C.accent, fontWeight: 600 }}>{fnRename.to}</span>
            <span style={{ flex: 1 }} />
            <button
              onClick={() => props.current && props.onApplyRename!(props.current, fnRename.to)}
              style={{
                padding: "4px 10px",
                background: C.accent, color: "#fff",
                border: "none", borderRadius: 4,
                fontFamily: mono, fontSize: 10, cursor: "pointer",
              }}
            >apply rename</button>
          </div>
        )}

        {/* Input row */}
        <div style={{
          padding: 12,
          borderTop: `1px solid ${C.border}`,
          background: C.bgMuted,
          display: "flex", flexDirection: "column", gap: 8,
        }}>
          {/* Quick actions */}
          {ready && turns.length === 0 && props.context && (
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              {QUICK_ACTIONS.map((qa) => (
                <button
                  key={qa.id}
                  onClick={() => submit(qa.prompt, { quickAction: true })}
                  disabled={busy}
                  style={quickBtnStyle}
                >{qa.label}</button>
              ))}
            </div>
          )}
          <div style={{
            display: "flex", alignItems: "flex-end", gap: 8,
            background: C.bg, border: `1px solid ${C.border}`,
            borderRadius: 6, padding: "8px 10px",
          }}>
            <textarea
              ref={inputRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  submit(input);
                }
              }}
              disabled={busy || !ready}
              placeholder={ready
                ? (turns.length === 0 && props.context
                    ? "Ask about this function — or pick a quick action above. ⏎ to send, ⇧⏎ for newline."
                    : "Follow up on the analysis…")
                : "Add an OpenRouter API key in Settings to enable Ember AI."}
              rows={2}
              style={{
                flex: 1, background: "transparent", color: C.text,
                border: "none", outline: "none", resize: "none",
                fontFamily: sans, fontSize: 13, lineHeight: 1.5,
              }}
            />
            <button
              onClick={() => busy ? cancel() : submit(input)}
              disabled={!busy && (!input.trim() || !ready)}
              style={{
                padding: "6px 14px",
                background: busy ? C.red : C.accent,
                color: "#fff",
                border: "none", borderRadius: 4,
                fontFamily: mono, fontSize: 11, fontWeight: 600,
                cursor: (!busy && (!input.trim() || !ready))
                  ? "not-allowed" : "pointer",
                opacity: (!busy && (!input.trim() || !ready)) ? 0.5 : 1,
              }}
            >{busy ? "stop" : "send"}</button>
          </div>
        </div>
      </div>
    </div>
  );
}

const quickBtnStyle: React.CSSProperties = {
  padding: "4px 10px",
  background: C.bgAlt, color: C.text,
  border: `1px solid ${C.border}`, borderRadius: 4,
  fontFamily: mono, fontSize: 10, cursor: "pointer",
};

function NoKeyHint(props: { provider: "openrouter" | "assistant-cli" | "codex-cli" }) {
  // Only openrouter is gated by a "missing key" state at this layer.
  // CLI providers defer their readiness check to the spawn itself —
  // if assistant/codex isn't installed or isn't logged in, the resulting
  // chat error surfaces the fix (`assistant auth login`, install codex,
  // etc.) right in the chat stream.
  return (
    <div style={{
      padding: 24, color: C.textMuted, fontFamily: serif, fontSize: 13,
      lineHeight: 1.7, fontStyle: "italic",
      display: "flex", flexDirection: "column", gap: 12, alignItems: "flex-start",
    }}>
      <div style={{ color: C.text, fontWeight: 600, fontFamily: sans, fontStyle: "normal" }}>
        Ember AI is not configured.
      </div>
      {props.provider === "openrouter" ? (
        <>
          <div>
            Drop an <span style={{ fontFamily: mono, color: C.text }}>OPENROUTER_API_KEY</span>{" "}
            into Settings → AI to enable, or switch the provider there to{" "}
            <span style={{ fontFamily: mono, color: C.text }}>assistant-cli</span> /{" "}
            <span style={{ fontFamily: mono, color: C.text }}>codex-cli</span> if you'd rather use
            a assistant Pro/Max or ChatGPT Plus subscription via the installed CLI.
          </div>
          <div style={{ fontFamily: mono, fontStyle: "normal", fontSize: 11, color: C.textFaint }}>
            get an OpenRouter key at <span style={{ color: C.text }}>openrouter.ai/keys</span>
          </div>
        </>
      ) : (
        <div>
          No active configuration. Open Settings → AI and check the provider's auth status.
        </div>
      )}
    </div>
  );
}

function EmptyState(props: {
  context?: { fnName?: string; fnAddr?: string; view: string; code: string };
  onPrompt: (prompt: string) => void;
}) {
  if (!props.context) {
    return (
      <div style={{
        padding: 24, color: C.textMuted,
        fontFamily: serif, fontStyle: "italic", fontSize: 13,
      }}>
        Open a function in the main view, then come back — quick actions auto-attach the body as context.
      </div>
    );
  }
  return (
    <div style={{
      padding: "12px 0", color: C.textMuted,
      display: "flex", flexDirection: "column", gap: 4,
    }}>
      <div style={{ fontFamily: sans, fontSize: 13, color: C.text }}>
        Context attached:{" "}
        <span style={{ fontFamily: mono, color: C.accent }}>
          {props.context.fnName ?? "<anonymous>"}
        </span>
        {props.context.fnAddr && (
          <span style={{ fontFamily: mono, fontSize: 11, color: C.textFaint }}>
            {" "}· {props.context.fnAddr}
          </span>
        )}
        <span style={{ fontFamily: mono, fontSize: 11, color: C.textFaint }}>
          {" "}· {props.context.view}
        </span>
      </div>
      <div style={{ fontFamily: serif, fontStyle: "italic", fontSize: 12 }}>
        Pick a quick action below or type a question.
      </div>
    </div>
  );
}

// One conversational turn. For assistants we light-render Markdown
// inline (paragraphs, fenced code, single-back-tick code spans). Full
// Markdown isn't worth the dep — the system prompt steers the model
// away from headers / lists / horizontal rules.
function Turn(props: { turn: ChatTurn }) {
  const isUser = props.turn.role === "user";
  return (
    <div style={{
      marginBottom: 14,
      display: "flex", flexDirection: "column",
      alignItems: isUser ? "flex-end" : "flex-start",
    }}>
      <div style={{
        fontFamily: mono, fontSize: 9, color: C.textFaint,
        textTransform: "uppercase", letterSpacing: 1, marginBottom: 4,
      }}>
        {isUser ? "you" : "ember-ai"}
        {props.turn.pending && (
          <span style={{ marginLeft: 6, color: C.accent }}>· streaming…</span>
        )}
      </div>
      <div style={{
        maxWidth: "92%",
        padding: "10px 14px",
        background: isUser ? "rgba(217,119,87,0.10)" : C.bg,
        border: `1px solid ${isUser ? "rgba(217,119,87,0.35)" : C.border}`,
        borderRadius: 6,
        fontFamily: sans, fontSize: 13, lineHeight: 1.6,
        color: C.text, whiteSpace: "pre-wrap",
      }}>
        {renderMarkdown(props.turn.content)}
        {props.turn.pending && !props.turn.content && (
          <span style={{ color: C.textFaint, fontStyle: "italic" }}>thinking…</span>
        )}
      </div>
    </div>
  );
}

// Cheap-and-cheerful Markdown renderer covering the subset our system
// prompt steers the model toward: paragraphs, single backtick spans,
// triple-backtick fenced blocks (with optional language tag), and
// `**bold**` runs. Lists / headers / images / links not handled —
// the system prompt tells the model not to use them.
function renderMarkdown(src: string): React.ReactNode {
  const out: React.ReactNode[] = [];
  const lines = src.split("\n");
  let i = 0;
  let key = 0;
  while (i < lines.length) {
    if (lines[i].startsWith("```")) {
      const lang = lines[i].slice(3).trim();
      i++;
      const buf: string[] = [];
      while (i < lines.length && !lines[i].startsWith("```")) {
        buf.push(lines[i]); i++;
      }
      i++; // closing fence
      out.push(
        <pre key={key++} style={{
          margin: "8px 0",
          padding: "10px 12px",
          background: C.bgMuted,
          border: `1px solid ${C.border}`,
          borderRadius: 4,
          fontFamily: mono, fontSize: 11.5, lineHeight: 1.5,
          overflowX: "auto",
          color: lang === "renames" ? C.accent : C.text,
        }}>{buf.join("\n")}</pre>
      );
    } else {
      out.push(<span key={key++}>{renderInline(lines[i])}{i < lines.length - 1 && "\n"}</span>);
      i++;
    }
  }
  return out;
}

function renderInline(line: string): React.ReactNode {
  const out: React.ReactNode[] = [];
  let key = 0;
  let i = 0;
  while (i < line.length) {
    if (line[i] === "`") {
      const end = line.indexOf("`", i + 1);
      if (end > i) {
        out.push(
          <code key={key++} style={{
            fontFamily: mono, fontSize: 12,
            color: C.accent,
            background: "rgba(217,119,87,0.10)",
            padding: "1px 4px", borderRadius: 3,
          }}>{line.slice(i + 1, end)}</code>
        );
        i = end + 1;
        continue;
      }
    }
    if (line[i] === "*" && line[i + 1] === "*") {
      const end = line.indexOf("**", i + 2);
      if (end > i + 1) {
        out.push(
          <strong key={key++} style={{ fontWeight: 600, color: C.text }}>
            {line.slice(i + 2, end)}
          </strong>
        );
        i = end + 2;
        continue;
      }
    }
    // Run of plain text up to the next markdown trigger.
    let j = i + 1;
    while (j < line.length && line[j] !== "`" &&
           !(line[j] === "*" && line[j + 1] === "*")) j++;
    out.push(line.slice(i, j));
    i = j;
  }
  return out;
}
