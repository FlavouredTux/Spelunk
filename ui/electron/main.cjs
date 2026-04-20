const { app, BrowserWindow, dialog, ipcMain, safeStorage } = require("electron");
const { spawn } = require("node:child_process");
const https = require("node:https");
const http  = require("node:http");
const { makeTools } = require("./ai_tools.cjs");
const fs = require("node:fs/promises");
const path = require("node:path");
// Official assistant SDK that wraps the user's installed `assistant` binary
// and handles subscription auth (Pro/Max OAuth) correctly. Loaded
// lazily so the renderer doesn't pay the import cost on startup.
// SDK ships as ESM (sdk.mjs), so we can't `require()` it from this CJS
// file — Node mandates dynamic `import()`. We expose query + the in-
// process MCP helpers (tool, createSdkMcpServer) since the agentic
// flow needs all three.
let _assistantSdk = null;
async function loadassistantSdk() {
  if (_assistantSdk) return _assistantSdk;
  try {
    const sdk = await import("@assistant-ai/assistant-agent-sdk");
    _assistantSdk = {
      query:               sdk.query,
      tool:                sdk.tool,
      createSdkMcpServer:  sdk.createSdkMcpServer,
    };
  } catch (e) {
    _assistantSdk = null;
    throw new Error(`@assistant-ai/assistant-agent-sdk not installed: ${e.message}`);
  }
  return _assistantSdk;
}

const EMBER_BIN = process.env.EMBER_BIN ||
  path.join(__dirname, "..", "..", "build", "cli", "ember");

const state = { binary: null };

function createWindow() {
  const win = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 960,
    minHeight: 600,
    backgroundColor: "#141413",
    titleBarStyle: process.platform === "darwin" ? "hiddenInset" : "default",
    show: false,
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      sandbox: false,
      nodeIntegration: false,
    },
  });

  win.once("ready-to-show", () => win.show());

  const devUrl = process.env.VITE_DEV_SERVER_URL || "http://localhost:5173";
  if (process.env.NODE_ENV !== "production") {
    win.loadURL(devUrl);
  } else {
    win.loadFile(path.join(__dirname, "..", "dist", "index.html"));
  }
}

function runEmber(args) {
  return new Promise((resolve, reject) => {
    const proc = spawn(EMBER_BIN, args, { cwd: path.dirname(EMBER_BIN) });
    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", (d) => { stdout += d.toString(); });
    proc.stderr.on("data", (d) => { stderr += d.toString(); });
    proc.on("error", (e) => reject(e));
    proc.on("close", (code) => {
      if (code === 0) resolve(stdout);
      else reject(new Error(stderr.trim() || `ember exited ${code}`));
    });
  });
}

// ----- ember:run result cache --------------------------------------------
//
// Each ember CLI invocation re-loads the binary off disk, re-parses
// headers/sections/symbols, and runs the requested analysis. On a
// 150 MB PE that's seconds of latency on every UI tab switch. Cache
// stdout keyed by (binary path, binary mtime, annotations file mtime,
// args) so repeat queries skip the spawn entirely. Mtime comparison
// invalidates the cache automatically when the user rebuilds the
// binary or commits annotation changes.

const RUN_CACHE     = new Map();   // key → stdout string
const RUN_CACHE_CAP = 200;          // entries; bound memory on giant inputs
const RUN_INFLIGHT  = new Map();   // key → in-flight Promise (dedup concurrent)

async function safeMtime(p) {
  if (!p) return 0;
  try { return (await fs.stat(p)).mtimeMs; }
  catch { return 0; }
}

function lruTouch(map, key, value) {
  if (map.has(key)) map.delete(key);
  map.set(key, value);
  while (map.size > RUN_CACHE_CAP) {
    const first = map.keys().next().value;
    map.delete(first);
  }
}

function sanitize(p) {
  return p.replace(/[^a-zA-Z0-9.-]/g, "_");
}

function sidecarPath(binaryPath) {
  return path.join(app.getPath("userData"), "projects", sanitize(binaryPath) + ".json");
}

function recentsPath() {
  return path.join(app.getPath("userData"), "recents.json");
}

ipcMain.handle("ember:pick", async () => {
  const r = await dialog.showOpenDialog({
    title: "Open binary",
    properties: ["openFile"],
    filters: [{ name: "Executables", extensions: ["*"] }],
  });
  if (r.canceled || r.filePaths.length === 0) return null;
  state.binary = r.filePaths[0];
  await addRecent(state.binary);
  return state.binary;
});

ipcMain.handle("ember:setBinary", async (_e, p) => {
  if (typeof p !== "string" || !p) return null;
  state.binary = p;
  await addRecent(p);
  return state.binary;
});

// Convert the on-disk JSON sidecar into the plain-text format the CLI
// expects. Returns the temp file path, or null if there's nothing to write.
async function writeCliAnnotations(binaryPath) {
  const jsonPath = sidecarPath(binaryPath);
  let parsed;
  try {
    parsed = JSON.parse(await fs.readFile(jsonPath, "utf8"));
  } catch { return null; }
  const renames = parsed.renames || {};
  const sigs    = parsed.signatures || {};
  if (Object.keys(renames).length === 0 && Object.keys(sigs).length === 0) {
    return null;
  }
  const lines = [];
  for (const [addr, name] of Object.entries(renames)) {
    const hex = String(addr).replace(/^0x/, "");
    lines.push(`rename ${hex} ${name}`);
  }
  for (const [addr, sig] of Object.entries(sigs)) {
    const hex = String(addr).replace(/^0x/, "");
    const parts = [sig.returnType || "void"];
    for (const p of sig.params || []) {
      parts.push(p.type || "u64", p.name || "_");
    }
    lines.push(`sig ${hex} ${parts.join("|")}`);
  }
  const outPath = path.join(app.getPath("userData"), "projects",
                            sanitize(binaryPath) + ".ann");
  await fs.mkdir(path.dirname(outPath), { recursive: true });
  await fs.writeFile(outPath, lines.join("\n") + "\n", "utf8");
  return outPath;
}

ipcMain.handle("ember:run", async (_e, args) => {
  if (!state.binary) throw new Error("no binary selected");
  if (!Array.isArray(args)) throw new Error("args must be array");
  const annPath = await writeCliAnnotations(state.binary);

  const binMtime = await safeMtime(state.binary);
  const annMtime = await safeMtime(annPath);
  // Embed mtimes in the key. When the binary or annotations change,
  // the new key won't hit prior entries — they fall out via LRU.
  const key = `${state.binary}|${binMtime}|${annMtime}|${args.join("\x00")}`;

  if (RUN_CACHE.has(key)) {
    const v = RUN_CACHE.get(key);
    lruTouch(RUN_CACHE, key, v);   // bubble to MRU
    return v;
  }
  // Concurrent identical requests — coalesce to a single spawn.
  if (RUN_INFLIGHT.has(key)) return RUN_INFLIGHT.get(key);

  const extra = annPath ? ["--annotations", annPath] : [];
  const p = runEmber([...args, ...extra, state.binary])
    .then((out) => { lruTouch(RUN_CACHE, key, out); return out; })
    .finally(() => { RUN_INFLIGHT.delete(key); });
  RUN_INFLIGHT.set(key, p);
  return p;
});

ipcMain.handle("ember:binary", async () => state.binary);

// ----- Annotations sidecar -----

ipcMain.handle("ember:loadAnnotations", async (_e, bp) => {
  try {
    const data = await fs.readFile(sidecarPath(bp), "utf8");
    const parsed = JSON.parse(data);
    return {
      renames:      parsed.renames      || {},
      notes:        parsed.notes        || {},
      signatures:   parsed.signatures   || {},
      localRenames: parsed.localRenames || {},
    };
  } catch {
    return { renames: {}, notes: {}, signatures: {}, localRenames: {} };
  }
});

ipcMain.handle("ember:saveAnnotations", async (_e, bp, data) => {
  const p = sidecarPath(bp);
  await fs.mkdir(path.dirname(p), { recursive: true });
  await fs.writeFile(p, JSON.stringify(data, null, 2), "utf8");
  return true;
});

// ----- AI providers -----
//
// Three backend paths, all funnelling through the same IPC streaming
// protocol so the renderer doesn't care which is active:
//
//   openrouter  — HTTPS to openrouter.ai. Requires an API key, billed
//                 per-token. The only path that works out of the box
//                 without installing extra binaries.
//   9router     — HTTP to localhost:20128 (9Router local proxy). Same
//                 OpenAI-compatible wire format as OpenRouter so it
//                 reuses the same streaming parser. API key is
//                 optional (the proxy only requires one when exposed
//                 to the internet via REQUIRE_API_KEY=true).
//   assistant-cli  — spawns `assistant -p` as a subprocess. Uses the
//                 user's logged-in assistant session (Pro/Max
//                 subscription or assistant Console API billing;
//                 configured by running `assistant auth login` once).
//                 No API key lives in Ember — assistant Code owns its
//                 own credentials.
//   codex-cli   — spawns `codex exec` as a subprocess. Uses the
//                 user's logged-in ChatGPT Plus/Pro subscription
//                 (configured via `codex login`). OpenAI explicitly
//                 supports subscription OAuth in third-party tools
//                 for Codex, so this is on the clean side of ToS.
//
// The renderer never sees credentials — the main process handles
// every key / token / subprocess stdin. All three paths emit the same
// `ai:chunk` / `ai:done` / `ai:error` IPC events keyed on a request
// id, so the chat panel's streaming UI just works uniformly.

const AI_CONFIG_PATH = () => path.join(app.getPath("userData"), "ai.json");

const AI_PROVIDERS = ["openrouter", "9router", "assistant-cli", "codex-cli"];
const AI_DEFAULT_PROVIDER = "openrouter";

// 9Router local proxy. The upstream project defaults to this port; a
// user who ran it on a different port can override with EMBER_9ROUTER_URL.
const NINE_ROUTER_URL =
  process.env.EMBER_9ROUTER_URL || "http://localhost:20128";

// Per-provider model lists surfaced as autocomplete suggestions. The
// combobox in the UI lets users type any model id regardless — these
// are just the well-known defaults so the dropdown isn't empty on
// first run.
const AI_MODEL_SUGGESTIONS = {
  "openrouter": [
    "assistant/assistant-sonnet-4.5",
    "assistant/assistant-haiku-4.5",
    "assistant/assistant-opus-4.6",
    "openai/gpt-5",
    "openai/gpt-5-mini",
    "google/gemini-2.5-pro",
    "google/gemini-2.5-flash",
    "deepseek/deepseek-chat-v3.5",
    "x-ai/grok-4",
    "meta-llama/llama-4-maverick",
  ],
  // 9router speaks OpenAI-compatible over its own namespace of free /
  // subscription / cheap tiers. Most identifiers map to the same
  // vendor/model id that OpenRouter uses; the free tier slugs (iflow-*,
  // qwen-*, kiro-assistant) are the headline draw for a user with no
  // OpenRouter credits.
  "9router": [
    "kiro-assistant-sonnet-4-5",
    "iflow-qwen3-coder",
    "iflow-glm-4.6",
    "qwen3-coder-plus",
    "gemini-2.5-pro",
    "assistant/assistant-sonnet-4.5",
    "assistant/assistant-haiku-4.5",
    "openai/gpt-5-mini",
    "deepseek/deepseek-chat-v3.5",
  ],
  "assistant-cli": [
    "sonnet",
    "opus",
    "haiku",
    "assistant-sonnet-4-6",
    "assistant-opus-4-7",
    "assistant-haiku-4-5",
  ],
  "codex-cli": [
    "gpt-5",
    "gpt-5-mini",
    "gpt-5-nano",
    "o3",
    "gpt-5.4",
  ],
};

function defaultModelFor(provider) {
  const list = AI_MODEL_SUGGESTIONS[provider] || [];
  return list[0] || "";
}

async function loadAiConfig() {
  let raw;
  try { raw = await fs.readFile(AI_CONFIG_PATH(), "utf8"); }
  catch { raw = "{}"; }
  let j; try { j = JSON.parse(raw); } catch { j = {}; }

  const provider = AI_PROVIDERS.includes(j.provider)
    ? j.provider
    : AI_DEFAULT_PROVIDER;

  // Migrate old single-provider config (pre-provider-split) — a
  // top-level `model` field gets hoisted into `models[provider]` if
  // the per-provider entry doesn't already exist. Keeps the old
  // user's picked model around instead of dropping it to the default.
  const models = j.models || {};
  if (typeof j.model === "string" && j.model && !models[provider]) {
    models[provider] = j.model;
  }
  const model = models[provider] || defaultModelFor(provider);

  // Decrypt only enough to know whether a key is present — we never
  // surface the plaintext back to the renderer.
  let hasKey = false;
  if (j.keyEncrypted && safeStorage.isEncryptionAvailable()) {
    try { hasKey = !!safeStorage.decryptString(Buffer.from(j.keyEncrypted, "base64")); }
    catch { hasKey = false; }
  } else if (j.keyPlain) {
    hasKey = true;
  }

  return {
    provider,
    model,
    hasKey,
    encrypted: !!j.keyEncrypted,
  };
}

async function loadAiKey() {
  try {
    const raw = await fs.readFile(AI_CONFIG_PATH(), "utf8");
    const j   = JSON.parse(raw);
    if (j.keyEncrypted && safeStorage.isEncryptionAvailable()) {
      return safeStorage.decryptString(Buffer.from(j.keyEncrypted, "base64"));
    }
    return j.keyPlain || "";
  } catch { return ""; }
}



async function saveAiConfig(patch) {
  // Read-modify-write so partial updates (just the provider, just the
  // model, just the key) don't clobber other fields.
  let cur;
  try { cur = JSON.parse(await fs.readFile(AI_CONFIG_PATH(), "utf8")); }
  catch { cur = {}; }

  if (AI_PROVIDERS.includes(patch.provider)) cur.provider = patch.provider;
  if (typeof patch.model === "string" && patch.model) {
    const prov = cur.provider || AI_DEFAULT_PROVIDER;
    cur.models = cur.models || {};
    cur.models[prov] = patch.model;
  }
  if (typeof patch.apiKey === "string") {
    delete cur.keyEncrypted;
    delete cur.keyPlain;
    if (patch.apiKey) {
      if (safeStorage.isEncryptionAvailable()) {
        cur.keyEncrypted = safeStorage.encryptString(patch.apiKey).toString("base64");
      } else {
        cur.keyPlain = patch.apiKey;
      }
    }
  }
  await fs.mkdir(path.dirname(AI_CONFIG_PATH()), { recursive: true });
  await fs.writeFile(AI_CONFIG_PATH(), JSON.stringify(cur, null, 2), "utf8");
}

// Probe whether a CLI is on PATH and whether the user is logged in.
// Uses the CLI's own `auth status` / `login status` subcommand so we
// stay aligned with whatever the official tool thinks is "logged in".
async function detectCli(kind) {
  const bin = kind === "assistant-cli" ? "assistant"
            : kind === "codex-cli"  ? "codex"
            : null;
  if (!bin) return { installed: false, loggedIn: false, version: "" };

  // `assistant -v` / `codex --version`: both exit 0 when the binary is
  // present, fail with ENOENT otherwise. We catch both.
  const version = await new Promise((resolve) => {
    const p = spawn(bin, ["--version"], { stdio: ["ignore", "pipe", "ignore"] });
    let out = "";
    p.stdout.on("data", (d) => { out += d.toString(); });
    p.on("error",  () => resolve(""));
    p.on("close",  () => resolve(out.trim()));
  });
  if (!version) return { installed: false, loggedIn: false, version: "" };

  // assistant: `assistant auth status` exits 0 when logged in.
  // codex:  `codex login status` exits 0 when logged in.
  const statusArgs = kind === "assistant-cli"
    ? ["auth", "status"]
    : ["login", "status"];
  const loggedIn = await new Promise((resolve) => {
    const p = spawn(bin, statusArgs, { stdio: ["ignore", "ignore", "ignore"] });
    p.on("error", () => resolve(false));
    p.on("close", (code) => resolve(code === 0));
  });
  return { installed: true, loggedIn, version };
}

ipcMain.handle("ember:ai:getConfig", async () => loadAiConfig());

ipcMain.handle("ember:ai:setConfig", async (_e, c) => {
  await saveAiConfig(c || {});
  return loadAiConfig();
});

ipcMain.handle("ember:ai:listModels", async (_e, provider) => {
  const p = provider || (await loadAiConfig()).provider;
  return (AI_MODEL_SUGGESTIONS[p] || []).slice();
});

ipcMain.handle("ember:ai:detectCli", async (_e, kind) => detectCli(kind));

// Active in-flight requests, keyed by id so `ai:cancel` can abort.
// Each entry records a {cancel} hook — HTTP requests use req.destroy,
// spawned CLIs use proc.kill. The renderer just calls cancel(id).
const AI_INFLIGHT = new Map();
let AI_NEXT_ID    = 1;

ipcMain.handle("ember:ai:cancel", async (_e, id) => {
  const ent = AI_INFLIGHT.get(id);
  if (!ent) return false;
  try { ent.cancel(); } catch {}
  AI_INFLIGHT.delete(id);
  return true;
});

// Flatten the chat-history message list into a single prompt string
// for CLI providers that take a one-shot query. The system prompt is
// lifted out to the CLI's --system-prompt flag; we preserve roles with
// "User:" / "Assistant:" prefixes on everything else so multi-turn
// conversations still make sense when replayed.
function flattenMessages(messages) {
  const lines = [];
  for (const m of messages) {
    if (m.role === "system") continue;  // carried separately
    const tag = m.role === "assistant" ? "Assistant:" : "User:";
    lines.push(`${tag} ${m.content}`);
  }
  return lines.join("\n\n");
}
function extractSystemPrompt(messages) {
  for (const m of messages) if (m.role === "system") return m.content;
  return "";
}

// Shared helper: spawn a subprocess, forward every stdout chunk to
// the renderer as `ai:chunk`, emit `ai:done` on clean exit, `ai:error`
// on non-zero exit or spawn failure. `parseChunk` is an optional
// line-oriented transformer — CLI tools that emit JSONL streaming
// events use it to pull out just the text delta; text-mode tools
// pass chunks through unchanged.
function spawnCliStream(id, send, cmd, args, stdinData, parseChunk, env) {
  let proc;
  try {
    proc = spawn(cmd, args, {
      stdio: ["pipe", "pipe", "pipe"],
      // Merge caller env on top of process.env so a missing entry
      // falls through to whatever the user's shell had when Ember
      // was launched. Undefined env leaves spawn's default (inherit).
      env: env ? { ...process.env, ...env } : undefined,
    });
  } catch (e) {
    send("ember:ai:error", `${cmd}: ${e.message || String(e)}`);
    return null;
  }

  let stderr = "";
  let stdoutTail = "";   // keep a small tail so we can surface diagnostic
                         // text that the CLI writes to stdout on failure
                         // instead of stderr (assistant -p does this).
  let total   = 0;
  let pending = "";
  proc.stdout.on("data", (chunk) => {
    const s = chunk.toString();
    stdoutTail = (stdoutTail + s).slice(-1024);
    if (!parseChunk) {
      total += s.length;
      send("ember:ai:chunk", s);
      return;
    }
    // Line-oriented: buffer partial lines across TCP-style chunk
    // boundaries so JSONL events don't get split mid-object.
    pending += s;
    let idx;
    while ((idx = pending.indexOf("\n")) !== -1) {
      const line = pending.slice(0, idx);
      pending = pending.slice(idx + 1);
      const delta = parseChunk(line);
      if (delta) {
        total += delta.length;
        send("ember:ai:chunk", delta);
      }
    }
  });
  proc.stderr.on("data", (d) => { stderr += d.toString(); });
  proc.on("error", (err) => {
    send("ember:ai:error",
         err.code === "ENOENT"
           ? `${cmd} not found on PATH — install it and run "${cmd} ${cmd === "assistant" ? "auth login" : "login"}"`
           : `${cmd}: ${err.message}`);
    AI_INFLIGHT.delete(id);
  });
  proc.on("close", (code) => {
    // Flush trailing partial line if any.
    if (pending && parseChunk) {
      const d = parseChunk(pending); pending = "";
      if (d) { total += d.length; send("ember:ai:chunk", d); }
    }
    if (code === 0) { send("ember:ai:done", { chars: total }); AI_INFLIGHT.delete(id); return; }

    // Map common CLI exit patterns to actionable guidance. Both
    // tools report "not logged in" via slightly different phrasings;
    // assistant's "-p" mode sends its diagnostic to stdout (not stderr)
    // and suggests the REPL-only "/login" command, which is not a
    // shell command at all. Rewrite it to something copy-pasteable.
    const diag = `${stderr}\n${stdoutTail}`.toLowerCase();
    let msg;
    if (/not logged in|please run \/login|unauthorized|not authenticated/.test(diag)) {
      msg = cmd === "assistant"
        ? `assistant -p (headless mode) can't use the \`assistant auth login\` session on its own. Run \`assistant setup-token\` in a terminal and paste the token into Settings → AI → "assistant OAuth token". Ember passes it to assistant via assistant_CODE_OAUTH_TOKEN on every spawn.`
        : `${cmd} is not signed in. Run \`codex login\` in a terminal, then retry.`;
    } else if (/rate[- ]?limit|429|exceeded your/i.test(diag)) {
      msg = `${cmd}: rate-limited by the provider. Wait a bit and retry, or switch provider.`;
    } else {
      const tail = (stderr.trim() || stdoutTail.trim()).slice(-400);
      msg = `${cmd} exited ${code}${tail ? `: ${tail}` : ""}`;
    }
    send("ember:ai:error", msg);
    AI_INFLIGHT.delete(id);
  });

  if (stdinData !== undefined && stdinData !== null) {
    proc.stdin.write(stdinData);
    proc.stdin.end();
  } else {
    proc.stdin.end();
  }
  return proc;
}

// Try to extract the text delta from one line of `assistant -p
// --output-format stream-json`. The format is one JSON event per
// line; text deltas arrive as `{"type":"assistant","message":{...}}`
// with nested content. Be permissive about shape drift between
// versions — any string field nested under content[] is a candidate.
function parseassistantStreamEvent(line) {
  if (!line || line[0] !== "{") return "";
  let j; try { j = JSON.parse(line); } catch { return ""; }
  // The SDK spec's streaming event for an assistant delta looks like
  //   { "type": "assistant", "message": { "content": [ {"type":"text","text":"..."} ] } }
  // but some versions emit partials as `content_block_delta` with a
  // `delta.text`. Handle both.
  if (j.type === "content_block_delta" && j.delta?.type === "text_delta") {
    return j.delta.text || "";
  }
  const content = j.message?.content;
  if (Array.isArray(content)) {
    let buf = "";
    for (const part of content) {
      if (part && part.type === "text" && typeof part.text === "string") {
        buf += part.text;
      }
    }
    return buf;
  }
  return "";
}

// Codex `exec --json` prints newline-delimited JSON events; the text
// deltas sit under `{ "msg": { "type": "agent_message_delta",
// "delta": "..." } }` in recent versions. Older versions emit the
// full assistant message under `agent_message` — we dedupe by only
// emitting deltas once the first `agent_message_delta` has appeared.
function makeCodexParser() {
  let sawDelta = false;
  let lastMessage = "";
  return (line) => {
    if (!line || line[0] !== "{") return "";
    let j; try { j = JSON.parse(line); } catch { return ""; }
    const msg = j.msg || j;
    if (msg.type === "agent_message_delta" && typeof msg.delta === "string") {
      sawDelta = true;
      return msg.delta;
    }
    if (!sawDelta && msg.type === "agent_message" &&
        typeof msg.message === "string") {
      // Non-streaming variant: emit the whole message once.
      const delta = msg.message.slice(lastMessage.length);
      lastMessage = msg.message;
      return delta;
    }
    return "";
  };
}

// Build the per-conversation tool context. `state.binary` is the
// currently-loaded binary path; without it there's nothing for the
// model to navigate, so tools are disabled and the chat falls back
// to single-turn answers over whatever the user already attached.
async function buildAiTools() {
  if (!state.binary) return null;
  const annPath = await writeCliAnnotations(state.binary);
  return makeTools(() => ({
    emberBin:   EMBER_BIN,
    binaryPath: state.binary,
    annPath,
  }));
}

// OpenAI-compatible tool definitions in the format chat completions
// expects. Mapped from our shared tool list — same descriptions, same
// JSON Schemas.
function tools_openaiFormat(tools) {
  if (!tools) return undefined;
  return tools.map((t) => ({
    type: "function",
    function: {
      name:        t.name,
      description: t.description,
      parameters:  t.jsonSchema,
    },
  }));
}

// Run one OpenAI-format chat completion turn against the given
// transport. Streams text deltas through `send` and accumulates any
// tool_call deltas (which arrive piecewise per OpenAI's spec —
// `id` + `name` + per-chunk `arguments` strings, keyed by `index`).
// Resolves to { contentLen, toolCalls } when the stream ends. The
// caller decides whether to loop (when toolCalls is non-empty) or
// finish.
function openaiTurn({ transport, reqOpts, body, send, label, registerCancel }) {
  return new Promise((resolve, reject) => {
    const req = transport.request(reqOpts, (res) => {
      if (res.statusCode && res.statusCode >= 400) {
        let buf = "";
        res.on("data", (d) => { buf += d.toString(); });
        res.on("end", () => reject(
          new Error(`${label} ${res.statusCode}: ${buf.slice(0, 400)}`)));
        return;
      }
      let pending     = "";
      let contentLen  = 0;
      const calls     = new Map();    // index -> { id, name, args }
      res.on("data", (chunk) => {
        pending += chunk.toString();
        let idx;
        while ((idx = pending.indexOf("\n\n")) !== -1) {
          const event = pending.slice(0, idx);
          pending = pending.slice(idx + 2);
          for (const rawLine of event.split("\n")) {
            const line = rawLine.startsWith("data: ") ? rawLine.slice(6) : rawLine;
            if (!line || !line.startsWith("{")) continue;
            try {
              const j = JSON.parse(line);
              const delta = j.choices?.[0]?.delta;
              if (!delta) continue;
              if (typeof delta.content === "string" && delta.content.length > 0) {
                contentLen += delta.content.length;
                send("ember:ai:chunk", delta.content);
              }
              if (Array.isArray(delta.tool_calls)) {
                for (const tc of delta.tool_calls) {
                  const i = tc.index ?? 0;
                  let cur = calls.get(i);
                  if (!cur) { cur = { id: "", name: "", args: "" }; calls.set(i, cur); }
                  if (tc.id) cur.id = tc.id;
                  if (tc.function?.name) cur.name = tc.function.name;
                  if (typeof tc.function?.arguments === "string") cur.args += tc.function.arguments;
                }
              }
            } catch { /* keepalive / partial */ }
          }
        }
      });
      res.on("end", () => {
        const toolCalls = [...calls.values()]
          .filter((c) => c.name)
          .map((c) => {
            let parsed = {};
            try { parsed = c.args ? JSON.parse(c.args) : {}; } catch { /* bad json */ }
            return { id: c.id, name: c.name, args: parsed, argsRaw: c.args };
          });
        resolve({ contentLen, toolCalls });
      });
    });
    req.on("error", reject);
    registerCancel(() => req.destroy(new Error("cancelled")));
    req.write(body);
    req.end();
  });
}

// Drive an OpenAI-format agentic loop: send messages, execute any
// tool_calls the model emits, append the results, send again. Stop
// when the model answers without tool calls or the iteration cap is
// hit. Cap is conservative — most real questions resolve in 1-3
// rounds; anything more usually means the model is stuck.
async function openrouterAgenticLoop({
  cfg, apiKey, chosenModel, messages, temperature, tools,
  send, registerCancel,
}) {
  const is9r = cfg.provider === "9router";
  let totalChars = 0;
  for (let iter = 0; iter < 8; iter++) {
    const body = JSON.stringify({
      model:       chosenModel,
      messages,
      stream:      true,
      temperature: typeof temperature === "number" ? temperature : 0.4,
      ...(tools && tools.length ? { tools: tools_openaiFormat(tools) } : {}),
    });

    let reqOpts, transport, label;
    if (is9r) {
      const u = new URL(NINE_ROUTER_URL);
      transport = u.protocol === "https:" ? https : http;
      label = "9Router";
      reqOpts = {
        method:   "POST",
        hostname: u.hostname,
        port:     u.port || (u.protocol === "https:" ? 443 : 80),
        path:     (u.pathname.replace(/\/$/, "") || "") + "/v1/chat/completions",
        headers:  {
          "Content-Type":   "application/json",
          "Content-Length": Buffer.byteLength(body),
          ...(apiKey ? { "Authorization": `Bearer ${apiKey}` } : {}),
        },
      };
    } else {
      transport = https;
      label = "OpenRouter";
      reqOpts = {
        method:   "POST",
        hostname: "openrouter.ai",
        path:     "/api/v1/chat/completions",
        headers:  {
          "Authorization":   `Bearer ${apiKey}`,
          "Content-Type":    "application/json",
          "Content-Length":  Buffer.byteLength(body),
          "HTTP-Referer":    "https://github.com/FlavouredTux/Ember",
          "X-Title":         "Ember",
        },
      };
    }

    const { contentLen, toolCalls } = await openaiTurn({
      transport, reqOpts, body, send, label, registerCancel,
    });
    totalChars += contentLen;

    if (toolCalls.length === 0) return totalChars;

    // Append the assistant's tool_call message verbatim — OpenAI
    // requires this exact shape so the follow-up can reference each
    // call by id when supplying the tool result.
    messages.push({
      role: "assistant",
      content: null,
      tool_calls: toolCalls.map((tc) => ({
        id:       tc.id,
        type:     "function",
        function: { name: tc.name, arguments: tc.argsRaw || "{}" },
      })),
    });

    // Execute every tool call this turn, appending each result as
    // its own `tool` role message keyed by tool_call_id.
    for (const tc of toolCalls) {
      send("ember:ai:tool", { name: tc.name, args: tc.args });
      let result, ok = true;
      try {
        const def = tools.find((t) => t.name === tc.name);
        if (!def) throw new Error(`unknown tool: ${tc.name}`);
        result = await def.exec(tc.args);
      } catch (err) {
        ok = false;
        result = `Error: ${err?.message || String(err)}`;
      }
      send("ember:ai:toolDone", { name: tc.name, ok, chars: result.length });
      messages.push({
        role:         "tool",
        tool_call_id: tc.id,
        content:      result,
      });
    }
  }
  throw new Error("agentic loop hit iteration cap (8); model may be stuck");
}

ipcMain.handle("ember:ai:chat", async (e, { messages, model, temperature }) => {
  const cfg = await loadAiConfig();
  const id  = String(AI_NEXT_ID++);
  const win = BrowserWindow.fromWebContents(e.sender);
  const send = (channel, ...args) => {
    if (win && !win.isDestroyed()) win.webContents.send(channel, id, ...args);
  };
  // The renderer's model state can drift from the persisted per-
  // provider config (e.g. user opened the AI panel, then swapped
  // provider in Settings). Config is authoritative — only honour an
  // explicit model override if it belongs to this provider's known
  // suggestion list, otherwise fall back to what we have on disk.
  const providerModels = AI_MODEL_SUGGESTIONS[cfg.provider] || [];
  const chosenModel =
    (typeof model === "string" && model && providerModels.includes(model))
      ? model
      : cfg.model;

  // ---- OpenRouter & 9Router (both OpenAI-compatible wire format) ---
  if (cfg.provider === "openrouter" || cfg.provider === "9router") {
    const is9r   = cfg.provider === "9router";
    const apiKey = await loadAiKey();
    if (!is9r && !apiKey) throw new Error("no OpenRouter API key configured");

    const tools = await buildAiTools();   // null when no binary loaded
    let cancelled = false;
    let currentCancel = () => {};
    AI_INFLIGHT.set(id, {
      cancel: () => { cancelled = true; currentCancel(); },
    });

    // Run the agentic loop in the background — the IPC handler returns
    // the request id immediately so the renderer can subscribe.
    (async () => {
      try {
        // Operate on a mutable copy so the renderer's array isn't
        // mutated by tool-result appends.
        const convo = messages.slice();
        const total = await openrouterAgenticLoop({
          cfg, apiKey, chosenModel, messages: convo, temperature, tools, send,
          registerCancel: (fn) => { currentCancel = fn; if (cancelled) fn(); },
        });
        send("ember:ai:done", { chars: total });
      } catch (err) {
        const m = err?.message || String(err);
        const friendly = is9r && /ECONNREFUSED|ENOTFOUND/.test(m)
          ? `9Router not reachable at ${NINE_ROUTER_URL}. Start the 9router proxy, or override with EMBER_9ROUTER_URL.`
          : m;
        send("ember:ai:error", friendly);
      } finally {
        AI_INFLIGHT.delete(id);
      }
    })();
    return id;
  }

  // ---- assistant (via official Agent SDK) ------------------------------
  // We call `@assistant-ai/assistant-agent-sdk`'s `query()` rather than
  // shelling out to `assistant -p` ourselves. The SDK is assistant's
  // own programmatic surface for assistant Code — it spawns the user's
  // installed `assistant` binary internally, handles the IPC, AND
  // crucially it accepts subscription OAuth (Pro / Max) where the
  // raw `-p` flag forces assistant_API_KEY billing. Same path t3code
  // uses; nothing token-scraping or ToS-grey here.
  if (cfg.provider === "assistant-cli") {
    let sdk;
    try { sdk = await loadassistantSdk(); }
    catch (e) { throw new Error(e.message); }
    const { query: queryFn, tool: toolFn, createSdkMcpServer } = sdk;

    const systemPrompt = extractSystemPrompt(messages);
    // The SDK's `prompt` field takes one user turn for one-shot
    // calls. Multi-turn history is flattened into a single string
    // with role prefixes — same approach as the previous CLI path
    // and good enough for the chat panel's typical 2-3 turn arc.
    const flat = flattenMessages(messages);

    // Wire Ember's binary-navigation tools into assistant's agent loop
    // via an in-process MCP server. The SDK runs the loop itself —
    // we just supply tool definitions and the model decides when to
    // call them. Each MCP tool name becomes `mcp__ember__<name>`
    // from the model's perspective.
    const emberTools = await buildAiTools();
    let mcpServers, allowedTools;
    if (emberTools) {
      const { z } = require("zod");
      const sdkTools = emberTools.map((t) => toolFn(
        t.name,
        t.description,
        t.zod,
        async (args) => {
          send("ember:ai:tool", { name: t.name, args });
          let text;
          try {
            text = await t.exec(args);
            send("ember:ai:toolDone", { name: t.name, ok: true, chars: text.length });
          } catch (err) {
            text = `Error: ${err?.message || String(err)}`;
            send("ember:ai:toolDone", { name: t.name, ok: false, chars: text.length });
          }
          return { content: [{ type: "text", text }] };
        },
      ));
      const server = createSdkMcpServer({ name: "ember", version: "0.1.0", tools: sdkTools });
      mcpServers = { ember: server };
      allowedTools = emberTools.map((t) => `mcp__ember__${t.name}`);
    }

    const abort = new AbortController();
    AI_INFLIGHT.set(id, { cancel: () => abort.abort() });

    let total = 0;
    (async () => {
      try {
        const q = queryFn({
          prompt: flat,
          options: {
            ...(chosenModel ? { model: chosenModel } : {}),
            // REPLACE assistant Code's default system prompt — we don't
            // want the autonomous-coding-agent preamble (use tools,
            // edit files, long explanations). It was diluting our
            // RE-analyst directives, in particular making the model
            // ignore the strict ```renames fenced-block requirement.
            ...(systemPrompt ? { systemPrompt: systemPrompt } : {}),
            // Allow only Ember's MCP tools. The SDK's built-in tools
            // (Bash, Read, Write, etc.) stay disabled — the analyst
            // shouldn't be reading random files; only navigating the
            // loaded binary via our query helpers.
            ...(allowedTools ? { allowedTools } : { allowedTools: [] }),
            ...(mcpServers ? { mcpServers } : {}),
            // Bare-mode equivalent: don't load user/project assistant.md,
            // hooks, MCP servers. Keeps responses focused on the
            // Ember context we attached, no environmental drift.
            settingSources: [],
            // Extended thinking is pure latency for the short,
            // pattern-recognition answers this panel asks for — the
            // analyst wants the verb-led one-liner now, not after a
            // reasoning preamble.
            thinking: { type: "disabled" },
            includePartialMessages: true,
            persistSession: false,
            permissionMode: "bypassPermissions",
            allowDangerouslySkipPermissions: true,
            abortController: abort,
            // Identify Ember in the SDK's User-Agent so assistant's
            // dashboards distinguish our traffic from raw `assistant` use.
            env: { ...process.env, assistant_AGENT_SDK_CLIENT_APP: "ember/0.1" },
          },
        });

        for await (const msg of q) {
          // Streaming text arrives as stream_event messages whose
          // inner `event` matches assistant's standard
          // BetaRawMessageStreamEvent shape. We only forward text
          // deltas — tool_use / start / stop / ping events are
          // bookkeeping the chat panel doesn't render.
          if (msg.type === "stream_event" &&
              msg.event?.type === "content_block_delta" &&
              msg.event.delta?.type === "text_delta" &&
              typeof msg.event.delta.text === "string") {
            total += msg.event.delta.text.length;
            send("ember:ai:chunk", msg.event.delta.text);
          }
        }
        send("ember:ai:done", { chars: total });
      } catch (err) {
        const m = err?.message || String(err);
        // Translate the SDK's common failure modes into actionable
        // guidance — these are the same diagnostics the user would
        // see at the CLI but rendered in-panel where they'll be read.
        let friendly = m;
        if (/ENOENT|assistant.*not found/i.test(m)) {
          friendly = "assistant binary not found on PATH. Install assistant Code (npm i -g @assistant-ai/assistant-code) and run `assistant auth login`.";
        } else if (/not.*logged in|please run \/login|unauthorized|authentication/i.test(m)) {
          friendly = "assistant Code session not authenticated. Run `assistant auth login` in a terminal, then retry.";
        } else if (/rate.?limit|429/i.test(m)) {
          friendly = "Rate-limited by assistant. Wait a bit and retry, or switch provider.";
        }
        send("ember:ai:error", friendly);
      } finally {
        AI_INFLIGHT.delete(id);
      }
    })();
    return id;
  }

  // ---- Codex (ChatGPT) CLI ------------------------------------------
  if (cfg.provider === "codex-cli") {
    const systemPrompt = extractSystemPrompt(messages);
    const flat         = flattenMessages(messages);
    const fullPrompt   = systemPrompt
      ? `${systemPrompt}\n\n---\n\n${flat}`
      : flat;
    const args = ["exec", "--json", "-"];  // read prompt from stdin
    if (chosenModel) { args.splice(1, 0, "--model", chosenModel); }

    const proc = spawnCliStream(id, send, "codex", args, fullPrompt,
                                makeCodexParser());
    if (proc) AI_INFLIGHT.set(id, { cancel: () => proc.kill("SIGTERM") });
    return id;
  }

  throw new Error(`unknown AI provider: ${cfg.provider}`);
});

// ----- Recents -----

async function readRecents() {
  try {
    const data = await fs.readFile(recentsPath(), "utf8");
    return JSON.parse(data).files || [];
  } catch {
    return [];
  }
}

async function addRecent(bp) {
  if (!bp) return [];
  const p = recentsPath();
  let files = await readRecents();
  files = [bp, ...files.filter((f) => f !== bp)].slice(0, 8);
  await fs.mkdir(path.dirname(p), { recursive: true });
  await fs.writeFile(p, JSON.stringify({ files }, null, 2), "utf8");
  return files;
}

ipcMain.handle("ember:recents", async () => {
  return await readRecents();
});

ipcMain.handle("ember:openRecent", async (_e, bp) => {
  try {
    await fs.access(bp);
  } catch {
    throw new Error(`file not found: ${bp}`);
  }
  state.binary = bp;
  await addRecent(bp);
  return bp;
});

app.whenReady().then(() => {
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
