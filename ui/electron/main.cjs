const { app, BrowserWindow, dialog, ipcMain, safeStorage } = require("electron");
const { spawn } = require("node:child_process");
const https = require("node:https");
const fs = require("node:fs/promises");
const path = require("node:path");

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
      renames:    parsed.renames    || {},
      notes:      parsed.notes      || {},
      signatures: parsed.signatures || {},
    };
  } catch {
    return { renames: {}, notes: {}, signatures: {} };
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

const AI_PROVIDERS = ["openrouter", "assistant-cli", "codex-cli"];
const AI_DEFAULT_PROVIDER = "openrouter";

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
  "assistant-cli": [
    "sonnet",
    "opus",
    "haiku",
    "assistant-sonnet-4-6",
    "assistant-opus-4-7",
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

  // Decrypt only enough to know whether a key is present — we never
  // surface the plaintext back to the renderer.
  let hasKey = false;
  if (j.keyEncrypted && safeStorage.isEncryptionAvailable()) {
    try { hasKey = !!safeStorage.decryptString(Buffer.from(j.keyEncrypted, "base64")); }
    catch { hasKey = false; }
  } else if (j.keyPlain) {
    hasKey = true;
  }

  const models = j.models || {};
  const model  = models[provider] || defaultModelFor(provider);

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
function spawnCliStream(id, send, cmd, args, stdinData, parseChunk) {
  let proc;
  try {
    proc = spawn(cmd, args, { stdio: ["pipe", "pipe", "pipe"] });
  } catch (e) {
    send("ember:ai:error", `${cmd}: ${e.message || String(e)}`);
    return null;
  }

  let stderr = "";
  let total  = 0;
  let pending = "";
  proc.stdout.on("data", (chunk) => {
    const s = chunk.toString();
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
    if (code === 0) send("ember:ai:done", { chars: total });
    else send("ember:ai:error",
              `${cmd} exited ${code}${stderr ? `: ${stderr.trim().slice(0, 300)}` : ""}`);
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

ipcMain.handle("ember:ai:chat", async (e, { messages, model, temperature }) => {
  const cfg = await loadAiConfig();
  const id  = String(AI_NEXT_ID++);
  const win = BrowserWindow.fromWebContents(e.sender);
  const send = (channel, ...args) => {
    if (win && !win.isDestroyed()) win.webContents.send(channel, id, ...args);
  };
  const chosenModel = model || cfg.model;

  // ---- OpenRouter ----------------------------------------------------
  if (cfg.provider === "openrouter") {
    const apiKey = await loadAiKey();
    if (!apiKey) throw new Error("no OpenRouter API key configured");

    const body = JSON.stringify({
      model:       chosenModel,
      messages,
      stream:      true,
      temperature: typeof temperature === "number" ? temperature : 0.4,
    });
    const req = https.request({
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
    }, (res) => {
      if (res.statusCode && res.statusCode >= 400) {
        let buf = "";
        res.on("data", (d) => { buf += d.toString(); });
        res.on("end", () => {
          send("ember:ai:error",
               `OpenRouter ${res.statusCode}: ${buf.slice(0, 400)}`);
          AI_INFLIGHT.delete(id);
        });
        return;
      }
      let pending = "";
      let total   = 0;
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
              const delta = j.choices?.[0]?.delta?.content;
              if (typeof delta === "string" && delta.length > 0) {
                total += delta.length;
                send("ember:ai:chunk", delta);
              }
            } catch { /* keepalive */ }
          }
        }
      });
      res.on("end", () => {
        send("ember:ai:done", { chars: total });
        AI_INFLIGHT.delete(id);
      });
    });
    req.on("error", (err) => {
      send("ember:ai:error", err.message || String(err));
      AI_INFLIGHT.delete(id);
    });
    AI_INFLIGHT.set(id, { cancel: () => req.destroy(new Error("cancelled")) });
    req.write(body);
    req.end();
    return id;
  }

  // ---- assistant Code CLI ----------------------------------------------
  if (cfg.provider === "assistant-cli") {
    const systemPrompt = extractSystemPrompt(messages);
    const flat         = flattenMessages(messages);
    const args = [
      "-p",                       // print/headless
      "--bare",                   // skip auto-discovery (faster, no hooks/skills)
      "--no-session-persistence", // don't pollute the user's session history
      "--output-format", "stream-json",
      "--include-partial-messages",
      "--verbose",                // stream-json requires verbose on recent versions
    ];
    if (chosenModel) args.push("--model", chosenModel);
    if (systemPrompt) args.push("--append-system-prompt", systemPrompt);
    args.push(flat);

    const proc = spawnCliStream(id, send, "assistant", args, null,
                                parseassistantStreamEvent);
    if (proc) AI_INFLIGHT.set(id, { cancel: () => proc.kill("SIGTERM") });
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
