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

// ----- AI / OpenRouter -----
//
// The renderer never sees the API key — it only sees streamed deltas
// labelled with a request id. We hold the key, plus the user-chosen
// model and a few canned model presets, in a small JSON sidecar in
// userData. Key bytes are encrypted with Electron's safeStorage when
// the OS supports it (Keychain on macOS, libsecret on Linux, DPAPI on
// Windows); when it doesn't, we fall back to plaintext with a flag in
// the sidecar so the renderer can warn the user.

const AI_CONFIG_PATH = () => path.join(app.getPath("userData"), "ai.json");

// Default models we surface in the picker. The user can paste any
// OpenRouter model id; this list is just the well-known set so the
// dropdown isn't empty on first run. Update freely — there's no
// version-pinning that depends on these strings.
const AI_DEFAULT_MODELS = [
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
];

async function loadAiConfig() {
  try {
    const raw = await fs.readFile(AI_CONFIG_PATH(), "utf8");
    const j   = JSON.parse(raw);
    let key = "";
    if (j.keyEncrypted && safeStorage.isEncryptionAvailable()) {
      try { key = safeStorage.decryptString(Buffer.from(j.keyEncrypted, "base64")); }
      catch { key = ""; }
    } else if (j.keyPlain) {
      key = j.keyPlain;
    }
    return {
      hasKey:    !!key,
      model:     j.model || AI_DEFAULT_MODELS[0],
      encrypted: !!j.keyEncrypted,
    };
  } catch {
    return { hasKey: false, model: AI_DEFAULT_MODELS[0], encrypted: false };
  }
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

async function saveAiConfig({ apiKey, model }) {
  const out = { model };
  if (typeof apiKey === "string") {
    if (safeStorage.isEncryptionAvailable()) {
      out.keyEncrypted = safeStorage.encryptString(apiKey).toString("base64");
    } else {
      // Plaintext fallback. Renderer surfaces this in the settings UI
      // so the user knows the file isn't safe to share.
      out.keyPlain = apiKey;
    }
  } else {
    // Caller didn't touch the key — preserve whatever's already on disk.
    try {
      const raw = await fs.readFile(AI_CONFIG_PATH(), "utf8");
      const j   = JSON.parse(raw);
      if (j.keyEncrypted) out.keyEncrypted = j.keyEncrypted;
      if (j.keyPlain)     out.keyPlain     = j.keyPlain;
    } catch { /* fresh config */ }
  }
  await fs.mkdir(path.dirname(AI_CONFIG_PATH()), { recursive: true });
  await fs.writeFile(AI_CONFIG_PATH(), JSON.stringify(out, null, 2), "utf8");
}

ipcMain.handle("ember:ai:getConfig", async () => loadAiConfig());

ipcMain.handle("ember:ai:setConfig", async (_e, c) => {
  await saveAiConfig({ apiKey: c.apiKey, model: c.model });
  return loadAiConfig();
});

ipcMain.handle("ember:ai:listModels", async () => AI_DEFAULT_MODELS.slice());

// Active in-flight requests, keyed by id so `ai:cancel` can abort.
const AI_INFLIGHT = new Map();
let AI_NEXT_ID    = 1;

ipcMain.handle("ember:ai:cancel", async (_e, id) => {
  const ent = AI_INFLIGHT.get(id);
  if (!ent) return false;
  try { ent.req.destroy(new Error("cancelled")); } catch {}
  AI_INFLIGHT.delete(id);
  return true;
});

ipcMain.handle("ember:ai:chat", async (e, { messages, model, temperature }) => {
  const apiKey = await loadAiKey();
  if (!apiKey) throw new Error("no OpenRouter API key configured");

  const id    = String(AI_NEXT_ID++);
  const win   = BrowserWindow.fromWebContents(e.sender);
  const send  = (channel, ...args) => {
    if (win && !win.isDestroyed()) win.webContents.send(channel, id, ...args);
  };

  const body = JSON.stringify({
    model:       model || (await loadAiConfig()).model,
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
      // OpenRouter recommends these for the request to be attributed
      // back to the calling app in their dashboards.
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
    // Server-Sent Events parsing. The OpenAI-compatible streaming
    // format chunks JSON deltas as `data: {...}\n\n` events; the
    // sentinel `data: [DONE]` ends the stream.
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
          if (!line || !line.startsWith("{")) {
            if (line === "[DONE]") { /* handled at end */ }
            continue;
          }
          try {
            const j = JSON.parse(line);
            const delta = j.choices?.[0]?.delta?.content;
            if (typeof delta === "string" && delta.length > 0) {
              total += delta.length;
              send("ember:ai:chunk", delta);
            }
          } catch {
            // Stray non-JSON keepalive comment — OpenRouter sends `: …`
            // every 15s. Ignore.
          }
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

  AI_INFLIGHT.set(id, { req });
  req.write(body);
  req.end();
  return id;
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
