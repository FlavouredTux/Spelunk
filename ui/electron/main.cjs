const { app, BrowserWindow, Menu, dialog, ipcMain, safeStorage, shell, screen } = require("electron");

if (process.platform === "linux") {
  const requestedOzone = process.env.ELECTRON_OZONE_PLATFORM;
  const requestedScale = process.env.ELECTRON_FORCE_DEVICE_SCALE_FACTOR ||
                         process.env.EMBER_FORCE_DEVICE_SCALE_FACTOR;
  if (requestedScale) {
    app.commandLine.appendSwitch("force-device-scale-factor", requestedScale);
  }
  if (process.env.EMBER_DISABLE_GPU === "1") {
    app.commandLine.appendSwitch("disable-gpu");
  }
  if (requestedOzone) {
    app.commandLine.appendSwitch("ozone-platform", requestedOzone);
    if (requestedOzone === "wayland") {
      app.commandLine.appendSwitch("enable-features", "WaylandWindowDecorations");
    }
  } else {
    app.commandLine.appendSwitch("ozone-platform-hint", process.env.ELECTRON_OZONE_PLATFORM_HINT || "auto");
  }
}

// Suppress the default File / Edit / View / Window / Help bar on
// Linux + Windows. Ember has its own title bar (NavArrows, jump,
// settings, …) and the platform menu duplicates nothing useful.
// macOS keeps its application-level menu by convention; setting it
// to null there strips Cmd+Q / Cmd+W and friends, which we don't want.
if (process.platform !== "darwin") {
  Menu.setApplicationMenu(null);
}
const { spawn } = require("node:child_process");
const https = require("node:https");
const http  = require("node:http");
const { makeTools } = require("./ai_tools.cjs");
const { makePluginHost } = require("./plugins.cjs");
const fs = require("node:fs/promises");
const fsSync = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { pipeline } = require("node:stream/promises");
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

// Windows MSVC / MinGW builds emit `ember.exe`; *nix builds emit
// bare `ember`. In packaged Electron the CLI ships in resources;
// in dev we run from the cmake build dir. Honour EMBER_BIN as an
// explicit override either way.
function defaultEmberBin() {
  const exe = process.platform === "win32" ? "ember.exe" : "ember";
  if (app.isPackaged) {
    return path.join(process.resourcesPath, "cli", exe);
  }
  return path.join(__dirname, "..", "..", "build", "cli", exe);
}
const EMBER_BIN = process.env.EMBER_BIN || defaultEmberBin();

const state = { binary: null };

function createWindow() {
  const win = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 960,
    minHeight: 600,
    backgroundColor: "#141413",
    titleBarStyle: process.platform === "darwin" ? "hiddenInset" : "default",
    icon: path.join(__dirname, "..", "assets", "icon.png"),
    show: false,
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      sandbox: false,
      nodeIntegration: false,
    },
  });

  win.once("ready-to-show", () => win.show());
  win.webContents.on("did-finish-load", () => {
    win.webContents.setZoomFactor(1);
    win.webContents.setVisualZoomLevelLimits(1, 1).catch(() => {});
  });

  // `app.isPackaged` is the only reliable dev/prod signal — a packaged
  // Electron app does NOT set NODE_ENV, so gating on it means the
  // installer tries to load the Vite dev server URL, loadURL fails
  // silently, `ready-to-show` never fires, and the window stays hidden
  // forever. Users see the process launch and nothing appear.
  if (!app.isPackaged) {
    const devUrl = process.env.VITE_DEV_SERVER_URL || "http://localhost:5173";
    win.loadURL(devUrl);
    if (process.env.EMBER_OPEN_DEVTOOLS === "1") {
      win.webContents.openDevTools({ mode: "detach" });
    }
  } else {
    win.loadFile(path.join(__dirname, "..", "dist", "index.html"));
  }

  // Belt and braces: if the renderer fails to load for any reason,
  // show the window anyway so the user isn't staring at nothing.
  win.webContents.on("did-fail-load", (_e, code, desc, url) => {
    console.error(`renderer load failed: ${code} ${desc} ${url}`);
    if (!win.isDestroyed() && !win.isVisible()) win.show();
  });
}

function collectMainDiagnostics() {
  const win = BrowserWindow.getAllWindows()[0] ?? null;
  const bounds = win?.getBounds() ?? null;
  const display = win ? screen.getDisplayMatching(bounds) : screen.getPrimaryDisplay();
  const commandLine = process.argv.filter((arg) =>
    arg.includes("ozone") ||
    arg.includes("wayland") ||
    arg.includes("enable-features") ||
    arg.includes("force-device-scale-factor")
  );
  const envKeys = [
    "XDG_SESSION_TYPE",
    "WAYLAND_DISPLAY",
    "DISPLAY",
    "XCURSOR_THEME",
    "XCURSOR_SIZE",
    "ELECTRON_OZONE_PLATFORM",
    "ELECTRON_OZONE_PLATFORM_HINT",
    "ELECTRON_ENABLE_LOGGING",
    "GDK_BACKEND",
    "QT_QPA_PLATFORM",
    "HYPRLAND_INSTANCE_SIGNATURE",
  ];
  const env = {};
  for (const key of envKeys) {
    if (process.env[key] != null) env[key] = process.env[key];
  }
  return {
    app: {
      version: app.getVersion(),
      electron: process.versions.electron,
      chrome: process.versions.chrome,
      node: process.versions.node,
      platform: process.platform,
      arch: process.arch,
      packaged: app.isPackaged,
      commandLine,
      env,
    },
    window: win ? {
      bounds,
      contentBounds: win.getContentBounds(),
      size: win.getSize(),
      contentSize: win.getContentSize(),
      zoomFactor: win.webContents.getZoomFactor(),
      zoomLevel: win.webContents.getZoomLevel(),
      url: win.webContents.getURL(),
      devToolsOpened: win.webContents.isDevToolsOpened(),
      backgroundThrottling: win.webContents.getBackgroundThrottling?.(),
    } : null,
    display: {
      id: display.id,
      scaleFactor: display.scaleFactor,
      bounds: display.bounds,
      workArea: display.workArea,
      rotation: display.rotation,
      colorDepth: display.colorDepth,
      colorSpace: display.colorSpace,
      internal: display.internal,
      label: display.label,
    },
  };
}

// stdout/stderr accumulated as a stream of UTF-8 string chunks rather
// than an ever-growing string. Two reasons:
//   1. setEncoding("utf8") gives the stream a stateful decoder that
//      doesn't split multi-byte sequences across `data` events — the
//      old `d.toString()` per chunk produced replacement chars in
//      demangled C++ symbols at chunk boundaries.
//   2. `arr.push(s)` + `arr.join("")` is O(n) regardless of V8's
//      cord-string heuristics, where `out += s` can fall back to
//      worst-case copying on multi-MB outputs.
function runEmber(args) {
  return new Promise((resolve, reject) => {
    const proc = spawn(EMBER_BIN, args, { cwd: path.dirname(EMBER_BIN) });
    proc.stdout.setEncoding("utf8");
    proc.stderr.setEncoding("utf8");
    const outChunks = [];
    const errChunks = [];
    proc.stdout.on("data", (d) => { outChunks.push(d); });
    proc.stderr.on("data", (d) => { errChunks.push(d); });
    proc.on("error", (e) => reject(e));
    proc.on("close", (code, signal) => {
      if (code === 0) return resolve(outChunks.join(""));
      // code === null means the process was killed by a signal (segfault,
      // OOM, SIGTERM, ...). Surface the signal + whatever stderr we got
      // so the renderer can show something actionable instead of a
      // mysterious "exited null".
      const how = code === null
        ? `ember killed by ${signal || "signal"}`
        : `ember exited ${code}`;
      const tail = errChunks.join("").trim();
      const msg = tail ? `${how}\n${tail.slice(-2000)}` : how;
      const full = `${msg}\n(cmd: ${EMBER_BIN} ${args.join(" ")})`;
      reject(new Error(full));
    });
  });
}

function runCapture(bin, args, cwd = process.cwd()) {
  return new Promise((resolve, reject) => {
    const proc = spawn(bin, args, { cwd });
    proc.stdout.setEncoding("utf8");
    proc.stderr.setEncoding("utf8");
    const outChunks = [];
    const errChunks = [];
    proc.stdout.on("data", (d) => { outChunks.push(d); });
    proc.stderr.on("data", (d) => { errChunks.push(d); });
    proc.on("error", reject);
    proc.on("close", (code) => {
      if (code === 0) return resolve(outChunks.join("").trim());
      const msg = errChunks.join("").trim() || `${bin} exited ${code}`;
      reject(new Error(msg));
    });
  });
}

function canonicalAddr(hex) {
  const s = String(hex || "").trim().replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]+$/.test(s)) return null;
  return "0x" + s.padStart(16, "0");
}

function defaultCorpusPath() {
  const home = os.homedir();
  const candidates = [
    path.join(home, "corpus_humongous_combined.teef"),
    path.join(home, "corpus_combined.teef"),
  ];
  for (const p of candidates) {
    try {
      if (fsSync.existsSync(p)) return p;
    } catch {}
  }
  return home;
}

function parseRecognizeRenames(stdout, threshold) {
  const renames = {};
  let scanned = 0;
  for (const line of String(stdout || "").split("\n")) {
    if (!line.trim()) continue;
    ++scanned;
    const parts = line.split("\t");
    if (parts.length < 5) continue;
    const addr = canonicalAddr(parts[0]);
    const suggested = String(parts[2] || "").trim();
    const confidence = Number(parts[3]);
    if (!addr || !suggested || !Number.isFinite(confidence)) continue;
    if (confidence < threshold) continue;
    if (/^sub_[0-9a-f]+$/i.test(suggested)) continue;
    renames[addr] = suggested;
  }
  return { renames, scanned };
}

function parseGitHubRepo(url) {
  const m = /github\.com[:/]([^/]+)\/([^/.]+?)(?:\.git)?$/i.exec(url || "");
  if (!m) return null;
  return { owner: m[1], repo: m[2] };
}

function compareVersions(a, b) {
  const pa = String(a || "").replace(/^v/i, "").split(".").map((x) => parseInt(x, 10) || 0);
  const pb = String(b || "").replace(/^v/i, "").split(".").map((x) => parseInt(x, 10) || 0);
  const n = Math.max(pa.length, pb.length);
  for (let i = 0; i < n; ++i) {
    const da = pa[i] || 0;
    const db = pb[i] || 0;
    if (da !== db) return da - db;
  }
  return 0;
}

function getJson(url, headers = {}) {
  return new Promise((resolve, reject) => {
    https.get(url, {
      headers: {
        "User-Agent": "Ember-Updater",
        "Accept": "application/vnd.github+json",
        ...headers,
      },
    }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        return resolve(getJson(res.headers.location, headers));
      }
      if (res.statusCode !== 200) {
        const code = res.statusCode;
        res.resume();
        return reject(new Error(`HTTP ${code} while fetching ${url}`));
      }
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (d) => { body += d; });
      res.on("end", () => {
        try { resolve(JSON.parse(body)); }
        catch (e) { reject(new Error(`invalid JSON from ${url}: ${e.message}`)); }
      });
    }).on("error", reject);
  });
}

function downloadFile(url, outPath) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { "User-Agent": "Ember-Updater" } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        return resolve(downloadFile(res.headers.location, outPath));
      }
      if (res.statusCode !== 200) {
        const code = res.statusCode;
        res.resume();
        return reject(new Error(`HTTP ${code} while downloading ${url}`));
      }
      fs.mkdir(path.dirname(outPath), { recursive: true })
        .then(() => pipeline(res, fsSync.createWriteStream(outPath)))
        .then(() => resolve(outPath))
        .catch(reject);
    }).on("error", reject);
  });
}

function pickReleaseAsset(release) {
  const assets = Array.isArray(release?.assets) ? release.assets : [];
  const choices = process.platform === "win32"
    ? [".exe"]
    : process.platform === "darwin"
      ? [".dmg", ".zip"]
      : [".AppImage", ".deb"];
  for (const ext of choices) {
    const hit = assets.find((a) => typeof a?.name === "string" && a.name.endsWith(ext));
    if (hit) return hit;
  }
  return null;
}

async function fetchLatestReleaseInfo() {
  const homepage = (() => {
    try { return require("../package.json").homepage; }
    catch { return ""; }
  })();
  const repo = parseGitHubRepo(homepage);
  if (!repo) throw new Error("package homepage is not a GitHub repo URL");
  const rel = await getJson(`https://api.github.com/repos/${repo.owner}/${repo.repo}/releases/latest`);
  const currentVersion = app.getVersion();
  const latestVersion = String(rel.tag_name || rel.name || "").replace(/^v/i, "");
  const asset = pickReleaseAsset(rel);
  return {
    ok: true,
    currentVersion,
    latestVersion,
    tag: rel.tag_name || "",
    releaseName: rel.name || rel.tag_name || "",
    url: rel.html_url || homepage,
    assetName: asset?.name || "",
    assetUrl: asset?.browser_download_url || "",
    notes: typeof rel.body === "string" ? rel.body : "",
    available: compareVersions(latestVersion, currentVersion) > 0 && !!asset,
  };
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

const RUN_CACHE       = new Map();   // key → stdout string
// Cap by total payload bytes, not entry count. Entries are stdout
// strings of unpredictable size: a `--functions` on a 150 MB PE can
// produce 30+ MB of TSV. The previous count-of-200 cap meant the cache
// could pin gigabytes — which was the renderer's "memory leak" feel
// after a few binaries opened. 256 MB matches a comfortable working
// set on machines with 8+ GB and gets evicted immediately on smaller
// outputs.
const RUN_CACHE_BYTES_CAP = 256 * 1024 * 1024;
let   RUN_CACHE_BYTES     = 0;
const RUN_INFLIGHT        = new Map();  // key → in-flight Promise (dedup concurrent)

async function safeMtime(p) {
  if (!p) return 0;
  try { return (await fs.stat(p)).mtimeMs; }
  catch { return 0; }
}

// JS strings are UTF-16 internally; .length × 2 is the on-heap cost
// V8 actually pays for the string body (ignoring any rope overhead,
// which is small relative to multi-MB stdout payloads).
function approxStringBytes(s) {
  return typeof s === "string" ? s.length * 2 : 0;
}

function lruTouch(map, key, value) {
  if (map.has(key)) {
    RUN_CACHE_BYTES -= approxStringBytes(map.get(key));
    map.delete(key);
  }
  map.set(key, value);
  RUN_CACHE_BYTES += approxStringBytes(value);
  while (RUN_CACHE_BYTES > RUN_CACHE_BYTES_CAP && map.size > 1) {
    const first = map.keys().next().value;
    RUN_CACHE_BYTES -= approxStringBytes(map.get(first));
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

ipcMain.handle("ember:debug:diagnostics", async () => collectMainDiagnostics());

// Generic file picker for callers that need a path other than the
// primary binary — e.g. the diff view's "old binary" selector and the
// .ember script applier. Doesn't touch state.binary or recents.
ipcMain.handle("ember:pickFile", async (_e, opts) => {
  const o = opts && typeof opts === "object" ? opts : {};
  const r = await dialog.showOpenDialog({
    title: typeof o.title === "string" ? o.title : "Select file",
    properties: ["openFile"],
    filters: Array.isArray(o.filters) ? o.filters : [
      { name: "All files", extensions: ["*"] },
    ],
  });
  if (r.canceled || r.filePaths.length === 0) return null;
  return r.filePaths[0];
});

ipcMain.handle("ember:setBinary", async (_e, p) => {
  if (typeof p !== "string" || !p) return null;
  state.binary = p;
  await addRecent(p);
  return state.binary;
});

// FNV-1a-64 of a string, used to compute the ember-side cache annotations
// path. Must match the C++ `fnv1a_64` in core/src/common/annotations.cpp —
// same algorithm, same offset/prime constants.
function fnv1a64(s) {
  let h = 0xcbf29ce484222325n;
  const m = 0x100000001b3n;
  for (let i = 0; i < s.length; i++) {
    h ^= BigInt(s.charCodeAt(i));
    h = (h * m) & 0xffffffffffffffffn;
  }
  return h.toString(16).padStart(16, "0");
}

// Locate the cache annotations file ember CLI / ember-agent promote
// writes to. Mirrors `cache_annotation_path` in core/src/common/
// annotations.cpp: path-keyed (not content-keyed), basename + FNV of
// the absolute parent dir. The XDG_CACHE_HOME / ~/.cache fallback also
// matches what ember does.
function emberCacheAnnotationsPath(binaryPath) {
  const abs = path.resolve(binaryPath);
  const parent = path.dirname(abs) || ".";
  const key = `${path.basename(abs)}@${fnv1a64(parent)}`;
  const cacheRoot = process.env.XDG_CACHE_HOME
    ? path.join(process.env.XDG_CACHE_HOME, "ember")
    : path.join(require("node:os").homedir(), ".cache", "ember");
  return path.join(cacheRoot, "annotations", key, "annotations.db");
}

// Memoize the parsed sidecar JSON and ember cache .db keyed by
// (path, mtime). Pre-fix every ember:run IPC call read+parsed each of
// these from scratch, costing ~50ms of pure I/O before the RUN_CACHE
// lookup even started — visible as per-click lag on slow disks.
const _SIDECAR_PARSE_CACHE  = new Map();   // binaryPath → { mtime, val }
const _CACHE_DB_PARSE_CACHE = new Map();   // binaryPath → { mtime, val }

async function memoByMtime(cache, key, filePath, parser) {
  const mtime = await safeMtime(filePath);
  const hit = cache.get(key);
  if (hit && hit.mtime === mtime) return hit.val;
  const val = await parser();
  cache.set(key, { mtime, val });
  return val;
}

// Parse the cache annotations.db (TSV-ish: `rename <hex_addr> <name>`,
// `note <hex_addr> <text>`, etc.). Returns { renames, notes } only —
// the cache format doesn't carry signatures/patches. Empty object if
// the file doesn't exist or is unreadable.
async function readEmberCacheAnnotations(binaryPath) {
  return memoByMtime(
    _CACHE_DB_PARSE_CACHE, binaryPath,
    emberCacheAnnotationsPath(binaryPath),
    () => parseEmberCacheAnnotations(binaryPath));
}

async function parseEmberCacheAnnotations(binaryPath) {
  const out = { renames: {}, notes: {}, fields: {} };
  try {
    const raw = await fs.readFile(emberCacheAnnotationsPath(binaryPath), "utf8");
    for (const line of raw.split("\n")) {
      const t = line.trim();
      if (!t || t.startsWith("#")) continue;
      const sp1 = t.indexOf(" ");
      if (sp1 < 0) continue;
      const kind = t.slice(0, sp1);
      const sp2 = t.indexOf(" ", sp1 + 1);
      if (sp2 < 0) continue;
      const addrHex = t.slice(sp1 + 1, sp2);
      const value   = t.slice(sp2 + 1);
      if (!/^[0-9a-fA-F]+$/.test(addrHex)) continue;
      // Match the address format ember --functions emits: 18-char
      // canonical hex (`0x` + 16 lowercase digits, zero-padded). The
      // sidebar / displayName helper looks up renames keyed off
      // FunctionInfo.addr which uses that exact form, so a trimmed
      // `0x2004` key would silently miss every match.
      const addr = "0x" + addrHex.toLowerCase().padStart(16, "0");
      if      (kind === "rename") out.renames[addr] = value;
      else if (kind === "note")   out.notes[addr]   = value;
      else if (kind === "field") {
        const parts = value.split("|");
        if (parts.length >= 3) {
          out.fields[`${addr}:${parts[0].trim()}:${parts[1].trim()}`] =
            parts.slice(2).join("|").trim();
        }
      }
      // signatures/types/patches are not in the cache .db format yet —
      // ignore unrecognised verbs rather than fail.
    }
  } catch { /* missing — return empty {} */ }
  return out;
}

// Pull the merged annotations view for a binary. Two stores feed in:
//   - the UI's JSON sidecar at <userData>/projects/<sanitized>.json
//     (renames + notes + signatures + localRenames + patches the user
//     edited in-app)
//   - ember's cache annotations.db at ~/.cache/ember/annotations/<key>/
//     (renames + notes from `ember-agent promote --apply` / `ember
//     --apply <script>`)
// The UI sidecar wins on conflict — manual renames override agent
// guesses. Patches / signatures / localRenames live only in the JSON
// sidecar (no cache-side equivalent yet).
async function readSidecarJson(binaryPath) {
  return memoByMtime(
    _SIDECAR_PARSE_CACHE, binaryPath,
    sidecarPath(binaryPath),
    async () => {
      try { return JSON.parse(await fs.readFile(sidecarPath(binaryPath), "utf8")); }
      catch { return {}; }
    });
}

async function readSidecar(binaryPath) {
  const [json, cache] = await Promise.all([
    readSidecarJson(binaryPath),
    readEmberCacheAnnotations(binaryPath),
  ]);
  return {
    renames:      { ...cache.renames, ...(json.renames    || {}) },
    notes:        { ...cache.notes,   ...(json.notes      || {}) },
    signatures:   json.signatures   || {},
    fields:       { ...cache.fields,  ...(json.fields     || {}) },
    localRenames: json.localRenames || {},
    patches:      json.patches      || {},
  };
}

async function saveSidecar(binaryPath, data) {
  const p = sidecarPath(binaryPath);
  await fs.mkdir(path.dirname(p), { recursive: true });
  await fs.writeFile(p, JSON.stringify(data, null, 2), "utf8");
  // Bust the parse cache so the next reader doesn't see stale JSON
  // before mtime resolution catches up (some filesystems quantize to
  // 1 ms, which on a fast machine can land within the same tick).
  _SIDECAR_PARSE_CACHE.delete(binaryPath);
}

// Stable per-patch-set hash used as the patched-binary filename suffix
// so a given patch combination materialises to one cached file. Cheap
// FNV-1a is fine — collision risk is irrelevant given the file is
// re-derivable, and it avoids dragging in node:crypto for one call.
function hashPatches(patches) {
  let h = 0xcbf29ce484222325n;
  const m = 0x100000001b3n;
  const keys = Object.keys(patches).sort();
  for (const k of keys) {
    const s = `${k}=${patches[k].bytes};`;
    for (let i = 0; i < s.length; i++) {
      h ^= BigInt(s.charCodeAt(i));
      h = (h * m) & 0xffffffffffffffffn;
    }
  }
  return h.toString(16).padStart(16, "0");
}

// If the sidecar has byte patches, materialise (or reuse cached) a
// patched copy of the original binary and return that path. Otherwise
// return the original. Failing to apply patches falls back to the
// original with a stderr warning — analysis is more useful than a
// hard error here, and the patches panel will surface the issue.
async function materializePatchedBinary(originalPath) {
  const ann = await readSidecar(originalPath);
  const patches = ann.patches || {};
  if (Object.keys(patches).length === 0) return originalPath;

  const tag = hashPatches(patches);
  const patchedPath = path.join(app.getPath("userData"), "projects",
                                sanitize(originalPath) + `.${tag}.patched`);

  // Reuse a previously-materialised file if it's still newer than the
  // original binary. The hash already covers patch-set identity, so
  // mtime is a belt-and-braces guard for the user editing the binary
  // in place. Run the two stats in parallel.
  const [origMtime, patchedMtime] = await Promise.all([
    safeMtime(originalPath),
    safeMtime(patchedPath),
  ]);
  if (patchedMtime && origMtime && patchedMtime >= origMtime) {
    return patchedPath;
  }

  // Write the patches file in the format ember --apply-patches expects.
  const patchesFile = path.join(app.getPath("userData"), "projects",
                                sanitize(originalPath) + ".patches.txt");
  const lines = Object.entries(patches).map(([addr, p]) => {
    // Insert spaces every 2 hex chars for readability — the parser
    // strips whitespace anyway. Address keeps its 0x prefix.
    const grouped = (p.bytes.match(/.{1,2}/g) || []).join(" ");
    return `${addr} ${grouped}`;
  });
  await fs.mkdir(path.dirname(patchesFile), { recursive: true });
  await fs.writeFile(patchesFile, lines.join("\n") + "\n", "utf8");

  try {
    await runEmber(["--apply-patches", patchesFile, "-o", patchedPath, originalPath]);
    return patchedPath;
  } catch (e) {
    console.warn(`ember: patch materialisation failed; falling back to original (${e.message})`);
    return originalPath;
  }
}

// Match the C++ side's escape_note: backslash, newline, carriage return.
// The C++ load() doesn't currently unescape, so multi-line notes will
// round-trip imperfectly through any apply that touches them — see
// core/src/common/annotations.cpp. Single-line notes (the common case)
// round-trip cleanly.
function escapeNote(s) {
  return String(s).replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/\r/g, "\\r");
}
function unescapeNote(s) {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    if (s[i] === "\\" && i + 1 < s.length) {
      const c = s[i + 1];
      if (c === "n")      { out += "\n"; i++; continue; }
      if (c === "r")      { out += "\r"; i++; continue; }
      if (c === "\\")     { out += "\\"; i++; continue; }
    }
    out += s[i];
  }
  return out;
}

// Parse the .ann TSV format ember reads/writes via Annotations::load /
// to_text — line-based: `rename <hex> <name>`, `sig <hex> <ret>|<type>|<name>|...`,
// `note <hex> <escaped>`, `const <hex> <name>`. Returns the JSON shape
// the renderer expects (subset — patches/localRenames don't live here).
function parseAnnText(text) {
  const renames = {};
  const signatures = {};
  const notes = {};
  const fields = {};
  for (const raw of String(text).split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const sp1 = line.indexOf(" ");
    if (sp1 < 0) continue;
    const kind = line.slice(0, sp1);
    const rest = line.slice(sp1 + 1).trim();
    if (kind === "rename") {
      const sp2 = rest.indexOf(" ");
      if (sp2 < 0) continue;
      const addr = `0x${rest.slice(0, sp2)}`;
      renames[addr] = rest.slice(sp2 + 1).trim();
    } else if (kind === "sig") {
      const sp2 = rest.indexOf(" ");
      if (sp2 < 0) continue;
      const addr = `0x${rest.slice(0, sp2)}`;
      const parts = rest.slice(sp2 + 1).split("|").map((s) => s.trim());
      if (parts.length === 0) continue;
      const params = [];
      for (let i = 1; i + 1 < parts.length; i += 2) {
        if (!parts[i]) continue;
        params.push({ type: parts[i], name: parts[i + 1] || "_" });
      }
      signatures[addr] = { returnType: parts[0] || "void", params };
    } else if (kind === "note") {
      const sp2 = rest.indexOf(" ");
      if (sp2 < 0) continue;
      const addr = `0x${rest.slice(0, sp2)}`;
      notes[addr] = unescapeNote(rest.slice(sp2 + 1));
    } else if (kind === "field") {
      const sp2 = rest.indexOf(" ");
      if (sp2 < 0) continue;
      const addr = `0x${rest.slice(0, sp2)}`;
      const parts = rest.slice(sp2 + 1).split("|").map((s) => s.trim());
      if (parts.length < 3) continue;
      fields[`${addr}:${parts[0]}:${parts[1]}`] = parts.slice(2).join("|");
    }
    // `const` (named_constants) isn't surfaced in the renderer's
    // annotation shape yet — silently ignored.
  }
  return { renames, signatures, notes, fields };
}

// Convert the on-disk JSON sidecar into the plain-text format the CLI
// expects. Returns the temp file path, or null if there's nothing to write.
//
// Cache the projected text in memory keyed by binaryPath, and skip the
// write when content is byte-identical to what's already on disk. This
// keeps the .ann file's mtime stable across repeated `ember:run` calls,
// which is the only thing that lets RUN_CACHE actually hit — without
// this guard, every IPC call rewrote the file with fresh mtime,
// invalidating every cached entry on every click.
const ANN_TEXT_CACHE = new Map();   // binaryPath → last projected text

async function writeCliAnnotations(binaryPath) {
  const parsed = await readSidecarJson(binaryPath);
  if (!parsed || Object.keys(parsed).length === 0) return null;
  const renames = parsed.renames || {};
  const sigs    = parsed.signatures || {};
  const notes   = parsed.notes || {};
  const fields  = parsed.fields || {};
  if (Object.keys(renames).length === 0 &&
      Object.keys(sigs).length === 0 &&
      Object.keys(notes).length === 0 &&
      Object.keys(fields).length === 0) {
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
  for (const [addr, text] of Object.entries(notes)) {
    const hex = String(addr).replace(/^0x/, "");
    lines.push(`note ${hex} ${escapeNote(text)}`);
  }
  for (const [key, name] of Object.entries(fields)) {
    const parts = String(key).split(":");
    if (parts.length < 3) continue;
    const hex = parts[0].replace(/^0x/, "");
    const param = parts[1];
    const off = parts.slice(2).join(":");
    lines.push(`field ${hex} ${param}|${off}|${name}`);
  }
  const text = lines.join("\n") + "\n";
  const outPath = path.join(app.getPath("userData"), "projects",
                            sanitize(binaryPath) + ".ann");

  // In-memory fast path: same projected text as the previous call for
  // this binary → assume the on-disk file still matches, skip both the
  // disk read and the write. The `readFile` path below covers cold
  // starts where the cache is empty but the file already exists.
  if (ANN_TEXT_CACHE.get(binaryPath) === text) return outPath;

  await fs.mkdir(path.dirname(outPath), { recursive: true });
  let onDisk = null;
  try { onDisk = await fs.readFile(outPath, "utf8"); } catch {}
  if (onDisk !== text) {
    await fs.writeFile(outPath, text, "utf8");
  }
  ANN_TEXT_CACHE.set(binaryPath, text);
  return outPath;
}

ipcMain.handle("ember:run", async (_e, args) => {
  if (!state.binary) throw new Error("no binary selected");
  if (!Array.isArray(args)) throw new Error("args must be array");
  // writeCliAnnotations + materializePatchedBinary both end up reading
  // the same sidecar JSON, so they can run in parallel now that the
  // parse is memoized by mtime. This was 50–100 ms of serial I/O on
  // every click before — the user sees it as "even small functions
  // load slowly."
  const [annPath, effective] = await Promise.all([
    writeCliAnnotations(state.binary),
    materializePatchedBinary(state.binary),
  ]);

  const [binMtime, annMtime, cliMtime] = await Promise.all([
    safeMtime(effective),
    safeMtime(annPath),
    safeMtime(EMBER_BIN),
  ]);
  // Embed mtimes in the key. When the binary, patches or annotations
  // change, the new key won't hit prior entries — they fall out via
  // LRU. The patched-copy mtime captures the patches themselves; the
  // CLI mtime keeps dev UI sessions from serving old pseudo-C after a
  // local rebuild.
  const key = `${effective}|${binMtime}|${annMtime}|${cliMtime}|${args.join("\x00")}`;

  if (RUN_CACHE.has(key)) {
    const v = RUN_CACHE.get(key);
    lruTouch(RUN_CACHE, key, v);   // bubble to MRU
    return v;
  }
  // Concurrent identical requests — coalesce to a single spawn.
  if (RUN_INFLIGHT.has(key)) return RUN_INFLIGHT.get(key);

  const extra = annPath ? ["--annotations", annPath] : [];
  const t0 = Date.now();
  const p = runEmber([...args, ...extra, effective])
    .then((out) => {
      lruTouch(RUN_CACHE, key, out);
      const dt = Date.now() - t0;
      // Anything over a second on a single ember spawn is worth knowing
      // about — either the binary's hot pages got evicted, the user is
      // on cold-cache after an annotations save, or a CLI flag changed
      // the cost class. Surface in the [electron] dev log so the user
      // can correlate to clicks without recording a full Performance
      // trace.
      if (dt >= 1000) {
        const argSummary = args.join(" ").slice(0, 80);
        const sizeKB = Math.round(out.length / 1024);
        console.warn(
          `[ember:run] slow: ${dt}ms  args=[${argSummary}]  out=${sizeKB}KB`
        );
      }
      return out;
    })
    .finally(() => { RUN_INFLIGHT.delete(key); });
  RUN_INFLIGHT.set(key, p);
  return p;
});

ipcMain.handle("ember:binary", async () => state.binary);

// Hex view: read a byte slice from the currently-loaded binary. Returns
// the bytes as a base64 string (Electron IPC serialises Uint8Array as
// a Buffer, which the renderer sees as an Object — base64 round-trips
// cleanly through structured clone). `eof` flags a short read so the
// renderer can stop scrolling.
ipcMain.handle("ember:readBytes", async (_e, offset, length) => {
  if (!state.binary) throw new Error("no binary selected");
  const off = Math.max(0, Math.floor(Number(offset) || 0));
  const len = Math.max(0, Math.min(0x100000, Math.floor(Number(length) || 0)));
  if (len === 0) return { base64: "", eof: false, totalSize: 0 };
  const fh = await fs.open(state.binary, "r");
  try {
    const stat = await fh.stat();
    const buf  = Buffer.alloc(len);
    const { bytesRead } = await fh.read(buf, 0, len, off);
    return {
      base64:    buf.subarray(0, bytesRead).toString("base64"),
      eof:       off + bytesRead >= stat.size,
      totalSize: stat.size,
    };
  } finally {
    await fh.close();
  }
});

// Translate a virtual address to a file offset by walking the ELF /
// Mach-O / PE headers directly. Cheap (one read of the first 4 KB) and
// avoids dragging another flag through the CLI surface.
const VADDR_MAP_CACHE = new Map();  // key (path|mtime) → [{vaddr, foff, size}, ...]

async function loadVaddrMap(binaryPath) {
  const mtime = await safeMtime(binaryPath);
  const key   = `${binaryPath}|${mtime}`;
  const hit   = VADDR_MAP_CACHE.get(key);
  if (hit) return hit;

  const out = [];
  let fh;
  try {
    fh = await fs.open(binaryPath, "r");
    const head = Buffer.alloc(4096);
    await fh.read(head, 0, head.length, 0);
    if (head[0] === 0x7f && head[1] === 0x45 && head[2] === 0x4c && head[3] === 0x46) {
      // ELF — parse the program header table.
      const is64   = head[4] === 2;
      const phoff  = is64 ? Number(head.readBigUInt64LE(0x20)) : head.readUInt32LE(0x1c);
      const phentsize = head.readUInt16LE(is64 ? 0x36 : 0x2a);
      const phnum     = head.readUInt16LE(is64 ? 0x38 : 0x2c);
      const phBuf = Buffer.alloc(phentsize * phnum);
      await fh.read(phBuf, 0, phBuf.length, phoff);
      for (let i = 0; i < phnum; i++) {
        const base = i * phentsize;
        const ptype = phBuf.readUInt32LE(base);
        if (ptype !== 1) continue;   // PT_LOAD
        const foff  = is64 ? Number(phBuf.readBigUInt64LE(base + 0x08)) : phBuf.readUInt32LE(base + 0x04);
        const vaddr = is64 ? Number(phBuf.readBigUInt64LE(base + 0x10)) : phBuf.readUInt32LE(base + 0x08);
        const fsz   = is64 ? Number(phBuf.readBigUInt64LE(base + 0x20)) : phBuf.readUInt32LE(base + 0x10);
        if (fsz > 0) out.push({ vaddr, foff, size: fsz });
      }
    } else if ((head[0] === 0xfe && head[1] === 0xed && head[2] === 0xfa) ||
               (head[0] === 0xcf && head[1] === 0xfa && head[2] === 0xed)) {
      // Mach-O (32 / 64). Walk LC_SEGMENT_64 / LC_SEGMENT load commands.
      const is64  = head[3] === 0xfe || head[3] === 0xcf || head[0] === 0xcf;
      const ncmds = head.readUInt32LE(0x10);
      let p = is64 ? 0x20 : 0x1c;
      for (let i = 0; i < ncmds && p + 8 <= head.length; i++) {
        const cmd  = head.readUInt32LE(p);
        const size = head.readUInt32LE(p + 4);
        if (cmd === 0x19 /* LC_SEGMENT_64 */) {
          const vmaddr   = Number(head.readBigUInt64LE(p + 24));
          const vmsize   = Number(head.readBigUInt64LE(p + 32));
          const fileoff  = Number(head.readBigUInt64LE(p + 40));
          if (vmsize > 0) out.push({ vaddr: vmaddr, foff: fileoff, size: vmsize });
        } else if (cmd === 0x01 /* LC_SEGMENT */) {
          const vmaddr   = head.readUInt32LE(p + 24);
          const vmsize   = head.readUInt32LE(p + 28);
          const fileoff  = head.readUInt32LE(p + 32);
          if (vmsize > 0) out.push({ vaddr: vmaddr, foff: fileoff, size: vmsize });
        }
        p += size;
        if (size === 0) break;
      }
    } else if (head[0] === 0x4d && head[1] === 0x5a) {
      // PE: header at e_lfanew. PE32+ section table follows the optional
      // header. We parse just the section table and use VirtualAddress +
      // PointerToRawData entries.
      const peOff = head.readUInt32LE(0x3c);
      if (peOff >= 0 && peOff + 24 < head.length &&
          head[peOff] === 0x50 && head[peOff + 1] === 0x45) {
        const numSections = head.readUInt16LE(peOff + 6);
        const optHdrSize  = head.readUInt16LE(peOff + 20);
        const imgBase = (() => {
          const ohOff = peOff + 24;
          if (head[ohOff] === 0x0b && head[ohOff + 1] === 0x02) {
            // PE32+ — ImageBase at offset 24 of optional header (8 bytes).
            return Number(head.readBigUInt64LE(ohOff + 24));
          }
          if (head[ohOff] === 0x0b && head[ohOff + 1] === 0x01) {
            return head.readUInt32LE(ohOff + 28);
          }
          return 0;
        })();
        const sectOff = peOff + 24 + optHdrSize;
        for (let i = 0; i < numSections; i++) {
          const o = sectOff + i * 40;
          if (o + 40 > head.length) break;
          const vsize  = head.readUInt32LE(o + 8);
          const vaddr  = head.readUInt32LE(o + 12) + imgBase;
          const foff   = head.readUInt32LE(o + 20);
          if (vsize > 0) out.push({ vaddr, foff, size: vsize });
        }
      }
    }
  } catch {
    // Header parse failed — fall through with empty mapping. Hex view
    // handles the empty case by refusing vaddr translation.
  } finally {
    try { await fh?.close(); } catch {}
  }
  VADDR_MAP_CACHE.set(key, out);
  return out;
}

ipcMain.handle("ember:vaddrToOffset", async (_e, vaddr) => {
  if (!state.binary) return null;
  const v = Number(vaddr);
  if (!Number.isFinite(v) || v < 0) return null;
  const map = await loadVaddrMap(state.binary);
  for (const s of map) {
    if (s.size > 0 && v >= s.vaddr && v < s.vaddr + s.size) {
      return s.foff + (v - s.vaddr);
    }
  }
  return null;
});

ipcMain.handle("ember:update:check", async () => {
  try {
    return await fetchLatestReleaseInfo();
  } catch (e) {
    return {
      ok: false,
      error: e?.message ?? String(e),
    };
  }
});

ipcMain.handle("ember:update:downloadAndInstall", async () => {
  try {
    const rel = await fetchLatestReleaseInfo();
    if (!rel.available) {
      return { ok: false, error: "no newer release available for this platform" };
    }
    if (!rel.assetUrl || !rel.assetName) {
      return { ok: false, error: "latest release has no matching downloadable asset" };
    }
    const outPath = path.join(app.getPath("downloads"), "Ember Updates", rel.assetName);
    await downloadFile(rel.assetUrl, outPath);
    const opened = await shell.openPath(outPath);
    return {
      ok: true,
      path: outPath,
      message: opened
        ? `Downloaded to ${outPath}. Open it manually if it did not launch: ${opened}`
        : `Downloaded and opened ${rel.assetName}.`,
    };
  } catch (e) {
    return { ok: false, error: e?.message ?? String(e) };
  }
});

const pluginHost = makePluginHost({
  app,
  runEmber,
  getCurrentBinary: () => state.binary,
  readAnnotations: readSidecar,
  saveAnnotations: saveSidecar,
});

ipcMain.handle("ember:plugins:list", async () => {
  return await pluginHost.listPlugins();
});

ipcMain.handle("ember:plugins:run", async (_e, pluginId, commandId, opts) => {
  return await pluginHost.runCommand(pluginId, commandId, opts || {});
});

ipcMain.handle("ember:plugins:match", async (_e, pluginId) => {
  return await pluginHost.matchPlugin(pluginId);
});

// ----- Annotations sidecar -----

// Save patches applied to a user-chosen output path. Prompts a save
// dialog, then re-runs the patcher with that destination — same code
// path as the temp materialisation, so format / translation logic
// can't drift between the two flows.
ipcMain.handle("ember:savePatchedAs", async () => {
  if (!state.binary) throw new Error("no binary selected");
  const ann = await readSidecar(state.binary);
  const patches = ann.patches || {};
  if (Object.keys(patches).length === 0) {
    throw new Error("no patches to save");
  }
  const defaultName = path.basename(state.binary) + ".patched";
  const r = await dialog.showSaveDialog({
    title: "Save patched binary",
    defaultPath: defaultName,
    properties: ["createDirectory"],
  });
  if (r.canceled || !r.filePath) return null;

  const patchesFile = path.join(app.getPath("userData"), "projects",
                                sanitize(state.binary) + ".patches.txt");
  const lines = Object.entries(patches).map(([addr, p]) => {
    const grouped = (p.bytes.match(/.{1,2}/g) || []).join(" ");
    return `${addr} ${grouped}`;
  });
  await fs.mkdir(path.dirname(patchesFile), { recursive: true });
  await fs.writeFile(patchesFile, lines.join("\n") + "\n", "utf8");
  await runEmber(["--apply-patches", patchesFile, "-o", r.filePath, state.binary]);
  return r.filePath;
});

ipcMain.handle("ember:loadAnnotations", async (_e, bp) => {
  // readSidecar already merges the JSON sidecar with the ember cache
  // annotations.db, so agent-applied renames flow through to the UI
  // automatically. Returning its result keeps both paths in sync.
  return readSidecar(bp);
});

ipcMain.handle("ember:saveAnnotations", async (_e, bp, data) => {
  await saveSidecar(bp, data);
  return true;
});

// Apply a declarative .ember script. Two modes selected by `dryRun`:
//
//   dryRun=true  → spawn `ember --apply <script> --dry-run`. The CLI
//                  prints the would-be annotations file to stdout. We
//                  return that text verbatim for the renderer to show
//                  as a preview. Sidecar is untouched.
//
//   dryRun=false → spawn `ember --apply <script>` for real. The CLI
//                  writes the merged annotations to the temp .ann file
//                  the run handler stages from the sidecar. We then
//                  read that file, parse it back, merge into the
//                  sidecar (preserving patches + localRenames which
//                  don't live in the .ann), save, and return the
//                  full updated Annotations to the renderer.
//
// Doing the apply inside one IPC call avoids a race where a concurrent
// `ember:run` would clobber the post-apply temp .ann before we read it.
ipcMain.handle("ember:applyEmberScript", async (_e, scriptPath, dryRun) => {
  if (!state.binary) throw new Error("no binary selected");
  if (typeof scriptPath !== "string" || !scriptPath) {
    throw new Error("scriptPath required");
  }
  const annPath  = await writeCliAnnotations(state.binary);
  const effective = await materializePatchedBinary(state.binary);
  const args = ["--apply", scriptPath];
  if (dryRun) args.push("--dry-run");
  if (annPath) args.push("--annotations", annPath);
  args.push(effective);

  const stdout = await runEmber(args);

  if (dryRun) {
    return { dryRun: true, preview: stdout, annotations: null };
  }

  // The CLI wrote the merged annotations to annPath (or to its own
  // resolved destination if annPath was null). If the temp .ann is
  // missing — script was a no-op against an empty sidecar — fall back
  // to whatever's already in the sidecar.
  let merged = null;
  if (annPath) {
    try {
      const text = await fs.readFile(annPath, "utf8");
      merged = parseAnnText(text);
    } catch { /* ann file vanished; treat as no-op */ }
  }

  // Read the sidecar last (after the apply) so any concurrent UI
  // edits in the meantime aren't silently overwritten.
  let sidecar = {};
  try {
    sidecar = JSON.parse(await fs.readFile(sidecarPath(state.binary), "utf8"));
  } catch { /* fresh sidecar */ }

  const next = {
    renames:      merged?.renames    ?? sidecar.renames    ?? {},
    signatures:   merged?.signatures ?? sidecar.signatures ?? {},
    notes:        merged?.notes      ?? sidecar.notes      ?? {},
    fields:       merged?.fields     ?? sidecar.fields     ?? {},
    // localRenames + patches never live in the .ann — preserve sidecar.
    localRenames: sidecar.localRenames || {},
    patches:      sidecar.patches      || {},
  };
  await saveSidecar(state.binary, next);
  return { dryRun: false, preview: null, annotations: next };
});

// Export the caller's in-memory annotations object to a user-chosen file.
// We accept the object directly (rather than re-reading the sidecar) so
// unsaved edits are captured. The file format is just the raw Annotations
// JSON — importing on another machine feeds this back into saveAnnotations.
ipcMain.handle("ember:exportAnnotations", async (_e, bp, data) => {
  const defaultName = (bp ? path.basename(bp) : "annotations") + ".ember.json";
  const r = await dialog.showSaveDialog({
    title: "Export annotations",
    defaultPath: defaultName,
    filters: [{ name: "Ember annotations", extensions: ["json"] }],
    properties: ["createDirectory", "showOverwriteConfirmation"],
  });
  if (r.canceled || !r.filePath) return null;
  const out = {
    // Small self-describing header so a human opening the file can tell
    // what it belongs to; ember version is advisory, we don't gate on it.
    ember: { version: 1, exported_for: bp ? path.basename(bp) : null },
    renames:      data?.renames      || {},
    notes:        data?.notes        || {},
    signatures:   data?.signatures   || {},
    fields:       data?.fields       || {},
    localRenames: data?.localRenames || {},
    patches:      data?.patches      || {},
  };
  await fs.writeFile(r.filePath, JSON.stringify(out, null, 2), "utf8");
  return r.filePath;
});

// Pick a file and return its parsed annotations payload. The renderer
// decides the merge strategy (replace vs merge) so this stays a dumb
// reader. Unknown fields pass through; missing fields default to empty.
ipcMain.handle("ember:importAnnotations", async () => {
  const r = await dialog.showOpenDialog({
    title: "Import annotations",
    filters: [
      { name: "Ember annotations", extensions: ["json", "ember", "ann", "db"] },
      { name: "All files", extensions: ["*"] },
    ],
    properties: ["openFile"],
  });
  if (r.canceled || r.filePaths.length === 0) return null;
  const raw = await fs.readFile(r.filePaths[0], "utf8");
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    parsed = parseAnnText(raw);
  }
  return {
    path:         r.filePaths[0],
    renames:      parsed.renames      || {},
    notes:        parsed.notes        || {},
    signatures:   parsed.signatures   || {},
    fields:       parsed.fields       || {},
    localRenames: parsed.localRenames || {},
    patches:      parsed.patches      || {},
  };
});

// Pick one or more TEEF corpus TSVs, run recognition against the current
// binary, and merge high-confidence suggestions into the same sidecar
// used by the manual "import renames" flow.
ipcMain.handle("ember:importCorpusRenames", async (_e, opts) => {
  if (!state.binary) throw new Error("no binary selected");
  const o = opts && typeof opts === "object" ? opts : {};
  const threshold = Number.isFinite(Number(o.threshold)) ? Number(o.threshold) : 0.85;
  const minFnSize = Number.isFinite(Number(o.minFnSize)) ? Math.max(0, Math.floor(Number(o.minFnSize))) : 32;
  const maxFnSize = Number.isFinite(Number(o.maxFnSize)) ? Math.max(0, Math.floor(Number(o.maxFnSize))) : 200000;
  const l0Prefilter = o.l0Prefilter !== false;

  const picked = await dialog.showOpenDialog({
    title: "Import renames from TEEF corpus",
    defaultPath: defaultCorpusPath(),
    filters: [
      { name: "TEEF corpora", extensions: ["teef", "tsv"] },
      { name: "All files", extensions: ["*"] },
    ],
    properties: ["openFile", "multiSelections"],
  });
  if (picked.canceled || picked.filePaths.length === 0) return null;

  const annPath = await writeCliAnnotations(state.binary);
  const effective = await materializePatchedBinary(state.binary);
  const args = ["--quiet", "--recognize"];
  if (l0Prefilter) args.push("--l0-prefilter");
  if (minFnSize > 0) args.push("--min-fn-size", String(minFnSize));
  if (maxFnSize > 0) args.push("--max-fn-size", String(maxFnSize));
  args.push("--recognize-threshold", String(threshold));
  for (const p of picked.filePaths) args.push("--corpus", p);
  if (annPath) args.push("--annotations", annPath);
  args.push(effective);

  const stdout = await runEmber(args);
  const parsed = parseRecognizeRenames(stdout, threshold);

  const sidecar = await readSidecar(state.binary);
  const next = {
    renames:      { ...(sidecar.renames || {}), ...parsed.renames },
    notes:        sidecar.notes || {},
    signatures:   sidecar.signatures || {},
    fields:       sidecar.fields || {},
    localRenames: sidecar.localRenames || {},
    patches:      sidecar.patches || {},
  };
  await saveSidecar(state.binary, next);

  return {
    annotations: next,
    imported: Object.keys(parsed.renames).length,
    scanned: parsed.scanned,
    corpusPaths: picked.filePaths,
  };
});

// Run YARA-like function identification (--identify) and return parsed
// results. No file picker needed — the built-in profile DB is always
// available.
ipcMain.handle("ember:identify", async (_e, opts) => {
  if (!state.binary) throw new Error("no binary selected");
  const o = opts && typeof opts === "object" ? opts : {};
  const threshold = Number.isFinite(Number(o.threshold)) ? Number(o.threshold) : 0.4;
  const effective = await materializePatchedBinary(state.binary);
  const args = ["--quiet", "--identify"];
  if (threshold !== 0.4) args.push("--identify-threshold", String(threshold));
  args.push(effective);
  const stdout = await runEmber(args);
  // Parse TSV: addr\tname\tcategory\tconfidence\tsignal\tvia
  const hits = [];
  for (const line of String(stdout || "").split("\n")) {
    if (!line.trim()) continue;
    const parts = line.split("\t");
    if (parts.length < 4) continue;
    hits.push({
      addr: parts[0],
      addrNum: parseInt(parts[0], 16),
      name: parts[1],
      category: parts[2],
      confidence: parseFloat(parts[3]) || 0,
      signal: parts[4] || "",
      via: parts[5] || "",
    });
  }
  return hits;
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
  const annPath   = await writeCliAnnotations(state.binary);
  const effective = await materializePatchedBinary(state.binary);
  return makeTools(() => ({
    emberBin:   EMBER_BIN,
    binaryPath: effective,
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
  for (let iter = 0; ; iter++) {
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

// ----- Discord Rich Presence ---------------------------------------------
//
// Pushes the user's current activity (binary + function + view) to a
// running Discord client. Off by default — privacy-first: opening a
// reverse-engineering tool against a binary leaks the binary's name to
// every Discord friend, which most users don't want by default.
//
// The renderer is the source of truth for what to display. It calls
// `ember.discord.setActivity(payload | null)`; this main-process side
// owns the RPC connection. Discord-not-running, no-client-id, and
// disconnect are all silent — we never surface a "couldn't push to
// Discord" error to the user. Failing to update presence is benign.
//
// To enable for distribution: register an Ember application on the
// Discord Developer Portal, paste the Client ID into DISCORD_CLIENT_ID
// below, and upload these asset names under Rich Presence → Art Assets:
//   ember_logo, view_pseudo, view_asm, view_cfg, view_ir, view_ssa
const DISCORD_CLIENT_ID = process.env.EMBER_DISCORD_CLIENT_ID || "1497960478855528458";

let discordClient = null;       // current Client instance, null when disconnected
let discordReady   = false;     // true once login() resolves
let discordLoginP  = null;      // in-flight login promise (deduped)
let discordLastActivity = null; // last successful payload, replayed on reconnect

function discordIsConfigured() {
  return DISCORD_CLIENT_ID && DISCORD_CLIENT_ID.length > 0;
}

async function discordEnsureConnected() {
  if (!discordIsConfigured()) return null;
  if (discordReady && discordClient) return discordClient;
  if (discordLoginP) return discordLoginP;

  discordLoginP = (async () => {
    try {
      const { Client } = require("@xhayper/discord-rpc");
      const c = new Client({ clientId: DISCORD_CLIENT_ID, transport: { type: "ipc" } });
      c.on("disconnected", () => {
        console.log("[discord] disconnected");
        discordReady = false;
      });
      console.log(`[discord] connecting (clientId=${DISCORD_CLIENT_ID})`);
      await c.login();
      console.log(`[discord] connected as ${c.user?.username || "?"}`);
      discordClient = c;
      discordReady  = true;
      if (discordLastActivity) {
        try {
          await c.user?.setActivity(discordLastActivity);
          console.log("[discord] replayed queued activity");
        } catch (e) {
          console.log(`[discord] replay failed: ${e?.message || e}`);
        }
      }
      return c;
    } catch (e) {
      console.log(`[discord] login failed: ${e?.message || e}`);
      discordReady = false;
      discordClient = null;
      return null;
    } finally {
      discordLoginP = null;
    }
  })();
  return discordLoginP;
}

// Discord enforces 2..128 char range on details/state and silently
// drops the activity if a string is too short or too long. Pad short
// values with a space so a single-char function name still works.
function discordClampString(s) {
  if (typeof s !== "string") return undefined;
  let t = s.trim();
  if (t.length === 0) return undefined;
  if (t.length === 1) t += " ";
  if (t.length > 128)  t = t.slice(0, 125) + "…";
  return t;
}

function discordSanitizeButtons(buttons) {
  if (!Array.isArray(buttons)) return undefined;
  const out = [];
  for (const b of buttons) {
    if (!b || typeof b.label !== "string" || typeof b.url !== "string") continue;
    if (!/^https?:\/\//i.test(b.url)) continue;
    let label = b.label.trim();
    if (label.length === 0) continue;
    if (label.length > 32) label = label.slice(0, 31) + "…";
    let url = b.url.trim();
    if (url.length > 512) continue;
    out.push({ label, url });
    if (out.length === 2) break;
  }
  return out.length ? out : undefined;
}

ipcMain.handle("ember:discord:setActivity", async (_e, payload) => {
  if (!discordIsConfigured()) {
    console.log("[discord] setActivity called but no client id configured");
    return false;
  }
  if (!payload) {
    console.log("[discord] clearing activity");
    discordLastActivity = null;
    if (discordReady && discordClient?.user) {
      try { await discordClient.user.clearActivity(); } catch (e) {
        console.log(`[discord] clear failed: ${e?.message || e}`);
      }
    }
    return true;
  }
  const activity = {
    // Default activity type (0 = "Playing"). We tried type 3 ("Watching")
    // for nicer wording, but Discord silently strips buttons and hides
    // the activity from the lower-left status strip for non-Playing
    // types. "Playing ember" is mildly off but the only type that gets
    // the full feature set.
    details:           discordClampString(payload.details),
    state:             discordClampString(payload.state),
    startTimestamp:    typeof payload.startTimestamp === "number" ? payload.startTimestamp : undefined,
    largeImageKey:     payload.largeImageKey,
    largeImageText:    discordClampString(payload.largeImageText),
    smallImageKey:     payload.smallImageKey,
    smallImageText:    discordClampString(payload.smallImageText),
    buttons:           discordSanitizeButtons(payload.buttons),
    // 0=NAME / 1=STATE / 2=DETAILS — picks which field drives the
    // inline mini-status under the user's name. xhayper maps this
    // straight to Discord's `status_display_type`.
    statusDisplayType: typeof payload.statusDisplayType === "number" ? payload.statusDisplayType : undefined,
    instance:          false,
  };
  discordLastActivity = activity;
  const c = await discordEnsureConnected();
  if (!c || !c.user) {
    console.log("[discord] setActivity: not connected, payload queued");
    return false;
  }
  try {
    await c.user.setActivity(activity);
    console.log(`[discord] activity pushed: ${activity.details} | ${activity.state}`);
    return true;
  } catch (e) {
    console.log(`[discord] setActivity failed: ${e?.message || e}`);
    discordReady = false;
    return false;
  }
});

// ---------------------------------------------------------------- agent
//
// Read-side IPC surface for the ember-agent harness. The harness is a
// sibling process (`agent/dist/main.js`); we never link against it.
// The renderer reads:
//   intel.jsonl  per-binary, append-only — the materialized fold view
//   events.jsonl per-run — turn-by-turn worker activity
// Locations match the layout that agent/src/intel/log.ts and
// agent/src/worker.ts write to: ~/.cache/ember/<binary-key>/intel.jsonl
// and ~/.cache/ember/agent/runs/r-XXXXXX/events.jsonl.

const crypto = require("node:crypto");

function intelPathFor(binaryPath) {
  // Mirrors agent/src/intel/log.ts intelPathFor: SHA-256 over
  // "<abspath>|<size>|<floor(mtimeMs)>|v1", first 16 hex chars.
  const stat = require("node:fs").statSync(binaryPath);
  const key = crypto.createHash("sha256")
    .update(binaryPath)
    .update("|")
    .update(String(stat.size))
    .update("|")
    .update(String(Math.floor(stat.mtimeMs)))
    .update("|v1")
    .digest("hex")
    .slice(0, 16);
  const root = process.env.XDG_CACHE_HOME
    ? path.join(process.env.XDG_CACHE_HOME, "ember")
    : path.join(require("node:os").homedir(), ".cache", "ember");
  return path.join(root, key, "intel.jsonl");
}

function runsRoot() {
  const cache = process.env.XDG_CACHE_HOME ?? path.join(require("node:os").homedir(), ".cache");
  return path.join(cache, "ember", "agent", "runs");
}

function readJsonl(p) {
  let raw = "";
  try { raw = require("node:fs").readFileSync(p, "utf8"); } catch { return []; }
  const out = [];
  for (const line of raw.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    try { out.push(JSON.parse(t)); } catch { /* skip corrupt */ }
  }
  return out;
}

// Fold the intel log. Mirrors agent/src/intel/log.ts but kept here so
// the renderer doesn't need to spawn ember-agent for every refresh.
function foldIntel(entries) {
  const retracted = new Set();
  for (const e of entries) if (e.kind === "retract") retracted.add(e.target_id);
  const buckets = new Map();
  for (const e of entries) {
    if (e.kind !== "claim") continue;
    if (retracted.has(e.id)) continue;
    const k = `${e.subject}|${e.predicate}`;
    const arr = buckets.get(k);
    if (arr) arr.push(e); else buckets.set(k, [e]);
  }
  const view = [];
  for (const [k, arr] of buckets) {
    arr.sort((a, b) => {
      if (b.confidence !== a.confidence) return b.confidence - a.confidence;
      return String(b.ts).localeCompare(String(a.ts));
    });
    const [winner, ...runners_up] = arr;
    const second = runners_up[0];
    const disputed = !!second
      && winner.confidence - second.confidence < 0.10
      && winner.agent !== second.agent
      && winner.value !== second.value;
    view.push({ key: k, winner, runners_up, disputed });
  }
  return view;
}

ipcMain.handle("agent:intelView", async (_e, binaryPath) => {
  if (!binaryPath) return { entries: [], view: [] };
  const p = intelPathFor(binaryPath);
  const entries = readJsonl(p);
  const view = foldIntel(entries);
  return { path: p, entries, view };
});

ipcMain.handle("agent:listRuns", async () => {
  const root = runsRoot();
  let dirs = [];
  try { dirs = require("node:fs").readdirSync(root); } catch { return []; }
  const out = [];
  for (const d of dirs) {
    if (!d.startsWith("r-")) continue;
    const ev = path.join(root, d, "events.jsonl");
    let mtime = 0, turns = 0, kind = "?", role = "?", model = "?", scope = "?", usd = 0;
    let claimsFiled = 0, forced = false, binary = "";
    try {
      mtime = require("node:fs").statSync(ev).mtimeMs;
      const events = readJsonl(ev);
      for (const e of events) {
        if (e.kind === "start") {
          role = e.role ?? role;
          model = e.model ?? model;
          scope = e.scope ?? scope;
          if (e.binary) binary = e.binary;   // attached to runs ≥1.0.2
        }
        if (e.kind === "turn") ++turns;
        if (e.tally?.usd != null) usd = e.tally.usd;
        if (e.kind === "tool_ok" && e.name === "intel_claim") ++claimsFiled;
        if (e.kind === "force_claim") forced = true;
        kind = e.kind;
      }
    } catch { continue; }
    out.push({ id: d, last: kind, turns, role, model, scope, usd, mtime, claimsFiled, forced, binary });
  }
  out.sort((a, b) => b.mtime - a.mtime);
  return out;
});

ipcMain.handle("agent:tailRun", async (_e, runId) => {
  if (!runId || !/^r-[\w-]+$/.test(runId)) return [];
  const ev = path.join(runsRoot(), runId, "events.jsonl");
  return readJsonl(ev);
});

// Fanout / promote. Spawn the agent CLI; capture stdout for the JSON
// reply. Detached fanout returns immediately by design.
// Locating the agent CLI + a usable Node.
//
// process.execPath in a packaged Electron app is Ember.exe — useless
// for running a node script. We need a real Node 22+. Resolution
// order: env override → 'node' on PATH → fail with a clear setup
// hint. Bundling node would add ~50MB to the installer; we prefer
// the smaller download and require Node as a soft prerequisite for
// agent features.
function findNode() {
  if (process.env.EMBER_AGENT_NODE) return process.env.EMBER_AGENT_NODE;
  if (!app.isPackaged) return process.execPath;   // dev mode: parent IS node
  return process.platform === "win32" ? "node.exe" : "node";
}

function findAgentEntry() {
  if (app.isPackaged) {
    return path.join(process.resourcesPath, "agent", "dist", "main.js");
  }
  return path.join(__dirname, "..", "..", "agent", "dist", "main.js");
}

ipcMain.handle("agent:fanout", async (_e, opts) => {
  const node = findNode();
  const agent = findAgentEntry();
  return new Promise((resolve, reject) => {
    const args = [agent, "fanout"];
    if (opts.binary)   args.push(`--binary=${opts.binary}`);
    if (opts.role)     args.push(`--role=${opts.role}`);
    if (opts.pick)     args.push(`--pick=${opts.pick}`);
    if (opts.limit)    args.push(`--limit=${opts.limit}`);
    if (opts.minSize)  args.push(`--min-size=${opts.minSize}`);
    if (opts.budget)   args.push(`--budget=${opts.budget}`);
    if (opts.maxTurns) args.push(`--max-turns=${opts.maxTurns}`);
    if (opts.model)    args.push(`--model=${opts.model}`);
    const proc = spawn(node, args, { cwd: path.dirname(agent), env: process.env });
    let out = "", err = "";
    proc.stdout.on("data", (b) => { out += b.toString(); });
    proc.stderr.on("data", (b) => { err += b.toString(); });
    proc.on("close", (code) => {
      if (code !== 0) return reject(new Error(err.trim() || `exit ${code}`));
      try { resolve(JSON.parse(out)); } catch { resolve({ raw: out }); }
    });
    proc.on("error", (e) => {
      if (e && e.code === "ENOENT") {
        reject(new Error(`Node.js not found. Install Node 22+ and ensure 'node' is on PATH, or set EMBER_AGENT_NODE to its absolute path. (looked up: ${node})`));
      } else { reject(e); }
    });
  });
});

ipcMain.handle("agent:promote", async (_e, opts) => {
  const node = findNode();
  const agent = findAgentEntry();
  return new Promise((resolve, reject) => {
    const args = [agent, "promote", opts.binary];
    if (opts.threshold) args.push(`--threshold=${opts.threshold}`);
    if (opts.apply)     args.push("--apply");
    if (opts.dryRun)    args.push("--dry-run");
    const proc = spawn(node, args, { cwd: path.dirname(agent), env: process.env });
    let out = "", err = "";
    proc.stdout.on("data", (b) => { out += b.toString(); });
    proc.stderr.on("data", (b) => { err += b.toString(); });
    proc.on("close", (code) => {
      if (code !== 0) return reject(new Error(err.trim() || `exit ${code}`));
      try { resolve(JSON.parse(out)); } catch { resolve({ raw: out }); }
    });
    proc.on("error", (e) => {
      if (e && e.code === "ENOENT") {
        reject(new Error(`Node.js not found. Install Node 22+ and ensure 'node' is on PATH, or set EMBER_AGENT_NODE to its absolute path. (looked up: ${node})`));
      } else { reject(e); }
    });
  });
});

// Agent config — read/write of ~/.config/ember/agent.toml plus a
// runtime defaults JSON sibling (agent.defaults.json) for per-role
// model + budget choices that aren't sensitive.
function agentConfigPath() {
  const home = require("node:os").homedir();
  return path.join(home, ".config", "ember", "agent.toml");
}
function agentDefaultsPath() {
  const home = require("node:os").homedir();
  return path.join(home, ".config", "ember", "agent.defaults.json");
}

function parseAgentToml(raw) {
  // Returns arrays per provider — single-key 'key = "X"' form is
  // accepted as a 1-element list; 'keys = ["A","B"]' as full list.
  const out = { assistant: [], openai: [], openrouter: [] };
  let section = "";
  const push = (s, v) => {
    if (!v) return;
    if (s === "assistant"  && !out.assistant.includes(v))  out.assistant.push(v);
    if (s === "openai"     && !out.openai.includes(v))     out.openai.push(v);
    if (s === "openrouter" && !out.openrouter.includes(v)) out.openrouter.push(v);
  };
  for (const line of raw.split("\n")) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const m = /^\[(\w+)\]$/.exec(t);
    if (m) { section = m[1]; continue; }
    const arr = /^keys\s*=\s*\[(.+)\]\s*$/.exec(t);
    if (arr) {
      const matches = arr[1].matchAll(/"([^"]*)"/g);
      for (const m2 of matches) push(section, m2[1]);
      continue;
    }
    const kv = /^(\w+)\s*=\s*"([^"]*)"$/.exec(t);
    if (kv && kv[1] === "key") push(section, kv[2]);
  }
  return out;
}

function emitAgentToml(cfg) {
  // Single-key uses 'key =' for back-compat; multi-key uses 'keys ='.
  const sect = (name, arr) => {
    if (!arr || arr.length === 0) return "";
    if (arr.length === 1) return `[${name}]\nkey = "${arr[0]}"\n`;
    const list = arr.map((k) => `"${k}"`).join(", ");
    return `[${name}]\nkeys = [${list}]\n`;
  };
  return [sect("assistant", cfg.assistant), sect("openai", cfg.openai), sect("openrouter", cfg.openrouter)]
    .filter(Boolean).join("\n");
}

ipcMain.handle("agent:getConfig", async () => {
  let cfg = { assistant: [], openai: [], openrouter: [] };
  try {
    const raw = require("node:fs").readFileSync(agentConfigPath(), "utf8");
    cfg = parseAgentToml(raw);
  } catch { /* no file yet */ }
  let defaults = {};
  try {
    defaults = JSON.parse(require("node:fs").readFileSync(agentDefaultsPath(), "utf8"));
  } catch { /* no defaults yet */ }
  // Mask keys to a head/tail snippet so the renderer can show
  // "sk-or-…xyz9" per key without ever holding the full secret.
  const mask = (s) => s ? s.slice(0, 6) + "…" + s.slice(-4) : "";
  return {
    masked: {
      assistant:  cfg.assistant.map(mask),
      openai:     cfg.openai.map(mask),
      openrouter: cfg.openrouter.map(mask),
    },
    counts: {
      assistant:  cfg.assistant.length,
      openai:     cfg.openai.length,
      openrouter: cfg.openrouter.length,
    },
    defaults,
    path: agentConfigPath(),
  };
});

ipcMain.handle("agent:setConfig", async (_e, patch) => {
  const fs = require("node:fs");
  const cfgPath = agentConfigPath();
  let cur = { assistant: [], openai: [], openrouter: [] };
  try { cur = parseAgentToml(fs.readFileSync(cfgPath, "utf8")); } catch {}
  const next = { assistant: [...cur.assistant], openai: [...cur.openai], openrouter: [...cur.openrouter] };
  // patch.keys per provider: array → replace whole list; null → clear.
  // (Old shape: string → wrapped to single-element list. Empty string
  // → leave as-is. Preserves earlier UI flow.)
  if (patch.keys) {
    const append = patch.keysMode === "append";
    for (const k of ["assistant", "openai", "openrouter"]) {
      const v = patch.keys[k];
      if (v === undefined) continue;       // leave as-is
      if (v === null) { next[k] = []; continue; }   // explicit clear
      const cleaned = Array.isArray(v)
        ? v.filter((s) => typeof s === "string" && s.trim().length > 0)
        : (typeof v === "string" && v !== "" ? [v] : []);
      if (append) {
        for (const s of cleaned) if (!next[k].includes(s)) next[k].push(s);
      } else {
        next[k] = cleaned;
      }
    }
    fs.mkdirSync(path.dirname(cfgPath), { recursive: true });
    fs.writeFileSync(cfgPath, emitAgentToml(next), { mode: 0o600 });
  }
  if (patch.defaults) {
    const dpath = agentDefaultsPath();
    let cur2 = {};
    try { cur2 = JSON.parse(fs.readFileSync(dpath, "utf8")); } catch {}
    fs.mkdirSync(path.dirname(dpath), { recursive: true });
    fs.writeFileSync(dpath, JSON.stringify({ ...cur2, ...patch.defaults }, null, 2));
  }
  return { ok: true };
});

ipcMain.handle("agent:tiebreak", async (_e, opts) => {
  const node = findNode();
  const agent = findAgentEntry();
  return new Promise((resolve, reject) => {
    const args = [agent, "tiebreak", `--binary=${opts.binary}`];
    if (opts.limit)    args.push(`--limit=${opts.limit}`);
    if (opts.budget)   args.push(`--budget=${opts.budget}`);
    if (opts.maxTurns) args.push(`--max-turns=${opts.maxTurns}`);
    if (opts.model)    args.push(`--model=${opts.model}`);
    const proc = spawn(node, args, { cwd: path.dirname(agent), env: process.env });
    let out = "", err = "";
    proc.stdout.on("data", (b) => { out += b.toString(); });
    proc.stderr.on("data", (b) => { err += b.toString(); });
    proc.on("close", (code) => {
      if (code !== 0) return reject(new Error(err.trim() || `exit ${code}`));
      try { resolve(JSON.parse(out)); } catch { resolve({ raw: out, stderr: err }); }
    });
    proc.on("error", (e) => {
      if (e && e.code === "ENOENT") {
        reject(new Error(`Node.js not found. Install Node 22+ and ensure 'node' is on PATH, or set EMBER_AGENT_NODE to its absolute path. (looked up: ${node})`));
      } else { reject(e); }
    });
  });
});

ipcMain.handle("agent:cascade", async (_e, opts) => {
  const node = findNode();
  const agent = findAgentEntry();
  return new Promise((resolve, reject) => {
    const args = [agent, "cascade", `--binary=${opts.binary}`];
    if (opts.role)             args.push(`--role=${opts.role}`);
    if (opts.perRound)         args.push(`--per-round=${opts.perRound}`);
    if (opts.maxRounds)        args.push(`--max-rounds=${opts.maxRounds}`);
    if (opts.budget)           args.push(`--budget=${opts.budget}`);
    if (opts.threshold)        args.push(`--threshold=${opts.threshold}`);
    if (opts.eligibilityRatio) args.push(`--eligibility-ratio=${opts.eligibilityRatio}`);
    if (opts.model)            args.push(`--model=${opts.model}`);
    if (Array.isArray(opts.models) && opts.models.length > 0) {
      args.push(`--models=${opts.models.join(",")}`);
    }
    const proc = spawn(node, args, { cwd: path.dirname(agent), env: process.env });
    let out = "", err = "";
    proc.stdout.on("data", (b) => { out += b.toString(); });
    proc.stderr.on("data", (b) => { err += b.toString(); });
    proc.on("close", (code) => {
      if (code !== 0) return reject(new Error(err.trim() || `exit ${code}`));
      try { resolve(JSON.parse(out)); } catch { resolve({ raw: out, stderr: err }); }
    });
    proc.on("error", (e) => {
      if (e && e.code === "ENOENT") {
        reject(new Error(`Node.js not found. Install Node 22+ and ensure 'node' is on PATH, or set EMBER_AGENT_NODE to its absolute path. (looked up: ${node})`));
      } else { reject(e); }
    });
  });
});

// ---------------------------------------------------------------- end agent

app.on("before-quit", async () => {
  // Best-effort clear so the user's profile doesn't show "viewing X"
  // after the app has quit. Both calls return Promises — a sync try/catch
  // wouldn't trap CONNECTION_ENDED when Discord has already dropped the
  // socket, which surfaces as an UnhandledPromiseRejectionWarning during
  // shutdown. Swallow async rejections too.
  try { Promise.resolve(discordClient?.user?.clearActivity?.()).catch(() => {}); } catch {}
  try { Promise.resolve(discordClient?.destroy?.()).catch(() => {}); } catch {}
});

// -------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CLI / second-instance binary forwarding
//
// `ember-ui /path/to/binary` (or `npm run dev -- /path/to/binary` in dev)
// loads that binary on startup. If the UI is already running, the second
// invocation forwards the path to the existing window via single-instance
// lock — no second window opens, the live session just switches binaries.
//
// Path is taken from the first non-flag positional that exists on disk.
// Electron-internal argv (--type=, --user-data-dir=, ...) and dev-only
// flags pass through untouched.
function pickBinaryFromArgv(argv) {
  for (const a of argv.slice(1)) {
    if (!a || a.startsWith("-")) continue;
    try {
      // Electron passes its own script path as argv[1] in dev runs (a JS
      // file, not the binary the user wants to RE). Filter those out by
      // checking the file extension is not source.
      if (/\.(js|cjs|mjs|ts|tsx|json)$/i.test(a)) continue;
      const st = require("fs").statSync(a);
      if (st.isFile()) return path.resolve(a);
    } catch { /* not an existing file — skip */ }
  }
  return null;
}

const initialBinary = pickBinaryFromArgv(process.argv);

function pushBinaryToRenderer(target) {
  // Mirrors what `ember:setBinary` IPC does on the main side; the
  // renderer listens for `ember:open-binary` and runs its own load
  // pipeline (info fetch, recents push, panels reset). Exposed via
  // preload as `electronAPI.onOpenBinary`.
  state.binary = target;
  void addRecent(target);
  for (const win of BrowserWindow.getAllWindows()) {
    win.webContents.send("ember:open-binary", target);
  }
}

const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  // Another instance already holds the lock; it'll receive our argv via
  // `second-instance`, switch its window, and we're done here.
  app.quit();
} else {
  app.on("second-instance", (_e, argv) => {
    const target = pickBinaryFromArgv(argv);
    const wins = BrowserWindow.getAllWindows();
    if (wins.length > 0) {
      const win = wins[0];
      if (win.isMinimized()) win.restore();
      win.focus();
      if (target) pushBinaryToRenderer(target);
    }
  });

  app.whenReady().then(() => {
    createWindow();
    if (initialBinary) {
      // Wait for the renderer's first paint before pushing — without
      // this the IPC fires before the listener is wired and gets dropped.
      const wins = BrowserWindow.getAllWindows();
      if (wins.length > 0) {
        wins[0].webContents.once("did-finish-load",
          () => pushBinaryToRenderer(initialBinary));
      }
    }
    app.on("activate", () => {
      if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
  });
}

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
