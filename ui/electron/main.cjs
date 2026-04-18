const { app, BrowserWindow, dialog, ipcMain } = require("electron");
const { spawn } = require("node:child_process");
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
  const extra = annPath ? ["--annotations", annPath] : [];
  return runEmber([...args, ...extra, state.binary]);
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
