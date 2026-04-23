const fs = require("node:fs/promises");
const path = require("node:path");

const KNOWN_PERMISSIONS = new Set([
  "read.binary-summary",
  "read.strings",
  "read.annotations",
  "project.rename",
  "project.note",
]);

function parseSummary(raw, binaryPath) {
  const lines = raw.split("\n");
  const info = {
    path: binaryPath,
    format: "",
    arch: "",
    endian: "",
    entry: "",
    sections: [],
    functions: [],
    imports: [],
  };

  for (const l of lines) {
    const m = /^(file|format|arch|endian|entry)\s+(.+)$/.exec(l.trim());
    if (!m) continue;
    if (m[1] === "format") info.format = m[2];
    else if (m[1] === "arch") info.arch = m[2];
    else if (m[1] === "endian") info.endian = m[2];
    else if (m[1] === "entry") info.entry = m[2];
  }

  let mode = "none";
  for (const rawLine of lines) {
    const line = rawLine.replace(/\r$/, "");
    if (/^sections\s+\(\d+\)/.test(line)) { mode = "sections"; continue; }
    if (/^defined symbols\s+\(\d+\)/.test(line)) { mode = "defined"; continue; }
    if (/^imports\s+\(\d+\)/.test(line)) { mode = "imports"; continue; }
    if (/^(file|format|arch|endian|entry)/.test(line.trim())) { mode = "none"; continue; }
    if (!line.trim()) continue;

    if (mode === "sections") {
      const m = /^\s*(\d+)\s+(\S+)?\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(\S+)/.exec(line);
      if (m && m[2]) info.sections.push({ name: m[2], vaddr: m[3], size: m[4], flags: m[5] });
      continue;
    }
    if (mode === "defined") {
      const m = /^\s*(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(\S+)\s+(.+)$/.exec(line);
      if (!m) continue;
      info.functions.push({
        addr: m[1],
        addrNum: parseInt(m[1], 16),
        size: parseInt(m[2], 16),
        kind: m[3],
        name: m[4].trim(),
      });
      continue;
    }
    if (mode === "imports") {
      const m = /^\s*(\S+)\s+(.+)$/.exec(line);
      if (!m) continue;
      info.imports.push({
        addr: "0x0",
        addrNum: 0,
        size: 0,
        kind: m[1],
        name: m[2].trim(),
        isImport: true,
      });
    }
  }

  info.functions = info.functions.filter(
    (f) => f.kind === "function" && f.name && !f.name.startsWith("<"),
  );
  return info;
}

function splitPipes(line) {
  const out = [];
  let cur = "";
  for (let i = 0; i < line.length; ++i) {
    const c = line[i];
    if (c === "\\" && i + 1 < line.length) {
      cur += c + line[i + 1];
      ++i;
      continue;
    }
    if (c === "|") { out.push(cur); cur = ""; continue; }
    cur += c;
  }
  out.push(cur);
  return out;
}

function unescapeField(s) {
  let out = "";
  for (let i = 0; i < s.length; ++i) {
    const c = s[i];
    if (c !== "\\" || i + 1 >= s.length) { out += c; continue; }
    const n = s[++i];
    switch (n) {
      case "n": out += "\n"; break;
      case "r": out += "\r"; break;
      case "t": out += "\t"; break;
      case "\\": out += "\\"; break;
      case "|": out += "|"; break;
      case "x": {
        const hex = s.slice(i + 1, i + 3);
        if (/^[0-9a-fA-F]{2}$/.test(hex)) {
          out += String.fromCharCode(parseInt(hex, 16));
          i += 2;
        } else {
          out += n;
        }
        break;
      }
      default: out += n;
    }
  }
  return out;
}

function parseStrings(raw) {
  const out = [];
  for (const line of raw.split("\n")) {
    if (!line) continue;
    const parts = splitPipes(line);
    if (parts.length < 3) continue;
    const [addrHex, escText, xrefStr] = parts;
    const addrNum = parseInt(addrHex, 16);
    if (!Number.isFinite(addrNum)) continue;
    const text = unescapeField(escText);
    const xrefs = xrefStr
      ? xrefStr.split(",").map((s) => parseInt(s, 16)).filter(Number.isFinite)
      : [];
    out.push({ addr: "0x" + addrNum.toString(16), addrNum, text, xrefs });
  }
  return out;
}

function cloneAnnotations(raw) {
  return {
    renames:      { ...(raw?.renames || {}) },
    notes:        { ...(raw?.notes || {}) },
    signatures:   { ...(raw?.signatures || {}) },
    localRenames: { ...(raw?.localRenames || {}) },
    patches:      { ...(raw?.patches || {}) },
  };
}

function normalizeManifest(raw, dir) {
  if (!raw || typeof raw !== "object") throw new Error("manifest must be an object");
  const {
    id, name, version, entry, description = "", permissions = [], apiVersion = 1,
  } = raw;
  if (!id || typeof id !== "string") throw new Error("manifest.id must be a string");
  if (!name || typeof name !== "string") throw new Error("manifest.name must be a string");
  if (!version || typeof version !== "string") throw new Error("manifest.version must be a string");
  if (!entry || typeof entry !== "string") throw new Error("manifest.entry must be a string");
  if (!Array.isArray(permissions)) throw new Error("manifest.permissions must be an array");
  for (const perm of permissions) {
    if (typeof perm !== "string" || !KNOWN_PERMISSIONS.has(perm)) {
      throw new Error(`unknown permission: ${perm}`);
    }
  }
  return {
    id,
    name,
    version,
    description,
    entry,
    apiVersion,
    permissions,
    dir,
  };
}

function normalizeCommand(plugin, raw) {
  if (!raw || typeof raw !== "object") throw new Error("command must be an object");
  if (!raw.id || typeof raw.id !== "string") throw new Error("command.id must be a string");
  if (!raw.title || typeof raw.title !== "string") throw new Error("command.title must be a string");
  if (typeof raw.run !== "function") throw new Error(`command ${raw.id} is missing run()`);
  return {
    id: raw.id,
    title: raw.title,
    description: typeof raw.description === "string" ? raw.description : "",
    permissions: Array.isArray(raw.permissions) ? raw.permissions : plugin.manifest.permissions,
    run: raw.run,
  };
}

function assertPermissions(plugin, requested) {
  for (const perm of requested || []) {
    if (!plugin.permissionSet.has(perm)) {
      throw new Error(`plugin ${plugin.manifest.id} lacks permission ${perm}`);
    }
  }
}

function commandRef(pluginId, commandId) {
  return `${pluginId}:${commandId}`;
}

function makePluginHost(opts) {
  const {
    app,
    runEmber,
    getCurrentBinary,
    readAnnotations,
    saveAnnotations,
  } = opts;

  const pluginCache = new Map();

  function pluginRoots() {
    const roots = [];
    if (app.isPackaged) roots.push(path.join(process.resourcesPath, "plugins"));
    else roots.push(path.join(__dirname, "..", "..", "plugins"));
    roots.push(path.join(app.getPath("userData"), "plugins"));
    return roots;
  }

  async function discoverManifests() {
    const found = [];
    for (const root of pluginRoots()) {
      let entries;
      try { entries = await fs.readdir(root, { withFileTypes: true }); }
      catch { continue; }
      for (const ent of entries) {
        if (!ent.isDirectory()) continue;
        const dir = path.join(root, ent.name);
        const manifestPath = path.join(dir, "plugin.json");
        try {
          const raw = JSON.parse(await fs.readFile(manifestPath, "utf8"));
          found.push(normalizeManifest(raw, dir));
        } catch (e) {
          found.push({
            id: `invalid:${ent.name}`,
            name: ent.name,
            version: "0",
            description: `Invalid plugin: ${e.message}`,
            entry: "",
            apiVersion: 1,
            permissions: [],
            dir,
            invalid: true,
          });
        }
      }
    }
    found.sort((a, b) => a.name.localeCompare(b.name));
    return found;
  }

  async function loadPlugin(manifest) {
    const hit = pluginCache.get(manifest.id);
    if (hit) return hit;
    if (manifest.invalid) throw new Error(manifest.description);

    const entryPath = path.join(manifest.dir, manifest.entry);
    let mod;
    try { mod = require(entryPath); }
    catch (e) { throw new Error(`failed loading ${manifest.id}: ${e.message}`); }
    const activate = mod?.activate;
    if (typeof activate !== "function") {
      throw new Error(`plugin ${manifest.id} does not export activate()`);
    }
    const runtime = await activate({
      apiVersion: 1,
      plugin: {
        id: manifest.id,
        name: manifest.name,
        version: manifest.version,
      },
    });
    if (!runtime || !Array.isArray(runtime.commands)) {
      throw new Error(`plugin ${manifest.id} activate() must return { commands: [] }`);
    }
    const plugin = {
      manifest,
      permissionSet: new Set(manifest.permissions),
      commands: runtime.commands.map((cmd) => normalizeCommand({ manifest }, cmd)),
    };
    pluginCache.set(manifest.id, plugin);
    return plugin;
  }

  async function currentBinary() {
    const bp = getCurrentBinary();
    if (!bp) throw new Error("no binary selected");
    return bp;
  }

  async function loadSummary(binaryPath) {
    const raw = await runEmber([binaryPath]);
    return parseSummary(raw, binaryPath);
  }

  async function loadStrings(binaryPath) {
    const raw = await runEmber(["--strings", binaryPath]);
    return parseStrings(raw);
  }

  function hostContextFor(plugin) {
    return {
      async loadSummary() {
        assertPermissions(plugin, ["read.binary-summary"]);
        return await loadSummary(await currentBinary());
      },
      async loadStrings() {
        assertPermissions(plugin, ["read.strings"]);
        return await loadStrings(await currentBinary());
      },
      async loadAnnotations() {
        assertPermissions(plugin, ["read.annotations"]);
        return cloneAnnotations(await readAnnotations(await currentBinary()));
      },
      async currentBinaryPath() {
        return await currentBinary();
      },
      proposalBuilders: {
        rename(addr, name, extra = {}) {
          return {
            kind: "rename",
            addr: typeof addr === "number" ? `0x${addr.toString(16)}` : String(addr),
            name,
            confidence: typeof extra.confidence === "number" ? extra.confidence : 0.5,
            reason: typeof extra.reason === "string" ? extra.reason : "",
          };
        },
        note(addr, text, extra = {}) {
          return {
            kind: "note",
            addr: typeof addr === "number" ? `0x${addr.toString(16)}` : String(addr),
            text,
            confidence: typeof extra.confidence === "number" ? extra.confidence : 0.5,
            reason: typeof extra.reason === "string" ? extra.reason : "",
          };
        },
      },
    };
  }

  async function listPlugins() {
    const manifests = await discoverManifests();
    const out = [];
    for (const manifest of manifests) {
      if (manifest.invalid) {
        out.push({
          id: manifest.id,
          name: manifest.name,
          version: manifest.version,
          description: manifest.description,
          permissions: [],
          commands: [],
          invalid: true,
        });
        continue;
      }
      try {
        const plugin = await loadPlugin(manifest);
        out.push({
          id: manifest.id,
          name: manifest.name,
          version: manifest.version,
          description: manifest.description,
          permissions: manifest.permissions,
          commands: plugin.commands.map((cmd) => ({
            id: cmd.id,
            ref: commandRef(manifest.id, cmd.id),
            title: cmd.title,
            description: cmd.description,
          })),
          invalid: false,
        });
      } catch (e) {
        out.push({
          id: manifest.id,
          name: manifest.name,
          version: manifest.version,
          description: `Failed to load: ${e.message}`,
          permissions: manifest.permissions,
          commands: [],
          invalid: true,
        });
      }
    }
    return out;
  }

  async function runCommand(pluginId, commandId, opts = {}) {
    const manifests = await discoverManifests();
    const manifest = manifests.find((m) => m.id === pluginId);
    if (!manifest) throw new Error(`unknown plugin ${pluginId}`);
    const plugin = await loadPlugin(manifest);
    const command = plugin.commands.find((cmd) => cmd.id === commandId);
    if (!command) throw new Error(`unknown command ${commandId}`);

    const result = await command.run(hostContextFor(plugin), opts.args || {});
    const proposals = Array.isArray(result?.proposals)
      ? result.proposals.filter((p) =>
        p && p.addr &&
        ((p.kind === "rename" && p.name) || (p.kind === "note" && p.text)))
      : [];
    const summary = typeof result?.summary === "string" ? result.summary : "";
    const notes = typeof result?.notes === "string" ? result.notes : "";

    if (!opts.apply) {
      return {
        pluginId,
        commandId,
        summary,
        notes,
        proposals,
        applied: false,
        appliedCount: 0,
      };
    }

    assertPermissions(plugin, ["project.rename"]);
    const bp = await currentBinary();
    const ann = cloneAnnotations(await readAnnotations(bp));
    let appliedCount = 0;
    for (const proposal of proposals) {
      if (proposal.kind === "rename") {
        assertPermissions(plugin, ["project.rename"]);
        if (ann.renames[proposal.addr] === proposal.name) continue;
        ann.renames[proposal.addr] = proposal.name;
        ++appliedCount;
      } else if (proposal.kind === "note") {
        assertPermissions(plugin, ["project.note"]);
        if (ann.notes[proposal.addr] === proposal.text) continue;
        ann.notes[proposal.addr] = proposal.text;
        ++appliedCount;
      }
    }
    await saveAnnotations(bp, ann);
    return {
      pluginId,
      commandId,
      summary,
      notes,
      proposals,
      applied: true,
      appliedCount,
      annotations: ann,
    };
  }

  return { listPlugins, runCommand };
}

module.exports = { makePluginHost };
