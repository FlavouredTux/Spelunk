const fs = require("node:fs/promises");
const path = require("node:path");

const KNOWN_PERMISSIONS = new Set([
  "read.binary-summary",
  "read.strings",
  "read.annotations",
  "read.functions",
  "read.xrefs",
  "read.arities",
  "read.decompile",
  "project.rename",
  "project.note",
]);

// Manifest matcher kinds supported in Phase 1. Adding a new kind means
// extending `normalizeMatcher` AND `evaluateMatchers` below.
const MATCHER_KINDS = new Set([
  "format",           // value:  "elf" | "mach-o" | "pe" (matches summary.format)
  "arch",             // value:  e.g. "x86_64", "aarch64" (matches summary.arch)
  "symbol-present",   // name:   literal defined-symbol name
  "string-present",   // text:   literal substring of any printable string
  "section-present",  // name:   literal section name
]);

function normalizeMatcher(raw, idx) {
  if (!raw || typeof raw !== "object") {
    throw new Error(`matcher[${idx}] must be an object`);
  }
  if (typeof raw.kind !== "string" || !MATCHER_KINDS.has(raw.kind)) {
    throw new Error(`matcher[${idx}] has unknown kind: ${raw.kind}`);
  }
  const out = { kind: raw.kind };
  if (raw.kind === "format" || raw.kind === "arch") {
    if (typeof raw.value !== "string" || !raw.value) {
      throw new Error(`matcher[${idx}] (${raw.kind}) requires a non-empty 'value'`);
    }
    out.value = raw.value;
  } else if (raw.kind === "symbol-present" || raw.kind === "section-present") {
    if (typeof raw.name !== "string" || !raw.name) {
      throw new Error(`matcher[${idx}] (${raw.kind}) requires a non-empty 'name'`);
    }
    out.name = raw.name;
  } else if (raw.kind === "string-present") {
    if (typeof raw.text !== "string" || !raw.text) {
      throw new Error(`matcher[${idx}] (string-present) requires a non-empty 'text'`);
    }
    out.text = raw.text;
  }
  return out;
}

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

function normalizePanelContribution(raw, idx) {
  if (!raw || typeof raw !== "object") {
    throw new Error(`contributes.panels[${idx}] must be an object`);
  }
  if (typeof raw.id !== "string" || !raw.id) {
    throw new Error(`contributes.panels[${idx}].id must be a non-empty string`);
  }
  if (typeof raw.title !== "string" || !raw.title) {
    throw new Error(`contributes.panels[${idx}].title must be a non-empty string`);
  }
  if (typeof raw.command !== "string" || !raw.command) {
    throw new Error(`contributes.panels[${idx}].command must reference a command id`);
  }
  return {
    id:          raw.id,
    title:       raw.title,
    command:     raw.command,
    description: typeof raw.description === "string" ? raw.description : "",
  };
}

function normalizeContributes(raw) {
  if (raw === undefined || raw === null) return { panels: [] };
  if (typeof raw !== "object") throw new Error("manifest.contributes must be an object");
  const panels = Array.isArray(raw.panels) ? raw.panels : [];
  return {
    panels: panels.map((p, i) => normalizePanelContribution(p, i)),
  };
}

function normalizeManifest(raw, dir) {
  if (!raw || typeof raw !== "object") throw new Error("manifest must be an object");
  const {
    id, name, version, entry, description = "", permissions = [], apiVersion = 1,
    matchers = [], contributes = {},
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
  if (!Array.isArray(matchers)) throw new Error("manifest.matchers must be an array");
  const normalizedMatchers = matchers.map((m, i) => normalizeMatcher(m, i));
  const normalizedContributes = normalizeContributes(contributes);
  return {
    id,
    name,
    version,
    description,
    entry,
    apiVersion,
    permissions,
    matchers: normalizedMatchers,
    contributes: normalizedContributes,
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

// Validate and strip a panel payload returned from a plugin command.
// Phase 2 supports one kind: "list" with rows of { addr?, label, detail?, tags[]? }.
// Invalid shapes are dropped (null) rather than rejected so a misbehaving
// plugin doesn't take down the whole run — the rename/note path still works.
function sanitizePanelData(raw) {
  if (!raw || typeof raw !== "object") return null;
  if (raw.kind !== "list") return null;
  if (!Array.isArray(raw.rows)) return null;
  const rows = [];
  for (const r of raw.rows) {
    if (!r || typeof r !== "object") continue;
    if (typeof r.label !== "string" || !r.label) continue;
    const row = { label: r.label };
    if (typeof r.addr === "string" && r.addr) row.addr = r.addr;
    else if (typeof r.addr === "number" && Number.isFinite(r.addr)) {
      row.addr = `0x${r.addr.toString(16)}`;
    }
    if (typeof r.detail === "string") row.detail = r.detail;
    if (Array.isArray(r.tags)) {
      row.tags = r.tags.filter((t) => typeof t === "string" && t.length > 0);
    }
    rows.push(row);
  }
  return { kind: "list", rows };
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

  async function loadFunctions(binaryPath) {
    // Uses the --functions TSV (addr\tsize\tkind\tname). Mirrors the
    // renderer-side parser in ui/src/api.ts so plugin and Sidebar see
    // the same discovered-function set.
    const raw = await runEmber(["--functions", binaryPath]);
    const out = [];
    for (const line of raw.split("\n")) {
      if (!line) continue;
      const parts = line.split("\t");
      if (parts.length < 4) continue;
      const addr = parts[0];
      const addrNum = parseInt(addr, 16);
      if (!Number.isFinite(addrNum)) continue;
      out.push({
        addr,
        addrNum,
        size: parseInt(parts[1], 16) || 0,
        kind: "function",
        name: parts.slice(3).join("\t").trim(),
      });
    }
    return out;
  }

  async function loadXrefs(binaryPath) {
    const raw = await runEmber(["--xrefs", binaryPath]);
    const callers = {};
    const callees = {};
    for (const line of raw.split("\n")) {
      const m = /^(0x[0-9a-f]+)\s*->\s*(0x[0-9a-f]+)/.exec(line);
      if (!m) continue;
      const a = parseInt(m[1], 16);
      const b = parseInt(m[2], 16);
      (callees[a] ??= []).push(b);
      (callers[b] ??= []).push(a);
    }
    for (const k in callers) callers[k] = Array.from(new Set(callers[k]));
    for (const k in callees) callees[k] = Array.from(new Set(callees[k]));
    return { callers, callees };
  }

  async function loadArities(binaryPath) {
    const raw = await runEmber(["--arities", binaryPath]);
    const out = {};
    for (const line of raw.split("\n")) {
      const m = /^(0x[0-9a-f]+)\s+(\d+)$/.exec(line.trim());
      if (!m) continue;
      out[parseInt(m[1], 16)] = parseInt(m[2], 10);
    }
    return out;
  }

  const VIEW_ARGS = {
    pseudo:    ["-p", "-s"],
    asm:       ["-d", "-s"],
    cfg:       ["-c", "-s"],
    cfgPseudo: ["--cfg-pseudo", "-s"],
    ir:        ["-i", "-s"],
    ssa:       ["-i", "--ssa", "-s"],
  };

  async function decompileAt(binaryPath, sym, view) {
    const pre = VIEW_ARGS[view] || VIEW_ARGS.pseudo;
    return await runEmber([...pre, String(sym), binaryPath]);
  }

  // Evaluate every matcher in the manifest against the current binary.
  // All matchers must hit for a plugin to be considered "matched"; partial
  // hits are still reported so the UI can show why a plugin didn't match.
  async function evaluateMatchers(manifest, binaryPath) {
    if (!manifest.matchers || manifest.matchers.length === 0) {
      return { score: 100, matched: true, evidence: [], failed: [] };
    }

    // Each source is fetched at most once per evaluation — matchers of the
    // same kind share the same underlying CLI call.
    let summary = null;
    let strings = null;
    const getSummary = async () => summary ??= await loadSummary(binaryPath);
    const getStrings = async () => strings ??= await loadStrings(binaryPath);

    const evidence = [];
    const failed = [];
    let matched = 0;

    for (const m of manifest.matchers) {
      let hit = false;
      let detail = "";

      if (m.kind === "format") {
        const s = await getSummary();
        if (s.format === m.value) { hit = true; detail = `format=${s.format}`; }
        else detail = `format=${s.format || "?"} (expected ${m.value})`;
      } else if (m.kind === "arch") {
        const s = await getSummary();
        if (s.arch === m.value) { hit = true; detail = `arch=${s.arch}`; }
        else detail = `arch=${s.arch || "?"} (expected ${m.value})`;
      } else if (m.kind === "symbol-present") {
        const s = await getSummary();
        const found = s.functions.find((f) => f.name === m.name);
        if (found) { hit = true; detail = `symbol ${m.name} @ ${found.addr}`; }
        else detail = `symbol ${m.name} not found`;
      } else if (m.kind === "section-present") {
        const s = await getSummary();
        const found = s.sections.find((sec) => sec.name === m.name);
        if (found) { hit = true; detail = `section ${m.name} @ ${found.vaddr}`; }
        else detail = `section ${m.name} not found`;
      } else if (m.kind === "string-present") {
        const all = await getStrings();
        const found = all.find((s) => s.text.includes(m.text));
        if (found) { hit = true; detail = `"${m.text}" @ ${found.addr}`; }
        else detail = `"${m.text}" not found in any string`;
      }

      if (hit) {
        ++matched;
        evidence.push({ kind: m.kind, detail });
      } else {
        failed.push({ ...m, detail });
      }
    }

    const total = manifest.matchers.length;
    const score = Math.round((matched / total) * 100);
    return { score, matched: score === 100, evidence, failed };
  }

  function hostContextFor(plugin, logs) {
    const log = (level, parts) => {
      if (!logs) return;
      const text = parts.map((p) =>
        typeof p === "string" ? p
        : (p === null || p === undefined ? String(p)
           : typeof p === "object" ? safeStringify(p)
           : String(p)),
      ).join(" ");
      logs.push({ level, text, ts: Date.now() });
      if (logs.length > 500) logs.shift();   // bound memory on chatty plugins
    };
    return {
      log:   (...parts) => log("info",  parts),
      warn:  (...parts) => log("warn",  parts),
      error: (...parts) => log("error", parts),
      async loadSummary() {
        assertPermissions(plugin, ["read.binary-summary"]);
        return await loadSummary(await currentBinary());
      },
      async loadStrings() {
        assertPermissions(plugin, ["read.strings"]);
        return await loadStrings(await currentBinary());
      },
      async loadFunctions() {
        assertPermissions(plugin, ["read.functions"]);
        return await loadFunctions(await currentBinary());
      },
      async loadXrefs() {
        assertPermissions(plugin, ["read.xrefs"]);
        return await loadXrefs(await currentBinary());
      },
      async loadArities() {
        assertPermissions(plugin, ["read.arities"]);
        return await loadArities(await currentBinary());
      },
      async decompile(sym, opts = {}) {
        assertPermissions(plugin, ["read.decompile"]);
        const view = typeof opts.view === "string" ? opts.view : "pseudo";
        return await decompileAt(await currentBinary(), sym, view);
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
          matchers: [],
          contributes: { panels: [] },
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
          matchers: manifest.matchers,
          contributes: manifest.contributes,
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
          matchers: manifest.matchers || [],
          contributes: manifest.contributes || { panels: [] },
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

    const logs = [];
    let result;
    try {
      result = await command.run(hostContextFor(plugin, logs), opts.args || {});
    } catch (e) {
      logs.push({ level: "error", text: `command threw: ${e?.message || String(e)}`, ts: Date.now() });
      throw Object.assign(e, { logs });
    }
    const proposals = Array.isArray(result?.proposals)
      ? result.proposals.filter((p) =>
        p && p.addr &&
        ((p.kind === "rename" && p.name) || (p.kind === "note" && p.text)))
      : [];
    const summary = typeof result?.summary === "string" ? result.summary : "";
    const notes = typeof result?.notes === "string" ? result.notes : "";
    const panel = sanitizePanelData(result?.panel);

    if (!opts.apply) {
      return {
        pluginId,
        commandId,
        summary,
        notes,
        proposals,
        panel,
        logs,
        applied: false,
        appliedCount: 0,
      };
    }

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
      panel,
      logs,
      applied: true,
      appliedCount,
      annotations: ann,
    };
  }

  async function matchPlugin(pluginId, binaryPathOverride) {
    const manifests = await discoverManifests();
    const manifest = manifests.find((m) => m.id === pluginId);
    if (!manifest) throw new Error(`unknown plugin ${pluginId}`);
    if (manifest.invalid) {
      return { score: 0, matched: false, evidence: [], failed: [] };
    }
    const bp = binaryPathOverride || (await currentBinary());
    return await evaluateMatchers(manifest, bp);
  }

  return { listPlugins, runCommand, matchPlugin };
}

// JSON.stringify but tolerates circular structures, BigInts and
// undefined values gracefully so a plugin's `host.log({...})` doesn't
// blow up on weird inputs.
function safeStringify(obj) {
  try {
    const seen = new WeakSet();
    return JSON.stringify(obj, (_k, v) => {
      if (typeof v === "bigint") return v.toString() + "n";
      if (typeof v === "object" && v !== null) {
        if (seen.has(v)) return "[circular]";
        seen.add(v);
      }
      return v;
    });
  } catch {
    return String(obj);
  }
}

module.exports = { makePluginHost };
