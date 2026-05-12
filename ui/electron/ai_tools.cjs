// AI binary-navigation tools for the Ember chat panel.
//
// The old bridge called a missing scripts/query.js helper once per tool
// call. This version talks directly to the native C++ `ember --serve`
// daemon: one loaded binary per chat request, length-framed responses,
// and the same tool surface for OpenAI-format function tools and
// assistant's in-process MCP server.

const { spawn } = require("node:child_process");
const path = require("node:path");
const { z } = require("zod");

const MAX_TOOL_OUTPUT = 24000;
const MAX_FUNCTION_ROWS = 80;
const MAX_STRING_ROWS = 80;

function clip(text, max = MAX_TOOL_OUTPUT) {
  text = String(text ?? "");
  if (!text.trim()) return "(no results)";
  if (text.length <= max) return text;
  return text.slice(0, max) + `\n\n[... truncated ${text.length - max} more chars; narrow the query]`;
}

function parseHex(s) {
  const raw = String(s || "").trim().replace(/^sub_/i, "").replace(/^0x/i, "");
  if (!/^[0-9a-f]+$/i.test(raw)) return null;
  return Number.parseInt(raw, 16);
}

function parseTargetAddr(s) {
  const raw = String(s || "").trim();
  if (/^0x[0-9a-f]+$/i.test(raw) || /^sub_[0-9a-f]+$/i.test(raw)) {
    return parseHex(raw);
  }
  if (/^\d+$/.test(raw)) return Number.parseInt(raw, 10);
  return null;
}

function hex(n) {
  return "0x" + Number(n).toString(16);
}

function escapeRegex(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function parseFunctionRows(tsv) {
  const rows = [];
  for (const line of String(tsv || "").split("\n")) {
    if (!line.trim()) continue;
    const [addr, size, kind, name] = line.split("\t");
    if (!addr || !name) continue;
    rows.push({ addr, size: size || "0x0", kind: kind || "", name: name || "" });
  }
  return rows;
}

function formatFunctionRows(rows) {
  return rows.slice(0, MAX_FUNCTION_ROWS)
    .map((r) => `${r.addr}\t${r.size}\t${r.kind}\t${r.name}`)
    .join("\n") +
    (rows.length > MAX_FUNCTION_ROWS ? `\n[+${rows.length - MAX_FUNCTION_ROWS} more functions]` : "");
}

function parseStringRows(tsv) {
  const rows = [];
  for (const line of String(tsv || "").split("\n")) {
    if (!line.trim()) continue;
    const parts = line.split("|");
    if (parts.length < 2) continue;
    rows.push({
      addr: parts[0],
      text: parts[1],
      xrefs: (parts[2] || "").split(",").map((s) => s.trim()).filter(Boolean),
      raw: line,
    });
  }
  return rows;
}

class EmberServeSession {
  constructor(ctx) {
    this.ctx = {
      emberBin: path.resolve(ctx.emberBin),
      binaryPath: path.resolve(ctx.binaryPath),
      annPath: ctx.annPath ? path.resolve(ctx.annPath) : "",
    };
    this.buf = Buffer.alloc(0);
    this.ready = false;
    this.deadErr = null;
    this.waitingReady = [];
    this.queue = [];

    const args = [
      ...(this.ctx.annPath ? ["--annotations", this.ctx.annPath] : []),
      "--serve",
      this.ctx.binaryPath,
    ];
    this.proc = spawn(this.ctx.emberBin, args, {
      cwd: path.dirname(this.ctx.emberBin),
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.proc.stdout.on("data", (b) => this.onData(b));
    this.proc.stderr.on("data", () => {});
    this.proc.on("error", (e) => this.die(e));
    this.proc.on("close", (code, sig) => {
      this.die(new Error(`ember --serve exited ${code ?? sig ?? "unknown"}`));
    });
  }

  key() {
    return `${this.ctx.emberBin}\n${this.ctx.binaryPath}\n${this.ctx.annPath || ""}`;
  }

  waitReady() {
    if (this.ready) return Promise.resolve();
    if (this.deadErr) return Promise.reject(this.deadErr);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const err = new Error("ember --serve handshake timeout");
        this.die(err);
        reject(err);
      }, 30000);
      this.waitingReady.push((err) => {
        clearTimeout(timer);
        if (err) reject(err);
        else resolve();
      });
    });
  }

  die(err) {
    if (this.deadErr) return;
    this.deadErr = err;
    for (const w of this.waitingReady) w(err);
    this.waitingReady = [];
    for (const q of this.queue) q.reject(err);
    this.queue = [];
  }

  onData(chunk) {
    this.buf = Buffer.concat([this.buf, chunk]);
    for (;;) {
      if (!this.ready) {
        const nl = this.buf.indexOf(0x0a);
        if (nl < 0) return;
        const line = this.buf.subarray(0, nl).toString("utf8");
        this.buf = this.buf.subarray(nl + 1);
        if (!line.startsWith("ready ")) {
          this.die(new Error(`unexpected ember --serve greeting: ${line}`));
          return;
        }
        this.ready = true;
        for (const w of this.waitingReady) w(null);
        this.waitingReady = [];
        continue;
      }

      const nl = this.buf.indexOf(0x0a);
      if (nl < 0) return;
      const header = this.buf.subarray(0, nl).toString("utf8");
      if (header.startsWith("err ")) {
        const pending = this.queue.shift();
        this.buf = this.buf.subarray(nl + 1);
        if (pending) pending.reject(new Error(header.slice(4)));
        continue;
      }
      if (!header.startsWith("ok ")) {
        this.die(new Error(`malformed ember --serve frame: ${header.slice(0, 120)}`));
        return;
      }
      const len = Number.parseInt(header.slice(3), 10);
      if (!Number.isFinite(len) || len < 0) {
        this.die(new Error(`bad ember --serve frame length: ${header}`));
        return;
      }
      const need = nl + 1 + len + 1;
      if (this.buf.length < need) return;
      const body = this.buf.subarray(nl + 1, nl + 1 + len).toString("utf8");
      this.buf = this.buf.subarray(need);
      const pending = this.queue.shift();
      if (pending) pending.resolve(body);
    }
  }

  async call(method, params = {}) {
    await this.waitReady();
    if (this.deadErr) throw this.deadErr;
    const fields = [method];
    for (const [k, v] of Object.entries(params)) {
      fields.push(`${k}=${String(v).replace(/[\t\r\n]/g, " ")}`);
    }
    const line = fields.join("\t") + "\n";
    return await new Promise((resolve, reject) => {
      this.queue.push({ resolve, reject });
      this.proc.stdin.write(line, (err) => {
        if (err) this.die(err);
      });
    });
  }

  close() {
    try { this.proc.stdin.end(); } catch {}
    try { this.proc.kill(); } catch {}
  }
}

function makeTools(getCtx) {
  let session = null;
  let functionCache = null;

  function getSession() {
    const ctx = getCtx();
    const key = `${ctx.emberBin}\n${ctx.binaryPath}\n${ctx.annPath || ""}`;
    if (!session || session.key() !== key) {
      try { session?.close(); } catch {}
      session = new EmberServeSession(ctx);
      functionCache = null;
    }
    return session;
  }

  async function call(method, params) {
    return await getSession().call(method, params);
  }

  async function functions() {
    if (functionCache) return functionCache;
    functionCache = parseFunctionRows(await call("functions"));
    return functionCache;
  }

  async function resolveAddr(target) {
    const direct = parseTargetAddr(target);
    if (direct != null) return hex(direct);

    const exact = String(target || "").trim();
    const rows = await functions();
    const found = rows.find((r) => r.name === exact)
      || rows.find((r) => r.name.toLowerCase() === exact.toLowerCase());
    if (!found) throw new Error(`no function named ${exact}`);
    return found.addr;
  }

  const tools = [
    {
      name: "find_function",
      description:
        "Search defined functions by case-insensitive name regex. Returns TSV rows: addr, size, kind, name. Use before guessing exact names.",
      zod: { query: z.string().describe("function-name regex, e.g. 'init|main|decrypt'") },
      jsonSchema: {
        type: "object",
        properties: { query: { type: "string", description: "case-insensitive function-name regex" } },
        required: ["query"],
      },
      exec: async ({ query }) => {
        const re = new RegExp(String(query || ""), "i");
        const hits = (await functions()).filter((r) => re.test(r.name));
        return clip(formatFunctionRows(hits));
      },
    },
    {
      name: "get_function",
      description:
        "Fetch pseudo-C for a function by name, sub_<addr>, or hex address. Use this before explaining callees or helpers.",
      zod: { target: z.string().describe("function name, sub_<hex>, or 0x-prefixed address") },
      jsonSchema: {
        type: "object",
        properties: { target: { type: "string", description: "function name, sub_<hex>, or address" } },
        required: ["target"],
      },
      exec: async ({ target }) => {
        const addr = await resolveAddr(target);
        return clip(await call("decompile", { fn: addr }));
      },
    },
    {
      name: "list_callers",
      description:
        "List incoming references/callers for a function or data address. Use for 'who uses this?' questions and to infer helper purpose from call sites.",
      zod: { target: z.string().describe("function name, sub_<hex>, or address") },
      jsonSchema: {
        type: "object",
        properties: { target: { type: "string", description: "function name, sub_<hex>, or address" } },
        required: ["target"],
      },
      exec: async ({ target }) => {
        const addr = await resolveAddr(target);
        return clip(await call("refs_to", { addr }));
      },
    },
    {
      name: "list_callees",
      description:
        "List direct/tail/known-indirect callees for a function. Use to map what a function delegates to before naming it.",
      zod: { target: z.string().describe("function name, sub_<hex>, or address") },
      jsonSchema: {
        type: "object",
        properties: { target: { type: "string", description: "function name, sub_<hex>, or address" } },
        required: ["target"],
      },
      exec: async ({ target }) => {
        const addr = await resolveAddr(target);
        return clip(await call("callees", { fn: addr }));
      },
    },
    {
      name: "find_strings",
      description:
        "Find string literals by regex and include xref sites. Use to locate handlers by error text, paths, protocol names, URLs, and format strings.",
      zod: { pattern: z.string().describe("case-insensitive regex over string bodies") },
      jsonSchema: {
        type: "object",
        properties: { pattern: { type: "string", description: "case-insensitive regex over string bodies" } },
        required: ["pattern"],
      },
      exec: async ({ pattern }) => {
        const re = new RegExp(String(pattern || ""), "i");
        const hits = parseStringRows(await call("strings")).filter((r) => re.test(r.text));
        const body = hits.slice(0, MAX_STRING_ROWS).map((r) => r.raw).join("\n")
          + (hits.length > MAX_STRING_ROWS ? `\n[+${hits.length - MAX_STRING_ROWS} more strings]` : "");
        return clip(body);
      },
    },
    {
      name: "strings_for_function",
      description:
        "List strings whose xref sites are inside one function. Use when pseudo-C has opaque constants or the function name is unclear.",
      zod: { target: z.string().describe("function name, sub_<hex>, or address") },
      jsonSchema: {
        type: "object",
        properties: { target: { type: "string", description: "function name, sub_<hex>, or address" } },
        required: ["target"],
      },
      exec: async ({ target }) => {
        const addr = await resolveAddr(target);
        const cf = String(await call("containing_fn", { addr })).trim().split("\t");
        const start = parseHex(cf[0] || addr) ?? parseHex(addr);
        const size = parseHex(cf[1] || "0") ?? 0x1000;
        if (start == null) throw new Error(`cannot resolve function extent for ${target}`);
        return clip(await call("strings_in_range", {
          start: hex(start),
          end: hex(start + (size || 0x1000)),
        }));
      },
    },
    {
      name: "identify_function",
      description:
        "Run Ember's built-in YARA-like function identifier and filter for a target when possible. Use for crypto/network/runtime recognition hints.",
      zod: { target: z.string().optional().describe("optional function name, sub_<hex>, or address to filter around") },
      jsonSchema: {
        type: "object",
        properties: { target: { type: "string", description: "optional function name, sub_<hex>, or address" } },
      },
      exec: async ({ target } = {}) => {
        const body = await call("identify");
        if (!target) return clip(body);
        const addr = await resolveAddr(target);
        const needle = addr.replace(/^0x0*/, "0x").toLowerCase();
        const lines = String(body).split("\n").filter((l) =>
          l.toLowerCase().includes(addr.toLowerCase()) ||
          l.toLowerCase().includes(needle));
        return clip(lines.join("\n"));
      },
    },
  ];

  Object.defineProperty(tools, "dispose", {
    enumerable: false,
    value: () => {
      try { session?.close(); } catch {}
      session = null;
    },
  });
  return tools;
}

module.exports = { makeTools };
