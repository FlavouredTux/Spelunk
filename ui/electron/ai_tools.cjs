// AI agent tools - let the model navigate the binary instead of
// being stuck with whatever pseudo-C the user attached up front.
// Each tool wraps a `scripts/query.js` command and returns plain text
// the model can read. The model decides when to call them; the loop
// (in main.cjs, per-provider) executes and feeds results back.
//
// All exec functions return a string. Empty string is returned as
// "(no results)" so the model doesn't have to special-case that.
//
// Output is truncated per-tool to keep token usage bounded - the
// model can always issue a more specific query if the truncated
// preview is enough to know what to ask for next.

const path = require("node:path");
const { spawn } = require("node:child_process");
const { z } = require("zod");

// In dev the script lives at the repo root; in packaged Electron it
// gets copied into `resources/scripts/`. EMBER_QUERY_SCRIPT lets
// integrators override (e.g. when testing a fork of query.js).
const QUERY_SCRIPT = process.env.EMBER_QUERY_SCRIPT || (() => {
  // The `app` import is heavy and only available in main; we resolve
  // lazily so this module also works under plain `node` for tests.
  let isPackaged = false, resPath = "";
  try {
    const { app } = require("electron");
    isPackaged = app.isPackaged;
    resPath    = process.resourcesPath || "";
  } catch { /* not running in electron */ }
  return isPackaged && resPath
    ? path.join(resPath, "scripts", "query.js")
    : path.join(__dirname, "..", "..", "scripts", "query.js");
})();
const MAX_TOOL_OUTPUT = 16000;     // chars; ~4k tokens per call

// Cap result strings so a curious model can't blow the context window
// with a 5000-line pseudo-C dump on a giant function.
function clip(text) {
  if (text.length <= MAX_TOOL_OUTPUT) return text;
  return text.slice(0, MAX_TOOL_OUTPUT) +
    `\n\n[... truncated ${text.length - MAX_TOOL_OUTPUT} more chars]`;
}

// Spawn the ember CLI with the query.js script. We invoke per call -
// the CLI's disk cache (xrefs / strings / arities) means re-loads are
// cheap after the first warm-up, and a fresh process avoids any
// state drift from previous tool calls.
function runScript(emberBin, binaryPath, annPath, cmd, args) {
  return new Promise((resolve, reject) => {
    const cliArgs = [
      "--script", QUERY_SCRIPT,
      ...(annPath ? ["--annotations", annPath] : []),
      binaryPath,
      "--", cmd, ...args.map(String),
    ];
    const proc = spawn(emberBin, cliArgs, { cwd: path.dirname(emberBin) });
    let out = "", err = "";
    proc.stdout.on("data", (d) => { out += d.toString(); });
    proc.stderr.on("data", (d) => { err += d.toString(); });
    proc.on("error", reject);
    proc.on("close", (code) => {
      if (code === 0) resolve(out.trimEnd() || "(no results)");
      else reject(new Error((err.trim() || `query failed (${code})`).slice(0, 400)));
    });
  });
}

// Resolve a name-or-address argument the model passed in. Names get
// looked up via `find-func <exact>` and we take the first hit; addrs
// (decimal or 0x-hex) pass through as-is. Returns a hex string the
// query.js commands accept.
async function resolveAddr(emberBin, binaryPath, annPath, target) {
  const t = String(target).trim();
  if (/^(0x[0-9a-fA-F]+|\d+)$/.test(t)) return t;
  const out = await runScript(emberBin, binaryPath, annPath, "find-func", [`^${escapeRegex(t)}$`]);
  // Output is `  0xADDR  name` per match. Take the first.
  const m = /^\s*(0x[0-9a-fA-F]+)\s/m.exec(out);
  if (!m) throw new Error(`no function named ${t}`);
  return m[1];
}

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Tool definitions. Each entry is consumed by both the OpenAI-format
// dispatcher (for openrouter / 9router) and the assistant Agent SDK
// (which takes Zod schemas via the in-process MCP helper).
function makeTools(getCtx) {
  // getCtx() must return { emberBin, binaryPath, annPath } at call
  // time - these can change between tool calls if the user opens a
  // new binary mid-conversation, so we resolve lazily.
  return [
    {
      name: "find_function",
      description:
        "Search the binary's defined functions by case-insensitive name regex. Use this when the user asks about a function by partial name, or when you need to discover what's available. Returns up to 50 matches as `addr  name` lines. Empty result means no match - try a broader pattern.",
      zod: { query: z.string().describe("name regex, e.g. 'init' or '^read.*Entity'") },
      jsonSchema: {
        type: "object",
        properties: { query: { type: "string", description: "name regex" } },
        required: ["query"],
      },
      exec: async ({ query }) => {
        const c = getCtx();
        return clip(await runScript(c.emberBin, c.binaryPath, c.annPath, "find-func", [String(query)]));
      },
    },
    {
      name: "get_function",
      description:
        "Fetch the pseudo-C decompilation of a function by name or hex address. Use this whenever you need to see another function's body - callees the user mentioned, helpers you suspect from the snippet, suspicious cross-references. Don't guess at a function's behavior when you can read it.",
      zod: { target: z.string().describe("function name or 0x-prefixed hex address") },
      jsonSchema: {
        type: "object",
        properties: { target: { type: "string", description: "function name or 0x-prefixed hex address" } },
        required: ["target"],
      },
      exec: async ({ target }) => {
        const c = getCtx();
        const addr = await resolveAddr(c.emberBin, c.binaryPath, c.annPath, target);
        return clip(await runScript(c.emberBin, c.binaryPath, c.annPath, "pseudo-c", [addr]));
      },
    },
    {
      name: "list_callers",
      description:
        "List the callers of a function by name or hex address. Useful when you need to know how a helper is invoked - what arguments different call sites pass, whether it's only used in one place, etc. Returns `addr  caller_name` lines.",
      zod: { target: z.string().describe("function name or 0x-prefixed hex address") },
      jsonSchema: {
        type: "object",
        properties: { target: { type: "string", description: "function name or 0x-prefixed hex address" } },
        required: ["target"],
      },
      exec: async ({ target }) => {
        const c = getCtx();
        const addr = await resolveAddr(c.emberBin, c.binaryPath, c.annPath, target);
        return clip(await runScript(c.emberBin, c.binaryPath, c.annPath, "callers", [addr]));
      },
    },
    {
      name: "list_callees",
      description:
        "List the functions that a given function calls, by name or hex address. Use this to map out what a function does at a glance before diving into its body, or to follow a call chain.",
      zod: { target: z.string().describe("function name or 0x-prefixed hex address") },
      jsonSchema: {
        type: "object",
        properties: { target: { type: "string", description: "function name or 0x-prefixed hex address" } },
        required: ["target"],
      },
      exec: async ({ target }) => {
        const c = getCtx();
        const addr = await resolveAddr(c.emberBin, c.binaryPath, c.annPath, target);
        return clip(await runScript(c.emberBin, c.binaryPath, c.annPath, "callees", [addr]));
      },
    },
    {
      name: "find_strings",
      description:
        "Find string literals in the binary matching a regex, AND list the instructions that reference them. Useful for locating handler functions by error messages, finding API endpoints by URL fragments, etc. Returns the string with each xref site indented below it.",
      zod: { pattern: z.string().describe("regex to match against the string body") },
      jsonSchema: {
        type: "object",
        properties: { pattern: { type: "string", description: "regex to match against the string body" } },
        required: ["pattern"],
      },
      exec: async ({ pattern }) => {
        const c = getCtx();
        return clip(await runScript(c.emberBin, c.binaryPath, c.annPath, "string-xrefs", [String(pattern)]));
      },
    },
  ];
}

module.exports = { makeTools };
