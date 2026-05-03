#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

function parseArgs(argv) {
  const args = new Map();
  for (let i = 0; i < argv.length; ++i) {
    const a = argv[i];
    if (!a.startsWith("--")) continue;
    const eq = a.indexOf("=");
    if (eq >= 0) args.set(a.slice(2, eq), a.slice(eq + 1));
    else args.set(a.slice(2), argv[++i]);
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));
const input = args.get("input");
const output = args.get("out") ?? "benchmarks/anchor-bench/site/data.js";
if (!input) {
  console.error("usage: update-site-data.mjs --input leaderboard.json [--out site/data.js]");
  process.exit(2);
}

const leaderboard = JSON.parse(readFileSync(resolve(input), "utf8"));
const data = {
  ...leaderboard,
  benchmark: leaderboard.entries?.[0]?.benchmark ?? "unknown",
  note: leaderboard.note ?? "Generated Anchor Bench leaderboard data.",
  hard_preview: leaderboard.hard_preview ?? [
    { band: "smoke", target_mix: "Compiler/runtime sanity", weight: 1 },
    { band: "medium", target_mix: "Imports, strings, direct xrefs", weight: 1 },
    { band: "hard", target_mix: "Deep anchor chains, no strings", weight: 2 },
    { band: "expert", target_mix: "C++ RTTI, virtuals, indirect calls", weight: 3 },
    { band: "negative", target_mix: "Ambiguous stubs; abstention required", weight: 2 }
  ],
};

const js = `window.ANCHOR_BENCH_DATA = ${JSON.stringify(data, null, 2)};\n`;
const out = resolve(output);
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, js, "utf8");
console.log(`wrote ${out}`);
