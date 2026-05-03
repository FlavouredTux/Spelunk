#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..");

function parseArgs(argv) {
  const out = new Map();
  for (let i = 0; i < argv.length; ++i) {
    const a = argv[i];
    if (!a.startsWith("--")) continue;
    const eq = a.indexOf("=");
    if (eq >= 0) {
      out.set(a.slice(2, eq), a.slice(eq + 1));
    } else {
      const v = argv[i + 1];
      if (v && !v.startsWith("--")) {
        out.set(a.slice(2), v);
        ++i;
      } else {
        out.set(a.slice(2), "true");
      }
    }
  }
  return out;
}

function usage() {
  console.error("usage: run.mjs --manifest PATH --model MODEL [--mode cascade|single-pass] [--per-round N] [--max-rounds N] [--budget N] [--settle-ms N] [--dry-run]");
  process.exit(2);
}

function pathFromRoot(p) {
  return isAbsolute(p) ? p : resolve(repoRoot, p);
}

function run(cmd, args, opts = {}) {
  const printable = [cmd, ...args].join(" ");
  if (opts.dryRun) {
    console.log(printable);
    return { status: 0, stdout: "", stderr: "" };
  }
  const r = spawnSync(cmd, args, {
    cwd: repoRoot,
    env: opts.env ?? process.env,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    stdio: opts.capture ? "pipe" : "inherit",
  });
  if (r.status !== 0) {
    throw new Error(`command failed (${r.status}): ${printable}\n${r.stderr ?? ""}`);
  }
  return r;
}

function sleep(ms) {
  if (ms <= 0) return;
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const manifestPath = args.get("manifest");
  const model = args.get("model");
  if (!manifestPath || !model) usage();

  const manifest = JSON.parse(readFileSync(pathFromRoot(manifestPath), "utf8"));
  const agent = pathFromRoot(args.get("agent") ?? "agent/dist/main.js");
  const ember = pathFromRoot(args.get("ember") ?? "build/cli/ember");
  const mode = args.get("mode") ?? manifest.defaults?.mode ?? "cascade";
  const dryRun = args.get("dry-run") === "true";
  const limitCases = args.has("limit-cases") ? Number(args.get("limit-cases")) : Infinity;
  const threshold = args.get("threshold") ?? String(manifest.defaults?.threshold ?? 0.85);
  const eligibilityRatio = args.get("eligibility-ratio") ?? String(manifest.defaults?.eligibilityRatio ?? 0.3);
  const budget = args.get("budget") ?? "0.05";
  const settleMs = Number(args.get("settle-ms") ?? manifest.defaults?.settleMs ?? (mode === "single-pass" ? 45000 : 0));

  if (!existsSync(agent)) {
    throw new Error(`agent entrypoint not found: ${agent}. Run: cd agent && npm run build`);
  }
  if (!existsSync(ember)) {
    throw new Error(`ember binary not found: ${ember}. Run: cmake --build build`);
  }
  if (!["cascade", "single-pass"].includes(mode)) {
    throw new Error(`unsupported mode: ${mode}`);
  }

  const env = {
    ...process.env,
    EMBER_BIN: ember,
    XDG_CACHE_HOME: process.env.XDG_CACHE_HOME ?? "/tmp/anchor-bench-cache",
  };

  let ran = 0;
  for (const c of manifest.cases ?? []) {
    if (ran++ >= limitCases) break;
    const binary = pathFromRoot(c.binary);
    console.log(`\n== ${c.id} (${mode}) ==`);
    if (mode === "cascade") {
      run(process.execPath, [
        agent,
        "cascade",
        `--binary=${binary}`,
        `--models=${model}`,
        `--per-round=${args.get("per-round") ?? "5"}`,
        `--max-rounds=${args.get("max-rounds") ?? "3"}`,
        `--budget=${budget}`,
        `--threshold=${threshold}`,
        `--eligibility-ratio=${eligibilityRatio}`,
      ], { env, dryRun });
    } else {
      const pick = "list:" + (c.targets ?? []).map((t) => t.address).join(",");
      run(process.execPath, [
        agent,
        "fanout",
        `--binary=${binary}`,
        `--model=${model}`,
        `--pick=${pick}`,
        `--limit=${String((c.targets ?? []).length)}`,
        `--budget=${budget}`,
      ], { env, dryRun });
    }
  }

  if (!dryRun) {
    if (settleMs > 0) {
      console.log(`\n== settle ${settleMs}ms ==`);
      sleep(settleMs);
    }
    console.log("\n== score ==");
    run(process.execPath, [
      pathFromRoot("benchmarks/anchor-bench/score.mjs"),
      `--manifest=${pathFromRoot(manifestPath)}`,
    ], { env });
  }
}

main();
