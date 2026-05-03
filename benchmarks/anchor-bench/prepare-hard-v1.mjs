#!/usr/bin/env node
import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..");
const outDir = resolve(repoRoot, "build/anchor-bench/hard-v1");

const fixtures = [
  "fp_scalar",
  "gotos",
  "tail_call",
  "indirect_tail",
  "decoder_misc",
  "printf_noise",
];

function run(cmd, args) {
  const r = spawnSync(cmd, args, {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: "pipe",
  });
  if (r.status !== 0) {
    throw new Error(`command failed: ${cmd} ${args.join(" ")}\n${r.stderr}`);
  }
  return r;
}

mkdirSync(outDir, { recursive: true });

for (const name of fixtures) {
  const src = resolve(repoRoot, "build/tests/fixtures", name);
  const dst = resolve(outDir, `${name}.stripped`);
  copyFileSync(src, dst);
  run("strip", ["--strip-all", dst]);
  console.log(`wrote ${dst}`);
}
