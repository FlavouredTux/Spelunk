#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..");

function pathFromRoot(p) {
  return isAbsolute(p) ? p : resolve(repoRoot, p);
}

function addrKey(a) {
  try {
    return "0x" + BigInt(a).toString(16);
  } catch {
    throw new Error(`invalid address: ${a}`);
  }
}

function fail(msg) {
  console.error(`manifest invalid: ${msg}`);
  process.exit(1);
}

const manifestPath = process.argv[2];
if (!manifestPath) {
  console.error("usage: validate-manifest.mjs MANIFEST.json");
  process.exit(2);
}

let manifest;
try {
  manifest = JSON.parse(readFileSync(pathFromRoot(manifestPath), "utf8"));
} catch (e) {
  fail(`cannot read JSON: ${e.message}`);
}

try {
  if (!manifest.name || typeof manifest.name !== "string") throw new Error("name is required");
  if (!Array.isArray(manifest.cases)) throw new Error("cases must be an array");
  const caseIds = new Set();
  let targets = 0;
  for (const c of manifest.cases) {
    if (!c.id || typeof c.id !== "string") throw new Error("case.id is required");
    if (caseIds.has(c.id)) throw new Error(`duplicate case id: ${c.id}`);
    caseIds.add(c.id);
    if (!c.binary || typeof c.binary !== "string") throw new Error(`case ${c.id}: binary is required`);
    if (!existsSync(pathFromRoot(c.binary))) throw new Error(`case ${c.id}: binary not found: ${c.binary}`);
    if (!Array.isArray(c.targets) || c.targets.length === 0) throw new Error(`case ${c.id}: targets must be non-empty`);
    const addrs = new Set();
    for (const t of c.targets) {
      const key = addrKey(t.address);
      if (addrs.has(key)) throw new Error(`case ${c.id}: duplicate target ${key}`);
      addrs.add(key);
      if (t.expect !== "abstain" && !t.canonical) throw new Error(`case ${c.id} ${key}: canonical required`);
      if (t.weight != null && !(Number(t.weight) > 0)) throw new Error(`case ${c.id} ${key}: weight must be positive`);
      targets += 1;
    }
  }
  console.log(`manifest ok: ${manifest.name} cases=${manifest.cases.length} targets=${targets}`);
} catch (e) {
  fail(e.message);
}
