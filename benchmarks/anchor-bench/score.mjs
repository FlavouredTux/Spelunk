#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
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
  console.error("usage: score.mjs --manifest PATH [--json] [--out PATH] [--model NAME] [--mode NAME] [--trial N]");
  process.exit(2);
}

function loadJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function assertManifest(manifest) {
  if (!manifest || typeof manifest !== "object") throw new Error("manifest must be an object");
  if (!manifest.name || typeof manifest.name !== "string") throw new Error("manifest.name is required");
  if (!Array.isArray(manifest.cases)) throw new Error("manifest.cases must be an array");
  const seenCaseIds = new Set();
  for (const c of manifest.cases) {
    if (!c.id || typeof c.id !== "string") throw new Error("case.id is required");
    if (seenCaseIds.has(c.id)) throw new Error(`duplicate case id: ${c.id}`);
    seenCaseIds.add(c.id);
    if (!c.binary || typeof c.binary !== "string") throw new Error(`case ${c.id}: binary is required`);
    if (!Array.isArray(c.targets) || c.targets.length === 0) throw new Error(`case ${c.id}: targets must be a non-empty array`);
    const seenTargets = new Set();
    for (const t of c.targets) {
      if (!t.address || typeof t.address !== "string") throw new Error(`case ${c.id}: target.address is required`);
      const key = addrKey(t.address);
      if (seenTargets.has(key)) throw new Error(`case ${c.id}: duplicate target ${key}`);
      seenTargets.add(key);
      if (t.expect === "abstain") continue;
      if (!t.canonical || typeof t.canonical !== "string") {
        throw new Error(`case ${c.id} ${key}: canonical is required unless expect is abstain`);
      }
    }
  }
}

function pathFromRoot(p) {
  return isAbsolute(p) ? p : resolve(repoRoot, p);
}

function normalizeName(s) {
  return String(s ?? "")
    .toLowerCase()
    .replace(/^_+/, "")
    .replace(/@@.*$/, "")
    .replace(/\.(isra|constprop|part)\.\d+$/g, "")
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .replace(/_+/g, "_");
}

function addrKey(a) {
  const n = BigInt(a);
  return "0x" + n.toString(16);
}

function intelPathFor(binary) {
  const cacheRoot = process.env.XDG_CACHE_HOME
    ? resolve(process.env.XDG_CACHE_HOME, "ember")
    : resolve(homedir(), ".cache", "ember");
  const st = statSync(binary);
  const key = createHash("sha256")
    .update(binary)
    .update("|")
    .update(String(st.size))
    .update("|")
    .update(String(Math.floor(st.mtimeMs)))
    .update("|v1")
    .digest("hex")
    .slice(0, 16);
  return resolve(cacheRoot, key, "intel.jsonl");
}

function readIntel(binary) {
  const p = intelPathFor(binary);
  let raw = "";
  try {
    raw = readFileSync(p, "utf8");
  } catch {
    return [];
  }
  const out = [];
  for (const line of raw.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    try { out.push(JSON.parse(t)); } catch {}
  }
  return out;
}

function foldNameClaims(binary) {
  const entries = readIntel(binary);
  const retracted = new Set();
  for (const e of entries) {
    if (e.kind === "retract") retracted.add(e.target_id);
  }
  const buckets = new Map();
  for (const e of entries) {
    if (e.kind !== "claim") continue;
    if (e.predicate !== "name") continue;
    if (retracted.has(e.id)) continue;
    const key = `${addrKey(e.subject)}|${e.predicate}`;
    const arr = buckets.get(key);
    if (arr) arr.push(e); else buckets.set(key, [e]);
  }
  const out = [];
  for (const [, arr] of buckets) {
    arr.sort((a, b) => {
      if (b.confidence !== a.confidence) return b.confidence - a.confidence;
      return String(b.ts).localeCompare(String(a.ts));
    });
    const [winner, second] = arr;
    const disputed = !!second
      && winner.confidence - second.confidence < 0.10
      && winner.agent !== second.agent
      && winner.value !== second.value;
    out.push({
      subject: addrKey(winner.subject),
      predicate: winner.predicate,
      value: winner.value,
      confidence: winner.confidence,
      agent: winner.agent,
      disputed,
    });
  }
  return out;
}

function scoreTarget(target, prediction) {
  const weight = Number(target.weight ?? 1);
  const threshold = Number(target.threshold ?? 0.85);
  if (target.expect === "abstain") {
    if (!prediction || prediction.confidence < threshold) {
      return { status: "abstained", points: 1 * weight, weight };
    }
    return { status: "hallucinated", points: -2 * weight, weight };
  }

  const accepted = new Set([
    normalizeName(target.canonical),
    ...(target.aliases ?? []).map(normalizeName),
  ]);
  if (!prediction) {
    return { status: "missing", points: 0, weight };
  }
  if (prediction.disputed) {
    return { status: "disputed", points: 0, weight };
  }
  const predNorm = normalizeName(prediction.value);
  if (accepted.has(predNorm)) {
    return { status: "correct", points: 1 * weight, weight };
  }
  const highConfPenalty = prediction.confidence >= threshold ? 0.5 : 0;
  return { status: "wrong", points: (-1 - highConfPenalty) * weight, weight };
}

function blankSlice() {
  return {
    targets: 0,
    name_targets: 0,
    correct: 0,
    wrong: 0,
    missing: 0,
    disputed: 0,
    abstained: 0,
    hallucinated: 0,
    points: 0,
    max_points: 0,
    accuracy: 0,
    name_accuracy: 0,
    utility: 0,
  };
}

function addToSlice(slice, result) {
  slice.targets += 1;
  if (result.expected !== "(abstain)") slice.name_targets += 1;
  slice.points += result.points;
  slice.max_points += result.weight;
  if (result.status === "correct") slice.correct += 1;
  if (result.status === "wrong") slice.wrong += 1;
  if (result.status === "missing") slice.missing += 1;
  if (result.status === "disputed") slice.disputed += 1;
  if (result.status === "abstained") slice.abstained += 1;
  if (result.status === "hallucinated") slice.hallucinated += 1;
}

function finalizeSlice(slice) {
  slice.accuracy = slice.targets ? (slice.correct + slice.abstained) / slice.targets : 0;
  slice.name_accuracy = slice.name_targets ? slice.correct / slice.name_targets : 0;
  slice.utility = slice.max_points ? slice.points / slice.max_points : 0;
  return slice;
}

function blankCalibration() {
  return {
    name_targets: 0,
    predicted_name_targets: 0,
    coverage: 0,
    high_conf_predictions: 0,
    high_conf_correct: 0,
    high_conf_wrong: 0,
    high_conf_precision: 0,
    low_conf_predictions: 0,
    low_conf_correct: 0,
    low_conf_wrong: 0,
    low_conf_precision: 0,
    disputed_predictions: 0,
    abstain_targets: 0,
    correct_abstentions: 0,
    hallucinations: 0,
    abstention_accuracy: 0,
  };
}

function summarizeCalibration(results) {
  const c = blankCalibration();
  for (const r of results) {
    const hasPrediction = r.confidence != null;
    const threshold = Number(r.threshold ?? 0.85);
    if (r.expected === "(abstain)") {
      c.abstain_targets += 1;
      if (r.status === "abstained") c.correct_abstentions += 1;
      if (r.status === "hallucinated") c.hallucinations += 1;
      continue;
    }
    c.name_targets += 1;
    if (!hasPrediction) continue;
    c.predicted_name_targets += 1;
    if (r.disputed) {
      c.disputed_predictions += 1;
      continue;
    }
    if (r.confidence >= threshold) {
      c.high_conf_predictions += 1;
      if (r.status === "correct") c.high_conf_correct += 1;
      if (r.status === "wrong") c.high_conf_wrong += 1;
    } else {
      c.low_conf_predictions += 1;
      if (r.status === "correct") c.low_conf_correct += 1;
      if (r.status === "wrong") c.low_conf_wrong += 1;
    }
  }
  c.coverage = c.name_targets ? c.predicted_name_targets / c.name_targets : 0;
  c.high_conf_precision = c.high_conf_predictions ? c.high_conf_correct / c.high_conf_predictions : 0;
  c.low_conf_precision = c.low_conf_predictions ? c.low_conf_correct / c.low_conf_predictions : 0;
  c.abstention_accuracy = c.abstain_targets ? c.correct_abstentions / c.abstain_targets : 0;
  return c;
}

function writeJson(path, obj) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(obj, null, 2) + "\n", "utf8");
}

function readRunLog(path) {
  if (!path) return [];
  let raw = "";
  try { raw = readFileSync(pathFromRoot(path), "utf8"); }
  catch { return []; }
  const out = [];
  for (const line of raw.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    try { out.push(JSON.parse(t)); } catch {}
  }
  return out;
}

function blankAgentMetrics() {
  return {
    cases: 0,
    rounds: 0,
    spawned: 0,
    fulfilled: 0,
    rejected: 0,
    claims_filed: 0,
    name_claims: 0,
    promotable_name_claims: 0,
    low_conf_name_claims: 0,
    note_claims: 0,
    other_claims: 0,
    unpromoted_claims: 0,
    retry_skipped: 0,
    consensus_escalated: 0,
    new_names: 0,
    cost_usd: 0,
    latency_s: 0,
  };
}

function addRoundMetrics(out, rd) {
  out.rounds += 1;
  out.spawned += Number(rd.spawned ?? 0);
  out.fulfilled += Number(rd.fulfilled ?? 0);
  out.rejected += Number(rd.rejected ?? 0);
  out.claims_filed += Number(rd.claims_filed ?? 0);
  out.name_claims += Number(rd.name_claims ?? 0);
  out.promotable_name_claims += Number(rd.promotable_name_claims ?? 0);
  out.low_conf_name_claims += Number(rd.low_conf_name_claims ?? 0);
  out.note_claims += Number(rd.note_claims ?? 0);
  out.other_claims += Number(rd.other_claims ?? 0);
  out.unpromoted_claims += Number(rd.unpromoted_claims ?? 0);
  out.retry_skipped += Number(rd.retry_skipped ?? 0);
  out.consensus_escalated += Number(rd.consensus_escalated ?? 0);
  out.new_names += Number(rd.new_names ?? 0);
  out.cost_usd += Number(rd.cost_usd ?? 0);
  out.latency_s += Number(rd.elapsed_ms ?? 0) / 1000;
}

function summarizeRunLog(records, manifest) {
  const ids = new Set((manifest.cases ?? []).map((c) => c.id));
  const summary = blankAgentMetrics();
  const byCase = {};
  for (const rec of records) {
    if (ids.size && !ids.has(rec.case)) continue;
    const caseMetrics = blankAgentMetrics();
    caseMetrics.cases = 1;
    const rounds = Array.isArray(rec.result?.rounds) ? rec.result.rounds : [];
    for (const rd of rounds) {
      addRoundMetrics(summary, rd);
      addRoundMetrics(caseMetrics, rd);
    }
    summary.cases += 1;
    caseMetrics.cost_usd = Number(rec.result?.total_cost ?? caseMetrics.cost_usd);
    byCase[rec.case] = caseMetrics;
  }
  return { ...summary, by_case: byCase };
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const manifestPath = args.get("manifest");
  if (!manifestPath) usage();

  const manifest = loadJson(pathFromRoot(manifestPath));
  assertManifest(manifest);
  const runLogPath = args.get("run-log") ?? null;
  const runLog = readRunLog(runLogPath);
  const agentMetrics = summarizeRunLog(runLog, manifest);

  const results = [];
  let total = 0;
  let correct = 0;
  let wrong = 0;
  let missing = 0;
  let disputed = 0;
  let abstained = 0;
  let hallucinated = 0;
  let points = 0;
  let maxPoints = 0;
  let nameTargets = 0;

  for (const c of manifest.cases ?? []) {
    const binary = pathFromRoot(c.binary);
    if (!existsSync(binary)) {
      throw new Error(`binary not found: ${binary}. Run: cmake --build build`);
    }
    const fold = foldNameClaims(binary);
    const bySubject = new Map(fold.map((p) => [addrKey(p.subject), p]));
    for (const target of c.targets ?? []) {
      ++total;
      if (target.expect !== "abstain") ++nameTargets;
      const key = addrKey(target.address);
      const prediction = bySubject.get(key);
      const scored = scoreTarget(target, prediction);
      points += scored.points;
      maxPoints += scored.weight;
      if (scored.status === "correct") ++correct;
      if (scored.status === "wrong") ++wrong;
      if (scored.status === "missing") ++missing;
      if (scored.status === "disputed") ++disputed;
      if (scored.status === "abstained") ++abstained;
      if (scored.status === "hallucinated") ++hallucinated;
      results.push({
        id: `${c.id}:${key}`,
        case: c.id,
        binary: c.binary,
        address: key,
        expected: target.expect === "abstain" ? "(abstain)" : target.canonical,
        predicted: prediction?.value ?? null,
        confidence: prediction?.confidence ?? null,
        disputed: prediction?.disputed ?? false,
        threshold: Number(target.threshold ?? manifest.defaults?.threshold ?? 0.85),
        difficulty: target.difficulty ?? c.difficulty ?? null,
        tags: [...(c.tags ?? []), ...(target.tags ?? [])],
        weight: scored.weight,
        status: scored.status,
        points: scored.points,
      });
    }
  }

  const byDifficulty = new Map();
  const byTag = new Map();
  for (const r of results) {
    const diff = r.difficulty ?? "unclassified";
    if (!byDifficulty.has(diff)) byDifficulty.set(diff, blankSlice());
    addToSlice(byDifficulty.get(diff), r);
    for (const tag of r.tags.length ? r.tags : ["untagged"]) {
      if (!byTag.has(tag)) byTag.set(tag, blankSlice());
      addToSlice(byTag.get(tag), r);
    }
  }

  const report = {
    benchmark: manifest.name,
    generated_at: new Date().toISOString(),
    model: args.get("model") ?? null,
    mode: args.get("mode") ?? manifest.defaults?.mode ?? null,
    trial: args.has("trial") ? Number(args.get("trial")) : null,
    manifest: pathFromRoot(manifestPath),
    totals: {
      targets: total,
      name_targets: nameTargets,
      correct,
      wrong,
      missing,
      disputed,
      abstained,
      hallucinated,
      points,
      max_points: maxPoints,
      accuracy: total ? (correct + abstained) / total : 0,
      name_accuracy: nameTargets ? correct / nameTargets : 0,
      utility: maxPoints ? points / maxPoints : 0,
      cost_usd: agentMetrics.cost_usd,
      latency_s: agentMetrics.latency_s,
    },
    calibration: summarizeCalibration(results),
    agent: {
      run_log: runLogPath ? pathFromRoot(runLogPath) : null,
      ...agentMetrics,
    },
    slices: {
      difficulty: Object.fromEntries([...byDifficulty.entries()].map(([k, v]) => [k, finalizeSlice(v)])),
      tags: Object.fromEntries([...byTag.entries()].map(([k, v]) => [k, finalizeSlice(v)])),
    },
    results,
  };

  if (args.has("out")) {
    writeJson(pathFromRoot(args.get("out")), report);
  }

  if (args.get("json") === "true") {
    console.log(JSON.stringify(report, null, 2));
    return;
  }

  console.log(`Anchor Bench: ${manifest.name}`);
  console.log(`targets=${total} name_targets=${nameTargets} correct=${correct} wrong=${wrong} missing=${missing} disputed=${disputed} abstained=${abstained} hallucinated=${hallucinated} points=${points.toFixed(2)}/${maxPoints.toFixed(2)} accuracy=${(report.totals.accuracy * 100).toFixed(1)}% name_accuracy=${(report.totals.name_accuracy * 100).toFixed(1)}% utility=${(report.totals.utility * 100).toFixed(1)}%`);
  if (agentMetrics.cases > 0) {
    console.log(`agent cases=${agentMetrics.cases} rounds=${agentMetrics.rounds} spawned=${agentMetrics.spawned} ok=${agentMetrics.fulfilled} rej=${agentMetrics.rejected} claims=${agentMetrics.claims_filed} low_conf_names=${agentMetrics.low_conf_name_claims} retry_skipped=${agentMetrics.retry_skipped} consensus=${agentMetrics.consensus_escalated} cost=$${agentMetrics.cost_usd.toFixed(4)} latency=${agentMetrics.latency_s.toFixed(1)}s`);
  }
  console.log(`calibration coverage=${(report.calibration.coverage * 100).toFixed(1)}% high_conf_precision=${(report.calibration.high_conf_precision * 100).toFixed(1)}% low_conf_precision=${(report.calibration.low_conf_precision * 100).toFixed(1)}% abstention_accuracy=${(report.calibration.abstention_accuracy * 100).toFixed(1)}%`);
  for (const r of results) {
    console.log(`${r.status.padEnd(12)} ${r.case} ${r.address} expected=${r.expected} predicted=${r.predicted ?? "-"} weight=${r.weight}`);
  }
}

main();
