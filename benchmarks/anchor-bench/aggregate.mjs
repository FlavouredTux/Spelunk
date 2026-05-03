#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

function parseArgs(argv) {
  const out = { reports: [] };
  for (let i = 0; i < argv.length; ++i) {
    const a = argv[i];
    if (a === "--out") {
      out.out = argv[++i];
    } else if (a.startsWith("--out=")) {
      out.out = a.slice("--out=".length);
    } else {
      out.reports.push(a);
    }
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));
if (!args.out || args.reports.length === 0) {
  console.error("usage: aggregate.mjs --out leaderboard.json report-a.json report-b.json ...");
  process.exit(2);
}

const reports = args.reports.map((p) => JSON.parse(readFileSync(p, "utf8")));
const byKey = new Map();
for (const r of reports) {
  const key = `${r.benchmark}|${r.model ?? "unknown"}|${r.mode ?? "unknown"}`;
  const arr = byKey.get(key);
  if (arr) arr.push(r); else byKey.set(key, [r]);
}

function mean(xs) {
  return xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : 0;
}

function stddev(xs) {
  if (xs.length <= 1) return 0;
  const m = mean(xs);
  return Math.sqrt(xs.reduce((s, x) => s + (x - m) ** 2, 0) / (xs.length - 1));
}

function sum(xs) {
  return xs.reduce((a, b) => a + b, 0);
}

const entries = [...byKey.values()].map((rs) => {
  const first = rs[0];
  const accuracies = rs.map((r) => r.totals.accuracy);
  const nameAccuracies = rs.map((r) => r.totals.name_accuracy ?? r.totals.accuracy);
  const utilities = rs.map((r) => r.totals.utility);
  return {
    model: first.model ?? "unknown",
    mode: first.mode ?? "unknown",
    benchmark: first.benchmark,
    generated_at: rs.map((r) => r.generated_at).sort().at(-1),
    trials: rs.length,
    targets: first.totals.targets,
    name_targets: first.totals.name_targets ?? first.totals.targets,
    accuracy: mean(accuracies),
    accuracy_stddev: stddev(accuracies),
    name_accuracy: mean(nameAccuracies),
    name_accuracy_stddev: stddev(nameAccuracies),
    utility: mean(utilities),
    utility_stddev: stddev(utilities),
    points: mean(rs.map((r) => r.totals.points)),
    max_points: first.totals.max_points,
    correct: mean(rs.map((r) => r.totals.correct)),
    wrong: mean(rs.map((r) => r.totals.wrong)),
    missing: mean(rs.map((r) => r.totals.missing)),
    disputed: mean(rs.map((r) => r.totals.disputed)),
    abstained: mean(rs.map((r) => r.totals.abstained)),
    hallucinated: mean(rs.map((r) => r.totals.hallucinated)),
    hallucinated_total: sum(rs.map((r) => r.totals.hallucinated)),
    reports: rs.map((r) => ({
      generated_at: r.generated_at,
      trial: r.trial,
      accuracy: r.totals.accuracy,
      name_accuracy: r.totals.name_accuracy ?? r.totals.accuracy,
      utility: r.totals.utility,
      points: r.totals.points,
      correct: r.totals.correct,
      wrong: r.totals.wrong,
      missing: r.totals.missing,
      hallucinated: r.totals.hallucinated,
    })),
    slices: first.slices,
  };
});

entries.sort((a, b) => {
  if (b.utility !== a.utility) return b.utility - a.utility;
  if (b.accuracy !== a.accuracy) return b.accuracy - a.accuracy;
  return a.hallucinated - b.hallucinated;
});

const leaderboard = {
  name: "Anchor Bench",
  generated_at: new Date().toISOString(),
  entries,
};

const out = resolve(args.out);
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, JSON.stringify(leaderboard, null, 2) + "\n", "utf8");
console.log(`wrote ${out} (${entries.length} entries)`);
