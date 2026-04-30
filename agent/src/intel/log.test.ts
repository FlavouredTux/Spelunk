import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { IntelLog, newId } from "./log.js";

function tmp(): string {
    return join(mkdtempSync(join(tmpdir(), "intel-")), "log.jsonl");
}

test("fold: single claim wins as undisputed", () => {
    const path = tmp();
    const log = new IntelLog(path);
    log.append({
        kind: "claim", id: "a1", agent: "alice", ts: "2026-01-01T00:00:00Z",
        subject: "0x1000", predicate: "name", value: "foo",
        evidence: "x", confidence: 0.9,
    });
    const v = log.fold();
    assert.equal(v.size, 1);
    const d = v.get("0x1000|name")!;
    assert.equal(d.winner.value, "foo");
    assert.equal(d.disputed, false);
    rmSync(path, { force: true });
});

test("fold: max-confidence wins, recency tiebreak", () => {
    const path = tmp();
    const log = new IntelLog(path);
    log.append({
        kind: "claim", id: "a1", agent: "alice", ts: "2026-01-01T00:00:00Z",
        subject: "0x1000", predicate: "name", value: "low_conf",
        evidence: "x", confidence: 0.7,
    });
    log.append({
        kind: "claim", id: "a2", agent: "bob", ts: "2026-01-02T00:00:00Z",
        subject: "0x1000", predicate: "name", value: "high_conf",
        evidence: "y", confidence: 0.95,
    });
    log.append({
        kind: "claim", id: "a3", agent: "carol", ts: "2026-01-03T00:00:00Z",
        subject: "0x1000", predicate: "name", value: "tied_recent",
        evidence: "z", confidence: 0.95,
    });
    const d = log.fold().get("0x1000|name")!;
    // tied at 0.95; carol's claim is more recent, wins
    assert.equal(d.winner.value, "tied_recent");
    rmSync(path, { force: true });
});

test("fold: retraction drops a claim from view", () => {
    const path = tmp();
    const log = new IntelLog(path);
    log.append({
        kind: "claim", id: "wrong", agent: "alice", ts: "2026-01-01T00:00:00Z",
        subject: "0x1000", predicate: "name", value: "wrong_name",
        evidence: "x", confidence: 0.95,
    });
    log.append({
        kind: "claim", id: "right", agent: "bob", ts: "2026-01-02T00:00:00Z",
        subject: "0x1000", predicate: "name", value: "right_name",
        evidence: "y", confidence: 0.85,
    });
    log.append({
        kind: "retract", id: "r1", agent: "carol", ts: "2026-01-03T00:00:00Z",
        target_id: "wrong", reason: "verified wrong",
    });
    const d = log.fold().get("0x1000|name")!;
    assert.equal(d.winner.value, "right_name");
    assert.equal(d.runners_up.length, 0);
    rmSync(path, { force: true });
});

test("disputes: detected when top two within 0.10, different agents, different values", () => {
    const path = tmp();
    const log = new IntelLog(path);
    log.append({
        kind: "claim", id: "a1", agent: "alice", ts: "2026-01-01T00:00:00Z",
        subject: "0x1000", predicate: "name", value: "name_a",
        evidence: "x", confidence: 0.92,
    });
    log.append({
        kind: "claim", id: "a2", agent: "bob", ts: "2026-01-02T00:00:00Z",
        subject: "0x1000", predicate: "name", value: "name_b",
        evidence: "y", confidence: 0.88,
    });
    const ds = log.disputes();
    assert.equal(ds.length, 1);
    assert.equal(ds[0].winner.value, "name_a");
    rmSync(path, { force: true });
});

test("disputes: NOT detected when same agent (self-supersede)", () => {
    const path = tmp();
    const log = new IntelLog(path);
    log.append({
        kind: "claim", id: "a1", agent: "alice", ts: "2026-01-01T00:00:00Z",
        subject: "0x1000", predicate: "name", value: "first_guess",
        evidence: "x", confidence: 0.8,
    });
    log.append({
        kind: "claim", id: "a2", agent: "alice", ts: "2026-01-02T00:00:00Z",
        subject: "0x1000", predicate: "name", value: "better_guess",
        evidence: "y", confidence: 0.85,
    });
    assert.equal(log.disputes().length, 0);
    rmSync(path, { force: true });
});

test("disputes: NOT detected when values match (same name, different reasoning)", () => {
    const path = tmp();
    const log = new IntelLog(path);
    log.append({
        kind: "claim", id: "a1", agent: "alice", ts: "2026-01-01T00:00:00Z",
        subject: "0x1000", predicate: "name", value: "parse_header",
        evidence: "x", confidence: 0.9,
    });
    log.append({
        kind: "claim", id: "a2", agent: "bob", ts: "2026-01-02T00:00:00Z",
        subject: "0x1000", predicate: "name", value: "parse_header",
        evidence: "y", confidence: 0.85,
    });
    assert.equal(log.disputes().length, 0);
    rmSync(path, { force: true });
});

test("newId: 12 hex chars, unique on rapid calls", () => {
    const ids = new Set<string>();
    for (let i = 0; i < 1000; ++i) ids.add(newId());
    assert.equal(ids.size, 1000);
    for (const id of ids) {
        assert.match(id, /^[0-9a-f]{12}$/);
    }
});
