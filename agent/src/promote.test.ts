import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { IntelLog, intelPathFor } from "./intel/log.js";
import { promote } from "./promote.js";

// Helper: create a temp "binary" file so intelPathFor's stat() succeeds,
// then point a fresh IntelLog at the same path it'll resolve to.
function setup(): { binary: string; intel: IntelLog; cleanup: () => void } {
    const dir = mkdtempSync(join(tmpdir(), "promote-"));
    const binary = join(dir, "fakebin");
    writeFileSync(binary, "x".repeat(64));
    statSync(binary);  // sanity
    const intel = new IntelLog(intelPathFor(binary));
    // Wipe the resolved path in case another test on the same machine
    // collided — intelPathFor hashes (path|size|mtime), so the dir is
    // unique, but be defensive.
    try { rmSync(intel.path, { force: true }); } catch {}
    return {
        binary,
        intel: new IntelLog(intelPathFor(binary)),
        cleanup() {
            try { rmSync(dir, { recursive: true, force: true }); } catch {}
            try { rmSync(intel.path, { force: true }); } catch {}
        },
    };
}

test("promote: emits [rename] for high-conf name claims", () => {
    const { binary, intel, cleanup } = setup();
    intel.append({
        kind: "claim", id: "1", agent: "namer", ts: "2026-01-01T00:00:00Z",
        subject: "0x401000", predicate: "name", value: "do_thing",
        evidence: "teef:0.95", confidence: 0.95,
    });
    intel.append({
        kind: "claim", id: "2", agent: "namer", ts: "2026-01-02T00:00:00Z",
        subject: "0x402000", predicate: "name", value: "low_conf_skip",
        evidence: "guess", confidence: 0.5,
    });
    const out = join(tmpdir(), `promote-${Date.now()}.ember`);
    const r = promote({
        binary, out, threshold: 0.85, apply: false, dryRun: false,
        emberBin: "/bin/false",
    });
    assert.equal(r.promoted, 1);
    assert.equal(r.skipped_low_conf, 1);
    const script = readFileSync(out, "utf8");
    assert.match(script, /\[rename\]/);
    assert.match(script, /0x401000 = do_thing/);
    assert.doesNotMatch(script, /low_conf_skip/);
    rmSync(out, { force: true });
    cleanup();
});

test("promote: skips disputed even if winner is high-conf", () => {
    const { binary, intel, cleanup } = setup();
    intel.append({
        kind: "claim", id: "1", agent: "alice", ts: "2026-01-01T00:00:00Z",
        subject: "0x401000", predicate: "name", value: "alice_name",
        evidence: "x", confidence: 0.92,
    });
    intel.append({
        kind: "claim", id: "2", agent: "bob", ts: "2026-01-02T00:00:00Z",
        subject: "0x401000", predicate: "name", value: "bob_name",
        evidence: "y", confidence: 0.88,
    });
    const out = join(tmpdir(), `promote-${Date.now()}.ember`);
    const r = promote({
        binary, out, threshold: 0.85, apply: false, dryRun: false,
        emberBin: "/bin/false",
    });
    assert.equal(r.promoted, 0);
    assert.equal(r.skipped_disputed, 1);
    rmSync(out, { force: true });
    cleanup();
});

test("promote: notes go into [note], names into [rename]", () => {
    const { binary, intel, cleanup } = setup();
    intel.append({
        kind: "claim", id: "1", agent: "namer", ts: "2026-01-01T00:00:00Z",
        subject: "0x401000", predicate: "name", value: "thing",
        evidence: "x", confidence: 0.9,
    });
    intel.append({
        kind: "claim", id: "2", agent: "namer", ts: "2026-01-01T00:00:01Z",
        subject: "0x401000", predicate: "note", value: "this is the entry",
        evidence: "y", confidence: 0.9,
    });
    const out = join(tmpdir(), `promote-${Date.now()}.ember`);
    promote({ binary, out, threshold: 0.85, apply: false, dryRun: false, emberBin: "/bin/false" });
    const script = readFileSync(out, "utf8");
    assert.match(script, /\[rename\]\n0x401000 = thing/);
    assert.match(script, /\[note\]\n0x401000 = this is the entry/);
    rmSync(out, { force: true });
    cleanup();
});

test("promote: sanitizes #, newline in value (would break .ember syntax)", () => {
    const { binary, intel, cleanup } = setup();
    intel.append({
        kind: "claim", id: "1", agent: "namer", ts: "2026-01-01T00:00:00Z",
        subject: "0x401000", predicate: "note", value: "first line\nsecond # third",
        evidence: "x", confidence: 0.9,
    });
    const out = join(tmpdir(), `promote-${Date.now()}.ember`);
    promote({ binary, out, threshold: 0.85, apply: false, dryRun: false, emberBin: "/bin/false" });
    const script = readFileSync(out, "utf8");
    assert.doesNotMatch(script, /first line\n.*0x401000/);
    // The literal `#` is replaced with U+266F so the .ember parser doesn't
    // see a comment marker mid-value.
    assert.match(script, /second ♯ third/);
    rmSync(out, { force: true });
    cleanup();
});
