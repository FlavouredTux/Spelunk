import { test } from "node:test";
import { strict as assert } from "node:assert";

import {
    consensusNameCandidates,
    formatCascadePlan,
    selectCascadeBatch,
    summarizeRoundClaims,
} from "./cascade.js";
import type { Claim } from "./intel/log.js";

test("cascade plan formatter emits readable target rows", () => {
    const lines = formatCascadePlan({
        scope: "list:0x1000",
        policy: "bottom_up_v1",
        candidates: 1,
        eligible: 1,
        selected: 1,
        top: [{
            addr: "0x1000",
            score: 113.25,
            ratio: 1,
            callees: 2,
            callers: 3,
            unresolved_callees: 0,
            size: 64,
            features: {
                known_callee_ratio: 1,
                known_callees: 2,
                total_callees: 2,
                caller_count: 3,
                unresolved_callee_count: 0,
                size: 64,
                is_leaf: false,
            },
            reasons: ["all callees known", "3 callers", "64 bytes"],
        }],
    });

    assert.match(lines[0], /scope=list:0x1000/);
    assert.match(lines[0], /policy=bottom_up_v1/);
    assert.match(lines[1], /0x1000/);
    assert.match(lines[1], /score=113\.3/);
    assert.match(lines[1], /all callees known/);
});

test("cascade round claim summary separates low-confidence signal from promotions", () => {
    const base = {
        kind: "claim" as const,
        id: "c0",
        agent: "agent-a",
        ts: "2026-05-14T00:00:00.000Z",
        subject: "0x1000",
        evidence: "test",
    };
    const claims: Claim[] = [
        { ...base, id: "c1", predicate: "name", value: "maybe_parse", confidence: 0.74 },
        { ...base, id: "c2", predicate: "name", value: "parse_packet", confidence: 0.91 },
        { ...base, id: "c3", predicate: "note", value: "looks parser-ish", confidence: 0.60 },
        { ...base, id: "c4", predicate: "tag", value: "io", confidence: 0.88 },
    ];

    assert.deepEqual(summarizeRoundClaims(claims, 0.85), {
        claims_filed: 4,
        name_claims: 2,
        promotable_name_claims: 1,
        low_conf_name_claims: 1,
        note_claims: 1,
        other_claims: 1,
        unpromoted_claims: 2,
    });
});

test("cascade batch selection skips retry-saturated low-confidence targets", () => {
    const plan = {
        scope: "all",
        candidates: 3,
        eligible: 3,
        selected: 3,
        top: [
            { addr: "0x1000", score: 30, ratio: 1, callees: 0, callers: 0, unresolved_callees: 0, size: 16, reasons: [] },
            { addr: "0x2000", score: 20, ratio: 1, callees: 0, callers: 0, unresolved_callees: 0, size: 16, reasons: [] },
            { addr: "0x3000", score: 10, ratio: 1, callees: 0, callers: 0, unresolved_callees: 0, size: 16, reasons: [] },
        ],
    };

    const selected = selectCascadeBatch({
        plan,
        perRound: 1,
        lowConfAttempts: new Map([["0x1000", 2]]),
        maxLowConfRetries: 2,
    });

    assert.deepEqual(selected.skipped.map((t) => t.addr), ["0x1000"]);
    assert.deepEqual(selected.batch.map((t) => t.addr), ["0x2000"]);
    assert.deepEqual(selected.consensus.map((t) => t.addr), []);
});

test("cascade consensus lets one retry-saturated target through", () => {
    const base = {
        kind: "claim" as const,
        id: "c0",
        agent: "agent-a",
        ts: "2026-05-14T00:00:00.000Z",
        subject: "0x1000",
        predicate: "name",
        evidence: "test",
    };
    const claims: Claim[] = [
        { ...base, id: "c1", value: "validate_short_string", confidence: 0.74 },
        { ...base, id: "c2", value: "validate_short_string", confidence: 0.84 },
        { ...base, id: "c3", value: "other_guess", confidence: 0.70 },
    ];
    const consensus = consensusNameCandidates(claims, 0.85);
    const plan = {
        scope: "all",
        candidates: 2,
        eligible: 2,
        selected: 2,
        top: [
            { addr: "0x1000", score: 30, ratio: 1, callees: 0, callers: 0, unresolved_callees: 0, size: 16, reasons: [] },
            { addr: "0x2000", score: 20, ratio: 1, callees: 0, callers: 0, unresolved_callees: 0, size: 16, reasons: [] },
        ],
    };

    assert.equal(consensus.get("0x1000")?.value, "validate_short_string");

    const selected = selectCascadeBatch({
        plan,
        perRound: 1,
        lowConfAttempts: new Map([["0x1000", 3]]),
        consensusCandidates: consensus,
        consensusEscalated: new Set(),
        maxLowConfRetries: 2,
    });

    assert.deepEqual(selected.batch.map((t) => t.addr), ["0x1000"]);
    assert.deepEqual(selected.consensus.map((t) => t.addr), ["0x1000"]);
    assert.deepEqual(selected.skipped.map((t) => t.addr), []);
});
