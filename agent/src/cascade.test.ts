import { test } from "node:test";
import { strict as assert } from "node:assert";

import { formatCascadePlan } from "./cascade.js";

test("cascade plan formatter emits readable target rows", () => {
    const lines = formatCascadePlan({
        scope: "list:0x1000",
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
            reasons: ["all callees known", "3 callers", "64 bytes"],
        }],
    });

    assert.match(lines[0], /scope=list:0x1000/);
    assert.match(lines[1], /0x1000/);
    assert.match(lines[1], /score=113\.3/);
    assert.match(lines[1], /all callees known/);
});
