// Generic reverse-engineering query dispatcher.
//
//   ember --script scripts/query.js <binary> -- <command> [args...]
//
// Addresses accept decimal or 0x-prefixed hex.

const COMMANDS = {
    "info":            cmd_info,
    "imports":         cmd_imports,
    "sections":        cmd_sections,
    "section-of":      cmd_section_of,
    "bytes":           cmd_bytes,
    "disasm":          cmd_disasm,
    "func":            cmd_func,
    "pseudo-c":        cmd_pseudo_c,
    "xrefs-to":        cmd_xrefs_to,
    "callers":         cmd_callers,
    "callees":         cmd_callees,
    "callers-chain":   cmd_callers_chain,
    "callees-chain":   cmd_callees_chain,
    "strings":         cmd_strings,
    "string-xrefs":    cmd_string_xrefs,
    "find-func":       cmd_find_func,
    "find-bytes":      cmd_find_bytes,
    "string-at":       cmd_string_at,
};

function parseAddr(s) {
    if (s === undefined) return null;
    return BigInt(s);
}

function hex(n) {
    return "0x" + BigInt(n).toString(16);
}

function fmtSymKind(s) {
    return (s.kind + "       ").slice(0, 8);
}

function cmd_info() {
    print(`format   ${binary.format}`);
    print(`arch     ${binary.arch}`);
    print(`entry    ${hex(binary.entry)}`);
    const secs = binary.sections();
    const syms = binary.symbols();
    const imports = syms.filter(s => s.isImport).length;
    const defined = syms.length - imports;
    print(`sections ${secs.length}`);
    print(`defined  ${defined}`);
    print(`imports  ${imports}`);
}

function cmd_imports(args) {
    const re = args[0] ? new RegExp(args[0]) : null;
    for (const s of binary.symbols()) {
        if (!s.isImport) continue;
        if (re && !re.test(s.name)) continue;
        print(`${hex(s.addr).padStart(12)}  ${s.name}`);
    }
}

function cmd_sections() {
    for (const s of binary.sections()) {
        const p = (s.readable ? "r" : "-") +
                  (s.writable ? "w" : "-") +
                  (s.executable ? "x" : "-");
        print(`${p}  ${hex(s.addr).padStart(18)}  size=${hex(s.size).padStart(8)}  ${s.name}`);
    }
}

function cmd_section_of(args) {
    const a = parseAddr(args[0]);
    for (const s of binary.sections()) {
        if (a >= s.addr && a < s.addr + s.size) {
            print(`${s.name}  [${hex(s.addr)}..${hex(s.addr + s.size)})`);
            return;
        }
    }
    print("(no containing section)");
}

function cmd_bytes(args) {
    const a = parseAddr(args[0]);
    const n = args[1] ? Number(args[1]) : 32;
    const buf = new Uint8Array(binary.bytesAt(a, n));
    const hx = Array.from(buf).map(b => b.toString(16).padStart(2, "0")).join(" ");
    print(`${hex(a)}: ${hx}`);
}

function cmd_disasm(args) {
    const a = parseAddr(args[0]);
    // Second arg is a rough instruction count; 8 bytes/insn is the typical avg.
    const nBytes = args[1] ? Number(args[1]) * 8 : 240;
    print(binary.disasm(a, nBytes).trimEnd());
}

function cmd_func(args) {
    const a = parseAddr(args[0]);
    print(binary.cfg(a).trimEnd());
}

function cmd_pseudo_c(args) {
    const a = parseAddr(args[0]);
    print(binary.decompile(a).trimEnd());
}

function cmd_xrefs_to(args) {
    const a = parseAddr(args[0]);
    for (const x of xrefs.to(a)) {
        print(`${hex(x.addr).padStart(12)}  ${x.name}`);
    }
}

function cmd_callers(args) {
    const a = parseAddr(args[0]);
    for (const x of xrefs.callers(a)) {
        print(`${hex(x.addr).padStart(12)}  ${x.name}`);
    }
}

function cmd_callees(args) {
    const a = parseAddr(args[0]);
    for (const x of xrefs.callees(a)) {
        print(`${hex(x.addr).padStart(12)}  ${x.name}`);
    }
}

function walkChain(startAddr, depth, fetch) {
    const visited = new Set();
    function rec(a, d, indent) {
        const key = a.toString(16);
        if (visited.has(key)) {
            print(`${indent}${hex(a)}  (cycle)`);
            return;
        }
        visited.add(key);
        const edges = fetch(a);
        if (edges.length === 0) return;
        for (const x of edges) {
            print(`${indent}${hex(x.addr).padStart(12)}  ${x.name}`);
            if (d > 1) rec(x.addr, d - 1, indent + "  ");
        }
    }
    rec(startAddr, depth, "");
}

function cmd_callers_chain(args) {
    const a = parseAddr(args[0]);
    const d = args[1] ? Number(args[1]) : 3;
    walkChain(a, d, addr => xrefs.callers(addr));
}

function cmd_callees_chain(args) {
    const a = parseAddr(args[0]);
    const d = args[1] ? Number(args[1]) : 3;
    walkChain(a, d, addr => xrefs.callees(addr));
}

function cmd_strings(args) {
    const re = new RegExp(args[0] || ".");
    for (const e of strings.search(re)) {
        print(`${hex(e.addr).padStart(12)}  ${JSON.stringify(e.text)}`);
    }
}

function cmd_string_xrefs(args) {
    const re = new RegExp(args[0] || ".");
    for (const e of strings.xrefs(re)) {
        print(`${hex(e.addr)}  ${JSON.stringify(e.text)}`);
        for (const x of e.xrefs) print(`    ref @ ${hex(x)}`);
    }
}

function cmd_find_func(args) {
    const re = new RegExp(args[0] || ".", "i");
    for (const s of binary.symbols()) {
        if (s.isImport) continue;
        if (s.kind !== "function") continue;
        if (!re.test(s.name)) continue;
        print(`${hex(s.addr).padStart(12)}  ${s.name}`);
    }
}

function cmd_find_bytes(args) {
    if (!args[0]) { log.error("find-bytes: missing hex pattern"); throw new Error("usage"); }
    const max = args[1] ? Number(args[1]) : 64;
    const hits = binary.findBytes(args[0], max);
    for (const a of hits) print(hex(a));
}

function cmd_string_at(args) {
    const a = parseAddr(args[0]);
    const max = args[1] ? Number(args[1]) : 1024;
    const s = binary.stringAt(a, max);
    if (s === null) { print("(not a string)"); return; }
    print(`${hex(a)}  ${JSON.stringify(s)}`);
}

// --- dispatch ---
const [cmd, ...rest] = argv;
if (!cmd || !(cmd in COMMANDS)) {
    log.error(`usage: query.js <cmd> [args]; known: ${Object.keys(COMMANDS).join(", ")}`);
    throw new Error(`unknown command: ${cmd ?? "(none)"}`);
}
COMMANDS[cmd](rest);
