// Move function names across binary versions via address-independent
// fingerprints. Same code compiled into a later build → same fingerprint,
// so names learned once carry forward automatically.
//
//   ember --script scripts/names.js <binary> -- dump
//     Print `<addr>\t<fingerprint>\t<blocks>\t<insts>\t<calls>\t<name>` for
//     every discovered function. No --project needed.
//
//   ember --script scripts/names.js <binary> -- export <db.tsv>
//     Write `<fingerprint>\t<name>` for every currently-named function
//     (anything not called sub_*) to <db.tsv>. No --project needed.
//
//   ember --script scripts/names.js <binary> --project <proj> -- import <db.tsv>
//     Read the TSV, fingerprint every function here, stage project.rename
//     for anything whose fingerprint matches. Requires --project.
//
// TSV columns for export/import:
//   <fingerprint-hex> \t <name> [\t <signature-or-empty> \t <note-or-empty>]
// Lines starting with '#' and blank lines are ignored on import.

function hex(n) { return "0x" + BigInt(n).toString(16); }

function escapeTsv(s) {
    return (s ?? "").replaceAll("\t", " ").replaceAll("\n", " ");
}

function isSubName(name) {
    return /^sub_[0-9a-f]+$/.test(name);
}

function fingerprintAll() {
    const out = [];
    for (const fn of binary.functions()) {
        const fp = binary.fingerprint(fn.addr);
        out.push({ addr: fn.addr, name: fn.name, fp });
    }
    return out;
}

function cmdDump() {
    const rows = fingerprintAll();
    print("# addr\tfingerprint\tblocks\tinsts\tcalls\tname");
    for (const r of rows) {
        if (!r.fp) continue;
        print(`${hex(r.addr)}\t${r.fp.hash}\t${r.fp.blocks}\t${r.fp.insts}\t${r.fp.calls}\t${r.name}`);
    }
}

function cmdExport(args) {
    const path = args[0];
    if (!path) throw new Error("export: missing <db.tsv>");
    let out = "# fingerprint\tname\tsig\tnote\n";
    let written = 0;
    for (const r of fingerprintAll()) {
        if (!r.fp) continue;
        if (isSubName(r.name)) continue;
        out += `${r.fp.hash}\t${escapeTsv(r.name)}\t\t\n`;
        ++written;
    }
    io.write(path, out);
    log.info(`wrote ${written} entries to ${path}`);
}

function parseDb(text) {
    const byFp = new Map();
    let dupes = 0;
    for (const raw of text.split("\n")) {
        const line = raw.replace(/\r$/, "");
        if (!line || line.startsWith("#")) continue;
        const parts = line.split("\t");
        const fp = parts[0];
        const name = parts[1];
        if (!fp || !name) continue;
        if (byFp.has(fp)) { ++dupes; continue; }
        byFp.set(fp, { name, sig: parts[2] || "", note: parts[3] || "" });
    }
    if (dupes > 0) log.warn(`db has ${dupes} duplicate fingerprint rows; first-wins`);
    return byFp;
}

function cmdImport(args) {
    const path = args[0];
    if (!path) throw new Error("import: missing <db.tsv>");
    const db = parseDb(io.read(path));
    log.info(`loaded ${db.size} entries from ${path}`);

    // Build a reverse index: fingerprint -> [addrs in this binary].
    // A DB entry whose fingerprint matches N>1 binary functions is
    // ambiguous — blindly renaming all of them to the same name silently
    // aliases them and the next find_by_name returns the wrong one. Cost
    // real debugging hours for one user; skip + warn instead.
    const rows = fingerprintAll();
    const fpToAddrs = new Map();
    for (const r of rows) {
        if (!r.fp) continue;
        const list = fpToAddrs.get(r.fp.hash);
        if (list) list.push(r.addr);
        else fpToAddrs.set(r.fp.hash, [r.addr]);
    }

    let renamed = 0;
    let collisions = 0;        // binary function already has a different name
    let alreadyNamed = 0;
    let ambiguous = 0;         // fingerprint maps to >1 candidate — skipped

    for (const r of rows) {
        if (!r.fp) continue;
        const entry = db.get(r.fp.hash);
        if (!entry) continue;
        if (!isSubName(r.name)) {
            if (r.name !== entry.name) {
                log.warn(`${hex(r.addr)}: already named ${r.name} (db says ${entry.name})`);
                ++collisions;
            } else {
                ++alreadyNamed;
            }
            continue;
        }
        const siblings = fpToAddrs.get(r.fp.hash) ?? [];
        if (siblings.length > 1) {
            // Report once, when we hit the first sibling. The rest of
            // the group advances the counter without re-logging.
            if (siblings[0] === r.addr) {
                const addrs = siblings.slice(0, 5).map(hex).join(", ");
                const suffix = siblings.length > 5 ? `, ... (+${siblings.length - 5})` : "";
                log.warn(`fingerprint ${r.fp.hash} matches ${siblings.length} candidates (${addrs}${suffix}); skipping '${entry.name}' — use a stricter anchor`);
            }
            ++ambiguous;
            continue;
        }
        project.rename(r.addr, entry.name);
        if (entry.note) project.note(r.addr, entry.note);
        ++renamed;
    }

    if (renamed > 0) {
        print(project.diff());
        project.commit();
        log.info(`applied ${renamed}, kept ${alreadyNamed}, ${collisions} name-collisions, ${ambiguous} ambiguous`);
    } else {
        log.info(`nothing to apply; ${alreadyNamed} already-named, ${collisions} name-collisions, ${ambiguous} ambiguous`);
    }
}

// --- dispatch ---
const COMMANDS = { dump: cmdDump, export: cmdExport, import: cmdImport };
const [cmd, ...rest] = argv;
if (!cmd || !(cmd in COMMANDS)) {
    log.error(`usage: names.js <dump|export|import> [path]`);
    throw new Error(`unknown command: ${cmd ?? "(none)"}`);
}
COMMANDS[cmd](rest);
