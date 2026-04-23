// Demo plugin for the Ember plugin harness. Exercises matchers, the
// enriched host context (summary + strings), proposal emission, and a
// contributed inspection panel. The manifest's string-present matcher
// on "RBX::Logger" means the plugin only lights up on Roblox-family
// binaries; on anything else the Settings badge is muted and commands
// require an explicit run-anyway confirm.
//
// Two commands:
//   - `list-logger-sites`   backs the "RBX::Logger sites" panel. Pure
//                           read-only; returns one row per function
//                           that references the string.
//   - `note-rbx-logger-sites`  same discovery, but emits note proposals
//                              so the sidebar's note filter surfaces
//                              the matched functions.

function collectLoggerSites(summary, strings) {
  const hits = strings.filter((s) => s.text.includes("RBX::Logger"));
  const sites = new Map(); // fnAddrHex -> { addr, label, detail }
  for (const str of hits) {
    for (const xref of str.xrefs) {
      const fn = findContainingFunction(summary.functions, xref);
      const addrHex = fn ? fn.addr : `0x${xref.toString(16)}`;
      if (sites.has(addrHex)) continue;
      sites.set(addrHex, {
        addr: addrHex,
        label: fn ? fn.name : addrHex,
        detail: `"${str.text.slice(0, 64)}" @ ${str.addr}`,
      });
    }
  }
  return Array.from(sites.values());
}

function findContainingFunction(functions, ip) {
  for (const f of functions) {
    if (f.size > 0 && ip >= f.addrNum && ip < f.addrNum + f.size) return f;
  }
  return null;
}

async function activate() {
  return {
    commands: [
      {
        id: "list-logger-sites",
        title: "List RBX::Logger sites",
        description: "Enumerate every function that references the RBX::Logger string.",
        permissions: ["read.binary-summary", "read.strings"],
        async run(ctx) {
          const [summary, strings] = await Promise.all([
            ctx.loadSummary(),
            ctx.loadStrings(),
          ]);
          const rows = collectLoggerSites(summary, strings);
          return {
            summary: rows.length
              ? `${rows.length} function${rows.length === 1 ? "" : "s"} reference RBX::Logger.`
              : "No RBX::Logger references found in scope.",
            notes: "Click a row to jump to its pseudo-C. Panels are read-only.",
            panel: { kind: "list", rows },
          };
        },
      },
      {
        id: "note-rbx-logger-sites",
        title: "Note RBX::Logger call sites",
        description: "Annotate every function that references the RBX::Logger string.",
        permissions: ["read.binary-summary", "read.strings", "read.annotations", "project.note"],
        async run(ctx) {
          const [summary, strings, annotations] = await Promise.all([
            ctx.loadSummary(),
            ctx.loadStrings(),
            ctx.loadAnnotations(),
          ]);
          const sites = collectLoggerSites(summary, strings);
          const proposals = [];
          for (const s of sites) {
            if (annotations.notes[s.addr]) continue;
            proposals.push(ctx.proposalBuilders.note(s.addr, "references RBX::Logger", {
              confidence: 0.9,
              reason: s.detail,
            }));
          }
          return {
            summary: proposals.length
              ? `Prepared ${proposals.length} note proposal${proposals.length === 1 ? "" : "s"} for RBX::Logger sites.`
              : "No new RBX::Logger notes to propose.",
            notes: "Demo plugin: proves matcher + note-proposal path end-to-end.",
            proposals,
          };
        },
      },
    ],
  };
}

module.exports = { activate };
