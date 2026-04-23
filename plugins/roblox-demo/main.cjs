// Phase-1 demo plugin. The manifest's string-present matcher on
// "RBX::Logger" means this plugin only lights up on Roblox-family
// binaries — on anything else the Settings card shows a muted badge
// and the command requires an explicit run-anyway confirm.
//
// The command itself is intentionally tiny: find every xref of the
// "RBX::Logger" string in scope and propose a note on each so the
// corresponding function shows up in the sidebar's note filter. It's
// a toy, but end-to-end it proves: matcher → host context read →
// proposal emission → annotation apply.

async function activate() {
  return {
    commands: [
      {
        id: "note-rbx-logger-sites",
        title: "Note RBX::Logger call sites",
        description: "Annotate every function that references the RBX::Logger string.",
        permissions: ["read.strings", "read.annotations", "project.note"],
        async run(ctx) {
          const [strings, annotations] = await Promise.all([
            ctx.loadStrings(),
            ctx.loadAnnotations(),
          ]);

          const hits = strings.filter((s) => s.text.includes("RBX::Logger"));
          const proposals = [];
          const seen = new Set();
          for (const s of hits) {
            for (const xref of s.xrefs) {
              const addrHex = `0x${xref.toString(16)}`;
              if (seen.has(addrHex)) continue;
              seen.add(addrHex);
              if (annotations.notes[addrHex]) continue;
              proposals.push(ctx.proposalBuilders.note(addrHex, "references RBX::Logger", {
                confidence: 0.9,
                reason: `xref of "${s.text.slice(0, 48)}" (@ ${s.addr})`,
              }));
            }
          }

          return {
            summary: proposals.length
              ? `Prepared ${proposals.length} note proposal${proposals.length === 1 ? "" : "s"} for RBX::Logger sites.`
              : "No RBX::Logger references found in scope.",
            notes: "Phase-1 demo plugin: proves matcher + note-proposal path end-to-end.",
            proposals,
          };
        },
      },
    ],
  };
}

module.exports = { activate };
