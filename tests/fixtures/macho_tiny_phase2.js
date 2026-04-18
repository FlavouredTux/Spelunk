// Exercises analysis, xrefs, strings, and project APIs against macho_tiny.
// Output is deterministic — pinned by the macho_tiny_script_phase2 golden.

const main = binary.findSymbol("main");
print(`main=0x${main.addr.toString(16)}`);

const dis = binary.disasm(main.addr, 6);
const disLines = dis.split("\n").filter(l => l.startsWith("0x")).length;
print(`disasm.lines=${disLines}`);

const cfg = binary.cfg(main.addr);
for (const l of cfg.split("\n")) {
  if (l.startsWith("  blocks") || l.startsWith("  calls") || l.startsWith("  edges")) {
    print(l.trim());
  }
}

const dec = binary.decompile(main.addr);
print(`decompile.has_return_0x2a=${/return\s+0x2a/.test(dec)}`);

print(`callees(main)=${xrefs.callees(main.addr).length}`);
print(`callers(main)=${xrefs.callers(main.addr).length}`);
print(`to(main)=${xrefs.to(main.addr).length}`);

// macho_tiny has no data section, so both are empty.
print(`strings.search=${strings.search(".").length}`);
print(`strings.xrefs=${strings.xrefs(".").length}`);

const dry = project.rename(main.addr, "entry_main", { dryRun: true });
print(`dry: ${dry.kind} 0x${dry.addr.toString(16)} ${dry.detail}`);
print(`pending_after_dry=${project.diff().length}`);

project.rename(main.addr, "entry_main");
project.note(main.addr, "program start");
project.setSignature(main.addr, {
  returnType: "int",
  params: [{ type: "int", name: "argc" }, { type: "char **", name: "argv" }],
});

const diff = project.diff().slice().sort((a, b) => a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : 0);
print(`pending=${diff.length}`);
for (const d of diff) {
  print(`  ${d.kind} 0x${d.addr.toString(16)} ${d.detail}`);
}

print(`committed=${project.commit()}`);
print(`post_commit_pending=${project.diff().length}`);
