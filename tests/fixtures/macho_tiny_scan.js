// Exercises the scripting API against the macho_tiny fixture:
//   - binary.{arch, format, entry}
//   - binary.sections(), binary.symbols(), findSymbol, symbolAt, bytesAt
// Output is deterministic so it can be used as a golden.

print(`arch=${binary.arch}`);
print(`format=${binary.format}`);
print(`entry=0x${binary.entry.toString(16)}`);

const secs = binary.sections();
print(`sections: ${secs.length}`);
for (const s of secs) {
  const perms = (s.readable ? "r" : "-") + (s.writable ? "w" : "-") + (s.executable ? "x" : "-");
  print(`  ${perms}  0x${s.addr.toString(16)}  size=0x${s.size.toString(16)}  ${s.name}`);
}

const syms = binary.symbols().filter(s => !s.isImport);
print(`defined symbols: ${syms.length}`);
for (const s of syms) {
  print(`  0x${s.addr.toString(16)}  size=0x${s.size.toString(16)}  ${s.kind}  ${s.name}`);
}

const m = binary.findSymbol("main");
print(`main.addr = 0x${m.addr.toString(16)}`);

const bytes = new Uint8Array(binary.bytesAt(m.addr, 6));
const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join(" ");
print(`main bytes: ${hex}`);

const at = binary.symbolAt(m.addr);
print(`symbolAt(main.addr) = ${at.name}`);
