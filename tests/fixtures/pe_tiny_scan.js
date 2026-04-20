// Exercise the read-only scripting surface on the pe_tiny fixture.
// Verifies that the PeBinary loader populates every field downstream
// consumers read: format, arch, entry, sections with flags, symbols
// (imports + exports + PDATA-synthesized), and bytesAt.

print("format:", binary.format);
print("arch:  ", binary.arch);
print("entry: ", "0x" + binary.entry.toString(16));

print("sections:");
for (const s of binary.sections()) {
    const flags =
        (s.readable   ? "R" : "-") +
        (s.writable   ? "W" : "-") +
        (s.executable ? "X" : "-");
    print("  " + s.name + " " + flags +
          " vaddr=0x" + s.addr.toString(16) +
          " size=0x"  + s.size.toString(16));
}

print("symbols:");
const syms = [...binary.symbols()].sort((a, b) => {
    if (a.isImport !== b.isImport) return a.isImport ? -1 : 1;
    if (a.addr < b.addr) return -1;
    if (a.addr > b.addr) return  1;
    return 0;
});
for (const s of syms) {
    const kind = s.isImport ? "import" : (s.isExport ? "export" : "local ");
    const addr = s.addr ? "0x" + s.addr.toString(16) : "—";
    const got  = s.gotAddr ? " got=0x" + s.gotAddr.toString(16) : "";
    print("  " + kind + " " + addr + " " + s.name + got);
}

// bytesAt on the entry point should return the first instruction bytes
// (48 83 ec 28 = `sub rsp, 0x28`).
const head = new Uint8Array(binary.bytesAt(binary.entry, 4));
const hex = Array.from(head).map(b => b.toString(16).padStart(2, "0")).join(" ");
print("entry bytes:", hex);
