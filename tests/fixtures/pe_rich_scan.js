print("format:", binary.format);
print("arch:  ", binary.arch);
print("entry: ", "0x" + binary.entry.toString(16));

print("symbols:");
for (const s of [...binary.symbols()].sort((a, b) => {
    if (a.isImport !== b.isImport) return a.isImport ? -1 : 1;
    if (a.addr < b.addr) return -1;
    if (a.addr > b.addr) return 1;
    return a.name.localeCompare(b.name);
})) {
    const kind =
        s.isImport ? "import" :
        s.isExport ? "export" :
        "local ";
    const addr = s.addr ? "0x" + s.addr.toString(16) : "—";
    const got = s.gotAddr ? " got=0x" + s.gotAddr.toString(16) : "";
    print("  " + kind + " " + addr + " " + s.name + got);
}

const head = new Uint8Array(binary.bytesAt(binary.entry, 8));
print("entry bytes:", Array.from(head).map(b => b.toString(16).padStart(2, "0")).join(" "));
