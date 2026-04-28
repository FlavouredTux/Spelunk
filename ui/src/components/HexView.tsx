import { useEffect, useRef, useState, useCallback } from "react";
import { C, sans, mono, serif } from "../theme";
import { readBytes, vaddrToOffset } from "../api";
import type { BinaryInfo, FunctionInfo } from "../types";

const ROW_BYTES = 16;
const ROW_PX    = 20;
const PAGE_BYTES = 4096;
const OVERSCAN_ROWS = 40;

export function HexView(props: {
  info: BinaryInfo;
  current: FunctionInfo | null;
  onClose: () => void;
}) {
  const { info, current, onClose } = props;

  const [totalSize, setTotalSize] = useState(0);
  // File-offset of the visible window's first byte. Drives reads and
  // is the unit of jump-to navigation.
  const [scrollTop, setScrollTop] = useState(0);
  const [viewH, setViewH] = useState(600);
  const scrollerRef = useRef<HTMLDivElement>(null);

  // Loaded bytes keyed by page-aligned file offset. Sparse so a 1 GB
  // binary doesn't materialize a 1 GB array — the user only ever sees
  // the rows in the current viewport plus a small overscan.
  const [pages, setPages] = useState<Map<number, Uint8Array>>(new Map());
  // Base-N input. Hex with optional 0x prefix. Empty => not jumping.
  const [jumpInput, setJumpInput] = useState("");
  const [jumpAsVaddr, setJumpAsVaddr] = useState(true);
  const [jumpError, setJumpError] = useState<string | null>(null);

  // Boot: get the file size so we know how far we can scroll.
  useEffect(() => {
    let cancel = false;
    readBytes(0, 1).then((r) => { if (!cancel) setTotalSize(r.totalSize); }).catch(() => {});
    return () => { cancel = true; };
  }, [info.path]);

  useEffect(() => {
    const el = scrollerRef.current;
    if (!el) return;
    const onScroll = () => setScrollTop(el.scrollTop);
    el.addEventListener("scroll", onScroll, { passive: true });
    const ro = new ResizeObserver(() => setViewH(el.clientHeight));
    ro.observe(el);
    setViewH(el.clientHeight);
    return () => { el.removeEventListener("scroll", onScroll); ro.disconnect(); };
  }, []);

  const totalRows = Math.max(1, Math.ceil(totalSize / ROW_BYTES));
  const firstRow  = Math.max(0, Math.floor(scrollTop / ROW_PX) - OVERSCAN_ROWS);
  const lastRow   = Math.min(totalRows, Math.ceil((scrollTop + viewH) / ROW_PX) + OVERSCAN_ROWS);

  // Fetch any pages overlapping the visible row range that we don't
  // already have. Pages are 4 KB so a typical 1024-px window covers 1
  // page (or 2 across a boundary). Fire-and-forget — the render falls
  // back to "·" placeholders for any byte the page hasn't arrived for.
  useEffect(() => {
    const startPage = Math.floor((firstRow * ROW_BYTES) / PAGE_BYTES);
    const endPage   = Math.floor((lastRow  * ROW_BYTES) / PAGE_BYTES);
    let cancel = false;
    (async () => {
      for (let p = startPage; p <= endPage; p++) {
        const off = p * PAGE_BYTES;
        if (pages.has(off)) continue;
        try {
          const r = await readBytes(off, PAGE_BYTES);
          if (cancel) return;
          setPages((prev) => {
            if (prev.has(off)) return prev;
            const next = new Map(prev);
            next.set(off, r.bytes);
            return next;
          });
        } catch { /* short read at EOF — let placeholder render */ }
      }
    })();
    return () => { cancel = true; };
  }, [firstRow, lastRow, pages, info.path]);

  const byteAt = useCallback((offset: number): number | null => {
    const pageOff = Math.floor(offset / PAGE_BYTES) * PAGE_BYTES;
    const page    = pages.get(pageOff);
    if (!page) return null;
    const idx = offset - pageOff;
    if (idx >= page.length) return null;
    return page[idx];
  }, [pages]);

  // Map a file offset back to a virtual address using the in-memory
  // section table. We look for a section whose vaddr range, when
  // shifted by (vaddr - foff), would land at this offset. Cheap and
  // good-enough for ELF; PE/Mach-O fall back to "—" when there's no
  // matching segment.
  const offsetToVaddr = useCallback((offset: number): string => {
    for (const s of info.sections) {
      const v = parseInt(s.vaddr, 16);
      const sz = parseInt(s.size, 16);
      if (!Number.isFinite(v) || !Number.isFinite(sz)) continue;
      if (offset >= v && offset < v + sz) {
        // Identity mapping: typical for ELF executable sections where
        // p_offset == p_vaddr, and a useful approximation otherwise.
        return "0x" + offset.toString(16);
      }
    }
    return "—";
  }, [info.sections]);

  const jump = useCallback(async (raw: string) => {
    setJumpError(null);
    const trimmed = raw.trim();
    if (!trimmed) return;
    const isHex = /^0x/i.test(trimmed) || /^[0-9a-fA-F]+$/.test(trimmed);
    if (!isHex) { setJumpError("not a hex value"); return; }
    const n = parseInt(trimmed.replace(/^0x/i, ""), 16);
    if (!Number.isFinite(n)) { setJumpError("not a hex value"); return; }
    let foff: number | null = n;
    if (jumpAsVaddr) {
      foff = await vaddrToOffset(n);
      if (foff == null) {
        setJumpError(`vaddr 0x${n.toString(16)} not in any loaded segment`);
        return;
      }
    }
    if (foff < 0 || foff >= totalSize) {
      setJumpError(`offset 0x${(foff ?? 0).toString(16)} out of range`);
      return;
    }
    if (scrollerRef.current) {
      const row = Math.floor(foff / ROW_BYTES);
      scrollerRef.current.scrollTop = row * ROW_PX - viewH / 3;
    }
  }, [jumpAsVaddr, totalSize, viewH]);

  // Auto-jump to current function on first open.
  const sentRef = useRef(false);
  useEffect(() => {
    if (sentRef.current) return;
    if (totalSize === 0) return;
    if (!current) return;
    sentRef.current = true;
    jump("0x" + current.addrNum.toString(16));
  }, [totalSize, current, jump]);

  return (
    <div
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}
      style={{
        position: "fixed", inset: 0,
        background: "rgba(10,10,9,0.55)",
        backdropFilter: "blur(3px)",
        zIndex: 1900,
        display: "flex", justifyContent: "center",
        padding: "5vh 4vw",
        animation: "fadeIn .15s ease-out",
      }}
    >
      <div
        style={{
          flex: 1, maxWidth: 1100,
          display: "flex", flexDirection: "column",
          background: C.bg,
          border: `1px solid ${C.borderStrong}`,
          borderRadius: 8,
          boxShadow: "0 30px 80px rgba(0,0,0,0.6)",
          overflow: "hidden",
        }}
      >
        <div style={{
          padding: "12px 18px", borderBottom: `1px solid ${C.border}`,
          background: C.bgAlt,
          display: "flex", alignItems: "center", gap: 14,
        }}>
          <div style={{ display: "flex", flexDirection: "column", lineHeight: 1.2 }}>
            <span style={{ fontFamily: sans, fontSize: 13, fontWeight: 600, color: C.text }}>
              Hex view
            </span>
            <span style={{ fontFamily: serif, fontStyle: "italic", fontSize: 11, color: C.textMuted, marginTop: 2 }}>
              raw bytes · {(totalSize / 1024).toFixed(1)} KB · file offset
            </span>
          </div>
          <div style={{ flex: 1 }} />
          <div style={{
            display: "flex", alignItems: "center", gap: 8,
            padding: "5px 10px",
            background: C.bgMuted,
            border: `1px solid ${C.border}`,
            borderRadius: 4,
          }}>
            <span style={{ fontFamily: mono, fontSize: 10, color: C.textFaint }}>
              jump
            </span>
            <button
              onClick={() => setJumpAsVaddr(!jumpAsVaddr)}
              title="Toggle interpretation of the input"
              aria-label="Toggle vaddr / file-offset jump mode"
              style={{
                fontFamily: mono, fontSize: 10,
                color: jumpAsVaddr ? C.accent : C.textMuted,
                padding: "2px 6px",
                border: `1px solid ${C.border}`, borderRadius: 3,
              }}
            >{jumpAsVaddr ? "vaddr" : "foff"}</button>
            <input
              value={jumpInput}
              onChange={(e) => { setJumpInput(e.target.value); setJumpError(null); }}
              onKeyDown={(e) => { if (e.key === "Enter") jump(jumpInput); }}
              placeholder={jumpAsVaddr ? "0x401234" : "0x1230"}
              style={{
                width: 130,
                fontFamily: mono, fontSize: 12,
                color: C.text,
              }}
            />
            <button
              onClick={() => jump(jumpInput)}
              style={{
                padding: "3px 10px",
                fontFamily: mono, fontSize: 10, color: C.accent,
                border: `1px solid ${C.border}`, borderRadius: 3,
              }}
            >go</button>
          </div>
          <button
            onClick={onClose}
            style={{
              padding: "4px 10px",
              fontFamily: mono, fontSize: 10, color: C.textMuted,
              background: C.bgMuted,
              border: `1px solid ${C.border}`, borderRadius: 4,
            }}
          >close</button>
        </div>

        {jumpError && (
          <div style={{
            padding: "6px 18px",
            background: "rgba(199,93,58,0.08)",
            borderBottom: "1px solid rgba(199,93,58,0.18)",
            fontFamily: mono, fontSize: 11, color: C.red,
          }}>{jumpError}</div>
        )}

        <div
          ref={scrollerRef}
          className="sel"
          style={{
            flex: 1, overflow: "auto",
            fontFamily: mono, fontSize: 11.5, lineHeight: `${ROW_PX}px`,
            padding: "8px 0",
          }}
        >
          <div style={{ height: firstRow * ROW_PX }} />
          {Array.from({ length: lastRow - firstRow }, (_, i) => {
            const rowIdx = firstRow + i;
            const offset = rowIdx * ROW_BYTES;
            return (
              <HexRow
                key={rowIdx}
                offset={offset}
                byteAt={byteAt}
                offsetToVaddr={offsetToVaddr}
              />
            );
          })}
          <div style={{ height: Math.max(0, (totalRows - lastRow) * ROW_PX) }} />
        </div>
      </div>
    </div>
  );
}

function HexRow(props: {
  offset: number;
  byteAt: (offset: number) => number | null;
  offsetToVaddr: (offset: number) => string;
}) {
  const { offset, byteAt, offsetToVaddr } = props;
  const cells: string[] = [];
  const ascii: string[] = [];
  let allUnloaded = true;
  for (let i = 0; i < ROW_BYTES; i++) {
    const b = byteAt(offset + i);
    if (b == null) {
      cells.push("··");
      ascii.push("·");
      continue;
    }
    allUnloaded = false;
    cells.push(b.toString(16).padStart(2, "0"));
    ascii.push(b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".");
  }
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        height: ROW_PX,
        padding: "0 18px",
        gap: 24,
        opacity: allUnloaded ? 0.3 : 1,
      }}
    >
      <span style={{
        width: 96, color: C.textFaint, fontVariantNumeric: "tabular-nums",
        flexShrink: 0,
      }} title={`vaddr ${offsetToVaddr(offset)}`}>
        {offset.toString(16).padStart(8, "0")}
      </span>
      <span style={{
        flex: 1, color: C.textWarm, letterSpacing: 1,
        whiteSpace: "pre",
      }}>
        {cells.slice(0, 8).join(" ")}{"  "}{cells.slice(8).join(" ")}
      </span>
      <span style={{
        width: 144, color: C.textMuted, whiteSpace: "pre",
        borderLeft: `1px solid ${C.border}`, paddingLeft: 12,
        flexShrink: 0,
      }}>
        {ascii.join("")}
      </span>
    </div>
  );
}
