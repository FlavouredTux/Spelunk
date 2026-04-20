import { useEffect, useMemo, useRef, useState } from "react";
import { C, sans, mono, serif } from "../theme";
import { assemble, bytesToHex } from "../asm";

type Mode = "asm" | "hex";

// Modal for editing a single byte patch. Two input modes:
//   asm — type x86-64 assembly (multi-line); branch targets are
//         absolute addresses, the assembler resolves them to rel32
//         against the patch site.
//   hex — raw bytes, space-tolerant (the original IDA-style entry).
// Length warning surfaces matches / shorter / clobbers-next so
// you don't accidentally overrun the next instruction.
export function PatchDialog(props: {
  vaddr:    number;
  origBytes: string;
  disasm:   string;
  onSave:   (vaddrHex: string, bytesHex: string) => void;
  onRevert?: () => void;
  onClose:  () => void;
}) {
  const stripped = props.origBytes.replace(/\s+/g, "").toUpperCase();
  const origLen  = stripped.length / 2;

  const [mode,    setMode]    = useState<Mode>("asm");
  const [hexDraft, setHexDraft] = useState(stripped);
  const [asmDraft, setAsmDraft] = useState("");
  const inputHexRef = useRef<HTMLInputElement>(null);
  const inputAsmRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    if (mode === "hex") { inputHexRef.current?.focus(); inputHexRef.current?.select(); }
    else                 { inputAsmRef.current?.focus(); }
  }, [mode]);

  // Resolve the current draft into a canonical hex string + status.
  const resolved = useMemo(() => {
    if (mode === "hex") {
      const cleaned  = hexDraft.replace(/\s+/g, "").toUpperCase();
      const validHex = /^[0-9A-F]*$/.test(cleaned);
      const evenHex  = cleaned.length > 0 && cleaned.length % 2 === 0;
      return {
        hex:    cleaned,
        ok:     validHex && evenHex,
        errors: !validHex ? ["non-hex characters"]
              : (cleaned.length > 0 && !evenHex) ? ["odd hex digit count"]
              : [],
      };
    }
    const r = assemble(asmDraft, props.vaddr);
    return {
      hex:    bytesToHex(r.bytes),
      ok:     r.errs.length === 0 && r.bytes.length > 0,
      errors: r.errs.map(e => `line ${e.line + 1}: ${e.error}`),
    };
  }, [mode, hexDraft, asmDraft, props.vaddr]);

  const newLen   = resolved.ok ? resolved.hex.length / 2 : 0;
  const lenDelta = newLen - origLen;

  const submit = () => {
    if (!resolved.ok) return;
    props.onSave(`0x${props.vaddr.toString(16)}`, resolved.hex);
  };

  const nopFill = () => {
    if (mode === "hex") setHexDraft("90".repeat(origLen).toUpperCase());
    else                 setAsmDraft(Array(origLen).fill("nop").join("\n"));
  };

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.preventDefault(); props.onClose(); }
      // Cmd/Ctrl+Enter to submit (plain Enter would be a newline in
      // the asm textarea).
      if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        submit();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, hexDraft, asmDraft]);

  return (
    <div
      onMouseDown={(e) => { if (e.target === e.currentTarget) props.onClose(); }}
      style={{
        position: "fixed", inset: 0,
        background: "rgba(10,10,9,0.55)",
        backdropFilter: "blur(3px)",
        zIndex: 2100,
        display: "flex", justifyContent: "center", paddingTop: "14vh",
        animation: "fadeIn .12s ease-out",
      }}
    >
      <div style={{
        width: 560, maxWidth: "92%",
        background: C.bgAlt,
        border: `1px solid ${C.borderStrong}`,
        borderRadius: 8,
        boxShadow: "0 24px 60px rgba(0,0,0,0.55)",
        overflow: "hidden",
        display: "flex", flexDirection: "column",
      }}>
        <div style={{
          padding: "14px 20px",
          borderBottom: `1px solid ${C.border}`,
          display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap",
        }}>
          <span style={{ fontFamily: sans, fontSize: 13, fontWeight: 600, color: C.text }}>
            Patch instruction
          </span>
          <span style={{ fontFamily: mono, fontSize: 11, color: C.accent }}>
            0x{props.vaddr.toString(16)}
          </span>
          <span style={{
            fontFamily: serif, fontStyle: "italic",
            fontSize: 11, color: C.textMuted,
            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
            maxWidth: 280,
          }} title={props.disasm}>
            {props.disasm}
          </span>
          <span style={{ flex: 1 }} />
          <ModeToggle mode={mode} onChange={setMode} />
        </div>

        <div style={{ padding: 20 }}>
          <div style={{
            fontFamily: mono, fontSize: 10, color: C.textMuted,
            marginBottom: 6,
            display: "flex", alignItems: "baseline", gap: 8,
          }}>
            <span>original</span>
            <span style={{ color: C.textFaint, textDecoration: "line-through" }}>
              {props.origBytes || "(empty)"}
            </span>
            <span style={{ color: C.textFaint }}>·</span>
            <span style={{ color: C.textFaint }}>{origLen} byte{origLen === 1 ? "" : "s"}</span>
          </div>

          {mode === "hex" ? (
            <input
              ref={inputHexRef}
              value={hexDraft}
              onChange={(e) => setHexDraft(e.target.value.toUpperCase())}
              placeholder="hex bytes, e.g. 90 90 90"
              spellCheck={false}
              autoCapitalize="off"
              autoCorrect="off"
              style={{
                width: "100%",
                padding: "10px 12px",
                fontFamily: mono, fontSize: 13,
                color: C.text, background: C.bgMuted,
                border: `1px solid ${resolved.ok ? C.border : C.red}`,
                borderRadius: 4, boxSizing: "border-box", outline: "none",
              }}
            />
          ) : (
            <>
              <textarea
                ref={inputAsmRef}
                value={asmDraft}
                onChange={(e) => setAsmDraft(e.target.value)}
                placeholder={`xor eax, eax\nret`}
                spellCheck={false}
                autoCapitalize="off"
                autoCorrect="off"
                rows={5}
                style={{
                  width: "100%",
                  padding: "10px 12px",
                  fontFamily: mono, fontSize: 13,
                  color: C.text, background: C.bgMuted,
                  border: `1px solid ${resolved.errors.length === 0 ? C.border : C.red}`,
                  borderRadius: 4, boxSizing: "border-box",
                  outline: "none", resize: "vertical",
                }}
              />
              {/* Live bytes preview — what we'd write to the sidecar. */}
              <div style={{
                marginTop: 6,
                padding: "6px 10px",
                fontFamily: mono, fontSize: 10,
                color: C.textMuted,
                background: C.bg,
                border: `1px solid ${C.border}`,
                borderRadius: 4,
                minHeight: 20,
                wordBreak: "break-all",
              }}>
                {resolved.hex
                  ? (resolved.hex.match(/.{1,2}/g) || []).join(" ")
                  : <span style={{ color: C.textFaint, fontStyle: "italic" }}>bytes appear here</span>}
              </div>
            </>
          )}

          <div style={{
            display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap",
            marginTop: 8,
            fontFamily: mono, fontSize: 10,
          }}>
            {resolved.errors.map((m, i) => (
              <span key={i} style={{ color: C.red }}>{m}</span>
            ))}
            {resolved.ok && lenDelta === 0 && (
              <span style={{ color: C.green }}>{newLen} byte{newLen === 1 ? "" : "s"} · matches</span>
            )}
            {resolved.ok && lenDelta < 0 && (
              <span style={{ color: C.textMuted }}>
                {newLen} byte{newLen === 1 ? "" : "s"} · {-lenDelta} short of original
                {" "}<span style={{ color: C.textFaint }}>(later bytes untouched)</span>
              </span>
            )}
            {resolved.ok && lenDelta > 0 && (
              <span style={{ color: "#dba85a" }}>
                {newLen} byte{newLen === 1 ? "" : "s"} · {lenDelta} past original
                {" "}<span style={{ color: C.textFaint }}>(clobbers next instruction)</span>
              </span>
            )}
            <span style={{ flex: 1 }} />
            <button
              type="button"
              onClick={nopFill}
              style={{
                padding: "4px 10px",
                background: C.bgMuted, color: C.textMuted,
                border: `1px solid ${C.border}`, borderRadius: 4,
                fontFamily: mono, fontSize: 10, cursor: "pointer",
              }}
            >NOP fill</button>
          </div>
        </div>

        <div style={{
          display: "flex", gap: 8, justifyContent: "flex-end",
          padding: "12px 20px",
          borderTop: `1px solid ${C.border}`,
          background: C.bg,
        }}>
          {props.onRevert && (
            <button
              type="button"
              onClick={() => { props.onRevert!(); props.onClose(); }}
              style={{
                padding: "6px 14px",
                background: "transparent", color: C.red,
                border: `1px solid ${C.red}`, borderRadius: 4,
                fontFamily: mono, fontSize: 11, cursor: "pointer",
                marginRight: "auto",
              }}
            >revert patch</button>
          )}
          <button
            type="button"
            onClick={props.onClose}
            style={{
              padding: "6px 14px",
              background: "transparent", color: C.textMuted,
              border: `1px solid ${C.border}`, borderRadius: 4,
              fontFamily: mono, fontSize: 11, cursor: "pointer",
            }}
          >cancel</button>
          <button
            type="button"
            onClick={submit}
            disabled={!resolved.ok}
            style={{
              padding: "6px 14px",
              background: resolved.ok ? C.accent : C.bgMuted,
              color:      resolved.ok ? "#fff"   : C.textMuted,
              border: "none", borderRadius: 4,
              fontFamily: mono, fontSize: 11, fontWeight: 600,
              cursor: resolved.ok ? "pointer" : "not-allowed",
            }}
          >apply patch</button>
        </div>
      </div>
    </div>
  );
}

function ModeToggle(props: { mode: Mode; onChange: (m: Mode) => void }) {
  return (
    <div style={{
      display: "flex",
      background: C.bgMuted,
      border: `1px solid ${C.border}`,
      borderRadius: 4,
      overflow: "hidden",
    }}>
      {(["asm", "hex"] as const).map((m, i) => {
        const active = m === props.mode;
        return (
          <button
            key={m}
            type="button"
            onClick={() => props.onChange(m)}
            style={{
              padding: "3px 10px",
              background: active ? C.accent : "transparent",
              color: active ? "#fff" : C.textMuted,
              border: "none",
              borderLeft: i > 0 ? `1px solid ${C.border}` : "none",
              fontFamily: mono, fontSize: 10,
              fontWeight: active ? 600 : 400,
              cursor: "pointer",
            }}
          >{m}</button>
        );
      })}
    </div>
  );
}
