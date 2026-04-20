import { useEffect, useRef, useState } from "react";
import { C, sans, mono, serif } from "../theme";

// Modal for editing a single byte patch. The user lands here from a
// right-click on an asm-view instruction. We pre-fill with the current
// bytes (already reflecting in-flight patches via the CLI temp-file
// routing), offer a one-click NOP preset, and show a length warning
// when the patch differs from the original instruction's length —
// shorter is fine (a NOP fill is a common pattern), longer means
// later instructions get clobbered.
export function PatchDialog(props: {
  vaddr:    number;     // virtual address of the instruction
  origBytes: string;    // existing bytes, space-separated hex pairs
  disasm:   string;     // mnemonic preview, used as a hint
  onSave:   (vaddrHex: string, bytesHex: string) => void;
  onRevert?: () => void;        // present when there's already a patch at this addr
  onClose:  () => void;
}) {
  // Normalise to "9090C3" form for editing convenience; we re-pretty
  // the value on display.
  const stripped = props.origBytes.replace(/\s+/g, "").toUpperCase();
  const [draft, setDraft] = useState(stripped);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
    inputRef.current?.select();
  }, []);

  const cleaned   = draft.replace(/\s+/g, "").toUpperCase();
  const validHex  = /^[0-9A-F]*$/.test(cleaned);
  const evenHex   = cleaned.length > 0 && cleaned.length % 2 === 0;
  const ok        = validHex && evenHex;
  const newLen    = ok ? cleaned.length / 2 : 0;
  const origLen   = stripped.length / 2;
  const lenDelta  = newLen - origLen;

  const submit = () => {
    if (!ok) return;
    props.onSave(`0x${props.vaddr.toString(16)}`, cleaned);
  };

  // NOP fill the original instruction length so the new bytes line up
  // with the existing instruction boundary — common case for "kill
  // this conditional" / "skip this call" patches.
  const nopFill = () => setDraft("90".repeat(origLen).toUpperCase());

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.preventDefault(); props.onClose(); }
      if (e.key === "Enter")  { e.preventDefault(); submit(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draft]);

  return (
    <div
      onMouseDown={(e) => { if (e.target === e.currentTarget) props.onClose(); }}
      style={{
        position: "fixed", inset: 0,
        background: "rgba(10,10,9,0.55)",
        backdropFilter: "blur(3px)",
        zIndex: 2100,
        display: "flex", justifyContent: "center", paddingTop: "18vh",
        animation: "fadeIn .12s ease-out",
      }}
    >
      <div style={{
        width: 520, maxWidth: "92%",
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
          display: "flex", alignItems: "baseline", gap: 12, flexWrap: "wrap",
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
          <input
            ref={inputRef}
            value={draft}
            onChange={(e) => setDraft(e.target.value.toUpperCase())}
            placeholder="hex bytes, e.g. 90 90 90"
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
            style={{
              width: "100%",
              padding: "10px 12px",
              fontFamily: mono, fontSize: 13,
              color: C.text,
              background: C.bgMuted,
              border: `1px solid ${ok ? C.border : C.red}`,
              borderRadius: 4,
              boxSizing: "border-box",
              outline: "none",
            }}
          />

          <div style={{
            display: "flex", alignItems: "center", gap: 10,
            marginTop: 8,
            fontFamily: mono, fontSize: 10,
          }}>
            {!validHex && (
              <span style={{ color: C.red }}>non-hex characters</span>
            )}
            {validHex && cleaned.length > 0 && !evenHex && (
              <span style={{ color: C.red }}>odd hex digit count</span>
            )}
            {ok && lenDelta === 0 && (
              <span style={{ color: C.green }}>{newLen} byte{newLen === 1 ? "" : "s"} · matches</span>
            )}
            {ok && lenDelta < 0 && (
              <span style={{ color: C.textMuted }}>
                {newLen} byte{newLen === 1 ? "" : "s"} · {-lenDelta} short of original
                {" "}<span style={{ color: C.textFaint }}>(later bytes untouched)</span>
              </span>
            )}
            {ok && lenDelta > 0 && (
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
            disabled={!ok}
            style={{
              padding: "6px 14px",
              background: ok ? C.accent : C.bgMuted,
              color:      ok ? "#fff"   : C.textMuted,
              border: "none", borderRadius: 4,
              fontFamily: mono, fontSize: 11, fontWeight: 600,
              cursor: ok ? "pointer" : "not-allowed",
            }}
          >apply patch</button>
        </div>
      </div>
    </div>
  );
}
