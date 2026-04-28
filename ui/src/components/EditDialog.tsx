import { useEffect, useMemo, useRef, useState } from "react";
import { C, sans, serif, mono } from "../theme";
import { demangle } from "../api";
import type { FunctionInfo, FunctionSig, ParamSig } from "../types";

type Mode = "rename" | "note" | "signature";

type SignatureValue = {
  name:       string;
  returnType: string;
  params:     ParamSig[];
};

type InitialSignature = {
  name:      string;
  signature: FunctionSig | null;
};

export function EditDialog(props: {
  fn: FunctionInfo;
  mode: Mode;
  // For rename/note: the existing string. For signature: the existing
  // (rename + signature) pair so we can edit both at once.
  initial: string | InitialSignature;
  onSave:  (value: string | SignatureValue) => void;
  onClose: () => void;
  onClear?: () => void;
}) {
  const { fn, mode, initial, onSave, onClose, onClear } = props;

  // Two branches of state based on mode; unused branch is ignored.
  const [stringValue, setStringValue] = useState(
    typeof initial === "string" ? initial : ""
  );
  const [sigValue, setSigValue] = useState<SignatureValue>(() => {
    if (mode !== "signature") return { name: "", returnType: "void", params: [] };
    const ii = initial as InitialSignature;
    return {
      name:       ii.name ?? "",
      returnType: ii.signature?.returnType || "void",
      params:     ii.signature?.params?.map(p => ({ ...p })) ?? [],
    };
  });

  const inputRef = useRef<HTMLInputElement | HTMLTextAreaElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
    if (inputRef.current instanceof HTMLInputElement) {
      inputRef.current.select();
    }
  }, []);

  const submit = () => {
    if (mode === "signature") {
      // Clean empty-trailing param rows before saving.
      const clean: SignatureValue = {
        name:       sigValue.name.trim(),
        returnType: sigValue.returnType.trim() || "void",
        params:     sigValue.params
                      .map(p => ({ type: p.type.trim(), name: p.name.trim() }))
                      .filter(p => p.type.length > 0),
      };
      onSave(clean);
    } else {
      onSave(stringValue.trim());
    }
  };

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.preventDefault(); onClose(); }
      if (e.key === "Enter" && (mode === "rename" || e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        submit();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, stringValue, sigValue, onClose]);

  const title = useMemo(() => ({
    rename:    "Rename function",
    note:      "Note on function",
    signature: "Edit signature",
  }[mode]), [mode]);

  const hasExisting = mode === "signature"
    ? (typeof initial === "object" &&
       initial !== null &&
       ((initial as InitialSignature).name ||
        (initial as InitialSignature).signature))
    : (typeof initial === "string" && initial.length > 0);

  return (
    <div
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(10,10,9,0.55)",
        backdropFilter: "blur(3px)",
        zIndex: 2100,
        display: "flex",
        justifyContent: "center",
        paddingTop: mode === "signature" ? "12vh" : "18vh",
        animation: "fadeIn .12s ease-out",
      }}
    >
      <div
        style={{
          width: mode === "signature" ? 640 : 520,
          maxWidth: "92%",
          maxHeight: "76vh",
          background: C.bgAlt,
          border: `1px solid ${C.borderStrong}`,
          borderRadius: 8,
          boxShadow: "0 24px 60px rgba(0,0,0,0.55)",
          overflow: "hidden",
          display: "flex",
          flexDirection: "column",
        }}
      >
        <div style={{
          padding: "14px 20px",
          borderBottom: `1px solid ${C.border}`,
          display: "flex", alignItems: "baseline", gap: 14,
          flexShrink: 0,
        }}>
          <span style={{ fontFamily: sans, fontSize: 13, fontWeight: 600, color: C.text }}>
            {title}
          </span>
          <span style={{ fontFamily: mono, fontSize: 11, color: C.accent }}>{fn.addr}</span>
          <span style={{
            fontFamily: serif, fontStyle: "italic",
            fontSize: 11, color: C.textMuted,
            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
          }} title={fn.name}>
            {demangle(fn.name)}
          </span>
        </div>

        <div style={{ padding: 20, overflowY: "auto", flex: 1 }}>
          {mode === "rename" && (
            <input
              ref={inputRef as React.RefObject<HTMLInputElement>}
              value={stringValue}
              onChange={(e) => setStringValue(e.target.value)}
              placeholder={demangle(fn.name)}
              style={{
                width: "100%",
                padding: "10px 12px",
                fontFamily: mono, fontSize: 14,
                color: C.text,
                background: C.bgMuted,
                border: `1px solid ${C.border}`,
                borderRadius: 4,
              }}
            />
          )}
          {mode === "note" && (
            <textarea
              ref={inputRef as React.RefObject<HTMLTextAreaElement>}
              value={stringValue}
              onChange={(e) => setStringValue(e.target.value)}
              placeholder="your note here (plain text)"
              rows={6}
              style={{
                width: "100%",
                padding: "10px 12px",
                fontFamily: serif, fontSize: 13,
                color: C.text,
                background: C.bgMuted,
                border: `1px solid ${C.border}`,
                borderRadius: 4,
                resize: "vertical",
                outline: "none",
              }}
            />
          )}
          {mode === "signature" && (
            <SignatureEditor
              value={sigValue}
              setValue={setSigValue}
              inputRef={inputRef as React.RefObject<HTMLInputElement>}
            />
          )}
          <div style={{
            marginTop: 10,
            fontFamily: serif, fontStyle: "italic",
            fontSize: 11, color: C.textFaint,
          }}>
            {mode === "rename"  && "Persists to the project sidecar file. Leave blank to clear."}
            {mode === "note"    && "Persists to the project sidecar file. Shows in the references panel."}
            {mode === "signature" && "Name + return type + typed params. Used in the function's header and in every call site."}
          </div>
        </div>

        <div style={{
          padding: "12px 20px",
          borderTop: `1px solid ${C.border}`,
          display: "flex", justifyContent: "space-between", alignItems: "center",
          gap: 10,
          flexShrink: 0,
        }}>
          <span style={{ fontFamily: mono, fontSize: 10, color: C.textFaint }}>
            {mode === "rename" ? "⏎ save · esc cancel" : "⌘⏎ save · esc cancel"}
          </span>
          <div style={{ display: "flex", gap: 8 }}>
            {hasExisting && onClear && (
              <button
                onClick={() => { onClear(); onClose(); }}
                style={{
                  padding: "6px 14px",
                  fontFamily: sans, fontSize: 12,
                  color: C.red,
                  background: "transparent",
                  border: `1px solid ${C.border}`,
                  borderRadius: 4,
                }}
              >Clear</button>
            )}
            <button
              onClick={onClose}
              style={{
                padding: "6px 14px",
                fontFamily: sans, fontSize: 12,
                color: C.textMuted,
                background: "transparent",
                border: `1px solid ${C.border}`,
                borderRadius: 4,
              }}
            >Cancel</button>
            <button
              onClick={submit}
              style={{
                padding: "6px 16px",
                fontFamily: sans, fontSize: 12, fontWeight: 600,
                color: "#fff",
                background: C.accent,
                border: "none",
                borderRadius: 4,
              }}
            >Save</button>
          </div>
        </div>
      </div>
    </div>
  );
}

// Heuristic plausibility check on a C-ish type string. Rejects empty
// or whitespace-only types but accepts pointer/qualifier-decorated
// names (`const char *`, `void**`, `unsigned long long`, …) and any
// known primitive plus the user-defined word characters Ember tends
// to emit (`u64`, `s32`, `addr_t`). Strict parsing isn't possible —
// the user might be referencing a struct that exists only in the
// target binary.
const KNOWN_TYPES = new Set([
  "void",
  "char", "uchar", "schar", "byte",
  "short", "ushort", "int", "uint", "long", "ulong",
  "size_t", "ssize_t", "ptrdiff_t", "intptr_t", "uintptr_t",
  "u8", "u16", "u32", "u64", "u128",
  "i8", "i16", "i32", "i64", "i128",
  "s8", "s16", "s32", "s64",
  "float", "double", "long double",
  "bool", "wchar_t",
  "addr_t",
  "const", "unsigned", "signed", "volatile", "static",
  "struct", "union", "enum", "auto",
]);

function isPlausibleType(t: string): boolean {
  const trimmed = t.trim();
  if (!trimmed) return true;   // empty = "void" by save convention
  // Strip pointer / array / qualifier decoration to reduce to the
  // base name. `const char *[]` → `char`; `unsigned long long` → keep
  // both tokens.
  const base = trimmed.replace(/[*\[\]]+/g, " ").trim();
  if (!base) return true;
  for (const tok of base.split(/\s+/)) {
    // Identifier-shape tokens (struct / typedef names) pass through;
    // we just sanity-check the regex shape.
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(tok)) return false;
    // Fall-through: any plausible C identifier is accepted. The
    // KNOWN_TYPES set is consulted only to suppress the warning for
    // the most common stdlib + Ember names — we don't reject other
    // identifiers because the user may be naming a target struct.
  }
  return true;
}

function SignatureEditor(props: {
  value: SignatureValue;
  setValue: (v: SignatureValue) => void;
  inputRef: React.RefObject<HTMLInputElement>;
}) {
  const { value, setValue, inputRef } = props;

  const updateParam = (i: number, patch: Partial<ParamSig>) => {
    const params = value.params.map((p, idx) => idx === i ? { ...p, ...patch } : p);
    setValue({ ...value, params });
  };
  const addParam = () => {
    setValue({ ...value, params: [...value.params, { type: "u64", name: `a${value.params.length + 1}` }] });
  };
  const removeParam = (i: number) => {
    setValue({ ...value, params: value.params.filter((_, idx) => idx !== i) });
  };

  const inputStyle: React.CSSProperties = {
    padding: "7px 10px",
    fontFamily: mono, fontSize: 12,
    color: C.text,
    background: C.bgMuted,
    border: `1px solid ${C.border}`,
    borderRadius: 4,
    outline: "none",
  };
  const errStyle: React.CSSProperties = {
    ...inputStyle,
    border: `1px solid rgba(199,93,58,0.4)`,
  };
  const labelStyle: React.CSSProperties = {
    fontFamily: mono, fontSize: 10,
    color: C.textFaint,
    letterSpacing: 0.5,
    textTransform: "uppercase",
    marginBottom: 4,
    display: "block",
  };
  const returnTypeWarn = !isPlausibleType(value.returnType);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <div>
          <span style={labelStyle}>function name</span>
          <input
            ref={inputRef}
            value={value.name}
            onChange={(e) => setValue({ ...value, name: e.target.value })}
            placeholder="my_func"
            style={{ ...inputStyle, width: "100%" }}
          />
        </div>
        <div>
          <span style={labelStyle}>return type</span>
          <input
            value={value.returnType}
            onChange={(e) => setValue({ ...value, returnType: e.target.value })}
            placeholder="void"
            style={{ ...(returnTypeWarn ? errStyle : inputStyle), width: "100%" }}
            aria-invalid={returnTypeWarn}
          />
          {returnTypeWarn && value.returnType.trim() && (
            <span style={{
              fontFamily: serif, fontStyle: "italic",
              fontSize: 10, color: C.red, marginTop: 4, display: "block",
            }}>unfamiliar type — saved verbatim</span>
          )}
        </div>
      </div>

      <div>
        <div style={{
          display: "flex", justifyContent: "space-between", alignItems: "center",
          marginBottom: 6,
        }}>
          <span style={labelStyle as React.CSSProperties}>parameters</span>
          <button
            onClick={addParam}
            style={{
              fontFamily: mono, fontSize: 11,
              color: C.accent,
              background: "transparent",
              border: `1px solid ${C.border}`,
              borderRadius: 4,
              padding: "2px 10px",
            }}
          >+ add</button>
        </div>

        {value.params.length === 0 ? (
          <div style={{
            padding: 12,
            fontFamily: serif, fontStyle: "italic", fontSize: 12, color: C.textFaint,
            textAlign: "center",
            border: `1px dashed ${C.border}`,
            borderRadius: 4,
          }}>
            no parameters — renders as <span style={{ fontFamily: mono }}>(void)</span>
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {value.params.map((p, i) => (
              <div key={i} style={{
                display: "grid",
                gridTemplateColumns: "28px 1fr 1fr 28px",
                gap: 8,
                alignItems: "center",
              }}>
                <span style={{
                  fontFamily: mono, fontSize: 10, color: C.textFaint,
                  textAlign: "right",
                }}>
                  {i + 1}
                </span>
                <input
                  value={p.type}
                  onChange={(e) => updateParam(i, { type: e.target.value })}
                  placeholder="type"
                  style={isPlausibleType(p.type) ? inputStyle : errStyle}
                  aria-invalid={!isPlausibleType(p.type)}
                />
                <input
                  value={p.name}
                  onChange={(e) => updateParam(i, { name: e.target.value })}
                  placeholder="name"
                  style={inputStyle}
                />
                <button
                  onClick={() => removeParam(i)}
                  title="Remove parameter"
                  style={{
                    fontFamily: mono, fontSize: 12,
                    color: C.textFaint,
                    background: "transparent",
                    border: `1px solid ${C.border}`,
                    borderRadius: 4,
                    padding: "4px 0",
                  }}
                >×</button>
              </div>
            ))}
          </div>
        )}
      </div>

      <div style={{
        padding: "8px 10px",
        fontFamily: mono, fontSize: 11,
        color: C.textWarm,
        background: C.bg,
        border: `1px solid ${C.border}`,
        borderRadius: 4,
        overflow: "hidden",
        textOverflow: "ellipsis",
        whiteSpace: "nowrap",
      }}>
        <span style={{ color: "#b0a486" }}>{value.returnType || "void"}</span>
        {" "}
        <span style={{ color: C.accent }}>{value.name || "(anonymous)"}</span>
        <span style={{ color: C.textFaint }}>(</span>
        {value.params.length === 0
          ? <span style={{ color: C.textFaint }}>void</span>
          : value.params.map((p, i) => (
              <span key={i}>
                <span style={{ color: "#b0a486" }}>{p.type || "?"}</span>
                {" "}
                <span style={{ color: C.textWarm }}>{p.name || "_"}</span>
                {i < value.params.length - 1 && <span style={{ color: C.textFaint }}>, </span>}
              </span>
            ))}
        <span style={{ color: C.textFaint }}>)</span>
      </div>
    </div>
  );
}
