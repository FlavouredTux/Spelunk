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
  const labelStyle: React.CSSProperties = {
    fontFamily: mono, fontSize: 10,
    color: C.textFaint,
    letterSpacing: 0.5,
    textTransform: "uppercase",
    marginBottom: 4,
    display: "block",
  };

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
            style={{ ...inputStyle, width: "100%" }}
          />
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
                  style={inputStyle}
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
