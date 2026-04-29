import { useState } from "react";
import { C, sans, serif, mono } from "../theme";
import type { ViewKind } from "../types";

// Recognise common ember CLI failure modes and turn them into a panel
// the user can act on: friendly explanation, a one-click switch into
// the view that's most useful given the failure, and the raw error
// tucked behind "show details" for when the friendly text isn't
// enough.
type Pattern = {
  match: (msg: string) => boolean;
  title: string;
  body: string;
  // Optional CTA: switch to a different view that's more likely to
  // produce something useful. e.g. when pseudo-C fails to decode,
  // raw asm at least shows the bytes + per-byte decode errors.
  suggest?: { label: string; view: ViewKind };
};

const PATTERNS: Pattern[] = [
  {
    match: (m) => /failed to decode any instructions/i.test(m),
    title: "No decodable code at this address",
    body:
      "The bytes here aren't valid x86-64 instructions. " +
      "This usually means the binary is packed or protected (Themida, VMProtect, …) " +
      "and the real code only exists in memory at runtime. " +
      "It can also mean the symbol points at data — some toolchains leave function records " +
      "for stripped or merged helpers.",
    suggest: { label: "view raw bytes", view: "asm" },
  },
  {
    match: (m) =>
      /no mapped bytes at entry/i.test(m) ||
      /not in any mapped section/i.test(m),
    title: "Nothing to decompile here",
    body:
      "This address isn't inside any loaded section, so the file has no bytes for ember " +
      "to read. Common causes: a stripped import thunk, a malformed symbol record, or " +
      "(on obfuscated binaries) a garbage indirect-jump target the call-graph walker " +
      "picked up. Pick a different function from the list.",
  },
  {
    match: (m) => /ambiguous/i.test(m),
    title: "Ambiguous symbol",
    body:
      "Several addresses share this symbol — usually C++ template specialisations or " +
      "`.constprop` / `.cold` clones with the same mangled name. Pick a specific entry " +
      "from the function list.",
  },
];

export function ErrorView(props: {
  message: string;
  currentView: ViewKind;
  onSwitchView: (v: ViewKind) => void;
}) {
  const [showDetails, setShowDetails] = useState(false);
  const hit = PATTERNS.find((p) => p.match(props.message));

  // Generic fallback — keeps the original raw-error rendering for
  // anything we haven't classified yet, just in a slightly nicer card.
  if (!hit) {
    return (
      <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", padding: 32 }}>
        <div
          style={{
            maxWidth: 520, padding: 20,
            background: "rgba(199,93,58,0.06)",
            border: "1px solid rgba(199,93,58,0.25)",
            borderRadius: 4,
            fontFamily: mono, fontSize: 12, color: C.red,
            whiteSpace: "pre-wrap",
          }}
        >
          {props.message}
        </div>
      </div>
    );
  }

  const canSuggest = hit.suggest && hit.suggest.view !== props.currentView;

  return (
    <div
      style={{
        flex: 1, display: "flex",
        alignItems: "center", justifyContent: "center",
        padding: 32,
      }}
    >
      <div
        style={{
          maxWidth: 560, width: "100%",
          background: C.bgAlt,
          border: `1px solid ${C.borderStrong}`,
          borderRadius: 8,
          overflow: "hidden",
        }}
      >
        <div
          style={{
            padding: "16px 20px 14px",
            borderBottom: `1px solid ${C.border}`,
            display: "flex", alignItems: "baseline", gap: 12,
          }}
        >
          <span
            style={{
              fontFamily: mono, fontSize: 10,
              color: C.accent, letterSpacing: 1,
            }}
          >
            HEADS UP
          </span>
          <span style={{ fontFamily: sans, fontSize: 14, fontWeight: 600, color: C.text }}>
            {hit.title}
          </span>
        </div>
        <div style={{ padding: "16px 20px" }}>
          <div
            className="sel"
            style={{
              fontFamily: serif, fontSize: 13, lineHeight: 1.55,
              color: C.textWarm,
            }}
          >
            {hit.body}
          </div>

          {canSuggest && hit.suggest && (
            <div style={{ marginTop: 16, display: "flex", gap: 8 }}>
              <button
                onClick={() => props.onSwitchView(hit.suggest!.view)}
                style={{
                  padding: "6px 14px",
                  fontFamily: mono, fontSize: 11, fontWeight: 600,
                  background: C.accent, color: "#fff",
                  border: `1px solid ${C.accent}`, borderRadius: 4,
                }}
              >
                {hit.suggest.label}
              </button>
            </div>
          )}

          <div style={{ marginTop: 16 }}>
            <button
              onClick={() => setShowDetails((s) => !s)}
              style={{
                fontFamily: mono, fontSize: 10,
                color: C.textFaint,
                padding: 0,
              }}
            >
              {showDetails ? "▾ hide details" : "▸ show details"}
            </button>
            {showDetails && (
              <div
                className="sel"
                style={{
                  marginTop: 8, padding: 12,
                  background: C.bg,
                  border: `1px solid ${C.border}`,
                  borderRadius: 4,
                  fontFamily: mono, fontSize: 11,
                  color: C.textMuted,
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                }}
              >
                {props.message}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
