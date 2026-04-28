import { C, sans, serif, mono } from "../theme";
import mascot from "../../assets/ember-mascot.png";

export function Welcome(props: {
  onOpen: () => void;
  loading: boolean;
  error: string | null;
  recents: string[];
  onOpenRecent: (p: string) => void;
}) {
  return (
    <div
      style={{
        height: "100%",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: C.bg,
        animation: "fadeIn .4s ease-out",
        overflow: "auto",
        padding: "40px 0",
      }}
    >
      <div style={{ textAlign: "center", maxWidth: 620, padding: 32 }}>

        <img
          src={mascot}
          alt="Ember"
          style={{
            display: "block",
            width: 280,
            height: "auto",
            margin: "0 auto 8px",
            userSelect: "none",
            pointerEvents: "none",
          }}
          draggable={false}
        />
        <div
          style={{
            fontFamily: serif,
            fontStyle: "italic",
            fontSize: 22,
            color: C.textMuted,
            marginBottom: 40,
            letterSpacing: -0.5,
          }}
        >
          a decompiler built from first principles
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(5, 1fr)",
            gap: 1,
            marginBottom: 36,
            border: `1px solid ${C.border}`,
            borderRadius: 4,
            overflow: "hidden",
            background: C.border,
          }}
        >
          {[
            { label: "parse", hint: "ELF / x64" },
            { label: "lift", hint: "→ SSA IR" },
            { label: "clean", hint: "DCE · prop" },
            { label: "structure", hint: "if · while" },
            { label: "emit", hint: "pseudo-C" },
          ].map((s) => (
            <div
              key={s.label}
              style={{
                background: C.bgAlt,
                padding: "18px 12px",
                fontFamily: sans,
              }}
            >
              <div style={{ fontSize: 11, fontWeight: 600, color: C.text, marginBottom: 4 }}>
                {s.label}
              </div>
              <div style={{ fontSize: 10, fontFamily: mono, color: C.textFaint }}>
                {s.hint}
              </div>
            </div>
          ))}
        </div>

        <button
          onClick={props.onOpen}
          disabled={props.loading}
          style={{
            padding: "14px 32px",
            background: C.accent,
            color: "#fff",
            border: "none",
            borderRadius: 4,
            fontFamily: sans,
            fontSize: 14,
            fontWeight: 600,
            cursor: props.loading ? "wait" : "pointer",
            transition: "opacity .15s, transform .15s",
            opacity: props.loading ? 0.6 : 1,
          }}
          onMouseEnter={(e) => {
            if (!props.loading) (e.currentTarget as HTMLElement).style.background = C.accentHover;
          }}
          onMouseLeave={(e) => {
            if (!props.loading) (e.currentTarget as HTMLElement).style.background = C.accent;
          }}
        >
          {props.loading ? "Loading…" : "Open binary"}
        </button>
        <div
          style={{
            marginTop: 16,
            fontFamily: mono,
            fontSize: 10,
            color: C.textFaint,
          }}
        >
          ELF / Mach-O / PE &nbsp;·&nbsp; x64 / aarch64 / PPC64 &nbsp;·&nbsp; or drop a binary anywhere
        </div>

        {props.recents.length > 0 && (
          <div
            style={{
              marginTop: 40,
              padding: "16px 20px",
              background: C.bgAlt,
              border: `1px solid ${C.border}`,
              borderRadius: 6,
              textAlign: "left",
            }}
          >
            <div style={{
              fontFamily: serif, fontStyle: "italic",
              fontSize: 11, color: C.textMuted,
              marginBottom: 8,
              letterSpacing: 0.3,
            }}>
              recent
            </div>
            {props.recents.slice(0, 6).map((p) => {
              const base = p.split("/").pop() || p;
              const dir = p.slice(0, p.length - base.length);
              return (
                <button
                  key={p}
                  onClick={() => props.onOpenRecent(p)}
                  disabled={props.loading}
                  style={{
                    width: "100%",
                    display: "flex",
                    alignItems: "baseline",
                    gap: 12,
                    padding: "7px 10px",
                    borderRadius: 4,
                    background: "transparent",
                    textAlign: "left",
                    cursor: props.loading ? "wait" : "pointer",
                  }}
                  onMouseEnter={(e) => {
                    if (!props.loading) (e.currentTarget as HTMLElement).style.background = C.bgMuted;
                  }}
                  onMouseLeave={(e) => {
                    (e.currentTarget as HTMLElement).style.background = "transparent";
                  }}
                >
                  <span style={{
                    fontFamily: mono, fontSize: 12, color: C.text, fontWeight: 500,
                    flexShrink: 0,
                  }}>{base}</span>
                  <span style={{
                    fontFamily: serif, fontStyle: "italic",
                    fontSize: 11, color: C.textFaint,
                    overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                  }} title={p}>{dir}</span>
                </button>
              );
            })}
          </div>
        )}

        {props.error && (
          <div
            style={{
              marginTop: 22,
              padding: 14,
              background: "rgba(199,93,58,0.08)",
              border: "1px solid rgba(199,93,58,0.25)",
              borderRadius: 4,
              fontFamily: mono,
              fontSize: 11,
              color: C.red,
              textAlign: "left",
              whiteSpace: "pre-wrap",
            }}
          >
            {props.error}
          </div>
        )}
      </div>
    </div>
  );
}
