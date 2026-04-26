import { useCallback, useEffect, useLayoutEffect, useState } from "react";
import { C, sans, serif, mono } from "../theme";

// Coach-marks for first-run. Each step either anchors to a DOM element
// carrying [data-tutorial="..."] (highlighted with a spotlight cutout)
// or, when the selector is null / the element isn't currently in the
// DOM, falls back to a centered card.
type Step = {
  selector: string | null;
  title: string;
  body: string;
  // Where the popover sits relative to the highlighted element.
  // Ignored when there's no anchor.
  placement?: "right" | "left" | "below" | "above";
};

const STEPS: Step[] = [
  {
    selector: null,
    title: "Welcome to Ember",
    body:
      "A from-scratch decompiler for x86-64 ELF, Mach-O, and PE. " +
      "Quick tour through the things you'll use every day — about a minute.",
  },
  {
    selector: '[data-tutorial="sidebar-search"]',
    title: "Function list",
    body:
      "Every defined function and import lives here. Type to filter by name, " +
      "toggle defined ↔ imports above, and right-click any row to rename or annotate.",
    placement: "right",
  },
  {
    selector: '[data-tutorial="jump"]',
    title: "Jump to function",
    body:
      "Press ⌃P (or click here) for fuzzy search across names, addresses, " +
      "and mangled symbols. Faster than scrolling once the list gets long.",
    placement: "below",
  },
  {
    selector: '[data-tutorial="tabs"]',
    title: "View modes",
    body:
      "Same function, five lenses: pseudo-C, raw asm, control-flow graph, lifted IR, " +
      "and SSA. Hotkeys p / d / c / i / s switch between them.",
    placement: "below",
  },
  {
    selector: '[data-tutorial="xrefs"]',
    title: "References",
    body:
      "Callers and callees of the current function. Click any row to navigate; " +
      "the back arrow in the title bar returns where you came from.",
    placement: "left",
  },
  {
    selector: null,
    title: "You're set",
    body:
      "Right-click any identifier in code to rename or attach a note. " +
      "Renames, signatures, and patches stage into the project file — " +
      "export them from the sidebar to share or version-control.",
  },
];

const POPOVER_W = 340;
const PAD = 14;

export function Tutorial(props: { onClose: () => void }) {
  const [i, setI] = useState(0);
  const [rect, setRect] = useState<DOMRect | null>(null);
  const step = STEPS[i];

  const next = useCallback(() => {
    setI((cur) => (cur < STEPS.length - 1 ? cur + 1 : (props.onClose(), cur)));
  }, [props]);
  const prev = useCallback(() => setI((cur) => Math.max(0, cur - 1)), []);

  // Locate + measure the anchor for the current step. Re-runs on
  // resize so the spotlight follows the layout. If the selector
  // doesn't resolve, we drop to the centered fallback.
  useLayoutEffect(() => {
    if (!step.selector) {
      setRect(null);
      return;
    }
    const el = document.querySelector(step.selector) as HTMLElement | null;
    if (!el) {
      setRect(null);
      return;
    }
    const update = () => setRect(el.getBoundingClientRect());
    update();
    window.addEventListener("resize", update);
    return () => window.removeEventListener("resize", update);
  }, [step.selector]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        props.onClose();
      } else if (e.key === "ArrowRight" || e.key === "Enter") {
        e.preventDefault();
        next();
      } else if (e.key === "ArrowLeft") {
        e.preventDefault();
        prev();
      }
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [next, prev, props]);

  const popStyle = popoverPosition(rect, step.placement);
  const last = i === STEPS.length - 1;

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 3000,
        // No own backdrop — the spotlight ring uses an inset box-shadow
        // that paints the dim layer in one element, so the highlight
        // and the dim stay perfectly in sync as the rect updates.
        background: rect ? "transparent" : "rgba(10,10,9,0.55)",
        backdropFilter: rect ? undefined : "blur(2px)",
        animation: "fadeIn .15s ease-out",
      }}
    >
      {rect && (
        <div
          style={{
            position: "fixed",
            top: rect.top - 4,
            left: rect.left - 4,
            width: rect.width + 8,
            height: rect.height + 8,
            border: `2px solid ${C.accent}`,
            borderRadius: 6,
            // 9999px outset spreads the shadow over the entire viewport,
            // creating a single-element spotlight cutout.
            boxShadow: "0 0 0 9999px rgba(10,10,9,0.55)",
            pointerEvents: "none",
            transition: "all .2s ease-out",
          }}
        />
      )}
      <div
        style={{
          position: "fixed",
          ...popStyle,
          background: C.bgAlt,
          border: `1px solid ${C.borderStrong}`,
          borderRadius: 8,
          padding: 18,
          boxShadow: "0 24px 60px rgba(0,0,0,0.55)",
          fontFamily: sans,
        }}
      >
        <div
          style={{
            fontFamily: serif, fontStyle: "italic",
            fontSize: 11, color: C.textFaint,
            marginBottom: 6, letterSpacing: 0.3,
          }}
        >
          step {i + 1} of {STEPS.length}
        </div>
        <div style={{ fontSize: 16, fontWeight: 600, color: C.text, marginBottom: 8 }}>
          {step.title}
        </div>
        <div
          className="sel"
          style={{ fontSize: 13, color: C.textWarm, lineHeight: 1.55, marginBottom: 18 }}
        >
          {step.body}
        </div>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
          <button
            onClick={props.onClose}
            style={{
              fontFamily: mono, fontSize: 10, color: C.textFaint,
              padding: "4px 6px",
            }}
          >
            skip
          </button>
          <div style={{ display: "flex", gap: 8 }}>
            {i > 0 && (
              <button
                onClick={prev}
                style={{
                  padding: "5px 12px", fontFamily: mono, fontSize: 11,
                  background: C.bgMuted, color: C.textMuted,
                  border: `1px solid ${C.border}`, borderRadius: 4,
                }}
              >
                back
              </button>
            )}
            <button
              onClick={next}
              style={{
                padding: "5px 14px", fontFamily: mono, fontSize: 11,
                background: C.accent, color: "#fff",
                border: `1px solid ${C.accent}`, borderRadius: 4,
                fontWeight: 600,
              }}
            >
              {last ? "done" : "next"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function popoverPosition(rect: DOMRect | null, placement: Step["placement"]): React.CSSProperties {
  if (!rect) {
    return {
      top: "50%", left: "50%",
      transform: "translate(-50%, -50%)",
      width: 400,
    };
  }
  let top: number;
  let left: number;
  switch (placement ?? "below") {
    case "right":
      top  = rect.top;
      left = rect.right + PAD;
      break;
    case "left":
      top  = rect.top;
      left = rect.left - POPOVER_W - PAD;
      break;
    case "above":
      top  = rect.top - PAD - 180;  // approximate; clamped below
      left = rect.left;
      break;
    default:
      top  = rect.bottom + PAD;
      left = rect.left;
  }
  // Clamp to viewport so the popover never falls off-screen on small
  // windows or when the anchor is near an edge.
  const vw = window.innerWidth;
  const vh = window.innerHeight;
  if (left + POPOVER_W > vw - 16) left = Math.max(16, vw - POPOVER_W - 16);
  if (left < 16) left = 16;
  if (top  < 16) top  = 16;
  if (top  > vh - 200) top = Math.max(16, vh - 220);
  return { top, left, width: POPOVER_W };
}
