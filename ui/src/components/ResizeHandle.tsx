import { useEffect, useRef, useState } from "react";
import { C } from "../theme";

// Vertical drag-to-resize handle. Sits on the right edge of the
// sidebar / left edge of the xrefs panel and rewrites the parent's
// width on pointer drag. Persistence is the parent's responsibility:
// we just emit `onChange(px)` while the user drags and `onCommit(px)`
// on release.
export function ResizeHandle(props: {
  edge: "left" | "right";
  width: number;
  min?: number;
  max?: number;
  onChange: (px: number) => void;
  onCommit?: (px: number) => void;
  ariaLabel?: string;
}) {
  const { edge, width, min = 200, max = 600, onChange, onCommit, ariaLabel } = props;
  const [hover, setHover] = useState(false);
  const [drag, setDrag]   = useState(false);
  const dragStateRef = useRef<{ startX: number; startW: number } | null>(null);

  useEffect(() => {
    if (!drag) return;
    const onMove = (e: PointerEvent) => {
      const st = dragStateRef.current;
      if (!st) return;
      const dx = edge === "right"
        ? (e.clientX - st.startX)         // sidebar grows when dragging right
        : (st.startX - e.clientX);        // xrefs panel grows when dragging left
      const next = Math.max(min, Math.min(max, st.startW + dx));
      onChange(next);
    };
    const onUp = () => {
      const st = dragStateRef.current;
      if (st) onCommit?.(width);
      dragStateRef.current = null;
      setDrag(false);
    };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup",   onUp);
    return () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup",   onUp);
    };
  }, [drag, edge, min, max, onChange, onCommit, width]);

  return (
    <div
      role="separator"
      aria-orientation="vertical"
      aria-label={ariaLabel ?? "Resize panel"}
      onPointerDown={(e) => {
        if (e.button !== 0) return;
        e.preventDefault();
        dragStateRef.current = { startX: e.clientX, startW: width };
        setDrag(true);
      }}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        width: 4,
        flexShrink: 0,
        cursor: "col-resize",
        background: hover || drag ? C.accent : "transparent",
        opacity: drag ? 0.8 : (hover ? 0.5 : 1),
        transition: drag ? "none" : "opacity .15s, background .15s",
        // Negative inline margin so the visual hit-area can be 4 px without
        // shifting the layout. This sits flush at the panel edge.
        marginLeft:  edge === "left"  ? -2 : 0,
        marginRight: edge === "right" ? -2 : 0,
        zIndex: 5,
      }}
    />
  );
}
