import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { C, sans, mono, serif } from "../theme";

export type MenuItem =
  | { kind: "item"; label: string; onClick: () => void | Promise<void>; hint?: string; danger?: boolean }
  | { kind: "sep" }
  | { kind: "header"; label: string; meta?: string };

export function ContextMenu(props: {
  x: number;
  y: number;
  items: MenuItem[];
  onClose: () => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState({ x: props.x, y: props.y, ready: false });

  useLayoutEffect(() => {
    if (!ref.current) return;
    const r = ref.current.getBoundingClientRect();
    let x = props.x;
    let y = props.y;
    const M = 6;
    if (x + r.width > window.innerWidth - M) x = window.innerWidth - r.width - M;
    if (y + r.height > window.innerHeight - M) y = window.innerHeight - r.height - M;
    if (x < M) x = M;
    if (y < M) y = M;
    setPos({ x, y, ready: true });
  }, [props.x, props.y]);

  useEffect(() => {
    const onMouseDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        props.onClose();
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") props.onClose();
    };
    const onWheel = () => props.onClose();
    window.addEventListener("mousedown", onMouseDown, true);
    window.addEventListener("keydown", onKey);
    window.addEventListener("wheel", onWheel, true);
    return () => {
      window.removeEventListener("mousedown", onMouseDown, true);
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("wheel", onWheel, true);
    };
  }, [props.onClose]);

  return (
    <div
      ref={ref}
      role="menu"
      style={{
        position: "fixed",
        top: pos.y,
        left: pos.x,
        minWidth: 224,
        padding: 4,
        background: C.bgAlt,
        border: `1px solid ${C.borderStrong}`,
        borderRadius: 6,
        boxShadow: "0 12px 40px rgba(0,0,0,0.5), 0 2px 6px rgba(0,0,0,0.3)",
        zIndex: 1000,
        fontFamily: sans,
        fontSize: 12,
        opacity: pos.ready ? 1 : 0,
        transform: pos.ready ? "none" : "translateY(-2px)",
        transition: "opacity .08s ease-out, transform .08s ease-out",
      }}
      onContextMenu={(e) => e.preventDefault()}
    >
      {props.items.map((item, i) => {
        if (item.kind === "sep") {
          return (
            <div
              key={i}
              style={{ height: 1, background: C.border, margin: "4px 6px" }}
            />
          );
        }
        if (item.kind === "header") {
          return (
            <div
              key={i}
              style={{
                padding: "8px 10px 10px",
                display: "flex",
                flexDirection: "column",
                gap: 2,
                borderBottom: `1px solid ${C.border}`,
                marginBottom: 4,
              }}
            >
              <span
                style={{
                  fontFamily: mono,
                  fontSize: 10,
                  color: C.textFaint,
                  letterSpacing: 0.3,
                }}
              >
                {item.meta ?? ""}
              </span>
              <span
                style={{
                  fontFamily: sans,
                  fontSize: 12,
                  fontWeight: 600,
                  color: C.text,
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                  maxWidth: 300,
                }}
                title={item.label}
              >
                {item.label}
              </span>
            </div>
          );
        }
        return <MenuButton key={i} item={item} onClose={props.onClose} />;
      })}
    </div>
  );
}

function MenuButton(props: {
  item: Extract<MenuItem, { kind: "item" }>;
  onClose: () => void;
}) {
  const { item } = props;
  const [hover, setHover] = useState(false);
  return (
    <button
      role="menuitem"
      onClick={async () => {
        try {
          await item.onClick();
        } finally {
          props.onClose();
        }
      }}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        width: "100%",
        gap: 16,
        padding: "7px 10px",
        borderRadius: 4,
        background: hover ? C.bgMuted : "transparent",
        color: item.danger
          ? (hover ? C.red : "#c75d3aee")
          : (hover ? C.text : C.textWarm),
        textAlign: "left",
        transition: "background .08s, color .08s",
      }}
    >
      <span>{item.label}</span>
      {item.hint && (
        <span
          style={{
            fontFamily: mono,
            fontSize: 10,
            color: hover ? C.textMuted : C.textFaint,
            letterSpacing: 0.3,
          }}
        >
          {item.hint}
        </span>
      )}
    </button>
  );
}

// Small confirmation pill overlay for "copied!" feedback
export function ToastPill(props: { message: string; onDone: () => void }) {
  useEffect(() => {
    const t = setTimeout(props.onDone, 1400);
    return () => clearTimeout(t);
  }, [props.onDone]);
  return (
    <div
      style={{
        position: "fixed",
        bottom: 44,
        left: "50%",
        transform: "translateX(-50%)",
        padding: "8px 16px",
        background: C.bgDark,
        border: `1px solid ${C.borderStrong}`,
        borderRadius: 100,
        fontFamily: serif,
        fontStyle: "italic",
        fontSize: 12,
        color: C.textWarm,
        zIndex: 2000,
        animation: "fadeIn .15s ease-out",
        boxShadow: "0 8px 24px rgba(0,0,0,0.4)",
      }}
    >
      {props.message}
    </div>
  );
}
