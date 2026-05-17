import { useEffect, useMemo, useRef, useState } from "react";
import type { CSSProperties, PointerEvent } from "react";
import { C, mono, sans } from "../theme";
import petSprite from "../../assets/ember-pet-sprite.png";
import type { EmberPetPosition } from "../settings";

const PET_W = 112;
const PET_H = 112;
const PAD = 18;

const LINES = [
  "symbol confidence: emotionally convincing",
  "sniffed the vtable; probably C++",
  "this thunk has main-character energy",
  "renaming sub_thing to sub_suspicious_thing",
  "imports look normal. suspiciously normal.",
  "control flow says no, vibes say maybe",
  "I found a string and got attached",
  "decompiler horoscope: stack locals ahead",
  "that branch is load-bearing nonsense",
  "xref trail is warm",
  "patch idea rejected by vibes committee",
  "ABI weirdness detected. allegedly.",
];

function rand(min: number, max: number): number {
  return Math.floor(min + Math.random() * (max - min + 1));
}

function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}

function viewportTarget(): { x: number; y: number } {
  const w = window.innerWidth;
  const h = window.innerHeight;
  const xMax = Math.max(PAD, w - PET_W - PAD);
  const yMin = Math.max(64, Math.round(h * 0.42));
  const yMax = Math.max(yMin, h - PET_H - 40);
  return { x: rand(PAD, xMax), y: rand(yMin, yMax) };
}

function defaultPosition(): EmberPetPosition {
  return {
    x: Math.max(PAD, window.innerWidth - PET_W - 34),
    y: Math.max(96, window.innerHeight - PET_H - 58),
  };
}

function clampPosition(p: EmberPetPosition): EmberPetPosition {
  return {
    x: clamp(p.x, PAD, Math.max(PAD, window.innerWidth - PET_W - PAD)),
    y: clamp(p.y, 64, Math.max(96, window.innerHeight - PET_H - 40)),
  };
}

export function EmberPet(props: {
  position: EmberPetPosition | null;
  onPositionChange: (position: EmberPetPosition) => void;
}) {
  const reduceMotion = useMemo(
    () => window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false,
    [],
  );
  const [pos, setPos] = useState(() => clampPosition(props.position ?? defaultPosition()));
  const [facing, setFacing] = useState<1 | -1>(1);
  const [walking, setWalking] = useState(false);
  const [line, setLine] = useState<string | null>(null);
  const [frame, setFrame] = useState(0);
  const lineTimer = useRef<number | null>(null);
  const walkTimer = useRef<number | null>(null);
  const walkingTimer = useRef<number | null>(null);
  const suppressClickRef = useRef(false);
  const dragRef = useRef<{
    pointerId: number;
    startX: number;
    startY: number;
    origin: EmberPetPosition;
    moved: boolean;
  } | null>(null);
  const posRef = useRef(pos);

  useEffect(() => {
    posRef.current = pos;
  }, [pos]);

  useEffect(() => {
    if (!props.position) return;
    const next = clampPosition(props.position);
    posRef.current = next;
    setPos(next);
  }, [props.position]);

  const clearLine = () => {
    if (lineTimer.current != null) window.clearTimeout(lineTimer.current);
    lineTimer.current = null;
    setLine(null);
  };

  const speak = () => {
    const next = LINES[rand(0, LINES.length - 1)];
    setLine(next);
    if (lineTimer.current != null) window.clearTimeout(lineTimer.current);
    lineTimer.current = window.setTimeout(() => {
      setLine(null);
      lineTimer.current = null;
    }, 5200);
  };

  useEffect(() => {
    const onResize = () => {
      setPos((p) => {
        const next = clampPosition(p);
        posRef.current = next;
        return next;
      });
    };
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  useEffect(() => {
    if (reduceMotion) {
      const t = window.setInterval(speak, 28000);
      return () => {
        window.clearInterval(t);
        if (lineTimer.current != null) window.clearTimeout(lineTimer.current);
      };
    }

    let cancelled = false;
    const scheduleWalk = () => {
      walkTimer.current = window.setTimeout(() => {
        if (cancelled) return;
        setPos((old) => {
          const next = viewportTarget();
          setFacing(next.x >= old.x ? 1 : -1);
          return next;
        });
        setWalking(true);
        if (walkingTimer.current != null) window.clearTimeout(walkingTimer.current);
        walkingTimer.current = window.setTimeout(() => {
          setWalking(false);
          walkingTimer.current = null;
        }, 1800);
        if (Math.random() > 0.48) speak();
        scheduleWalk();
      }, rand(9000, 18000));
    };

    const hello = window.setTimeout(speak, 2200);
    scheduleWalk();
    return () => {
      cancelled = true;
      window.clearTimeout(hello);
      if (walkTimer.current != null) window.clearTimeout(walkTimer.current);
      if (walkingTimer.current != null) window.clearTimeout(walkingTimer.current);
      if (lineTimer.current != null) window.clearTimeout(lineTimer.current);
    };
  }, [reduceMotion]);

  useEffect(() => {
    const frames = walking ? [4, 5, 6, 7] : line ? [3, 0, 3, 1] : [0, 1, 2, 1];
    setFrame(frames[0]);
    if (reduceMotion) return;

    let i = 0;
    const delay = walking ? 135 : line ? 220 : 650;
    const t = window.setInterval(() => {
      i = (i + 1) % frames.length;
      setFrame(frames[i]);
    }, delay);
    return () => window.clearInterval(t);
  }, [reduceMotion, walking, line]);

  const onPointerDown = (e: PointerEvent<HTMLButtonElement>) => {
    if (e.button !== 0) return;
    dragRef.current = {
      pointerId: e.pointerId,
      startX: e.clientX,
      startY: e.clientY,
      origin: posRef.current,
      moved: false,
    };
    e.currentTarget.setPointerCapture(e.pointerId);
  };

  const onPointerMove = (e: PointerEvent<HTMLButtonElement>) => {
    const drag = dragRef.current;
    if (!drag || drag.pointerId !== e.pointerId) return;
    const dx = e.clientX - drag.startX;
    const dy = e.clientY - drag.startY;
    if (Math.abs(dx) + Math.abs(dy) > 4) drag.moved = true;
    const next = clampPosition({
      x: drag.origin.x + dx,
      y: drag.origin.y + dy,
    });
    posRef.current = next;
    setPos(next);
    if (Math.abs(dx) > 2) setFacing(dx >= 0 ? 1 : -1);
  };

  const finishDrag = (e: PointerEvent<HTMLButtonElement>) => {
    const drag = dragRef.current;
    if (!drag || drag.pointerId !== e.pointerId) return;
    dragRef.current = null;
    suppressClickRef.current = drag.moved;
    props.onPositionChange(posRef.current);
    if (e.currentTarget.hasPointerCapture(e.pointerId)) {
      e.currentTarget.releasePointerCapture(e.pointerId);
    }
  };

  const petStyle: CSSProperties = {
    position: "fixed",
    left: 0,
    top: 0,
    width: PET_W,
    height: PET_H,
    transform: `translate3d(${pos.x}px, ${pos.y}px, 0)`,
    transition: dragRef.current || reduceMotion ? undefined : "transform 1.8s cubic-bezier(.22,.8,.22,1)",
    zIndex: 1900,
    pointerEvents: "none",
  };
  const bubbleOnRight = pos.x + PET_W + 260 < window.innerWidth || pos.x < 260;
  const frameCol = frame % 4;
  const frameRow = Math.floor(frame / 4);

  return (
    <div style={petStyle} aria-live="polite">
      {line && (
        <div
          style={{
            position: "absolute",
            right: bubbleOnRight ? "auto" : PET_W - 8,
            left: bubbleOnRight ? PET_W - 8 : "auto",
            bottom: PET_H + 2,
            width: 292,
            maxWidth: "min(292px, calc(100vw - 32px))",
            padding: "8px 10px",
            background: C.bgAlt,
            border: `1px solid ${C.borderStrong}`,
            borderRadius: 6,
            boxShadow: "0 14px 36px rgba(0,0,0,0.42)",
            color: C.textWarm,
            fontFamily: mono,
            fontSize: 10.5,
            lineHeight: 1.35,
            pointerEvents: "auto",
            animation: "fadeIn .16s ease-out",
          }}
        >
          <button
            onClick={clearLine}
            title="Dismiss"
            aria-label="Dismiss pet dialog"
            style={{
              float: "right",
              marginLeft: 8,
              color: C.textFaint,
              fontFamily: sans,
              fontSize: 12,
              lineHeight: 1,
            }}
          >
            x
          </button>
          {line}
        </div>
      )}
      <button
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={finishDrag}
        onPointerCancel={finishDrag}
        onClick={() => {
          if (suppressClickRef.current) {
            suppressClickRef.current = false;
            return;
          }
          speak();
        }}
        className="ember-pet-button"
        title="Ember pet"
        aria-label="Ember pet"
        style={{
          position: "absolute",
          inset: 0,
          display: "block",
          pointerEvents: "auto",
          cursor: "grab",
          touchAction: "none",
        }}
      >
        <span
          style={{
            position: "absolute",
            left: 4,
            right: 4,
            bottom: 12,
            height: 12,
            borderRadius: "50%",
            background: "rgba(0,0,0,0.28)",
            filter: "blur(2px)",
            transform: walking ? "scaleX(1.12)" : "scaleX(.92)",
            transition: "transform .5s ease",
          }}
        />
        <span
          style={{
            position: "absolute",
            left: 0,
            top: 0,
            width: PET_W,
            height: PET_H,
            display: "block",
            transform: `scaleX(${facing})`,
            transformOrigin: "center",
          }}
        >
          <span
            aria-hidden
            style={{
              position: "absolute",
              inset: 0,
              backgroundImage: `url(${petSprite})`,
              backgroundRepeat: "no-repeat",
              backgroundSize: `${PET_W * 4}px ${PET_H * 2}px`,
              backgroundPosition: `-${frameCol * PET_W}px -${frameRow * PET_H}px`,
              filter: "drop-shadow(0 1px 0 rgba(255,255,255,0.12)) drop-shadow(0 8px 14px rgba(0,0,0,0.34))",
              userSelect: "none",
              pointerEvents: "none",
            }}
          />
        </span>
      </button>
    </div>
  );
}
