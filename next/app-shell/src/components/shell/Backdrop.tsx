import { useRef } from "react";
import { usePointerGlow } from "../../hooks/usePointerGlow";

export function Backdrop() {
  const cursorRef = useRef<HTMLSpanElement>(null);
  usePointerGlow(cursorRef);

  return (
    <div className="backdrop" aria-hidden="true">
      <span className="backdrop__grid" />
      <span className="backdrop__glow" />
      <span className="backdrop__glow backdrop__glow--low" />
      <span className="backdrop__cursor" ref={cursorRef} />
    </div>
  );
}
