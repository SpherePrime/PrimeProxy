import { useEffect, type RefObject } from "react";

const GLOW_TARGETS = ".panel, .hero";

export function usePointerGlow(cursorRef: RefObject<HTMLElement>) {
  useEffect(() => {
    let frame = 0;
    let last: PointerEvent | null = null;

    const paint = () => {
      frame = 0;
      if (!last) return;
      const { clientX, clientY, target } = last;
      cursorRef.current?.style.setProperty("--cx", `${clientX}px`);
      cursorRef.current?.style.setProperty("--cy", `${clientY}px`);
      const host = target instanceof Element ? target.closest<HTMLElement>(GLOW_TARGETS) : null;
      if (host) {
        const rect = host.getBoundingClientRect();
        host.style.setProperty("--mx", `${clientX - rect.left}px`);
        host.style.setProperty("--my", `${clientY - rect.top}px`);
      }
    };

    const onMove = (event: PointerEvent) => {
      last = event;
      if (!frame) frame = requestAnimationFrame(paint);
    };

    window.addEventListener("pointermove", onMove, { passive: true });
    return () => {
      window.removeEventListener("pointermove", onMove);
      if (frame) cancelAnimationFrame(frame);
    };
  }, [cursorRef]);
}
