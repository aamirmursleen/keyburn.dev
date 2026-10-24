// Scroll reveals and on-screen-only loops, for every page.
//
// Progressive enhancement only: without this file every [data-reveal] block is visible (the
// CSS hides them only under the `js` class) and every .loop shows its resting frame. Loops are
// attached in CSS but paused; here they run only while on screen, never under reduced motion.

const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

export function prefersReducedMotion(): boolean {
  return reducedMotion.matches;
}

/** Fades [data-reveal] content in as it scrolls into view. */
export function revealOnScroll(): void {
  const targets = document.querySelectorAll("[data-reveal]");
  if (!("IntersectionObserver" in window)) {
    targets.forEach((node) => node.classList.add("is-in"));
    return;
  }
  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        entry.target.classList.add("is-in");
        observer.unobserve(entry.target);
      }
    },
    { rootMargin: "0px 0px -6% 0px", threshold: 0.06 },
  );
  targets.forEach((node) => observer.observe(node));
}

/** Runs each .loop only while it is on screen (and the visitor hasn't asked for less motion). */
export function playLoopsOnScreen(): void {
  if (!("IntersectionObserver" in window)) return;
  const visible = new Set<Element>();
  const apply = (node: Element): void => {
    node.classList.toggle("is-playing", visible.has(node) && !reducedMotion.matches && !document.hidden);
  };
  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (entry.isIntersecting) visible.add(entry.target);
        else visible.delete(entry.target);
        apply(entry.target);
      }
    },
    { threshold: 0.1 },
  );
  const loops = document.querySelectorAll(".loop");
  loops.forEach((node) => observer.observe(node));
  const refresh = (): void => loops.forEach(apply);
  reducedMotion.addEventListener("change", refresh);
  document.addEventListener("visibilitychange", refresh);
}
