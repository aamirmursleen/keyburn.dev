// Progressive enhancements for the homepage: scroll reveals, loops that only run while on
// screen, the sticky title bar, the FAQ accordion, live hints next to the form options and
// the footer's local-time line.
//
// The page is complete without this file: content is visible and readable, the accordion
// is open and the form works. Everything here only adds classes, ARIA state, textContent
// and CSS custom properties (CSSOM), so it runs under the strict CSP and Trusted Types
// 'none'. It never reads, stores or sends the secret or the created links; for the
// passphrase it only checks whether the field is empty (to show "On"/"Off").

/** A refresh that re-renders time-dependent text. */
type Task = () => void;

const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
const finePointer = window.matchMedia("(hover: hover) and (pointer: fine)");

function el<T extends HTMLElement = HTMLElement>(id: string): T | null {
  return document.getElementById(id) as T | null;
}

function onScreen(
  targets: Iterable<Element>,
  callback: (entry: IntersectionObserverEntry, observer: IntersectionObserver) => void,
  options: IntersectionObserverInit,
): void {
  const observer = new IntersectionObserver((entries) => {
    for (const entry of entries) callback(entry, observer);
  }, options);
  for (const target of targets) observer.observe(target);
}

/** Fades sections in as they scroll into view. Hiding is gated on the `js` class in CSS. */
function revealOnScroll(): void {
  onScreen(
    document.querySelectorAll("[data-reveal]"),
    (entry, observer) => {
      if (!entry.isIntersecting) return;
      entry.target.classList.add("is-in");
      observer.unobserve(entry.target);
    },
    { rootMargin: "0px 0px -6% 0px", threshold: 0.06 },
  );
}

/** Loops run only while visible, restarting from frame 0 each time they come back. */
function playLoopsOnScreen(): void {
  onScreen(
    document.querySelectorAll(".loop"),
    (entry) => entry.target.classList.toggle("is-playing", entry.isIntersecting),
    { threshold: 0.1 },
  );
}

/** Gives the title bar its floating glass state once it sticks to the top. */
function stickyBar(): void {
  const bar = document.querySelector<HTMLElement>(".win-bar");
  const sentinel = el("bar-sentinel");
  if (!bar || !sentinel) return;
  onScreen(
    [sentinel],
    (entry) => {
      const stuck = !entry.isIntersecting && entry.boundingClientRect.top < 0 && getComputedStyle(bar).position === "sticky";
      bar.classList.toggle("is-stuck", stuck);
    },
    { threshold: 0 },
  );
}

/**
 * WAI-ARIA accordion. The HTML ships every answer open (readable without JS); here all but
 * the first collapse, without animating. This runs before the browser scrolls to a #fragment,
 * so it normally happens off screen; if the FAQ is somehow already visible, everything stays
 * open so nothing the visitor is looking at moves.
 */
function accordion(): void {
  const faq = document.querySelector<HTMLElement>(".faq");
  if (!faq) return;
  const visible = faq.getBoundingClientRect().top < window.innerHeight;
  faq.classList.add("is-settling");
  requestAnimationFrame(() => requestAnimationFrame(() => faq.classList.remove("is-settling")));
  faq.querySelectorAll<HTMLElement>(".faq-item").forEach((item, index) => {
    const button = item.querySelector<HTMLButtonElement>(".faq-q");
    if (!button) return;
    const set = (open: boolean): void => {
      button.setAttribute("aria-expanded", String(open));
      item.classList.toggle("is-closed", !open);
    };
    set(visible || index === 0);
    button.addEventListener("click", () => set(button.getAttribute("aria-expanded") !== "true"));
  });
}

/** "Create a secret link" and friends: scroll to the form and put the cursor in it. */
function focusFormLinks(): void {
  const compose = el("compose");
  const created = el("created");
  document.querySelectorAll<HTMLAnchorElement>("a[data-focus-form]").forEach((link) => {
    link.addEventListener("click", (event) => {
      // After a link was created the form is hidden: go to the result instead of clearing it.
      const showingResult = compose?.hidden === true;
      const section = showingResult ? created : compose;
      const target = el(showingResult ? "copy-secret-link" : "secret");
      if (!section || !target) return;
      event.preventDefault();
      section.scrollIntoView({ behavior: reducedMotion.matches ? "auto" : "smooth", block: "start" });
      target.focus({ preventScroll: true });
    });
  });
}

const timeFormat = new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" });
const weekdayFormat = new Intl.DateTimeFormat(undefined, { weekday: "long" });
const shortWeekdayFormat = new Intl.DateTimeFormat(undefined, { weekday: "short" });
const dateFormat = new Intl.DateTimeFormat(undefined, { day: "numeric", month: "short" });

function startOfDay(date: Date): number {
  return new Date(date.getFullYear(), date.getMonth(), date.getDate()).getTime();
}

/** "today, 3:15 pm", "tomorrow, 2:00 pm", "Sat, 2:00 pm" or "31 Oct, 2:00 pm". */
function describeMoment(at: Date, now: Date): string {
  const days = Math.round((startOfDay(at) - startOfDay(now)) / 86_400_000);
  const time = timeFormat.format(at);
  if (days === 0) return `today, ${time}`;
  if (days === 1) return `tomorrow, ${time}`;
  if (days < 7) return `${shortWeekdayFormat.format(at)}, ${time}`;
  return `${dateFormat.format(at)}, ${time}`;
}

/** Live hints beside the options: when it would expire if sent now, views, passphrase on/off. */
function liveHints(): Task {
  const expires = el<HTMLSelectElement>("expires");
  const views = el<HTMLSelectElement>("views");
  const passphrase = el<HTMLInputElement>("passphrase");
  const expiresOut = el("expires-status");
  const viewsOut = el("views-status");
  const passOut = el("pass-status");
  const passState = el("pass-state");
  if (!expires || !views || !passphrase || !expiresOut || !viewsOut || !passOut || !passState) return () => {};

  const update = (): void => {
    const now = new Date();
    expiresOut.textContent = `Expires ${describeMoment(new Date(now.getTime() + Number(expires.value) * 1000), now)}`;
    const count = Number(views.value);
    viewsOut.textContent = count === 1 ? "Deleted after 1 view" : `Deleted after ${count} views`;
    const on = passphrase.value.length > 0;
    passOut.textContent = on ? "On" : "Off";
    passState.classList.toggle("is-on", on);
  };

  for (const field of [expires, views, passphrase]) {
    field.addEventListener("input", update);
    field.addEventListener("change", update);
  }
  // "Generate" and a successful send change the passphrase field without an input event.
  el("passphrase-generate")?.addEventListener("click", update);
  const compose = el("compose");
  if (compose) new MutationObserver(update).observe(compose, { attributes: true, attributeFilter: ["hidden"] });
  update();
  return update;
}

function partOfDay(hour: number): string {
  if (hour >= 5 && hour < 12) return "morning";
  if (hour >= 12 && hour < 17) return "afternoon";
  if (hour >= 17 && hour < 22) return "evening";
  return "night";
}

/** The footer line that follows the visitor's local time. */
function localTime(): Task {
  const line = el("foot-time");
  if (!line) return () => {};
  return () => {
    const now = new Date();
    line.textContent = `It's ${timeFormat.format(now)} on ${weekdayFormat.format(now)} where you are. Whatever you share doesn't have to outlive the ${partOfDay(now.getHours())}.`;
  };
}

/** Re-runs the time-based text at every minute boundary. */
function everyMinute(tasks: Task[]): void {
  const run = (): void => {
    for (const task of tasks) task();
    window.setTimeout(run, 60_000 - (Date.now() % 60_000) + 50);
  };
  run();
}

/** Pointer-driven depth for the banner shapes and the footer wordmark. */
function pointerEffects(): void {
  if (!finePointer.matches || reducedMotion.matches) return;

  const banner = document.querySelector<HTMLElement>(".banner");
  if (banner) {
    let frame = 0;
    banner.addEventListener("pointermove", (event) => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        const box = banner.getBoundingClientRect();
        banner.style.setProperty("--px", ((event.clientX - box.left) / box.width - 0.5).toFixed(3));
        banner.style.setProperty("--py", ((event.clientY - box.top) / box.height - 0.5).toFixed(3));
      });
    });
    banner.addEventListener("pointerleave", () => {
      cancelAnimationFrame(frame);
      banner.style.setProperty("--px", "0");
      banner.style.setProperty("--py", "0");
    });
  }

  const footer = document.querySelector<HTMLElement>(".site-foot");
  const wordmark = document.querySelector<HTMLElement>(".wordmark");
  if (footer && wordmark) {
    let frame = 0;
    footer.addEventListener("pointermove", (event) => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        const box = wordmark.getBoundingClientRect();
        const x = Math.min(Math.max((event.clientX - box.left) / box.width, -0.2), 1.2);
        wordmark.style.setProperty("--mxn", x.toFixed(3));
        wordmark.style.setProperty("--lean", "9");
        wordmark.style.setProperty("--dx", `${Math.round(event.clientX - (box.left + box.width / 2))}px`);
        wordmark.style.setProperty("--dy", `${Math.round(event.clientY - (box.top + box.height * 0.56))}px`);
      });
    });
    footer.addEventListener("pointerleave", () => {
      cancelAnimationFrame(frame);
      for (const name of ["--mxn", "--lean", "--dx", "--dy"]) wordmark.style.removeProperty(name);
    });
  }
}

/** Shows the real host in the link diagrams, and sizes the terminal's typing animation. */
function hostLabels(): void {
  if (location.host) {
    document.querySelectorAll<HTMLElement>("[data-host]").forEach((node) => {
      node.textContent = location.host;
    });
  }
  const command = el("term-command");
  if (command) command.style.setProperty("--n", String(command.textContent?.length ?? 0));
}

export function initLanding(): void {
  const root = document.documentElement;
  root.classList.remove("no-js");
  root.classList.add("js");
  hostLabels();
  accordion();
  focusFormLinks();
  everyMinute([liveHints(), localTime()]);
  pointerEffects();
  if (!("IntersectionObserver" in window)) {
    document.querySelectorAll("[data-reveal]").forEach((node) => node.classList.add("is-in"));
    return;
  }
  revealOnScroll();
  playLoopsOnScreen();
  stickyBar();
}
