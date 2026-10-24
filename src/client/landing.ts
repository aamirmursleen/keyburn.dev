// Progressive enhancements for the homepage: the FAQ accordion, "create a secret" links that
// put the cursor in the form, live hints next to the form options and the hero's countdown.
// (Shared chrome, scroll reveals and loops live in shell.ts and motion.ts.)
//
// The page is complete without this file: content is visible and readable, the accordion
// is open and the form works. Everything here only adds classes, ARIA state and textContent,
// so it runs under the strict CSP and Trusted Types 'none'. It never reads, stores or sends
// the secret or the created links; for the passphrase it only checks how long it is (to show
// "On", "Off" or "Too short").

import { prefersReducedMotion } from "./motion";

/** A refresh that re-renders time-dependent text. */
type Task = () => void;

function el<T extends HTMLElement = HTMLElement>(id: string): T | null {
  return document.getElementById(id) as T | null;
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
  const target = (): { section: HTMLElement | null; field: HTMLElement | null } => {
    // After a link was created the form is hidden: go to the result instead of clearing it.
    const showingResult = compose?.hidden === true;
    return { section: showingResult ? created : compose, field: el(showingResult ? "copy-secret-link" : "secret") };
  };
  document.querySelectorAll<HTMLAnchorElement>("a[data-focus-form]").forEach((link) => {
    link.addEventListener("click", (event) => {
      const { section, field } = target();
      if (!section || !field) return;
      event.preventDefault();
      section.scrollIntoView({ behavior: prefersReducedMotion() ? "auto" : "smooth", block: "start" });
      field.focus({ preventScroll: true });
    });
  });
  // Arriving from "New secret" on another page (/#compose): the browser scrolls, we focus.
  if (location.hash === "#compose") target().field?.focus({ preventScroll: true });
}

const timeFormat = new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" });
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

/** Live hints beside the options: when it would expire if sent now, views, passphrase state. */
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
    // The form refuses passphrases shorter than 8 characters, so say so before sending.
    const length = passphrase.value.length;
    const state = length === 0 ? "off" : length < 8 ? "short" : "on";
    passOut.textContent = state === "off" ? "Off" : state === "short" ? "Too short (8+ characters)" : "On";
    passState.classList.toggle("is-on", state === "on");
    passState.classList.toggle("is-short", state === "short");
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

/** Re-runs the time-based text at every minute boundary. */
function everyMinute(tasks: Task[]): void {
  const run = (): void => {
    for (const task of tasks) task();
    window.setTimeout(run, 60_000 - (Date.now() % 60_000) + 50);
  };
  run();
}

/** The hero ring's "DELETES IN 23:59:59", ticking only while it is on screen. */
function heroCountdown(): void {
  const clock = el("hero-countdown");
  const art = clock?.closest(".hero-art");
  if (!clock || !art || !("IntersectionObserver" in window)) return;
  const DAY = 24 * 3600;
  let left = DAY - 1;
  let timer = 0;
  let onScreen = false;
  const pad = (n: number): string => String(n).padStart(2, "0");
  const tick = (): void => {
    left = left > 0 ? left - 1 : DAY - 1;
    clock.textContent = `${pad(Math.floor(left / 3600))}:${pad(Math.floor(left / 60) % 60)}:${pad(left % 60)}`;
  };
  const sync = (): void => {
    const run = onScreen && !document.hidden && !prefersReducedMotion();
    if (run && !timer) timer = window.setInterval(tick, 1000);
    if (!run && timer) {
      window.clearInterval(timer);
      timer = 0;
    }
  };
  new IntersectionObserver(
    (entries) => {
      for (const entry of entries) onScreen = entry.isIntersecting;
      sync();
    },
    { threshold: 0.1 },
  ).observe(art);
  document.addEventListener("visibilitychange", sync);
  window.matchMedia("(prefers-reduced-motion: reduce)").addEventListener("change", sync);
}

export function initLanding(): void {
  accordion();
  focusFormLinks();
  everyMinute([liveHints()]);
  heroCountdown();
}
