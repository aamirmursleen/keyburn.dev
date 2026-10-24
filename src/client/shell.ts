// Enhancements shared by every page's window chrome: the `js` class, the open-a-link box, the
// "On this page" sidebar, pill pickers, copy buttons on code blocks, the receipt's view pips,
// scroll reveals and loops.
//
// Like the rest of the client, this only adds classes, attributes, textContent and elements made
// with createElement (Trusted Types 'none', no inline styles: custom properties are set through
// the CSSOM). It never reads a secret, a passphrase or a created link; for the request note it
// only counts characters.

import { copyText, h } from "./dom";
import { playLoopsOnScreen, prefersReducedMotion, revealOnScroll } from "./motion";
import { initOpenLink } from "./open-link";
import { initPills } from "./pills";
import { receiptPips } from "./receipt-pips";

/**
 * The logo's entrance plays on the first page of a visit only (remembered for this tab in
 * sessionStorage, which never leaves the browser); after that it simply shows the logo.
 */
function brandIntro(): void {
  if (prefersReducedMotion()) return;
  let seen = false;
  try {
    seen = sessionStorage.getItem("kb-intro") === "1";
    sessionStorage.setItem("kb-intro", "1");
  } catch {
    // storage unavailable: play it every time
  }
  if (!seen) document.documentElement.classList.add("kb-intro");
}

/** Shows the real host in illustrations such as the terminal on the homepage. */
function hostLabels(): void {
  if (!location.host) return;
  document.querySelectorAll<HTMLElement>("[data-host]").forEach((node) => {
    node.textContent = location.host;
  });
}

/**
 * "Skip to content" without touching the URL: on the secret, receipt, request and inbox pages a
 * changed #fragment reloads the page (see main.ts), so in-page links must not set one.
 */
function skipLinks(): void {
  const main = document.getElementById("main");
  if (!main) return;
  document.querySelectorAll<HTMLAnchorElement>('a[href="#main"]').forEach((link) => {
    link.addEventListener("click", (event) => {
      event.preventDefault();
      main.focus({ preventScroll: true });
      main.scrollIntoView({ block: "start", behavior: prefersReducedMotion() ? "auto" : "smooth" });
    });
  });
}

/**
 * Highlights the section being read in the sidebar's "On this page" list. Like the design, the
 * first entry is highlighted until the reader scrolls past it (the CSS starts there too).
 */
function sectionSpy(): void {
  const list = document.querySelector<HTMLElement>(".toc-list");
  if (!list) return;
  const links = Array.from(list.querySelectorAll<HTMLAnchorElement>("a.toc-link"));
  const sections = links.map((link) => document.getElementById(link.hash.slice(1)));
  let current = -1;
  let frame = 0;

  const update = (): void => {
    frame = 0;
    const line = Math.min(window.innerHeight * 0.35, 260);
    let index = 0;
    sections.forEach((section, i) => {
      if (section && section.getBoundingClientRect().top <= line) index = i;
    });
    const last = sections.length - 1;
    const atEnd = window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 4;
    const lastSection = sections[last];
    if (atEnd && lastSection && lastSection.getBoundingClientRect().top < window.innerHeight) index = last;
    if (index === current) return;
    current = index;
    links.forEach((link, i) => {
      if (i === index) link.setAttribute("aria-current", "location");
      else link.removeAttribute("aria-current");
    });
    list.style.setProperty("--toc-i", String(index));
  };
  const schedule = (): void => {
    if (!frame) frame = requestAnimationFrame(update);
  };
  window.addEventListener("scroll", schedule, { passive: true });
  window.addEventListener("resize", schedule);
  update();
}

/** The request page's "Request a secret" shortcut: go to the form and put the cursor in it. */
function focusNoteLinks(): void {
  document.querySelectorAll<HTMLAnchorElement>("a[data-focus-note]").forEach((link) => {
    link.addEventListener("click", (event) => {
      const section = document.getElementById("new");
      const compose = document.getElementById("q-compose");
      const target = document.getElementById(compose?.hidden ? "q-copy-client" : "q-note");
      if (!section || !target) return;
      event.preventDefault();
      section.scrollIntoView({ behavior: prefersReducedMotion() ? "auto" : "smooth", block: "start" });
      target.focus({ preventScroll: true });
    });
  });
}

/** "12 / 1000" next to the request note (a count only; the note itself is never read). */
function noteCounter(): void {
  const note = document.getElementById("q-note");
  const count = document.getElementById("q-note-count");
  if (!(note instanceof HTMLTextAreaElement) || !count) return;
  const max = note.maxLength > 0 ? note.maxLength : 1000;
  const update = (): void => {
    count.textContent = `${note.value.length} / ${max}`;
  };
  note.addEventListener("input", update);
  // "Create another" clears the note without an input event.
  const compose = document.getElementById("q-compose");
  if (compose) new MutationObserver(update).observe(compose, { attributes: true, attributeFilter: ["hidden"] });
  update();
}

/** Copy buttons on the code blocks marked data-copy (the install and connect commands). */
function codeCopyButtons(): void {
  const cards = document.querySelectorAll<HTMLElement>(".code-card[data-copy]");
  if (!cards.length) return;
  const status = h("p", { class: "visually-hidden", attrs: { role: "status" } });
  document.body.append(status);
  cards.forEach((card) => {
    const pre = card.querySelector("pre");
    if (!pre) return;
    const button = h("button", {
      class: "code-copy",
      text: "Copy",
      attrs: { type: "button", "aria-label": `Copy ${card.dataset.copy ?? "this"}` },
    });
    button.addEventListener("click", async () => {
      status.textContent = "";
      await copyText(pre.textContent ?? "", button);
      status.textContent = button.textContent?.startsWith("Copied") ? "Copied to the clipboard." : "Select the text and press Ctrl or ⌘ and C.";
    });
    card.append(button);
    card.classList.add("has-copy");
  });
}

export function initShell(): void {
  const root = document.documentElement;
  root.classList.remove("no-js");
  root.classList.add("js");
  brandIntro();
  hostLabels();
  skipLinks();
  initOpenLink();
  initPills();
  sectionSpy();
  focusNoteLinks();
  noteCounter();
  codeCopyButtons();
  receiptPips();
  revealOnScroll();
  playLoopsOnScreen();
}
