// The receipt's "views used" bar: one pip per allowed view, filled for each view used.
//
// Purely decorative (aria-hidden): it mirrors the "Views used: 1 of 3" row that
// pages/manage.ts renders into #m-details, and hides itself if that row is missing or
// doesn't look as expected. It reads only those two numbers.

import { h } from "./dom";

export function receiptPips(): void {
  const details = document.getElementById("m-details");
  const pips = document.getElementById("m-pips");
  if (!details || !pips) return;

  const render = (): void => {
    const term = Array.from(details.querySelectorAll("dt")).find((dt) => dt.textContent === "Views used");
    const match = /^(\d+) of (\d+)$/.exec(term?.nextElementSibling?.textContent?.trim() ?? "");
    const used = Number(match?.[1]);
    const max = Number(match?.[2]);
    if (!match || max < 1 || max > 10 || used > max) {
      pips.hidden = true;
      return;
    }
    const bar = Array.from({ length: max }, (_, index) => h("span", { class: index < used ? "pip on" : "pip" }));
    pips.replaceChildren(h("span", { class: "pip-row" }, ...bar), h("span", { class: "pip-label", text: `${used} / ${max} views` }));
    pips.hidden = false;
  };

  new MutationObserver(render).observe(details, { childList: true });
  render();
}
