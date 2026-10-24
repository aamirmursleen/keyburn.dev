// Pill buttons for <select data-pills> (expiry and view limits).
//
// The native <select> stays in the page as the single source of truth: the create and request
// scripts (and the browser tests) read and set it as before. The pills are a WAI-ARIA radio
// group in front of it; choosing one sets the select's value and dispatches the same `input`
// and `change` events a person changing the select would. Changes made to the select from
// elsewhere are mirrored back. Without JavaScript the plain select is shown instead.

function syncPills(select: HTMLSelectElement, pills: HTMLButtonElement[]): void {
  for (const pill of pills) {
    const checked = pill.dataset.value === select.value;
    pill.setAttribute("aria-checked", String(checked));
    pill.tabIndex = checked ? 0 : -1;
  }
}

function choose(select: HTMLSelectElement, pills: HTMLButtonElement[], pill: HTMLButtonElement): void {
  const value = pill.dataset.value ?? "";
  if (select.value !== value) {
    select.value = value;
    select.dispatchEvent(new Event("input", { bubbles: true }));
    select.dispatchEvent(new Event("change", { bubbles: true }));
  }
  syncPills(select, pills);
}

function enhance(select: HTMLSelectElement): void {
  const label = select.id ? document.querySelector<HTMLLabelElement>(`label[for="${select.id}"]`) : null;
  const group = document.createElement("div");
  group.className = "pills";
  group.setAttribute("role", "radiogroup");
  if (label) {
    label.id ||= `${select.id}-label`;
    group.setAttribute("aria-labelledby", label.id);
  }

  const pills = Array.from(select.options, (option) => {
    const pill = document.createElement("button");
    pill.type = "button";
    pill.className = "pill";
    pill.setAttribute("role", "radio");
    pill.dataset.value = option.value;
    const full = option.textContent?.trim() ?? option.value;
    const short = option.dataset.pill;
    pill.textContent = short ?? full;
    // "15 min" on screen, "15 minutes" for screen readers (the name still contains the label).
    if (short && short !== full) pill.setAttribute("aria-label", full);
    return pill;
  });

  pills.forEach((pill, index) => {
    pill.addEventListener("click", () => choose(select, pills, pill));
    pill.addEventListener("keydown", (event) => {
      const last = pills.length - 1;
      const next =
        event.key === "ArrowRight" || event.key === "ArrowDown"
          ? index === last ? 0 : index + 1
          : event.key === "ArrowLeft" || event.key === "ArrowUp"
            ? index === 0 ? last : index - 1
            : event.key === "Home"
              ? 0
              : event.key === "End"
                ? last
                : -1;
      if (next < 0) return;
      event.preventDefault();
      const target = pills[next];
      if (!target) return;
      choose(select, pills, target);
      target.focus();
    });
  });

  group.append(...pills);
  select.after(group);
  // The select stays present (and visible to scripts and tests) but out of the way.
  select.classList.add("has-pills");
  select.tabIndex = -1;
  select.setAttribute("aria-hidden", "true");
  select.addEventListener("change", () => syncPills(select, pills));
  select.addEventListener("input", () => syncPills(select, pills));
  // Clicking the label goes to the chosen pill rather than the hidden select.
  label?.addEventListener("click", (event) => {
    event.preventDefault();
    pills.find((pill) => pill.tabIndex === 0)?.focus();
  });
  syncPills(select, pills);
}

export function initPills(): void {
  document.querySelectorAll<HTMLSelectElement>("select[data-pills]").forEach(enhance);
}
