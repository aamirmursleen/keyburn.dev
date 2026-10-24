import { b64urlEncode } from "../../shared/encoding";
import type { SecretStatusOutput } from "../../shared/protocol";
import { post } from "../api";
import { busy, byId, confirmDialog, countryLabel, formatRemaining, formatWhen, h, only, plural, showError } from "../dom";
import { forgetFragment, splitKeys, takeFragment } from "../links";
import { errorMessage } from "../messages";

type State = SecretStatusOutput["state"];

const BADGES: Record<State, { label: string; tone: string }> = {
  active: { label: "Active", tone: "active" },
  viewed: { label: "Opened", tone: "done" },
  opened: { label: "Opened", tone: "done" },
  expired: { label: "Expired", tone: "" },
  revoked: { label: "Destroyed", tone: "" },
  locked: { label: "Locked out", tone: "bad" },
  abandoned: { label: "Never completed", tone: "" },
};

function summary(status: SecretStatusOutput): string {
  const used = status.maxViews - status.viewsLeft;
  switch (status.state) {
    case "active":
      return used === 0
        ? `Not opened yet. It expires in ${formatRemaining(status.expiresAt)}.`
        : `Opened ${plural(used, "time")}. ${plural(status.viewsLeft, "view")} left; expires in ${formatRemaining(status.expiresAt)}.`;
    case "viewed":
      return "It was opened and then permanently deleted from our servers.";
    case "expired":
      return "It expired and was permanently deleted.";
    case "revoked":
      return "It was destroyed early. The link no longer works.";
    case "locked":
      return "Someone entered the wrong passphrase 5 times, so it was destroyed. If that wasn't your recipient, the link may have leaked.";
    default:
      return "The upload never finished, so it was deleted.";
  }
}

export function initManage(): void {
  const views = ["m-loading", "m-view", "m-gone", "m-fail"].map((id) => byId(id));
  const [loading, view, gone, fail] = views as [HTMLElement, HTMLElement, HTMLElement, HTMLElement];

  const parts = splitKeys(takeFragment("m"), [16, 32]);
  if (!parts?.[0] || !parts[1]) return only(gone, views);
  const id = b64urlEncode(parts[0]);
  const manageToken = b64urlEncode(parts[1]);

  const destroy = byId<HTMLButtonElement>("m-destroy");
  const refresh = byId<HTMLButtonElement>("m-refresh");
  const error = byId("m-error");
  let state: State | null = null;
  let latest = 0;

  function render(status: SecretStatusOutput): void {
    state = status.state;
    const badge = byId("m-badge");
    badge.textContent = BADGES[status.state].label;
    badge.className = `badge ${BADGES[status.state].tone}`;
    byId("m-summary").textContent = summary(status);

    const rows: [string, string][] = [
      ["Created", formatWhen(status.createdAt)],
      status.endedAt ? ["Ended", formatWhen(status.endedAt)] : ["Expires", formatWhen(status.expiresAt)],
      ["Views used", `${status.maxViews - status.viewsLeft} of ${status.maxViews}`],
      ["Passphrase", status.passphrase ? "Yes" : "No"],
      ["File attached", status.hasFile ? "Yes" : "No"],
    ];
    byId("m-details").replaceChildren(...rows.flatMap(([term, value]) => [h("dt", { text: term }), h("dd", { text: value })]));
    byId("m-events").replaceChildren(
      ...(status.views.length
        ? status.views.map((event) => h("li", { text: `${formatWhen(event.at)}: opened from ${countryLabel(event.country)}` }))
        : [h("li", { class: "muted", text: "Not opened yet." })]),
    );
    destroy.hidden = status.state !== "active";
    if (status.state !== "active") forgetFragment("m");
    only(view, views);
  }

  async function load(quiet = false): Promise<void> {
    if (!quiet) only(loading, views);
    const request = ++latest;
    const res = await post<SecretStatusOutput>("secret/status", { id, manageToken });
    if (request !== latest) return; // a newer refresh is already in flight
    if (res.ok) return render(res.data);
    if (res.error === "not_found") return only(gone, views);
    if (quiet) return showError(error, errorMessage(res.error));
    byId("m-fail-body").textContent = errorMessage(res.error);
    only(fail, views);
  }

  destroy.addEventListener("click", async () => {
    const confirmed = await confirmDialog({
      title: "Destroy this secret?",
      body: "The link stops working immediately and the content is permanently deleted. This can't be undone.",
      confirm: "Destroy",
    });
    if (!confirmed) return;
    busy(destroy, "Destroying…");
    showError(error, null);
    try {
      const res = await post<SecretStatusOutput>("secret/revoke", { id, manageToken });
      latest++;
      if (res.ok) render(res.data);
      else showError(error, errorMessage(res.error));
    } finally {
      busy(destroy, null);
    }
  });
  refresh.addEventListener("click", async () => {
    busy(refresh, "Refreshing…");
    showError(error, null);
    await load(true).finally(() => busy(refresh, null));
  });
  byId("m-retry").addEventListener("click", () => void load());

  // Keep the receipt live while the secret is still active.
  setInterval(() => {
    if (state === "active" && !document.hidden) void load(true);
  }, 30_000);
  void load();
}
