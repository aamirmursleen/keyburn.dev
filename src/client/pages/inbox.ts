import { aad, inboxToken, openPayload, requestAddress, requesterKeys } from "../../shared/crypto";
import { b64urlDecode, type Bytes } from "../../shared/encoding";
import { lookupWithLegacyId } from "../../shared/legacy";
import type { InboxState, InboxStatusOutput, OpenInboxOutput } from "../../shared/protocol";
import { post } from "../api";
import { showContent } from "../content";
import { busy, byId, confirmDialog, copyText, countryLabel, formatWhen, h, only, showError } from "../dom";
import { forgetFragment, links, splitKeys, takeFragment } from "../links";
import { errorMessage } from "../messages";

const BADGES: Record<InboxState, { label: string; tone: string }> = {
  waiting: { label: "Waiting", tone: "active" },
  receiving: { label: "Receiving", tone: "active" },
  received: { label: "Response ready", tone: "active" },
  opened: { label: "Opened", tone: "done" },
  expired: { label: "Expired", tone: "" },
  revoked: { label: "Cancelled", tone: "" },
  viewed: { label: "Opened", tone: "done" },
  locked: { label: "Closed", tone: "" },
  abandoned: { label: "Closed", tone: "" },
};

function summary(status: InboxStatusOutput): string {
  switch (status.state) {
    case "waiting":
      return "No response yet. Send the client link to the person you're asking.";
    case "receiving":
      return "A response is being uploaded right now. Refresh in a moment.";
    case "received":
      return `A response arrived ${status.submittedAt ? formatWhen(status.submittedAt) : ""} from ${countryLabel(status.country)}. Opening it deletes it from our servers.`;
    case "opened":
      return "You opened the response, and it has been deleted from our servers.";
    case "expired":
      return status.submittedAt
        ? "The response wasn't opened in time, so it was deleted."
        : "The request expired without a response.";
    case "revoked":
      return "This request was cancelled. The client link no longer works.";
    default:
      return "This request is closed.";
  }
}

export function initInbox(): void {
  const views = ["i-loading", "i-view", "i-content", "i-gone", "i-fail"].map((id) => byId(id));
  const [loading, view, content, gone, fail] = views as [HTMLElement, HTMLElement, HTMLElement, HTMLElement, HTMLElement];

  const parts = splitKeys(takeFragment("i"), [32, 32]);
  const [Q, d] = parts ?? [];
  if (!Q || !d) return only(gone, views);
  run(Q, d);

  function run(Q: Bytes, d: Bytes): void {
    const openButton = byId<HTMLButtonElement>("i-open");
    const refresh = byId<HTMLButtonElement>("i-refresh");
    const cancel = byId<HTMLButtonElement>("i-cancel");
    const error = byId("i-error");
    const clientLink = byId<HTMLInputElement>("i-client-link");
    let address: Awaited<ReturnType<typeof requestAddress>> | null = null;
    let token: string | null = null;
    let status: InboxStatusOutput | null = null;
    let latest = 0;

    async function render(next: InboxStatusOutput): Promise<void> {
      status = next;
      const badge = byId("i-badge");
      badge.textContent = BADGES[next.state].label;
      badge.className = `badge ${BADGES[next.state].tone}`;
      byId("i-summary").textContent = summary(next);

      const noteBox = byId("i-note-box");
      noteBox.hidden = true;
      if (next.note && address) {
        try {
          const note = await openPayload(address.noteKey, aad.requestNote(address.id), next.note);
          byId("i-note").textContent = note.text;
          noteBox.hidden = note.text.length === 0;
        } catch {
          noteBox.hidden = true;
        }
      }

      const live = next.endedAt === null;
      const rows: [string, string][] = [["Created", formatWhen(next.createdAt)]];
      if (next.state === "waiting") rows.push(["Client link works until", formatWhen(next.expiresAt)]);
      if (next.state === "received" || next.state === "receiving") rows.push(["Deleted if not opened by", formatWhen(next.expiresAt)]);
      if (next.endedAt) rows.push(["Ended", formatWhen(next.endedAt)]);
      byId("i-details").replaceChildren(...rows.flatMap(([term, value]) => [h("dt", { text: term }), h("dd", { text: value })]));

      const showClient = next.state === "waiting" && next.pub !== null;
      byId("i-client-box").hidden = !showClient;
      clientLink.value = showClient && next.pub ? links.request(Q, b64urlDecode(next.pub)) : "";
      openButton.hidden = next.state !== "received";
      cancel.hidden = !live;
      if (!live) forgetFragment("i");
      only(view, views);
    }

    async function load(quiet = false): Promise<void> {
      if (!quiet) only(loading, views);
      address ??= await requestAddress(Q);
      const inbox = (token ??= await inboxToken(Q, d));
      const request = ++latest;
      const { id, res } = await lookupWithLegacyId(address, (id) => post<InboxStatusOutput>("request/status", { id, inboxToken: inbox }));
      if (request !== latest) return; // a newer refresh is already in flight
      if (res.ok) address = { ...address, id, legacyId: id };
      if (res.ok) return render(res.data);
      if (res.error === "not_found") return only(gone, views);
      if (quiet) return showError(error, errorMessage(res.error));
      byId("i-fail-body").textContent = errorMessage(res.error);
      only(fail, views);
    }

    openButton.addEventListener("click", async () => {
      if (!address || !token || !status?.pub) return;
      busy(openButton, "Opening…");
      showError(error, null);
      try {
        latest++;
        const res = await post<OpenInboxOutput>("request/open", { id: address.id, inboxToken: token });
        if (!res.ok) {
          if (res.error === "conflict" || res.error === "not_found") return await load(true);
          return showError(error, errorMessage(res.error));
        }
        const keys = await requesterKeys(b64urlDecode(status.pub), d, Q, address.id, b64urlDecode(res.data.ephPub));
        const payload = await openPayload(keys.textKey, aad.requestText(address.id), res.data);
        const file = res.data.file;
        showContent(
          "i",
          payload,
          file ? { kind: "request", id: address.id, ticket: file, key: keys.fileKey, aad: aad.requestFile(address.id) } : null,
        );
        byId("i-after").textContent = file
          ? "This response has been deleted from our servers. Download the file now: the download works for 15 minutes."
          : "This response has been deleted from our servers. Save it somewhere safe before you leave this page.";
        only(content, views);
      } catch {
        showError(error, "The response couldn't be decrypted. The inbox link may be damaged.");
      } finally {
        busy(openButton, null);
      }
    });

    cancel.addEventListener("click", async () => {
      if (!address || !token) return;
      const confirmed = await confirmDialog({
        title: "Cancel this request?",
        body:
          status?.state === "received"
            ? "The response will be deleted without being opened. This can't be undone."
            : "The client link will stop working immediately. This can't be undone.",
        confirm: "Cancel request",
      });
      if (!confirmed) return;
      busy(cancel, "Cancelling…");
      try {
        const res = await post<InboxStatusOutput>("request/revoke", { id: address.id, inboxToken: token });
        latest++;
        if (res.ok) await render(res.data);
        else showError(error, errorMessage(res.error));
      } finally {
        busy(cancel, null);
      }
    });

    refresh.addEventListener("click", async () => {
      busy(refresh, "Refreshing…");
      showError(error, null);
      await load(true).finally(() => busy(refresh, null));
    });
    const copyButton = byId<HTMLButtonElement>("i-copy-client");
    copyButton.addEventListener("click", () => void copyText(clientLink.value, copyButton, clientLink));
    byId("i-retry").addEventListener("click", () => void load());

    // Watch for the response while waiting.
    setInterval(() => {
      if ((status?.state === "waiting" || status?.state === "receiving") && !document.hidden) void load(true);
    }, 20_000);
    void load().catch(() => {
      byId("i-fail-body").textContent = errorMessage("network");
      only(fail, views);
    });
  }
}
