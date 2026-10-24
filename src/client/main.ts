import { initLanding } from "./landing";
import { initCreate } from "./pages/create";
import { initInbox } from "./pages/inbox";
import { initManage } from "./pages/manage";
import { initRequest } from "./pages/request";
import { initReveal } from "./pages/reveal";
import { initSubmit } from "./pages/submit";
import { initShell } from "./shell";

const pages: Record<string, () => void> = {
  create: initCreate,
  reveal: initReveal,
  manage: initManage,
  request: initRequest,
  submit: initSubmit,
  inbox: initInbox,
};

const page = document.body.dataset.page ?? "";
pages[page]?.();
// Every page: the window chrome, pills, reveals and loops (progressive enhancement only).
initShell();
// The homepage's accordion, live hints and countdown (progressive enhancement only).
if (page === "create") initLanding();

// Opening a link that differs only in its fragment is a same-document navigation.
// Reload so the new key is read and wiped from the address bar like any other.
if (["reveal", "manage", "submit", "inbox"].includes(page)) {
  window.addEventListener("hashchange", () => location.reload());
}
