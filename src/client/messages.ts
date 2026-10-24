import type { ApiError, GoneReason } from "../shared/protocol";
import { formatWhen } from "./dom";

export function errorMessage(error: ApiError | "network"): string {
  switch (error) {
    case "network":
      return "We couldn't reach the server. Check your connection and try again.";
    case "rate_limited":
      return "Too many requests from your network. Please wait a minute and try again.";
    case "quota_exceeded":
      return "Your network has reached today's limit. Please try again tomorrow.";
    case "capacity":
      return "This service has reached its limit for new secrets today. Please try again later.";
    case "payload_too_large":
      return "That's too large. Text can be up to 64 KB and files up to 25 MB.";
    case "unavailable":
      return "The service is temporarily unavailable. Please try again shortly.";
    default:
      return "Something went wrong. Please try again.";
  }
}

export function goneMessage(reason: GoneReason | "not_found" | "incomplete", at?: number): { title: string; body: string } {
  const when = at ? ` on ${formatWhen(at)}` : "";
  switch (reason) {
    case "viewed":
    case "opened":
      return {
        title: "This secret was already viewed",
        body: `It was opened${when} and then permanently deleted. If that wasn't you, tell the sender, because someone else may have opened it.`,
      };
    case "expired":
      return { title: "This secret has expired", body: `It expired${when} and was permanently deleted. Ask the sender for a new link.` };
    case "revoked":
      return { title: "This secret was destroyed", body: `The sender destroyed it${when}, before it was opened.` };
    case "locked":
      return {
        title: "This secret was destroyed",
        body: "Too many wrong passphrases were entered, so it was permanently deleted to keep it safe. Ask the sender for a new link.",
      };
    case "abandoned":
      return { title: "This secret was never completed", body: "Its upload didn't finish, so it was deleted. Ask the sender to try again." };
    case "incomplete":
      return {
        title: "This link is incomplete",
        body: "Part of the link is missing. Make sure you copied the whole link, including everything after the # sign.",
      };
    default:
      return {
        title: "This secret doesn't exist",
        body: "It may have expired or already been viewed, or the link may be wrong. Secrets can only be opened from the original link.",
      };
  }
}
