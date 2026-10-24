export type CliErrorCode =
  | "usage"
  | "bad_link"
  | "untrusted_origin"
  | "not_found"
  | "gone"
  | "passphrase_required"
  | "wrong_passphrase"
  | "network"
  | "server"
  | "rate_limited"
  | "too_large"
  | "unsafe_storage"
  | "bad_handle"
  | "expired_handle"
  | "no_terminal";

/** An expected failure with a stable code. Messages never contain secret material. */
export class CliError extends Error {
  constructor(
    readonly code: CliErrorCode,
    message: string,
    readonly attemptsLeft?: number,
  ) {
    super(message);
    this.name = "CliError";
  }
}

/** Process exit codes, so scripts can tell failures apart. */
export const EXIT_CODES: Record<CliErrorCode, number> = {
  usage: 2,
  bad_link: 2,
  untrusted_origin: 2,
  not_found: 3,
  gone: 3,
  passphrase_required: 4,
  wrong_passphrase: 4,
  network: 5,
  server: 5,
  rate_limited: 5,
  too_large: 2,
  unsafe_storage: 6,
  bad_handle: 2,
  expired_handle: 3,
  no_terminal: 7,
};
