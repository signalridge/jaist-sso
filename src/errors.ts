export type ErrorCode =
  | "input-required"
  | "cancelled"
  | "timeout"
  | "network"
  | "rejected"
  | "unsupported"
  | "unsafe-destination"
  | "invalid-input";

/** Messages are deliberately independent of HTTP bodies, URLs and credentials. */
export class AuthenticationError extends Error {
  readonly code: ErrorCode;
  constructor(code: ErrorCode, message: string) {
    super(message);
    this.name = "AuthenticationError";
    this.code = code;
  }
}

export function checkAbort(signal?: AbortSignal): void {
  if (signal?.aborted) {
    throw new AuthenticationError(
      signal.reason?.name === "TimeoutError" ? "timeout" : "cancelled",
      "Authentication interrupted",
    );
  }
}

export async function interruptible<T>(
  promise: Promise<T>,
  signal: AbortSignal,
): Promise<T> {
  checkAbort(signal);
  return new Promise((resolve, reject) => {
    const aborted = () => {
      try {
        checkAbort(signal);
      } catch (error) {
        reject(error);
      }
    };
    signal.addEventListener("abort", aborted, { once: true });
    promise
      .then(resolve, reject)
      .finally(() => signal.removeEventListener("abort", aborted));
  });
}
