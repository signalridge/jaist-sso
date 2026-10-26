import { createInterface } from "node:readline/promises";
import { Writable } from "node:stream";
import { AuthenticationError, checkAbort } from "./errors.ts";
import type { ChallengeHandler } from "./types.ts";

export type TerminalOptions = {
  input?: NodeJS.ReadStream;
  output?: NodeJS.WriteStream;
};

/** Opt-in terminal interaction; importing the core never reads stdin. */
export function createTerminalHandler(
  options: TerminalOptions = {},
): ChallengeHandler {
  const input = options.input || process.stdin;
  const output = options.output || process.stderr;
  async function question(
    label: string,
    hidden: boolean,
    signal: AbortSignal,
  ): Promise<string> {
    checkAbort(signal);
    if (!input.isTTY || !output.isTTY)
      throw new AuthenticationError(
        "input-required",
        "Interactive terminal is unavailable",
      );
    let muted = false;
    const sink = new Writable({
      write(chunk, _encoding, callback) {
        if (!muted) output.write(chunk);
        callback();
      },
    });
    const rl = createInterface({
      input,
      output: sink,
      terminal: true,
      historySize: 0,
    });
    const cancel = new AbortController();
    const combined = AbortSignal.any([signal, cancel.signal]);
    rl.once("SIGINT", () => cancel.abort());
    try {
      const answer = rl.question(label, { signal: combined });
      muted = hidden;
      return await answer;
    } catch {
      checkAbort(combined);
      throw new AuthenticationError("cancelled", "Input cancelled");
    } finally {
      muted = false;
      rl.close();
      sink.destroy();
      if (hidden) output.write("\n");
    }
  }
  return async (challenge) => {
    if (challenge.kind === "username")
      return question("JAIST username: ", false, challenge.signal);
    if (challenge.kind === "password")
      return question("JAIST password: ", true, challenge.signal);
    if (challenge.kind === "otp") {
      return question(
        challenge.method === "email-otp"
          ? "Email OTP: "
          : "Authenticator OTP: ",
        true,
        challenge.signal,
      );
    }
    if (challenge.kind === "certificate")
      throw new AuthenticationError(
        "input-required",
        "Supply the certificate through a credential provider",
      );
    for (const [i, method] of challenge.methods.entries())
      output.write(`  ${i + 1}) ${method}\n`);
    const answer = await question(
      "Authentication method: ",
      false,
      challenge.signal,
    );
    const method = challenge.methods[Number(answer) - 1];
    if (!/^\d+$/.test(answer) || !method)
      throw new AuthenticationError(
        "invalid-input",
        "Invalid authentication method",
      );
    return method;
  };
}
