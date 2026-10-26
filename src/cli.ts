#!/usr/bin/env bun
import { authenticate } from "./authenticate.ts";
import { parseCLI, readCredentialInput, reportError } from "./cli-support.ts";
import { AuthenticationError } from "./errors.ts";
import { HttpSession, httpsURL } from "./session.ts";
import { createTerminalHandler } from "./terminal.ts";

export async function main(args = process.argv.slice(2)): Promise<void> {
  const options = parseCLI(args);
  if (options.help) {
    process.stdout.write(
      "Usage: jaist-sso --url SERVICE_URL [--method certificate|totp|email-otp]\n  [--credentials-stdin | --credentials-fd N] [--session-json]\n",
    );
    return;
  }
  if (!options.url)
    throw new AuthenticationError(
      "invalid-input",
      "A target service URL is required",
    );
  if (options.json && process.stdout.isTTY)
    throw new AuthenticationError(
      "invalid-input",
      "Session JSON requires a pipe or redirected stdout",
    );
  const controller = new AbortController();
  const cancel = () => controller.abort();
  process.once("SIGINT", cancel);
  process.once("SIGTERM", cancel);
  const signal = AbortSignal.any([
    controller.signal,
    AbortSignal.timeout(180_000),
  ]);
  const session = new HttpSession({
    serviceOrigin: httpsURL(options.url).origin,
  });
  try {
    const credentials =
      options.fd === undefined
        ? undefined
        : await readCredentialInput(options.fd, signal);
    const callback = await authenticate({
      session,
      request: { url: options.url },
      method: options.method,
      credentials,
      onChallenge: createTerminalHandler(),
      signal,
    });
    const final = await session.request(
      {
        url: callback.url,
        method: "POST",
        body: new URLSearchParams(
          callback.fields.map(([k, v]) => [k, v]),
        ).toString(),
      },
      signal,
    );
    if (final.status !== 200)
      throw new AuthenticationError(
        "rejected",
        "Target service rejected the SAML callback",
      );
    if (options.json)
      process.stdout.write(
        `${JSON.stringify({ origin: session.serviceOrigin, cookies: session.cookies.values(`${session.serviceOrigin}/`) })}\n`,
      );
    else
      process.stdout.write(
        "JAIST SSO completed; target service returned HTTP 200\n",
      );
  } finally {
    session.close();
    process.removeListener("SIGINT", cancel);
    process.removeListener("SIGTERM", cancel);
  }
}

if (import.meta.main)
  main().catch((error) => {
    process.exitCode = reportError(error);
  });
