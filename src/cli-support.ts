import { createReadStream } from "node:fs";
import { parseArgs } from "node:util";
import { AuthenticationError, checkAbort } from "./errors.ts";
import type { AuthMethod, Certificate, CredentialProvider } from "./types.ts";

export type CLIOptions = {
  help: boolean;
  url?: string;
  method?: AuthMethod;
  fd?: number;
  json: boolean;
};
export function parseCLI(args: string[]): CLIOptions {
  const { values } = parseArgs({
    args,
    strict: true,
    allowPositionals: false,
    options: {
      help: { type: "boolean", short: "h" },
      url: { type: "string" },
      method: { type: "string" },
      "credentials-fd": { type: "string" },
      "credentials-stdin": { type: "boolean" },
      "session-json": { type: "boolean" },
    },
  });
  if (
    values.method &&
    !["certificate", "totp", "email-otp"].includes(values.method)
  )
    throw new AuthenticationError(
      "invalid-input",
      "Invalid authentication method",
    );
  if (values["credentials-fd"] && values["credentials-stdin"])
    throw new AuthenticationError(
      "invalid-input",
      "Choose one credential input descriptor",
    );
  const fdText = values["credentials-stdin"] ? "0" : values["credentials-fd"];
  const fd = fdText === undefined ? undefined : Number(fdText);
  if (
    fdText !== undefined &&
    (!/^\d+$/.test(fdText) ||
      !Number.isSafeInteger(fd) ||
      fd === 1 ||
      fd === 2 ||
      (fd ?? 0) < 0)
  ) {
    throw new AuthenticationError(
      "invalid-input",
      "Invalid credential descriptor",
    );
  }
  return {
    help: values.help || false,
    url: values.url,
    method: values.method as AuthMethod | undefined,
    fd,
    json: values["session-json"] || false,
  };
}

export function decodeCredentialInput(raw: string): CredentialProvider {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new AuthenticationError(
      "invalid-input",
      "Credential input is not JSON",
    );
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
    throw new AuthenticationError("invalid-input", "Invalid credential input");
  const data = parsed as Record<string, unknown>;
  const provider: CredentialProvider = {};
  for (const key of ["username", "password"] as const) {
    const value = data[key];
    if (value !== undefined) {
      if (
        typeof value !== "string" ||
        !value ||
        /[\r\n]/.test(value) ||
        value.includes("\0")
      )
        throw new AuthenticationError(
          "invalid-input",
          "Invalid credential value",
        );
      provider[key] = async () => value;
    }
  }
  if (data.otp !== undefined) {
    if (typeof data.otp !== "string" || !/^\d{6,8}$/.test(data.otp))
      throw new AuthenticationError("invalid-input", "Invalid OTP input");
    const code = data.otp;
    let used = false;
    provider.otp = async () => {
      if (used)
        throw new AuthenticationError(
          "input-required",
          "A new OTP is required",
        );
      used = true;
      return code;
    };
  }
  if (data.certificate !== undefined) {
    if (!data.certificate || typeof data.certificate !== "object")
      throw new AuthenticationError(
        "invalid-input",
        "Invalid certificate input",
      );
    const cert = data.certificate as Record<string, unknown>;
    if (
      typeof cert.pfxBase64 !== "string" ||
      !cert.pfxBase64 ||
      cert.pfxBase64.length > 1_400_000 ||
      (cert.passphrase !== undefined && typeof cert.passphrase !== "string")
    )
      throw new AuthenticationError(
        "invalid-input",
        "Invalid certificate input",
      );
    const pfx = Buffer.from(cert.pfxBase64, "base64");
    if (pfx.toString("base64") !== cert.pfxBase64)
      throw new AuthenticationError(
        "invalid-input",
        "Invalid certificate encoding",
      );
    const value: Certificate = {
      pfx,
      passphrase: cert.passphrase as string | undefined,
    };
    provider.certificate = async () => value;
  }
  return provider;
}

export async function readCredentialInput(
  fd: number,
  signal: AbortSignal,
): Promise<CredentialProvider> {
  checkAbort(signal);
  try {
    const stream = createReadStream("", { fd, autoClose: false, signal });
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of stream) {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += bytes.length;
      if (size > 2 * 1024 * 1024) {
        stream.destroy();
        throw new AuthenticationError(
          "invalid-input",
          "Credential input size limit exceeded",
        );
      }
      chunks.push(bytes);
    }
    const buffer = Buffer.concat(chunks);
    try {
      return decodeCredentialInput(buffer.toString("utf8"));
    } finally {
      buffer.fill(0);
    }
  } catch (error) {
    checkAbort(signal);
    if (error instanceof AuthenticationError) throw error;
    throw new AuthenticationError(
      "invalid-input",
      "Cannot read credential descriptor",
    );
  }
}

export function reportError(error: unknown): number {
  if (error instanceof AuthenticationError) {
    const messages = {
      "input-required": "Authentication requires additional input",
      cancelled: "Authentication cancelled",
      timeout: "Authentication timed out",
      network: "Authentication network request failed",
      rejected: "Authentication was rejected",
      unsupported: "Authentication flow is not supported",
      "unsafe-destination": "Authentication destination is not allowed",
      "invalid-input": "Authentication input or options are invalid",
    };
    // Providers are application code and may throw even this exported class
    // with sensitive messages. Never print an exception's message or stack.
    if (!Object.hasOwn(messages, error.code)) {
      process.stderr.write("invalid-input: Invalid authentication error\n");
      return 1;
    }
    process.stderr.write(`${error.code}: ${messages[error.code]}\n`);
    return error.code === "input-required"
      ? 2
      : error.code === "cancelled"
        ? 130
        : 1;
  }
  process.stderr.write(
    "invalid-input: Invalid options or unexpected internal failure\n",
  );
  return 1;
}
