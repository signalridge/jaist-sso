import { Agent, request } from "node:https";
import { createSecureContext, type SecureContext } from "node:tls";
import { AuthenticationError, checkAbort, interruptible } from "./errors.ts";
import type { Certificate, Navigation, Page } from "./types.ts";

export const SSO_ORIGIN = "https://auth.jaist.ac.jp";
export const CERTIFICATE_ORIGIN = "https://auth-cert.jaist.ac.jp";
export const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

export function httpsURL(value: string, base?: string): URL {
  let url: URL;
  try {
    url = new URL(value, base);
  } catch {
    throw new AuthenticationError("unsafe-destination", "Invalid destination");
  }
  if (
    url.protocol !== "https:" ||
    (url.port && url.port !== "443") ||
    url.username ||
    url.password
  ) {
    throw new AuthenticationError(
      "unsafe-destination",
      "HTTPS on the standard port is required",
    );
  }
  return url;
}

type Cookie = {
  name: string;
  value: string;
  domain: string;
  path: string;
  hostOnly: boolean;
  secure: boolean;
  expires: number;
  order: number;
};

/** Private, per-authentication cookie storage; never persisted. */
export class CookieJar {
  #cookies: Cookie[] = [];
  #order = 0;
  set(line: string, origin: string): void {
    const url = httpsURL(origin);
    const parts = line.split(";");
    const first = parts.shift() || "";
    const equals = first.indexOf("=");
    if (equals < 1) return;
    const lastSlash = url.pathname.lastIndexOf("/");
    const cookie: Cookie = {
      name: first.slice(0, equals).trim(),
      value: first.slice(equals + 1).trim(),
      domain: url.hostname,
      path: lastSlash > 0 ? url.pathname.slice(0, lastSlash) : "/",
      hostOnly: true,
      secure: false,
      expires: Infinity,
      order: this.#order++,
    };
    if (
      !/^[!#$%&'*+.^_`|~\w-]+$/.test(cookie.name) ||
      /[\r\n]/.test(cookie.value) ||
      cookie.value.includes("\0")
    )
      return;
    let maxAge: number | undefined;
    for (const part of parts) {
      const split = part.indexOf("=");
      const name = (split < 0 ? part : part.slice(0, split))
        .trim()
        .toLowerCase();
      const value = split < 0 ? "" : part.slice(split + 1).trim();
      if (name === "domain") {
        cookie.domain = value.toLowerCase().replace(/^\./, "");
        cookie.hostOnly = false;
      }
      if (name === "path" && value.startsWith("/")) cookie.path = value;
      if (name === "secure") cookie.secure = true;
      if (name === "max-age" && /^-?\d+$/.test(value)) maxAge = Number(value);
      if (name === "expires" && Number.isFinite(Date.parse(value)))
        cookie.expires = Date.parse(value);
    }
    // Cross-host cookies are accepted only under JAIST's known parent domain.
    // Explicit third-party service origins still support their own host-only cookies.
    if (
      !cookie.hostOnly &&
      cookie.domain !== url.hostname &&
      !(
        cookie.domain === "jaist.ac.jp" && url.hostname.endsWith(".jaist.ac.jp")
      )
    )
      return;
    if (maxAge !== undefined) cookie.expires = Date.now() + maxAge * 1000;
    if (cookie.name.startsWith("__Secure-") && !cookie.secure) return;
    if (
      cookie.name.startsWith("__Host-") &&
      (!cookie.secure || !cookie.hostOnly || cookie.path !== "/")
    )
      return;
    this.#cookies = this.#cookies.filter(
      (c) =>
        !(
          c.name === cookie.name &&
          c.domain === cookie.domain &&
          c.path === cookie.path
        ),
    );
    if (cookie.expires > Date.now()) this.#cookies.push(cookie);
  }
  #matching(value: string): Cookie[] {
    const url = httpsURL(value);
    return this.#cookies
      .filter(
        (c) =>
          c.expires > Date.now() &&
          (c.hostOnly
            ? url.hostname === c.domain
            : url.hostname === c.domain ||
              url.hostname.endsWith(`.${c.domain}`)) &&
          (!c.secure || url.protocol === "https:") &&
          (url.pathname === c.path ||
            (url.pathname.startsWith(c.path) &&
              (c.path.endsWith("/") || url.pathname[c.path.length] === "/"))),
      )
      .sort((a, b) => b.path.length - a.path.length || a.order - b.order);
  }
  header(url: string): string {
    return this.#matching(url)
      .map((c) => `${c.name}=${c.value}`)
      .join("; ");
  }
  values(url: string): Readonly<Record<string, string>> {
    const values: Record<string, string> = Object.create(null);
    for (const c of this.#matching(url)) values[c.name] ??= c.value;
    return values;
  }
  clear(): void {
    this.#cookies = [];
  }
  toJSON(): string {
    return "[CookieJar]";
  }
}

export type TransportRequest = Navigation & {
  headers: Readonly<Record<string, string>>;
  signal: AbortSignal;
  secureContext?: SecureContext;
};
export type TransportResponse = {
  status: number;
  body: string;
  cookies?: readonly string[];
  location?: string;
};
export type Transport = (
  request: TransportRequest,
) => Promise<TransportResponse>;

const defaultTransport: Transport = async (options) => {
  const agent = new Agent({
    keepAlive: false,
    rejectUnauthorized: true,
    secureContext: options.secureContext,
  });
  try {
    return await new Promise<TransportResponse>((resolve, reject) => {
      const req = request(
        options.url,
        {
          method: options.method || "GET",
          headers: options.headers,
          agent,
          signal: options.signal,
        },
        (response) => {
          const chunks: Buffer[] = [];
          let size = 0;
          response.on("data", (chunk: Buffer) => {
            size += chunk.length;
            if (size > MAX_RESPONSE_BYTES)
              req.destroy(
                new AuthenticationError(
                  "unsupported",
                  "Response size limit exceeded",
                ),
              );
            else chunks.push(chunk);
          });
          response.on("error", () =>
            reject(new AuthenticationError("network", "Response interrupted")),
          );
          response.on("end", () =>
            resolve({
              status: response.statusCode || 0,
              body: Buffer.concat(chunks).toString("utf8"),
              cookies: response.headers["set-cookie"],
              location: response.headers.location,
            }),
          );
        },
      );
      req.on("error", (error) =>
        reject(
          error instanceof AuthenticationError
            ? error
            : new AuthenticationError("network", "HTTPS request failed"),
        ),
      );
      req.end(options.body);
    });
  } finally {
    agent.destroy();
  }
};

export type SessionOptions = {
  serviceOrigin: string;
  transport?: Transport;
  maxRequests?: number;
};

export class HttpSession {
  readonly serviceOrigin: string;
  readonly cookies = new CookieJar();
  #transport: Transport;
  #contexts = new Map<string, SecureContext>();
  #requests = 0;
  #maxRequests: number;
  #closed = false;
  constructor(options: SessionOptions) {
    this.serviceOrigin = httpsURL(options.serviceOrigin).origin;
    if ([SSO_ORIGIN, CERTIFICATE_ORIGIN].includes(this.serviceOrigin)) {
      throw new AuthenticationError(
        "invalid-input",
        "Use the target service origin, not the SSO origin",
      );
    }
    this.#transport = options.transport || defaultTransport;
    this.#maxRequests = options.maxRequests ?? 80;
  }
  allowedURL(value: string, base?: string): URL {
    const url = httpsURL(value, base);
    if (
      ![this.serviceOrigin, SSO_ORIGIN, CERTIFICATE_ORIGIN].includes(url.origin)
    ) {
      throw new AuthenticationError(
        "unsafe-destination",
        "Unexpected authentication destination",
      );
    }
    return url;
  }
  useCertificate(certificate: Certificate): void {
    try {
      this.#contexts.set(
        CERTIFICATE_ORIGIN,
        createSecureContext({
          pfx: Buffer.from(certificate.pfx),
          passphrase: certificate.passphrase,
        }),
      );
    } catch {
      throw new AuthenticationError(
        "invalid-input",
        "Cannot load client certificate",
      );
    }
  }
  async request(navigation: Navigation, signal?: AbortSignal): Promise<Page> {
    if (this.#closed)
      throw new AuthenticationError("invalid-input", "Session is closed");
    let url = this.allowedURL(navigation.url);
    let body = navigation.body;
    let method = navigation.method || (body === undefined ? "GET" : "POST");
    for (let hop = 0; hop < 12; hop++) {
      checkAbort(signal);
      if (++this.#requests > this.#maxRequests)
        throw new AuthenticationError(
          "unsupported",
          "Authentication request limit exceeded",
        );
      const headers: Record<string, string> = {
        "User-Agent": "jaist-sso",
        Cookie: this.cookies.header(url.href),
      };
      if (body !== undefined)
        headers["Content-Type"] = navigation.json
          ? "application/json"
          : "application/x-www-form-urlencoded";
      if (navigation.json)
        headers["Accept-API-Version"] = "protocol=1.0,resource=2.0";
      const deadline = AbortSignal.any([
        ...(signal ? [signal] : []),
        AbortSignal.timeout(20_000),
      ]);
      let response: TransportResponse;
      try {
        response = await interruptible(
          this.#transport({
            url: url.href,
            method,
            body,
            headers,
            signal: deadline,
            secureContext: this.#contexts.get(url.origin),
          }),
          deadline,
        );
      } catch (error) {
        checkAbort(deadline);
        if (error instanceof AuthenticationError) throw error;
        throw new AuthenticationError(
          "network",
          "Authentication transport failed",
        );
      }
      checkAbort(deadline);
      if (Buffer.byteLength(response.body) > MAX_RESPONSE_BYTES)
        throw new AuthenticationError(
          "unsupported",
          "Response size limit exceeded",
        );
      for (const cookie of response.cookies || [])
        this.cookies.set(cookie, url.href);
      if (
        [301, 302, 303, 307, 308].includes(response.status) &&
        response.location
      ) {
        const destination = this.allowedURL(response.location, url.href);
        if (
          [307, 308].includes(response.status) &&
          body !== undefined &&
          destination.origin !== url.origin
        ) {
          throw new AuthenticationError(
            "unsafe-destination",
            "Refused cross-origin POST replay",
          );
        }
        if ([301, 302, 303].includes(response.status)) {
          body = undefined;
          method = "GET";
        }
        url = destination;
        continue;
      }
      return { url: url.href, body: response.body, status: response.status };
    }
    throw new AuthenticationError("unsupported", "Too many HTTP redirects");
  }
  close(): void {
    this.#closed = true;
    this.cookies.clear();
    this.#contexts.clear();
  }
  toJSON(): string {
    return "[HttpSession]";
  }
}
