import { AuthenticationError, checkAbort, interruptible } from "./errors.ts";
import { pageRedirect, samlForm } from "./saml.ts";
import { CERTIFICATE_ORIGIN, type HttpSession, SSO_ORIGIN } from "./session.ts";
import type {
  AuthMethod,
  Certificate,
  Challenge,
  ChallengeAnswer,
  ChallengeHandler,
  CredentialProvider,
  Navigation,
  Page,
  ServiceCallback,
} from "./types.ts";

type Callback = {
  type: string;
  input: { name: string; value: unknown }[];
  output: { name: string; value: unknown }[];
};
type AuthResponse = {
  authId?: string;
  tokenId?: string;
  callbacks: Callback[];
};
export type AuthenticateOptions = {
  session: HttpSession;
  request: Navigation;
  method?: AuthMethod;
  credentials?: CredentialProvider;
  onChallenge?: ChallengeHandler;
  signal?: AbortSignal;
  timeoutMs?: number;
};

export function methodForLabel(label: string): AuthMethod | undefined {
  const value = label.trim().toLowerCase().replace(/\s+/g, " ");
  if (value === "client certificate") return "certificate";
  if (value === "otp (authenticator)" || value === "otp (app)") return "totp";
  if (value === "otp (email)") return "email-otp";
}

function response(value: unknown): AuthResponse {
  if (!value || typeof value !== "object")
    throw new AuthenticationError("unsupported", "Invalid SSO response");
  const data = value as Record<string, unknown>;
  if (typeof data.tokenId === "string" && data.tokenId)
    return { tokenId: data.tokenId, callbacks: [] };
  if (
    typeof data.authId !== "string" ||
    !data.authId ||
    !Array.isArray(data.callbacks)
  ) {
    throw new AuthenticationError(
      "rejected",
      "SSO authentication was rejected",
    );
  }
  const callbacks: Callback[] = data.callbacks.map((value) => {
    if (!value || typeof value !== "object")
      throw new AuthenticationError("unsupported", "Invalid SSO callback");
    const item = value as Record<string, unknown>;
    if (typeof item.type !== "string")
      throw new AuthenticationError("unsupported", "Invalid SSO callback");
    const fields = (value: unknown): { name: string; value: unknown }[] => {
      if (value === undefined) return [];
      if (
        !Array.isArray(value) ||
        value.some(
          (x) => !x || typeof x !== "object" || typeof x.name !== "string",
        )
      ) {
        throw new AuthenticationError(
          "unsupported",
          "Invalid SSO callback fields",
        );
      }
      return value as { name: string; value: unknown }[];
    };
    return {
      type: item.type,
      input: fields(item.input),
      output: fields(item.output),
    };
  });
  return { authId: data.authId, callbacks };
}

function certificate(value: ChallengeAnswer): Certificate {
  if (
    typeof value === "string" ||
    !(value.pfx instanceof Uint8Array) ||
    !value.pfx.byteLength ||
    (value.passphrase !== undefined && typeof value.passphrase !== "string")
  ) {
    throw new AuthenticationError(
      "invalid-input",
      "A PKCS#12 certificate is required",
    );
  }
  return value;
}

/** One authentication transaction. No automatic retry of rejected credentials. */
export async function authenticate(
  options: AuthenticateOptions,
): Promise<ServiceCallback> {
  const timeout = options.timeoutMs ?? 180_000;
  if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > 900_000)
    throw new AuthenticationError(
      "invalid-input",
      "Invalid authentication timeout",
    );
  const signal = AbortSignal.any([
    ...(options.signal ? [options.signal] : []),
    AbortSignal.timeout(timeout),
  ]);
  const { session } = options;
  const credentials = options.credentials || {};
  const pending = new Map<string, string>();
  const submitted = new Set<string>();
  let selected: AuthMethod | undefined;
  let otpAttempts = 0;
  let completed = false;

  async function ask(
    challenge: Challenge,
    provider?: () => Promise<ChallengeAnswer>,
  ): Promise<ChallengeAnswer> {
    checkAbort(signal);
    const promise = provider ? provider() : options.onChallenge?.(challenge);
    if (!promise)
      throw new AuthenticationError(
        "input-required",
        `Input required: ${challenge.kind}`,
      );
    return interruptible(promise, signal);
  }
  function text(value: ChallengeAnswer): string {
    if (
      typeof value !== "string" ||
      !value ||
      /[\r\n]/.test(value) ||
      value.includes("\0")
    )
      throw new AuthenticationError(
        "invalid-input",
        "Invalid authentication input",
      );
    return value;
  }
  async function api(url: string, payload?: unknown): Promise<AuthResponse> {
    const page = await session.request(
      {
        url,
        method: "POST",
        json: true,
        body: payload ? JSON.stringify(payload) : "",
      },
      signal,
    );
    if (page.status !== 200 && page.status !== 401)
      throw new AuthenticationError(
        page.status >= 500 ? "network" : "rejected",
        "SSO request failed",
      );
    let value: unknown;
    try {
      value = JSON.parse(page.body);
    } catch {
      throw new AuthenticationError("unsupported", "SSO response is not JSON");
    }
    const result = response(value);
    if (
      page.status === 401 &&
      (result.tokenId || !(selected === "totp" || selected === "email-otp"))
    ) {
      throw new AuthenticationError(
        "rejected",
        "SSO credentials were rejected",
      );
    }
    return result;
  }

  async function openam(value: string): Promise<Page> {
    const url = session.allowedURL(value);
    if (![SSO_ORIGIN, CERTIFICATE_ORIGIN].includes(url.origin))
      throw new AuthenticationError(
        "unsafe-destination",
        "Unexpected SSO origin",
      );
    const fragment = url.hash.slice(1);
    const params = new URLSearchParams(
      fragment.includes("&") ? fragment.slice(fragment.indexOf("&") + 1) : "",
    );
    for (const [key, value] of url.searchParams) params.set(key, value);
    const apiURL = `${url.origin}/sso/json/authenticate?${params}`;
    const saved = pending.get(url.origin);
    pending.delete(url.origin);
    let auth = await api(
      apiURL,
      saved ? { ...Object.fromEntries(params), authId: saved } : undefined,
    );
    for (let step = 0; step < 16; step++) {
      if (auth.tokenId) {
        session.cookies.set(
          `iPlanetDirectoryPro=${auth.tokenId}; Path=/; Secure`,
          url.origin,
        );
        if (url.origin === SSO_ORIGIN) completed = true;
        const target = params.get("goto");
        if (!target)
          throw new AuthenticationError(
            "unsupported",
            "Missing SAML continuation",
          );
        return session.request(
          {
            url: session.allowedURL(
              target.replace(/^\//, ""),
              `${url.origin}/sso/`,
            ).href,
          },
          signal,
        );
      }
      if (!auth.authId || !auth.callbacks.length)
        throw new AuthenticationError("unsupported", "Missing SSO challenge");
      for (const callback of auth.callbacks) {
        const output = Object.fromEntries(
          callback.output.map((x) => [x.name, x.value]),
        );
        const input = callback.input;
        const field = input[0];
        if (callback.type === "RedirectCallback") {
          if (typeof output.redirectUrl !== "string")
            throw new AuthenticationError(
              "unsupported",
              "Missing authentication redirect",
            );
          const destination = session.allowedURL(output.redirectUrl);
          if (![SSO_ORIGIN, CERTIFICATE_ORIGIN].includes(destination.origin))
            throw new AuthenticationError(
              "unsafe-destination",
              "Unexpected authentication redirect",
            );
          pending.set(url.origin, auth.authId);
          if (output.trackingCookie === true)
            session.cookies.set(
              `authId=${auth.authId}; Path=/; Secure`,
              url.origin,
            );
          if (output.redirectMethod === "POST") {
            if (
              !output.redirectData ||
              typeof output.redirectData !== "object" ||
              Array.isArray(output.redirectData) ||
              Object.values(output.redirectData).some(
                (x) => typeof x !== "string",
              )
            )
              throw new AuthenticationError(
                "unsupported",
                "Invalid authentication redirect data",
              );
            return session.request(
              {
                url: destination.href,
                method: "POST",
                body: new URLSearchParams(
                  output.redirectData as Record<string, string>,
                ).toString(),
              },
              signal,
            );
          }
          if (
            output.redirectMethod !== undefined &&
            output.redirectMethod !== "GET"
          )
            throw new AuthenticationError(
              "unsupported",
              "Unsupported authentication redirect method",
            );
          return session.request({ url: destination.href }, signal);
        }
        if (callback.type === "ChoiceCallback") {
          if (
            url.origin !== SSO_ORIGIN ||
            selected ||
            !Array.isArray(output.choices) ||
            output.choices.some((x) => typeof x !== "string") ||
            input.length !== 1 ||
            !field
          ) {
            throw new AuthenticationError(
              "unsupported",
              "Unexpected authentication method selection",
            );
          }
          const methods = output.choices.map((label) =>
            methodForLabel(label as string),
          );
          const available = methods.filter(
            (value): value is AuthMethod => value !== undefined,
          );
          if (!available.length)
            throw new AuthenticationError(
              "unsupported",
              "No supported authentication method is offered",
            );
          const requested =
            options.method ||
            (await ask({ kind: "method", methods: available, signal }));
          if (
            typeof requested !== "string" ||
            !available.includes(requested as AuthMethod) ||
            methods.filter((x) => x === requested).length !== 1
          ) {
            throw new AuthenticationError(
              "unsupported",
              "Requested authentication method is unavailable",
            );
          }
          selected = requested as AuthMethod;
          field.value = methods.indexOf(selected);
          if (selected === "certificate") {
            const value = certificate(
              await ask(
                { kind: "certificate", signal },
                credentials.certificate,
              ),
            );
            session.useCertificate(value);
          }
        } else if (
          ["NameCallback", "PasswordCallback"].includes(callback.type)
        ) {
          if (url.origin !== SSO_ORIGIN || input.length !== 1 || !field)
            throw new AuthenticationError(
              "unsupported",
              "Unexpected credential challenge",
            );
          if (selected === "totp" || selected === "email-otp") {
            if (++otpAttempts > 3)
              throw new AuthenticationError(
                "rejected",
                "OTP attempt limit reached",
              );
            const method = selected;
            const getOTP = credentials.otp;
            const code = text(
              await ask(
                { kind: "otp", method, attempt: otpAttempts, signal },
                getOTP ? () => getOTP(method, signal) : undefined,
              ),
            );
            if (!/^\d{6,8}$/.test(code))
              throw new AuthenticationError(
                "invalid-input",
                "OTP must contain 6 to 8 digits",
              );
            field.value = code;
          } else {
            if (selected || submitted.has(callback.type))
              throw new AuthenticationError(
                "rejected",
                "Repeated credential challenge; stopped",
              );
            const kind =
              callback.type === "NameCallback" ? "username" : "password";
            field.value = text(await ask({ kind, signal }, credentials[kind]));
            submitted.add(callback.type);
          }
        } else if (callback.type === "ConfirmationCallback") {
          if (
            input.length !== 1 ||
            !field ||
            (output.options !== undefined &&
              (!Array.isArray(output.options) ||
                output.options.some((x) => typeof x !== "string")))
          ) {
            throw new AuthenticationError(
              "unsupported",
              "Invalid confirmation challenge",
            );
          }
          const labels = (output.options as string[] | undefined) || [];
          const matches = labels.flatMap((label, i) =>
            ["ok", "next", "continue", "submit", "login", "log in"].includes(
              label.trim().toLowerCase(),
            )
              ? [i]
              : [],
          );
          if (matches.length === 1) field.value = matches[0];
          else if (
            !labels.length &&
            [0, 1, 2].includes(output.optionType as number)
          )
            field.value = 0;
          else
            throw new AuthenticationError(
              "unsupported",
              "Unsupported confirmation options",
            );
        } else if (
          callback.type === "HiddenValueCallback" &&
          input.every((x) => typeof x.value === "string")
        ) {
          // Server-provided tracking values are echoed, never prompted for.
        } else if (!(callback.type === "TextOutputCallback" && !input.length)) {
          throw new AuthenticationError(
            "unsupported",
            "Unsupported authentication challenge",
          );
        }
      }
      auth = await api(apiURL, auth);
    }
    throw new AuthenticationError("unsupported", "SSO step limit reached");
  }

  let page = await session.request(options.request, signal);
  for (let step = 0; step < 32; step++) {
    checkAbort(signal);
    if (page.status !== 200)
      throw new AuthenticationError(
        page.status >= 500 ? "network" : "rejected",
        "Authentication navigation failed",
      );
    const url = session.allowedURL(page.url);
    if (url.pathname.replace(/\/$/, "").endsWith("/XUI")) {
      page = await openam(url.href);
      continue;
    }
    const form = samlForm(page);
    if (form) {
      const destination = session.allowedURL(form.url);
      if (destination.origin === session.serviceOrigin) {
        if (
          !completed ||
          !form.fields.some(([name, value]) => name === "SAMLResponse" && value)
        )
          throw new AuthenticationError(
            "unsupported",
            "Missing completed SAML response",
          );
        return form;
      }
      page = await session.request(
        {
          url: form.url,
          method: "POST",
          body: new URLSearchParams(
            form.fields.map(([k, v]) => [k, v]),
          ).toString(),
        },
        signal,
      );
      continue;
    }
    const redirect = pageRedirect(page);
    if (!redirect)
      throw new AuthenticationError("unsupported", "Unsupported SAML page");
    page = await session.request(
      { url: session.allowedURL(redirect, page.url).href },
      signal,
    );
  }
  throw new AuthenticationError("unsupported", "SAML step limit reached");
}
