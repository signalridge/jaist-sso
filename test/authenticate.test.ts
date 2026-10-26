import { describe, expect, test } from "bun:test";
import { decodeCredentialInput } from "../src/cli-support.ts";
import {
  AuthenticationError,
  authenticate,
  HttpSession,
} from "../src/index.ts";
import { createTerminalHandler } from "../src/terminal.ts";
import { fixture, SERVICE, syntheticPfx } from "./fixture.ts";

const credentials = {
  username: async () => "synthetic-user",
  password: async () => "synthetic-password",
};
describe("authentication transactions", () => {
  for (const method of ["totp", "email-otp"] as const) {
    test(`completes ${method} and returns the target callback without submitting it`, async () => {
      const mock = fixture();
      const session = new HttpSession({
        serviceOrigin: SERVICE,
        transport: mock.transport,
      });
      const seen: string[] = [];
      const result = await authenticate({
        session,
        request: { url: SERVICE },
        credentials,
        method,
        onChallenge: async (challenge) => {
          expect(challenge.kind).toBe("otp");
          if (challenge.kind !== "otp") throw new Error("Unexpected challenge");
          seen.push(challenge.method);
          return method === "totp" ? "123456" : "12345678";
        },
      });
      expect(seen).toEqual([method]);
      expect(result.url).toBe(`${SERVICE}/saml/acs`);
      expect(result.fields).toContainEqual([
        "SAMLResponse",
        "synthetic+assertion/==",
      ]);
      expect(mock.calls.some((x) => x.url === result.url)).toBe(false);
      expect(mock.calls.every((x) => x.secureContext === undefined)).toBe(true);
      session.close();
    });
  }
  test("certificate IdP authenticates and resumes the original authId without a second password", async () => {
    const mock = fixture();
    const session = new HttpSession({
      serviceOrigin: SERVICE,
      transport: mock.transport,
    });
    const pfx = syntheticPfx();
    try {
      const result = await authenticate({
        session,
        request: { url: SERVICE },
        method: "certificate",
        credentials: {
          ...credentials,
          certificate: async () => ({ pfx, passphrase: "synthetic-test" }),
        },
      });
      expect(result.url).toBe(`${SERVICE}/saml/acs`);
      expect(
        mock.calls
          .filter((x) => x.secureContext)
          .every(
            (x) => new URL(x.url).origin === "https://auth-cert.jaist.ac.jp",
          ),
      ).toBe(true);
      const passwordPosts = mock.calls.filter(
        (x) =>
          x.headers["Content-Type"] === "application/json" &&
          x.body?.includes('"authId":"password"'),
      );
      expect(passwordPosts).toHaveLength(1);
    } finally {
      pfx.fill(0);
      session.close();
    }
  });
  test("rejects the primary password once without retry", async () => {
    const mock = fixture({ rejectPassword: true });
    const session = new HttpSession({
      serviceOrigin: SERVICE,
      transport: mock.transport,
    });
    await expect(
      authenticate({
        session,
        request: { url: SERVICE },
        credentials,
        method: "totp",
      }),
    ).rejects.toMatchObject({ code: "rejected" });
    expect(
      mock.calls.filter((x) => x.body?.includes('"authId":"password"')),
    ).toHaveLength(1);
  });
  test("rejects an invalid OTP without reusing it or repeating the password", async () => {
    const mock = fixture({ rejectOtp: true });
    const session = new HttpSession({
      serviceOrigin: SERVICE,
      transport: mock.transport,
    });
    let attempts = 0;
    await expect(
      authenticate({
        session,
        request: { url: SERVICE },
        method: "totp",
        credentials: {
          ...credentials,
          otp: async () => {
            attempts++;
            return "123456";
          },
        },
      }),
    ).rejects.toMatchObject({ code: "rejected" });
    expect(attempts).toBe(1);
  });
  test("missing headless OTP input returns input-required", async () => {
    const mock = fixture();
    const session = new HttpSession({
      serviceOrigin: SERVICE,
      transport: mock.transport,
    });
    await expect(
      authenticate({
        session,
        request: { url: SERVICE },
        credentials,
        method: "email-otp",
      }),
    ).rejects.toMatchObject({ code: "input-required" });
  });
  test("the method choice is delegated to the caller", async () => {
    const mock = fixture();
    const session = new HttpSession({
      serviceOrigin: SERVICE,
      transport: mock.transport,
    });
    const seen: string[] = [];
    await authenticate({
      session,
      request: { url: SERVICE },
      credentials,
      onChallenge: async (c) => {
        seen.push(c.kind);
        return c.kind === "method" ? "totp" : "123456";
      },
    });
    expect(seen).toEqual(["method", "otp"]);
  });
  test("an unrelated service callback is never followed", async () => {
    const mock = fixture({ callbackOrigin: "https://untrusted.invalid" });
    const session = new HttpSession({
      serviceOrigin: SERVICE,
      transport: mock.transport,
    });
    await expect(
      authenticate({
        session,
        request: { url: SERVICE },
        method: "totp",
        credentials: {
          ...credentials,
          otp: async () => "123456",
        },
      }),
    ).rejects.toMatchObject({ code: "unsafe-destination" });
    expect(
      mock.calls.some((x) => x.url.startsWith("https://untrusted.invalid")),
    ).toBe(false);
  });
  test("abort interrupts a caller waiting for human input", async () => {
    const mock = fixture();
    const session = new HttpSession({
      serviceOrigin: SERVICE,
      transport: mock.transport,
    });
    const controller = new AbortController();
    const promise = authenticate({
      session,
      request: { url: SERVICE },
      signal: controller.signal,
      onChallenge: async () => {
        controller.abort();
        return new Promise(() => {});
      },
    });
    await expect(promise).rejects.toBeInstanceOf(AuthenticationError);
  });
});

test("credential JSON is read without evaluating commands or environment references", async () => {
  const provider = decodeCredentialInput(
    JSON.stringify({
      username: "$(not-a-command)",
      password: "$SECRET_LITERAL",
      otp: "123456",
    }),
  );
  expect(await provider.username?.()).toBe("$(not-a-command)");
  expect(await provider.password?.()).toBe("$SECRET_LITERAL");
  expect(await provider.otp?.("totp", new AbortController().signal)).toBe(
    "123456",
  );
  await expect(
    provider.otp?.("totp", new AbortController().signal),
  ).rejects.toMatchObject({ code: "input-required" });
});

test("non-interactive terminal handler fails instead of reading stdin", async () => {
  const handler = createTerminalHandler({
    input: { isTTY: false } as NodeJS.ReadStream,
    output: { isTTY: false } as NodeJS.WriteStream,
  });
  await expect(
    handler({ kind: "password", signal: new AbortController().signal }),
  ).rejects.toMatchObject({ code: "input-required" });
});
