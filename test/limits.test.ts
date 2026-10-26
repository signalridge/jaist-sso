import { expect, test } from "bun:test";
import { interruptible } from "../src/errors.ts";
import { authenticate, HttpSession } from "../src/index.ts";
import { fixture, SERVICE } from "./fixture.ts";

test("the total deadline interrupts an uncooperative custom transport", async () => {
  const session = new HttpSession({
    serviceOrigin: SERVICE,
    transport: async () => new Promise(() => {}),
  });
  await expect(
    authenticate({ session, request: { url: SERVICE }, timeoutMs: 10 }),
  ).rejects.toMatchObject({ code: "timeout" });
});

test("a promise is still observed when its producer aborts before returning it", async () => {
  const controller = new AbortController();
  controller.abort();
  await expect(
    interruptible(
      Promise.reject(new Error("synthetic-provider-error")),
      controller.signal,
    ),
  ).rejects.toMatchObject({ code: "cancelled" });
  await Bun.sleep(0);
});
test("unknown challenges stop without submitting credentials", async () => {
  const mock = fixture();
  let credentialsRead = 0;
  const session = new HttpSession({
    serviceOrigin: SERVICE,
    transport: async (request) => {
      if (new URL(request.url).pathname === "/sso/json/authenticate")
        return {
          status: 200,
          body: JSON.stringify({
            authId: "unknown",
            callbacks: [{ type: "UnknownCallback", input: [], output: [] }],
          }),
        };
      return mock.transport(request);
    },
  });
  await expect(
    authenticate({
      session,
      request: { url: SERVICE },
      credentials: {
        username: async () => {
          credentialsRead++;
          return "synthetic";
        },
      },
    }),
  ).rejects.toMatchObject({ code: "unsupported" });
  expect(credentialsRead).toBe(0);
});
test("repeated OTP challenges have a bounded attempt count", async () => {
  const mock = fixture();
  let attempts = 0;
  const session = new HttpSession({
    serviceOrigin: SERVICE,
    transport: async (request) => {
      if (request.body?.includes('"authId":"otp"'))
        return {
          status: 401,
          body: JSON.stringify({
            authId: "otp",
            callbacks: [
              {
                type: "PasswordCallback",
                input: [{ name: "IDToken1", value: "" }],
                output: [],
              },
            ],
          }),
        };
      return mock.transport(request);
    },
  });
  await expect(
    authenticate({
      session,
      request: { url: SERVICE },
      method: "totp",
      credentials: {
        username: async () => "synthetic-user",
        password: async () => "synthetic-password",
        otp: async () => {
          attempts++;
          return "123456";
        },
      },
    }),
  ).rejects.toMatchObject({ code: "rejected" });
  expect(attempts).toBe(3);
});
test("server hidden fields are echoed without invoking a credential prompt", async () => {
  const mock = fixture();
  let echoed = false;
  const session = new HttpSession({
    serviceOrigin: SERVICE,
    transport: async (request) => {
      const page = await mock.transport(request);
      if (request.body?.includes('"authId":"username"')) {
        echoed = JSON.parse(request.body).callbacks.some(
          (value: { type: string; input: { value: string }[] }) =>
            value.type === "HiddenValueCallback" &&
            value.input[0]?.value === "synthetic-tracking",
        );
      }
      if (
        new URL(request.url).pathname === "/sso/json/authenticate" &&
        page.status === 200
      ) {
        const data = JSON.parse(page.body);
        if (data.authId === "username") {
          data.callbacks.push({
            type: "HiddenValueCallback",
            input: [{ name: "IDToken2", value: "synthetic-tracking" }],
            output: [],
          });
          return { ...page, body: JSON.stringify(data) };
        }
      }
      return page;
    },
  });
  await authenticate({
    session,
    request: { url: SERVICE },
    method: "totp",
    credentials: {
      username: async () => "synthetic-user",
      password: async () => "synthetic-password",
      otp: async () => "123456",
    },
  });
  expect(echoed).toBe(true);
});

test("HTTP 401 cannot become success even if a token field is present", async () => {
  const mock = fixture();
  const session = new HttpSession({
    serviceOrigin: SERVICE,
    transport: async (request) => {
      if (request.body?.includes('"authId":"otp"'))
        return {
          status: 401,
          body: JSON.stringify({ tokenId: "synthetic-token" }),
        };
      return mock.transport(request);
    },
  });
  await expect(
    authenticate({
      session,
      request: { url: SERVICE },
      method: "totp",
      credentials: {
        username: async () => "synthetic-user",
        password: async () => "synthetic-password",
        otp: async () => "123456",
      },
    }),
  ).rejects.toMatchObject({ code: "rejected" });
});
