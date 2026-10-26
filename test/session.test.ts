import { expect, test } from "bun:test";
import { pageRedirect, samlForm } from "../src/saml.ts";
import { CookieJar, HttpSession } from "../src/session.ts";

test("cookies honor host, domain, path, expiry and secure prefixes", () => {
  const jar = new CookieJar();
  jar.set(
    "session=one; Path=/sso; Secure",
    "https://auth.jaist.ac.jp/sso/login",
  );
  expect(jar.header("https://vpn.jaist.ac.jp/")).toBe("");
  expect(jar.header("https://auth.jaist.ac.jp/ssomething")).toBe("");
  expect(jar.header("https://auth.jaist.ac.jp/sso/")).toBe("session=one");
  jar.set(
    "global=shared; Domain=jaist.ac.jp; Path=/; Secure",
    "https://auth.jaist.ac.jp/",
  );
  expect(jar.header("https://vpn.jaist.ac.jp/")).toBe("global=shared");
  jar.set("bad=one; Domain=ac.jp; Path=/", "https://auth.jaist.ac.jp/");
  jar.set(
    "__Host-bad=one; Domain=jaist.ac.jp; Path=/; Secure",
    "https://auth.jaist.ac.jp/",
  );
  jar.set("expired=one; Max-Age=0; Path=/", "https://auth.jaist.ac.jp/");
  expect(jar.header("https://auth.jaist.ac.jp/")).toBe("global=shared");
  expect(JSON.stringify(jar)).toBe('"[CookieJar]"');
  jar.clear();
  expect(jar.header("https://auth.jaist.ac.jp/sso/")).toBe("");
});
test("redirects are validated before requests and POST bodies cannot cross origins on 307", async () => {
  let calls = 0;
  const session = new HttpSession({
    serviceOrigin: "https://vpn.jaist.ac.jp",
    transport: async () => {
      calls++;
      return {
        status: 307,
        body: "",
        location: "https://auth.jaist.ac.jp/receive",
      };
    },
  });
  await expect(
    session.request({
      url: "https://vpn.jaist.ac.jp/",
      body: "password=synthetic",
    }),
  ).rejects.toMatchObject({ code: "unsafe-destination" });
  expect(calls).toBe(1);
  await expect(
    session.request({ url: "http://vpn.jaist.ac.jp/" }),
  ).rejects.toMatchObject({ code: "unsafe-destination" });
  await expect(
    session.request({ url: "https://untrusted.invalid/" }),
  ).rejects.toMatchObject({ code: "unsafe-destination" });
  expect(calls).toBe(1);
});
test("cookie parsing retains embedded equals and removes expired replacements", () => {
  const jar = new CookieJar();
  jar.set("ticket=a=b==; Path=/", "https://vpn.jaist.ac.jp/");
  expect(jar.values("https://vpn.jaist.ac.jp/").ticket).toBe("a=b==");
  jar.set("ticket=gone; Path=/; Max-Age=0", "https://vpn.jaist.ac.jp/");
  expect(jar.header("https://vpn.jaist.ac.jp/")).toBe("");
});
test("SAML parser handles quoted >, entities and duplicate hidden field order", () => {
  const page = {
    url: "https://auth.jaist.ac.jp/sso",
    status: 200,
    body: `<form action="https://vpn.jaist.ac.jp/acs?x=1&amp;y=2" method="POST" title="a > b"><input name="SAMLResponse" type="hidden" value="a+b/=="><input type=hidden name=RelayState value="&#65;&amp;"></form>`,
  };
  const form = samlForm(page);
  expect(form?.url).toBe("https://vpn.jaist.ac.jp/acs?x=1&y=2");
  expect(form?.fields).toEqual([
    ["SAMLResponse", "a+b/=="],
    ["RelayState", "A&"],
  ]);
});
test("SAML parser rejects ambiguity and ignores forms written in scripts", () => {
  const form = `<form method="POST"><input type="hidden" name="SAMLResponse" value="one"></form>`;
  expect(() =>
    samlForm({
      url: "https://auth.jaist.ac.jp/",
      status: 200,
      body: form + form,
    }),
  ).toThrow();
  expect(
    samlForm({
      url: "https://auth.jaist.ac.jp/",
      status: 200,
      body: `<script>${form}</script>`,
    }),
  ).toBeUndefined();
});
test("landing template redirect preserves the original query without evaluating JavaScript", () => {
  expect(
    pageRedirect({
      url: "https://auth.jaist.ac.jp/sso/?realm=x&goto=y",
      status: 200,
      body: `<script>var params = getQueryParameters(); var url = '/sso/UI/Login'; url += params; top.location.replace(url);</script>`,
    }),
  ).toBe("/sso/UI/Login?realm=x&goto=y");
});
test("closed sessions cannot be reused and request limits bound loops", async () => {
  const session = new HttpSession({
    serviceOrigin: "https://vpn.jaist.ac.jp",
    maxRequests: 1,
    transport: async () => ({ status: 302, body: "", location: "/again" }),
  });
  await expect(
    session.request({ url: "https://vpn.jaist.ac.jp/" }),
  ).rejects.toMatchObject({ code: "unsupported" });
  session.close();
  await expect(
    session.request({ url: "https://vpn.jaist.ac.jp/" }),
  ).rejects.toMatchObject({ code: "invalid-input" });
});
