// Synthetic OpenAM/F5 transaction. No requests leave this transport.
import { spawnSync } from "node:child_process";
import type {
  Transport,
  TransportRequest,
  TransportResponse,
} from "../src/session.ts";
import { CERTIFICATE_ORIGIN, SSO_ORIGIN } from "../src/session.ts";

export const SERVICE = "https://vpn.jaist.ac.jp";
const mainXui = `${SSO_ORIGIN}/sso/XUI/#login/&realm=/jaist&goto=%2FSSOPOST%2Freturn`;
const certXui = `${CERTIFICATE_ORIGIN}/sso/XUI/#login/&realm=/&goto=%2FSSOPOST%2Freturn`;
function callback(
  type: string,
  output: Record<string, unknown> = {},
  value: unknown = "",
) {
  return {
    type,
    input: type === "RedirectCallback" ? [] : [{ name: "IDToken1", value }],
    output: Object.entries(output).map(([name, value]) => ({ name, value })),
  };
}
export function syntheticPfx(): Uint8Array {
  const result = spawnSync(
    "bash",
    [
      "-c",
      `
set -euo pipefail
pem="$(openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=synthetic.invalid -days 1 -keyout /dev/stdout -out /dev/stdout 2>/dev/null)"
openssl pkcs12 -export -in <(printf '%s' "$pem") -inkey <(printf '%s' "$pem") -passout pass:synthetic-test -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256 2>/dev/null
`,
    ],
    { stdio: ["ignore", "pipe", "pipe"], timeout: 15_000 },
  );
  if (result.status !== 0)
    throw new Error(
      "OpenSSL is required to generate synthetic in-memory test certificates",
    );
  return result.stdout;
}

export function fixture(
  options: {
    rejectPassword?: boolean;
    rejectOtp?: boolean;
    missingTicket?: boolean;
    callbackOrigin?: string;
  } = {},
) {
  let phase = 0;
  let method = -1;
  const calls: TransportRequest[] = [];
  const json = (data: unknown, status = 200): TransportResponse => ({
    status,
    body: JSON.stringify(data),
  });
  const form = (
    origin: string,
    name: string,
    value: string,
  ): TransportResponse => ({
    status: 200,
    body: `<form method='POST' action='${origin}'><input name='${name}' type='hidden' value='${value}'><input type='hidden' name='RelayState' value='opaque&amp;state'></form>`,
  });
  const transport: Transport = async (request) => {
    calls.push(request);
    const url = new URL(request.url);
    if (url.origin === SERVICE && url.pathname === "/")
      return {
        ...form(
          `${SSO_ORIGIN}/sso/start`,
          "SAMLRequest",
          "synthetic+request/==",
        ),
        cookies: ["MRHSession=initial; Path=/; Secure"],
      };
    if (url.origin === SSO_ORIGIN && url.pathname === "/sso/start")
      return {
        status: 302,
        body: "",
        location: mainXui,
        cookies: ["AMAuthCookie=synthetic; Path=/; Secure"],
      };
    if (url.pathname === "/sso/XUI/")
      return { status: 200, body: "<html></html>" };
    if (
      url.origin === SSO_ORIGIN &&
      url.pathname === "/sso/json/authenticate"
    ) {
      const data = request.body ? JSON.parse(request.body) : {};
      if (data.authId === "certificate-pending")
        return json({ tokenId: "synthetic-main-token" });
      if (phase++ === 0)
        return json({
          authId: "username",
          callbacks: [callback("NameCallback")],
        });
      if (phase === 2) {
        if (data.callbacks[0].input[0].value !== "synthetic-user")
          throw new Error("Username was not supplied");
        return json({
          authId: "password",
          callbacks: [callback("PasswordCallback")],
        });
      }
      if (phase === 3) {
        if (options.rejectPassword)
          return json({ code: 401, message: "synthetic rejection" }, 401);
        if (data.callbacks[0].input[0].value !== "synthetic-password")
          throw new Error("Password was not supplied");
        return json({
          authId: "methods",
          callbacks: [
            callback("ChoiceCallback", {
              choices: [
                "OTP (Email)",
                "OTP (Authenticator)",
                "Client Certificate",
              ],
            }),
            callback("ConfirmationCallback", { options: ["Next"] }),
          ],
        });
      }
      if (phase === 4) {
        method = data.callbacks[0].input[0].value;
        if (method === 2)
          return json({
            authId: "certificate-pending",
            callbacks: [
              callback("RedirectCallback", {
                redirectUrl: `${CERTIFICATE_ORIGIN}/sso/start`,
                redirectMethod: "GET",
                trackingCookie: true,
              }),
            ],
          });
        return json({
          authId: "otp",
          callbacks: [
            callback("PasswordCallback"),
            callback("ConfirmationCallback", { options: ["Submit", "Cancel"] }),
          ],
        });
      }
      const code = data.callbacks[0].input[0].value;
      if (options.rejectOtp || code !== (method === 0 ? "12345678" : "123456"))
        return json({ code: 401 }, 401);
      return json({ tokenId: "synthetic-main-token" });
    }
    if (url.origin === CERTIFICATE_ORIGIN && url.pathname === "/sso/start") {
      if (!request.secureContext)
        throw new Error(
          "Certificate context was not offered to certificate IdP",
        );
      return { status: 302, body: "", location: certXui };
    }
    if (
      url.origin === CERTIFICATE_ORIGIN &&
      url.pathname === "/sso/json/authenticate"
    )
      return json({ tokenId: "synthetic-cert-token" });
    if (
      url.origin === CERTIFICATE_ORIGIN &&
      url.pathname === "/sso/SSOPOST/return"
    )
      return form(
        `${SSO_ORIGIN}/sso/cert-return`,
        "SAMLResponse",
        "synthetic-certificate-assertion",
      );
    if (url.origin === SSO_ORIGIN && url.pathname === "/sso/cert-return") {
      if (!request.headers.Cookie?.includes("authId=certificate-pending"))
        throw new Error("Pending authentication was not retained");
      return {
        status: 302,
        body: "",
        location: `${SSO_ORIGIN}/sso/?realm=/jaist&goto=%2FSSOPOST%2Freturn`,
      };
    }
    if (url.origin === SSO_ORIGIN && url.pathname === "/sso/")
      return {
        status: 200,
        body: `<script>function redirectToAuth() { var params = getQueryParameters(); var url = "/sso/UI/Login"; if (params != "") { url += params; } top.location.replace(url); }</script>`,
      };
    if (url.origin === SSO_ORIGIN && url.pathname === "/sso/UI/Login")
      return { status: 302, body: "", location: mainXui };
    if (url.origin === SSO_ORIGIN && url.pathname === "/sso/SSOPOST/return")
      return form(
        `${options.callbackOrigin || SERVICE}/saml/acs`,
        "SAMLResponse",
        "synthetic+assertion/==",
      );
    if (url.origin === SERVICE && url.pathname === "/saml/acs") {
      if (!request.headers.Cookie?.includes("MRHSession=initial"))
        throw new Error("Initial gateway session was lost");
      const body = new URLSearchParams(request.body);
      if (
        body.get("SAMLResponse") !== "synthetic+assertion/==" ||
        body.get("RelayState") !== "opaque&state"
      )
        throw new Error("SAML fields were changed");
      return {
        status: 200,
        body: "<html>synthetic portal</html>",
        cookies: [
          "MRHSession=synthetic-vpn-session; Path=/; Secure",
          ...(options.missingTicket
            ? []
            : ["F5_ST=synthetic-ticket; Path=/; Secure"]),
        ],
      };
    }
    throw new Error("Unexpected synthetic request");
  };
  return { transport, calls };
}
