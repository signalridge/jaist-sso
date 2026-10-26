# jaist-sso

JAIST-SSO authentication for Bun applications. The library completes password
and second-factor authentication and returns the SAML POST callback for the
calling service. It does not create a VPN tunnel or assume a credential store.

TypeScript runs directly on Bun 1.4.4 or later. There are **no third-party runtime
dependencies**. Biome, TypeScript and Bun type definitions are development-only.
The package is published under the MIT license.

## Installation

```sh
bun add @signalridge/jaist-sso
bunx @signalridge/jaist-sso --help
```

## Development

```sh
bun install --frozen-lockfile
bun run check
bun run format
```

`check` runs Biome lint, formatting/import checks, strict TypeScript checking and
the test suite. Individual commands are `lint`, `format:check`, `typecheck` and
`test`. Tests generate synthetic certificates through the existing OpenSSL CLI;
no JAIST credentials or network access are required by the tests. CI checks Linux
and macOS. No compilation step is needed for running the library or CLI.

## Library

```ts
import { authenticate, HttpSession } from "@signalridge/jaist-sso";
import { createTerminalHandler } from "@signalridge/jaist-sso/terminal";

const session = new HttpSession({ serviceOrigin: "https://service.example" });
try {
  const callback = await authenticate({
    session,
    request: { url: "https://service.example/" },
    method: "totp",
    credentials: {
      username: async () => readUsername(),
      password: async () => readPassword(),
    },
    onChallenge: createTerminalHandler(),
    signal: abortController.signal,
  });

  // The caller submits this callback using the SAME session. The target service
  // validates the SAML response and establishes its own session.
  const result = await session.request({
    url: callback.url,
    method: "POST",
    body: new URLSearchParams(
      callback.fields.map(([k, v]) => [k, v]),
    ).toString(),
  });
  // Validate service-specific success here; HTTP 200 alone may be a login page.
} finally {
  session.close();
}
```

The `readUsername`, `readPassword` and `abortController` names above are supplied
by your application. `request` can instead be the service's already prepared
SAML POST navigation. The service origin must be explicit. JAIST SSO and its
certificate IdP are the only additional allowed origins; arbitrary redirects and
cross-origin 307/308 POST replay are rejected.

The only target-service assumption is a SAML POST binding. JavaScript execution,
FIDO2/passkeys and arbitrary third-party authentication chains are not implemented.
Compatibility with another JAIST-connected service requires its own validation.

## Authentication methods

| Method        | Credential provider                                     | Interaction                                                        |
| ------------- | ------------------------------------------------------- | ------------------------------------------------------------------ |
| `certificate` | `certificate: async () => ({ pfx, passphrase })`        | PKCS#12 stays in memory and is offered only to the certificate IdP |
| `totp`        | `otp: async (method, signal) => code`, or `onChallenge` | Current Authenticator code                                         |
| `email-otp`   | Same OTP provider/handler                               | Code from the email sent by JAIST                                  |

If `method` is omitted, `onChallenge` selects from the server's supported choices.
The library does not read OTP seeds or mailboxes. Applications can supply their
own code provider. It never chooses a different factor after rejection or
automatically repeats a rejected password. OTP challenge continuations are bounded
to three code submissions; providers must supply fresh codes rather than replay
a rejected value. Email resending is not automated.

Only the certificate path has been validated against the live JAIST VPN service.
OTP paths have complete synthetic transaction tests and still need live validation.

## Interaction and headless use

The core has no stdin reads or UI. `onChallenge` receives a typed `username`,
`password`, `method`, `certificate` or `otp` challenge with an abort signal.
The optional terminal handler hides passwords/OTP, does not retain history and
restores terminal mode on completion/cancellation. It returns `input-required`
when no interactive terminal is available.

Headless applications use credential providers. A missing factor produces
`AuthenticationError` with code `input-required`, rather than polling/retrying.
Other stable codes include `rejected`, `unsupported`, `unsafe-destination`,
`invalid-input`, `cancelled`, `timeout` and `network`. Exceptions from your own
providers remain your responsibility; the CLI prints only known safe errors.

## CLI and credential pipes

Interactive OTP login starts at the original service URL, not a bookmarked SSO
URL containing temporary SAML state:

```sh
bun src/cli.ts --url https://service.example/ --method totp
```

Use `--credentials-stdin` for non-interactive JSON, or `--credentials-fd 3` to
keep stdin available for terminal OTP input. Your credential producer writes
JSON with this shape through the pipe (these are synthetic placeholders):

```json
{
  "username": "synthetic-user",
  "password": "synthetic-password",
  "certificate": {
    "pfxBase64": "BASE64_PKCS12_FROM_YOUR_CREDENTIAL_PROVIDER",
    "passphrase": "synthetic-export-password"
  }
}
```

`certificate` is needed only for certificate authentication. An optional `otp`
string can supply one OTP; the CLI never reuses it after a rejection. Username,
password, certificate and code are not accepted as command-line values or read
from environment variables. `--session-json` explicitly emits service-scoped
cookies to a pipe/redirected stdout and refuses a terminal. Treat that output as
a credential; the default output contains only completion status.

## Security boundaries

Cookies, certificates, passwords and SAML messages are held in memory. No
temporary key files, browser profiles or persistent cookie jars are used. JavaScript
and native TLS memory cannot be guaranteed to be securely erased; release
references and call `close()` when finished. Session objects redact accidental JSON
serialization, but explicit cookie values and SAML callbacks are sensitive.

Keep real credentials, certificates, HAR files and HTTP dumps out of Git, tests,
CI and issue reports. Tests and logs must use synthetic values. Do not disable TLS
verification or automatic redirect checks. A consuming daemon should pause after
authentication rejection rather than starting repeated login transactions.

## Releases

Run `bun run check` and `bun run pack:check` before creating a version tag.
The tag must equal `v` followed by the manifest version. `publish.yml` validates
the clean checkout, archive allowlist and npm integrity, publishes with npm Trusted
Publishing/OIDC and provenance, then creates the GitHub release. A published
version is reused only when its contents match; changed contents require a new
version. The first publication of a new npm name requires an authenticated
bootstrap, followed by a Trusted Publisher binding to this repository,
`publish.yml`, and the `npm-publish` environment. No long-lived npm token is used
by the workflow.

Use one `HttpSession` per transaction; do not run concurrent login flows through
a shared session. Caller-supplied sessions remain caller-owned and must be closed.
