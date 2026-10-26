# Changelog

## 0.1.0

- Add a JAIST-SSO transaction API with password and certificate, Authenticator OTP
  and email OTP challenges.
- Add opt-in terminal interaction and a CLI with credential-pipe input.
- Keep PKCS#12 keys, cookies and SAML state in memory; restrict authentication
  navigation to the explicit service and JAIST identity providers.
- Bound timeouts and OTP attempts; stop on unsupported or rejected authentication.
- Protect CLI diagnostics from provider error messages and terminal secret echo.

Certificate authentication has live validation against the default JAIST VPN
gateway. OTP methods have synthetic transaction tests and need live validation.
