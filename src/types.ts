export type AuthMethod = "certificate" | "totp" | "email-otp";
export type Certificate = { pfx: Uint8Array; passphrase?: string };
export type Challenge =
  | { kind: "username"; signal: AbortSignal }
  | { kind: "password"; signal: AbortSignal }
  | { kind: "method"; methods: readonly AuthMethod[]; signal: AbortSignal }
  | { kind: "certificate"; signal: AbortSignal }
  | {
      kind: "otp";
      method: "totp" | "email-otp";
      attempt: number;
      signal: AbortSignal;
    };

export type ChallengeAnswer = string | Certificate;
export type ChallengeHandler = (
  challenge: Challenge,
) => Promise<ChallengeAnswer>;
export type CredentialProvider = {
  username?: () => Promise<string>;
  password?: () => Promise<string>;
  certificate?: () => Promise<Certificate>;
  otp?: (method: "totp" | "email-otp", signal: AbortSignal) => Promise<string>;
};
export type Navigation = {
  url: string;
  method?: "GET" | "POST";
  body?: string;
  json?: boolean;
};
export type Page = { url: string; body: string; status: number };
export type ServiceCallback = {
  url: string;
  method: "POST";
  fields: readonly (readonly [string, string])[];
};
