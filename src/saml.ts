import { AuthenticationError } from "./errors.ts";
import type { Page, ServiceCallback } from "./types.ts";

function entity(value: string): string {
  const named: Record<string, string> = {
    amp: "&",
    quot: '"',
    apos: "'",
    lt: "<",
    gt: ">",
    nbsp: "\u00a0",
  };
  return value.replace(
    /&(#x[\da-f]+|#\d+|amp|quot|apos|lt|gt|nbsp);/gi,
    (_, name: string) => {
      if (!name.startsWith("#")) return named[name.toLowerCase()] || "";
      const n =
        name[1]?.toLowerCase() === "x"
          ? parseInt(name.slice(2), 16)
          : Number(name.slice(1));
      return n > 0 && n <= 0x10ffff ? String.fromCodePoint(n) : "\ufffd";
    },
  );
}
function attributes(source: string): Record<string, string> {
  const output: Record<string, string> = Object.create(null);
  for (const match of source.matchAll(
    /([^\s=<>/'"]+)\s*(?:=\s*(?:"([^"]*)"|'([^']*)'|([^\s<>]+)))?/g,
  )) {
    if (match[1])
      output[match[1].toLowerCase()] = entity(
        match[2] ?? match[3] ?? match[4] ?? "",
      );
  }
  return output;
}

/** Parse only the hidden SAML POST form, without executing page JavaScript. */
export function samlForm(page: Page): ServiceCallback | undefined {
  const source = page.body
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<script\b[^>]*>[\s\S]*?<\/script\s*>/gi, "");
  const forms: {
    action: string;
    method: string;
    fields: [string, string][];
  }[] = [];
  let current: (typeof forms)[number] | undefined;
  for (const match of source.matchAll(
    /<(\/?[a-z]+)\b((?:"[^"]*"|'[^']*'|[^'">])*)>/gi,
  )) {
    const tag = match[1]?.toLowerCase();
    const attrs = attributes(match[2] || "");
    if (tag === "form") {
      current = {
        action: attrs.action || "",
        method: (attrs.method || "GET").toUpperCase(),
        fields: [],
      };
      forms.push(current);
    } else if (tag === "/form") current = undefined;
    else if (
      tag === "input" &&
      current &&
      attrs.name &&
      attrs.type?.toLowerCase() === "hidden"
    ) {
      current.fields.push([attrs.name, attrs.value || ""]);
    }
  }
  const matching = forms.filter((form) =>
    form.fields.some(
      ([name]) => name === "SAMLRequest" || name === "SAMLResponse",
    ),
  );
  if (matching.length > 1)
    throw new AuthenticationError("unsupported", "Ambiguous SAML page");
  const form = matching[0];
  if (!form) return;
  if (form.method !== "POST")
    throw new AuthenticationError("unsupported", "Unsupported SAML method");
  let target: URL;
  try {
    target = new URL(form.action, page.url);
  } catch {
    throw new AuthenticationError("unsafe-destination", "Invalid SAML action");
  }
  return { url: target.href, method: "POST", fields: form.fields };
}

export function pageRedirect(page: Page): string | undefined {
  for (const match of page.body.matchAll(
    /<meta\b((?:"[^"]*"|'[^']*'|[^'">])*)>/gi,
  )) {
    const attrs = attributes(match[1] || "");
    if (attrs["http-equiv"]?.toLowerCase() === "refresh") {
      const value = attrs.content?.match(/url\s*=\s*(.+)/i)?.[1];
      if (value) return value.replace(/^["']|["']$/g, "");
    }
  }
  for (const match of page.body.matchAll(
    /<script\b[^>]*>([\s\S]*?)<\/script\s*>/gi,
  )) {
    const js = match[1] || "";
    const direct =
      js.match(
        /(?:window\.|top\.|self\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']/,
      )?.[1] ||
      js.match(
        /(?:window\.|top\.|self\.)?location\.(?:replace|assign)\(\s*["']([^"']+)["']/,
      )?.[1];
    if (direct) return entity(direct);
    const target = js.match(/var\s+url\s*=\s*["']([^"']+)["']/)?.[1];
    if (
      target &&
      js.includes("top.location.replace(url)") &&
      js.includes("url += params") &&
      js.includes("getQueryParameters()")
    ) {
      return target + new URL(page.url).search;
    }
  }
}
