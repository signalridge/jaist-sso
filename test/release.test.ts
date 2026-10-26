import { expect, test } from "bun:test";
import { reconcileIntegrity, validateRelease } from "../scripts/release.ts";

const manifest = {
  name: "@signalridge/jaist-sso",
  version: "0.1.0",
  license: "MIT",
  publishConfig: { access: "public" },
};
test("release tag must match public package metadata", () => {
  expect(() => validateRelease(manifest, "v0.1.0")).not.toThrow();
  expect(() => validateRelease(manifest, "main")).toThrow();
  expect(() =>
    validateRelease({ ...manifest, private: true }, "v0.1.0"),
  ).toThrow();
  expect(() =>
    validateRelease({ ...manifest, license: "UNLICENSED" }, "v0.1.0"),
  ).toThrow();
});
test("publication is idempotent only when the published contents match", () => {
  expect(reconcileIntegrity(404, undefined, "sha512-synthetic")).toBe(true);
  expect(
    reconcileIntegrity(
      200,
      { dist: { integrity: "sha512-synthetic" } },
      "sha512-synthetic",
    ),
  ).toBe(false);
  expect(() =>
    reconcileIntegrity(
      200,
      { dist: { integrity: "sha512-other" } },
      "sha512-synthetic",
    ),
  ).toThrow();
  for (const status of [401, 403, 429, 500])
    expect(() =>
      reconcileIntegrity(status, undefined, "sha512-synthetic"),
    ).toThrow();
});
