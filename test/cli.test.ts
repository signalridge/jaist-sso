import { expect, test } from "bun:test";
import { spawn } from "node:child_process";
import type { Writable } from "node:stream";
import { parseCLI } from "../src/cli-support.ts";

test("CLI help runs without credentials or a network connection", () => {
  const run = Bun.spawnSync([process.execPath, "src/cli.ts", "--help"], {
    cwd: `${import.meta.dir}/..`,
    env: process.env,
  });
  expect(run.exitCode).toBe(0);
  expect(run.stdout.toString()).toContain("--credentials-fd");
});
test("malformed credential JSON does not echo its contents", () => {
  const run = Bun.spawnSync(
    [
      process.execPath,
      "src/cli.ts",
      "--url",
      "https://vpn.jaist.ac.jp",
      "--credentials-stdin",
    ],
    {
      cwd: `${import.meta.dir}/..`,
      stdin: Buffer.from("synthetic-private-input"),
    },
  );
  expect(run.exitCode).toBe(1);
  expect(run.stdout.byteLength).toBe(0);
  expect(run.stderr.toString()).not.toContain("synthetic-private-input");
  expect(run.stderr.toString()).toContain("Credential input is not JSON");
});
test("credential descriptor selection is unambiguous", () => {
  expect(parseCLI(["--credentials-fd", "3"]).fd).toBe(3);
  expect(parseCLI(["--credentials-stdin"]).fd).toBe(0);
  for (const value of ["1", "2", "-1", "NaN", "3.5"])
    expect(() => parseCLI(["--credentials-fd", value])).toThrow();
  expect(() =>
    parseCLI(["--credentials-fd", "3", "--credentials-stdin"]),
  ).toThrow();
});

test("an inherited credential pipe is read without environment or argv credentials", async () => {
  const child = spawn(
    process.execPath,
    [
      "-e",
      `
    import { readCredentialInput } from './src/cli-support.ts';
    const credentials = await readCredentialInput(3, AbortSignal.timeout(2000));
    const valid = (await credentials.username()) === 'synthetic-user';
    console.log(JSON.stringify({ valid }));
  `,
    ],
    { cwd: `${import.meta.dir}/..`, stdio: ["ignore", "pipe", "pipe", "pipe"] },
  );
  let stdout = "";
  let stderr = "";
  child.stdout?.on("data", (value) => {
    stdout += value.toString();
  });
  child.stderr?.on("data", (value) => {
    stderr += value.toString();
  });
  const closed = new Promise<number | null>((resolve, reject) => {
    child.once("close", resolve);
    child.once("error", reject);
  });
  (child.stdio[3] as Writable).end(
    JSON.stringify({
      username: "synthetic-user",
      password: "synthetic-private-password",
    }),
  );
  expect(await closed).toBe(0);
  expect(JSON.parse(stdout)).toEqual({ valid: true });
  expect(stderr).toBe("");
  expect(stdout).not.toContain("synthetic-private-password");
});
