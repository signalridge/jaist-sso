import { expect, test } from "bun:test";
import { PassThrough } from "node:stream";
import { createTerminalHandler } from "../src/terminal.ts";

test("terminal passwords and OTP are hidden and raw mode is restored", async () => {
  const input = Object.assign(new PassThrough(), {
    isTTY: true,
    isRaw: false,
    setRawMode(mode: boolean) {
      this.isRaw = mode;
      return this;
    },
  });
  const output = Object.assign(new PassThrough(), { isTTY: true, columns: 80 });
  let written = "";
  output.on("data", (data) => {
    written += data.toString();
  });
  const handler = createTerminalHandler({
    input: input as unknown as NodeJS.ReadStream,
    output: output as unknown as NodeJS.WriteStream,
  });
  const signal = new AbortController().signal;
  const password = handler({ kind: "password", signal });
  queueMicrotask(() => input.write("synthetic-private-password\n"));
  expect(await password).toBe("synthetic-private-password");
  expect(written).not.toContain("synthetic-private-password");
  expect(input.isRaw).toBe(false);
  const otp = handler({ kind: "otp", method: "email-otp", attempt: 1, signal });
  queueMicrotask(() => input.write("12345678\n"));
  expect(await otp).toBe("12345678");
  expect(written).not.toContain("12345678");
  expect(input.isRaw).toBe(false);
  input.destroy();
  output.destroy();
});

test("Ctrl-C cancels hidden input and restores raw mode", async () => {
  const input = Object.assign(new PassThrough(), {
    isTTY: true,
    isRaw: false,
    setRawMode(mode: boolean) {
      this.isRaw = mode;
      return this;
    },
  });
  const output = Object.assign(new PassThrough(), { isTTY: true, columns: 80 });
  output.resume();
  const handler = createTerminalHandler({
    input: input as unknown as NodeJS.ReadStream,
    output: output as unknown as NodeJS.WriteStream,
  });
  const result = handler({
    kind: "password",
    signal: new AbortController().signal,
  });
  queueMicrotask(() => input.write("\u0003"));
  await expect(result).rejects.toMatchObject({ code: "cancelled" });
  expect(input.isRaw).toBe(false);
  input.destroy();
  output.destroy();
});
