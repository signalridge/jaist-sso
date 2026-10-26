import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, readFileSync } from "node:fs";
import { basename } from "node:path";

type Manifest = {
  name: string;
  version: string;
  private?: boolean;
  license: string;
  publishConfig?: { access?: string };
};
export function validateRelease(manifest: Manifest, tag: string): void {
  if (
    manifest.private === true ||
    manifest.license !== "MIT" ||
    manifest.publishConfig?.access !== "public" ||
    !/^@signalridge\/[a-z0-9-]+$/.test(manifest.name) ||
    !/^\d+\.\d+\.\d+(?:-[\w.-]+)?$/.test(manifest.version) ||
    tag !== `v${manifest.version}`
  ) {
    throw new Error("Release tag and public package metadata must match");
  }
}

export function reconcileIntegrity(
  status: number,
  remote: unknown,
  integrity: string,
): boolean {
  if (status === 404) return true;
  if (status !== 200)
    throw new Error(
      "Registry lookup failed; refusing to assume the version is unpublished",
    );
  const data = remote as { dist?: { integrity?: string } } | null;
  if (data?.dist?.integrity !== integrity)
    throw new Error(
      "Published version has different contents; bump the version instead",
    );
  return false;
}

async function main(tag: string, verify = false): Promise<void> {
  const manifest: Manifest = JSON.parse(readFileSync("package.json", "utf8"));
  validateRelease(manifest, tag);
  if (
    execFileSync("git", ["status", "--porcelain"], { encoding: "utf8" }).trim()
  )
    throw new Error("Release checkout must be clean");
  const packed: { filename: string; files: { path: string }[] }[] = JSON.parse(
    execFileSync("npm", ["pack", "--json", "--ignore-scripts"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "inherit"],
    }),
  );
  const archive = packed[0];
  if (
    packed.length !== 1 ||
    !archive ||
    archive.filename !== basename(archive.filename) ||
    archive.files.some(
      (file) =>
        !/^(?:package\.json|README\.md|LICENSE|CHANGELOG\.md|src\/[\w-]+\.ts)$/.test(
          file.path,
        ),
    )
  )
    throw new Error("Unexpected files in release archive");
  const integrity = `sha512-${createHash("sha512").update(readFileSync(archive.filename)).digest("base64")}`;
  const response = await fetch(
    `https://registry.npmjs.org/${encodeURIComponent(manifest.name)}/${manifest.version}`,
    { signal: AbortSignal.timeout(15_000) },
  );
  const remote = response.status === 200 ? await response.json() : undefined;
  const publish = reconcileIntegrity(response.status, remote, integrity);
  if (verify && publish)
    throw new Error("Published version is not visible in the registry yet");
  if (process.env.GITHUB_OUTPUT)
    appendFileSync(
      process.env.GITHUB_OUTPUT,
      `publish=${publish}\nfilename=${archive.filename}\n`,
    );
  console.log(
    `${manifest.name}@${manifest.version}: ${publish ? "ready to publish" : "published contents match"}`,
  );
}

if (import.meta.main) {
  main(process.argv[2] || "", process.argv.includes("--verify")).catch(() => {
    console.error(
      "Release validation failed; check tag, clean checkout, archive and registry integrity",
    );
    process.exitCode = 1;
  });
}
