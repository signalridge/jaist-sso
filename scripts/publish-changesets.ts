import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type Manifest,
  packRelease,
  reconcileIntegrity,
  validateRelease,
  waitForIntegrity,
} from "./release.ts";

const shipped = ["package.json", "README.md", "LICENSE", "CHANGELOG.md", "src"];
type PullRequest = {
  number?: number;
  merged_at?: string | null;
  merge_commit_sha?: string;
  head?: { ref?: string; sha?: string; repo?: { full_name?: string } };
  base?: { ref?: string; repo?: { full_name?: string } };
};

export function compareVersions(left: string, right: string): number {
  if (![left, right].every((value) => /^\d+\.\d+\.\d+$/.test(value)))
    throw new Error("Only stable three-part versions are supported");
  const a = left.split(".").map(Number);
  const b = right.split(".").map(Number);
  for (const index of [0, 1, 2]) {
    const difference = (a[index] ?? 0) - (b[index] ?? 0);
    if (difference !== 0) return Math.sign(difference);
  }
  return 0;
}

export function isVersionTransition(
  before: Manifest,
  after: Manifest,
  deleted: string[],
): boolean {
  return (
    before.name === after.name &&
    before.version !== after.version &&
    compareVersions(after.version, before.version) > 0 &&
    deleted.some(
      (path) =>
        /^\.changeset\/[\w-]+\.md$/.test(path) &&
        path !== ".changeset/README.md",
    )
  );
}

export function qualifyingPullRequest(
  pr: PullRequest,
  repository: string,
  sha: string,
): boolean {
  return (
    Number.isSafeInteger(pr.number) &&
    (pr.number ?? 0) > 0 &&
    typeof pr.merged_at === "string" &&
    pr.merged_at.length > 0 &&
    pr.merge_commit_sha === sha &&
    pr.head?.ref === "changeset-release/main" &&
    /^[a-f0-9]{40}$/.test(pr.head.sha ?? "") &&
    pr.head.repo?.full_name === repository &&
    pr.base?.ref === "main" &&
    pr.base.repo?.full_name === repository
  );
}

export function releaseNotes(changelog: string, version: string): string {
  const sections = changelog.split(/^## /m);
  const entry = sections.find(
    (section) => section.split("\n", 1)[0]?.trim() === version,
  );
  if (!entry) throw new Error("Missing changelog entry for release");
  return entry.slice(entry.indexOf("\n") + 1).trim();
}

function git(...args: string[]): string {
  return execFileSync("git", args, { encoding: "utf8" }).trim();
}

async function json(url: string, headers?: HeadersInit) {
  const response = await fetch(url, {
    headers,
    signal: AbortSignal.timeout(20_000),
  });
  if (response.status !== 200 && response.status !== 404)
    throw new Error(`Lookup failed with HTTP ${response.status}`);
  return {
    status: response.status,
    data: response.status === 200 ? await response.json() : undefined,
  };
}

function github(path: string) {
  const token = process.env.GITHUB_TOKEN;
  if (!token) throw new Error("GitHub workflow token is required");
  return json(`https://api.github.com/${path}`, {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  });
}

async function selectRelease(
  repository: string,
  sha: string,
): Promise<PullRequest | undefined> {
  const before: Manifest = JSON.parse(git("show", `${sha}^:package.json`));
  const after: Manifest = JSON.parse(git("show", `${sha}:package.json`));
  const deleted = git(
    "diff",
    "--name-only",
    "--diff-filter=D",
    `${sha}^`,
    sha,
    "--",
    ".changeset",
  ).split("\n");
  if (!isVersionTransition(before, after, deleted)) return;
  const result = await github(
    `repos/${repository}/commits/${sha}/pulls?per_page=100`,
  );
  if (!Array.isArray(result.data))
    throw new Error("Cannot inspect associated pull requests");
  const candidate = (result.data as PullRequest[]).find((pr) =>
    qualifyingPullRequest(pr, repository, sha),
  );
  if (!candidate)
    throw new Error(
      "Version change must come from a merged Changesets pull request",
    );
  return candidate;
}

async function publish(
  repository: string,
  sha: string,
  pr: PullRequest,
): Promise<void> {
  git("fetch", "--no-tags", "origin", `refs/pull/${pr.number}/head`);
  const head = git("rev-parse", "FETCH_HEAD");
  if (head !== pr.head?.sha)
    throw new Error("Release PR head changed unexpectedly");
  if (git("diff", "--name-only", head, sha, "--", ...shipped))
    throw new Error("Merged package differs from the reviewed release PR");
  const directory = mkdtempSync(join(tmpdir(), "changesets-release-"));
  try {
    const snapshot = execFileSync("git", ["archive", head, "--", ...shipped]);
    execFileSync("tar", ["-x", "-C", directory], { input: snapshot });
    const manifest: Manifest = JSON.parse(
      readFileSync(join(directory, "package.json"), "utf8"),
    );
    const tag = `v${manifest.version}`;
    validateRelease(manifest, tag);
    const notes = releaseNotes(
      readFileSync(join(directory, "CHANGELOG.md"), "utf8"),
      manifest.version,
    );
    const archive = packRelease(directory);
    const endpoint = `https://registry.npmjs.org/${encodeURIComponent(manifest.name)}`;
    const lookup = () => json(`${endpoint}/${manifest.version}`);
    const registry = await json(endpoint);
    if (registry.status !== 200)
      throw new Error(
        "New package names require an initial authenticated bootstrap",
      );
    const latest: unknown = registry.data?.["dist-tags"]?.latest;
    if (typeof latest !== "string")
      throw new Error("Registry has no stable latest version");
    const remote = await lookup();
    const needed = reconcileIntegrity(
      remote.status,
      remote.data,
      archive.integrity,
    );
    if (needed && compareVersions(manifest.version, latest) < 0)
      throw new Error("Refusing to move the npm latest tag backwards");
    const existingTag = await github(`repos/${repository}/git/ref/tags/${tag}`);
    if (existingTag.status === 200) {
      let object = existingTag.data.object;
      if (object?.type === "tag") {
        const annotated = await github(
          `repos/${repository}/git/tags/${object.sha}`,
        );
        object = annotated.data?.object;
      }
      if (object?.type !== "commit" || object.sha !== sha)
        throw new Error("Existing release tag points to another commit");
    }
    if (needed) {
      // A failed response can still mean npm accepted the publication. Verify
      // the exact version before deciding whether a retry is needed.
      let failed = false;
      try {
        execFileSync(
          "npm",
          [
            "publish",
            archive.filename,
            "--access",
            "public",
            "--provenance",
            "--ignore-scripts",
          ],
          {
            cwd: directory,
            stdio: "inherit",
          },
        );
      } catch {
        failed = true;
      }
      try {
        await waitForIntegrity(lookup, archive.integrity);
      } catch (error) {
        if (failed)
          throw new Error(
            "Publication failed or is still processing; rerun this workflow to reconcile safely",
            { cause: error },
          );
        throw error;
      }
    }
    const release = await github(`repos/${repository}/releases/tags/${tag}`);
    const env = { ...process.env, GH_TOKEN: process.env.GITHUB_TOKEN };
    if (release.status === 404) {
      execFileSync(
        "gh",
        [
          "release",
          "create",
          tag,
          archive.filename,
          "--repo",
          repository,
          "--target",
          sha,
          "--title",
          tag,
          "--notes-file",
          "-",
          `--latest=${compareVersions(manifest.version, latest) >= 0}`,
        ],
        {
          input: notes,
          env,
          stdio: ["pipe", "inherit", "inherit"],
        },
      );
    } else {
      if (release.data.draft || release.data.prerelease)
        throw new Error("Unexpected draft or prerelease");
      execFileSync(
        "gh",
        [
          "release",
          "upload",
          tag,
          archive.filename,
          "--repo",
          repository,
          "--clobber",
        ],
        { env, stdio: "inherit" },
      );
    }
    console.log(`New tag: ${manifest.name}@${manifest.version}`);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

async function main(): Promise<void> {
  const repository = process.env.GITHUB_REPOSITORY ?? "";
  const sha = process.env.GITHUB_SHA ?? "";
  if (
    !/^signalridge\/[a-z0-9-]+$/.test(repository) ||
    !/^[a-f0-9]{40}$/.test(sha) ||
    git("rev-parse", "HEAD") !== sha
  )
    throw new Error("Run from the original GitHub Actions revision");
  const candidate = await selectRelease(repository, sha);
  if (process.argv.includes("--classify")) {
    console.log(Boolean(candidate));
    return;
  }
  if (!candidate) {
    console.log("No merged Changesets release transition; nothing to publish");
    return;
  }
  await publish(repository, sha, candidate);
}

if (import.meta.main) {
  main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : "Release failed");
    process.exitCode = 1;
  });
}
