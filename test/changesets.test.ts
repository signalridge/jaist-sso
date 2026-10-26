import { expect, test } from "bun:test";
import {
  compareVersions,
  isVersionTransition,
  qualifyingPullRequest,
  releaseNotes,
} from "../scripts/publish-changesets.ts";

const before = {
  name: "@signalridge/synthetic",
  version: "0.1.0",
  license: "MIT",
};
const after = { ...before, version: "0.1.1" };
const sha = "a".repeat(40);
const repository = "signalridge/synthetic";
const pr = {
  number: 1,
  merged_at: "2026-01-01T00:00:00Z",
  merge_commit_sha: sha,
  head: {
    ref: "changeset-release/main",
    sha: "b".repeat(40),
    repo: { full_name: repository },
  },
  base: { ref: "main", repo: { full_name: repository } },
};

test("only an increased version with a consumed changeset is a release transition", () => {
  expect(isVersionTransition(before, after, [".changeset/synthetic.md"])).toBe(
    true,
  );
  expect(isVersionTransition(before, before, [".changeset/synthetic.md"])).toBe(
    false,
  );
  expect(isVersionTransition(before, after, [".changeset/README.md"])).toBe(
    false,
  );
  expect(isVersionTransition(before, after, ["README.md"])).toBe(false);
  expect(isVersionTransition(after, before, [".changeset/synthetic.md"])).toBe(
    false,
  );
  expect(
    isVersionTransition(before, { ...after, name: "other" }, [
      ".changeset/synthetic.md",
    ]),
  ).toBe(false);
});

test("release authority requires the merged same-repository PR at the original SHA", () => {
  expect(qualifyingPullRequest(pr, repository, sha)).toBe(true);
  expect(
    qualifyingPullRequest({ ...pr, merged_at: null }, repository, sha),
  ).toBe(false);
  expect(qualifyingPullRequest(pr, repository, "c".repeat(40))).toBe(false);
  expect(
    qualifyingPullRequest(
      { ...pr, head: { ...pr.head, repo: { full_name: "fork/synthetic" } } },
      repository,
      sha,
    ),
  ).toBe(false);
  expect(
    qualifyingPullRequest(
      { ...pr, base: { ...pr.base, ref: "feature" } },
      repository,
      sha,
    ),
  ).toBe(false);
  expect(
    qualifyingPullRequest(
      { ...pr, head: { ...pr.head, ref: "manual-bump" } },
      repository,
      sha,
    ),
  ).toBe(false);
  expect(
    qualifyingPullRequest(
      { ...pr, head: { ...pr.head, sha: "invalid" } },
      repository,
      sha,
    ),
  ).toBe(false);
});

test("version ordering cannot regress latest through lexical comparison", () => {
  expect(compareVersions("0.10.0", "0.9.9")).toBe(1);
  expect(compareVersions("1.0.0", "0.99.99")).toBe(1);
  expect(compareVersions("1.2.3", "1.2.3")).toBe(0);
  expect(compareVersions("1.2.2", "1.2.3")).toBe(-1);
  expect(() => compareVersions("1.2.3-rc.1", "1.2.3")).toThrow();
});

test("GitHub release notes contain only the selected changelog entry", () => {
  const changelog =
    "# Package\n\n## 0.1.1\n\n### Patch Changes\n\n- Updated docs.\n\n## 0.1.0\n\n- Initial release.\n";
  expect(releaseNotes(changelog, "0.1.1")).toBe(
    "### Patch Changes\n\n- Updated docs.",
  );
  expect(() => releaseNotes(changelog, "0.2.0")).toThrow();
});
