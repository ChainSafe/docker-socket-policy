# Release Versioning

Every push to `main` cuts a release. The release workflow (`.github/workflows/release.yml`, `version` job) derives the next version from the commit messages since the latest release tag. This document defines the rule.

## The Rule

The workflow scans every commit in `<latest tag>..HEAD`. It finds the bump for each commit, and the highest bump wins.

| Row | The commits in the range include | Below 1.0.0 | 1.0.0 and above |
|---|---|---|---|
| `release-as` | a `Release-As: vX.Y.Z` line | exactly that version | exactly that version |
| `breaking` | a subject `type!:` / `type(scope)!:`, or a line starting `BREAKING CHANGE:` / `BREAKING-CHANGE:` | minor | major |
| `feature` | a subject `feat:` / `feat(scope):` | minor | minor |
| `other` | anything else (`fix`, `docs`, `chore`, `test`, `spec`, `ci`, non-conventional) | patch | patch |
| `no-tag` | there is no release tag | start from `v0.0.0`, then apply the rows above | — |

- A minor bump resets the patch number. A major bump resets the minor and patch numbers.
- The latest tag is the highest version among tags that match `vX.Y.Z` exactly. Other tags are ignored. Versions are compared as numbers, so `v0.10.0` is greater than `v0.9.0`.
- If the range is empty (HEAD is already tagged), the release is still a patch.

## What Counts

| Signal | Where it must be | Example |
|---|---|---|
| Commit type (`feat`, `fix!`, …) | subject line (first line) only | `feat(ts): add flag` |
| `BREAKING CHANGE:` / `BREAKING-CHANGE:` | start of any line in the message | footer in the squash body |
| `Release-As:` | start of any line in the message | footer in the squash body |

Only the subject decides the commit type because GitHub's default squash body lists the branch commits as `* …` bullets. A `* feat: x` bullet under a `fix:` subject is therefore history, not a feature, and it does not count. A breaking-change footer is a deliberate statement, so it counts wherever it starts a line.

## Why the Whole Range

One release can cover several merges. v0.2.25 covers #56 and #58, because the release run for `a654ff8` (#56) never reached the version job. If the workflow looked only at the last commit, a `feat` or breaking change in an earlier merge would be lost.

## `Release-As`

A `Release-As` footer sets the version exactly and overrides the computed bump.

| Item | Rule |
|---|---|
| Syntax | `Release-As: vX.Y.Z`. The key is case-insensitive, the `v` is optional, and whitespace around the value is ignored. |
| Valid value | three numeric parts, strictly greater than the latest tag |
| Malformed value (for example, `Release-As: 0.3`) | the release job fails |
| Value not greater than the latest tag | the release job fails |
| Two different values in the range | the release job fails |
| The same value more than once | accepted |
| Scope | applies only to the release whose range contains it; the next release computes normally |

If the job fails, no tag is created. To recover, push a new commit (for example, a revert or a commit with a corrected `Release-As` footer).

## Release Notes

If the range contains breaking commits, the workflow generates a **⚠️ Breaking changes** section. The section lists the subject of each breaking commit and its `BREAKING CHANGE:` text. It is passed to `gh release create --notes-file … --generate-notes`, which prepends it to GitHub's generated notes. If there are no breaking commits, the notes are GitHub's generated notes only. You do not have to edit the notes by hand.

## Guidance for Whoever Squash-Merges

| Part | What goes there |
|---|---|
| Squash title | the Conventional Commit subject, which sets the type: `fix(release): … (#54)`, `feat!: … (#47)` |
| Squash body | footers: `BREAKING CHANGE: <what breaks and how to migrate>`, `Release-As: vX.Y.Z` |

Check the title before you merge. GitHub pre-fills it from the PR title, and a wrong type gives a wrong version.

## Worked Examples

| Change | Shipped as | With this rule |
|---|---|---|
| #47 `feat!: dockerd-parity listening socket` | v0.2.22 (patch) | v0.3.0 (`breaking`, below 1.0) |
| #53 `fix!: deny percent-encoded request paths` | v0.2.26 (patch, notes written by hand) | v0.3.0 (`breaking`), with a generated breaking-changes section |
| #56 + #58 (both `fix`) | v0.2.25 | v0.2.25 (`other`) |
| #54 (this change), squash body `Release-As: v0.3.0` | — | v0.3.0 (`release-as`). It corrects the version for the breaking changes in #47 and #53. |

Other examples: `fix!: x` on v1.4.2 gives v2.0.0. `feat: x` on v1.4.2 gives v1.5.0. `fix: x` with no tag gives v0.0.1.

## What Is Unchanged

- Every push to `main` still releases.
- Each release is still created as a draft prerelease and published automatically by the `publish-release` job once every artifact has uploaded.
- Pre-release tags, CHANGELOG files, and the release concurrency setting are out of scope.

## Rejected Alternatives

| Alternative | Why it was rejected |
|---|---|
| release-please / semantic-release | Heavier. They take over changelogs and release PRs, which this repo does not use. |
| Correct only AGENTS.md (say that every release is a patch) | Breaking changes would still ship as patches with hand-written notes, as #47 and #53 did. |
| `feat` gives a patch below 1.0 | Then a feature and a fix would look the same. Below 1.0, minor is the only signal left for "new behaviour". |

## Implementation and Tests

| File | Purpose |
|---|---|
| `scripts/release-version.sh` | Reads NUL-separated commit messages on stdin. Takes the latest tag (or empty) as its argument. Prints `bump=…` and `tag=vX.Y.Z`. |
| `scripts/release-notes.sh` | Reads the same input and prints the breaking-changes section, or nothing. |
| `scripts/release-version_test.sh` | One test case per row of the rule table, plus edge cases. |
| `make test-release` | Runs the tests. The tests also run in CI (`release-scripts` job). |
