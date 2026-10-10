# Release Versioning

Every push to `main` cuts a release. The release workflow (`.github/workflows/release.yml`, `version` job) derives the next version from the commit messages since the latest release tag. This document defines the rule.

## The Rule

The workflow scans every commit in `<latest tag>..HEAD`. It finds the bump for each commit, and the highest bump wins.

| Row | The commits in the range include | Below 1.0.0 | 1.0.0 and above |
|---|---|---|---|
| `release-as` | a `Release-As: vX.Y.Z` line (the newest one decides) | exactly that version | exactly that version |
| `breaking` | a subject `type!:` / `type(scope)!:`, or a line starting `BREAKING CHANGE:` / `BREAKING-CHANGE:` | minor | major |
| `feature` | a subject `feat:` / `feat(scope):` | minor | minor |
| `other` | anything else (`fix`, `docs`, `chore`, `test`, `spec`, `ci`, non-conventional) | patch | patch |
| `no-tag` | there is no tag matching `vX.Y.Z` | start from `v0.0.0`, then apply the rows above | — |

- A minor bump resets the patch number. A major bump resets the minor and patch numbers.
- The latest tag is the highest version among tags that match `vX.Y.Z` exactly and are reachable from the commit being released (`git tag --merged HEAD`). Other tags are ignored. Versions are compared as numbers, so `v0.10.0` is greater than `v0.9.0`.
- If the range is empty (HEAD is already tagged), the release is still a patch.

## What Counts

| Signal | Where it must be | Example |
|---|---|---|
| Commit type (`feat`, `fix!`, …) | subject line (first line) only | `feat(ts): add flag` |
| `BREAKING CHANGE:` / `BREAKING-CHANGE:` | start of any line in the message | footer in the squash body |
| `Release-As:` | start of any line in the message | footer in the squash body |

Types are matched case-insensitively (`Feat!:` counts as breaking), as Conventional Commits allows. The `BREAKING CHANGE:` / `BREAKING-CHANGE:` footer token is case-sensitive, as Conventional Commits requires.

Only the subject decides the commit type because GitHub's default squash body lists the branch commits as `* …` bullets. A `* feat: x` bullet under a `fix:` subject is therefore history, not a feature, and it does not count. A breaking-change footer is a deliberate statement, so it counts wherever it starts a line.

## Why the Whole Range

One release can cover several merges. v0.2.25 covers #56 and #58, because the release run for `a654ff8` (#56) never reached the version job. If the workflow looked only at the last commit, a `feat` or breaking change in an earlier merge would be lost.

## `Release-As`

A `Release-As` footer sets the version exactly and overrides the computed bump.

| Item | Rule |
|---|---|
| Syntax | `Release-As: vX.Y.Z`. The key is case-insensitive, the `v` is optional (`0.3.0` and `v0.3.0` are the same value), and whitespace around the value is ignored. |
| Several in the range | only the newest one decides; older ones are ignored. Within one message, the last `Release-As` line decides. |
| Valid value | three numeric parts, strictly greater than the latest tag |
| Newest value malformed (for example, `Release-As: 0.3`) | the `version` job's bump step fails |
| Newest value not greater than the latest tag | the `version` job's bump step fails |
| Scope | applies only to the release whose range contains it; the next release computes normally |

The bump step runs before the tag is created, so when it fails no tag or release exists. To recover, merge a commit whose message carries a corrected `Release-As` footer: it becomes the newest one and decides. (Once the bump step has passed, a later failure, for example in `gh release create` or an artifact job, leaves the tag and draft behind; that is unchanged by this rule.)

## Release Notes

If the range contains breaking commits, the workflow generates a **⚠️ Breaking changes** section. A commit is breaking for the notes by exactly the `breaking` row's rule (a `!` subject or a `BREAKING CHANGE:` / `BREAKING-CHANGE:` line), so a `* feat!: …` bullet in a squash body does not add an entry. A footer's text runs from `BREAKING CHANGE:` to the next blank line, the next footer-token line (any `Word: …` line, for example `Release-As:` or `Note:`), or the end of the message; continuation lines are kept and indented under the entry. Put migration notes directly under the footer, before any other token line. The section lists the subject of each breaking commit and its `BREAKING CHANGE:` text. It is passed to `gh release create --notes-file … --generate-notes`, which prepends it to GitHub's generated notes. If there are no breaking commits, the notes are GitHub's generated notes only. You no longer have to add the breaking-change section by hand; impact or migration detail beyond the footer text still needs a human.

## Guidance for Whoever Squash-Merges

| Part | What goes there |
|---|---|
| Squash title | the Conventional Commit subject, which sets the type: `fix(release): … (#54)`, `feat!: … (#47)` |
| Squash body | footers: `BREAKING CHANGE: <what breaks and how to migrate>`, `Release-As: vX.Y.Z` |

Check the pre-filled title and body before you merge: a wrong type gives a wrong version.

In this repo the default squash body is built from the branch's commit messages (`squash_merge_commit_message: COMMIT_MESSAGES`); for a single-commit PR it is that commit's message. Footers written in the PR description or in a separate file are **not** included.

**Put footers in a branch commit's own message** (`git commit` with a body ending in `Release-As: vX.Y.Z` or `BREAKING CHANGE: …`, at column 0). The default squash then carries them, whoever merges and however. Editing the merge dialog, or `gh pr merge <N> --squash --subject … --body-file <file>`, also works but depends on the person merging remembering; footers were lost that way three times (#60, #62, #64; see below).

## Worked Examples

| Change | Shipped as | With this rule |
|---|---|---|
| #47 `feat!: dockerd-parity listening socket` | v0.2.22 (patch) | v0.3.0 (`breaking`, below 1.0) |
| #53 `fix!: deny percent-encoded request paths` | v0.2.26 (patch, notes written by hand) | v0.3.0 (`breaking`), with a generated breaking-changes section |
| #56 + #58 (both `fix`) | v0.2.25 | v0.2.25 (`other`) |
| #54 (#60), merged with the default squash body (no footer) | v0.2.27 (patch, computed by this rule) | v0.2.27 (`other`), correct for #54 alone |
| #61 (#62), also merged with the default squash body | not released: its release run was cancelled before tagging | would have been v0.2.28 (`other`) |
| #63 (#64), footer only in a separate merge-message file; merged with the default body | not released: run cancelled before tagging | would have been v0.2.28 (`other`) |
| #63 follow-up, footer `Release-As: v0.3.0` in the branch commit itself (range `v0.2.27..HEAD`, includes #62 and #64) | v0.3.0 | v0.3.0 (`release-as`). It corrects the version line for the breaking changes in #47 and #53. |

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
| `scripts/release-latest-tag.sh` | Prints the newest strict `vX.Y.Z` tag merged into a ref (default `HEAD`), or nothing if there is none. Fails if git fails. |
| `scripts/release-version_test.sh` | One test case per row of the rule table, plus edge cases. |
| `scripts/release-latest-tag_test.sh` | Builds throwaway repos: no tags, non-strict tags, version sort, pre-releases, unmerged tags, an explicit ref, a git failure, and a ref that does not resolve. |
| `make test-release` | Runs the tests. The tests also run in CI (`release-scripts` job). |
