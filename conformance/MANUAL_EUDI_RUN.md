# Manual EUDI Wallet engineering conformance

[Wallet EU engineering (Identity Conformance)](../.github/workflows/eudi-wallet-conformance.yml)
is a manual engineering-conformance lane that runs entirely on standard
GitHub-hosted Linux runners. It requires no separate machine, deployment
secret, preinstalled release files, or crates.io publishing token. Release
preparation and framework execution both use Ubuntu 26.04.

The workflow accepts an explicitly selected published Identity Conformance
release. Its menu defaults to `v0.3.3` and lists recent releases with the required
CLI contract (`v0.3.1` through `v0.3.3`); an optional
release-tag override selects another version without a Wallet commit. GitHub
Actions cannot populate a dispatch dropdown from live release data, so the menu
is a snapshot. The override is validated against the live published release.
Wallet owns its product candidate and release provenance;
Identity Conformance owns the engineering plan, upstream standards inputs,
execution, and result validation.

## Run

In GitHub Actions, select **Wallet EU engineering (Identity Conformance)**, choose **Run workflow**,
and select `main`. Select the framework release, or enter its exact `vX.Y.Z`
tag in **framework_release_override**. For `candidate` (the default), enter the
full Wallet SHA in **target_commit** and its exact retained signed package
preflight in **preflight_run_id**. These inputs are required for candidate runs;
the dispatcher never silently selects a source revision or evidence run.
For `published`, enter the exact `reallyme-wallet-vX.Y.Z` tag in **wallet_release**;
candidate commit and preflight inputs must then be blank. The workflow runs
only on manual dispatch in `reallyme/wallet`
from `main`. It is not triggered by pushes, pull requests, schedules, workflow
completion, or publication, and it is not an ordinary source-CI prerequisite.

Candidate mode reads the selected commit's approved package policy and proves
that the commit is on main's history. It requires a successful first-attempt
package preflight for that exact commit. Retests reuse its signed package archives;
they do not build, publish, or upload a new package set. Expired Actions artifacts
must be restored by a fresh legitimate preflight; no substitute evidence is accepted.
Published mode resolves
the selected release's exact tag, version and signed package preflight. That
release commit may differ from the workflow's commit. Candidate evidence does not
claim that the packages have been published.

## Framework authentication

Wallet resolves the selected release to its full commit using GitHub's release
and tag records. Before executing framework code, its own bootstrap verifies the
published manifest's SHA-256 from GitHub asset metadata, exact version and commit,
canonical input ordering, bounded regular files, every listed input digest, and
the aggregate input digest. Links and path traversal are rejected. The selected
framework then independently rebuilds and verifies its complete release manifest.
Missing, draft, prerelease, substituted, or incompatible releases fail closed.
The bootstrap requires every framework entry point before executing any of them.
Older releases may reject newer Wallet evidence; selection does not imply
compatibility with every historical target. Releases before `v0.3.1` lack the
required CLI contract and are not advertised as menu choices.

## Run names and badges

Runs identify the framework explicitly, for example
**Identity Conformance v0.3.3 · Wallet candidate**. A run title identifies the
selected release and target mode; GitHub's status icon supplies its outcome.
The successful summary and evidence artifact name use the authenticated framework
release tag and include the Wallet target version. Full framework, target, and
dispatcher commits remain in the statement and result.

The README shows two distinct indicators. The workflow-status badge reports the
latest run's outcome. **Last successful engineering run** reads GitHub's live
public workflow history, filtered to successful manual runs on `main`, and shows
that run's title. Its link opens the matching successful-run history, where each
run retains its statement and result. A later failure remains visible in the
workflow-status badge while the historical indicator keeps the previous success.
The indicators describe engineering workflow execution, not a product conformity
or certification badge. Shields and GitHub image caching can delay refreshes.

## Verified package preparation

The preparation job:

1. Downloads the selected target's preflight manifest and complete 17-crate set
   from its Actions artifacts in candidate mode, or release assets in published mode.
2. Verifies exact package names, sizes, hashes, source commit, immutable release
   tag when published, successful first-attempt preflight run, and signed GitHub provenance for
   the manifest and every crate. Self-hosted build provenance is refused.
3. In published mode, checks that each crates.io version is available, is not yanked, and has the
   same immutable checksum as its reviewed release archive.
4. Reads the exact successful preflight job steps and derives the component
   attestation's format, lint, unit, integration, vector, security, and build
   evidence from those observed results. Missing, duplicated, skipped, failed,
   or substituted steps fail preparation; passing claims are never assumed.
5. Bundles the verified release archives, original preflight manifest, and
   bounded check-evidence records. It binds that bundle, the release Cargo.lock,
   framework source locks, and attestation bytes into a deployment manifest.

The deployment and component attestation carry the same exact `target` identity.
Only published targets include `release_id` and `release_ref`
(`reallyme-wallet-v<version>`); candidate targets contain no publication identity.

The derived component attestation summarizes the existing package-preflight
checks; it does not claim that the EUDI plan has already run. The compiler version
is resolved from the exact release commit's `rust-toolchain.toml` and preflight
workflow; both pins must agree. Historical releases retain their observed compiler
when a newer workflow prepares their evidence. Its check-evidence
hashes refer to records inside the bundle. Raw process output, credentials, and
private deployment information are not collected.

Wallet materializes exactly three files in the same job:
`deployment.json`, `wallet-release`, and `wallet-attestation.json`. There is no
intermediate upload or cross-run substitution of these derived inputs.

## Framework execution and results

After preparation succeeds, the dispatcher checks out the exact manifest-selected
Wallet source and invokes the selected framework's code tests, independent probes,
result validator, package-preflight verifier, and statement builder. It revalidates
every package signature and, in published mode, the release assets and registry
checksums before uploading a passing statement. Framework domain checks remain in
Identity Conformance; Wallet owns target selection and GitHub orchestration.

The result binds the framework version and revision, workflow revision, candidate
digest, artifact and attestation hashes, source locks, normative ledger digests,
checks, and plan assertions. The plan independently checks the exclusive
Wallet Unit Attestation lifetime bound and the Wallet Provider's three
unregistered-attribute policy choices.
The result artifact is retained for seven days. Inspect its component identity
to determine which release was tested; its filename includes the target commit
and run ID. The dispatcher commit is recorded as `workflow_revision`, separately
from the target Wallet commit and framework revision. Treat the result as
internal engineering evidence.

This lane does not execute the complete external EUDI device/testbed suites or
establish EU or OpenID Foundation certification. Those composed and external
assessments retain their own plans and accepted execution evidence.

## Local validation

`node --test scripts/*.test.mjs` checks the release-input preparation and the
manual-workflow contract. Negative cases cover automatic triggers, mutable or
mismatched releases, write permissions, extra jobs, secret injection, skipped
preparation, tampered archives, invalid signatures, wrong candidates, yanked
versions, and substituted registry checksums or CI results.

`node scripts/check_ci_lane_ownership.mjs` keeps automatic source CI independent
of Identity Conformance. Actionlint checks the dispatcher. A local execution must
use the exact selected candidate or
published source and its cryptographically verified package evidence; synthetic fixtures are test inputs,
not qualification evidence.
