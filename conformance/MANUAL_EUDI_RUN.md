# Manual EUDI Wallet engineering conformance

[EUDI Wallet Conformance](../.github/workflows/eudi-wallet-conformance.yml)
is a manual engineering-conformance lane that runs entirely on standard
GitHub-hosted Linux runners. It requires no separate machine, deployment
secret, preinstalled release files, or crates.io publishing token. Release
preparation and framework execution both use Ubuntu 26.04.

The workflow pins Identity Conformance 0.3.2's reusable workflow and checkout
to the same published release commit,
[`97974ea1ca9b7144bc19fa9337a089118db72924`](https://github.com/reallyme/identity-conformance/tree/97974ea1ca9b7144bc19fa9337a089118db72924).
Wallet owns its product candidate and release provenance;
Identity Conformance owns the engineering plan, upstream standards inputs,
execution, and result validation.

## Run

In GitHub Actions, select **EUDI Wallet Conformance**, choose **Run workflow**,
and select `main`. Choose `candidate` (the default) to test the dispatch commit,
or `published` to test the latest published Wallet release. The workflow runs
only on manual dispatch in `reallyme/wallet`
from `main`. It is not triggered by pushes, pull requests, schedules, workflow
completion, or publication, and it is not an ordinary source-CI prerequisite.

Candidate mode uses the dispatch commit and its approved package-policy version,
with a successful package preflight for that exact commit. Published mode resolves
the latest release's immutable tag, version and signed package preflight. That
release commit may differ from the workflow's commit. Candidate evidence does not
claim that the packages have been published.

## Verified release preparation

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

Wallet uploads exactly three files as a one-day Actions artifact:
`deployment.json`, `wallet-release`, and `wallet-attestation.json`.

## Framework execution and results

After preparation succeeds, the pinned reusable framework workflow downloads
that artifact from the same workflow run. It validates the three-file contract,
checks out the exact manifest-selected Wallet source, executes
`reallyme-wallet-conformance`, and validates the result before upload.

The result binds the framework version and revision, workflow revision, candidate
digest, artifact and attestation hashes, source locks, normative ledger digests,
checks, and plan assertions. The plan independently checks the exclusive
Wallet Unit Attestation lifetime bound and the Wallet Provider's three
unregistered-attribute policy choices.
The result artifact is retained for seven days. Inspect its component identity
to determine which release was tested; its filename also includes the workflow
commit and run ID. Treat the result as internal engineering evidence.

This lane does not execute the complete external EUDI device/testbed suites or
establish EU or OpenID Foundation certification. Those composed and external
assessments retain their own plans and accepted execution evidence.

## Local validation

`node --test scripts/*.test.mjs` checks the release-input preparation and the
manual-workflow contract. Negative cases cover automatic triggers, mutable or
mismatched pins, write permissions, extra jobs, secret injection, skipped
preparation, tampered archives, invalid signatures, wrong candidates, yanked
versions, and substituted registry checksums or CI results.

`node scripts/check_ci_lane_ownership.mjs` keeps automatic source CI independent
of Identity Conformance. Actionlint checks the caller and pinned reusable
workflow together. A local execution must use the exact selected candidate or
published source and its cryptographically verified package evidence; synthetic fixtures are test inputs,
not qualification evidence.
