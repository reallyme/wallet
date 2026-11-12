# Manual EUDI Wallet engineering conformance

[EUDI Wallet Conformance](../.github/workflows/eudi-wallet-conformance.yml)
is a manual release-qualification lane that runs entirely on standard
GitHub-hosted Linux runners. It requires no separate machine, deployment
secret, preinstalled release files, or crates.io publishing token. Release
preparation and framework execution both use Ubuntu 26.04.

The workflow pins Identity Conformance's reusable workflow and checkout to
the same reviewed commit,
[`098e748e3bbb774280fcafc944e3a745094f53c7`](https://github.com/reallyme/identity-conformance/tree/098e748e3bbb774280fcafc944e3a745094f53c7).
Wallet owns its product candidate and release provenance;
Identity Conformance owns the engineering plan, upstream standards inputs,
execution, and result validation.

## Run

In GitHub Actions, select **EUDI Wallet Conformance**, choose **Run workflow**,
and select `main`. The workflow runs only on manual dispatch in `reallyme/wallet`
from `main`. It is not triggered by pushes, pull requests, schedules, workflow
completion, or publication, and it is not an ordinary source-CI prerequisite.

The selected release version comes from Wallet's approved package policy. The
candidate source commit comes from the signed release preflight and must match
the published release tag. It may differ from the workflow's own commit: adding
CI support does not change the source identity of an existing published release.

## Verified release preparation

The preparation job:

1. Downloads the published release's preflight manifest and complete 17-crate set.
2. Verifies exact package names, sizes, hashes, source commit, immutable release
   tag, successful first-attempt preflight run, and signed GitHub provenance for
   the manifest and every crate. Self-hosted build provenance is refused.
3. Checks that each crates.io version is available, is not yanked, and has the
   same immutable checksum as its reviewed release archive.
4. Reads the exact successful preflight job steps and derives the component
   attestation's format, lint, unit, integration, vector, security, and build
   evidence from those observed results. Missing, duplicated, skipped, failed,
   or substituted steps fail preparation; passing claims are never assumed.
5. Bundles the verified release archives, original preflight manifest, and
   bounded check-evidence records. It binds that bundle, the release Cargo.lock,
   framework source locks, and attestation bytes into a deployment manifest.

The derived component attestation summarizes the existing release-preflight
checks; it does not claim that the EUDI plan has already run. Its check-evidence
hashes refer to records inside the bundle. Raw process output, credentials, and
private deployment information are not collected.

Wallet uploads exactly three files as a one-day Actions artifact:
`deployment.json`, `wallet-release`, and `wallet-attestation.json`.

## Framework execution and results

After preparation succeeds, the pinned reusable framework workflow downloads
that artifact from the same workflow run. It validates the three-file contract,
checks out the exact manifest-selected Wallet source, executes
`reallyme-wallet-conformance`, and validates the result before upload.

The result binds the framework revision, workflow revision, candidate digest,
artifact and attestation hashes, source locks, checks, and plan assertions.
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
workflow together. A local release execution must use the same public release
and cryptographically verified evidence; synthetic fixtures are test inputs,
not qualification evidence.
