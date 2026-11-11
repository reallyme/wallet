# Manual EUDI Wallet engineering conformance

[EUDI Wallet Conformance](../.github/workflows/eudi-wallet-conformance.yml)
is a manually dispatched release-qualification lane. It calls the reusable
workflow in Identity Conformance at
[`46cb1a6b2a016189f29ead608f3e5ddd460c1d07`](https://github.com/reallyme/identity-conformance/tree/46cb1a6b2a016189f29ead608f3e5ddd460c1d07).
Both the reusable workflow reference and its framework checkout use that commit.

The selected framework revision includes caller-owned candidate manifests after
the initial framework 0.1.0 release. The framework owns the plan and upstream
standards inputs; Wallet's operator supplies the candidate. No framework-owned
product BOM or reference baseline selects the Wallet release implicitly.

## Runner and protected inputs

Prepare an ephemeral Linux x64 self-hosted runner with all four labels:
`self-hosted`, `linux`, `x64`, and `eudi-wallet-conformance`. Restrict its runner
group to trusted repositories and workflows. The Wallet caller accepts only
manual dispatches from this repository's `main` branch.

Before the job starts, materialize these regular files outside the Actions
workspace; directories and symlinks are not accepted:

| Path | Contents |
| --- | --- |
| `/protected-inputs/wallet-release` | The reviewed Wallet release bundle, matching the manifest's artifact SHA-256 |
| `/protected-inputs/wallet-attestation.json` | The component attestation for that exact bundle and Wallet commit |

Configure the repository Actions secret
`EUDI_WALLET_DEPLOYMENT_MANIFEST_B64` with the Base64-encoded deployment
manifest. Base64 is transport encoding; keep the manifest and its decoded
contents protected. Do not put secrets, credentials, or private execution
evidence in this repository.

The manifest must satisfy the pinned framework's
[deployment schema](https://github.com/reallyme/identity-conformance/blob/46cb1a6b2a016189f29ead608f3e5ddd460c1d07/schemas/eudi-wallet-deployment-manifest.schema.json):

- Identify component `wallet`, repository `https://github.com/reallyme/wallet`,
  and a full public source commit.
- Identify the release bundle and component attestation by their exact hashes.
- Bind the EUDI source, legal-source, and publication locks from the selected
  framework revision.
- Declare the framework's required evidence policy. The attestation must contain
  passing format, lint, unit, integration, vector, security, and build evidence.

The tested source commit comes from the protected manifest. It may differ from
the workflow's own commit when qualifying an earlier published release. Source,
artifact, and attestation must identify the same candidate. The runner refuses
a dirty source checkout or an unavailable candidate; it does not substitute
`main` or a reference baseline.

## Run and interpret the result

In GitHub Actions, select **EUDI Wallet Conformance**, choose **Run workflow**,
and select `main`. There are no free-form dispatch inputs or inherited secrets.
The workflow is not triggered by pushes, pull requests, schedules, or releases,
and it is not a prerequisite of ordinary source CI or crates.io publication.

The reusable workflow executes `reallyme-wallet-conformance` against the exact
source and validates the internal result before uploading it. The result binds
the framework revision, workflow revision, candidate digest, artifact and
attestation hashes, source locks, checks, and plan assertions. Its artifact name
uses the workflow commit; inspect the result's component identity to determine
which Wallet release was tested. Treat result artifacts as internal evidence.

This lane produces engineering conformance evidence. It does not execute the
complete external EUDI device/testbed suites or establish EU or OpenID
Foundation certification. Those composed and external assessments retain their
own plans, deployment prerequisites, and accepted execution evidence.

## Local validation

`node --test scripts/*.test.mjs` exercises the manual-workflow security contract,
including refusal of automatic triggers, mutable or mismatched framework pins,
write permissions, inherited secrets, additional jobs, and substituted paths.
`node scripts/check_ci_lane_ownership.mjs` also enforces that contract while
keeping automatic source CI independent of Identity Conformance.

Workflow linting and source tests do not validate protected deployment inputs.
For a local execution, use an exact checkout of the pinned framework and the
same reviewed manifest, release bundle, and component attestation. Run its
deployment validator, EUDI Wallet runner, and execution-result validator as
defined in the reusable workflow. Do not manufacture release attestations or
treat test fixtures as evidence for a published release.
