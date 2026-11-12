#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { existsSync, readFileSync, readdirSync } from "node:fs";
import { MANUAL_EUDI_WORKFLOW_PATH, verifyManualEudiWorkflow } from "./verify_manual_eudi_workflow.mjs";

const workflowPaths = Object.freeze({
  fuzz: ".github/workflows/fuzz.yml",
  protobuf: ".github/workflows/protobuf-ci.yml",
  repositorySecurity: ".github/workflows/repository-security.yml",
  rust: ".github/workflows/rust-ci.yml",
  secretScan: ".github/workflows/secret-scan.yml",
  preflight: ".github/workflows/crates-package-preflight.yml",
  release: ".github/workflows/crates-release.yml",
  manualEudi: MANUAL_EUDI_WORKFLOW_PATH,
});

const fail = (reason) => {
  process.stderr.write(`CI lane ownership check failed: ${reason}\n`);
  process.exit(1);
};

const workflows = Object.fromEntries(
  Object.entries(workflowPaths).map(([name, path]) => {
    if (!existsSync(path)) {
      fail(`${path} is missing`);
    }
    return [name, readFileSync(path, "utf8")];
  }),
);
// Public source checks must remain runnable with the ordinary read-only token.
// Only the reviewed manual caller may execute the external conformance plan.
for (const path of readdirSync(".github/workflows")) {
  if (!/\.ya?ml$/u.test(path)) continue;
  const workflowPath = `.github/workflows/${path}`;
  const source = readFileSync(workflowPath, "utf8");
  if (workflowPath === MANUAL_EUDI_WORKFLOW_PATH) {
    try {
      verifyManualEudiWorkflow(source);
    } catch {
      fail("public CI must keep hosted EUDI conformance pinned, read-only, and manual-only");
    }
  } else if (/identity[-_]conformance/iu.test(source)) {
    fail("public CI must keep Identity Conformance in its reviewed manual lane");
  }
  if (/identity[-_]taxonomy|generate_wallet_taxonomy_evidence/iu.test(source)) {
    fail("public CI must not require private taxonomy evidence or its generator");
  }
  if (/repository:\s*["']?reallyme\/(?:ssi|zk)(?:[\s"']|$)/iu.test(source)) {
    fail("public CI must consume SSI and ZK registry packages without source checkouts");
  }
}
const localGate = readFileSync("scripts/check_security_gates.sh", "utf8");

const requireText = (source, expected, reason) => {
  if (!source.includes(expected)) fail(reason);
};

const rejectText = (source, forbidden, reason) => {
  if (source.includes(forbidden)) fail(reason);
};

const requireCount = (source, needle, expected, reason) => {
  const actual = source.split(needle).length - 1;
  if (actual !== expected) fail(`${reason}; expected ${expected}, found ${actual}`);
};

for (const name of ["rust", "fuzz", "protobuf"]) {
  requireText(
    workflows[name],
    "workflow_dispatch:",
    `${name} must support exact-commit manual release qualification`,
  );
}

for (const required of [
  "cargo check --locked --workspace --all-features",
  "cargo clippy --locked --workspace --all-targets --all-features -- -D warnings",
  "cargo nextest run --locked --workspace --no-default-features --features native",
  "cargo nextest run --locked --workspace --all-features",
  "cargo doc --locked --workspace --no-deps --all-features",
  "node scripts/check_rust_release_policy.mjs --check-wasm",
  "node scripts/check_rust_release_policy.mjs --check-msrv",
  "node scripts/check_rust_package_surfaces.mjs",
  "node scripts/check-published-semver.mjs",
  "node scripts/publish-crates-in-order.mjs inspect",
  "node --test scripts/*.test.mjs",
  "cargo deny --locked check",
  "cargo deny --locked --manifest-path fuzz/Cargo.toml --config fuzz/deny.toml check",
  "scripts/audit_committed_lockfiles.sh",
]) {
  requireCount(workflows.rust, required, 1, `Rust CI must own ${required} exactly once`);
}
requireText(workflows.rust, "RUSTFLAGS: -Dwarnings", "Rust CI must deny compiler warnings");
requireText(workflows.rust, "RUSTDOCFLAGS: -Dwarnings", "Rust CI must deny rustdoc warnings");
requireText(
  workflows.rust,
  "tool: cargo-nextest@${{ env.CARGO_NEXTEST_VERSION }}",
  "Rust CI must install its pinned nextest version",
);

for (const command of [
  "buf lint",
  "buf generate",
  "node scripts/check_schema_source_lock.mjs",
  "node scripts/check_wallet_schema_breaking.mjs",
  "node scripts/harden-generated-wallet-proto.mjs --check-idempotent",
  "node scripts/check-proto-hardening-concurrency.mjs",
  "node scripts/check-proto-first-boundaries.mjs",
]) {
  requireText(workflows.protobuf, command, `protobuf CI is missing ${command}`);
  rejectText(workflows.rust, command, `Rust CI duplicates protobuf-owned command: ${command}`);
}
for (const command of ["cargo check", "cargo test", "cargo clippy", "cargo build"]) {
  rejectText(
    workflows.protobuf,
    command,
    `protobuf CI must not duplicate Rust workspace compilation: ${command}`,
  );
}

requireCount(
  workflows.fuzz,
  '      - "Cargo.lock"',
  2,
  "fuzz CI must run for root dependency lock changes on pull requests and pushes",
);
requireCount(
  workflows.fuzz,
  "cargo +nightly-2026-09-15 fuzz build",
  1,
  "fuzz targets must be built once",
);
requireText(
  workflows.fuzz,
  "cargo +nightly-2026-09-15 metadata --locked --manifest-path fuzz/Cargo.toml",
  "fuzz CI must validate its committed lockfile",
);
requireText(
  workflows.fuzz,
  "fuzz-executables-${{ github.sha }}",
  "fuzz binaries must be immutable per commit",
);
requireText(
  workflows.fuzz,
  "WALLET_FUZZ_RUNS: \"16\"",
  "PR and push fuzz smoke must use a bounded corpus",
);
requireText(
  workflows.fuzz,
  "matrix:\n        target:",
  "scheduled fuzzing must isolate targets in a matrix",
);
for (const target of ["wallet_proto_decode", "wallet_proto_json", "wallet_identifier"]) {
  requireCount(
    workflows.fuzz,
    `          - ${target}`,
    1,
    `scheduled fuzzing must include ${target}`,
  );
}
requireText(
  workflows.fuzz,
  "scripts/run-fuzz-smoke.sh",
  "fuzz CI must use the validated runner",
);

requireText(
  workflows.secretScan,
  "scripts/run-gitleaks.sh",
  "secret scanning must use the checksummed gitleaks runner",
);
requireText(
  workflows.secretScan,
  "fetch-depth: 0",
  "secret scanning must inspect complete history",
);
rejectText(
  workflows.secretScan,
  "go install",
  "secret scanning must not build an unreviewed scanner",
);
requireText(
  workflows.repositorySecurity,
  "private-vulnerability-reporting",
  "repository security CI must enforce private vulnerability reporting",
);

requireText(
  workflows.preflight,
  "workflow_dispatch:",
  "release preflight must be manually initiated",
);
requireText(
  workflows.preflight,
  "node scripts/write_release_attestation.mjs",
  "release preflight must produce reviewed evidence",
);
requireText(
  workflows.preflight,
  "target/package/*.crate",
  "release preflight must preserve the exact reviewed crate archives",
);
requireText(
  workflows.preflight,
  "actions/attest-build-provenance@",
  "release preflight must cryptographically attest its evidence",
);
requireText(
  workflows.release,
  "RELEASE_ATTESTATION_CRATE_DIRECTORY:",
  "release must verify downloaded reviewed archives",
);
requireText(
  workflows.release,
  "REVIEWED_CRATE_DIRECTORY:",
  "release must publish the exact reviewed archives",
);

requireCount(
  localGate,
  "scripts/audit_committed_lockfiles.sh",
  1,
  "the local gate must audit every committed Cargo lockfile once",
);
requireCount(
  localGate,
  "node scripts/check_rust_release_policy.mjs --check-wasm",
  1,
  "the local gate must check the bounded Wasm participant set once",
);

process.stdout.write("CI lanes match the reviewed publication and security contract\n");
