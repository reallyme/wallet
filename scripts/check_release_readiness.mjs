#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { checkReadinessExecution } from "./check_readiness_execution.mjs";
import { MANUAL_EUDI_WORKFLOW_PATH, verifyManualEudiWorkflow } from "./verify_manual_eudi_workflow.mjs";

const coreUrl = process.env.RELEASE_READINESS_CORE_URL;
if (typeof coreUrl !== "string" || coreUrl.length === 0) {
  console.error("release readiness check failed: pinned core URL is unavailable");
  process.exit(1);
}
const { createReleaseReadinessContext } = await import(coreUrl);

const supportedArguments = new Set(["--policy-only"]);
const suppliedArguments = process.argv.slice(2);
for (const argument of suppliedArguments) {
  if (!supportedArguments.has(argument)) {
    console.error(`release readiness check failed: unsupported argument ${argument}`);
    process.exit(2);
  }
}
if (new Set(suppliedArguments).size !== suppliedArguments.length) {
  console.error("release readiness check failed: duplicate arguments are not allowed");
  process.exit(2);
}

const shared = createReleaseReadinessContext({
  scriptUrl: import.meta.url,
  requireTrackedFiles: true,
});

shared.assertReallyMeReleasePackagePolicy({
  scriptPath: "scripts/check_release_readiness.mjs",
  version: "0.6.9",
});
shared.assertWorkflowActionsPinned();
shared.assertNodeWorkflowJobsPinNode({ nodeVersion: "26" });
shared.assertCargoFuzzWorkflowPolicy({
  workflow: ".github/workflows/fuzz.yml",
  version: "0.13.2",
  minimumInstallations: 1,
  requiredInstallSteps: [
    { job: "build", name: "Install cargo-fuzz" },
  ],
});
shared.assertCargoWorkspacePolicy();
shared.assertRepositoryShapePolicy({
  archetype: "protocol-engine",
  requiredLanes: [
    "crates",
    "contracts",
    "conformance",
    "docs",
    "scripts",
    ".github",
  ],
  optionalLanes: ["vectors", "fuzz"],
  exceptions: [],
  crates: [
    { path: "crates/wallet", role: "domain" },
    { path: "crates/proto", role: "proto" },
    { path: "crates/proto-codec", role: "proto-codec" },
    { path: "crates/types", role: "domain" },
    { path: "crates/flows", role: "domain" },
    { path: "crates/lifecycle", role: "domain" },
    { path: "crates/inventory", role: "domain" },
    { path: "crates/consent", role: "domain" },
    { path: "crates/attestation", role: "domain" },
    { path: "crates/provider", role: "provider" },
    { path: "crates/runtime", role: "runtime" },
    { path: "crates/storage", role: "storage" },
    { path: "crates/keystore", role: "provider" },
    { path: "crates/render", role: "adapter" },
    { path: "crates/log", role: "domain" },
    { path: "crates/http", role: "transport" },
    { path: "crates/wallet-zk", role: "support" },
  ],
  forbiddenPaths: [
    "packages",
    "schema-baseline",
    "crates/proto/wallet",
    "crates/proto/codec",
  ],
  requireReleaseReadiness: true,
});
shared.assertSpdxHeaders({
  copyright:
    "SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved",
  license: "SPDX-License-Identifier: MIT OR Apache-2.0",
  exclusions: [
    { path: "crates/proto/src/generated", reason: "generated" },
    { path: "crates/proto/proto/identity", reason: "vendored" },
    { path: "crates/proto/proto/reallyme/crypto", reason: "vendored" },
    { path: "crates/proto/proto/reallyme/identity", reason: "vendored" },
    { path: "crates/proto/proto/reallyme/openid4vci", reason: "vendored" },
    { path: "crates/proto/proto/reallyme/openid4vp", reason: "vendored" },
  ],
  requireExclusionsMatched: true,
  requireExclusionReasons: true,
});
shared.assertRustSourcePolicy({
  roots: ["."],
  generatedPrefixes: ["crates/proto/src/generated"],
});

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));

function assertNoDocumentationSpdxHeaders() {
  const tracked = spawnSync(
    "git",
    ["ls-files", "-z", "--", "*.md", "*.txt"],
    { cwd: root, encoding: "utf8" },
  );
  if (tracked.status !== 0) {
    console.error(
      "release readiness check failed: unable to enumerate tracked documentation",
    );
    process.exit(1);
  }
  for (const path of tracked.stdout.split("\0").filter(Boolean)) {
    const source = readFileSync(resolve(root, path), "utf8");
    if (
      source.includes("SPDX-FileCopyrightText:") ||
      source.includes("SPDX-License-Identifier:")
    ) {
      console.error(
        `release readiness check failed: ${path} must not carry an SPDX header`,
      );
      process.exit(1);
    }
  }
}

assertNoDocumentationSpdxHeaders();

const fail = (message) => {
  console.error(`release readiness check failed: ${message}`);
  process.exit(1);
};

const readText = (path) => readFileSync(resolve(root, path), "utf8");
const rootCargo = readText("Cargo.toml");

const assertNoTrackedPlatformSources = () => {
  const sourceListing = spawnSync(
    "git",
    [
      "ls-files",
      "-z",
      "--",
      "*.swift",
      "*.ts",
      "*.tsx",
      "*.mts",
      "*.cts",
      "*.kt",
      "*.kts",
    ],
    { cwd: root, encoding: "utf8" },
  );
  if (sourceListing.status !== 0) {
    fail("unable to enumerate tracked platform-language sources");
  }
  const existingSources = sourceListing.stdout
    .split("\0")
    .filter((path) => path.length > 0 && existsSync(resolve(root, path)));
  if (existingSources.length > 0) {
    fail(
      `Wallet platform-language sources belong in reallyme/identity: ${existingSources.join(", ")}`,
    );
  }
};

const assertFile = (path) => {
  if (!existsSync(resolve(root, path)) || !statSync(resolve(root, path)).isFile()) {
    fail(`${path} is missing`);
  }
};

const assertVectorManifest = () => {
  let manifest;
  try {
    manifest = JSON.parse(readText("vectors/manifest.json"));
  } catch {
    fail("vectors/manifest.json is not valid JSON");
  }
  if (
    manifest?.schema_version !== 1
    || manifest?.hash_algorithm !== "sha256"
    || !Array.isArray(manifest?.vectors)
    || manifest.vectors.length === 0
  ) {
    fail("vectors/manifest.json has an invalid shape");
  }
  const seen = new Set();
  for (const vector of manifest.vectors) {
    if (
      typeof vector?.path !== "string"
      || vector.path.length === 0
      || vector.path.startsWith("/")
      || vector.path.split("/").includes("..")
      || typeof vector?.sha256 !== "string"
      || !/^[0-9a-f]{64}$/u.test(vector.sha256)
      || seen.has(vector.path)
    ) {
      fail("vectors/manifest.json contains an invalid vector entry");
    }
    seen.add(vector.path);
    const bytes = readFileSync(resolve(root, "vectors", vector.path));
    const actual = createHash("sha256").update(bytes).digest("hex");
    if (actual !== vector.sha256) {
      fail(`vectors/${vector.path} does not match its pinned SHA-256`);
    }
  }
};

const assertSameFile = (left, right) => {
  if (!readFileSync(resolve(root, left)).equals(readFileSync(resolve(root, right)))) {
    fail(`${right} is not a byte-for-byte mirror of ${left}`);
  }
};

const assertPathAbsent = (path) => {
  if (existsSync(resolve(root, path))) {
    fail(`${path} must not exist`);
  }
};

const assertContains = (path, needle) => {
  const text = readText(path);
  if (!text.includes(needle)) {
    fail(`${path} does not contain ${needle}`);
  }
};

const assertNotContains = (path, needle) => {
  const text = readText(path);
  if (text.includes(needle)) {
    fail(`${path} must not contain ${needle}`);
  }
};

const assertOccurrenceCount = (path, needle, expectedCount) => {
  const actualCount = readText(path).split(needle).length - 1;
  if (actualCount !== expectedCount) {
    fail(
      `${path} must contain ${needle} exactly ${expectedCount} times; found ${actualCount}`,
    );
  }
};

const assertRustSourcesExcludePatterns = (paths, patterns) => {
  const visit = (path) => {
    for (const entry of readdirSync(resolve(root, path), { withFileTypes: true })) {
      const child = `${path}/${entry.name}`;
      if (entry.isDirectory()) {
        // Generated protobuf identifiers are stable wire and ABI names. Build
        // output is not repository source and may contain dependency code.
        if (entry.name !== "generated" && entry.name !== "target") {
          visit(child);
        }
        continue;
      }
      if (!entry.isFile() || !entry.name.endsWith(".rs")) {
        continue;
      }
      const source = readText(child);
      for (const pattern of patterns) {
        if (pattern.test(source)) {
          fail(`${child} contains retired ZK Rust API naming`);
        }
      }
    }
  };

  for (const path of paths) {
    visit(path);
  }
};

const assertExecutable = (path) => {
  const mode = statSync(resolve(root, path)).mode;
  if ((mode & 0o111) === 0) {
    fail(`${path} is not executable`);
  }
};

assertPathAbsent(".github/workflows/taxonomy-coverage.yml");
for (const workflowName of readdirSync(resolve(root, ".github/workflows"))) {
  if (!workflowName.endsWith(".yml") && !workflowName.endsWith(".yaml")) {
    continue;
  }
  const workflowPath = `.github/workflows/${workflowName}`;
  assertNotContains(workflowPath, "reallyme/identity-taxonomy");
  if (workflowPath === MANUAL_EUDI_WORKFLOW_PATH) {
    try {
      verifyManualEudiWorkflow(readFileSync(resolve(root, workflowPath), "utf8"));
    } catch {
      fail("EUDI conformance must use the reviewed pinned manual caller");
    }
  } else {
    assertNotContains(workflowPath, "reallyme/identity-conformance");
  }
  assertNotContains(workflowPath, "REALLYME_CI_TOKEN");
}

for (const path of [
  "Cargo.toml",
  "rust-toolchain.toml",
  "crates/wallet/Cargo.toml",
  "crates/wallet/src/lib.rs",
  "LICENSE-APACHE",
  "LICENSE-MIT",
  "README.md",
  "SECURITY.md",
  "SPEC_MAP.md",
  "buf.yaml",
  "buf.gen.yaml",
  "deny.toml",
  ".github/workflows/rust-ci.yml",
  ".github/workflows/protobuf-ci.yml",
  ".github/workflows/fuzz.yml",
  ".github/workflows/crates-package-preflight.yml",
  ".github/workflows/crates-release.yml",
  MANUAL_EUDI_WORKFLOW_PATH,
  "crates/proto/proto-source-lock.json",
  "crates/proto/baselines/manifest.json",
  "crates/proto/baselines/README.md",
  "crates/proto/baselines/wallet-v1.binpb",
  "fuzz/Cargo.toml",
  "fuzz/deny.toml",
  "fuzz/README.md",
  "fuzz/fuzz_targets/wallet_proto_json.rs",
  "crates/proto/tests/fixtures/wallet-provider-v1-golden.txt",
  "crates/proto/tests/fixtures/protojson/get-credential-request.json",
  "crates/proto/tests/fixtures/protojson/delete-credential-success-response.json",
  "crates/proto/tests/fixtures/protojson/malicious-duplicate-operation.json",
  "crates/proto/tests/fixtures/protojson/malicious-unknown-field.json",
  "crates/proto/tests/fixtures/protojson/malicious-unknown-enum.json",
  "crates/proto/tests/fixtures/protojson/malicious-wrong-shape.json",
  "crates/proto-codec/tests/protojson_fixture_tests.rs",
  "vectors/README.md",
  "vectors/manifest.json",
  "vectors/wallet-key-storage-v1-golden.txt",
  "vectors/wallet-operation-v1-golden.json",
  "vectors/wallet-provider-v1-golden.txt",
  "vectors/protojson/get-credential-request.json",
  "vectors/protojson/delete-credential-success-response.json",
  "vectors/protojson/malicious-duplicate-operation.json",
  "vectors/protojson/malicious-unknown-field.json",
  "vectors/protojson/malicious-unknown-enum.json",
  "vectors/protojson/malicious-wrong-shape.json",
  "fuzz/corpus/wallet_proto_json/get-credential-request.json",
  "fuzz/corpus/wallet_proto_json/delete-credential-success-response.json",
  "fuzz/corpus/wallet_proto_json/malicious-duplicate-operation.json",
  "fuzz/corpus/wallet_proto_json/malicious-unknown-field.json",
  "fuzz/corpus/wallet_proto_json/malicious-unknown-enum.json",
  "fuzz/corpus/wallet_proto_json/malicious-wrong-shape.json",
  "scripts/check_security_gates.sh",
  "scripts/check-proto-first-boundaries.mjs",
  "scripts/check_rust_package_surfaces.mjs",
  "scripts/check_rust_release_policy.mjs",
  "scripts/check_crates_release_workflows.mjs",
  "scripts/check_schema_source_lock.mjs",
  "scripts/check_wallet_schema_breaking.mjs",
  "scripts/harden-generated-wallet-proto.mjs",
  "scripts/proto-hardening/core.mjs",
  "scripts/proto-hardening/README.md",
  "scripts/check-proto-hardening-concurrency.mjs",
  "contracts/compliance/README.md",
  "contracts/compliance/requirements/wallet_core.toml",
  "crates/proto/Cargo.toml",
  "crates/proto/README.md",
  "crates/proto/NOTICE",
  "crates/proto/src/lib.rs",
  "crates/proto-codec/Cargo.toml",
  "crates/proto-codec/README.md",
  "crates/proto-codec/NOTICE",
  "crates/proto-codec/src/lib.rs",
  "crates/proto-codec/src/limits.rs",
  "crates/proto-codec/src/proto_json.rs",
  "crates/proto-codec/tests/provider_operation_golden_tests.rs",
  "crates/provider/Cargo.toml",
  "crates/provider/src/backend.rs",
  "crates/provider/src/validate_descriptor.rs",
  "crates/provider/src/validate_response.rs",
  "crates/runtime/src/execute_operation.rs",
  "crates/runtime/src/backend.rs",
  "crates/runtime/src/handle_tests.rs",
  "crates/http/Cargo.toml",
  "crates/http/src/lib.rs",
  "crates/http/src/serve.rs",
  "crates/http/src/oidf_wallet_flow.rs",
  "crates/http/src/parse_oidf_wallet_launch.rs",
  "crates/http/src/serve_oidf_wallet_harness.rs",
  "crates/http/src/strict_json_value.rs",
  "crates/http/tests/serve_tests.rs",
  "crates/storage/src/journal.rs",
  "docs/architecture/WALLET_PROVIDER_CONTRACT.md",
  "docs/architecture/SDK_COMPOSITION.md",
  "docs/architecture/RUST_PACKAGE_POLICY.md",
  "docs/architecture/DOMAIN_SERIALIZATION_POLICY.md",
  "conformance/features/identity-wallet-handoff-v1.json",
  "conformance/features/wallet-package-policy-v1.json",
  "conformance/features/wallet-operation-capabilities-v1.json",
  "crates/proto/tests/fixtures/wallet-operation-v1-golden.json",
  "conformance/tests/identity_handoff_tests.rs",
  "conformance/tests/layout_tests.rs",
  "conformance/tests/package_policy_tests.rs",
  "conformance/tests/domain_serialization_policy_tests.rs",
  "conformance/tests/operation_capability_tests.rs",
  "conformance/tests/presentation_zk_tests.rs",
  "crates/wallet-zk/Cargo.toml",
  "crates/wallet-zk/src/lib.rs",
  "crates/wallet-zk/src/error.rs",
  "crates/wallet-zk/src/prove_presentation_derivation.rs",
  "crates/proto/proto/reallyme/wallet/v1/wallet.proto",
  "crates/proto/proto/reallyme/wallet/v1/wallet_operation.proto",
  "crates/proto/proto/reallyme/wallet/v1/wallet_provider.proto",
  "crates/proto/proto/reallyme/wallet/v1/wallet_service.proto",
]) {
  assertFile(path);
}

for (const retiredPath of [
  "LICENSE",
  "crates/http/LICENSE",
  "crates/proto/LICENSE",
  "crates/proto-codec/LICENSE",
  "docs/architecture/IDENTITY_SDK_HANDOFF.md",
  "docs/architecture/IDENTITY_SDK_MIGRATION_LEDGER.md",
  "conformance/features/identity-sdk-wallet-handoff-v1.json",
  "conformance/tests/identity_sdk_handoff_tests.rs",
]) {
  assertPathAbsent(retiredPath);
}

// The SSI-owned imported schema still contains a stable wire enum whose name
// predates the repository rename. Exclude only that locked schema; all other
// tracked source must use the current Identity repository/package name.
const retiredIdentitySdkReferenceCheck = spawnSync(
  "git",
  [
    "grep",
    "-n",
    "-I",
    "-i",
    "-E",
    "identity[-_ ]sdk",
    "--",
    ".",
    ":(exclude)crates/proto/proto/reallyme/identity/common/v1/errors.proto",
    ":(exclude)scripts/check-proto-first-boundaries.mjs",
    ":(exclude)scripts/check_release_readiness.mjs",
  ],
  { cwd: root, encoding: "utf8" },
);
if (retiredIdentitySdkReferenceCheck.status === 0) {
  fail("tracked files contain retired identity-sdk repository or package references");
}
if (retiredIdentitySdkReferenceCheck.status !== 1) {
  fail("tracked identity repository and package references could not be inspected");
}

assertOccurrenceCount(".github/workflows/rust-ci.yml", "paths:", 0);
assertOccurrenceCount(".github/workflows/protobuf-ci.yml", '"!**/*.md"', 2);
assertOccurrenceCount(".github/workflows/fuzz.yml", "paths:", 2);
assertVectorManifest();
for (const path of [
  "wallet-key-storage-v1-golden.txt",
  "wallet-operation-v1-golden.json",
  "wallet-provider-v1-golden.txt",
  "protojson/get-credential-request.json",
  "protojson/delete-credential-success-response.json",
  "protojson/malicious-duplicate-operation.json",
  "protojson/malicious-unknown-field.json",
  "protojson/malicious-unknown-enum.json",
  "protojson/malicious-wrong-shape.json",
]) {
  assertSameFile(`vectors/${path}`, `crates/proto/tests/fixtures/${path}`);
}

assertExecutable("scripts/check_security_gates.sh");
assertExecutable("scripts/check-proto-first-boundaries.mjs");
assertExecutable("scripts/check_schema_source_lock.mjs");
assertExecutable("scripts/check_wallet_schema_breaking.mjs");
assertExecutable("scripts/harden-generated-wallet-proto.mjs");
assertExecutable("scripts/check-proto-hardening-concurrency.mjs");
assertExecutable("scripts/check_ci_lane_ownership.mjs");
assertExecutable("scripts/check_rust_release_policy.mjs");
assertExecutable("scripts/run-fuzz-smoke.sh");
assertExecutable("scripts/run-gitleaks.sh");
assertExecutable("scripts/verify_required_ci.mjs");
assertContains(
  "scripts/harden-generated-wallet-proto.mjs",
  'import { hardenGeneratedProto } from "./proto-hardening/core.mjs";',
);
assertNotContains("scripts/harden-generated-wallet-proto.mjs", "function hardenDebug");
assertContains(
  "scripts/proto-hardening/core.mjs",
  "export function hardenGeneratedProto",
);
assertContains(".github/workflows/protobuf-ci.yml", '"scripts/proto-hardening/**"');
assertContains("fuzz/Cargo.toml", 'name = "wallet_proto_json"');
assertContains(".github/workflows/fuzz.yml", "fuzz run wallet_proto_json");
assertContains(
  "fuzz/fuzz_targets/wallet_proto_json.rs",
  "wallet_proto_from_json::<WalletOperationRequest>",
);

// Structural policy runs in Rust/release policy jobs; protobuf execution has
// its own required exact-commit CI lane. Complete local release checks still
// run every execution gate unless the declared policy-only mode is selected.
const policyOnly = suppliedArguments.includes("--policy-only");
const executionChecks = checkReadinessExecution({ policyOnly, root });
if (!executionChecks.success) fail(executionChecks.reason);

assertContains("Cargo.toml", 'exclude = ["fuzz"]');
assertContains("Cargo.toml", '"crates/wallet"');
assertNotContains("Cargo.toml", "[package]");
assertContains("Cargo.toml", 'license = "MIT OR Apache-2.0"');
assertContains("Cargo.toml", 'rust-version = "1.99"');
assertContains("rust-toolchain.toml", 'channel = "1.99.0"');
assertContains(
  "crates/wallet/Cargo.toml",
  'include = ["/LICENSE-MIT", "/LICENSE-APACHE", "/src/**/*.rs", "/tests/**/*.rs", "/Cargo.toml"]',
);
assertContains("crates/wallet/Cargo.toml", 'http = ["dep:reallyme-wallet-http"]');
assertContains("Cargo.toml", '[workspace.lints.rust]');
assertContains("Cargo.toml", 'deprecated = "deny"');
assertContains("Cargo.toml", 'unsafe_code = "deny"');
assertContains("Cargo.toml", '[workspace.lints.clippy]');
assertContains("Cargo.toml", 'unwrap_used = "deny"');
assertContains("Cargo.toml", 'wildcard_imports = "deny"');
assertContains("Cargo.toml", 'panic = "abort"');
assertContains("Cargo.toml", '"crates/proto"');
assertContains("Cargo.toml", '"crates/proto-codec"');
assertContains("Cargo.toml", '"crates/provider"');
assertContains("Cargo.toml", '"crates/wallet-zk"');
assertContains(
  "Cargo.toml",
  'compression_brotli = { package = "reallyme-compression-brotli", version = "=0.6.2" }',
);
assertContains("Cargo.toml", 'reallyme-credential = { version = "=0.6.2"');
assertContains("Cargo.toml", 'reallyme-openid-oauth = { version = "=0.6.2"');
assertContains("Cargo.toml", 'reallyme-disclosure-policy = { version = "=0.6.2"');
assertContains("Cargo.toml", 'reallyme-credential-status = { version = "=0.6.2"');
assertContains("Cargo.toml", 'reallyme-vp-core = { version = "=0.6.2"');
assertContains("Cargo.toml", 'reallyme-ssi-proto = { version = "=0.6.2"');
assertContains("Cargo.toml", 'reallyme-etsi-eaa-conformance = { version = "=0.6.2"');
assertContains("Cargo.toml", 'reallyme-trust-x509 = { version = "=0.6.2"');
assertContains("Cargo.toml", 'reallyme-openid4vci-wallet = { version = "=0.3.2"');
assertContains("Cargo.toml", 'reallyme-openid4vp-wallet = { version = "=0.3.1"');
assertContains("Cargo.toml", 'reallyme-zk-api = { version = "=0.3.2" }');
assertNotContains("Cargo.toml", 'path = "../ssi/');
assertNotContains("Cargo.toml", 'path = "../crypto/');
assertNotContains("Cargo.toml", 'path = "../openid4vci/');
assertNotContains("Cargo.toml", 'path = "../openid4vp/');
assertNotContains("Cargo.toml", 'path = "../zk/');
assertNotContains("Cargo.toml", "[patch.crates-io]");
assertNotContains("fuzz/Cargo.toml", "[patch.crates-io]");
assertNotContains("fuzz/Cargo.toml", 'path = "../../crypto/');
assertNotContains("Cargo.toml", 'path = "../identity/crates/');
assertNotContains("Cargo.toml", '"crates/ffi"');
assertNotContains("Cargo.toml", '"crates/wasm"');
assertNotContains("crates/flows/Cargo.toml", "reallyme-zk-api");
assertRustSourcesExcludePatterns(["crates", "conformance", "fuzz"], [
  /\bDirectClaimV1\b/u,
  /\bPreparedPersonaV1\b/u,
  /\bCommonRootV1\b/u,
  /\bZkCommonRoot[A-Za-z0-9_]*\b/u,
  /\bZkPreparedCredentialBindingInputs\b/u,
  /\bZkPreparedEvidenceVerifier\b/u,
  /\bZkPreparedEvidenceVerifyRequest\b/u,
  /\bZkPreparedHolderPublicKey\b/u,
  /\bZkPreparedJoinError\b/u,
  /\bZkPreparedJoinReason\b/u,
  /\bZkPreparedProof\b/u,
  /\bZkPreparedBundleKind\b/u,
  /\bZkPreparedProofStage\b/u,
  /\bZkPreparedProofWindow\b/u,
  /\bZkPreparedProofWindowError\b/u,
  /\bZkPreparedProofWindowReason\b/u,
  /\bZkPreparedRawPublicInputs\b/u,
  /\bZkPreparedReplayChallenge\b/u,
  /\bZkPreparedReplayError\b/u,
  /\bZkPreparedReplayReason\b/u,
  /\bZkPreparedReplayStore\b/u,
  /\bZkPreparedStageJoin\b/u,
  /\bZkPreparedStatusAuthority\b/u,
  /\bZkPreparedStatusFeed\b/u,
  /\bZkPreparedStatusListPointer\b/u,
  /\bZkPreparedSubjectPublicKey\b/u,
  /\bZkVerifiedPreparedEvidence\b/u,
]);
assertContains("crates/wallet-zk/Cargo.toml", 'name = "reallyme-wallet-zk"');
assertContains("crates/wallet-zk/Cargo.toml", "publish = true");
assertContains("crates/wallet-zk/Cargo.toml", "reallyme-zk-api = { workspace = true }");
assertNotContains("Cargo.toml", "jni =");
assertNotContains("Cargo.toml", "wasm-bindgen");
assertContains(
  ".github/workflows/rust-ci.yml",
  "node scripts/check_rust_release_policy.mjs --check-msrv",
);
assertOccurrenceCount(".github/workflows/rust-ci.yml", "toolchain: 1.99.0", 4);

for (const workflow of [
  ".github/workflows/protobuf-ci.yml",
  ".github/workflows/crates-package-preflight.yml",
  ".github/workflows/crates-release.yml",
]) {
  assertOccurrenceCount(workflow, "toolchain: 1.99.0", 1);
}
assertContains("crates/proto-codec/Cargo.toml", 'name = "reallyme-wallet-proto-codec"');
assertContains("crates/proto/Cargo.toml", '"/baselines/**/*"');
assertContains("crates/proto-codec/Cargo.toml", 'reallyme-wallet-proto = { path = "../proto"');
assertContains("crates/proto-codec/src/limits.rs", "MAX_WALLET_PROTO_MESSAGE_BYTES");
assertContains("crates/proto-codec/src/limits.rs", "WALLET_PROTO_UNKNOWN_FIELD_LIMIT");
assertContains("crates/proto-codec/src/proto_json.rs", "JsonDuplicateKey");
assertContains("crates/proto-codec/src/proto_json.rs", "try_encoded_len");
assertNotContains("crates/proto-codec/src/proto_json.rs", ".encode_to_vec()");
assertContains("crates/proto-codec/src/encode.rs", "try_encode_bounded");
assertNotContains("crates/proto-codec/src/encode.rs", ".encode_to_vec()");
assertNotContains("buf.gen.yaml", "buf.build/apple/swift");
assertNotContains("buf.gen.yaml", "buf.build/protocolbuffers/java");
assertNotContains("buf.gen.yaml", "buf.build/protocolbuffers/kotlin");
assertNotContains("buf.gen.yaml", "buf.build/bufbuild/es");
assertContains("buf.gen.yaml", "views=false");
assertContains(
  "buf.gen.yaml",
  "extern_path=.reallyme.crypto.v1=::reallyme_crypto_proto::generated::proto::reallyme::crypto::v1",
);
assertContains("buf.gen.yaml", "exclude_package=.reallyme.openid4vp.v1");
assertContains("crates/proto/src/generated/buffa/mod.rs", "pub mod wallet");
assertNotContains("crates/proto/src/generated/buffa/mod.rs", "pub mod identity");
assertNotContains("crates/proto/src/generated/buffa/mod.rs", "pub mod crypto");
assertNotContains("crates/proto/src/generated/buffa/mod.rs", "pub mod openid4vci");
assertNotContains("crates/proto/src/generated/buffa/mod.rs", "pub mod openid4vp");
assertContains(".github/workflows/protobuf-ci.yml", "BUF_VERSION: 1.73.0");
assertContains(".github/workflows/protobuf-ci.yml", "BUFFA_VERSION: 0.9.2");
assertContains(".github/workflows/crates-package-preflight.yml", "BUF_VERSION: 1.73.0");
assertContains(".github/workflows/crates-package-preflight.yml", "BUFFA_VERSION: 0.9.2");
assertContains(
  ".github/workflows/protobuf-ci.yml",
  "node scripts/check_schema_source_lock.mjs",
);
assertContains(
  ".github/workflows/protobuf-ci.yml",
  "node scripts/check_wallet_schema_breaking.mjs",
);
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  "node scripts/check_schema_source_lock.mjs",
);
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  "node scripts/check_wallet_schema_breaking.mjs",
);
assertContains(
  "crates/proto-codec/src/limits.rs",
  "MAX_WALLET_PROVIDER_PROTO_MESSAGE_BYTES",
);
assertContains("crates/proto/proto/reallyme/wallet/v1/wallet_operation.proto", "message WalletOperationRequest");
assertContains("crates/proto/proto/reallyme/wallet/v1/wallet_operation.proto", "bytes idempotency_key = 1;");
assertContains("crates/proto/proto/reallyme/wallet/v1/wallet_operation.proto", "message WalletOperationResponse");
assertContains("crates/proto/proto/reallyme/wallet/v1/wallet_provider.proto", "message WalletProviderDescriptor");
assertContains("crates/proto/proto/reallyme/wallet/v1/wallet_provider.proto", "message WalletProviderRequest");
assertContains("crates/proto/proto/reallyme/wallet/v1/wallet_provider.proto", "message WalletProviderResponse");
assertContains("crates/proto/proto/reallyme/wallet/v1/wallet_provider.proto", "uint64 executor_id = 2;");
assertContains("crates/proto/proto/reallyme/wallet/v1/wallet_service.proto", "rpc WalletOperation");
assertContains("crates/runtime/src/execute_operation.rs", "pub fn execute_operation");
assertContains(
  "crates/runtime/src/execute_operation.rs",
  "pub fn execute_wallet_operation_v1",
);
assertContains(
  "crates/runtime/src/execute_operation.rs",
  "pub trait WalletOperationExecutor",
);
assertContains(
  "crates/http/src/serve.rs",
  "decode_wallet_operation_connect_request",
);
assertContains("crates/http/src/serve.rs", "wallet_proto_from_json(json)");
assertContains("crates/http/src/serve.rs", "wallet_proto_to_json(message)");
assertContains("crates/http/src/serve.rs", "encode_wallet_operation_response(message)");
assertNotContains("crates/http/src/serve.rs", ".encode_to_vec()");
assertContains("crates/http/src/serve.rs", "canonical_problem_response");
assertContains("crates/http/src/serve_response.rs", "proto_error_to_proto(reason)");
assertNotContains("crates/http/src/serve.rs", "application/problem+json");
assertNotContains(
  "crates/http/src/serve.rs",
  "/reallyme.wallet.v1.WalletCoreService/PutCredentialRecord",
);
assertContains(
  "crates/proto/proto/reallyme/wallet/v1/wallet_service.proto",
  "rpc WalletOperation(WalletOperationRequest) returns (WalletOperationResponse);",
);
assertNotContains(
  "crates/proto/proto/reallyme/wallet/v1/wallet_service.proto",
  "rpc PutCredentialRecord",
);
assertContains(
  "crates/http/tests/serve/boundary.rs",
  "canonical_connect_json_rejects_duplicate_keys",
);
assertContains(
  "crates/http/tests/serve/boundary.rs",
  "canonical_connect_proto_malformed_body_returns_typed_envelope",
);
assertContains(
  "crates/http/tests/serve/boundary.rs",
  "canonical_connect_body_limit_returns_typed_envelope",
);
assertContains(
  "crates/http/tests/serve_tests.rs",
  "axum_state_rejects_zero_and_unbounded_body_limits",
);
assertContains(
  "crates/http/src/parse_oidf_wallet_launch.rs",
  "#[serde(deny_unknown_fields)]",
);
assertContains(
  "crates/http/src/serve_oidf_wallet_harness_tests.rs",
  "rejects_oversized_get_launch_input",
);
assertContains("crates/runtime/src/execute_operation.rs", "begin_idempotent_operation");
assertContains("crates/runtime/src/execute_operation.rs", "commit_idempotent_operation");
assertNotContains("crates/runtime/src/handle_tests.rs", "canonical_and_legacy");
for (const handlerName of [
  "put_credential_record",
  "get_credential_record",
  "apply_credential_status_evidence",
  "delete_credential_record",
  "claim_presentation_copy",
  "evaluate_verifier_entitlement",
  "append_transaction_log",
  "append_qtsp_decision",
  "save_flow_snapshot",
  "get_flow_snapshot",
  "put_wallet_lifecycle_record",
  "get_wallet_lifecycle_record",
  "apply_wallet_lifecycle_event",
  "append_wallet_lifecycle_evidence",
]) {
  const handlerPath = handlerName === "apply_wallet_lifecycle_event"
    ? "crates/runtime/src/apply_lifecycle_event.rs"
    : "crates/runtime/src/handle.rs";
  assertContains(handlerPath, `pub(crate) fn ${handlerName}`);
  assertNotContains(handlerPath, `pub fn ${handlerName}`);
}
assertContains("crates/runtime/src/apply_lifecycle_event.rs", "reconcile_wallet_lifecycle_retry");
assertContains("crates/runtime/src/apply_lifecycle_event.rs", "apply_reconciled_wallet_lifecycle_retry");
assertContains(
  "crates/proto/proto/reallyme/wallet/v1/wallet_provider.proto",
  "WalletLifecycleRetryReconciliation retry_reconciliation = 1;",
);
assertContains(
  "crates/provider/src/provider_backend.rs",
  "SynchronousProtobufProviderBackend",
);
assertContains(
  "crates/provider/src/provider_backend.rs",
  "AsynchronousHostProtobufProviderBackend",
);
assertContains("crates/provider/src/provider_backend.rs", "validate_provider_exchange");
assertContains("crates/provider/src/backend.rs", "ProtobufProviderBackend");
assertContains(
  "crates/provider/src/validate_descriptor.rs",
  "REQUIRED_PROVIDER_CAPABILITIES",
);
assertContains("crates/runtime/src/backend.rs", "fn create_credential_record");
assertContains("crates/runtime/src/backend.rs", "fn create_wallet_lifecycle_record");
assertContains(
  "crates/runtime/src/backend.rs",
  "fn compare_and_swap_credential_record",
);
assertContains(
  "crates/runtime/src/backend.rs",
  "fn compare_and_swap_wallet_lifecycle_record",
);
assertContains(
  "crates/proto/proto/reallyme/wallet/v1/errors.proto",
  "WALLET_ERROR_REASON_REVISION_CONFLICT",
);
assertContains("crates/proto/proto/reallyme/wallet/v1/wallet.proto", "RecordRevision expected_revision");
assertContains("crates/proto/proto/reallyme/wallet/v1/wallet.proto", "uint32 state_schema_version = 5;");
assertContains(
  "crates/proto/proto/reallyme/wallet/v1/wallet.proto",
  "reallyme.crypto.v1.AeadAlgorithm encryption_algorithm = 5;",
);
assertContains(
  "crates/proto/proto/reallyme/wallet/v1/wallet.proto",
  "reserved \"algorithm\";",
);
assertNotContains("crates/proto/proto/reallyme/wallet/v1/wallet.proto", "message QeaaCompliance");
assertNotContains("crates/proto/proto/reallyme/wallet/v1/errors.proto", "message IdentityError");
assertNotContains(
  "crates/proto/proto/reallyme/wallet/v1/wallet.proto",
  "message WalletCredentialStoreRequest",
);
assertNotContains("crates/proto/proto/reallyme/wallet/v1/wallet.proto", "message WalletArtifact");
assertNotContains("crates/proto/proto/reallyme/wallet/v1/wallet.proto", "message WalletCard");
assertNotContains("crates/proto/proto/reallyme/wallet/v1/wallet.proto", "message BatchPool");
assertNotContains("crates/types/src/credential.rs", "pub struct WalletCard");
assertContains(
  "conformance/tests/proto_contract_tests.rs",
  "legacy_wallet_messages_are_absent_from_owned_and_canonical_contracts",
);
assertContains("crates/types/src/flow.rs", "pub enum FlowStateSchemaVersion");
assertContains("crates/types/src/storage.rs", "pub enum StorageEncryptionAlgorithm");
assertContains("crates/flows/src/contact_model.rs", "pub enum ContactProtocolVersion");
assertNotContains("crates/flows/src/contact_model.rs", "pub version: String");
assertContains(
  "crates/proto-codec/src/convert.rs",
  "storage_encryption_algorithm_from_proto",
);
assertContains(
  "crates/proto-codec/tests/convert_tests.rs",
  "encrypted_record_header_rejects_unapproved_crypto_algorithm",
);
assertNotContains("crates/proto-codec/src/convert.rs", "legacy_storage_encryption_algorithm");
assertContains(
  "crates/inventory/src/validate_record.rs",
  "record.header.algorithm.nonce_length()",
);
assertContains(
  "crates/proto-codec/tests/convert_tests.rs",
  "rejects_missing_and_unknown_flow_state_schema_versions",
);
assertContains(
  "crates/proto-codec/tests/convert_tests.rs",
  "rejects_malformed_empty_and_kind_mismatched_flow_state_payloads",
);
assertContains(
  "crates/proto/proto/reallyme/wallet/v1/errors.proto",
  "CONVERT_ERROR_REASON_INVALID_FLOW_STATE_PAYLOAD",
);
assertContains("crates/storage/src/journal.rs", "pub trait OperationJournal");
assertContains(
  "docs/architecture/WALLET_PROVIDER_CONTRACT.md",
  "WalletProviderRequest",
);
assertContains(
  "docs/architecture/SDK_COMPOSITION.md",
  "ReallyMe Wallet is the Rust policy and state engine",
);
assertContains(
  "docs/architecture/SDK_COMPOSITION.md",
  "General Wallet client API",
);
assertContains(
  "docs/architecture/SDK_COMPOSITION.md",
  "remain in `reallyme/identity`",
);
assertContains(
  "vectors/wallet-operation-v1-golden.json",
  "AEAD_ALGORITHM_AES_256_GCM_SIV",
);
assertContains(
  "conformance/features/identity-wallet-handoff-v1.json",
  '"product_facing_swift_api": "reallyme/identity"',
);
assertContains(
  "conformance/features/identity-wallet-handoff-v1.json",
  '"wallet_platform_binding_crates_allowed": false',
);
assertContains(
  "conformance/features/identity-wallet-handoff-v1.json",
  '"method_name_dispatch_catalog_allowed": false',
);
assertContains(
  "conformance/features/identity-wallet-handoff-v1.json",
  '"native_ffi_and_jni_bindings": "reallyme/identity"',
);
assertContains(
  "conformance/features/identity-wallet-handoff-v1.json",
  '"sha2_256": "7ce2cd70fde0946ed812277ab06daafaae77e88fac8e9727e6207be571a0a4a4"',
);
assertContains(
  "conformance/features/identity-wallet-handoff-v1.json",
  '"sha2_256": "371e57accb9fdc535ddd1a19ef9743e5d6b2f1f9ef179e1d6435a500dbf5fae7"',
);
assertContains(
  "crates/proto-codec/tests/provider_operation_golden_tests.rs",
  "provider_golden_fixtures_match_canonical_protobuf",
);
assertContains(
  "conformance/features/identity-wallet-handoff-v1.json",
  '"status": "complete"',
);
assertContains(
  "conformance/tests/identity_handoff_tests.rs",
  "identity_handoff_matches_the_rust_only_wallet_boundary",
);
assertContains(
  ".github/workflows/rust-ci.yml",
  "node scripts/check_rust_package_surfaces.mjs",
);
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  "node scripts/check_rust_package_surfaces.mjs",
);
for (const path of [
  "crates/ffi",
  "crates/wasm",
  "gen",
  "Package.swift",
  "Package.resolved",
  "packages",
  "crates/runtime/src/serve.rs",
  "crates/runtime/src/serve_oidf_wallet_harness.rs",
  "crates/runtime/tests/serve_tests.rs",
  "crates/runtime/examples/serve_oidf_wallet_harness.rs",
  "crates/proto/proto/reallyme/openid4vci/v1/openid4vci_service.proto",
  "crates/proto/proto/reallyme/openid4vp/v1/openid4vp_service.proto",
  "fuzz/artifacts/wallet_delivery_json",
  "fuzz/artifacts/wallet_distribution_json",
  "fuzz/corpus/wallet_delivery_json",
  "fuzz/corpus/wallet_distribution_json",
]) {
  assertPathAbsent(path);
}
assertContains("crates/http/src/serve.rs", "WalletCoreService/WalletOperation");
assertContains(
  "conformance/fixtures/wallets/wallet-core-sdk-boundary.json",
  '"canonical_entrypoint": "execute_wallet_operation_v1"',
);
assertNotContains(
  "conformance/fixtures/wallets/wallet-core-sdk-boundary.json",
  '"compatibility_service"',
);
assertContains(
  "conformance/tests/sdk_contract_tests.rs",
  "sdk_boundary_fixture_names_only_the_canonical_operation_protocol",
);
assertContains(
  "vectors/wallet-operation-v1-golden.json",
  '"protobuf_hex": "927d150a13',
);
assertContains(
  "vectors/wallet-operation-v1-golden.json",
  '"id": "delete-credential-idempotent-request"',
);
assertContains(
  "conformance/features/wallet-operation-capabilities-v1.json",
  '"ambient_provider_fallback": false',
);
assertContains(
  "conformance/features/wallet-operation-capabilities-v1.json",
  '"missing_adapter_behavior": "fail_closed"',
);
assertContains(
  "conformance/features/wallet-operation-capabilities-v1.json",
  '"platform_binding_owner": "reallyme/identity"',
);
assertContains(
  "conformance/features/wallet-operation-capabilities-v1.json",
  '"generic_client_substrate_owner": "reallyme/vaultkit"',
);
assertContains(
  "conformance/features/wallet-operation-capabilities-v1.json",
  '"opaque_storage_surface_owner": "reallyme/vaultwallet"',
);
assertContains(
  "conformance/features/wallet-operation-capabilities-v1.json",
  '"response_replay": "exact_canonical_bytes"',
);
assertContains(
  "conformance/features/wallet-operation-capabilities-v1.json",
  '"atomicity": "atomic_create"',
);
assertContains(
  "conformance/features/wallet-operation-capabilities-v1.json",
  '"correlation": "executor_id_and_request_id"',
);
assertContains(
  "conformance/tests/operation_capability_tests.rs",
  "capability_manifest_is_exhaustive_and_matches_dispatch",
);
assertContains(
  "conformance/features/wallet-package-policy-v1.json",
  '"authorized_public_packages": [',
);
assertNotContains(
  "conformance/features/wallet-package-policy-v1.json",
  '"classification": "private_composition_leaf"',
);
assertContains(
  "conformance/features/wallet-package-policy-v1.json",
  '"owner": "reallyme/identity"',
);
assertContains(
  "conformance/features/wallet-client-surface-ownership-v1.json",
  '"general_wallet_client_bindings": "reallyme/identity"',
);
assertContains(
  "conformance/features/wallet-client-surface-ownership-v1.json",
  '"expert_hardware_binding_provider": "injected-platform-host"',
);
assertContains(
  "conformance/features/wallet-client-surface-ownership-v1.json",
  '"generic_client_substrate": "reallyme/vaultkit"',
);
assertContains(
  "conformance/features/wallet-client-surface-ownership-v1.json",
  '"opaque_storage_engine": "reallyme/vaultwallet"',
);
assertContains(
  "conformance/features/wallet-client-surface-ownership-v1.json",
  '"wallet_v1_protected_read_mode": "vault-proxy-only"',
);
assertContains(
  "conformance/features/wallet-client-surface-ownership-v1.json",
  '"vaultkit": "121ecf457cb970a1c3022fe702484093efb2d9c0"',
);
assertContains(
  "conformance/tests/client_surface_ownership_tests.rs",
  "client_surface_ownership_is_closed_and_hardware_scope_is_exact",
);
assertContains(
  "conformance/tests/package_policy_tests.rs",
  "package_policy_matches_the_workspace_and_authorizes_only_the_release_graph",
);
assertContains(
  "conformance/tests/layout_tests.rs",
  "repository_uses_the_standardized_wallet_shape",
);
assertContains(
  "docs/architecture/RUST_PACKAGE_POLICY.md",
  "The seventeen Wallet Rust crates in the approved release graph are authorized",
);
assertContains(
  "docs/architecture/DOMAIN_SERIALIZATION_POLICY.md",
  "Generated ProtoJSON is the only JSON representation of the public Wallet",
);
assertContains(
  "conformance/tests/domain_serialization_policy_tests.rs",
  "hand_written_domain_serde_is_absent",
);
assertNotContains("crates/types/Cargo.toml", "serde");

for (const path of [
  "crates/wallet-zk/src/prove_presentation_derivation_tests.rs",
  "conformance/tests/presentation_zk_tests.rs",
]) {
  assertContains(path, "ZkWitness::try_from_noir_witness_stack_v1");
  assertNotContains(path, "ZkWitness::try_from_exact_bytes");
}
assertContains(
  "conformance/tests/presentation_zk_tests.rs",
  "zk_presentation_rejects_prover_substitution_of_each_session_context",
);
assertPathAbsent("conformance/tests/zk_external_binding_tests.rs");
for (const required of [
  "../zk/crates/proto/proto/reallyme/zk/v1/manifest.proto",
  "../openid4vp/crates/proto/proto/reallyme/openid4vp/v1/openid4vp.proto",
]) {
  assertContains("conformance/reports/external-readiness.json", required);
}
for (const forbidden of [
  "../zk/proto/reallyme/zk/v1/manifest.proto",
  "../openid4vp/protos/reallyme/openid4vp/v1/openid4vp.proto",
]) {
  assertNotContains("conformance/reports/external-readiness.json", forbidden);
}
assertPathAbsent("crates/types/src/delivery.rs");
assertContains("crates/keystore/src/model.rs", "ZeroizeOnDrop");
assertContains("crates/keystore/src/attest.rs", "ZeroizeOnDrop");
assertContains("crates/attestation/src/model.rs", "ZeroizeOnDrop");
assertContains("crates/lifecycle/src/model.rs", "ZeroizeOnDrop");
assertContains("crates/types/src/identifiers.rs", "ZeroizeOnDrop");
assertContains(
  "crates/types/src/credential_tests.rs",
  "credential_owners_advertise_drop_time_zeroization",
);
assertContains(
  "crates/types/src/consent_tests.rs",
  "consent_owners_advertise_drop_time_zeroization",
);
assertContains(
  "crates/types/src/log_tests.rs",
  "log_owners_advertise_drop_time_zeroization",
);
assertContains(
  "crates/flows/src/state_tests.rs",
  "resumable_states_advertise_drop_time_zeroization",
);
assertContains(
  "crates/http/src/oidf_wallet_flow.rs",
  "OidfWalletFlowRequest(<redacted>)",
);
assertContains(
  "crates/http/src/serve_oidf_wallet_harness_tests.rs",
  "oidf_launch_owners_advertise_drop_time_zeroization",
);
assertNotContains("crates/keystore/src/attest.rs", "#[derive(Debug");
assertNotContains("crates/attestation/src/model.rs", "#[derive(Debug");
assertContains("crates/proto/proto/reallyme/wallet/v1/wallet.proto", "reallyme.security: sensitive-owner");
assertContains(
  "crates/proto/src/generated/buffa/reallyme.wallet.v1.wallet.rs",
  "impl ::zeroize::ZeroizeOnDrop for EncryptedRecord",
);
assertContains(
  "crates/proto/src/generated/buffa/reallyme.wallet.v1.wallet_operation.rs",
  "WalletOperationRequest(<redacted>)",
);
assertContains(
  "crates/proto/src/generated/buffa/reallyme.wallet.v1.wallet_provider.rs",
  "WalletProviderRequest(<redacted>)",
);
assertContains(
  "crates/proto/src/generated/buffa/reallyme.wallet.v1.wallet_provider.rs",
  "impl ::zeroize::ZeroizeOnDrop for WalletProviderRequest",
);
assertContains(
  "crates/proto/proto/reallyme/wallet/v1/errors.proto",
  "reallyme.security: sensitive-owner",
);
assertContains(
  "crates/proto/src/generated/buffa/reallyme.wallet.v1.errors.rs",
  "WalletErrorEnvelope(<redacted>)",
);
assertContains(
  "crates/proto/src/generated/buffa/reallyme.wallet.v1.errors.rs",
  "impl ::zeroize::ZeroizeOnDrop for WalletErrorEnvelope",
);
assertContains(
  "crates/proto/tests/generated_security_tests.rs",
  "imported_protocol_owners_remain_redacted_by_wallet_snapshot_wrappers",
);
assertContains(
  "crates/proto/tests/generated_security_tests.rs",
  "wallet_error_envelope_debug_redacts_nested_correlation_value",
);

for (const forbidden of [
  "reallyme-wallet-attestation",
  "reallyme-wallet-keystore",
  "reallyme-wallet-lifecycle",
  "reallyme-wallet-types",
  "thiserror",
]) {
  assertNotContains("crates/proto/Cargo.toml", forbidden);
}

for (const forbidden of [
  "pub mod codec",
  "pub mod convert",
  "pub mod decode",
  "pub mod encode",
  "pub mod error",
]) {
  assertNotContains("crates/proto/src/lib.rs", forbidden);
}

// Encoding and decoding are distinct reviewed boundaries. A compatibility
// re-export would recreate a second public codec surface and obscure ownership.
assertPathAbsent("crates/proto-codec/src/codec.rs");
assertNotContains("crates/proto-codec/src/lib.rs", "pub mod codec;");

if (rootCargo.includes('swift = [') || rootCargo.includes('kotlin = [')) {
  fail("Rust cargo features must not encode Swift or Kotlin package policy");
}
assertNoTrackedPlatformSources();

assertContains("README.md", "scripts/audit_committed_lockfiles.sh");
assertContains("README.md", "cargo deny check");
assertContains("README.md", "cargo +nightly-2026-09-15 fuzz build");
assertContains("SECURITY.md", "scripts/check_security_gates.sh");
assertContains("SECURITY.md", "cargo +nightly-2026-09-15 fuzz build");
assertContains("SECURITY.md", "every committed Cargo lockfile");
assertContains("SECURITY.md", "cargo deny check");
assertContains("deny.toml", 'unknown-registry = "deny"');
assertContains("deny.toml", 'wildcards = "deny"');
assertContains("deny.toml", "allow-git = []");
assertNotContains("Cargo.lock", "git+https://github.com/reallyme/ssi");
for (const unpublishedOpenId4VciDependency of [
  "openid4vci-http",
  "openid4vci-issuer",
  "openid4vci-proto-codec",
]) {
  assertNotContains("Cargo.toml", unpublishedOpenId4VciDependency);
  assertNotContains("conformance/Cargo.toml", unpublishedOpenId4VciDependency);
}
assertPathAbsent("conformance/tests/openid4vci_composition_tests.rs");
assertPathAbsent("conformance/tests/openid4vci_live_adapter_tests.rs");
assertContains("fuzz/Cargo.toml", "[package.metadata]");
assertContains("fuzz/Cargo.toml", "cargo-fuzz = true");
assertContains("fuzz/Cargo.toml", "[workspace]");
assertContains("fuzz/deny.toml", 'crate = "libfuzzer-sys"');
assertContains("fuzz/deny.toml", 'allow = ["NCSA"]');

for (const target of [
  "wallet_proto_decode",
  "wallet_proto_json",
  "wallet_identifier",
]) {
  assertContains("fuzz/Cargo.toml", `name = "${target}"`);
  assertFile(`fuzz/fuzz_targets/${target}.rs`);
}

for (const workflow of [
  ".github/workflows/rust-ci.yml",
  ".github/workflows/fuzz.yml",
]) {
  assertNotContains(workflow, "repository: reallyme/ssi");
  assertNotContains(workflow, "repository: reallyme/identity");
  assertNotContains(workflow, "repository: reallyme/crypto");
  assertNotContains(workflow, "repository: reallyme/openid4vci");
  assertNotContains(workflow, "repository: reallyme/openid4vp");
  assertNotContains(workflow, "repository: reallyme/zk");
}

assertContains(
  "crates/proto/proto-source-lock.json",
  '"repository": "https://github.com/reallyme/ssi.git"',
);
assertNotContains(
  "crates/proto/proto-source-lock.json",
  '"repository": "https://github.com/reallyme/identity.git"',
);

for (const workflow of [".github/workflows/rust-ci.yml"]) {
  assertContains(workflow, "runs-on: ubuntu-24.04");
  assertNotContains(workflow, "swift-actions/setup-swift");
  assertContains(workflow, "repository: reallyme/release-readiness");
  assertContains(workflow, "ref: 9cf40c7da1def8a8d809af51789284097c572dd5");
  assertContains(
    workflow,
    "node .release-readiness/scripts/run-consumer-check.mjs --policy-only",
  );
}

assertContains(".github/workflows/crates-package-preflight.yml", "runs-on: ubuntu-24.04");
assertNotContains(
  ".github/workflows/crates-package-preflight.yml",
  "swift-actions/setup-swift",
);
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  "repository: reallyme/release-readiness",
);
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  "ref: 9cf40c7da1def8a8d809af51789284097c572dd5",
);
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  "node .release-readiness/scripts/run-consumer-check.mjs",
);

for (const command of [
  "node scripts/check_schema_source_lock.mjs",
  "buf lint",
  "node scripts/check_wallet_schema_breaking.mjs",
  "buf generate",
  "cargo fmt --package reallyme-wallet-proto",
  "node scripts/harden-generated-wallet-proto.mjs --check-idempotent",
  "node scripts/check-proto-hardening-concurrency.mjs",
  "node scripts/check-proto-first-boundaries.mjs",
]) {
  assertContains(".github/workflows/protobuf-ci.yml", command);
  assertContains(".github/workflows/crates-package-preflight.yml", command);
}

const ciLaneOwnershipCheck = spawnSync(
  process.execPath,
  ["scripts/check_ci_lane_ownership.mjs"],
  { cwd: root, encoding: "utf8" },
);
if (ciLaneOwnershipCheck.status !== 0) {
  fail(ciLaneOwnershipCheck.stderr.trim() || "CI lane ownership check failed");
}

const publicCratePolicyCheck = spawnSync(
  process.execPath,
  ["scripts/check_rust_release_policy.mjs"],
  { cwd: root, encoding: "utf8" },
);
if (publicCratePolicyCheck.status !== 0) {
  fail(publicCratePolicyCheck.stderr.trim() || "public crate toolchain policy check failed");
}

const cratesReleaseWorkflowCheck = spawnSync(
  process.execPath,
  ["scripts/check_crates_release_workflows.mjs"],
  { cwd: root, encoding: "utf8" },
);
if (cratesReleaseWorkflowCheck.status !== 0) {
  fail(cratesReleaseWorkflowCheck.stderr.trim() || "crates.io workflow policy check failed");
}

console.log(policyOnly ? "release policy checks passed; execution remains in its owning CI lanes" : "release readiness checks passed");
