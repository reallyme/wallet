#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const policyPath = resolve(
  root,
  "conformance/features/wallet-package-policy-v1.json",
);
const PACKAGE_NAME = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const MAX_CARGO_OUTPUT_BYTES = 4 * 1024 * 1024;
const MAX_CARGO_METADATA_BYTES = 32 * 1024 * 1024;
const CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index";

const fail = (reason) => {
  process.stderr.write(`Rust package surface check failed: ${reason}\n`);
  process.exit(1);
};

let policy;
try {
  policy = JSON.parse(readFileSync(policyPath, "utf8"));
} catch {
  fail("package policy is not valid JSON");
}

if (
  policy === null
  || typeof policy !== "object"
  || Array.isArray(policy)
  || policy.schema_version !== 1
  || !Array.isArray(policy.workspace_packages)
) {
  fail("package policy has an invalid shape");
}

const packages = policy.workspace_packages.filter(
  (entry) => entry?.classification === "intended_rust_release",
);
if (packages.length === 0) {
  fail("package policy declares no intended Rust release packages");
}

const assertUniqueReallyMeLockPackages = (lockPath) => {
  const identities = new Set();
  const packageBlocks = readFileSync(resolve(root, lockPath), "utf8")
    .split("[[package]]")
    .slice(1);
  for (const block of packageBlocks) {
    const name = /^name = "([^"]+)"$/mu.exec(block)?.[1];
    const version = /^version = "([^"]+)"$/mu.exec(block)?.[1];
    if (name === undefined || version === undefined || !name.startsWith("reallyme-")) {
      continue;
    }
    const identity = `${name}@${version}`;
    if (identities.has(identity)) {
      fail(`${lockPath} resolves a ReallyMe package from multiple sources: ${identity}`);
    }
    identities.add(identity);
  }
};

assertUniqueReallyMeLockPackages("Cargo.lock");
assertUniqueReallyMeLockPackages("fuzz/Cargo.lock");

const readLockedGraph = (manifest) => {
  const result = spawnSync(
    "cargo",
    ["metadata", "--locked", "--all-features", "--format-version", "1", "--manifest-path", manifest],
    {
      cwd: root,
      encoding: "utf8",
      maxBuffer: MAX_CARGO_METADATA_BYTES,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  if (result.status !== 0 || result.error !== undefined) {
    fail(`cargo rejected the locked dependency graph for ${manifest}`);
  }
  try {
    const graph = JSON.parse(result.stdout);
    if (!Array.isArray(graph.packages) || !Array.isArray(graph.workspace_members)) {
      fail(`invalid dependency metadata for ${manifest}`);
    }
    return graph;
  } catch {
    fail(`invalid dependency metadata for ${manifest}`);
  }
};

const assertRegistryGraph = (graph, localMembers, manifest) => {
  const reallyMePackageSources = new Map();
  for (const pkg of graph.packages) {
    if (typeof pkg?.name !== "string" || typeof pkg.version !== "string" ||
        typeof pkg.id !== "string") {
      fail(`invalid package metadata for ${manifest}`);
    }
    if (!localMembers.has(pkg.id) && pkg.source !== CRATES_IO_SOURCE) {
      fail(`${manifest} resolves external package ${pkg.name} outside crates.io`);
    }
    if (!pkg.name.startsWith("reallyme-")) {
      continue;
    }
    const identity = `${pkg.name}@${pkg.version}`;
    const previous = reallyMePackageSources.get(identity);
    if (previous !== undefined && previous !== pkg.id) {
      fail(`${manifest} resolves a ReallyMe dependency from multiple sources: ${identity}`);
    }
    reallyMePackageSources.set(identity, pkg.id);
  }
};

const workspace = readLockedGraph("Cargo.toml");
const fuzz = readLockedGraph("fuzz/Cargo.toml");
assertRegistryGraph(workspace, new Set(workspace.workspace_members), "Cargo.toml");
// Fuzzing exercises the local Wallet crates through its separate workspace.
assertRegistryGraph(
  fuzz,
  new Set([...workspace.workspace_members, ...fuzz.workspace_members]),
  "fuzz/Cargo.toml",
);

const names = new Set();
const manifests = new Set();
for (const entry of packages) {
  if (
    entry === null
    || typeof entry !== "object"
    || Array.isArray(entry)
    || typeof entry.name !== "string"
    || !PACKAGE_NAME.test(entry.name)
    || typeof entry.manifest !== "string"
    || entry.manifest.length === 0
    || entry.publish !== true
    || names.has(entry.name)
    || manifests.has(entry.manifest)
  ) {
    fail("intended Rust package declaration is invalid");
  }
  names.add(entry.name);
  manifests.add(entry.manifest);

  for (const licenseName of ["LICENSE-MIT", "LICENSE-APACHE"]) {
    let crateLicense;
    try {
      crateLicense = readFileSync(resolve(root, entry.manifest, "..", licenseName));
    } catch {
      fail(`${entry.name} omits ${licenseName}`);
    }
    if (!crateLicense.equals(readFileSync(resolve(root, licenseName)))) {
      fail(`${entry.name} has a mismatched ${licenseName}`);
    }
  }

  const packaged = spawnSync(
    "cargo",
    ["package", "--locked", "--list", "--allow-dirty", "-p", entry.name],
    {
      cwd: root,
      encoding: "utf8",
      maxBuffer: MAX_CARGO_OUTPUT_BYTES,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  if (packaged.status !== 0 || packaged.error !== undefined) {
    fail(`cargo rejected ${entry.name}`);
  }

  const paths = packaged.stdout
    .split(/\r?\n/u)
    .map((path) => path.trim())
    .filter((path) => path.length > 0);
  const uniquePaths = new Set(paths);
  if (
    paths.length === 0
    || uniquePaths.size !== paths.length
    || !uniquePaths.has("Cargo.toml")
    || !uniquePaths.has("Cargo.toml.orig")
    || !uniquePaths.has("Cargo.lock")
    || !uniquePaths.has("src/lib.rs")
    || !uniquePaths.has("LICENSE-MIT")
    || !uniquePaths.has("LICENSE-APACHE")
  ) {
    fail(`${entry.name} has an incomplete or ambiguous package surface`);
  }
  if (
    entry.name === "reallyme-wallet-proto"
    && ![
      "proto/reallyme/wallet/v1/errors.proto",
      "proto/reallyme/wallet/v1/wallet.proto",
      "proto/reallyme/wallet/v1/wallet_operation.proto",
      "proto/reallyme/wallet/v1/wallet_provider.proto",
      "proto/reallyme/wallet/v1/wallet_service.proto",
    ].every((path) => uniquePaths.has(path))
  ) {
    fail("reallyme-wallet-proto package omits canonical schema sources");
  }
  if (
    entry.name === "reallyme-wallet-proto"
    && ![
      "baselines/README.md",
      "baselines/manifest.json",
      "baselines/wallet-v1.binpb",
    ].every((path) => uniquePaths.has(path))
  ) {
    fail("reallyme-wallet-proto package omits its compatibility baseline");
  }
  if (
    entry.name === "reallyme-wallet-proto"
    && ![
      "tests/fixtures/wallet-operation-v1-golden.json",
      "tests/fixtures/wallet-provider-v1-golden.txt",
      "tests/fixtures/protojson/get-credential-request.json",
      "tests/fixtures/protojson/delete-credential-success-response.json",
      "tests/fixtures/protojson/malicious-duplicate-operation.json",
      "tests/fixtures/protojson/malicious-unknown-field.json",
      "tests/fixtures/protojson/malicious-unknown-enum.json",
      "tests/fixtures/protojson/malicious-wrong-shape.json",
    ].every((path) => uniquePaths.has(path))
  ) {
    fail("reallyme-wallet-proto package omits contract fixtures");
  }
  if (entry.name === "reallyme-wallet-proto-codec") {
    const requiredTests = [
      "tests/boundary_tests.rs",
      "tests/protojson_fixture_tests.rs",
      "tests/key_storage_codec_tests.rs",
      "tests/operation_golden_tests.rs",
      "tests/provider_operation_golden_tests.rs",
    ];
    if (!requiredTests.every((path) => uniquePaths.has(path))) {
      fail("reallyme-wallet-proto-codec package omits boundary tests");
    }
    const fixturePrefixes = [
      ["tests/fixtures/proto/", "crates/proto/tests/fixtures/"],
      ["tests/fixtures/fuzz/", "fuzz/corpus/wallet_proto_json/"],
    ];
    for (const [packagedPrefix, sourcePrefix] of fixturePrefixes) {
      const fixturePaths = paths.filter((path) => path.startsWith(packagedPrefix));
      if (fixturePaths.length === 0) {
        fail(`reallyme-wallet-proto-codec package omits ${packagedPrefix}`);
      }
      for (const fixturePath of fixturePaths) {
        const sourcePath = `${sourcePrefix}${fixturePath.slice(packagedPrefix.length)}`;
        let sourceBytes;
        try {
          sourceBytes = readFileSync(resolve(root, sourcePath));
        } catch {
          fail(`reallyme-wallet-proto-codec has an orphaned ${fixturePath}`);
        }
        if (!sourceBytes.equals(readFileSync(resolve(root, "crates/proto-codec", fixturePath)))) {
          fail(`reallyme-wallet-proto-codec fixture drift: ${fixturePath}`);
        }
      }
    }
  }

  for (const path of paths) {
    const segments = path.split("/");
    if (
      path.startsWith("/")
      || path.includes("\\")
      || segments.includes("")
      || segments.includes(".")
      || segments.includes("..")
      || segments.includes(".git")
      || segments.includes("target")
      || segments.some((segment) => segment === ".env" || segment.startsWith(".env."))
    ) {
      fail(`${entry.name} contains a forbidden package path`);
    }
  }
}

process.stdout.write(`Validated ${packages.length} intended Rust package surfaces\n`);
