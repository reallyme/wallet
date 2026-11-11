#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const policyPath = resolve(root, "conformance/features/wallet-package-policy-v1.json");
const mode = process.argv[2] ?? "--validate";
const supportedModes = new Set(["--validate", "--check-msrv", "--check-wasm"]);

if (process.argv.length > 3 || !supportedModes.has(mode)) {
  process.stderr.write(
    "usage: node scripts/check_rust_release_policy.mjs [--check-msrv|--check-wasm]\n",
  );
  process.exit(2);
}

const fail = (reason) => {
  process.stderr.write(`public crate toolchain policy check failed: ${reason}\n`);
  process.exit(1);
};

const run = (command, arguments_, options = {}) => {
  const result = spawnSync(command, arguments_, {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    stdio: options.capture === false ? "inherit" : ["ignore", "pipe", "pipe"],
  });
  if (result.error !== undefined || result.status !== 0) {
    if (options.capture !== false) {
      process.stdout.write(result.stdout ?? "");
      process.stderr.write(result.stderr ?? "");
    }
    fail(options.reason ?? `${command} failed`);
  }
  return result.stdout ?? "";
};

let policy;
try {
  policy = JSON.parse(readFileSync(policyPath, "utf8"));
} catch {
  fail("package policy is unavailable or invalid JSON");
}

if (
  policy?.schema_version !== 1
  || policy.policy_id !== "reallyme.wallet.package-policy.v1"
  || policy.release_version !== "0.1.0"
  || policy.maintainer_rust_toolchain !== "1.99.0"
  || policy.public_crate_msrv !== "1.99"
  || !Array.isArray(policy.authorized_public_packages)
  || !Array.isArray(policy.intended_rust_release_order)
  || !Array.isArray(policy.identity_composed_wasm_packages)
  || !Array.isArray(policy.workspace_packages)
) {
  fail("package policy has an invalid toolchain or release contract");
}

const requireUniqueStrings = (values, context) => {
  if (
    values.length === 0
    || values.some((value) => typeof value !== "string" || value.length === 0)
    || new Set(values).size !== values.length
  ) {
    fail(`${context} must contain unique non-empty strings`);
  }
};

requireUniqueStrings(policy.authorized_public_packages, "authorized public packages");
requireUniqueStrings(policy.identity_composed_wasm_packages, "Identity Wasm packages");

const releaseOrder = policy.intended_rust_release_order.flatMap((stage) => {
  if (!Array.isArray(stage)) {
    fail("release order contains a non-array stage");
  }
  requireUniqueStrings(stage, "release order stage");
  return stage;
});
const authorizedSorted = [...policy.authorized_public_packages].sort();
const releaseOrderSorted = [...releaseOrder].sort();
if (
  releaseOrderSorted.length !== authorizedSorted.length
  || releaseOrderSorted.some((name, index) => name !== authorizedSorted[index])
) {
  fail("release order must enumerate the authorized public package set exactly once");
}

const toolchain = readFileSync(resolve(root, "rust-toolchain.toml"), "utf8");
for (const required of [
  'channel = "1.99.0"',
  'components = ["clippy", "rustfmt"]',
  'targets = ["wasm32-unknown-unknown"]',
  'profile = "minimal"',
]) {
  if (!toolchain.includes(required)) {
    fail(`rust-toolchain.toml is missing ${required}`);
  }
}

const metadataText = run(
  "cargo",
  ["metadata", "--locked", "--format-version", "1", "--no-deps"],
  { reason: "Cargo rejected the locked workspace metadata" },
);
let metadata;
try {
  metadata = JSON.parse(metadataText);
} catch {
  fail("Cargo returned invalid workspace metadata");
}

const workspaceMemberIds = new Set(metadata.workspace_members ?? []);
const workspacePackages = (metadata.packages ?? []).filter((pkg) =>
  workspaceMemberIds.has(pkg.id)
);
const packagesByName = new Map(workspacePackages.map((pkg) => [pkg.name, pkg]));
if (
  packagesByName.size !== workspacePackages.length
  || packagesByName.size !== policy.workspace_packages.length
) {
  fail("workspace package inventory differs from package policy");
}

const declaredNames = new Set();
for (const entry of policy.workspace_packages) {
  if (
    entry === null
    || typeof entry !== "object"
    || typeof entry.name !== "string"
    || typeof entry.manifest !== "string"
    || typeof entry.classification !== "string"
    || typeof entry.publish !== "boolean"
    || declaredNames.has(entry.name)
  ) {
    fail("workspace package declaration is invalid");
  }
  declaredNames.add(entry.name);
  const pkg = packagesByName.get(entry.name);
  if (pkg === undefined) {
    fail(`workspace package is missing: ${entry.name}`);
  }
  const manifest = resolve(pkg.manifest_path);
  if (manifest !== resolve(root, entry.manifest)) {
    fail(`workspace manifest path drifted: ${entry.name}`);
  }
  const publishable = !(Array.isArray(pkg.publish) && pkg.publish.length === 0);
  if (publishable !== entry.publish) {
    fail(`publish setting drifted: ${entry.name}`);
  }
  if (entry.publish) {
    if (
      entry.classification !== "intended_rust_release"
      || pkg.version !== policy.release_version
      || pkg.rust_version !== policy.public_crate_msrv
    ) {
      fail(`public crate release or MSRV metadata drifted: ${entry.name}`);
    }
  } else if (entry.classification === "intended_rust_release") {
    fail(`private crate is classified for publication: ${entry.name}`);
  }
}

const actualPublicNames = workspacePackages
  .filter((pkg) => !(Array.isArray(pkg.publish) && pkg.publish.length === 0))
  .map((pkg) => pkg.name)
  .sort();
const expectedPublicNames = [...policy.authorized_public_packages].sort();
if (
  actualPublicNames.length !== expectedPublicNames.length
  || actualPublicNames.some((name, index) => name !== expectedPublicNames[index])
) {
  fail("Cargo publishable package set differs from the approved set");
}

const releasePosition = new Map(releaseOrder.map((name, index) => [name, index]));
for (const pkg of workspacePackages) {
  const packagePosition = releasePosition.get(pkg.name);
  if (packagePosition === undefined) continue;
  for (const dependency of pkg.dependencies ?? []) {
    const dependencyPosition = releasePosition.get(dependency.name);
    if (dependencyPosition !== undefined && dependencyPosition >= packagePosition) {
      fail(`release order places ${pkg.name} before its Wallet dependency ${dependency.name}`);
    }
  }
}

const actualWasmPackages = workspacePackages
  .filter((pkg) => Object.hasOwn(pkg.features ?? {}, "wasm"))
  .map((pkg) => pkg.name)
  .sort();
const expectedWasmPackages = [...policy.identity_composed_wasm_packages].sort();
if (
  actualWasmPackages.length !== expectedWasmPackages.length
  || actualWasmPackages.some((name, index) => name !== expectedWasmPackages[index])
) {
  fail("Wasm feature set differs from Identity's composed Wasm dependency set");
}

for (const pkg of workspacePackages) {
  if ((pkg.dependencies ?? []).some((dependency) => dependency.name === "wasm-bindgen")) {
    fail(`${pkg.name} must not depend on wasm-bindgen`);
  }
  for (const target of pkg.targets ?? []) {
    if ((target.crate_types ?? []).includes("cdylib")) {
      fail(`${pkg.name} must not publish a cdylib target`);
    }
  }
}

const tracked = run("git", ["ls-files", "-z"], {
  reason: "tracked repository files could not be enumerated",
})
  .split("\0")
  .filter((path) => path.length > 0);
for (const path of tracked) {
  if (
    path.endsWith(".wasm")
    || path === "package.json"
    || path.endsWith("/package.json")
    || path === "package-lock.json"
    || path.endsWith("/package-lock.json")
    || path === "pnpm-lock.yaml"
    || path.endsWith("/pnpm-lock.yaml")
    || path === "yarn.lock"
    || path.endsWith("/yarn.lock")
  ) {
    fail(`lower-level repository contains a standalone Wasm or npm artifact: ${path}`);
  }
}

if (mode === "--check-msrv") {
  const rustcVerbose = run("rustc", ["--version", "--verbose"], {
    reason: "MSRV rustc is unavailable",
  });
  if (!/^release: 1\.99\.0$/mu.test(rustcVerbose)) {
    fail("MSRV job must run with exactly Rust 1.99.0");
  }
  const checkArguments = ["check", "--locked", "--lib", "--all-features"];
  for (const name of policy.authorized_public_packages) {
    checkArguments.push("--package", name);
  }
  run("cargo", checkArguments, {
    capture: false,
    reason: "public crate set does not compile at the declared MSRV",
  });
}

if (mode === "--check-wasm") {
  const rustcVerbose = run("rustc", ["--version", "--verbose"], {
    reason: "maintainer rustc is unavailable",
  });
  if (!/^release: 1\.99\.0$/mu.test(rustcVerbose)) {
    fail("Wasm lane must run with exactly Rust 1.99.0");
  }
  const checkArguments = [
    "check",
    "--locked",
    "--no-default-features",
    "--features",
    "wasm",
    "--target",
    "wasm32-unknown-unknown",
  ];
  for (const name of policy.identity_composed_wasm_packages) {
    checkArguments.push("--package", name);
  }
  run("cargo", checkArguments, {
    capture: false,
    reason: "Identity's Wallet Wasm participant set does not compile",
  });
}

process.stdout.write(
  `Validated ${policy.authorized_public_packages.length} public crates at MSRV ${policy.public_crate_msrv}`
    + ` and ${policy.identity_composed_wasm_packages.length} Identity Wasm participants\n`,
);
