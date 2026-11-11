// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved

// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MODE_INSPECT = "inspect";
const MODE_ORDER = "order";
const MODE_PUBLISH = "publish";
const MAX_PUBLISH_ATTEMPTS = 12;
const CRATES_IO_DEFAULT_RATE_LIMIT_RETRY_MS = 60000;
const CRATES_IO_INDEX_RETRY_BASE_MS = 15000;
const policyPath = fileURLToPath(
  new URL("../conformance/features/wallet-package-policy-v1.json", import.meta.url),
);
let releasePolicy;
try {
  releasePolicy = JSON.parse(fs.readFileSync(policyPath, "utf8"));
} catch {
  console.error("the approved Wallet package policy could not be read");
  process.exit(1);
}
if (
  releasePolicy?.policy_id !== "reallyme.wallet.package-policy.v1"
  || typeof releasePolicy.release_version !== "string"
  || !Array.isArray(releasePolicy.authorized_public_packages)
  || !Array.isArray(releasePolicy.intended_rust_release_order)
) {
  console.error("the approved Wallet package policy is invalid");
  process.exit(1);
}
const APPROVED_RELEASE_VERSION = releasePolicy.release_version;
const APPROVED_PUBLIC_PACKAGES = new Set(releasePolicy.authorized_public_packages);
const APPROVED_PUBLISH_ORDER = releasePolicy.intended_rust_release_order.flatMap((stage) => {
  if (!Array.isArray(stage)) {
    console.error("the approved Wallet publish order contains an invalid stage");
    process.exit(1);
  }
  return stage;
});
if (
  APPROVED_PUBLIC_PACKAGES.size !== releasePolicy.authorized_public_packages.length
  || APPROVED_PUBLISH_ORDER.length !== APPROVED_PUBLIC_PACKAGES.size
  || new Set(APPROVED_PUBLISH_ORDER).size !== APPROVED_PUBLISH_ORDER.length
  || APPROVED_PUBLISH_ORDER.some((name) => !APPROVED_PUBLIC_PACKAGES.has(name))
) {
  console.error("the approved Wallet package set and publish order differ");
  process.exit(1);
}
const args = process.argv.slice(2);
const mode = args[0] ?? MODE_INSPECT;
const allowDirty = args.includes("--allow-dirty");
const unknownArgs = args.slice(1).filter((arg) => arg !== "--allow-dirty");
const releaseVersion = process.env.RELEASE_VERSION ?? "";
const releaseSha = process.env.RELEASE_SHA ?? "";
const releaseAttestationPath = process.env.RELEASE_ATTESTATION_PATH ?? "";
const reviewedCrateDirectory = process.env.REVIEWED_CRATE_DIRECTORY ?? "";
const publicationLedgerPath = process.env.PUBLICATION_LEDGER_PATH ?? "";
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;

if (
  (mode !== MODE_INSPECT && mode !== MODE_ORDER && mode !== MODE_PUBLISH) ||
  unknownArgs.length !== 0
) {
  console.error(
    `usage: node scripts/publish_crates_in_order.mjs ${MODE_INSPECT}|${MODE_ORDER}|${MODE_PUBLISH} [--allow-dirty]`,
  );
  process.exit(2);
}

if (allowDirty && mode !== MODE_INSPECT && mode !== MODE_ORDER) {
  console.error("--allow-dirty is only supported for local package inspection and order checks");
  process.exit(2);
}

if (mode === MODE_PUBLISH && releaseVersion.length === 0) {
  console.error("RELEASE_VERSION must be set when publishing crates.");
  process.exit(2);
}
if (mode === MODE_PUBLISH && releaseAttestationPath.length === 0) {
  console.error("RELEASE_ATTESTATION_PATH must be set when publishing crates.");
  process.exit(2);
}
if (mode === MODE_PUBLISH && reviewedCrateDirectory.length === 0) {
  console.error("REVIEWED_CRATE_DIRECTORY must identify the preflight crate archives.");
  process.exit(2);
}
if (
  mode === MODE_PUBLISH &&
  publicationLedgerPath.length !== 0 &&
  !/^[0-9a-f]{40}$/u.test(releaseSha)
) {
  console.error("RELEASE_SHA must be an exact Git commit when recording publication state.");
  process.exit(2);
}

if (releaseVersion.length !== 0 && !/^[0-9]+[.][0-9]+[.][0-9]+$/u.test(releaseVersion)) {
  console.error("RELEASE_VERSION must be an exact semver release such as 0.1.0.");
  process.exit(2);
}
if (releaseVersion.length !== 0 && releaseVersion !== APPROVED_RELEASE_VERSION) {
  console.error(`RELEASE_VERSION must equal the approved ${APPROVED_RELEASE_VERSION} release.`);
  process.exit(2);
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    stdio: options.capture ? "pipe" : "inherit",
  });
  if (result.error) {
    throw result.error;
  }
  return result;
}

function sleepMs(delayMs) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, delayMs);
}

function retryAfterMs(output) {
  const match = /try again after ([^\n.]+ GMT)/i.exec(output);
  if (!match) {
    return null;
  }

  const retryAt = Date.parse(match[1]);
  if (!Number.isFinite(retryAt)) {
    return null;
  }

  const delayMs = retryAt - Date.now() + 10000;
  return Math.max(delayMs, 10000);
}

const metadataResult = run(
  "cargo",
  ["metadata", "--locked", "--format-version", "1", "--no-deps"],
  {
    capture: true,
  },
);

if (metadataResult.status !== 0) {
  process.stderr.write(metadataResult.stderr);
  process.exit(metadataResult.status ?? 1);
}

const metadata = JSON.parse(metadataResult.stdout);
const packageDirectory = path.join(metadata.target_directory, "package");

function loadAttestedPackageHashes() {
  if (mode !== MODE_PUBLISH) {
    return new Map();
  }
  let document;
  try {
    document = JSON.parse(fs.readFileSync(releaseAttestationPath, "utf8"));
  } catch {
    console.error("reviewed package attestation could not be read");
    process.exit(1);
  }
  if (
    document?.schema !== "reallyme.wallet.crates_preflight.v3" ||
    document.release_sha !== process.env.RELEASE_SHA ||
    document.version !== releaseVersion ||
    !Array.isArray(document.crates)
  ) {
    console.error("reviewed package attestation does not match this release");
    process.exit(1);
  }
  const hashes = new Map();
  for (const crate of document.crates) {
    const suffix = `-${releaseVersion}.crate`;
    if (
      typeof crate?.file !== "string" ||
      !crate.file.endsWith(suffix) ||
      typeof crate.sha256 !== "string" ||
      !SHA256_PATTERN.test(crate.sha256)
    ) {
      console.error("reviewed package attestation contains an invalid package entry");
      process.exit(1);
    }
    const name = crate.file.slice(0, -suffix.length);
    if (name.length === 0 || hashes.has(name)) {
      console.error("reviewed package attestation contains an invalid package entry");
      process.exit(1);
    }
    hashes.set(name, crate.sha256);
  }
  return hashes;
}

const attestedPackageHashes = loadAttestedPackageHashes();

function isPublishablePackage(pkg) {
  return !(Array.isArray(pkg.publish) && pkg.publish.length === 0);
}

const publishable = new Map();
for (const pkg of metadata.packages) {
  if (isPublishablePackage(pkg)) {
    publishable.set(pkg.name, pkg);
  }
}

const unexpectedPublicPackages = [...publishable.keys()].filter(
  (name) => !APPROVED_PUBLIC_PACKAGES.has(name),
);
const missingPublicPackages = [...APPROVED_PUBLIC_PACKAGES].filter(
  (name) => !publishable.has(name),
);
if (unexpectedPublicPackages.length !== 0 || missingPublicPackages.length !== 0) {
  console.error("publishable package set differs from the approved release policy");
  for (const name of unexpectedPublicPackages.sort()) {
    console.error(`- unexpected public package: ${name}`);
  }
  for (const name of missingPublicPackages.sort()) {
    console.error(`- missing public package: ${name}`);
  }
  process.exit(1);
}

function dependencyPackageName(dep) {
  return dep.package ?? dep.name;
}

function isWorkspacePathDependency(dep) {
  return (
    dep.source === null &&
    typeof dep.path === "string" &&
    publishable.has(dependencyPackageName(dep))
  );
}

function isPublishOrderingDependency(dep) {
  // crates.io resolves normalized dev-dependencies while validating an upload,
  // so public path-based test dependencies must be available first as well.
  return isWorkspacePathDependency(dep);
}

function parseVersion(version) {
  const parts = version.split(".");
  if (!/^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u.test(version)) {
    return null;
  }

  const parsed = parts.map((part) => Number.parseInt(part, 10));
  if (parsed.some((part) => !Number.isSafeInteger(part) || part < 0)) {
    return null;
  }

  return {
    major: parsed[0],
    minor: parsed[1],
    patch: parsed[2],
  };
}

function isCaretReqSatisfied(req, version) {
  if (!req.startsWith("^")) {
    return req === `=${version}` || req === version;
  }

  const minimum = parseVersion(req.slice(1));
  const actual = parseVersion(version);
  if (minimum === null || actual === null) {
    return false;
  }

  if (actual.major !== minimum.major) {
    return false;
  }

  if (minimum.major === 0 && actual.minor !== minimum.minor) {
    return false;
  }

  // Cargo keeps ^0.0.x within that exact patch release.
  if (minimum.major === 0 && minimum.minor === 0 && actual.patch !== minimum.patch) {
    return false;
  }

  if (actual.minor < minimum.minor) {
    return false;
  }

  if (actual.minor === minimum.minor && actual.patch < minimum.patch) {
    return false;
  }

  return true;
}

function checkPathDependencyVersions() {
  const failures = [];
  for (const pkg of publishable.values()) {
    for (const dep of pkg.dependencies) {
      if (!isPublishOrderingDependency(dep)) {
        continue;
      }

      const target = publishable.get(dependencyPackageName(dep));
      if (!isCaretReqSatisfied(dep.req, target.version)) {
        failures.push(
          `${pkg.name} depends on ${dep.name} with ${dep.req}; local version is ${target.version}`,
        );
      }
    }
  }

  if (failures.length !== 0) {
    console.error("publishable workspace path dependency versions are stale:");
    for (const failure of failures) {
      console.error(`- ${failure}`);
    }
    process.exit(1);
  }
}

function checkReleaseVersion() {
  const failures = [];
  for (const pkg of publishable.values()) {
    if (pkg.version !== APPROVED_RELEASE_VERSION) {
      failures.push(`${pkg.name} is ${pkg.version}; expected ${APPROVED_RELEASE_VERSION}`);
    }
  }
  if (failures.length !== 0) {
    console.error("publishable crate versions do not match the approved release policy:");
    for (const failure of failures) {
      console.error(`- ${failure}`);
    }
    process.exit(1);
  }
}

const ordered = APPROVED_PUBLISH_ORDER.map((name) => publishable.get(name));

console.log(`Publish order (${ordered.length} crates):`);
for (const pkg of ordered) {
  console.log(`- ${pkg.name} ${pkg.version}`);
}

function checkRequiredPublishOrderEdges() {
  const failures = [];
  for (const pkg of ordered) {
    for (const dep of pkg.dependencies) {
      if (!isPublishOrderingDependency(dep)) {
        continue;
      }
      const dependencyName = dependencyPackageName(dep);
      if (orderedIndexByName.get(dependencyName) >= orderedIndexByName.get(pkg.name)) {
        failures.push(`${dependencyName} must publish before ${pkg.name}`);
      }
    }
  }

  if (failures.length !== 0) {
    console.error(
      `approved publish order: ${APPROVED_PUBLISH_ORDER.join(", ")}`,
    );
    console.error("required publish dependency order is not satisfied:");
    for (const failure of failures) {
      console.error(`- ${failure}`);
    }
    process.exit(1);
  }
}

const orderedIndexByName = new Map();
ordered.forEach((pkg, index) => {
  orderedIndexByName.set(pkg.name, index);
});

checkPathDependencyVersions();
checkRequiredPublishOrderEdges();
checkReleaseVersion();

if (mode === MODE_ORDER) {
  process.exit(0);
}

const unpackDirectory = path.join(packageDirectory, "release-preflight");

function packageApprovedWorkspace() {
  // This workspace intentionally contains source-only implementation crates.
  // Package the reviewed set as one workspace operation so Cargo can normalize
  // dependencies whose earlier versions do not exist in the registry yet.
  // Explicit exclusions prevent source-only members from becoming release
  // inputs or blocking package construction.
  const packageArgs = ["package", "--workspace", "--no-verify", "--locked"];
  for (const pkg of metadata.packages) {
    if (!publishable.has(pkg.name)) {
      packageArgs.push("--exclude", pkg.name);
    }
  }
  if (allowDirty) {
    packageArgs.push("--allow-dirty");
  }
  const packageResult = run("cargo", packageArgs);
  if (packageResult.status !== 0) {
    process.exit(packageResult.status ?? 1);
  }
}

if (mode === MODE_INSPECT) {
  packageApprovedWorkspace();

  fs.rmSync(unpackDirectory, { force: true, recursive: true });
  fs.mkdirSync(unpackDirectory, { recursive: true });
  for (const pkg of ordered) {
    const archive = path.join(packageDirectory, `${pkg.name}-${pkg.version}.crate`);
    const extractResult = run("tar", ["-xzf", archive, "-C", unpackDirectory]);
    if (extractResult.status !== 0) {
      process.exit(extractResult.status ?? 1);
    }
  }
}

function unresolvedRegistryPackages(output) {
  const missing = [];
  const noMatchPattern = /no matching package named `([^`]+)` found/g;
  for (let match = noMatchPattern.exec(output); match !== null; match = noMatchPattern.exec(output)) {
    missing.push(match[1]);
  }

  const versionSelectPattern = /failed to select a version for the requirement `([^`\s]+) =/g;
  for (
    let match = versionSelectPattern.exec(output);
    match !== null;
    match = versionSelectPattern.exec(output)
  ) {
    missing.push(match[1]);
  }

  return [...new Set(missing)];
}

function isEarlierWorkspaceDependency(pkg, depName) {
  const pkgIndex = orderedIndexByName.get(pkg.name);
  const depIndex = orderedIndexByName.get(depName);
  return depIndex !== undefined && pkgIndex !== undefined && depIndex < pkgIndex;
}

function inspectPackage(pkg) {
  const listArgs = ["package", "-p", pkg.name, "--list", "--locked"];
  if (allowDirty) {
    listArgs.push("--allow-dirty");
  }
  const listResult = run("cargo", listArgs);
  if (listResult.status !== 0) {
    process.exit(listResult.status ?? 1);
  }

  const manifestPath = path.join(unpackDirectory, `${pkg.name}-${pkg.version}`, "Cargo.toml");
  const patchArgs = [];
  for (const dependency of ordered) {
    if (!isEarlierWorkspaceDependency(pkg, dependency.name)) {
      continue;
    }
    const dependencyPath = path.join(unpackDirectory, `${dependency.name}-${dependency.version}`);
    patchArgs.push(
      "--config",
      `patch.crates-io.'${dependency.name}'.path=${JSON.stringify(dependencyPath)}`,
    );
  }

  // Fetch the normalized archive's locked dependency graph explicitly before
  // enforcing an offline build. This proves each packaged crate builds from
  // its published shape, not only from the workspace path dependency graph.
  const fetchArgs = ["fetch", "--manifest-path", manifestPath, ...patchArgs];
  if (patchArgs.length === 0) {
    fetchArgs.push("--locked");
  }
  const fetchResult = run("cargo", fetchArgs);
  if (fetchResult.status !== 0) {
    process.exit(fetchResult.status ?? 1);
  }

  const checkArgs = [
    "check",
    "--manifest-path",
    manifestPath,
    "--all-features",
    "--locked",
    "--offline",
    ...patchArgs,
  ];
  const checkResult = run("cargo", checkArgs);
  if (checkResult.status !== 0) {
    process.exit(checkResult.status ?? 1);
  }

  if (pkg.name === "reallyme-wallet-proto-codec") {
    // This crate's contract tests use packaged fixture copies. Execute them
    // from the extracted archive so source-tree tests cannot mask omissions.
    const testResult = run("cargo", [
      "test",
      "--manifest-path",
      manifestPath,
      "--all-features",
      "--tests",
      "--locked",
      "--offline",
      ...patchArgs,
    ]);
    if (testResult.status !== 0) {
      process.exit(testResult.status ?? 1);
    }
  }

  const dryRunArgs = ["publish", "-p", pkg.name, "--dry-run", "--locked"];
  if (allowDirty) {
    dryRunArgs.push("--allow-dirty");
  }
  const dryRunResult = run("cargo", dryRunArgs, { capture: true });
  process.stdout.write(dryRunResult.stdout);
  process.stderr.write(dryRunResult.stderr);
  if (dryRunResult.status === 0) {
    return;
  }

  const combined = `${dryRunResult.stdout}\n${dryRunResult.stderr}`;
  const missing = unresolvedRegistryPackages(combined);
  if (
    missing.length !== 0 &&
    missing.every((depName) => isEarlierWorkspaceDependency(pkg, depName))
  ) {
    console.log(
      `${pkg.name} dry-run reached unpublished ordered workspace dependencies: ${missing.join(", ")}`,
    );
    return;
  }

  process.exit(dryRunResult.status ?? 1);
}

function preparePackage(pkg) {
  const localArchive = path.join(packageDirectory, `${pkg.name}-${pkg.version}.crate`);
  if (!fs.existsSync(localArchive)) {
    console.error(`${pkg.name} ${pkg.version} archive is missing from the workspace package set`);
    process.exit(1);
  }
  const localHash = createHash("sha256").update(fs.readFileSync(localArchive)).digest("hex");
  if (attestedPackageHashes.get(pkg.name) !== localHash) {
    console.error(`${pkg.name} ${pkg.version} archive differs from reviewed preflight bytes`);
    process.exit(1);
  }
  const reviewedArchive = path.resolve(
    reviewedCrateDirectory,
    `${pkg.name}-${pkg.version}.crate`,
  );
  if (!fs.existsSync(reviewedArchive)) {
    console.error(`${pkg.name} ${pkg.version} reviewed archive is missing`);
    process.exit(1);
  }
  const reviewedHash = createHash("sha256")
    .update(fs.readFileSync(reviewedArchive))
    .digest("hex");
  if (reviewedHash !== localHash) {
    console.error(`${pkg.name} ${pkg.version} archive differs from downloaded reviewed bytes`);
    process.exit(1);
  }
}

function prepareAllPackages() {
  if (attestedPackageHashes.size !== ordered.length) {
    console.error("reviewed package attestation does not cover the complete release graph");
    process.exit(1);
  }
  packageApprovedWorkspace();
  for (const pkg of ordered) {
    preparePackage(pkg);
  }
}

function publishPackage(pkg) {

  // Preflight already built and tested this exact archive. Skipping Cargo's
  // second build ensures build scripts never inherit the registry credential.
  const args = ["publish", "-p", pkg.name, "--locked", "--no-verify"];

  for (let attempt = 1; attempt <= MAX_PUBLISH_ATTEMPTS; attempt += 1) {
    const result = run("cargo", args, { capture: true });
    process.stdout.write(result.stdout);
    process.stderr.write(result.stderr);

    if (result.status === 0) {
      verifyPublishedPackageMatches(pkg);
      return "published";
    }

    const combined = `${result.stdout}\n${result.stderr}`;
    if (combined.includes("already uploaded") || combined.includes("already exists")) {
      verifyPublishedPackageMatches(pkg);
      console.log(`${pkg.name} ${pkg.version} is already published; continuing.`);
      return "verified_existing";
    }

    const lowerCombined = combined.toLowerCase();
    const rateLimitDelayMs = retryAfterMs(combined);
    if (
      lowerCombined.includes("too many requests") ||
      lowerCombined.includes("rate-limited") ||
      lowerCombined.includes("rate limited")
    ) {
      // Exhaustion must fail the release before attempting dependent crates.
      if (attempt === MAX_PUBLISH_ATTEMPTS) {
        console.error(`publication retry limit reached for ${pkg.name}`);
        process.exit(result.status ?? 1);
      }
      const delayMs = rateLimitDelayMs ?? CRATES_IO_DEFAULT_RATE_LIMIT_RETRY_MS;
      console.log(
        `crates.io rate-limited new crate uploads; retrying ${pkg.name} in ${Math.ceil(delayMs / 1000)}s...`,
      );
      sleepMs(delayMs);
      continue;
    }

    if (!combined.includes("no matching package named") || attempt === MAX_PUBLISH_ATTEMPTS) {
      process.exit(result.status ?? 1);
    }

    const delayMs = attempt * CRATES_IO_INDEX_RETRY_BASE_MS;
    console.log(
      `crates.io index has not observed a freshly published dependency yet; retrying ${pkg.name} in ${delayMs / 1000}s...`,
    );
    sleepMs(delayMs);
  }
}

const publicationLedger = {
  schema: "reallyme.wallet.crates-publication-ledger.v1",
  repository: "reallyme/wallet",
  source_commit: releaseSha,
  release_version: releaseVersion,
  state: "not_started",
  crates: ordered.map((pkg, publishOrder) => ({
    name: pkg.name,
    version: pkg.version,
    publish_order: publishOrder,
    state: "pending",
    archive_sha256: null,
  })),
};

function writePublicationLedger() {
  if (mode !== MODE_PUBLISH || publicationLedgerPath.length === 0) return;
  fs.mkdirSync(path.dirname(publicationLedgerPath), { recursive: true });
  const temporaryPath = `${publicationLedgerPath}.tmp`;
  fs.writeFileSync(temporaryPath, `${JSON.stringify(publicationLedger, null, 2)}\n`, {
    mode: 0o600,
  });
  fs.renameSync(temporaryPath, publicationLedgerPath);
}

function verifyPublishedPackageMatches(pkg) {
  const localArchive = path.join(packageDirectory, `${pkg.name}-${pkg.version}.crate`);
  if (!fs.existsSync(localArchive)) {
    console.error(`${pkg.name} ${pkg.version} local package archive is missing`);
    process.exit(1);
  }

  const comparisonDirectory = fs.mkdtempSync(path.join(packageDirectory, "published-"));
  const publishedArchive = path.join(comparisonDirectory, `${pkg.name}-${pkg.version}.crate`);
  const packageName = encodeURIComponent(pkg.name);
  const packageVersion = encodeURIComponent(pkg.version);
  const downloadUrl =
    `https://static.crates.io/crates/${packageName}/${packageName}-${packageVersion}.crate`;

  try {
    const downloadResult = run(
      "curl",
      [
        "--fail-with-body",
        "--location",
        "--proto",
        "=https",
        "--tlsv1.2",
        "--retry",
        "5",
        "--retry-all-errors",
        "--output",
        publishedArchive,
        downloadUrl,
      ],
      { capture: true },
    );
    if (downloadResult.status !== 0) {
      process.stdout.write(downloadResult.stdout);
      process.stderr.write(downloadResult.stderr);
      process.exit(downloadResult.status ?? 1);
    }

    const localChecksum = createHash("sha256").update(fs.readFileSync(localArchive)).digest("hex");
    const publishedChecksum = createHash("sha256")
      .update(fs.readFileSync(publishedArchive))
      .digest("hex");
    if (localChecksum !== publishedChecksum) {
      console.error(
        `${pkg.name} ${pkg.version} is already published from different source bytes`,
      );
      process.exit(1);
    }
  } finally {
    fs.rmSync(comparisonDirectory, { force: true, recursive: true });
  }
}

if (mode === MODE_PUBLISH) {
  // Rebuild and compare every archive before uploading the first crate. A
  // late mismatch must not leave an immutable prefix of the release graph
  // published while the remaining crates are rejected.
  prepareAllPackages();
  publicationLedger.state = "in_progress";
  writePublicationLedger();
}

for (const pkg of ordered) {
  if (mode === MODE_INSPECT) {
    inspectPackage(pkg);
    continue;
  }

  const ledgerEntry = publicationLedger.crates.find((entry) => entry.name === pkg.name);
  if (ledgerEntry !== undefined) {
    ledgerEntry.state = "attempting";
    writePublicationLedger();
  }
  const publishState = publishPackage(pkg);
  if (ledgerEntry !== undefined) {
    ledgerEntry.state = publishState;
    ledgerEntry.archive_sha256 = attestedPackageHashes.get(pkg.name) ?? null;
    writePublicationLedger();
  }
}

if (mode === MODE_PUBLISH) {
  publicationLedger.state = "completed";
  writePublicationLedger();
}
