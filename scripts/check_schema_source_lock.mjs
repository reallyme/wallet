#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { createHash } from "node:crypto";
import { lstatSync, readFileSync, readdirSync } from "node:fs";
import { basename, dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

import { registryChecksumFromLock } from "./sibling_registry_provenance_core.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const protoRoot = resolve(root, "crates/proto/proto");
const lockPath = resolve(root, "crates/proto/proto-source-lock.json");
const baselineManifestPath = resolve(root, "crates/proto/baselines/manifest.json");
const sha256Pattern = /^[a-f0-9]{64}$/u;
const revisionPattern = /^[a-f0-9]{40}$/u;
const versionPattern = /^\d+\.\d+\.\d+$/u;
const registrySource = "registry+https://github.com/rust-lang/crates.io-index";
if (process.argv.length !== 2) {
  process.stderr.write("Usage: node scripts/check_schema_source_lock.mjs\n");
  process.exit(2);
}

const fail = (reason) => {
  process.stderr.write(`Wallet schema source lock check failed: ${reason}\n`);
  process.exit(1);
};

const isRecord = (value) =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const assertExactKeys = (record, expected, label) => {
  const actual = Object.keys(record).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail(`${label} has an unexpected shape`);
  }
};

const parseLock = () => {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(lockPath, "utf8"));
  } catch {
    fail("crates/proto/proto-source-lock.json is not valid JSON");
  }
  if (!isRecord(parsed)) {
    fail("the lock root must be an object");
  }
  assertExactKeys(parsed, ["schema_version", "sources"], "the lock root");
  if (parsed.schema_version !== 1 || !Array.isArray(parsed.sources)) {
    fail("the lock schema version or sources collection is invalid");
  }
  return parsed;
};

const collectProtoFiles = (directory, files) => {
  const entries = readdirSync(directory, { withFileTypes: true });
  for (const entry of entries) {
    const entryPath = resolve(directory, entry.name);
    if (entry.isSymbolicLink()) {
      fail("vendored schema inputs must not contain symbolic links");
    }
    if (entry.isDirectory()) {
      collectProtoFiles(entryPath, files);
    } else if (entry.isFile() && entry.name.endsWith(".proto")) {
      files.add(`proto/${relative(protoRoot, entryPath).split(sep).join("/")}`);
    }
  }
};

const lock = parseLock();
const cargoLockText = readFileSync(resolve(root, "Cargo.lock"), "utf8");
const metadataResult = spawnSync(
  "cargo", ["metadata", "--locked", "--offline", "--format-version", "1"],
  { cwd: root, encoding: "utf8", maxBuffer: 32 * 1024 * 1024 },
);
if (metadataResult.status !== 0) {
  fail("resolved Cargo package metadata is unavailable");
}
let resolvedPackages;
try {
  resolvedPackages = JSON.parse(metadataResult.stdout).packages ?? [];
} catch {
  fail("resolved Cargo package metadata is invalid");
}

const archiveMember = (archivePath, name) => {
  const extracted = spawnSync("tar", ["-xOzf", archivePath, name], {
    cwd: root,
    maxBuffer: 2 * 1024 * 1024,
    stdio: ["ignore", "pipe", "ignore"],
  });
  if (extracted.status !== 0 || !Buffer.isBuffer(extracted.stdout)) {
    fail(`registry crate member ${name} is unavailable`);
  }
  return extracted.stdout;
};

const verifyResolvedRegistrySource = (source) => {
  const matches = resolvedPackages.filter((pkg) =>
    pkg.name === source.crate_name && pkg.version === source.crate_version &&
    pkg.source === registrySource,
  );
  if (matches.length !== 1) {
    fail(`${source.name} is not the unique resolved registry crate`);
  }
  const pkg = matches[0];
  const lockChecksum = registryChecksumFromLock(
    cargoLockText, source.crate_name, source.crate_version,
  );
  if (lockChecksum !== source.crate_checksum) {
    fail(`${source.name} registry checksum differs from Cargo.lock`);
  }
  const crateRoot = dirname(pkg.manifest_path);
  const registryDirectory = basename(dirname(crateRoot));
  const archivePath = resolve(
    crateRoot, "..", "..", "..", "cache", registryDirectory,
    `${source.crate_name}-${source.crate_version}.crate`,
  );
  let archive;
  try {
    archive = readFileSync(archivePath);
  } catch {
    fail(`${source.name} resolved registry archive is unavailable`);
  }
  if (archive.length === 0 || archive.length > 32 * 1024 * 1024 ||
      createHash("sha256").update(archive).digest("hex") !== lockChecksum) {
    fail(`${source.name} resolved registry archive differs from Cargo.lock`);
  }
  const memberPrefix = `${source.crate_name}-${source.crate_version}/`;
  let vcs;
  try {
    vcs = JSON.parse(archiveMember(archivePath, `${memberPrefix}.cargo_vcs_info.json`).toString("utf8"));
  } catch {
    fail(`${source.name} registry VCS provenance is invalid`);
  }
  if (vcs?.git?.sha1 !== source.revision || vcs?.git?.dirty === true) {
    fail(`${source.name} registry VCS revision differs from the source lock`);
  }
  return { archivePath, memberPrefix };
};

const lockedFiles = new Set();
const sourceNames = new Set();

for (const [sourceIndex, source] of lock.sources.entries()) {
  const label = `sources[${sourceIndex}]`;
  if (!isRecord(source)) {
    fail(`${label} must be an object`);
  }
  assertExactKeys(
    source,
    ["name", "repository", "revision", "revision_state", "crate_name", "crate_version", "crate_checksum", "files"],
    label,
  );
  if (
    typeof source.name !== "string" ||
    source.name.length === 0 ||
    sourceNames.has(source.name)
  ) {
    fail(`${label} has an invalid or duplicate name`);
  }
  sourceNames.add(source.name);
  if (
    typeof source.repository !== "string" ||
    !source.repository.startsWith("https://github.com/reallyme/") ||
    !source.repository.endsWith(".git")
  ) {
    fail(`${label} has an invalid ReallyMe repository URL`);
  }
  if (typeof source.revision !== "string" || !revisionPattern.test(source.revision)) {
    fail(`${label} has an invalid Git revision`);
  }
  if (source.revision_state !== "clean_commit") {
    fail(`${label} has an invalid revision state`);
  }
  if (typeof source.crate_name !== "string" ||
      !/^reallyme-[a-z0-9-]+-proto$/u.test(source.crate_name) ||
      typeof source.crate_version !== "string" ||
      !versionPattern.test(source.crate_version) ||
      typeof source.crate_checksum !== "string" ||
      !sha256Pattern.test(source.crate_checksum)) {
    fail(`${label} has invalid resolved registry provenance`);
  }
  if (!Array.isArray(source.files) || source.files.length === 0) {
    fail(`${label} must lock at least one schema file`);
  }
  const registry = verifyResolvedRegistrySource(source);

  for (const [fileIndex, file] of source.files.entries()) {
    const fileLabel = `${label}.files[${fileIndex}]`;
    if (!isRecord(file)) {
      fail(`${fileLabel} must be an object`);
    }
    assertExactKeys(file, ["path", "sha256"], fileLabel);
    if (
      typeof file.path !== "string" ||
      !file.path.startsWith("proto/") ||
      !file.path.endsWith(".proto") ||
      file.path.includes("\\")
    ) {
      fail(`${fileLabel} has an invalid path`);
    }
    const localImportPath = file.path.slice("proto/".length);
    const absolutePath = resolve(protoRoot, localImportPath);
    const relativePath = relative(protoRoot, absolutePath);
    if (relativePath.startsWith(`..${sep}`) || relativePath === "..") {
      fail(`${fileLabel} escapes the repository root`);
    }
    if (lockedFiles.has(file.path)) {
      fail(`${fileLabel} duplicates another locked path`);
    }
    lockedFiles.add(file.path);
    if (lstatSync(absolutePath).isSymbolicLink()) {
      fail(`${file.path} must be a regular checked-in file`);
    }
    if (typeof file.sha256 !== "string" || !sha256Pattern.test(file.sha256)) {
      fail(`${fileLabel} has an invalid SHA-256 digest`);
    }
    const actualDigest = createHash("sha256").update(readFileSync(absolutePath)).digest("hex");
    if (actualDigest !== file.sha256) {
      fail(`${file.path} does not match its locked SHA-256 digest`);
    }
    const registryBytes = archiveMember(
      registry.archivePath,
      `${registry.memberPrefix}${file.path}`,
    );
    if (!registryBytes.equals(readFileSync(absolutePath))) {
      fail(`${file.path} differs from the resolved registry crate`);
    }
  }
}

const importedRoots = [
  "identity",
  "reallyme/crypto",
  "reallyme/identity/common",
  "reallyme/openid4vci",
  "reallyme/openid4vp",
];
const vendoredFiles = new Set();
for (const importedRoot of importedRoots) {
  collectProtoFiles(resolve(protoRoot, importedRoot), vendoredFiles);
}
if (
  vendoredFiles.size !== lockedFiles.size ||
  [...vendoredFiles].some((path) => !lockedFiles.has(path))
) {
  fail("the vendored schema inventory does not match the lock file");
}

let baselineManifest;
try {
  baselineManifest = JSON.parse(readFileSync(baselineManifestPath, "utf8"));
} catch {
  fail("crates/proto/baselines/manifest.json is not valid JSON");
}
if (!isRecord(baselineManifest)) {
  fail("the baseline manifest must be an object");
}
assertExactKeys(
  baselineManifest,
  ["schema_version", "baseline", "sha256"],
  "the baseline manifest",
);
if (
  baselineManifest.schema_version !== 1 ||
  baselineManifest.baseline !== "wallet-v1.binpb" ||
  typeof baselineManifest.sha256 !== "string" ||
  !sha256Pattern.test(baselineManifest.sha256)
) {
  fail("the baseline manifest fields are invalid");
}
const baselinePath = resolve(root, "crates/proto/baselines", baselineManifest.baseline);
if (lstatSync(baselinePath).isSymbolicLink()) {
  fail("the Wallet compatibility baseline must be a regular checked-in file");
}
const baselineDigest = createHash("sha256")
  .update(readFileSync(baselinePath))
  .digest("hex");
if (baselineDigest !== baselineManifest.sha256) {
  fail("the Wallet compatibility baseline does not match its locked digest");
}

process.stdout.write(`Verified ${lockedFiles.size} locked Wallet schema inputs and the v1 compatibility baseline\n`);
