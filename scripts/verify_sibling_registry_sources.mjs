#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { gunzipSync } from "node:zlib";
import {
  pinnedRegistryRepository,
  registryChecksumFromLock,
} from "./sibling_registry_provenance_core.mjs";

const CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index";
const COMMIT_PATTERN = /^[0-9a-f]{40}$/u;
const CHECKSUM_PATTERN = /^[0-9a-f]{64}$/u;
const MAX_ARCHIVE_BYTES = 32 * 1024 * 1024;
const MAX_UNCOMPRESSED_BYTES = 128 * 1024 * 1024;
const MAX_API_BYTES = 1024 * 1024;
const MAX_CARGO_METADATA_BYTES = 32 * 1024 * 1024;
const CONFIG_PATH = "scripts/sibling-source-provenance.json";
const USER_AGENT = "reallyme-wallet-release-provenance/1.0 (security@really.me)";

const fail = (code) => {
  process.stderr.write(`sibling registry provenance failed: ${code}\n`);
  process.exit(1);
};

const run = (command, arguments_, cwd, code) => {
  const result = spawnSync(command, arguments_, {
    cwd,
    encoding: "utf8",
    maxBuffer: MAX_CARGO_METADATA_BYTES,
    stdio: ["ignore", "pipe", "ignore"],
  });
  if (result.status !== 0 || typeof result.stdout !== "string") {
    fail(code);
  }
  return result.stdout.trim();
};

const parseJson = (text, code) => {
  try {
    return JSON.parse(text);
  } catch {
    fail(code);
  }
};

const readConfig = () => {
  const value = parseJson(readFileSync(CONFIG_PATH, "utf8"), "invalid-config-json");
  if (
    value?.schema !== "reallyme.wallet.sibling_source_provenance.v1" ||
    !Array.isArray(value.repositories) ||
    value.repositories.length === 0
  ) {
    fail("invalid-config");
  }
  const directories = new Set();
  const prefixes = new Set();
  const additionalPackages = new Set();
  for (const repository of value.repositories) {
    if (
      typeof repository?.directory !== "string" ||
      !/^[a-z0-9][a-z0-9-]*$/u.test(repository.directory) ||
      typeof repository.package_prefix !== "string" ||
      !/^reallyme-[a-z0-9-]+-$/u.test(repository.package_prefix) ||
      !Array.isArray(repository.additional_packages) ||
      repository.additional_packages.some((name) =>
        typeof name !== "string" ||
        !/^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(name) ||
        additionalPackages.has(name)) ||
      new Set(repository.additional_packages).size !== repository.additional_packages.length ||
      typeof repository.commit !== "string" ||
      !COMMIT_PATTERN.test(repository.commit) ||
      directories.has(repository.directory) ||
      prefixes.has(repository.package_prefix)
    ) {
      fail("invalid-config");
    }
    directories.add(repository.directory);
    prefixes.add(repository.package_prefix);
    for (const name of repository.additional_packages) additionalPackages.add(name);
  }
  for (const prefix of prefixes) {
    if ([...prefixes].some((other) => other !== prefix && prefix.startsWith(other))) {
      fail("invalid-config");
    }
  }
  for (const name of additionalPackages) {
    if ([...prefixes].some((prefix) => name.startsWith(prefix))) {
      fail("invalid-config");
    }
  }
  return value.repositories;
};

const fetchBytes = async (url, maximum, code) => {
  let response;
  try {
    response = await fetch(url, {
      headers: { "user-agent": USER_AGENT },
      redirect: "follow",
      signal: AbortSignal.timeout(30_000),
    });
  } catch {
    fail(code);
  }
  if (!response.ok) {
    fail(`${code}-http-${response.status}`);
  }
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null) {
    const parsedLength = Number(declaredLength);
    if (!Number.isSafeInteger(parsedLength) || parsedLength < 0 || parsedLength > maximum) {
      fail(`${code}-too-large`);
    }
  }
  if (response.body === null) {
    fail(`${code}-too-large`);
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      if (!(value instanceof Uint8Array) || value.length > maximum - total) {
        await reader.cancel();
        fail(`${code}-too-large`);
      }
      total += value.length;
      chunks.push(Buffer.from(value));
    }
  } catch {
    fail(`${code}-read-failed`);
  }
  if (total === 0) {
    fail(`${code}-too-large`);
  }
  const bytes = Buffer.concat(chunks, total);
  return bytes;
};

const tarEntry = (archive, requestedSuffix) => {
  let offset = 0;
  while (offset + 512 <= archive.length) {
    const header = archive.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      break;
    }
    const name = header.subarray(0, 100).toString("utf8").replace(/\0.*$/u, "");
    const prefix = header.subarray(345, 500).toString("utf8").replace(/\0.*$/u, "");
    const fullName = prefix.length === 0 ? name : `${prefix}/${name}`;
    const sizeText = header.subarray(124, 136).toString("ascii").replace(/\0.*$/u, "").trim();
    if (!/^[0-7]+$/u.test(sizeText)) {
      fail("invalid-crate-tar-size");
    }
    const size = Number.parseInt(sizeText, 8);
    if (!Number.isSafeInteger(size) || size < 0) {
      fail("invalid-crate-tar-size");
    }
    const contentsStart = offset + 512;
    const contentsEnd = contentsStart + size;
    if (contentsEnd > archive.length) {
      fail("truncated-crate-tar");
    }
    if (fullName.endsWith(requestedSuffix)) {
      return archive.subarray(contentsStart, contentsEnd);
    }
    const paddedSize = Math.ceil(size / 512) * 512;
    offset = contentsStart + paddedSize;
  }
  fail("missing-cargo-vcs-info");
};

const verifyPackage = async (pkg) => {
  const encodedName = encodeURIComponent(pkg.name);
  const encodedVersion = encodeURIComponent(pkg.version);
  const apiBytes = await fetchBytes(
    `https://crates.io/api/v1/crates/${encodedName}/${encodedVersion}`,
    MAX_API_BYTES,
    `registry-metadata-${pkg.name}`,
  );
  const metadata = parseJson(apiBytes.toString("utf8"), `invalid-registry-metadata-${pkg.name}`);
  const checksum = metadata?.version?.checksum;
  if (typeof checksum !== "string" || !CHECKSUM_PATTERN.test(checksum)) {
    fail(`invalid-registry-checksum-${pkg.name}`);
  }
  const crateBytes = await fetchBytes(
    `https://crates.io/api/v1/crates/${encodedName}/${encodedVersion}/download`,
    MAX_ARCHIVE_BYTES,
    `registry-archive-${pkg.name}`,
  );
  const actualChecksum = createHash("sha256").update(crateBytes).digest("hex");
  if (actualChecksum !== checksum) {
    fail(`registry-checksum-mismatch-${pkg.name}`);
  }
  if (actualChecksum !== pkg.expectedChecksum) {
    fail(`registry-source-bytes-mismatch-${pkg.name}`);
  }
  let tar;
  try {
    tar = gunzipSync(crateBytes, { maxOutputLength: MAX_UNCOMPRESSED_BYTES });
  } catch {
    fail(`invalid-registry-archive-${pkg.name}`);
  }
  const vcsBytes = tarEntry(tar, "/.cargo_vcs_info.json");
  const vcs = parseJson(vcsBytes.toString("utf8"), `invalid-cargo-vcs-info-${pkg.name}`);
  if (vcs?.git?.sha1 !== pkg.commit || vcs?.git?.dirty === true) {
    fail(`registry-source-commit-mismatch-${pkg.name}`);
  }
};

const repositories = readConfig();

const lockText = readFileSync("Cargo.lock", "utf8");
const registryChecksum = (name, version) => {
  const checksum = registryChecksumFromLock(lockText, name, version);
  if (checksum === null) {
    fail(`missing-lock-checksum-${name}`);
  }
  return checksum;
};

const metadata = parseJson(
  run("cargo", ["metadata", "--locked", "--format-version", "1"], process.cwd(), "cargo-metadata"),
  "invalid-cargo-metadata",
);
const packageById = new Map((metadata.packages ?? []).map((pkg) => [pkg.id, pkg]));
const nodeById = new Map((metadata.resolve?.nodes ?? []).map((node) => [node.id, node]));
const workspaceMembers = new Set(metadata.workspace_members);
const reachable = new Set();
const pending = (metadata.packages ?? [])
  .filter(
    (pkg) =>
      workspaceMembers.has(pkg.id) &&
      !(Array.isArray(pkg.publish) && pkg.publish.length === 0),
  )
  .map((pkg) => pkg.id);
while (pending.length > 0) {
  const packageId = pending.pop();
  if (typeof packageId !== "string" || reachable.has(packageId)) {
    continue;
  }
  reachable.add(packageId);
  const node = nodeById.get(packageId);
  if (node === undefined || packageById.get(packageId) === undefined) {
    fail("invalid-cargo-resolve-graph");
  }
  for (const dependency of node.dependencies ?? []) {
    if (!reachable.has(dependency)) {
      pending.push(dependency);
    }
  }
}
const packages = [];
const identities = new Set();
for (const pkg of metadata.packages ?? []) {
  if (typeof pkg?.manifest_path !== "string" || typeof pkg.name !== "string") {
    fail("invalid-cargo-package");
  }
  if (!reachable.has(pkg.id)) {
    continue;
  }
  if (workspaceMembers.has(pkg.id)) {
    continue;
  }
  if (pkg.source !== CRATES_IO_SOURCE) {
    fail(`non-registry-release-dependency-${pkg.name}`);
  }
  const repository = pinnedRegistryRepository(repositories, pkg.name);
  if (repository === null) {
    continue;
  }
  const identity = `${pkg.name}@${pkg.version}`;
  if (!identities.has(identity)) {
    identities.add(identity);
    packages.push({
      name: pkg.name,
      version: pkg.version,
      commit: repository.commit,
      expectedChecksum: registryChecksum(pkg.name, pkg.version),
    });
  }
}
if (packages.length === 0) {
  fail("no-registry-sibling-packages");
}
packages.sort((left, right) => left.name.localeCompare(right.name));
for (let index = 0; index < packages.length; index += 6) {
  await Promise.all(packages.slice(index, index + 6).map(verifyPackage));
}
process.stdout.write(
  `verified ${packages.length} sibling registry packages against pinned source commits\n`,
);
