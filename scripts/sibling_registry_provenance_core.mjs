// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

const CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index";
const CHECKSUM_PATTERN = /^[0-9a-f]{64}$/u;

// Cargo.lock is generated TOML with one package table per entry. Exact line
// matching avoids accepting a checksum from a dependency array or metadata.
export function registryChecksumFromLock(lockText, name, version) {
  if (typeof lockText !== "string" || typeof name !== "string" || typeof version !== "string") {
    return null;
  }
  const matches = [];
  for (const block of lockText.split(/^\[\[package\]\]\s*$/mu).slice(1)) {
    const field = (key) => block.match(new RegExp(`^${key} = "([^"]+)"$`, "mu"))?.[1];
    if (field("name") === name && field("version") === version &&
        field("source") === CRATES_IO_SOURCE) {
      matches.push(field("checksum"));
    }
  }
  return matches.length === 1 && CHECKSUM_PATTERN.test(matches[0] ?? "")
    ? matches[0]
    : null;
}

export function pinnedRegistryRepository(repositories, packageName) {
  if (!Array.isArray(repositories) || typeof packageName !== "string") {
    return null;
  }
  const matches = repositories.filter(
    (repository) =>
      (typeof repository?.package_prefix === "string" &&
        packageName.startsWith(repository.package_prefix)) ||
      (Array.isArray(repository?.additional_packages) &&
        repository.additional_packages.includes(packageName)),
  );
  return matches.length === 1 ? matches[0] : null;
}
