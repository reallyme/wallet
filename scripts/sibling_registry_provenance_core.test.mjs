// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import test from "node:test";
import assert from "node:assert/strict";

import {
  pinnedRegistryRepository,
  registryChecksumFromLock,
} from "./sibling_registry_provenance_core.mjs";

const checksum = "a".repeat(64);
const entry = (source, digest = checksum) => `[[package]]\nname = "reallyme-openid4vci-types"\nversion = "0.1.1"\nsource = "${source}"\nchecksum = "${digest}"\n`;
const registry = "registry+https://github.com/rust-lang/crates.io-index";

test("selects the exact Cargo.lock registry checksum", () => {
  const lock = `${entry(registry)}\n[[package]]\nname = "unrelated"\nversion = "0.1.1"\nchecksum = "${"b".repeat(64)}"\n`;
  assert.equal(registryChecksumFromLock(lock, "reallyme-openid4vci-types", "0.1.1"), checksum);
});

test("rejects missing, duplicated, malformed, and non-registry checksum entries", () => {
  assert.equal(registryChecksumFromLock(entry("git+https://example.test/repo"), "reallyme-openid4vci-types", "0.1.1"), null);
  assert.equal(registryChecksumFromLock(entry(registry, "bad"), "reallyme-openid4vci-types", "0.1.1"), null);
  assert.equal(registryChecksumFromLock(`${entry(registry)}${entry(registry)}`, "reallyme-openid4vci-types", "0.1.1"), null);
  assert.equal(registryChecksumFromLock(entry(registry), "reallyme-openid4vci-types", "0.1.2"), null);
});

test("selects one pinned repository for a resolved registry package", () => {
  const repositories = [
    { package_prefix: "reallyme-openid4vci-", commit: "a" },
    { package_prefix: "reallyme-openid4vp-", commit: "b" },
  ];
  assert.equal(
    pinnedRegistryRepository(repositories, "reallyme-openid4vci-types"),
    repositories[0],
  );
  assert.equal(pinnedRegistryRepository(repositories, "unrelated"), null);
  assert.equal(
    pinnedRegistryRepository([...repositories, repositories[0]], "reallyme-openid4vci-types"),
    null,
  );
});

test("includes explicitly named protocol packages outside the standard prefix", () => {
  const repository = {
    package_prefix: "reallyme-openid4vci-",
    additional_packages: ["openid4vci-profiles"],
  };
  assert.equal(pinnedRegistryRepository([repository], "openid4vci-profiles"), repository);
  assert.equal(pinnedRegistryRepository([repository], "openid4vci-profiles-other"), null);
  assert.equal(pinnedRegistryRepository([repository, repository], "openid4vci-profiles"), null);
});
