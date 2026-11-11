#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { readFileSync } from "node:fs";

const preflight = readFileSync(".github/workflows/crates-package-preflight.yml", "utf8");
const release = readFileSync(".github/workflows/crates-release.yml", "utf8");
const siblingProvenance = JSON.parse(
  readFileSync("scripts/sibling-source-provenance.json", "utf8"),
);

const executableYaml = (source) =>
  source
    .split("\n")
    .filter((line) => !/^\s*#/u.test(line))
    .map((line) => line.replace(/\s+#.*$/u, ""))
    .join("\n");

const preflightExecutable = executableYaml(preflight);
const releaseExecutable = executableYaml(release);

const fail = (reason) => {
  process.stderr.write(`crates release workflow check failed: ${reason}\n`);
  process.exit(1);
};

const requireText = (source, expected, reason) => {
  if (!source.includes(expected)) {
    fail(reason);
  }
};

requireText(preflightExecutable, "name: Crates Package Preflight", "preflight button name drifted");
requireText(preflightExecutable, "version:\n", "preflight must request an exact release version");
requireText(preflightExecutable, "node scripts/write_release_attestation.mjs", "preflight must attest reviewed packages");
requireText(preflightExecutable, "node scripts/verify_sibling_registry_sources.mjs", "preflight must bind registry siblings to tested commits");
const fetchDependenciesStep = preflightExecutable.indexOf(
  "- name: Fetch locked workspace dependencies\n        working-directory: wallet\n        run: cargo fetch --locked",
);
const readinessGateStep = preflightExecutable.indexOf("- name: Run complete release-readiness gate");
if (fetchDependenciesStep < 0 || readinessGateStep < 0 || fetchDependenciesStep >= readinessGateStep) {
  fail("preflight must fetch the locked workspace dependencies before offline release checks");
}
requireText(releaseExecutable, "name: Crates.io Release", "release button name drifted");
requireText(releaseExecutable, "node scripts/verify_release_attestation.mjs", "release must verify the reviewed preflight");
requireText(releaseExecutable, "environment: crates-io", "publish must use the protected crates-io environment");
requireText(releaseExecutable, "CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}", "publish must use the crates-io environment secret");
requireText(releaseExecutable, 'tag="reallyme-wallet-v${RELEASE_VERSION}"', "release tag convention drifted");

if (!Array.isArray(siblingProvenance.repositories)) {
  fail("sibling source provenance is invalid");
}
for (const repository of siblingProvenance.repositories) {
  if (
    typeof repository?.directory !== "string" ||
    typeof repository.commit !== "string" ||
    !/^[0-9a-f]{40}$/u.test(repository.commit)
  ) {
    fail("sibling source provenance is invalid");
  }
  // Registry provenance is established from Cargo.lock, archive bytes and
  // embedded VCS metadata. A source checkout is unnecessary for that proof;
  // any checkout that is retained must still match the reviewed commit.
  for (const source of [preflightExecutable, releaseExecutable]) {
    if (source.includes(`repository: reallyme/${repository.directory}`)) {
      requireText(
        source,
        `ref: ${repository.commit}`,
        `source checkout does not pin ${repository.directory} to its provenance commit`,
      );
    }
  }
}

if (preflightExecutable.includes("CARGO_REGISTRY_TOKEN") || preflightExecutable.includes("cargo publish")) {
  fail("preflight must not receive registry credentials or publish");
}
if (releaseExecutable.includes("id-token: write")) {
  fail("release must not request an OIDC identity token");
}
if (releaseExecutable.includes("rust-lang/crates-io-auth-action@")) {
  fail("release must not use crates.io trusted publishing");
}
const secretReferences = [...releaseExecutable.matchAll(/\$\{\{\s*secrets\.([A-Z0-9_]+)\s*\}\}/gu)]
  .map((match) => match[1]);
if (
  secretReferences.length !== 1
  || secretReferences[0] !== "CARGO_REGISTRY_TOKEN"
) {
  fail("release may reference only the crates-io environment token secret");
}
if (/Swatinem\/rust-cache@/u.test(releaseExecutable)) {
  fail("the credential-bearing publish job must not restore an executable build cache");
}
if (/workflow_dispatch:\s*\n\s+inputs:/u.test(releaseExecutable)) {
  fail("release must derive its version from the reviewed source, not a second input");
}

for (const source of [preflightExecutable, releaseExecutable]) {
  for (const match of source.matchAll(/\buses\s*:\s*["']?([^\s,@}"']+)@([^\s,}"']+)/gu)) {
    if (!/^[0-9a-f]{40}$/u.test(match[2])) {
      fail("every third-party action must be pinned to a full commit SHA");
    }
  }
  const lines = source.split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    if (!/\buses\s*:\s*["']?actions\/checkout@/u.test(lines[index])) continue;
    const usesIndent = /^ */u.exec(lines[index])?.[0].length ?? 0;
    let start = index;
    let indent;
    while (start >= 0) {
      const item = /^([ ]*)-\s/u.exec(lines[start]);
      if (item && item[1].length < usesIndent) {
        indent = item[1].length;
        break;
      }
      start -= 1;
    }
    if (indent === undefined) start = index;
    let end = start + 1;
    while (
      end < lines.length &&
      (indent === undefined || !new RegExp(`^ {${indent}}-\\s`, "u").test(lines[end]))
    ) {
      end += 1;
    }
    const step = lines.slice(start, end).join("\n");
    if (!/persist-credentials\s*:\s*false/u.test(step)) {
      fail("every checkout must disable persisted credentials");
    }
  }
}

process.stdout.write("crates release workflows match the reviewed publication contract\n");
