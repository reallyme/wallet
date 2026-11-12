// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved

// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";

const script = fileURLToPath(new URL("./publish-crates-in-order.mjs", import.meta.url));
const { release_version: releaseVersion } = JSON.parse(readFileSync(
  new URL("../conformance/features/wallet-package-policy-v1.json", import.meta.url),
  "utf8",
));
const packageNames = [
  "reallyme-wallet-types",
  "reallyme-wallet-keystore",
  "reallyme-wallet-lifecycle",
  "reallyme-wallet-log",
  "reallyme-wallet-attestation",
  "reallyme-wallet-consent",
  "reallyme-wallet-inventory",
  "reallyme-wallet-render",
  "reallyme-wallet-proto",
  "reallyme-wallet-zk",
  "reallyme-wallet-proto-codec",
  "reallyme-wallet-storage",
  "reallyme-wallet-flows",
  "reallyme-wallet-runtime",
  "reallyme-wallet-http",
  "reallyme-wallet-provider",
  "reallyme-wallet",
];

const archiveContents = (name) => Buffer.from(`reviewed archive for ${name}`, "utf8");

function runFixture({
  mode = "publish",
  scenario = "success",
  requirement = `^${releaseVersion}`,
  version = releaseVersion,
} = {}) {
  const directory = mkdtempSync(join(tmpdir(), "wallet-publish-test-"));
  try {
    const callsPath = join(directory, "calls.json");
    const preload = join(directory, "mock.mjs");
    const attestationPath = join(directory, "attestation.json");
    const reviewedDirectory = join(directory, "reviewed");
    mkdirSync(join(directory, "package"));
    mkdirSync(reviewedDirectory);
    for (const name of packageNames) {
      writeFileSync(join(reviewedDirectory, `${name}-${version}.crate`), archiveContents(name));
    }
    writeFileSync(
      attestationPath,
      JSON.stringify({
        schema: "reallyme.wallet.crates_preflight.v3",
        release_sha: "1111111111111111111111111111111111111111",
        version,
        crates: packageNames.map((name) => ({
          file: `${name}-${version}.crate`,
          sha256: createHash("sha256").update(archiveContents(name)).digest("hex"),
          size: archiveContents(name).length,
        })),
      }),
    );
    // Intercept every child process: these tests must never invoke Cargo,
    // access a registry, publish a crate, or perform real retry waits.
    writeFileSync(preload, `
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { writeFileSync } from "node:fs";
const calls = [];
const scenario = ${JSON.stringify(scenario)};
let attempts = 0;
Atomics.wait = (_array, _index, _value, delay) => {
  calls.push(["wait", delay]);
  writeFileSync(${JSON.stringify(callsPath)}, JSON.stringify(calls));
  return "timed-out";
};
childProcess.spawnSync = (command, args) => {
  calls.push([command, ...args]);
  writeFileSync(${JSON.stringify(callsPath)}, JSON.stringify(calls));
  const ok = { status: 0, stdout: "", stderr: "" };
  if (command === "curl") {
    const output = args[args.indexOf("--output") + 1];
    const archive = output.split("/").at(-1);
    const name = archive.slice(0, -"-${version}.crate".length);
    const contents = scenario === "checksum-mismatch"
      ? Buffer.from("different published bytes", "utf8")
      : Buffer.from("reviewed archive for " + name, "utf8");
    writeFileSync(output, contents);
    return ok;
  }
  if (command !== "cargo") return { ...ok, status: 99 };
  if (args[0] === "metadata") return { ...ok, stdout: JSON.stringify({
    target_directory: ${JSON.stringify(directory)},
    packages: [
      { name: "reallyme-wallet-types", version: ${JSON.stringify(version)}, publish: null, dependencies: [] },
      { name: "reallyme-wallet-keystore", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [{ name: "reallyme-wallet-types", source: null, path: "crates/types", kind: null, req: ${JSON.stringify(requirement)} }] },
      { name: "reallyme-wallet-lifecycle", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [{ name: "reallyme-wallet-types", source: null, path: "crates/types", kind: null, req: ${JSON.stringify(requirement)} }] },
      { name: "reallyme-wallet-log", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [{ name: "reallyme-wallet-types", source: null, path: "crates/types", kind: null, req: ${JSON.stringify(requirement)} }] },
      { name: "reallyme-wallet-attestation", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [{ name: "reallyme-wallet-keystore", source: null, path: "crates/keystore", kind: null, req: ${JSON.stringify(requirement)} }] },
      { name: "reallyme-wallet-consent", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [
          { name: "reallyme-wallet-types", source: null, path: "crates/types", kind: null, req: ${JSON.stringify(requirement)} },
          { name: "reallyme-wallet-storage", source: null, path: "crates/storage", kind: null, req: ${JSON.stringify(requirement)} },
        ] },
      { name: "reallyme-wallet-inventory", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [{ name: "reallyme-wallet-types", source: null, path: "crates/types", kind: null, req: ${JSON.stringify(requirement)} }] },
      { name: "reallyme-wallet-render", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [{ name: "reallyme-wallet-types", source: null, path: "crates/types", kind: null, req: ${JSON.stringify(requirement)} }] },
      { name: "reallyme-wallet-proto", version: ${JSON.stringify(version)}, publish: null, dependencies: [] },
      { name: "reallyme-wallet-zk", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [{ name: "reallyme-wallet-types", source: null, path: "crates/types", kind: null, req: ${JSON.stringify(requirement)} }] },
      { name: "reallyme-wallet-proto-codec", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [{ name: "reallyme-wallet-proto", source: null, path: "crates/proto", kind: null, req: ${JSON.stringify(requirement)} }] },
      { name: "reallyme-wallet-storage", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [{ name: "reallyme-wallet-proto-codec", source: null, path: "crates/proto-codec", kind: null, req: ${JSON.stringify(requirement)} }] },
      { name: "reallyme-wallet-flows", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [
          { name: "reallyme-wallet-attestation", source: null, path: "crates/attestation", kind: null, req: ${JSON.stringify(requirement)} },
          { name: "reallyme-wallet-consent", source: null, path: "crates/consent", kind: null, req: ${JSON.stringify(requirement)} },
        ] },
      { name: "reallyme-wallet-runtime", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [
          { name: "reallyme-wallet-proto-codec", source: null, path: "crates/proto-codec", kind: null, req: ${JSON.stringify(requirement)} },
          { name: "reallyme-wallet-consent", source: null, path: "crates/consent", kind: null, req: ${JSON.stringify(requirement)} },
          { name: "reallyme-wallet-storage", source: null, path: "crates/storage", kind: null, req: ${JSON.stringify(requirement)} },
        ] },
      { name: "reallyme-wallet-http", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [{ name: "reallyme-wallet-runtime", source: null, path: "crates/runtime", kind: null, req: ${JSON.stringify(requirement)} }] },
      { name: "reallyme-wallet-provider", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [{ name: "reallyme-wallet-runtime", source: null, path: "crates/runtime", kind: null, req: ${JSON.stringify(requirement)} }] },
      { name: "reallyme-wallet", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [{ name: "reallyme-wallet-provider", source: null, path: "crates/provider", kind: null, req: ${JSON.stringify(requirement)} }] },
    ],
  }) };
  if (args[0] === "package") {
    for (const name of ${JSON.stringify(packageNames)}) {
      writeFileSync(
        ${JSON.stringify(join(directory, "package"))} + "/" + name + "-${version}.crate",
        Buffer.from("reviewed archive for " + name, "utf8"),
      );
    }
    return ok;
  }
  if (args[0] !== "publish") return { ...ok, status: 99 };
  attempts += 1;
  if (scenario === "exhausted" || (scenario === "retry" && attempts === 1)) {
    return { ...ok, status: 101, stderr: "too many requests" };
  }
  if (scenario === "failure") return { ...ok, status: 101, stderr: "package verification failed" };
  return ok;
};
syncBuiltinESMExports();
`);
    const result = spawnSync(process.execPath, ["--import", pathToFileURL(preload).href, script, mode], {
      cwd: directory,
      encoding: "utf8",
      timeout: 10_000,
      env: {
        ...process.env,
        RELEASE_ATTESTATION_PATH: attestationPath,
        RELEASE_SHA: "1111111111111111111111111111111111111111",
        RELEASE_VERSION: version,
        REVIEWED_CRATE_DIRECTORY: reviewedDirectory,
      },
    });
    assert.equal(result.error, undefined);
    const calls = existsSync(callsPath)
      ? JSON.parse(readFileSync(callsPath, "utf8"))
      : [];
    return { ...result, calls };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test("successful publication respects dependency order", () => {
  const result = runFixture();
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.calls.filter((call) => call[1] === "publish").map((call) => call[3]),
    [
      "reallyme-wallet-proto",
      "reallyme-wallet-types",
      "reallyme-wallet-lifecycle",
      "reallyme-wallet-render",
      "reallyme-wallet-zk",
      "reallyme-wallet-keystore",
      "reallyme-wallet-attestation",
      "reallyme-wallet-proto-codec",
      "reallyme-wallet-storage",
      "reallyme-wallet-inventory",
      "reallyme-wallet-log",
      "reallyme-wallet-consent",
      "reallyme-wallet-flows",
      "reallyme-wallet-runtime",
      "reallyme-wallet-http",
      "reallyme-wallet-provider",
      "reallyme-wallet",
    ]);
});

test("every package is attested before the first upload", () => {
  const result = runFixture();
  assert.equal(result.status, 0, result.stderr);
  const firstPublish = result.calls.findIndex((call) => call[1] === "publish");
  const packageCallsBeforePublish = result.calls
    .slice(0, firstPublish)
    .filter((call) => call[1] === "package");
  assert.equal(packageCallsBeforePublish.length, 1);
  assert.ok(packageCallsBeforePublish[0].includes("--workspace"));
});

test("published registry bytes must match the attested archive", () => {
  const result = runFixture({ scenario: "checksum-mismatch" });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /published from different source bytes/u);
  assert.equal(result.calls.filter((call) => call[1] === "publish").length, 1);
});

test("rate-limit exhaustion fails without publishing dependent crates", () => {
  const result = runFixture({ scenario: "exhausted" });
  assert.equal(result.status, 101);
  const publishes = result.calls.filter((call) => call[1] === "publish");
  assert.equal(publishes.length, 12);
  assert.ok(publishes.every((call) => call[3] === "reallyme-wallet-proto"));
  assert.equal(result.calls.filter((call) => call[0] === "wait").length, 11);
});

test("transient rate limits retry before publishing dependent crates", () => {
  const result = runFixture({ scenario: "retry" });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.calls.filter((call) => call[0] === "wait"), [["wait", 60000]]);
});

test("non-retryable publication errors fail immediately", () => {
  const result = runFixture({ scenario: "failure" });
  assert.equal(result.status, 101);
  assert.equal(result.calls.filter((call) => call[1] === "publish").length, 1);
  assert.equal(result.calls.filter((call) => call[0] === "wait").length, 0);
});

test("release policy accepts only compatible requirements at the approved version", () => {
  // A fixed future version eventually becomes the approved release. Derive a
  // different valid patch version so this remains a rejection test after bumps.
  const [major, minor, patch] = releaseVersion.split(".");
  const unapprovedVersion = `${major}.${minor}.${BigInt(patch) + 1n}`;
  for (const [requirement, version, accepted] of [
    [`^${releaseVersion}`, releaseVersion, true],
    [`=${releaseVersion}`, releaseVersion, true],
    [releaseVersion, releaseVersion, true],
    ["^0.0.1", releaseVersion, false],
    [`^${releaseVersion}junk`, releaseVersion, false],
    [`^${unapprovedVersion}`, unapprovedVersion, false],
  ]) {
    const result = runFixture({ mode: "order", requirement, version });
    assert.equal(result.status === 0, accepted, `${requirement} / ${version}`);
    assert.ok(result.calls.every((call) => call[1] === "metadata"));
  }
});
