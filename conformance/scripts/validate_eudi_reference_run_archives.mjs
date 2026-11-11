// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
// SPDX-License-Identifier: MIT OR Apache-2.0

import { createHash } from "node:crypto";
import { createReadStream, lstatSync, readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const REQUIRED_KINDS = Object.freeze([
  "suite_export",
  "run_summary",
  "fixture_hash_manifest",
  "environment_manifest",
  "difference_summary",
]);
const SHA256_HEX = /^[0-9a-f]{64}$/u;
const MAX_MANIFEST_BYTES = 1_048_576;

class ReferenceArchiveError extends Error {
  constructor(code) {
    super(`reference-run-archive-invalid:${code}`);
    this.name = "ReferenceArchiveError";
    this.code = code;
  }
}

function fail(reason) {
  throw new ReferenceArchiveError(reason);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requireKinds(value) {
  return Array.isArray(value)
    && value.length === REQUIRED_KINDS.length
    && new Set(value).size === REQUIRED_KINDS.length
    && REQUIRED_KINDS.every((kind) => value.includes(kind));
}

function checkedFile(root, base, relativePath) {
  if (
    typeof relativePath !== "string"
    || relativePath.length === 0
    || relativePath.includes("\\")
    || relativePath.includes("\0")
    || path.posix.isAbsolute(relativePath)
    || relativePath.split("/").some((part) => part === "" || part === "." || part === "..")
  ) {
    fail("unsafe-path");
  }

  const candidate = path.resolve(base, relativePath);
  const confined = path.relative(root, candidate);
  if (confined === "" || confined === ".." || confined.startsWith(`..${path.sep}`)) {
    fail("path-outside-root");
  }

  let metadata;
  let canonical;
  try {
    metadata = lstatSync(candidate);
    canonical = realpathSync(candidate);
  } catch {
    fail("missing-file");
  }
  const realConfined = path.relative(root, canonical);
  if (
    !metadata.isFile()
    || metadata.isSymbolicLink()
    || realConfined === ".."
    || realConfined.startsWith(`..${path.sep}`)
  ) {
    fail("invalid-file");
  }
  return { path: candidate, size: metadata.size };
}

function readManifest(file) {
  if (file.size > MAX_MANIFEST_BYTES) {
    fail("oversized-manifest");
  }
  let document;
  try {
    document = JSON.parse(readFileSync(file.path, "utf8"));
  } catch {
    fail("malformed-manifest");
  }
  if (!isRecord(document)) {
    fail("malformed-manifest");
  }
  return document;
}

async function sha256File(file) {
  const digest = createHash("sha256");
  for await (const chunk of createReadStream(file.path)) {
    digest.update(chunk);
  }
  return digest.digest("hex");
}

/** Validate every required run and the bytes of every archived artifact. */
export async function validateReferenceArchives(rootPath, manifestPath) {
  const root = realpathSync(rootPath);
  const manifest = readManifest(checkedFile(root, root, manifestPath));
  if (!requireKinds(manifest.required_artifact_kinds)
      || !Array.isArray(manifest.runs)
      || manifest.runs.length === 0) {
    fail("invalid-run-list");
  }

  const runIds = new Set();
  const archivePaths = new Set();
  for (const run of manifest.runs) {
    if (!isRecord(run)
        || typeof run.id !== "string"
        || run.id.length === 0
        || runIds.has(run.id)
        || run.status !== "passed"
        || !requireKinds(run.required_artifacts)) {
      fail("invalid-run");
    }
    runIds.add(run.id);
    const archive = checkedFile(root, root, run.expected_archive_path);
    if (archivePaths.has(archive.path)) {
      fail("duplicate-archive");
    }
    archivePaths.add(archive.path);
    const record = readManifest(archive);
    if (record.id !== run.id || record.status !== "passed" || !Array.isArray(record.artifacts)) {
      fail("invalid-archive");
    }

    const kinds = new Set();
    const paths = new Set();
    for (const artifact of record.artifacts) {
      if (!isRecord(artifact)
          || !REQUIRED_KINDS.includes(artifact.kind)
          || kinds.has(artifact.kind)
          || typeof artifact.sha2_256 !== "string"
          || !SHA256_HEX.test(artifact.sha2_256)) {
        fail("invalid-artifact-entry");
      }
      kinds.add(artifact.kind);
      // Archive-relative paths keep a run self-contained. Resolve and check
      // every file before trusting its manifest-supplied digest.
      const file = checkedFile(root, path.dirname(archive.path), artifact.path);
      if (paths.has(file.path)) {
        fail("duplicate-artifact-path");
      }
      paths.add(file.path);
      if (await sha256File(file) !== artifact.sha2_256) {
        fail("artifact-digest-mismatch");
      }
    }
    if (!requireKinds([...kinds])) {
      fail("missing-artifact");
    }
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
  const manifestPath = process.argv[2] ?? "conformance/eudi/reference-run-manifest.json";
  try {
    await validateReferenceArchives(root, manifestPath);
    process.stdout.write("EUDI reference-wallet run archives are complete.\n");
  } catch (error) {
    process.stderr.write(`${error instanceof ReferenceArchiveError ? error.message : "reference-run-archive-invalid"}\n`);
    process.exitCode = 1;
  }
}
