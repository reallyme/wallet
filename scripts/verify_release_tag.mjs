#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { fileURLToPath } from "node:url";

const FULL_SHA = /^[0-9a-f]{40}$/u;
const VERSION = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const MAX_ANNOTATED_TAG_DEPTH = 8;

export class ReleaseTagError extends Error {
  constructor(code) {
    super(code);
    this.name = "ReleaseTagError";
    this.code = code;
  }
}

const fail = (code) => {
  throw new ReleaseTagError(code);
};

/** Check the exact commit behind both lightweight and annotated tags. */
export const verifyReleaseTag = async ({ env = process.env, request = fetch } = {}) => {
  const { RELEASE_SHA: releaseSha, RELEASE_VERSION: version } = env;
  const { GITHUB_REPOSITORY: repository, GH_TOKEN: token } = env;
  if (!FULL_SHA.test(releaseSha ?? "") || !VERSION.test(version ?? "")) {
    fail("invalid-release-identity");
  }
  if (!REPOSITORY.test(repository ?? "") || typeof token !== "string" || token.length === 0) {
    fail("invalid-github-identity");
  }
  const api = env.GITHUB_API_URL ?? "https://api.github.com";
  let apiUrl;
  try {
    apiUrl = new URL(api);
  } catch {
    fail("invalid-github-api-url");
  }
  if (apiUrl.protocol !== "https:" || apiUrl.username || apiUrl.password) {
    fail("invalid-github-api-url");
  }
  const tag = `reallyme-wallet-v${version}`;
  const read = async (path) => {
    const url = new URL(`${apiUrl.pathname.replace(/\/$/u, "")}/repos/${repository}/${path}`, apiUrl);
    try {
      return await request(url, {
        headers: {
          Accept: "application/vnd.github+json",
          Authorization: `Bearer ${token}`,
          "X-GitHub-Api-Version": "2022-11-28",
        },
        redirect: "error",
      });
    } catch {
      fail("tag-lookup-failed");
    }
  };
  // A missing ref is a documented 404. The commits endpoint instead returns
  // 422 for an unknown name, which cannot safely be treated as tag absence.
  const response = await read(`git/ref/tags/${tag}`);
  if (response.status === 404) {
    return tag;
  }
  if (response.status !== 200) {
    fail("tag-lookup-failed");
  }
  const decode = async (response) => {
    if (response.status !== 200) fail("tag-lookup-failed");
    try {
      return await response.json();
    } catch {
      fail("tag-lookup-failed");
    }
  };
  const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
  const target = (value) => {
    if (
      !isRecord(value) || !isRecord(value.object) ||
      !["commit", "tag"].includes(value.object.type) ||
      typeof value.object.sha !== "string" || !FULL_SHA.test(value.object.sha)
    ) fail("tag-lookup-failed");
    return value.object;
  };
  const ref = await decode(response);
  if (!isRecord(ref) || ref.ref !== `refs/tags/${tag}`) {
    fail("tag-lookup-failed");
  }
  let object = target(ref);
  const seen = new Set();
  for (let depth = 0; object.type === "tag"; depth += 1) {
    if (depth >= MAX_ANNOTATED_TAG_DEPTH || seen.has(object.sha)) fail("tag-lookup-failed");
    seen.add(object.sha);
    const annotation = await decode(await read(`git/tags/${object.sha}`));
    if (!isRecord(annotation) || annotation.sha !== object.sha) fail("tag-lookup-failed");
    object = target(annotation);
  }
  if (object.sha !== releaseSha) {
    fail("tag-conflicts-with-release-commit");
  }
  return tag;
};

const isMain = process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  try {
    const tag = await verifyReleaseTag();
    console.log(`release tag preflight passed: ${tag}`);
  } catch (error) {
    const code = error instanceof ReleaseTagError ? error.code : "unexpected-failure";
    console.error(`release tag preflight failed: ${code}`);
    process.exitCode = 1;
  }
}
