#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { fileURLToPath } from "node:url";

const FULL_SHA = /^[0-9a-f]{40}$/u;
const VERSION = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;

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
  const url = new URL(`${apiUrl.pathname.replace(/\/$/u, "")}/repos/${repository}/commits/${tag}`, apiUrl);
  let response;
  try {
    response = await request(url, {
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
  if (response.status === 404) {
    return tag;
  }
  if (response.status !== 200) {
    fail("tag-lookup-failed");
  }
  let body;
  try {
    body = await response.json();
  } catch {
    fail("tag-lookup-failed");
  }
  if (
    body === null ||
    typeof body !== "object" ||
    Array.isArray(body) ||
    typeof body.sha !== "string" ||
    !FULL_SHA.test(body.sha)
  ) {
    fail("tag-lookup-failed");
  }
  if (body.sha !== releaseSha) {
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
