#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

bind="${OIDF_WALLET_HARNESS_BIND:-127.0.0.1:8787}"
endpoint="http://${bind}/oidf/wallet/authorize"

echo "OIDF wallet harness endpoint: ${endpoint}"
echo "This wallet-core example validates launch transport and fails closed without a composed OidfWalletFlowDriver."
echo "Set OIDF_WALLET_HARNESS_ENDPOINT to an identity composed harness endpoint for the OpenID4VP OIDF wallet plan."
echo "For a remote OIDF server, expose this listener through a public HTTPS tunnel or staging ingress."

exec cargo run --locked -p reallyme-wallet-http --features oidf-conformance-harness --example serve_oidf_wallet_harness -- "${bind}"
