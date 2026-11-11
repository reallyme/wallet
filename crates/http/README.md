# reallyme-wallet-http

Native Axum adapters for the Wallet protobuf runtime. The crate handles HTTP
framing and delegates state and policy decisions to `reallyme-wallet-runtime`.
Identity owns platform bindings, Connect clients, and final server composition.

## Operation endpoint

`wallet_router` exposes
`POST /reallyme.wallet.v1.WalletCoreService/WalletOperation`. Requests and
responses use `application/proto` or strict generated `application/json`
ProtoJSON, with optional Brotli compression. Errors use the canonical
`WalletOperationResponse` envelope. Responses include `Cache-Control: no-store`.

Construct `AxumWalletState` with a backend, request authorizer, positive body
limit, and timeout of at most 60 seconds. The default body-limit helper returns
64 KiB; the configured limit applies to both compressed and decompressed input.
The timeout covers request decoding. Once execution begins, the handler waits
for its definitive result so a committed mutation is not reported as a timeout.

## OIDF conformance harness

The `oidf-conformance-harness` feature is disabled by default and provides test
infrastructure only. The repository example binds to loopback and has no
protocol driver:

```sh
cargo run --locked -p reallyme-wallet-http --features oidf-conformance-harness --example serve_oidf_wallet_harness -- 127.0.0.1:8787
```

Set `OIDF_WALLET_HARNESS_CALLBACK_ORIGINS` to the comma-separated HTTPS
origins of the suite's verifier. A launch whose `request_uri`, `response_uri`,
or `redirect_uri` is outside those origins is refused with `invalid_request`;
with the variable unset, every such launch is refused. A launch that passes
the callback check still fails with `unsupported`, because the example injects
no `OidfWalletFlowDriver`.
See the [conformance guide](../../conformance/README.md) for the composed
Identity host used by real suite runs.

All routes require an exact allowed `Host`. Configure ingress hosts with
`with_allowed_hosts` and callback origins with `with_allowed_callback_origins`.
Session reads and reset require a control token set through `with_control_token`.
The example reads `OIDF_WALLET_HARNESS_CONTROL_TOKEN` (32–256 ASCII bytes);
without it, those routes remain closed. Networked deployments also require
authenticated test-runner access around the launch endpoint.
