# ElX Control

Standalone Go control-plane module for the ElX VPN service. **ElX-control is the sole source of truth** for the Control runtime, SQL migrations, agent, authentication, FUP and policy journal. The active integration branch is `feat/elx-management-stage3`. The former embedded mirror has been deleted from ElX-ui; the panel contains only its Unix-socket HTTP adapters and customer/admin frontend.

## Implemented boundaries

- Durable PostgreSQL policy journal, revisions, and operation-id replay protection.
- mTLS-authenticated node delivery and pinned Ed25519 policy readback.
- Durable session-slot reservations and one-time device proofs.
- Authorized, durable VLESS-profile drain queue: mTLS agent executes core deny+drain, verifies pinned Ed25519 proof, then releases only the matching session generation.
- Cumulative ElXray usage readback, nonce-bound remote signed accounting over mTLS, per-period FUP events and a queueing FUP reconciler.
- Per-entitlement shared upload/download rate grants and automatic core-signed deny-and-drain barriers before releasing reduced commitments.
- Calendar-aware FUP rollover (day/week/month) with atomic source-watermark inheritance and dynamic current-period collection.
- Long-running mTLS node policy, session-drain, signed usage and 15-second lease agents, FUP maintenance loop, RAWI API client, and tested allocation primitives.
- Canonical policy-manifest driven FUP accounting: automatic grant-to-subscription mapping from pinned core keys/epochs, deterministic assignment identifiers, and live node-scoped assignment discovery over mTLS (static file is optional).

See `docs/elx/policy-smoke.ru.md` for Windows/WSL, PostgreSQL and two-node live VLESS integration checks.

Signed FUP provisioning: `elx-control provision-usage` links one purchased node rate grant to a pinned ElXray identity, a current FUP period and an authenticated accounting stream. `elx-control usage-coverage` reports bound, primed and fresh sources. The first signed sample establishes a watermark instead of charging historical traffic. See `docs/elx/signed-fup-provisioning.ru.md` for operator procedures and limitations.

## Windows quick start

With Git for Windows, WSL Ubuntu, Docker Desktop and a Go toolchain installed, download and execute:

```powershell
$runner = Join-Path $env:TEMP 'run-elx-windows.ps1'
Invoke-WebRequest 'https://raw.githubusercontent.com/ElXnet/ElX-control/feat/elx-management-stage3/scripts/run-elx-windows.ps1' -OutFile $runner
powershell.exe -NoProfile -ExecutionPolicy Bypass -File $runner -Workspace 'C:\ElX-test'
```

This checks the **standalone** Control module. Scripts create an isolated PostgreSQL test database; they do not change a VPS.

## Integration still required

Core-side signed VLESS deny/drain evidence, Control-authorized automatic session release, signed accounting, 15-second fail-closed network-partition leases, and rate-reduction barriers have been implemented in the working branches. For production, mandatory lease mode must be enabled on both core and node agent with provisioned trust anchors and the persisted policy store. Remaining integration: verified provisioning that binds each device's authenticated VLESS profile to its entitlement, billing, email recovery/verification and production-grade per-IP auth throttling, node/key rotation and recovery procedures, and multi-device failure/load tests. The invite-only customer cabinet routes and ownership checks exist in the integration branch but still need release verification. Do not infer device identity from IP addresses, HWIDs or copied subscription URLs. Local token buckets permit a bounded burst; the grant ledger enforces conservative allocations, not mathematically zero packet-level bursts.

Do not merge this branch or deploy as a finished business service solely on the basis of unit tests. All local and GitHub Actions test results should be inspected first.

For verified assignment bootstrapping run `elx-control auto-provision-usage -entitlement UUID -schedule UUID` on the Control host with `ELX_POLICY_BINDING` pointing to the same trusted manifest as `serve-policy`. Nodes running `serve-usage` discover only their own assignments over mTLS on each poll. Payment processing and safe core-incarnation rotation are separate workflows.

## Paid profiles and isolated payment verifier

The payment reader/settlement verifier is a **separate service**: it holds the private Ed25519 attestation key and bank API credentials. ElX Control handles only server-priced checkout orders and validates the verifier's signed settlement against a pinned public key. Payment confirmation is exposed on `serve-payment-ingress` using a **separate restricted** `ELX_PAYMENT_SOCKET`; it is not routed through the administrative `ELX_MANAGEMENT_SOCKET`. Profile creation is a durable disabled-first ElX-ui outbox. Rate allocations, signed Control leases and per-node reconciliation must be verified before enabling paid VPN access.

For the operator commands, failure recovery, separate Unix users/groups, 30-day tariff, invoice replay tests and signed core rotation see [Paid profiles and core rotation](docs/elx/paid-profiles-and-core-rotation.ru.md).
