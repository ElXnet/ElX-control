# ElX Control

Standalone Go control-plane module for the ElX VPN service. The active implementation lives on the `feat/multinode-policy` branch, mirrored during the integration transition in `ElX-ui/elx-control-journal`.

## Implemented boundaries

- Durable PostgreSQL policy journal, revisions, and operation-id replay protection.
- mTLS-authenticated node delivery and pinned Ed25519 policy readback.
- Durable session-slot reservations and one-time device proofs.
- Authorized, durable VLESS-profile drain queue: mTLS agent executes core deny+drain, verifies pinned Ed25519 proof, then releases only the matching session generation.
- Cumulative ElXray usage readback, nonce-bound remote signed accounting over mTLS, per-period FUP events and a queueing FUP reconciler.
- Per-entitlement shared upload/download rate grants and automatic core-signed deny-and-drain barriers before releasing reduced commitments.
- Calendar-aware FUP rollover (day/week/month) with atomic source-watermark inheritance and dynamic current-period collection.
- Long-running mTLS node policy, session-drain, signed usage and 15-second lease agents, FUP maintenance loop, RAWI API client, and tested allocation primitives.

See `docs/elx/policy-smoke.ru.md` for Windows/WSL, PostgreSQL and two-node live VLESS integration checks.

## Windows quick start

With Git for Windows, WSL Ubuntu, Docker Desktop and a Go toolchain installed, download and execute:

```powershell
$runner = Join-Path $env:TEMP 'run-elx-windows.ps1'
Invoke-WebRequest 'https://raw.githubusercontent.com/ElXnet/ElX-control/feat/multinode-policy/scripts/run-elx-windows.ps1' -OutFile $runner
powershell.exe -NoProfile -ExecutionPolicy Bypass -File $runner -Workspace 'C:\ElX-test'
```

This checks the **standalone** Control module. Scripts create an isolated PostgreSQL test database; they do not change a VPS.

## Integration still required

Core-side signed VLESS deny/drain evidence, Control-authorized automatic session release, signed accounting, 15-second fail-closed network-partition leases, and rate-reduction barriers have been implemented in the working branches. For production, mandatory lease mode must be enabled on both core and node agent with provisioned trust anchors and the persisted policy store. Remaining integration: verified provisioning that binds each device's authenticated VLESS profile to its entitlement, authorized personal-cabinet actions and billing, node/key rotation and recovery procedures, and multi-device failure/load tests. Do not infer device identity from IP addresses, HWIDs or copied subscription URLs. Local token buckets permit a bounded burst; the grant ledger enforces conservative allocations, not mathematically zero packet-level bursts.

Do not merge this branch or deploy as a finished business service solely on the basis of unit tests. All local and GitHub Actions test results should be inspected first.
