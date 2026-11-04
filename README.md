# ElX Control

Standalone Go control-plane module for the ElX VPN service. The active implementation lives on the `feat/multinode-policy` branch, mirrored during the integration transition in `ElX-ui/elx-control-journal`.

## Implemented boundaries

- Durable PostgreSQL policy journal, revisions, and operation-id replay protection.
- mTLS-authenticated node delivery and pinned Ed25519 policy readback.
- Durable session-slot reservations and one-time device proofs.
- Generation- and VLESS-profile-fenced session release, pinned Ed25519 core key validation and mTLS proof receiver (core-side drain proof producer still required).
- Cumulative ElXray usage readback, nonce-bound remote signed accounting over mTLS, per-period FUP events and a queueing FUP reconciler.
- Per-entitlement shared upload/download grant ledger with conservative, as-yet-unfinalized reduction barriers.
- Calendar-aware FUP rollover (day/week/month) with atomic source-watermark inheritance and dynamic current-period collection.\n- Long-running mTLS node policy agent, FUP maintenance loop, RAWI API client, and tested allocation primitives.

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

The database's session-fence verification is not itself proof that ElXray has drained a particular device's flows. Core-generated drain receipts, unique profile-to-device bindings, automatic node provisioning/key rotation, stale-sample fail-closed policy leases, generation-bound core drain proof production, and signed rate-barrier enforcement in ElXray must be integrated and tested before paid production traffic. Current command `collect-usage` requires a pre-provisioned trusted source assignment. Never infer device identity from an IP address or a copied subscription URL.

Do not merge this branch or deploy as a finished business service solely on the basis of unit tests. All local and GitHub Actions test results should be inspected first.
