# ElX Control

Standalone Go control-plane module for the ElX VPN service. The active implementation lives on the `feat/multinode-policy` branch, mirrored during the integration transition in `ElX-ui/elx-control-journal`.

## Implemented boundaries

- Durable PostgreSQL policy journal, revisions, and operation-id replay protection.
- mTLS-authenticated node delivery and pinned Ed25519 policy readback.
- Durable session-slot reservations and one-time device proofs.
- Generation-fenced release requiring a registered core signing key.
- Cumulative ElXray usage readback, verified collection, and per-period FUP events.
- Per-entitlement shared upload/download grant ledger and reduction barriers.
- RAWI provider API client and tested weighted allocation primitives.

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

The database's session-fence verification is not itself proof that ElXray has drained a particular device's flows. Core-generated drain receipts, unique profile-to-device bindings, ongoing accounting scheduling, FUP delivery to every node, and automatic period rollover must be integrated and tested before paid production traffic. Current command `collect-usage` requires a pre-provisioned trusted source assignment. Never infer device identity from an IP address or a copied subscription URL.

Do not merge this branch or deploy as a finished business service solely on the basis of unit tests. All local and GitHub Actions test results should be inspected first.
