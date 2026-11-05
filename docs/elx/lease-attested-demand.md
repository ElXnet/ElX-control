# Signed core lease acceptance in rate-demand telemetry

Only a *live, pinned ElXray core* can attest that a Control-signed subscription lease was actually installed into the enforcing token limiter. The preceding Control ticket, policy RPC ACK, device subscription URL, and a node-controlled boolean are not valid demand-authority evidence.

## Transport and journal

The existing mTLS `elx.node.v1.SignedAccounting` challenge/submit cycle carries three independently signed records on the **same** server-issued, single-use nonce:

- `elx-usage-bin`: mandatory billable FUP counters.
- `elx-pressure-bin`: optional per-direction limiter pressure, with core incarnation/sequence/revision.
- `elx-lease-accept-bin`: optional 88-byte core-accepted lease receipt plus Ed25519 signature, tied to node, incarnation, lease sequence/expiry, upload/download ceilings and actual policy rates.

ElXray only produces the third proof when its verified Control-signed lease is installed and still allows VPN admission. Control accepts a proof only when the mTLS certificate node, pinned core signing key, bound subscription, challenge, core incarnation, current policy, committed grant and reported pressure agree.

In PostgreSQL migration `020_lease_acceptance.sql`, `elx_rate_lease_acceptances` stores this proof's verified lease expiry and the **exact latest signed pressure sequence**. Usage, pressure and lease acceptance are verified and saved in one transaction along with consumption of the server nonce. Invalid signatures roll the entire submission back. An older agent or core can still send billable FUP usage without the new optional proofs; it never gains a positive demand signal from that.

`journal.PreviewDemand` requires a currently valid, no-more-than-10-second-old acceptance record for exactly the signed pressure sequence, a live entitlement, a nonrevoked core, matched policy revision and committed upload/download rates, and no pending rate move or takeover. Any absence or mismatch is treated as frozen, never unused capacity. After verified core replacement, rotation deletes old pressure and accepted leases within the same transaction.

## Scheduler boundary

The preview is intentionally **read only**. Although it now requires accepted core lease evidence, a production scheduler must ensure the read-to-queue gap cannot authorize a stale grant (recheck authority inside the rate journal transaction, serialize with policy and FUP), enforce leader fencing across Control replicas, and preserve reduce-before-increase signed barriers. Until those conditions and network tests are met, do not automatically enqueue rate moves. Never interpret `rate=0` as a customer-selected unlimited rate.
