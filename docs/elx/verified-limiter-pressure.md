# Signed limiter-pressure ingestion

ElXray generates `elx-pressure-bin` under a fresh 16-byte, lowercase-hex challenge, signs the 120-byte binary evidence with the core's durable Ed25519 key and appends the 64-byte signature. `corepolicy.ReadPressure` generates its own unpredictable challenge and validates the local response. `corepolicy.VerifyPressureEvidence` verifies pinned identity, signature, subscription, challenge, revision, timestamp freshness, limits and directional counters; `ValidatePressureProgress` rejects replays and core restarts without reconciliation.

## Authenticated node → Control transport

The existing FUP `SignedAccounting` mTLS channel is extended, not replaced.

1. Control authenticates the node certificate, binds it to an assigned accounting stream, a core incarnation and a purchased grant, and generates the existing server-side nonce.
2. The node retrieves its ordinary signed FUP usage sample (`elx-usage-bin`) **and**, when the core supports it, the separately signed `elx-pressure-bin` record using the SAME nonce.
3. `usagetransport.PollOne` submits both as one message over authenticated mTLS. A core without signed pressure continues to submit FUP usage; this produces **no** trusted rate demand.
4. Control checks the assigned node, subscription, pinned core signing key and nonce under the existing database transaction. It accounts billable usage and validates pressure in the SAME transaction; an invalid signature rolls back both.
5. Under the entitlement's budget lock, Control only records a pressure sample if the source maps to a provisioned `(node_id,resource_id)`, no rate move is pending, and the core's reported upload/download policy matches the **committed** grant. Missing/mismatched observations are frozen/unknown rather than proof of free speed.
6. `elx_rate_pressure_samples` (migration 018) persists the latest signed sequence, core incarnation, revisions, rates, independent counters and receipt time. A duplicate/regressed report or unapproved core restart fails closed. The journal transaction consumes the nonce atomically with both reports.

This does **not** let a VPN subscription URL or external HTTP client manage, submit or invent device usage.

## Next integration

The verified remote accounting + pressure ingestion now exists, but **automatic rate scheduling is not enabled**. The remaining scheduler must read these durable samples under the entitlement lock, require fresh successful Control leases and a confirmed core revision, compute bounded directional demand from adjacent counter deltas, smooth it to avoid oscillations, and call `journal.RebalanceDemand` one operation at a time. A stale/missing sample is frozen, not a zero-demand observation.

The sample table contains the latest high-watermark only, not a time-series. To measure a rate, the scheduler must persist a previous accepted sample separately or the table must be extended with a short history. Do not infer throughput by dividing a single lifetime payload counter by wall-clock time.

Core reductions can only release global allocations after signed rate barriers, and the policy must be enforced by a healthy core lease. No production multi-node performance guarantees follow from these component tests alone.
