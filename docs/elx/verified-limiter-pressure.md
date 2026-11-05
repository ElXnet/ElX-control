# Verified ElXray limiter-pressure reads

`corepolicy.Client.ReadPressure(ctx,subscription,pinnedKey)` generates a fresh random challenge and reads `elx-pressure-bin` from the protected local ElXray gRPC socket. `VerifyPressureEvidence` validates the exact 184-byte Ed25519-signed record specified by ElXray `docs/electrium/SIGNED_PRESSURE_EVIDENCE.md` and rejects malformed values, future timestamps and samples older than ten seconds.

A sample includes the ElXray core incarnation, per-subscription sequence, policy revision, configured upload/download rates, cumulative payload bytes, blocked call counters, blocked nanoseconds and instantaneous waiter gauges. It is **not** the client's HWID, not proof of a leased node and not authorization to increase a grant.

`ValidatePressureProgress(previous,next)` requires that the same already-pinned core incarnation produces a strictly newer sequence and timestamp with nondecreasing revision, payload and saturation counters. If a new boot appears, the caller must stop and reconcile the durable node identity before accepting its counters. The *calling* scheduler must persist the last accepted high-watermark in PostgreSQL and compare it under the entitlement lock. In-memory state alone is not sufficient across multiple Control instances.

Next integration: relay this evidence alongside existing usage over the authenticated node transport; verify source node and journal `(node_id,resource_id)` assignment and `policy revision`; store high-watermark transactionally; compute a bounded requested rate from consecutive signed deltas, lease status and purchased FUP limit. Unknown, expired, unleased, stale, incomplete or monotonicity-violating evidence must result in a frozen allocation. Never expose a client-controlled `LeaseValid` flag or use an unverified sample as input to `journal.RebalanceDemand`.

**No automatic scheduler is activated by this PR.**
