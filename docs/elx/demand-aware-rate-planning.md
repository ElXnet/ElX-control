# Demand-aware rate planning contract

ElX Control owns the global upload and download budgets. Every amount is a signed 64-bit **byte-per-second** rate. Upload and download are independent, and a local grant is either positive in both directions or fully disabled. A zero rate is **not** sent as Xray's legacy unlimited setting.

## Existing authority

`journal.QueueRateMove` is the only durable rate reservation path. `journal.FinalizeRateMove` releases reduced commitments only after the policy journal has an applied receipt and the pinned ElXray instance has signed the exact rate barrier. A successful transport ACK alone cannot free a rate commitment. The agent must check readback against the pinned core identity.

`allocation.PlanRebalance` is a **pure planning function**, not an authorization API or an automatic runtime scheduler. It accepts the effective purchased/FUP budget and a current, trustworthy snapshot of device commitments. `Current` means the maximum committed/pending/unknown amount, **never measured usage**. If either direction is unknown or the core has lost contact, the entire grant is marked `Frozen`. Its existing commitment stays charged. Missing grants must not be interpreted as released.

`Requested` is the demand estimator's bounded target, considering observed throughput, limiter wait/saturation, user-device cap and entitlement. `Weight` is positive and bounded. Neither measurement nor a request authorizes rate increases.

## Transitions

A plan has `Lower`, `Raise`, `Target` and `FrozenOverBudget`.

1. Persist the snapshot's version and proposed intent. Recheck the entitlement and every target revision under the entitlement lock.
2. Enqueue `Lower` only. For each reduction, wait for durable core readback, signed drain/barrier, and journal finalization.
3. Re-snapshot all grants and recompute `PlanRebalance`; the old `Raise` list is **only a proposal**, never an executable authorization. Do not increase using a stale plan.
4. Only then use `QueueRateMove` for newly affordable increases; recheck FUP/entitlement, target revision, pending moves and core incarnation for each individual operation.
5. After any timeout, duplicate request, new core boot, or leadership change, reconcile the journal before scheduling another change. A lost ACK does not imply free capacity.

If frozen reservations already exceed the current effective budget, the planner proposes reductions of mutable grants but suppresses increases; it cannot revoke an unknown core or falsely claim strict compliance. An operator or safe fencing/lease expiry must resolve the oversized frozen reservation.

## Additional implementation required

This change implements the side-effect-free planner with deterministic tests. A long-running scheduler must still obtain authenticated measurements, estimate and smooth demand, persist idempotent operations and revisions, enforce the above phase barrier, handle multi-process connectors, and provide multi-node integration/load tests. Do not advertise an active global demand-aware limiter until that scheduler and real core enforcement have passed the failure matrix.

Mandatory tests for the end-to-end scheduler: two saturated nodes, one idle node requesting more, independent upload/download, 50+50 to 30+70 with a lost ACK, simultaneous admissions, stale revisions, unknown node, FUP activation mid-transition, core restart with lower persisted cap, and Control outage.
