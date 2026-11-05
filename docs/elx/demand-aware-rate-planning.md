# Demand-aware rate allocation and journal reconciliation

ElX Control owns the global upload and download budgets. All rates are **bytes per second**. Each direction is independently constrained. A disabled local policy is represented explicitly by `disabled=true`, not by Xray's historical `rate=0` (unlimited).

## Implemented

- `allocation.PlanRebalance` calculates independent weighted max-min targets for trusted node/resource grants. A target ID is an internal identifier for the journal's `(node_id, resource_id)` pair, **not** a physical device.
- `journal.RebalanceDemand` takes the effective purchased/FUP cap under the existing entitlement row lock, reads durable committed grants and pending operations, and queues **at most one** operation through `QueueRateMove`.
- Disabled or expired entitlements are refused by the reconciler; their revocation is handled by the separate signed drain workflow. Incomplete operations block further planning. Missing, expired, unleased, rotating, and zero-demand observations freeze the grant at its already committed allocation; no capacity is silently reclaimed.
- The first cycle queues reductions only. Later cycles require a new locked snapshot, and increases are queued only when the journal's signed rate barrier has been applied/finalized. A transport ACK alone does not free capacity.
- `QueueRateMove` remains the final authorization gate, validating budget, revision and competing grants while committing the operation atomically. A concurrent writer or new FUP reduction turns a stale proposal into a safe `waiting` result.
- PostgreSQL tests exercise two-phase move, replay before proof, unknown/stale demand, tightening budgets and invalid target inputs.

## Reconciliation cycle contract

The trusted scheduler obtains a short-lived per-target demand observation `journal.RateDemand`. This must come from **mTLS-validated, lease-checked telemetry**. `LeaseValid` is an assertion by the privileged collector, not a remotely supplied boolean or public API permission.

Each observation includes target identity, upload/download requested rate, fairness weight, timestamp and lease status. Observations older than ten seconds, more than two seconds in the future or lacking a valid lease are treated as unknown. A missing observation is also unknown. Unknown or pending grants keep their full committed allocation. A zero demand means the VPN may simply be idle: it does **not** authorize disconnecting it.

Call `RebalanceDemand(ctx, db, entitlementID, observations)`. Interpret its result:

- `lower`: a rate reduction was queued in the existing journal; poll it through authenticated node delivery, require durable readback **and a signed ElXray reduction barrier**, then finalize.
- `waiting`: an earlier operation is pending or a concurrent change invalidated the snapshot; do not automatically reuse its previously committed budget.
- `raise`: a rate increase was queued; core application and durable journal finalization are still required.
- `stable`: no operation was necessary for the current snapshot. It does not mean every target is reachable; check `FrozenTargets` and `FrozenOverBudget`.

Repeat only with fresh observations and a **new** journal snapshot. The scheduler must not execute the returned plan's old `Raise` list without resnapshotting. The function does not communicate with the nodes itself.

## Boundaries and unfinished integration

This is the **durable single-operation reconciliation mechanism**, not a running autonomous production scheduler. The authenticated node collector, limiter pressure/demand estimator, smoothing and hysteresis, schedule loop, core/connector accounting and long-duration multi-node failure tests still need implementation and wiring.

The current global journal budget is per node/resource, not per device. An additional verified device-bound enforcement layer is needed so that one VPN installation cannot acquire more device slots, while a router consumes one. No new grant is created by this function; provisioning the core/grant baseline and its trust anchors remains a prerequisite.

Before production acceptance, verify multi-node real traffic, demand spikes, simultaneous FUP activation, lost ACK/barrier, core restart and rollback, network partitions, lease expiry and recovery, multi-process connector budgets, and concurrent independent scheduler instances. Do not claim strict global enforcement solely from a green Go test run.
