# Leader-fenced demand-aware rate scheduler

The `elx-control serve-scheduler` foreground command continuously reconciles independently purchased per-entitlement upload and download **byte/second** budgets. It shares the existing signed Control journal; it never changes an ElXray rate on its own. A node agent applies the pending policy revision, Control validates the signed core readback, and **a lower rate does not release capacity** until the distinct signed rate barrier is finalized.

## Authorization invariant

Each scheduler pass does **all** of the following under the same PostgreSQL entitlement rate-budget row lock:

1. Validate a live, current `elx_rate_scheduler_leaders` epoch, held by this process. Acquiring after expiry increments the epoch, even for the old holder. PostgreSQL time is authoritative.
2. Recompute purchased and applied FUP limits and read **two** signed, monotonic core pressure samples from the pinned incarnation and policy revision.
3. Require the exact same latest pressure sequence to have a fresh, core-signed **accepted** Control lease (not a merely issued ticket) with matching node, core key, effective policy, positive rates and no pending migration/rotation.
4. Plan independent upload/download shares. Missing, stale, unbound or lease-less targets remain frozen at existing commitments. Ignore HTTP, subscription-client and user-supplied demand/lease flags.
5. Recheck the live leader epoch against a fresh PostgreSQL timestamp and queue **at most one** journal operation **before committing** the transaction. There is no planning-to-enqueue unlock gap. Queueing still enforces the locked FUP budget, operation revision and conservative pending-rate reservations.

If a prior decrease has not finalized its signed core barrier, no subsequent increase can reuse those bytes/second. After a new core incarnation starts, it needs new pinned signed measurements and a new accepted lease. Loss of leader epoch or database connection fails closed.

## Operation

The process is **disabled unless explicitly enabled**. Do not enable it for paying users until multi-node VLESS/Vision/UDP/TUN throughput, crash/restart, FUP rollover, session takeover and network partition acceptance checks pass.

```bash
# Same DSN and migrations as other Control services.
export ELX_CONTROL_POSTGRES_DSN='postgres://USER:PASS@127.0.0.1:5432/elx?sslmode=require'
export ELX_RATE_SCHEDULER_ENABLED=1
elx-control serve-scheduler -interval 5s -leader-ttl 15s
```

Each running process chooses a new random UUID leader identity; do **not** configure identical shared identities across replicas. The PostgreSQL leader epoch is per entitlement; two Control replicas may run concurrently, but only one can queue for an entitlement. A restart waits until an existing token expires, then takes over with a higher epoch. Operations already queued remain journal-owned and idempotent.

For a Windows/WSL test with PostgreSQL, use the repository's `scripts/run-elx-windows.ps1` or run:

```bash
export ELX_TEST_POSTGRES_DSN='postgres://...'
go test -race ./internal/elxcontrol/journal ./internal/elxcontrol/allocation ./internal/elxcontrol/scheduler
go test ./internal/elxcontrol/usagetransport ./internal/elxcontrol/accounting
```

No automatic rate granting is started by simply compiling Control or running the customer cabinet. The scheduler is a separate supervised service and must use a restricted database role. Test the network paths on two Windows clients/WSL before a VPS rollout; these PostgreSQL tests are not proof of wire-speed fairness or zero burst.

## Limitations

- Expired or unsupported lease proof means **frozen**, not zero speed.
- Token buckets allow a small bounded burst and cannot promise mathematically zero transient wire overshoot.
- Dynamic balancing is within one entitlement's purchased rate budget and strict FUP; a global infrastructure QoS policy for the sum of all entitlements is separate.
- The scheduler does not identify a device by HWID, IP or copied subscription URL. Device active slots are handled by the separate signed session-owner subsystem.
- A single sweep intentionally fails if more than 10,000 entitlements are active; pagination and load testing are required before exceeding that bound.
