# Stage 4 — technical VLESS provisioning acceptance ledger

Paired draft branches:
- [ElXray PR #22](https://github.com/ElXnet/ElXray/pull/22)
- [ElX-control PR #23](https://github.com/ElXnet/ElX-control/pull/23)

**Status: IN_PROGRESS. Not TESTING, not DONE. Do not merge, deploy, or enable
`ELXRAY_TECHNICAL_PROVISIONING=1` in production.**

## Scope and safety invariants

Stage 4 provisions, installs, retires and recovers a *technical* VLESS account
via separately signed Control operations; technical UUID is not proof of a
physical device, session ownership or permission to send payload. Admission
requires later owner/device proof and is deliberately denied at this stage.
Control never frees a paid bandwidth grant or device slot solely on an
INSTALL/RETIRE receipt.

All operations require exact node/resource/executor, authority generation,
immutable PostgreSQL intent, and independent core/Control Ed25519 identities.
ElXray validates an effective VLESS UUID alias (not only the printed UUID)
and permanently tombstones retired identities.

## Implemented in draft, pending system acceptance

| Item | Implementation | Evidence needed |
| --- | --- | --- |
| Signed v1 PREPARE | Durable Control reservation and core PREPARED journal | Two-core PostgreSQL and protected socket E2E |
| Signed v2 INSTALL | Dedicated mTLS dispatch; core INSTALLING -> live AddUser/readback -> INSTALLED; pinned core proof, transactional Control APPLIED | Real inbound, crash, duplicate/replay and deny-payload E2E |
| Signed v2 RETIRE | Durable tombstone before live RemoveUser, session fence/drain, independently pinned core proof and Control retired APPLIED | Multi-inbound aliases, live sessions, reload/rollback/restart E2E |
| Safe boot rehydration | Restores exact INSTALLED technical users, never PREPARED/RETIRED; unresolved mutations block managed boot | Store/boot identity, static JSON and crash fault-injection |
| Expired lost-ACK | Read-only RecoverInstalled/RetiredProof from immutable local journal; mTLS-scoped Control pending-ID poll | PostgreSQL commit ambiguity, node crash and foreign proof E2E |
| Rate scheduler | Signed core telemetry, leader lease, budget-reserved lower/barrier/raise | Real two-node redistribution test currently FAIL |

## Confirmed CI evidence and active defect

ElXray stage-4 head `a2bec607` passed all six workflows before
the follow-up change to distinguish core lease ceiling errors.
**Do not reuse those green checks for the new head**.

Control CI run 42906827660 failed `local-suite`: the scheduler durably
reserved a node-0 `lower`, but both live core policies remained revision 1.
Go, PostgreSQL, signed telemetry, partition and lease-expiry checks passed
up to that operation. The follow-up run 42919971143 proved Control's
agent was repeatedly reclassifying any core `ErrUnauthorized` as a
retryable signed-ceiling shortage, silently leaving the operation INTENT.

The paired draft code now gives a *separate* `ErrLeaseCeiling` marker only
when a fresh signed speed ceiling can actually help, while malformed
operation identity, executor, generation, digest and signature remain
non-retryable PermissionDenied. Control retries only that narrowly defined
marker; a retry never creates a local grant or central APPLIED. Positive
and negative unit tests were added on both sides. **Exact-head CI is
still pending**. A disposable E2E-only diagnostic switch logs rejected
scope predicates as booleans, never keys, signed payloads or IDs.

## Real implementation gaps before TESTING

1. Make interrupted `INSTALLING` / `RETIRING` recoverable by a safe,
   operator-authorized reconciliation or explicit quarantined re-provision,
   never by guessing that the VLESS mutation succeeded or undoing tombstones.
2. Enforce and test profile replacement/UUID rotation as explicit signed
   RETIRE + fresh PREPARE/INSTALL, including conflict during live traffic.
3. Prove global no-bypass under static JSON, hot reload, duplicate Control
   writers, rollback and effective-UUID aliases across all inbounds.
4. Implement and pass real two-core PostgreSQL acceptance for the complete
   technical lifecycle, expired signed job/lost ACK, restart and failover,
   plus fault injection for durable journal writes and ambiguous DB commits.
5. Full Go/race/vet/format and platform CI on **the exact same paired SHA**.

## Workflow

`IN_PROGRESS` (functionality or tests incomplete) ->
`TESTING` (complete implementation undergoing acceptance) ->
`DONE` (all P0 gates passed). A FAIL or NOT RUN is never PASS.
Do not merge until the complete paired-head gate is green and verified.
