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

## Operator-only read-only technical reconciliation audit

With access to the Control primary PostgreSQL, an operator may run:

```bash
elx-control inspect-technical-recovery <canonical-node-uuid>
```

A PostgreSQL integration test runs the operator inspection against a
disposable isolated schema through a **read-only** database connection.
It confirms node-scoped INTENT selection, expired/future classification,
redacted output, preservation of the original operation states, and
fail-closed behavior for an over-128 backlog (no partial JSON).

This produces a bounded JSON view of up to 128 central `INTENT`
PREPARE/INSTALL/RETIRE operations. It includes operation/profile/resource/
executor UUIDs, Control phase, grant expiry and a **suggested investigation
step**. It never returns emails, secret keys or signed payloads. More than
128 unresolved operations fails visibly instead of silently truncating.

`read_only_core_proof_probe` is a possible next inspection, **NOT** proof
that the core installed/retired the profile. No Control `APPLIED` status,
device owner admission, rate grant, UUID reissue, or VLESS mutation occurs.
An interrupted core `INSTALLING`/`RETIRING` remains quarantined until
independent evidence and an explicitly approved recovery procedure exist.
The report sees Control's phase only; it cannot establish core state
without the separate authenticated core readback.

## Paired-source E2E preflight and signed scheduler diagnostics

The Control checkout and ElXray are **siblings** in GitHub Actions.
ELXRAY_SOURCE points to the *same* ElXray module as ELXRAY_BIN, also
under the separate nobody-UID Unix peer-credential agent. A pure Python
preflight rejects an unrelated module, missing checkout, accidental nested
checkout and Control checkout as its core source before expensive tests.

Scheduler/FUP failure now prints a disposable PostgreSQL snapshot of
committed rates, pending reservations, operation status and revisions.
INTENT is never inferred to be APPLIED. This corrects the earlier
"matching Stage-4 ElXray module is required" fixture failure, NOT
the still-unproven two-core reduce/barrier/raise E2E scenario.

## Two-real-core static-JSON admission regression

Technical mode requires a stable nonempty VLESS inbound tag: an
untagged or ambiguous inbound must **fail startup closed** rather than
becoming a payload-admitting static fallback. The shared older E2E fixture
created untagged VLESS JSON; the Stage-4-specific disposable test now
pins an explicit unique tag on each node. Separate fast Python tests
reject missing, duplicate and oversized tags without changing core rules.

The disposable \`test_stage4_static_bypass.py\` exercises two real
managed ElXray nodes with protected Unix peer credentials and PostgreSQL
Control lease agents. It checks that the *preconfigured* VLESS JSON
identities remain non-admitting when Stage-4 technical provisioning is
enabled, before and after signed lease delivery. It then restarts node
zero with the same static configuration and journal: restart may
conclusively fail closed, or succeed with continued payload denial.
A live unsigned or orphan connection is never counted as acceptance.

This is a deliberately negative test, not proof that owner/device
authorization exists. It does not substitute for positive signed
PREPARE/INSTALL/RETIRE proof or live hot reload/multi-inbound alias tests.

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

## 2026-11-11: exact-head two-core lifecycle PASS and pending lost-ACK fault injection

The Stage-4 positive real-core PostgreSQL lifecycle gate passed in Control
workflow [#43019083443](https://github.com/ElXnet/ElX-control/actions/runs/43019083443)
for Control `e91267f` + paired ElXray `0f0f3f8`: **4 of 4 CI jobs PASS**.
The suite verifies two independently pinned core/store/boot identities,
Control-signed PREPARE → INSTALL → RETIRE, live VLESS UUID no-payload admission,
PostgreSQL APPLIED proof, durable journal tombstones, and unchanged purchased
bandwidth and owner/device slot reservations. This is not physical device
authorization and does not cover interrupted INSTALLING/RETIRING by itself.

A new **pending/not yet passed** test `test_stage4_lost_ack.py` extends
real-core testing with a disposable SQL confirmation row lock. It lets an
authentic signed INSTALL finish in ElXray without letting its signed Control
ACK commit; the original operation then expires. A fresh agent is expected to
read only the immutable terminal journal evidence, obtain a new independently
signed core recovery receipt, and commit the original PostgreSQL INTENT.
The runner tests failure closed if the ACK accidentally committed or a new
operation was invented. The agent now attempts recovery before stale PREPARE
retries so a finished, unacknowledged installation is reconciled first.
No real PostgreSQL instance or production API accepts the test helper.
CI on the exact new head is **PENDING**; this does not close the separate
RETIRED lost-ACK, interrupted-operation, alias/rotation, or hot-reload gates.

## Stage-4 hardening batch — 2026-11-11 (NOT YET PUSHED/VERIFIED)

The paired core adds a global normalized-UUID preflight for signed INSTALL
across every running VLESS inbound. A foreign static UUID alias, exact UUID
in a different inbound, target email collision or malformed validator
refuses installation before writing INSTALLING. A second all-inbound snapshot
must match exactly one live installed user before INSTALLED is persisted,
and signed retire/read-only recovery refuse shadow aliases.
This does NOT turn a prepared/installed technical UUID into admitted VPN traffic.

Control's independent signed store witness previously omitted technical
RETIRE tombstones (it considered only session-owner drain generations).
It now includes the maximum persisted denial generation from both session
owners and durable Control RETIRE intents, including still-INTENT lost ACKs.
A lease before the core commits the corresponding tombstone is intentionally
refused; after the core records it, the independent HWM must agree.
Fresh-UUID re-provisioning under the same email follows a signed RETIRE,
never a reused old effective UUID, owner slot or budget grant.

New mandatory tests: real two-core cross-inbound shadow INSTALL denial;
replacement on both real cores; isolated PostgreSQL witness digest regression.
All tests run only on disposable local resources. This batch is pending
exact paired-head CI; do not assert PASS, merge, or deploy yet.

## Operator crash-forensics gate and stale static rollback acceptance (pending)

The paired core now includes `cmd/elx-technical-inspect`: read-only,
fail-closed offline verification of the durable journal plus anchor against
an independently obtained Control store, exact profile and original
operation ID. `-require-terminal` rejects `INSTALLING`/`RETIRING`
rather than guessing AddUser/RemoveUser outcome or mutating the ledger.
`docs/elx/stage4-operator-recovery.md` states isolation and evidence
requirements. It **does not** implement an independently attested abort
that could release a pending Control INTENT: that remains a P0
security/functionality blocker.

The two-core real VLESS lifecycle gate also attempts a stale static UUID
alias after the original profile was signed-RETIRED and re-provisioned with
a fresh UUID. Managed core startup may refuse or the live data plane must
deny both stale and new VLESS traffic without device owner proof.
CI still NOT RUN on this staged exact paired head.

## 2026-11-11: durable operator-quarantined incident (new, not CI-verified)

Migration 027 adds an irreversible Control node quarantine record bound to
the exact unresolved technical `INTENT`, original operation/profile,
independently pinned store ID and a SHA-256 digest of an archived offline
inspection. An administrator must first isolate the physical node and
archive journal+anchor and the separate Control store witness, then invoke
`elx-control quarantine-technical-node` with matching
`--node --resource --profile --operation --store --phase --evidence-sha256
--operator --confirm-node --physically-fenced`.
The operation is **not** a core proof: it never promotes an uncertain
INSTALL/RETIRE to APPLIED, releases purchased capacity, reuses the UUID or
permits VPN payload. Exact retries are idempotent; conflicting incident
data is rejected. A quarantined node cannot receive a new Control-signed
store witness, technical grants, installs, retires or automatic recovery
deliveries; signed confirmation paths also refuse the frozen operation.
The inspection API reports `nodeQuarantined` and directs operator review.

This is a fail-closed safety state, not a distributed proof that the node is
physically off. The CLI acknowledgement cannot replace external fencing,
revocation of cached leases, backed-up evidence or audited authority.
Definitive replacement/rebootstrap under a NEW store and independent
node identity still requires explicit decommission design and tests.
No production deployment is authorized. Exact paired-head CI pending.
