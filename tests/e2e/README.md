# ElX cross-repository test harness

The checkout layout is fixed and explicit:

```
D:\ElX-test\
  ElX-control\
  ElXray\
  ElX-ui\
```

From PowerShell:

```powershell
cd D:\ElX-test\ElX-control

# Update all three clean main branches and run the PostgreSQL-backed
# Control + ElXray race/unit/integration and live two-node VLESS tests.
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-elx-windows.ps1 -Workspace "D:\ElX-test" -Distro Ubuntu

# Full local verification, including ElXray's entire Go tree and runtime
# benchmark, and ElX-ui's full make verify / race / node-e2e / vulncheck.
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-elx-windows.ps1 -Workspace "D:\ElX-test" -Distro Ubuntu -Full
```

The `-Full` option needs WSL Ubuntu, Docker Desktop WSL integration, Go,
Python 3, gcc, Git, OpenSSL, make, **Node >= 26**, npm, and **golangci-lint**.
The frontend dependency installation and vulnerability checking require
network access. The full runner exits nonzero for missing prerequisites or
failed steps; it does not silently downgrade to a reduced suite.

## Live E2E acceptance scope

`tests/e2e/test_multinode.py` is started by `scripts/elx-test-local.sh`.
It creates its own CA, keys and certificates, tests **two different ElXray
processes** with independent VLESS inbounds and SOCKS client processes, and
a **real Control mTLS server and two autonomous node agents**. All data
sockets bind only to localhost. PostgreSQL is disposable by default: the
wrapper starts `postgres:18` in Docker, with a random host port, and
removes it afterward. Do not supply a production Control DSN.

Assertions:

1. Real VLESS traffic on both independent nodes, signed counters from the
   correct core key, rejection of the other node's key.
2. Unauthorized client certificate and valid node certificate pointed at
   the wrong core cannot consume another node's queued operation.
3. A conflicting reuse of the same operation ID is rejected.
4. Control agents deliver different rate policy revisions to both cores.
   Already established connections continue to transfer data after a
   **non-disabling** rate reduction.
5. Disabling one node's subscription closes its established connection,
   prevents new payload, and leaves the second node connected.
6. Restarting the disabled core retains its disabled revision and
   generates a new signed incarnation.
7. Concurrent independent VLESS client connections pass through both cores.
8. A simulated Control-to-agent transport partition leaves established VPN
   traffic alive, does not apply unreceived commands, and delivers a queued
   policy after Control returns.
9. Restarting Control does not lose the command journal; re-enabling the
   disabled subscription restores traffic on both nodes.

The E2E is a reproducible loopback acceptance scenario, not a benchmark
for WAN latency or commercial VPN throughput. Control rate allocation uses
a **single purchased per-entitlement budget**, but this test only applies
explicit per-node journal policy changes; it **does not** prove a pooled
bandwidth budget under concurrent measured network load. Budget safety,
signed accepted leases, rate-barrier finalization and leader fencing are
separately tested by PostgreSQL-backed journal tests.

**Remaining P0 acceptance gates:** active-slot accounting with two actual
clients and copied subscriptions; end-to-end rate-scheduler throughput
under simultaneous upload/download on both nodes; packet loss and
partition/failover of Control/Postgres and their leader epochs; hardware-
specific TUN/Vision/UDP behavior; load and soak testing with up to 200 users.
Those checks must not be marked passed merely because this script is green.


## P0 two-node saturation and disruption suite

`test_rate_partition.py` is run immediately after `test_multinode.py`
by the same local/CI suite. It boots a disposable independent test lab
with **two real ElXray cores, two VLESS/SOCKS clients, two Control agents
and PostgreSQL**. Both clients send and receive sustained traffic at once.
Their explicitly allocated upload and download grants sum to 300,000 B/s
per direction and the measured combined rate must stay below 125% of
that ceiling. The 25% allowance is a deterministic test tolerance, not an
allowed commercial tariff oversubscription; token buckets permit an
initial 8192-byte burst per node.

The same scenario stops the Control mTLS service, queues durable policy
changes in PostgreSQL, checks the agents cannot apply them while the
authority is unreachable, and confirms both agents apply the correct
revision after restoration. It also checks that a Control instance
pointed at an unavailable PostgreSQL endpoint refuses to become an
alternate policy authority.

The PostgreSQL test `TestTwoDeviceSlotsAcrossNodes` concurrently
reserves two device ownership slots from **two distinct device keys on
different nodes**, rejects third/fourth devices, refuses to free an
occupied slot on a mere revoke request, requires an exact core-signed
fence, and races two replacement devices for the one released slot.

**Do not confuse these tests with a completed P0 deployment acceptance:**

- The bandwidth test checks enforcement of allocated per-node grants
  under real traffic. It does **not** wire signed pressure evidence and
  leases into the automatic multi-node demand scheduler. Scheduler
  atomicity and signed rate barriers are covered separately by journal
  integration tests. End-to-end scheduler auto-reallocation remains open.
- The signed-slot test exercises Control admission and ownership, not
  the integration of a running remote device's VPN handshake with
  `ReserveWithProof`. No **physical two-PC acceptance** is asserted.
- The ordinary `test_rate_partition.py` outage test runs **without mandatory Control leases**: established VPN flows deliberately remain connected while Control is unreachable. A **separate** `test_lease_partition.py` provisions actual PostgreSQL-backed grants for both cores and turns on mandatory signed Control leases. It must demonstrate both nodes deny traffic before a valid ticket, expire and close idle flows after a Control outage, deny new payload, and accept only fresh VPN connections after signed renewal. These are different and complementary modes.
- A non-responsive PostgreSQL listener is a control-plane startup
  failure, not a real cluster split-brain / packet-loss test. Repeated
  leader election and stale epoch rejection are checked in dedicated
  journal tests; full network partition and takeover remain open.

All these remaining gates must stay visible in the release report.

### Mandatory signed lease partition E2E

`test_lease_partition.py` starts the same two-core lab with
`ELXRAY_REQUIRE_CONTROL_LEASE=1`, configures separate per-node mTLS
manifests, creates a private Control lease-signing seed and uses the
**test-only** Go fixture `tests/e2e/seed_lease.go` to install two
PostgreSQL rate grants with exact pinned core incarnations and signing
keys. Control then issues real fifteen-second Ed25519 leases to the
autonomous agents. The test deliberately drops the Control listener
for eighteen seconds, asserts that both existing idle VLESS flows are
terminated and new traffic rejected, then restarts the *same* signing
authority and requires new VPN handshakes to succeed.

This test proves signed lease expiry on a local-loopback service outage;
it does not exercise physical WAN loss, asymmetric packet loss,
multi-master replication, or a database failover from one primary to
another. The offline device and FUP admission behavior still requires
a multi-client deployment acceptance run.


## Full suite on machines with restricted public Internet

The legacy `-Full` runner previously called `go test ./...` without
preparing Xray's geodata files and without isolating tests that dial
Cloudflare/Google/other external DNS endpoints. This could fail in WSL NAT
even when the ElX Control + ElXray real loopback E2E was green.

`scripts/elxray-full-go-tests.sh` now downloads `geoip.dat` and
`geosite.dat` using the **same sources and SHA-256 verification** as
ElXray's own GitHub CI. It then runs all deterministic Go tests, with the
exact network-dependent test names printed as a `SKIPPED` pattern.
This is a *reduced*, explicitly labelled gate, NOT a claim that every
upstream test was executed.

To opt into live public Internet ECH/DNS/REALITY tests during `-Full`:
```powershell
$env:ELX_EXTERNAL_NETWORK_TESTS = "1"
# This environment variable must also reach WSL. Prefer running from WSL:
```
```bash
ELX_EXTERNAL_NETWORK_TESTS=1 bash scripts/elxray-full-go-tests.sh ../ElXray
```
The local Windows launcher does not automatically pass custom Windows
environment variables into WSL: execute that command inside Ubuntu or
set `WSLENV=ELX_EXTERNAL_NETWORK_TESTS/u` in Windows before launching
`-Full`. In either case these public tests may fail from blocked network
paths, and their failures remain failures.
