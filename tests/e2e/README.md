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
7. Restarting Control does not lose the command journal; re-enabling the
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
