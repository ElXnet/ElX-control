#!/usr/bin/env python3
"""P0: core-signed pressure -> Control scheduler -> journal -> agents -> VLESS.

Runs against a disposable PostgreSQL lab and two real loopback ElXray cores.
Does not claim actual Windows device, WAN, Vision or UDP acceptance.
"""
from pathlib import Path
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid

from test_multinode import command, read_exact, require, wait_for
from test_lease_partition import LeasedLab, eventually_live
from stage4_workspace import stage4_core_source

BLOCK = b"v" * 4096

class JournaledSchedulerLab(LeasedLab):
    """Two real managed cores with the Stage-3 durable operation journal.

    Earlier CI only enabled ELXRAY_MODE=managed, but omitted the core
    journal. Its agent then sent a managed operation to a node that could
    *never* accept the operation-bearing RPC. Preserve the production
    requirement instead of downgrading the core or suppressing the failure.
    """

    def __init__(self, folder):
        super().__init__(folder)
        self.store_ids = [str(uuid.uuid4()) for _ in range(2)]
        self.journals = [folder / f"node-{i}-operations.json" for i in range(2)]
        core_repo = stage4_core_source(__file__)
        self.core_repo = core_repo
        runner = subprocess.run([
            "go", "run", "-tags=elx_e2e_provision", str(Path(__file__).with_name("provision_managed_core.go")),
            self.resource_id,
            str(folder / "node-0-state.json"), str(self.journals[0]), self.store_ids[0],
            str(folder / "node-1-state.json"), str(self.journals[1]), self.store_ids[1],
        ], cwd=core_repo, env={
            **os.environ, "ELX_STAGE4_E2E_DISPOSABLE": "1",
        }, text=True, capture_output=True, check=False, timeout=120)
        require(runner.returncode == 0,
                f"managed core journal provisioning failed: {runner.stderr[-1800:]}")

    def env(self, *, node=None, cert=None):
        env = super().env(node=node, cert=cert)
        if node is not None and hasattr(self, "journals"):
            env["ELXRAY_OP_JOURNAL"] = str(self.journals[node])
            env["ELX_AGENT_STORE_WITNESS_REQUIRED"] = "1"
        return env

    def seed(self):
        super().seed()
        for i in range(2):
            # An administrative baseline pinned independently in PostgreSQL
            # is mandatory before the first short-lived lease with a journal.
            fixture(self, "witness", self.node_ids[i], self.resource_id,
                    self.executor_ids[i], self.store_ids[i])


def fixture(lab, *args):
    return command([lab.folder / "rate-scheduler-fixture", *args],
                   env=lab.env(), timeout=15).stdout


def verified(lab):
    return json.loads(fixture(lab, "inspect", lab.entitlement))


def wait_verified(lab, timeout=35):
    def check():
        samples = verified(lab)
        return samples if len(samples) == 2 else None
    return wait_for("two fresh core-signed demand estimates and accepted leases",
                    check, lab.processes, timeout=timeout)


def saturate(lab, node, stop, failures):
    # A single sustained VLESS flow exercises upload and download limiters
    # simultaneously. Keep the socket open across a live policy transition.
    try:
        with lab.connect(node) as conn:
            conn.settimeout(30)
            while not stop.is_set():
                conn.sendall(BLOCK)
                require(read_exact(conn, len(BLOCK)) == BLOCK,
                        "saturated VPN flow lost echo payload")
    except BaseException as exc:
        if not stop.is_set():
            failures.append(str(exc))


def await_redistribution(lab, timeout=90):
    # Control must first lower the idle node. Its committed capacity is NOT
    # released until the agent delivers a separate signed rate barrier.
    start = time.monotonic()
    lower = None
    raise_node = None
    while time.monotonic() - start < timeout:
        for name, proc in list(lab.processes.items()):
            require(proc.poll() is None, f"{name} crashed: {proc.returncode}")
        p0 = lab.get_policy(0)
        p1 = lab.get_policy(1)
        down0 = int(p0["downlinkBps"])
        up0 = int(p0["uplinkBps"])
        down1 = int(p1["downlinkBps"])
        up1 = int(p1["uplinkBps"])
        if up0 < 250000 and down0 < 250000:
            lower = (up0, down0)
        if up1 > 250000 and down1 > 250000:
            raise_node = (up1, down1)
        if lower is not None and raise_node is not None:
            require(lower[0] + raise_node[0] <= 500000,
                    "global upload overcommit after scheduler transition")
            require(lower[1] + raise_node[1] <= 500000,
                    "global download overcommit after scheduler transition")
            return lower, raise_node
        time.sleep(0.35)
    raise AssertionError(f"automatic signed redistribution timed out; "
                         f"node0={lab.get_policy(0)}, node1={lab.get_policy(1)}")


def run():
    for key in ("ELXRAY_BIN", "ELX_CONTROL_BIN", "ELX_CONTROL_POSTGRES_DSN"):
        require(os.environ.get(key), f"missing {key}")
    require("elx_test" in os.environ["ELX_CONTROL_POSTGRES_DSN"],
            "refusing non-disposable database")
    with tempfile.TemporaryDirectory(prefix="elx-live-scheduler-e2e-") as temp:
        lab = None
        connections = []
        stop = threading.Event()
        failures = []
        traffic = None
        try:
            lab = JournaledSchedulerLab(Path(temp))
            # Diagnostic output remains in disposable local core logs only;
            # production gRPC errors stay generic and never expose store data.
            lab.base_env["ELXRAY_E2E_LEASE_DIAGNOSTICS"] = "1"
            lab.base_env["ELX_AGENT_E2E_DIAGNOSTICS"] = "1"
            # The shared echo fixture closes idle sockets after 6 seconds.
            # This test holds a real, initially idle VPN connection across
            # telemetry collection and asynchronous rate operations, so the
            # echo endpoint must not terminate it before the core does.
            lab.echo.idle_timeout = 120
            root = Path(__file__).resolve().parents[2]
            compiled = subprocess.run(
                ["go", "build", "-o", str(lab.folder / "rate-scheduler-fixture"),
                 "./tests/e2e/rate_scheduler_fixture"],
                cwd=root, env=lab.env(), capture_output=True, text=True,
                timeout=120, check=False,
            )
            require(compiled.returncode == 0,
                    f"fixture compile failed: {compiled.stderr[-1500:]}")
            lab.start()
            # Use real Control grants, not a test-only bypass of the lease API.
            lab.seed()
            boots = [lab.usage(i)["Incarnation"] for i in range(2)]
            fixture(lab, "seed", lab.entitlement, lab.resource_id,
                    lab.node_ids[0], boots[0], lab.keys[0], lab.executor_ids[0],
                    lab.node_ids[1], boots[1], lab.keys[1], lab.executor_ids[1])
            for i in range(2):
                lab.start_agent(i)
            for i in range(2):
                connections.append(eventually_live(lab, i))
            # One distinct usage reporter per mTLS identity. The master
            # authenticates, discovers assignments and verifies signatures.
            for i in range(2):
                lab.spawn(f"usage{i}", [lab.control, "serve-usage",
                          "-interval", "2s"],
                          env=lab.env(node=i, cert=f"node{i}"))
            wait_verified(lab)
            print("PASS: Control accepted signed demand/lease telemetry from both real cores",
                  flush=True)
            # Induce independently verified saturation on node1, while the
            # live but idle node0 must keep a small nonzero grant.
            traffic = threading.Thread(
                target=saturate, args=(lab, 1, stop, failures), daemon=True)
            traffic.start()
            time.sleep(4)
            lab.spawn("scheduler", [lab.control, "serve-scheduler",
                      "-interval", "2s", "-leader-ttl", "15s"],
                      env={**lab.env(), "ELX_RATE_SCHEDULER_ENABLED": "1"})
            lower, higher = await_redistribution(lab)
            require(not failures, f"VPN traffic failed during scheduler move: {failures}")
            for i, message in enumerate((b"idle-session-kept-after-lower",
                                         b"busy-session-kept-after-raise")):
                try:
                    lab.ping(connections[i], message)
                except BaseException as exc:
                    raise AssertionError(
                        f"node {i} established VPN flow failed after redistribution: {exc}"
                    ) from exc
            print(f"PASS: automatic signed reduce/barrier/raise "
                  f"node0={lower} node1={higher}; upload/download budget 500000 B/s",
                  flush=True)
        except BaseException:
            if lab is not None and (lab.folder / "rate-scheduler-fixture").is_file():
                # Audit actual DB commitments before interpreting an INTENT
                # as a committed rate change or a core-signed barrier.
                try:
                    print("--- signed-rate PostgreSQL state ---", file=sys.stderr)
                    print(fixture(lab, "fup-state", lab.entitlement),
                          file=sys.stderr)
                except BaseException as audit_error:
                    print(f"diagnostic ledger read unavailable: {audit_error}",
                          file=sys.stderr)
            if lab is not None:
                for log in sorted(Path(temp).glob("*.log")):
                    print(f"--- {log.name} ---", file=sys.stderr)
                    print(log.read_text(errors="replace")[-12000:], file=sys.stderr)
            raise
        finally:
            stop.set()
            # Do not block shutdown forever on a saturated socket.
            if traffic is not None:
                traffic.join(timeout=5)
            for conn in connections:
                conn.close()
            if lab is not None:
                lab.close()


if __name__ == "__main__":
    try:
        run()
    except (AssertionError, OSError, subprocess.SubprocessError, ValueError,
            socket.timeout) as exc:
        sys.exit(f"FAIL: live attested scheduler E2E: {exc}")
