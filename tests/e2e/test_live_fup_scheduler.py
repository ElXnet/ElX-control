#!/usr/bin/env python3
"""P0 network acceptance: real signed FUP threshold + scheduler + Control loss.

Two real loopback ElXray VLESS cores report signed usage and pressure over
mTLS. PostgreSQL creates the FUP event from the core-signed usage increment;
a separate FUP worker reduces grants only through signed core rate barriers.
The policy authority is deliberately stopped during reconciliation. Also
tests leader-fenced scheduler takeover, NOT PostgreSQL physical HA.
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

from test_multinode import require, wait_for
from test_lease_partition import LeasedLab, eventually_live, assert_denied
from test_live_scheduler import fixture, wait_verified, saturate, await_redistribution

BLOCK = b"fup-traffic-" * 340  # 4080 bytes; well below socket payload limits


def state(lab):
    return json.loads(fixture(lab, "fup-state", lab.entitlement))


def wait_fup_event(lab):
    return wait_for("real core-signed FUP threshold event", lambda: (
        current if (current := state(lab))["event"] else None),
        lab.processes, timeout=35)


def wait_fup_converged(lab):
    def check():
        observed = state(lab)
        p0, p1 = lab.get_policy(0), lab.get_policy(1)
        up = [int(p["uplinkBps"]) for p in (p0, p1)]
        down = [int(p["downlinkBps"]) for p in (p0, p1)]
        # Confirm BOTH actual cores agree with the durable PostgreSQL grant.
        if not observed["event"] or observed["pending"] != 0:
            return None
        if up == [20000, 20000] and down == [20000, 20000] and (
                observed["committedUp"] == 40000 and
                observed["committedDown"] == 40000):
            return observed
        return None
    try:
        return wait_for("signed FUP 40k/40k convergence on both live VLESS nodes",
                        check, lab.processes, timeout=95)
    except AssertionError as exc:
        observed = state(lab)
        policies = [lab.get_policy(i) for i in range(2)]
        raise AssertionError(
            f"{exc}; durable FUP state={json.dumps(observed, sort_keys=True)}; "
            f"real core policies={json.dumps(policies, sort_keys=True)}"
        ) from exc


def run():
    for key in ("ELXRAY_BIN", "ELX_CONTROL_BIN", "ELX_CONTROL_POSTGRES_DSN"):
        require(os.environ.get(key), f"missing {key}")
    require("elx_test" in os.environ["ELX_CONTROL_POSTGRES_DSN"],
            "refusing non-disposable PostgreSQL")

    with tempfile.TemporaryDirectory(prefix="elx-fup-partition-e2e-") as temp:
        lab = None
        stop = threading.Event()
        failures = []
        busy = None
        try:
            lab = LeasedLab(Path(temp))
            lab.echo.idle_timeout = 120
            built = subprocess.run(
                ["go", "build", "-o", str(lab.folder / "rate-scheduler-fixture"),
                 "./tests/e2e/rate_scheduler_fixture"],
                cwd=Path(__file__).resolve().parents[2],
                env=lab.env(), capture_output=True, text=True,
                timeout=120, check=False,
            )
            require(built.returncode == 0,
                    f"fixture build error: {built.stderr[-1800:]}")
            lab.start()
            lab.seed()
            boots = [lab.usage(i)["Incarnation"] for i in range(2)]
            fixture(lab, "seed", lab.entitlement, lab.resource_id,
                    lab.node_ids[0], boots[0], lab.keys[0],
                    lab.node_ids[1], boots[1], lab.keys[1])
            for i in range(2):
                lab.start_agent(i)
                eventually_live(lab, i).close()
                lab.spawn(f"usage{i}", [lab.control, "serve-usage",
                          "-interval", "2s"],
                          env=lab.env(node=i, cert=f"node{i}"))
            wait_verified(lab)

            # First establish a REAL signed automatic 32k/467k rebalance.
            busy = threading.Thread(
                target=saturate, args=(lab, 1, stop, failures), daemon=True)
            busy.start()
            time.sleep(4)
            lab.spawn("scheduler-a", [lab.control, "serve-scheduler",
                      "-interval", "2s", "-leader-ttl", "15s"],
                      env={**lab.env(), "ELX_RATE_SCHEDULER_ENABLED": "1"})
            lower, higher = await_redistribution(lab)
            stop.set()
            busy.join(timeout=6)
            require(not failures, f"VLESS saturation lost payload: {failures}")
            print(f"PASS: real signed scheduler baseline {lower} / {higher}",
                  flush=True)
            # The FUP recovery stage must not race an unrelated demand
            # redistribution. Stop the scheduler after proving it works.
            # A separate PostgreSQL interleaving gate exercises the exact
            # FUP-vs-pending-scheduler transaction race deterministically.
            # Restart the scheduler below to prove fenced leader takeover
            # under the active FUP ceiling, without requiring equal node
            # shares while demand-aware redistribution is also running.
            lab.stop("scheduler-a")

            # Activate only after two real signed streams were primed.
            # The guarded TEST fixture arms an additional 64KiB of demand
            # above the already-accounted usage. Fake/unsigned payload alone
            # cannot cause this transition.
            fixture(lab, "arm-fup", lab.entitlement)
            lab.spawn("fup", [lab.control, "serve-fup", "-interval", "1s"],
                      env=lab.env())
            with lab.connect(1) as flow:
                flow.settimeout(25)
                for _ in range(48):
                    lab.ping(flow, BLOCK)
            crossed = wait_fup_event(lab)
            require(crossed["event"], "no database FUP event")
            print("PASS: actual signed VLESS traffic crossed live FUP threshold",
                  flush=True)

            # Cut mTLS authority during / immediately after FUP reconciliation.
            # The independent FUP journal worker may enqueue reductions;
            # agents must not forge policy receipts without Control.
            lab.stop("control")
            time.sleep(18)
            for i in range(2):
                assert_denied(lab, i)
            print("PASS: both VPN nodes fail closed when mandatory Control leases expire "
                  "during FUP reconciliation", flush=True)
            lab.spawn("control", [lab.control, "serve-policy"],
                      env=lab.env(cert="control"))
            # Pending FUP journal reductions must finish first. An expired
            # mandatory lease is not evidence that policy/barrier application
            # failed: those are independent safety/recovery operations.
            converged = wait_fup_converged(lab)
            for i in range(2):
                eventually_live(lab, i).close()
            print(f"PASS: both real cores restored and settled at signed "
                  f"FUP cap 20000+20000 B/s; {converged}", flush=True)

            # Two independent scheduler processes share only PostgreSQL
            # leader fencing. After scheduler A stops, B must acquire a NEW
            # epoch, and the active FUP cap must remain authoritative.
            old_epoch = state(lab)["leaderEpoch"]
            require(old_epoch > 0, "scheduler baseline had no PostgreSQL leader")
            lab.spawn("scheduler-a", [lab.control, "serve-scheduler",
                      "-interval", "2s", "-leader-ttl", "15s"],
                      env={**lab.env(), "ELX_RATE_SCHEDULER_ENABLED": "1"})
            def leader_a_ready():
                observed = state(lab)
                return observed if observed["leaderEpoch"] > old_epoch else None
            previous = wait_for("scheduler A re-acquires a fenced epoch after FUP",
                                leader_a_ready, lab.processes, timeout=40)
            lab.spawn("scheduler-b", [lab.control, "serve-scheduler",
                      "-interval", "2s", "-leader-ttl", "15s"],
                      env={**lab.env(), "ELX_RATE_SCHEDULER_ENABLED": "1"})
            lab.stop("scheduler-a")
            def new_leader():
                current = state(lab)
                if current["leaderEpoch"] > previous["leaderEpoch"] and (
                        current["leaderHolder"] != previous["leaderHolder"]):
                    return current
                return None
            transferred = wait_for("fenced scheduler leadership after process stop",
                                   new_leader, lab.processes, timeout=40)
            require(transferred["committedUp"] == 40000 and
                    transferred["committedDown"] == 40000,
                    "scheduler takeover exceeded active FUP")
            print(f"PASS: scheduler takeover increased leader epoch "
                  f"{previous['leaderEpoch']} -> {transferred['leaderEpoch']} "
                  "without violating FUP", flush=True)
            print("PASS: real signed FUP, Control recovery and scheduler failover E2E",
                  flush=True)
        except BaseException:
            if lab is not None:
                for log in sorted(Path(temp).glob("*.log")):
                    print(f"--- {log.name} ---", file=sys.stderr)
                    print(log.read_text(errors="replace")[-4500:], file=sys.stderr)
            raise
        finally:
            stop.set()
            if busy is not None:
                busy.join(timeout=5)
            if lab is not None:
                lab.close()


if __name__ == "__main__":
    try:
        run()
    except (AssertionError, OSError, subprocess.SubprocessError, ValueError,
            socket.timeout) as exc:
        sys.exit(f"FAIL: signed FUP/Control partition/scheduler takeover E2E: {exc}")
