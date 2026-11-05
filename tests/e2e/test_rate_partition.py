#!/usr/bin/env python3
"""Sustained two-node VLESS bandwidth and Control interruption acceptance.

The two ElXray token buckets are explicitly allocated grants within one
aggregate test ceiling. This proves the *data plane* enforces both grants,
not that PostgreSQL's demand scheduler delivered those grants itself.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

from test_multinode import Lab, command, read_exact, require, wait_for

PAYLOAD = b"x" * 4096
CHUNKS = 256   # 1 MiB per node; enough to amortize 8192-byte burst


def exercise_data_plane(lab):
    # Independent uplink/downlink grants total 300,000 bytes/s each.
    # Both TCP streams are started together and kept continuously busy.
    grants = ((140000, 155000), (160000, 145000))
    for i, (up, down) in enumerate(grants):
        lab.enqueue(i, 0, up, down)
        lab.start_agent(i)
        policy = lab.await_revision(i, 2)
        require(int(policy["uplinkBps"]) == up and
                int(policy["downlinkBps"]) == down,
                f"node {i} did not apply signed policy rates")

    before = [lab.usage(i) for i in range(2)]
    gate = threading.Barrier(3)

    def transfer(i):
        with lab.connect(i) as conn:
            conn.settimeout(35)
            gate.wait(timeout=10)
            for _ in range(CHUNKS):
                conn.sendall(PAYLOAD)
                require(read_exact(conn, len(PAYLOAD)) == PAYLOAD,
                        f"node {i} lost VLESS payload under saturation")
        return time.monotonic()

    with ThreadPoolExecutor(max_workers=2) as pool:
        transfers = [pool.submit(transfer, i) for i in range(2)]
        gate.wait(timeout=10)
        started = time.monotonic()
        finished = [job.result(timeout=45) for job in transfers]
    elapsed = max(finished) - started
    sent = len(PAYLOAD) * CHUNKS * 2
    budget_up, budget_down = map(sum, zip(*grants))
    observed = sent / elapsed
    # An ElXray bucket starts with an 8 KiB credit per node; for >=1 MiB
    # per node its effect is <1%. Allow timing and scheduler noise, but
    # reject any gross aggregate overspeed on the actual VPN path.
    require(observed <= min(budget_up, budget_down) * 1.25,
            f"two nodes exceeded the committed aggregate lab ceiling: "
            f"{observed:.0f} B/s > {min(budget_up, budget_down)} B/s")
    require(elapsed < 35, f"VPN link stalled or exceeded test deadline: {elapsed:.1f}s")
    for i in range(2):
        def counted(node=i):
            sample = lab.usage(node)
            minimum = len(PAYLOAD) * CHUNKS
            return sample if (sample["UpBytes"] - before[node]["UpBytes"] >= minimum
                              and sample["DownBytes"] - before[node]["DownBytes"] >= minimum) else None
        wait_for(f"node {i} signed saturated traffic", counted, lab.processes, timeout=7)
    print(f"PASS: simultaneous two-node upload/download: {observed:.0f} B/s "
          f"over {elapsed:.2f}s, independent budget {budget_up}/{budget_down} B/s",
          flush=True)


def exercise_control_outage(lab):
    # The test is deliberately NOT running with mandatory signed Control
    # leases, so it checks durable control-plane recovery, NOT paid-session
    # fail-closed after lease expiration. That requires a separate test.
    with lab.connect(0) as node0, lab.connect(1) as node1:
        lab.ping(node0, b"control-before-loss-0")
        lab.ping(node1, b"control-before-loss-1")
        lab.stop("control")
        lab.enqueue(0, 1, 120000, 125000)
        lab.enqueue(1, 1, 130000, 135000)
        for _ in range(4):
            lab.ping(node0, b"still-live-0")
            lab.ping(node1, b"still-live-1")
            time.sleep(0.2)
        require(int(lab.get_policy(0)["revision"]) == 2,
                "node0 changed policy while Control transport unavailable")
        require(int(lab.get_policy(1)["revision"]) == 2,
                "node1 changed policy while Control transport unavailable")
        for i in range(2):
            agent = lab.processes[f"agent{i}"]
            require(agent.poll() is None, f"agent{i} died instead of retrying the outage")
        lab.spawn("control", [lab.control, "serve-policy"], env=lab.env(cert="control"))
        for i, (up, down) in enumerate(((120000, 125000), (130000, 135000))):
            policy = lab.await_revision(i, 3)
            require(int(policy["uplinkBps"]) == up and
                    int(policy["downlinkBps"]) == down,
                    f"node {i} lost journal operation across Control transport outage")
        lab.ping(node0, b"still-live-after-restore-0")
        lab.ping(node1, b"still-live-after-restore-1")
    print("PASS: mTLS Control transport outage: no unauthorized policy advance, "
          "agents retry and both nodes recover queued revisions", flush=True)


def exercise_database_unavailable(lab):
    # Start another Control instance against an unreachable loopback PostgreSQL
    # endpoint. The server MUST exit instead of exposing an unauthenticated
    # or memory-only policy authority. Do not stop the shared PG fixture.
    invalid = lab.env(cert="control")
    invalid["ELX_CONTROL_POSTGRES_DSN"] = (
        "host=127.0.0.1 port=1 dbname=elx_test user=elx "
        "password=invalid sslmode=disable connect_timeout=1"
    )
    lab.stop("control")
    lab.spawn("db-unreachable", [lab.control, "serve-policy"], env=invalid)
    def rejected():
        proc = lab.processes["db-unreachable"]
        if proc.poll() is None:
            return False
        require(proc.returncode != 0, "Control with unavailable database exited successfully")
        return True
    wait_for("Control failing closed without PostgreSQL", rejected, {
        key: value for key, value in lab.processes.items() if key != "db-unreachable"
    }, timeout=6)
    lab.stop("db-unreachable")
    with lab.connect(0) as node0, lab.connect(1) as node1:
        lab.ping(node0, b"db-outage-zero")
        lab.ping(node1, b"db-outage-one")
    lab.spawn("control", [lab.control, "serve-policy"], env=lab.env(cert="control"))
    for i in range(2):
        lab.await_revision(i, 3)
    print("PASS: Control refuses to start without PostgreSQL; "
          "previous applied non-lease policies remain unchanged", flush=True)


def main():
    for key in ("ELXRAY_BIN", "ELX_CONTROL_BIN", "ELX_CONTROL_POSTGRES_DSN"):
        require(os.environ.get(key), f"missing test environment: {key}")
    with tempfile.TemporaryDirectory(prefix="elx-p0-rate-network-") as tmp:
        lab = None
        try:
            lab = Lab(Path(tmp))
            lab.start()
            exercise_data_plane(lab)
            exercise_control_outage(lab)
            exercise_database_unavailable(lab)
            print("PASS: bandwidth and control-plane disruption E2E", flush=True)
        except BaseException:
            if lab is not None:
                for log in sorted(Path(tmp).glob("*.log")):
                    print(f"--- {log.name} ---", file=sys.stderr)
                    print(log.read_text(errors="replace")[-2500:], file=sys.stderr)
            raise
        finally:
            if lab is not None:
                lab.close()


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, subprocess.SubprocessError, ValueError,
            threading.BrokenBarrierError) as error:
        sys.exit(f"FAIL: P0 rate/network E2E: {error}")
