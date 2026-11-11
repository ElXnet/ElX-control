#!/usr/bin/env python3
"""Signed Stage-4 PREPARE/INSTALL/RETIRE against two real managed ElXray cores.

Disposable PostgreSQL, Control mTLS, Unix SO_PEERCRED, real VLESS validators,
core-signed operation receipts and independent immutable boot/store witness.
A technical VLESS identity NEVER grants payload without separate owner proof.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import uuid

from test_multinode import command, require, wait_for
from test_lease_partition import assert_denied
from test_live_scheduler import JournaledSchedulerLab, fixture
from stage4_workspace import ensure_disposable_technical_inbound_tag


def journal_state(lab, node, profile):
    data = json.loads(lab.journals[node].read_text(encoding="utf-8"))
    return (data.get("technicalProfiles") or {}).get(profile), data.get("deniedProfiles") or {}


def database_state(lab, node, profile):
    return json.loads(fixture(lab, "technical-state", profile, lab.node_ids[node]))


def enqueue(lab, action, node, profile, email, tag):
    now = int(time.time())
    op = str(uuid.uuid4())
    args = [
        lab.control, "enqueue-technical-" + ("profile" if action == "prepare" else action),
        "-node", lab.node_ids[node], "-resource", lab.resource_id,
        "-profile", profile, "-operation", op, "-entitlement", lab.entitlement,
        "-email", email, "-inbound", tag, "-core-revision", "2",
        "-not-before", str(now - 1), "-not-after", str(now + 56),
    ]
    if action != "prepare":
        args.extend(["-flow", ""])
    result = command(args, env=lab.env(), timeout=25)
    require("INTENT" in result.stdout and op in result.stdout,
            "Control did not persist the technical INTENT")
    return op


def wait_phase(lab, node, profile, phase, db_phase, operations):
    def check():
        disk, denied = journal_state(lab, node, profile)
        if not disk or disk["phase"] != phase:
            return None
        ledger = database_state(lab, node, profile)
        if ledger["profileState"] != db_phase:
            return None
        if any(ledger["operations"].get(k) != v for k, v in operations.items()):
            return None
        require(ledger["storeId"] == lab.store_ids[node],
                "PostgreSQL proof linked to a different immutable store")
        require(ledger["coreBoot"] == lab.usage(node)["Incarnation"],
                "independent PostgreSQL core boot witness mismatched")
        require(ledger["coreRevision"] == 2,
                "technical action silently advanced paid rate revision")
        require(ledger["committedUp"] == ledger["committedDown"] == 250000,
                "technical action modified purchased rate allocations")
        require(ledger["activeSlots"] == 2,
                "technical action freed a purchased device/owner slot")
        return disk, denied
    return wait_for(f"node {node} core {phase} / Control {db_phase}",
                    check, lab.processes, timeout=35)


def run():
    for key in ("ELXRAY_BIN", "ELX_CONTROL_BIN", "ELX_CONTROL_POSTGRES_DSN"):
        require(os.environ.get(key), f"missing {key}")
    require("elx_test" in os.environ["ELX_CONTROL_POSTGRES_DSN"],
            "refusing non-disposable PostgreSQL")
    with tempfile.TemporaryDirectory(prefix="elx-live-scheduler-e2e-") as temp:
        lab = None
        try:
            lab = JournaledSchedulerLab(Path(temp))
            tags = [
                ensure_disposable_technical_inbound_tag(
                    lab.folder / f"node-{i}.json", i)
                for i in range(2)
            ]
            lab.base_env.update({
                "ELXRAY_TECHNICAL_PROVISIONING": "1",
                "ELX_AGENT_TECHNICAL_PREPARE": "1",
                "ELX_AGENT_TECHNICAL_INSTALL": "1",
                "ELX_AGENT_TECHNICAL_RETIRE": "1",
            })
            lab.start()
            lab.seed()
            # Offline store bootstrap has no core boot ID. Establish a
            # genuine Control-applied signed policy to pin the incarnation
            # BEFORE accepting any signed technical VLESS result.
            for i in range(2):
                lab.enqueue(i, 0, 250000, 250000)
                lab.start_agent(i)
            for i in range(2):
                lab.await_revision(i, 2)
                assert_denied(lab, i)
            print("PASS: two managed cores, pinned signed store/boot witnesses", flush=True)

            profiles = [str(uuid.uuid4()) for _ in range(2)]
            emails = [f"technical-{i}@lab" for i in range(2)]
            for i in range(2):
                enqueue(lab, "prepare", i, profiles[i], emails[i], tags[i])
            for i in range(2):
                disk, _ = wait_phase(lab, i, profiles[i], "PREPARED", "prepared",
                                     {"prepare": "INTENT"})
                require(disk["profileId"] == profiles[i], "PREPARED UUID mismatch")
                assert_denied(lab, i)
            print("PASS: two durable Control-signed PREPARE outcomes", flush=True)

            for i in range(2):
                enqueue(lab, "install", i, profiles[i], emails[i], tags[i])
            for i in range(2):
                disk, _ = wait_phase(lab, i, profiles[i], "INSTALLED", "installed",
                                     {"prepare": "APPLIED", "install": "APPLIED"})
                require(disk.get("installOperationId"),
                        "missing durable core VLESS INSTALL identity")
                assert_denied(lab, i)
            print("PASS: two real VLESS INSTALLs and independent PostgreSQL "
                  "core-signed APPLIED confirmations", flush=True)

            for i in range(2):
                enqueue(lab, "retire", i, profiles[i], emails[i], tags[i])
            for i in range(2):
                disk, denied = wait_phase(
                    lab, i, profiles[i], "RETIRED", "retired",
                    {"prepare": "APPLIED", "install": "APPLIED", "retire": "APPLIED"})
                require(disk.get("retireGeneration") == 2 and denied.get(profiles[i]) == 2,
                        "durable permanent effective VLESS UUID tombstone missing")
                assert_denied(lab, i)
            print("PASS: two signed RETIREs, permanent tombstones, independent "
                  "PostgreSQL proof and unchanged paid slots/rate", flush=True)
        except BaseException:
            if lab is not None:
                for path in sorted(Path(temp).glob("*.log")):
                    print(f"--- {path.name} ---", file=sys.stderr)
                    print(path.read_text(errors="replace")[-6000:], file=sys.stderr)
            raise
        finally:
            if lab is not None:
                lab.close()


if __name__ == "__main__":
    try:
        run()
    except (AssertionError, OSError, ValueError, subprocess.SubprocessError,
            socket.timeout) as exc:
        sys.exit(f"FAIL: real two-core Stage-4 technical lifecycle: {exc}")
