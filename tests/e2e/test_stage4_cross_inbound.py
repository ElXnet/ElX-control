#!/usr/bin/env python3
"""Real negative E2E: cross-inbound VLESS UUID aliases are never installed.

Two managed ElXray cores and disposable PostgreSQL are used; a second static
VLESS inbound has an alias of the dynamic account on node 0. A genuine
Control-signed INSTALL must fail BEFORE journal INSTALLING and AddUser.
"""
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import uuid

from test_multinode import available_ports, command, require
from test_lease_partition import assert_denied
from test_live_scheduler import JournaledSchedulerLab
from test_stage4_lifecycle import (
    assert_technical_uuid_denied, database_state, enqueue, journal_state, wait_phase)
from stage4_workspace import ensure_disposable_technical_inbound_tag


def run():
    for key in ("ELXRAY_BIN", "ELX_CONTROL_BIN", "ELX_CONTROL_POSTGRES_DSN"):
        require(os.environ.get(key), "missing " + key)
    require("elx_test" in os.environ["ELX_CONTROL_POSTGRES_DSN"],
            "refusing non-disposable PostgreSQL")
    with tempfile.TemporaryDirectory(prefix="elx-live-scheduler-e2e-") as temp:
        lab = None
        try:
            lab = JournaledSchedulerLab(Path(temp))
            tag = ensure_disposable_technical_inbound_tag(
                lab.folder / "node-0.json", 0)
            ensure_disposable_technical_inbound_tag(
                lab.folder / "node-1.json", 1)
            profile = uuid.uuid4()
            raw = bytearray(profile.bytes)
            raw[6] ^= 0x35
            raw[7] ^= 0x79
            shadow_id = str(uuid.UUID(bytes=bytes(raw)))
            shadow_port = available_ports(1)[0]
            config_path = lab.folder / "node-0.json"
            config = json.loads(config_path.read_text(encoding="utf-8"))
            shadow = copy.deepcopy(config["inbounds"][0])
            shadow["tag"] = "shadow-vless-inbound"
            shadow["port"] = shadow_port
            shadow["settings"]["clients"] = [{
                "id": shadow_id, "email": "shadow@lab"
            }]
            config["inbounds"].append(shadow)
            config_path.write_text(json.dumps(config), encoding="utf-8")
            lab.base_env.update({
                "ELXRAY_TECHNICAL_PROVISIONING": "1",
                "ELX_AGENT_TECHNICAL_PREPARE": "1",
                "ELX_AGENT_TECHNICAL_INSTALL": "1",
            })
            lab.start()
            lab.seed()
            for node in range(2):
                result = command([
                    lab.control, "queue-rate-move", "-entitlement", lab.entitlement,
                    "-node", lab.node_ids[node], "-resource", lab.resource_id,
                    "-operation", str(uuid.uuid4()), "-expected", "0",
                    "-up", "250000", "-down", "250000",
                ], env=lab.env())
                require(json.loads(result.stdout)["revision"] == 1,
                        "signed budget move not durably reserved")
                lab.start_agent(node)
            for node in range(2):
                lab.await_revision(node, 2)
            email = "new-technical@lab"
            enqueue(lab, "prepare", 0, str(profile), email, tag)
            wait_phase(lab, 0, str(profile), "PREPARED", "prepared",
                       {"prepare": "INTENT"})
            assert_technical_uuid_denied(lab, 0, shadow_id, shadow_port)
            enqueue(lab, "install", 0, str(profile), email, tag)
            # A malformed/foreign effective key must stop this one agent
            # with AlreadyExists. Other node and Control continue serving.
            deadline = time.monotonic() + 18
            while lab.processes["agent0"].poll() is None and time.monotonic() < deadline:
                time.sleep(0.15)
            require(lab.processes["agent0"].poll() not in (None, 0),
                    "foreign-inbound alias did not cause signed INSTALL failure")
            # Agent0's refusal is the EXPECTED security result. Remove the
            # stopped process from liveness monitoring before checking the
            # other healthy processes and dedicated VLESS denial.
            lab.stop("agent0")
            disk, denied = journal_state(lab, 0, str(profile))
            ledger = database_state(lab, 0, str(profile))
            require(disk is not None and disk["phase"] == "PREPARED" and
                    denied.get(str(profile), 0) == 0,
                    "cross-inbound collision mutated the technical core journal")
            require(ledger["profileState"] == "prepared" and
                    ledger["operations"]["install"] == "INTENT",
                    "cross-inbound alias was centrally acknowledged")
            require(lab.processes["node0"].poll() is None and
                    lab.processes["node1"].poll() is None and
                    lab.processes["agent1"].poll() is None,
                    "cross-inbound alias crashed an unrelated managed core")
            assert_denied(lab, 0)
            assert_denied(lab, 1)
            assert_technical_uuid_denied(lab, 0, shadow_id, shadow_port)
            print("PASS: signed INSTALL cannot adopt normalized UUID shadow "
                  "from another VLESS inbound; no payload or central APPLIED", flush=True)
        except BaseException:
            if lab is not None:
                for logfile in sorted(Path(temp).glob("*.log")):
                    print(f"--- {logfile.name} ---", file=sys.stderr)
                    print(logfile.read_text(errors="replace")[-7000:], file=sys.stderr)
            raise
        finally:
            if lab is not None:
                lab.close()


if __name__ == "__main__":
    try:
        run()
    except (AssertionError, OSError, ValueError, subprocess.SubprocessError,
            socket.timeout) as exc:
        sys.exit(f"FAIL: cross-inbound VLESS alias / signed INSTALL: {exc}")
