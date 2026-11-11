#!/usr/bin/env python3
"""Real expired lost-ACK INSTALL and RETIRE recovery without replay.

A disposable PostgreSQL row lock blocks Control's signed INSTALL confirmation
after the real ElXray journal reaches INSTALLED. The original agent is stopped;
the signed operation expires; a fresh agent can only request a READ-ONLY
core-signed recovery receipt for the original immutable operation ID.
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
from test_live_scheduler import JournaledSchedulerLab
from test_stage4_lifecycle import (
    assert_technical_uuid_denied, database_state, enqueue, journal_state, wait_phase)
from stage4_workspace import ensure_disposable_technical_inbound_tag


def run():
    for key in ("ELXRAY_BIN", "ELX_CONTROL_BIN", "ELX_CONTROL_POSTGRES_DSN"):
        require(os.environ.get(key), "missing " + key)
    require("elx_test" in os.environ["ELX_CONTROL_POSTGRES_DSN"],
            "never fault-inject against production PostgreSQL")
    with tempfile.TemporaryDirectory(prefix="elx-live-scheduler-e2e-") as temp:
        lab = None
        try:
            lab = JournaledSchedulerLab(Path(temp))
            tag = ensure_disposable_technical_inbound_tag(
                lab.folder / "node-0.json", 0)
            ensure_disposable_technical_inbound_tag(lab.folder / "node-1.json", 1)
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
                        "signed budget move not reserved")
                lab.start_agent(node)
            for node in range(2):
                lab.await_revision(node, 2)
                assert_denied(lab, node)
            profile = str(uuid.uuid4())
            email = "lost-confirm@lab"
            enqueue(lab, "prepare", 0, profile, email, tag)
            wait_phase(lab, 0, profile, "PREPARED", "prepared", {"prepare": "INTENT"})

            # The PREPARE agent must not race the independently signed INSTALL
            # while the test acquires the exact pending operation row lock.
            lab.stop("agent0")
            operation = enqueue(lab, "install", 0, profile, email, tag, ttl=18)
            ready = lab.folder / "technical-ack-lock.ready"
            lab.spawn("technical-ack-lock", [
                lab.folder / "rate-scheduler-fixture",
                "hold-technical-confirm", operation, ready,
            ], env={**lab.env(), "ELX_STAGE4_E2E_DISPOSABLE": "1"})
            wait_for("PostgreSQL install ACK fault lock", ready.is_file,
                     lab.processes, timeout=8)
            lab.start_agent(0)

            def locally_installed_centrally_pending():
                record, _ = journal_state(lab, 0, profile)
                if not record or record["phase"] != "INSTALLED":
                    return None
                ledger = database_state(lab, 0, profile)
                if ledger["profileState"] != "prepared" or ledger["operations"]["install"] != "INTENT":
                    return None
                require(ledger["coreBoot"] == lab.usage(0)["Incarnation"],
                        "lost-ACK test did not pin the genuine core boot")
                return record
            wait_for("core INSTALLED while Control install ACK is withheld",
                     locally_installed_centrally_pending, lab.processes, timeout=10)
            # No new owner admission despite a genuinely installed VLESS user.
            assert_technical_uuid_denied(lab, 0, profile)
            lab.stop("agent0")
            lab.stop("technical-ack-lock")  # releases DB lock, no COMMIT
            ledger = database_state(lab, 0, profile)
            require(ledger["operations"]["install"] == "INTENT" and
                    ledger["profileState"] == "prepared",
                    "fault injection did not preserve the authentic lost-ACK case")
            print("PASS: real core INSTALLED, Control INSTALL still INTENT; "
                  "signed confirmation was withheld without mutating a receipt", flush=True)

            # Signed operations are short-lived. Expiry cannot be extended
            # or replayed, and no new UUID/operation is issued to repair it.
            deadline = int(ledger.get("installNotAfter", 0))
            if not deadline:
                deadline = int(time.time()) + 20  # conservative expiry wait
            sleep = max(0, deadline + 2 - time.time())
            time.sleep(min(25, sleep))
            # Original INSTALL must no longer be present in Control delivery.
            # Recovery uses the independently signed terminal journal outcome.
            lab.base_env["ELX_AGENT_TECHNICAL_RECOVERY"] = "1"
            lab.start_agent(0)
            record, _ = wait_phase(
                lab, 0, profile, "INSTALLED", "installed",
                {"prepare": "APPLIED", "install": "APPLIED"})
            require(record["installOperationId"] == operation,
                    "recovery substituted a new INSTALL operation instead of original")
            assert_technical_uuid_denied(lab, 0, profile)
            assert_denied(lab, 1)
            print("PASS: expired lost Control ACK recovered by core-signed "
                  "read-only INSTALLED proof; no replay or device admission", flush=True)

            # Repeat the real fault with RETIRE: the core's permanent UUID
            # tombstone must already exist when Control still says installed.
            # Recovery proves the terminal absence; it cannot resurrect an
            # old VLESS user or release purchased rate/device rights.
            lab.stop("agent0")
            retired_op = enqueue(lab, "retire", 0, profile, email, tag, ttl=18)
            ready.unlink()
            lab.spawn("technical-ack-lock-retire", [
                lab.folder / "rate-scheduler-fixture",
                "hold-technical-confirm", retired_op, ready,
            ], env={**lab.env(), "ELX_STAGE4_E2E_DISPOSABLE": "1"})
            wait_for("PostgreSQL RETIRE ACK lock", ready.is_file,
                     lab.processes, timeout=8)
            lab.base_env["ELX_AGENT_TECHNICAL_RETIRE"] = "1"
            lab.start_agent(0)

            def locally_retired_centrally_pending():
                durable, tombstones = journal_state(lab, 0, profile)
                if durable is None or durable["phase"] != "RETIRED":
                    return None
                ledger = database_state(lab, 0, profile)
                if ledger["profileState"] != "installed" or ledger["operations"].get("retire") != "INTENT":
                    return None
                require(tombstones.get(profile) == 2,
                        "retired identity lacks durable effective-UUID tombstone")
                return durable
            wait_for("core RETIRED while Control RETIRE ACK is withheld",
                     locally_retired_centrally_pending, lab.processes, timeout=10)
            assert_technical_uuid_denied(lab, 0, profile)
            lab.stop("agent0")
            lab.stop("technical-ack-lock-retire")
            ledger = database_state(lab, 0, profile)
            require(ledger["operations"].get("retire") == "INTENT" and
                    ledger["profileState"] == "installed",
                    "RETIRE proof unexpectedly committed without signed recovery")
            print("PASS: real core RETIRED with durable tombstone while "
                  "Control RETIRE remains INTENT", flush=True)

            time.sleep(22)  # signed RETIRE expires; must not be replayed
            lab.start_agent(0)
            retired, tombstones = wait_phase(
                lab, 0, profile, "RETIRED", "retired",
                {"prepare": "APPLIED", "install": "APPLIED", "retire": "APPLIED"})
            require(retired["retireOperationId"] == retired_op and tombstones.get(profile) == 2,
                    "recovery changed the permanent RETIRE operation/tombstone")
            assert_technical_uuid_denied(lab, 0, profile)
            assert_denied(lab, 1)
            print("PASS: expired lost RETIRE ACK recovered read-only from "
                  "core-signed terminal absence, no UUID reuse or capacity release", flush=True)
        except BaseException:
            if lab is not None:
                for logfile in sorted(Path(temp).glob("*.log")):
                    print(f"--- {logfile.name} ---", file=sys.stderr)
                    print(logfile.read_text(errors="replace")[-6500:], file=sys.stderr)
            raise
        finally:
            if lab is not None:
                lab.close()


if __name__ == "__main__":
    try:
        run()
    except (AssertionError, OSError, ValueError, subprocess.SubprocessError,
            socket.timeout) as exc:
        sys.exit(f"FAIL: real expired INSTALL/RETIRE lost-ACK recovery: {exc}")
