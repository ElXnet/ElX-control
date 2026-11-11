#!/usr/bin/env python3
"""Real-core Stage-4 negative acceptance for static VLESS JSON bypass.

The two paid managed nodes must not admit any payload with
ELXRAY_TECHNICAL_PROVISIONING=1, even if the old static VLESS account and
a separately signed Control lease are present. This is NOT an INSTALL or
device-owner authorization test. It deliberately never provides a test
bypass to the protected runtime.
"""
from pathlib import Path
import os
import socket
import subprocess
import sys
import tempfile
import time

from test_multinode import require
from test_lease_partition import assert_denied
from test_live_scheduler import JournaledSchedulerLab
from stage4_workspace import ensure_disposable_technical_inbound_tag


def assert_static_deny_while_core_alive(lab, node, label):
    process = lab.processes.get(f"node{node}")
    require(process is not None and process.poll() is None,
            f"{label}: managed ElXray core not alive for real denial check")
    assert_denied(lab, node)
    require(process.poll() is None,
            f"{label}: rejected static user crashed the managed core")


def run():
    for key in ("ELXRAY_BIN", "ELX_CONTROL_BIN", "ELX_CONTROL_POSTGRES_DSN"):
        require(os.environ.get(key), f"missing {key}")
    require("elx_test" in os.environ["ELX_CONTROL_POSTGRES_DSN"],
            "never test static VLESS bypass against production PostgreSQL")
    with tempfile.TemporaryDirectory(prefix="elx-live-scheduler-e2e-") as tmp:
        lab = None
        try:
            lab = JournaledSchedulerLab(Path(tmp))
            # The legacy shared fixture deliberately leaves VLESS untagged.
            # A technical installation/recovery must bind an exact inbound:
            # add stable tags to the disposable JSON, never weaken ElXray.
            for node in range(2):
                ensure_disposable_technical_inbound_tag(
                    lab.folder / f"node-{node}.json", node)
            # Only explicitly managed cores opt in. This is intentionally
            # incompatible with forwarding payload until later owner/device
            # authorization is implemented; never weaken this admission gate.
            lab.base_env["ELXRAY_TECHNICAL_PROVISIONING"] = "1"
            lab.start()
            for node in range(2):
                assert_static_deny_while_core_alive(lab, node, "before signed Control lease")

            # Use genuine PostgreSQL grants, Control mTLS and the
            # separate nobody-UID Unix-socket agent; no unsigned rates.
            lab.seed()
            for node in range(2):
                lab.start_agent(node)
            time.sleep(5)
            for node in range(2):
                agent = lab.processes.get(f"agent{node}")
                require(agent is not None and agent.poll() is None,
                        f"managed Control agent crashed on node {node}")
                assert_static_deny_while_core_alive(lab, node, "after Control lease delivery")
            print("PASS: two managed Stage-4 cores reject static VLESS JSON "
                  "identities despite independent Control lease agents", flush=True)

            # An old static identity must never become payload-authorized
            # by restarting the managed core against its existing on-disk
            # policy and journal. A safely refused startup is fail-closed.
            lab.stop("node0")
            lab.spawn("node0", [lab.core, "run", "-c", lab.folder / "node-0.json"],
                      env=lab.env(node=0))
            try:
                lab.await_revision(0, 1)
            except (AssertionError, OSError, socket.timeout):
                restarted = lab.processes["node0"]
                require(restarted.poll() is not None,
                        "uncertain core restart was not conclusively rejected")
                print("PASS: ambiguous managed restart quarantined instead of "
                      "falling back to static VLESS admission", flush=True)
            else:
                assert_static_deny_while_core_alive(lab, 0, "after on-disk restart")
                print("PASS: managed core restart did not resurrect static "
                      "VLESS payload authorization", flush=True)
        except BaseException:
            if lab is not None:
                for log in sorted(Path(tmp).glob("*.log")):
                    print(f"--- {log.name} ---", file=sys.stderr)
                    print(log.read_text(errors="replace")[-6500:], file=sys.stderr)
            raise
        finally:
            if lab is not None:
                lab.close()


if __name__ == "__main__":
    try:
        run()
    except (AssertionError, OSError, subprocess.SubprocessError,
            ValueError, socket.timeout) as exc:
        sys.exit(f"FAIL: Stage-4 static VLESS bypass protection: {exc}")
